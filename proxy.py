#!/usr/bin/env python3
"""Credential Proxy — Matrix 审批 + TPM + KeePassXC + LLM 脱敏代理"""
import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
import uuid
from collections import OrderedDict

from aiohttp import web, ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientConnectionResetError
from nio import AsyncClient, RoomMessageText, ReactionEvent

logger = logging.getLogger("credential-proxy")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TPM_DIR = os.path.join(BASE_DIR, "tpm")
DB_DIR = os.path.join(BASE_DIR, "db")

TOKEN_PREFIX = "__VG_CRED_"
TOKEN_SUFFIX = "__"
MAX_TOKEN_ENTRIES = 5000
HOP_HEADERS = frozenset({"host", "transfer-encoding", "content-length", "content-encoding", "connection", "keep-alive", "te"})


def _make_token(n: int) -> str:
    return f"{TOKEN_PREFIX}{n:04d}{TOKEN_SUFFIX}"


# 從環境變量讀取 LLM 代理配置：LLM_<PORT>=<UPSTREAM_URL>
def _parse_proxy_env() -> dict[int, str]:
    proxies = {}
    for k, v in os.environ.items():
        if not k.startswith("LLM_"):
            continue
        try:
            port = int(k[4:])
        except ValueError:
            continue
        proxies[port] = v.strip().rstrip("/")
    return proxies


class CredentialProxy:
    def __init__(self, homeserver, room_id, access_token):
        self.homeserver = homeserver
        self.room_id = room_id
        self.access_token = access_token
        self.master_password = None
        self.kdbx_path = None
        self.keyfile_path = None
        self.pending_requests = {}
        self.approval_msgs = {}
        self.unlock_event = None
        self._unlock_msg_id = None
        self._lock = asyncio.Lock()
        self._unlock_in_progress = False
        self._unlock_task = None
        self._runners = []
        self._kp = None  # KeePass cache
        self._shutting_down = False
        self._start_ts = int(time.time() * 1000)
        self._last_credential_request = 0.0
        self._credential_min_interval = 2.0

        self.pwd_to_token = OrderedDict()
        self.token_to_pwd = {}
        self._token_seq = 0

        if os.path.isdir(DB_DIR):
            kdbx_files = []
            for f in sorted(os.listdir(DB_DIR)):
                if f.endswith(".kdbx"):
                    kdbx_files.append(f)
                    self.kdbx_path = os.path.join(DB_DIR, f)
                elif f.endswith(".key"):
                    self.keyfile_path = os.path.join(DB_DIR, f)
            if len(kdbx_files) > 1:
                logger.warning(
                    f"DB_DIR 中发现 {len(kdbx_files)} 个 .kdbx 文件，"
                    f"使用字母序最后一个: {kdbx_files[-1]}"
                )
        if self.kdbx_path:
            logger.info(f"密码库: {self.kdbx_path}")
        else:
            logger.warning("未找到 .kdbx 文件，凭据获取将不可用")

        self.tpm_primary = os.path.join(TPM_DIR, "primary.ctx")
        self.tpm_seal_pub = os.path.join(TPM_DIR, "seal.pub")
        self.tpm_seal_priv = os.path.join(TPM_DIR, "seal.priv")
        logger.info(f"TPM primary: {self.tpm_primary}")

        self.proxies = _parse_proxy_env()
        for port, url in sorted(self.proxies.items()):
            logger.info(f"LLM 代理 → 0.0.0.0:{port} → {url}")

    # ── Token ──
    async def _register_secret(self, value):
        if not value or len(value) < 4:
            return value
        async with self._lock:
            if value in self.pwd_to_token:
                self.pwd_to_token.move_to_end(value)
                return self.pwd_to_token[value]
            self._token_seq += 1
            token = _make_token(self._token_seq)
            if len(self.pwd_to_token) >= MAX_TOKEN_ENTRIES:
                oldest = next(iter(self.pwd_to_token))
                old_token = self.pwd_to_token.pop(oldest)
                self.token_to_pwd.pop(old_token, None)
            self.pwd_to_token[value] = token
            self.token_to_pwd[token] = value
            return token

    async def _maybe_register(self, value, use_token=True):
        return await self._register_secret(value) if use_token else value

    def _redact(self, text, pwd_to_token=None):
        # 按长度降序：长密码先替换，避免短密码是长密码子串时导致长密码泄漏
        mapping = pwd_to_token if pwd_to_token is not None else self.pwd_to_token
        for pwd, token in sorted(mapping.items(),
                                 key=lambda x: len(x[0]), reverse=True):
            text = text.replace(pwd, token)
        return text

    def _restore(self, text, token_to_pwd=None):
        mapping = token_to_pwd if token_to_pwd is not None else self.token_to_pwd
        for token, pwd in mapping.items():
            text = text.replace(token, pwd)
        return text

    # ── TPM ──
    def _tpm_unseal(self):
        with tempfile.NamedTemporaryFile(suffix=".ctx", delete=False) as f:
            seal_ctx = f.name
        try:
            r = subprocess.run(
                ["tpm2_load", "-C", self.tpm_primary, "-u", self.tpm_seal_pub,
                 "-r", self.tpm_seal_priv, "-c", seal_ctx],
                capture_output=True, text=True,
            )
            if r.returncode != 0:
                raise RuntimeError(f"tpm2_load: {r.stderr.strip()}")
            r2 = subprocess.run(
                ["tpm2_unseal", "-c", seal_ctx],
                capture_output=True, text=True,
            )
            if r2.returncode != 0:
                raise RuntimeError(f"tpm2_unseal: {r2.stderr.strip()}")
            return r2.stdout.rstrip("\n\r")
        finally:
            try:
                os.unlink(seal_ctx)
            except OSError:
                pass

    # ── Bot ──
    async def start_bot(self):
        self.client = AsyncClient(self.homeserver)
        self.client.access_token = self.access_token
        try:
            whoami = await self.client.whoami()
        except Exception:
            logger.exception("Matrix whoami 失败，bot 不可用")
            return
        self.client.user_id = whoami.user_id
        logger.info(f"Bot: {self.client.user_id}")
        self.client.add_event_callback(self.on_text, RoomMessageText)
        self.client.add_event_callback(self.on_reaction, ReactionEvent)

        sync_token_file = os.path.join(BASE_DIR, "sync_token")
        since = None
        try:
            with open(sync_token_file) as f:
                since = f.read().strip()
                if since:
                    logger.info("从 sync token 恢复")
        except FileNotFoundError:
            pass
        except Exception:
            logger.warning("读取 sync_token 失败", exc_info=True)

        retry_delay = 1
        while True:
            try:
                resp = await self.client.sync(timeout=30000, since=since, full_state=False)
                retry_delay = 1
                await self.client.run_response_callbacks([resp])
                if hasattr(resp, "next_batch") and resp.next_batch:
                    since = resp.next_batch
                    try:
                        with open(sync_token_file, "w") as f:
                            f.write(since)
                    except Exception:
                        logger.debug("保存 sync_token 失败", exc_info=True)
            except Exception:
                logger.exception(f"Matrix sync 失败，{retry_delay}s 后重试")
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 60)

    async def on_text(self, room, event):
        if room.room_id != self.room_id:
            return
        b = event.body.strip()
        if b == "lock proxy":
            async with self._lock:
                self.master_password = None
                if self.unlock_event and not self.unlock_event.is_set():
                    self.unlock_event.set()
                self.unlock_event = None
                self._unlock_msg_id = None
                self._unlock_in_progress = False
                self._kp = None
                for r in self.pending_requests.values():
                    r["approved"] = False
                    r["event"].set()
                self.pending_requests.clear()
                self.approval_msgs.clear()
            await self._say("🔒 Proxy 已锁定")
        elif b == "status":
            async with self._lock:
                s = "✅ 已解锁" if self.master_password else "🔒 未解锁"
                n_pending = len(self.pending_requests)
                n_secrets = len(self.pwd_to_token)
            await self._say(
                f"Proxy: {s} | 待审批: {n_pending}"
                f" | LLM secrets: {n_secrets}"
            )
        elif b == "forget secrets":
            async with self._lock:
                n = len(self.pwd_to_token)
                self.pwd_to_token.clear()
                self.token_to_pwd.clear()
            await self._say(f"🧹 已清除 {n} 个 LLM 密碼映射")

    async def on_reaction(self, room, event):
        if room.room_id != self.room_id:
            return
        ts = getattr(event, "server_timestamp", 0) or 0
        if ts > 0 and ts < self._start_ts:
            return
        sender = event.source.get("sender", "")
        if sender == self.client.user_id:
            return
        relates_to = event.source.get("content", {}).get("m.relates_to", {})
        orig = relates_to.get("event_id", "")
        key = relates_to.get("key", "")
        if not orig or key not in ("✅", "❎"):
            return
        say_text = None
        async with self._lock:
            if self.unlock_event and orig == self._unlock_msg_id:
                if key == "✅":
                    if not self._unlock_in_progress:
                        self._unlock_in_progress = True
                        task = asyncio.create_task(self._do_unlock())
                        task.add_done_callback(lambda t: t.exception())
                        self._unlock_task = task
                        say_text = "⏳ TPM 解封中…"
                else:
                    if not self.unlock_event.is_set():
                        self.unlock_event.set()
                    self.unlock_event = None
                    say_text = "❌ 解锁被拒绝"
            elif not (req_id := self.approval_msgs.get(orig)):
                pass
            elif not (req := self.pending_requests.get(req_id)):
                pass
            elif req["approved"] is not None:
                pass
            else:
                ok = (key == "✅")
                req["approved"] = ok
                req["event"].set()
                say_text = f"{key} 已{'批准' if ok else '拒绝'}: {req['entry']}"
        if say_text:
            await self._say(say_text)

    async def _do_unlock(self):
        try:
            pw = await asyncio.get_event_loop().run_in_executor(None, self._tpm_unseal)
            async with self._lock:
                if not self._unlock_in_progress:
                    return
                self.master_password = pw
                self._kp = None  # 密码变更，清缓存
                self._unlock_in_progress = False
                self._unlock_msg_id = None
                if self.unlock_event and not self.unlock_event.is_set():
                    self.unlock_event.set()
            await self._say("✅ TPM 解锁成功！主密码已加载到内存")
        except Exception:
            logger.exception("TPM fail")
            async with self._lock:
                self._unlock_in_progress = False
                if self.unlock_event and not self.unlock_event.is_set():
                    self.unlock_event.set()
                self.unlock_event = None
            await self._say("❌ TPM 解锁失败，详见服务端日志")

    async def _say(self, text):
        try:
            await self.client.room_send(
                self.room_id, "m.room.message",
                {"msgtype": "m.notice", "body": text},
            )
        except Exception:
            logger.debug("_say 发送失败", exc_info=True)

    async def _ask(self, text):
        resp = await self.client.room_send(
            self.room_id, "m.room.message",
            {"msgtype": "m.text", "body": text},
        )
        eid = getattr(resp, "event_id",
                      None) or (resp.get("event_id") if isinstance(resp, dict) else None)
        if eid:
            count = 0
            for k in ("✅", "❎"):
                try:
                    await self.client.room_send(self.room_id, "m.reaction", {
                        "m.relates_to": {
                            "event_id": eid, "key": k, "rel_type": "m.annotation",
                        }
                    })
                    count += 1
                except Exception:
                    logger.debug("_ask 添加 reaction 失败", exc_info=True)
            if count < 2:
                logger.warning(f"_ask 仅 {count}/2 个 reaction 成功, message 缺少审批按钮")
                return None
        return eid

    # ── Credential API (port 8877) ──
    async def start_credential_api(self, port=8877):
        app = web.Application()
        app.router.add_post("/credential", self.handle_credential)
        app.router.add_get("/health", self.handle_health)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", port).start()
        self._runners.append(runner)
        logger.info(f"Credential API → 0.0.0.0:{port}")

    async def handle_health(self, _):
        async with self._lock:
            return web.json_response({
                "status": "ok",
                "unlocked": self.master_password is not None,
                "pending": len(self.pending_requests),
                "llm_secrets": len(self.pwd_to_token),
            })

    async def handle_credential(self, request):
        # 频率限制：两次请求之间至少间隔 self._credential_min_interval 秒
        async with self._lock:
            now = time.monotonic()
            if now - self._last_credential_request < self._credential_min_interval:
                return web.json_response(
                    {"error": "请求过于频繁，请稍后再试"}, status=429)
            self._last_credential_request = now

        try:
            data = await request.json()
        except (json.JSONDecodeError, Exception):
            return web.json_response({"error": "invalid json"}, status=400)
        entry_name = data.get("entry", "").strip()
        field = data.get("field", "").strip()
        use_token = data.get("token", True)
        if not entry_name:
            return web.json_response({"error": "missing entry"}, status=400)

        # 解锁
        async with self._lock:
            if not self.master_password:
                if not self.unlock_event:
                    self.unlock_event = asyncio.Event()
                    need_ask = True
                else:
                    need_ask = False
                unlock_evt = self.unlock_event
            else:
                unlock_evt = None
                need_ask = False

        if need_ask:
            msg_id = await self._ask(
                "🔓 Proxy 未解锁\n点 ✅ 解锁（TPM 自动解封）\n点 ❎ 拒绝",
            )
            if msg_id is None:
                logger.error("解锁消息发送失败，Matrix 可能不可用")
                async with self._lock:
                    if self.unlock_event and not self.unlock_event.is_set():
                        self.unlock_event.set()
                return web.json_response({"error": "无法发送解锁消息"}, status=503)
            async with self._lock:
                self._unlock_msg_id = msg_id
        if unlock_evt is not None:
            try:
                await asyncio.wait_for(unlock_evt.wait(), timeout=300)
            except asyncio.TimeoutError:
                return web.json_response({"error": "解锁超时"}, status=408)

        # 审批
        async with self._lock:
            mp = self.master_password
            if not mp:
                return web.json_response({"error": "解锁失败"}, status=403)
            req_id = uuid.uuid4().hex[:8]
            evt = asyncio.Event()
            self.pending_requests[req_id] = {
                "entry": entry_name, "approved": None,
                "event": evt,
            }
        msg_id = await self._ask(f"🔑 凭据请求: {entry_name}\n点 ✅ 批准 或 ❎ 拒绝")
        if msg_id is None:
            async with self._lock:
                self.pending_requests.pop(req_id, None)
            return web.json_response({"error": "无法发送审批消息"}, status=503)
        async with self._lock:
            self.approval_msgs[msg_id] = req_id
        try:
            await asyncio.wait_for(evt.wait(), timeout=300)
        except asyncio.TimeoutError:
            async with self._lock:
                req = self.pending_requests.get(req_id)
                if req and req.get("approved") is True:
                    pass
                else:
                    self.pending_requests.pop(req_id, None)
                    for eid, rid in list(self.approval_msgs.items()):
                        if rid == req_id:
                            self.approval_msgs.pop(eid, None)
                    return web.json_response({"error": "审批超时"}, status=408)

        async with self._lock:
            req = self.pending_requests.get(req_id)
            approved = req.get("approved") if req else None
            self.pending_requests.pop(req_id, None)
            for eid, rid in list(self.approval_msgs.items()):
                if rid == req_id:
                    self.approval_msgs.pop(eid, None)
            if approved is not True:
                return web.json_response({"error": "审批被拒绝"}, status=403)

        # 取凭据（带 KeePass 缓存，锁内原子创建避免竞态）
        try:
            from pykeepass import PyKeePass
            loop = asyncio.get_running_loop()
            kp = None
            async with self._lock:
                kp = self._kp
                if kp is None:
                    kp = await loop.run_in_executor(
                        None,
                        lambda: PyKeePass(self.kdbx_path, password=mp,
                                          keyfile=self.keyfile_path))
                    self._kp = kp
            entry = await loop.run_in_executor(
                None,
                lambda: kp.find_entries(title=entry_name, first=True))
            if not entry:
                return web.json_response({"error": f"未找到 {entry_name}"}, status=404)

            if field:
                m = {"password": entry.password, "username": entry.username,
                     "url": entry.url, "title": entry.title}
                val = m.get(field)
                if val is None and hasattr(entry, "get_custom_property"):
                    val = entry.get_custom_property(field)
                if val is None:
                    return web.json_response({"error": f"无属性 {field}"}, status=404)
                return web.json_response({"value": await self._maybe_register(val, use_token)})

            props = {}
            if hasattr(entry, "get_custom_property"):
                for k in (entry.custom_properties or {}):
                    v = entry.get_custom_property(k)
                    if v:
                        props[k] = await self._maybe_register(v, use_token)
            result = {"title": await self._maybe_register(entry.title, use_token),
                      "username": await self._maybe_register(entry.username or "", use_token),
                      "password": await self._maybe_register(entry.password or "", use_token),
                      "url": await self._maybe_register(entry.url or "", use_token)}
            if props:
                result["custom_properties"] = props
            return web.json_response(result)
        except Exception:
            logger.exception("KeePass fail")
            return web.json_response({"error": "KeePass 内部错误"}, status=500)

    # ── LLM 代理 ──
    async def start_llm_proxies(self):
        if not self.proxies:
            logger.info("LLM 代理已禁用（未设置 LLM_* 环境变量）")
            return
        for port, upstream in sorted(self.proxies.items()):
            await self._start_one_proxy(port, upstream)

    async def _start_one_proxy(self, port, upstream):
        session = ClientSession(timeout=ClientTimeout(total=600, connect=30))

        async def handler(request):
            target_url = upstream + request.path_qs
            body = await request.read()
            body_text = body.decode("utf-8", errors="replace") if body else ""

            # 拍快照防 "forget secrets" 竞态
            snapshot_p2t = dict(self.pwd_to_token)
            snapshot_t2p = dict(self.token_to_pwd)

            if body_text:
                out_body = self._redact(body_text, snapshot_p2t).encode("utf-8")
            else:
                out_body = b""

            # 透传 Hermes 的所有 header（含 Authorization）
            headers = {}
            for k, v in request.headers.items():
                low = k.lower()
                if low in HOP_HEADERS:
                    continue
                headers[k] = v

            try:
                upstream_resp = await session.request(
                    request.method, target_url,
                    headers=headers, data=out_body,
                )
                
                content_type = upstream_resp.content_type or ""

                if content_type.startswith("text/event-stream"):
                    resp = web.StreamResponse(
                        status=upstream_resp.status,
                        headers={
                            k: v
                            for k, v in upstream_resp.headers.items()
                            if k.lower() not in HOP_HEADERS
                        },
                    )
                    await resp.prepare(request)

                    buf = ""
                    MAX_BUF = 1_048_576  # 1MB
                    try:
                        async for chunk in upstream_resp.content.iter_chunked(4096):
                            chunk_text = chunk.decode(
                                "utf-8", errors="replace"
                            )
                            buf += chunk_text
                            if len(buf.encode("utf-8")) > MAX_BUF:
                                logger.warning(
                                    "SSE buf 超过 1MB 上限，强制截断"
                                )
                                # 截断到最近换行符，保持行完整性
                                char_cut = max(0, len(buf) - MAX_BUF // 2)
                                nl = buf.find("\n", char_cut)
                                buf = buf[nl + 1:] if nl >= 0 else buf[-MAX_BUF // 2:]
                            while "\n" in buf:
                                line, buf = buf.split("\n", 1)
                                line = line.rstrip("\r")
                                if line.startswith("data:"):
                                    payload = line[5:]
                                    if payload.startswith(" "):
                                        payload = payload[1:]
                                    restored = "data: " + self._restore(
                                        payload, snapshot_t2p
                                    )
                                    await resp.write(
                                        (restored + "\n").encode("utf-8")
                                    )
                                else:
                                    await resp.write(
                                        (line + "\n").encode("utf-8")
                                    )
                    except (
                        ConnectionResetError,
                        ConnectionAbortedError,
                        BrokenPipeError,
                        ClientConnectionResetError,
                        asyncio.TimeoutError,
                    ) as e:
                        logger.debug(f"SSE 客户端断连: {e}")
                    if buf:
                        try:
                            restored_buf = self._restore(buf, snapshot_t2p)
                            await resp.write(restored_buf.encode("utf-8"))
                        except (
                            ConnectionResetError,
                            ConnectionAbortedError,
                            BrokenPipeError,
                        ):
                            logger.debug("SSE 客户端已断连，跳过残余缓冲写入")
                    try:
                        await resp.write_eof()
                    except (
                        ConnectionResetError,
                        ConnectionAbortedError,
                        BrokenPipeError,
                    ):
                        logger.debug("SSE write_eof 失败，客户端已断连")
                    return resp
                else:
                    resp_body = await upstream_resp.read()
                    resp_text = resp_body.decode(
                        "utf-8", errors="replace"
                    )
                    out_text = self._restore(resp_text, snapshot_t2p)
                    return web.Response(
                        body=out_text.encode("utf-8"),
                        status=upstream_resp.status,
                        headers={
                            k: v
                            for k, v in upstream_resp.headers.items()
                            if k.lower() not in HOP_HEADERS
                        },
                    )
            except Exception:
                logger.exception(
                    f"LLM 上游请求失败: {request.method} {target_url}"
                )
                raise


        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handler)

        app.on_cleanup.append(lambda _app: session.close())
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", port).start()
        self._runners.append(runner)
        logger.info(f"LLM 代理 → 0.0.0.0:{port} → {upstream}")

    async def run(self):
        tasks = [
            self.start_credential_api(8877),
            self.start_llm_proxies(),
            self.start_bot(),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.error(f"服务启动失败: {r}")


def main():
    import signal as _signal
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    if len(sys.argv) < 4:
        print(
            f"用法: {sys.argv[0]} <homeserver> <room_id> <access_token>",
            file=sys.stderr,
        )
        print("\nLLM 代理通过环境变量配置：", file=sys.stderr)
        print("  LLM_8878=https://api.opencode.ai/v1", file=sys.stderr)
        print("  LLM_8879=https://api.deepseek.com/v1", file=sys.stderr)
        sys.exit(1)
    p = CredentialProxy(sys.argv[1], sys.argv[2], sys.argv[3])

    async def shutdown(sig):
        if p._shutting_down:
            return
        p._shutting_down = True
        logger.info(f"收到信号 {sig.name}，正在优雅关闭…")
        await p._say("🔌 Proxy 正在关闭…")
        async with p._lock:
            p.master_password = None
            p._kp = None
            if p.unlock_event and not p.unlock_event.is_set():
                p.unlock_event.set()
            for r in p.pending_requests.values():
                if not r["event"].is_set():
                    r["event"].set()
        for runner in p._runners:
            await runner.cleanup()
        p._runners.clear()
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for s in (_signal.SIGTERM, _signal.SIGINT):
        loop.add_signal_handler(s, lambda s=s: asyncio.create_task(shutdown(s)))
    try:
        loop.run_until_complete(p.run())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        loop.close()
        logger.info("Proxy 已关闭")


if __name__ == "__main__":
    main()
