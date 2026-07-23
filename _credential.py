"""CredentialMixin — HTTP API：凭据查询（/credential）+ 健康检查（/health）。"""
import asyncio
import logging
import os
import time
import uuid

from aiohttp import web

try:
    from pykeepass import PyKeePass
except ImportError:
    PyKeePass = None

logger = logging.getLogger("credential-proxy")

# ── Constants ──
_CREDENTIAL_PORT_RAW = os.environ.get("CREDENTIAL_PORT", "8877")
try:
    _CREDENTIAL_API_PORT = int(_CREDENTIAL_PORT_RAW)
except (ValueError, TypeError):
    _CREDENTIAL_API_PORT = 8877
UNLOCK_TIMEOUT = 300       # 解锁等待超时 (s)
APPROVAL_TIMEOUT = 300     # 审批等待超时 (s)
RATE_LIMIT_INTERVAL = 2.0  # 凭据请求最小间隔 (s)


class CredentialMixin:
    """Mixin: 凭据 HTTP API 及 KeePass 查询。"""

    # ── API startup ──

    async def start_credential_api(self, port: int = _CREDENTIAL_API_PORT):
        app = web.Application()
        app.router.add_post("/credential", self.handle_credential)
        app.router.add_get("/health", self.handle_health)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", port).start()
        self._runners.append(runner)
        logger.info("Credential API → 0.0.0.0:%d", port)

    # ── Health ──

    async def handle_health(self, _request) -> web.Response:
        """健康检查端点（无锁 — 只读属性快照）。"""
        return web.json_response({
            "status": "ok",
            "unlocked": self.master_password is not None,
            "pending": len(self.pending_requests),
            "llm_secrets": len(self.pwd_to_token),
        })

    # ── Credential ──

    async def handle_credential(self, request) -> web.Response:
        # 频率限制 + 解锁状态检查（合并为一次锁）
        async with self._lock:
            now = time.monotonic()
            if now - self._last_credential_request < RATE_LIMIT_INTERVAL:
                return web.json_response(
                    {"error": "请求过于频繁，请稍后再试"}, status=429,
                )
            self._last_credential_request = now

            # 解锁阶段（与频率限制共享同一次锁）
            need_ask = False
            if not self.master_password:
                if not self.unlock_event:
                    # 首次触发解锁：创建 Event 并请求审批
                    self.unlock_event = asyncio.Event()
                    need_ask = True
                elif self._unlock_in_progress:
                    # 解锁已在进行中：不重复发审批消息，只等待
                    need_ask = False
                unlock_evt = self.unlock_event
            else:
                unlock_evt = None
                need_ask = False

        # JSON 解析与参数提取（在锁外执行）
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "JSON 格式错误"}, status=400)

        entry_name = data.get("entry", "").strip()
        field = data.get("field", "").strip()
        use_token = data.get("token", True)
        if not entry_name:
            return web.json_response({"error": "缺少 entry 参数"}, status=400)

        if need_ask:
            msg_id = await self._ask(
                "🔓 Proxy 未解锁\n点 ✅ 解锁（TPM 自动解封）\n点 ❎ 拒绝",
            )
            if msg_id is None:
                logger.error("解锁消息发送失败，Matrix 可能不可用")
                async with self._lock:
                    if self.unlock_event and not self.unlock_event.is_set():
                        self.unlock_event.set()
                    self.unlock_event = None
                    self._unlock_msg_id = None
                return web.json_response(
                    {"error": "无法发送解锁消息"}, status=503,
                )
            async with self._lock:
                self._unlock_msg_id = msg_id

        if unlock_evt is not None:
            try:
                await asyncio.wait_for(unlock_evt.wait(), timeout=UNLOCK_TIMEOUT)
            except TimeoutError:
                async with self._lock:
                    if self.unlock_event and not self.unlock_event.is_set():
                        self.unlock_event.set()
                    self.unlock_event = None
                    self._unlock_msg_id = None
                return web.json_response({"error": "解锁超时"}, status=408)

        # ── 审批阶段 ──
        async with self._lock:
            mp = self.master_password
            if not mp:
                return web.json_response({"error": "解锁失败"}, status=403)
            req_id = uuid.uuid4().hex[:8]
            evt = asyncio.Event()
            self.pending_requests[req_id] = {
                "entry": entry_name, "approved": None, "event": evt,
            }

        msg_id = await self._ask(
            f"🔑 凭据请求: {entry_name}\n点 ✅ 批准 或 ❎ 拒绝",
        )
        if msg_id is None:
            async with self._lock:
                self._cleanup_request(req_id)
            return web.json_response(
                {"error": "无法发送审批消息"}, status=503,
            )
        async with self._lock:
            self.approval_msgs[msg_id] = req_id

        try:
            await asyncio.wait_for(evt.wait(), timeout=APPROVAL_TIMEOUT)
        except TimeoutError:
            async with self._lock:
                req = self.pending_requests.get(req_id)
                if req and req.get("approved") is True:
                    # 刚好在超时前被批准 — 继续正常流程
                    pass
                else:
                    self._cleanup_request(req_id)
                    return web.json_response({"error": "审批超时"}, status=408)

        async with self._lock:
            req = self.pending_requests.get(req_id)
            approved = req.get("approved") if req else None
            self._cleanup_request(req_id)
            if approved is not True:
                return web.json_response({"error": "审批被拒绝"}, status=403)

        # ── 取凭据 ──
        if self.kdbx_path is None:
            return web.json_response(
                {"error": "密码库未配置（db/ 目录下无 .kdbx 文件）"},
                status=503,
            )
        try:
            if PyKeePass is None:
                return web.json_response(
                    {"error": "pykeepass 未安装"}, status=503,
                )
            loop = asyncio.get_running_loop()
            # _kp_semaphore 序列化所有 KeePass 访问（PyKeePass 非线程安全）
            async with self._kp_semaphore:
                async with self._lock:
                    kp = self._kp
                if kp is None:
                    kp = await loop.run_in_executor(
                        None,
                        lambda: PyKeePass(
                            self.kdbx_path, password=mp,
                            keyfile=self.keyfile_path,
                        ),
                    )
                    async with self._lock:
                        if self._kp is None:
                            self._kp = kp
                        else:
                            kp = self._kp
                entry = await loop.run_in_executor(
                    None,
                    lambda: kp.find_entries(title=entry_name, first=True),
                )
            if not entry:
                return web.json_response(
                    {"error": f"未找到 {entry_name}"}, status=404,
                )

            if field:
                m = {
                    "password": entry.password,
                    "username": entry.username,
                    "url": entry.url,
                    "title": entry.title,
                }
                val = m.get(field)
                if val is None and hasattr(entry, "get_custom_property"):
                    val = entry.get_custom_property(field)
                if val is None:
                    return web.json_response(
                        {"error": f"无属性 {field}"}, status=404,
                    )
                return web.json_response({
                    "value": await self._maybe_register(val, use_token),
                })

            props = {}
            if hasattr(entry, "get_custom_property"):
                for k in (entry.custom_properties or {}):
                    v = entry.get_custom_property(k)
                    if v:
                        props[k] = await self._maybe_register(v, use_token)
            result = {
                "title": await self._maybe_register(entry.title, use_token),
                "username": await self._maybe_register(
                    entry.username or "", use_token,
                ),
                "password": await self._maybe_register(
                    entry.password or "", use_token,
                ),
                "url": await self._maybe_register(
                    entry.url or "", use_token,
                ),
            }
            if props:
                result["custom_properties"] = props
            return web.json_response(result)
        except Exception:
            logger.exception("KeePass 查询失败")
            return web.json_response({"error": "KeePass 内部错误"}, status=500)

    # ── Helpers ──

    def _cleanup_request(self, req_id: str):
        """安全清理审批请求及其关联的 approval 消息映射。
        调用者必须持有 self._lock。"""
        self.pending_requests.pop(req_id, None)
        for eid, rid in list(self.approval_msgs.items()):
            if rid == req_id:
                self.approval_msgs.pop(eid, None)
