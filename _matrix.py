"""MatrixMixin — Matrix Bot：同步、消息处理、反应审批。"""
import asyncio
import logging
import os

from aiohttp.client_exceptions import ClientConnectionResetError
from nio import AsyncClient, RoomMessageText, ReactionEvent

logger = logging.getLogger("credential-proxy")

# ── Constants ──
SYNC_TIMEOUT = 30000          # Matrix sync timeout (ms)
MAX_RETRY_DELAY = 60          # 重试退避上限 (s)
REACTION_APPROVE = "✅"
REACTION_REJECT = "❎"
REACTIONS = (REACTION_APPROVE, REACTION_REJECT)
CMD_LOCK = "lock proxy"
CMD_STATUS = "status"
CMD_FORGET = "forget secrets"

# 客户端断连时 SSE 写入可能抛出的异常
SSE_CLIENT_GONE = (
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
    ClientConnectionResetError,
    asyncio.TimeoutError,
)

# 透传时需剥离的逐跳头
HOP_HEADERS = frozenset({
    "host", "transfer-encoding", "content-length",
    "content-encoding", "connection", "keep-alive", "te",
})


class MatrixMixin:
    """Mixin: Matrix bot 生命周期、消息处理、审批交互。"""

    # ── Bot lifecycle ──

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

        sync_token_file = os.path.join(self._base_dir, "sync_token")
        since = None
        try:
            with open(sync_token_file) as f:
                since = f.read().strip()
                if since:
                    logger.info("从 sync token 恢复")
        except FileNotFoundError:
            pass
        except Exception:
            logger.exception("读取 sync_token 失败")

        retry_delay = 1
        while not self._shutting_down:
            try:
                resp = await self.client.sync(
                    timeout=SYNC_TIMEOUT, since=since, full_state=False,
                )
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
                retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY)

    # ── Text commands ──

    async def on_text(self, room, event):
        if room.room_id != self.room_id:
            return
        body = event.body.strip()
        if body == CMD_LOCK:
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
        elif body == CMD_STATUS:
            async with self._lock:
                s = "✅ 已解锁" if self.master_password else "🔒 未解锁"
                n_pending = len(self.pending_requests)
                n_secrets = len(self.pwd_to_token)
            await self._say(
                f"Proxy: {s} | 待审批: {n_pending}"
                f" | LLM secrets: {n_secrets}"
            )
        elif body == CMD_FORGET:
            async with self._lock:
                n = len(self.pwd_to_token)
                self.pwd_to_token.clear()
                self.token_to_pwd.clear()
            await self._say(f"🧹 已清除 {n} 个 LLM 密码映射")

    # ── Reaction handling ──

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
        if not orig or key not in REACTIONS:
            return

        say_text = None
        async with self._lock:
            if self.unlock_event and orig == self._unlock_msg_id:
                if key == REACTION_APPROVE:
                    if not self._unlock_in_progress:
                        self._unlock_in_progress = True
                        self._unlock_generation += 1
                        gen = self._unlock_generation
                        task = asyncio.create_task(self._do_unlock(gen))
                        task.add_done_callback(
                            lambda t, _logger=logger: (
                                _logger.error("解锁任务异常", exc_info=t.exception())
                                if t.exception() else None
                            )
                        )
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
                ok = (key == REACTION_APPROVE)
                req["approved"] = ok
                req["event"].set()
                say_text = f"{key} 已{'批准' if ok else '拒绝'}: {req['entry']}"
        if say_text:
            await self._say(say_text)

    # ── Messaging ──

    async def _say(self, text: str):
        """发送纯文本通知。client 未就绪时静默跳过。"""
        if self.client is None:
            return
        try:
            await self.client.room_send(
                self.room_id, "m.room.message",
                {"msgtype": "m.notice", "body": text},
            )
        except Exception:
            logger.debug("_say 发送失败", exc_info=True)

    async def _ask(self, text: str) -> str | None:
        """发送审批消息并预加 ✅❎ reaction，返回 event_id。"""
        resp = await self.client.room_send(
            self.room_id, "m.room.message",
            {"msgtype": "m.text", "body": text},
        )
        eid = (
            getattr(resp, "event_id", None)
            or (resp.get("event_id") if isinstance(resp, dict) else None)
        )
        if eid:
            count = 0
            for k in REACTIONS:
                try:
                    await self.client.room_send(self.room_id, "m.reaction", {
                        "m.relates_to": {
                            "event_id": eid, "key": k,
                            "rel_type": "m.annotation",
                        }
                    })
                    count += 1
                except Exception:
                    logger.debug("_ask 添加 reaction 失败", exc_info=True)
            if count < len(REACTIONS):
                logger.warning(
                    f"_ask 仅 {count}/{len(REACTIONS)} 个 reaction 成功"
                    "，消息仍然可用"
                )
        return eid

    # ── Utilities ──

    @staticmethod
    def _filter_hop_headers(headers: dict) -> dict:
        """过滤逐跳头，返回可安全透传的 headers。"""
        return {
            k: v for k, v in headers.items()
            if k.lower() not in HOP_HEADERS
        }
