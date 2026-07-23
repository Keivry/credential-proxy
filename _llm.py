"""LlmMixin — LLM API 反向代理：脱敏请求 → 上游 → 还原响应。"""
import json
import logging

from aiohttp import ClientSession, ClientTimeout, web

from _matrix import SSE_CLIENT_GONE
from _token import TOKEN_RE

logger = logging.getLogger("credential-proxy")

# ── Constants ──
UPSTREAM_TOTAL_TIMEOUT = 600    # 上游总超时 (s)
UPSTREAM_CONNECT_TIMEOUT = 30   # 上游连接超时 (s)
SSE_CHUNK_SIZE = 4096           # SSE 流式块大小
SSE_MAX_BUF = 1_048_576         # SSE 缓冲区上限 (1MB)


def _mk_sse_event(content: str, finish_reason: str | None = None) -> str:
    """Build OpenAI-compatible SSE data event JSON.
    
    Content is always included when non-empty — OpenAI allows
    content + finish_reason in the same delta event.
    """
    delta = {"content": content} if content else {}
    event = json.dumps({
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
    })
    return f"data: {event}\n"


class LlmMixin:
    """Mixin: LLM 反向代理，脱敏/还原。"""

    # ── Startup ──

    async def start_llm_proxies(self):
        if not self.proxies:
            logger.info("LLM 代理已禁用（未设置 LLM_* 环境变量）")
            return
        # 共享 ClientSession：所有端口共用一个连接池
        self._shared_session = ClientSession(
            timeout=ClientTimeout(
                total=UPSTREAM_TOTAL_TIMEOUT,
                connect=UPSTREAM_CONNECT_TIMEOUT,
            ),
        )
        for port, upstream in sorted(self.proxies.items()):
            await self._start_one_proxy(port, upstream)

    async def _start_one_proxy(self, port: int, upstream: str):
        session = self._shared_session  # 共享会话

        async def handler(request):
            target_url = upstream.rstrip("/") + "/" + request.path_qs.lstrip("/")
            body = await request.read()
            body_text = body.decode("utf-8", errors="replace") if body else ""

            # 拍快照防 "forget secrets" 竞态（需持锁，防快照不一致）
            async with self._lock:
                snapshot_p2t = dict(self.pwd_to_token)
                snapshot_t2p = dict(self.token_to_pwd)

            if body_text:
                out_body = self._redact(body_text, snapshot_p2t).encode("utf-8")
                # 快速路径：无 token 时不扫描
                if snapshot_t2p and b"__VG_CRED_" in out_body:
                    # 收集本次请求实际使用的 token，仅还原这些（防 LLM 幻觉泄露）
                    used_tokens = set()
                    for m in TOKEN_RE.finditer(out_body):
                        used_tokens.add(m.group().decode())
                    active_t2p = {
                        t: p for t, p in snapshot_t2p.items()
                        if t in used_tokens
                    }
                else:
                    active_t2p = {}
            else:
                out_body = b""
                active_t2p = {}

            # 透传 Hermes headers（过滤逐跳头）
            headers = self._filter_hop_headers(dict(request.headers))

            try:
                # async with 确保上游响应在 SSE 客户端断连时正确释放连接
                async with session.request(
                    request.method, target_url,
                    headers=headers, data=out_body,
                ) as upstream_resp:

                    content_type = upstream_resp.content_type or ""

                    if content_type.startswith("text/event-stream"):
                        # ── SSE 流式 ──
                        resp = web.StreamResponse(
                            status=upstream_resp.status,
                            headers=self._filter_hop_headers(
                                dict(upstream_resp.headers),
                            ),
                        )
                        await resp.prepare(request)

                        if active_t2p:
                            # ── JSON-aware 流式 token 还原（广义 Plan C） ──
                            content_buf = ""  # 累积 delta.content 片段，O(1) 单字符串追加
                            byte_buf = bytearray()

                            async def _flush(c: str, fr: str | None = None):
                                """flush 内容作为 SSE 事件并清空 content_buf。"""
                                nonlocal content_buf
                                if c or fr:
                                    if c:
                                        c = self._restore(c, active_t2p)
                                    await resp.write(
                                        _mk_sse_event(c, fr).encode(),
                                    )
                                content_buf = ""

                            try:
                                async for chunk in upstream_resp.content.iter_chunked(
                                    SSE_CHUNK_SIZE,
                                ):
                                    byte_buf.extend(chunk)
                                    pos = 0
                                    while (idx := byte_buf.find(
                                        b"\n", pos,
                                    )) >= 0:
                                        line_bytes = bytes(byte_buf[pos:idx])
                                        pos = idx + 1
                                        line = line_bytes.decode(
                                            "utf-8", errors="replace",
                                        ).rstrip("\r")

                                        # 非 data 行：还原后透传（防 token 泄漏）
                                        if not line.startswith("data:"):
                                            await resp.write(
                                                (self._restore(line, active_t2p)
                                                 + "\n").encode("utf-8"),
                                            )
                                            continue

                                        payload = line[5:]
                                        if payload.startswith(" "):
                                            payload = payload[1:]

                                        # [DONE] 标记：先 flush 累积内容
                                        if payload.strip() == "[DONE]":
                                            await _flush(content_buf)
                                            await resp.write(
                                                "data: [DONE]\n".encode(),
                                            )
                                            continue

                                        # 解析 JSON，提取 delta content
                                        try:
                                            parsed = json.loads(payload)
                                            choices = parsed.get("choices", [])
                                            choice = choices[0] if choices else {}
                                            delta = choice.get("delta", {})
                                            finish_reason = choice.get(
                                                "finish_reason",
                                            )

                                            if "content" not in delta:
                                                # 非 content 事件：先 flush 累积内容，再还原后写出
                                                await _flush(content_buf)
                                                await resp.write(
                                                    (self._restore(line, active_t2p)
                                                     + "\n").encode("utf-8"),
                                                )
                                                continue

                                            # 追加 content 片段，还原 token
                                            content_buf += delta["content"]
                                            restored = self._restore(
                                                content_buf, active_t2p,
                                            )

                                            # 找安全 flush 点
                                            last_us = restored.rfind("__")
                                            safe = restored
                                            pending = ""
                                            if last_us >= 0:
                                                suffix = restored[last_us:]
                                                maybe_prefix = any(
                                                    t.startswith(suffix)
                                                    for t in active_t2p
                                                )
                                                if maybe_prefix:
                                                    safe = restored[:last_us]
                                                    pending = suffix

                                            # flush 安全部分
                                            if safe:
                                                await resp.write(
                                                    _mk_sse_event(safe).encode(),
                                                )
                                            content_buf = pending

                                            if finish_reason:
                                                content_buf = self._restore(
                                                    content_buf, active_t2p,
                                                )
                                                await resp.write(
                                                    _mk_sse_event(
                                                        content_buf, finish_reason,
                                                    ).encode(),
                                                )
                                                content_buf = ""

                                        except (
                                            json.JSONDecodeError,
                                            KeyError,
                                            IndexError,
                                            TypeError,
                                        ):
                                            logger.warning(
                                                "SSE JSON 解析失败，"
                                                "还原后转发: %s...",
                                                payload[:80],
                                            )
                                            await resp.write(
                                                (self._restore(line, active_t2p)
                                                 + "\n").encode("utf-8"),
                                            )

                                    # Trim processed portion (O(1) memmove vs O(n²) del)
                                    if pos > 0:
                                        byte_buf = (
                                            bytearray(byte_buf[pos:])
                                            if pos < len(byte_buf)
                                            else bytearray()
                                        )

                                    # 缓冲区溢出保护
                                    if len(byte_buf) > SSE_MAX_BUF:
                                        logger.warning(
                                            "SSE 缓冲区超过 1MB 上限，"
                                            "保留最后一个部分行",
                                        )
                                        last_nl = byte_buf.rfind(b"\n")
                                        if last_nl >= 0:
                                            byte_buf = bytearray(
                                                byte_buf[last_nl + 1:],
                                            )
                                        if len(byte_buf) > SSE_MAX_BUF:
                                            byte_buf = bytearray()
                            except SSE_CLIENT_GONE as e:
                                logger.debug("SSE 客户端断连: %s", e)

                            # 流结束：flush 残留
                            if content_buf:
                                content_buf = self._restore(content_buf, active_t2p)
                                try:
                                    await resp.write(
                                        _mk_sse_event(content_buf).encode(),
                                    )
                                except (
                                    ConnectionResetError,
                                    ConnectionAbortedError,
                                    BrokenPipeError,
                                ):
                                    logger.debug("SSE 残余写入失败")
                            if byte_buf:
                                try:
                                    residual = byte_buf.decode(
                                        "utf-8", errors="replace",
                                    )
                                    restored = self._restore(
                                        residual, active_t2p,
                                    )
                                    await resp.write(
                                        restored.encode("utf-8"),
                                    )
                                except (
                                    ConnectionResetError,
                                    ConnectionAbortedError,
                                    BrokenPipeError,
                                ):
                                    logger.debug("SSE 残余写入失败")
                            try:
                                await resp.write_eof()
                            except (
                                ConnectionResetError,
                                ConnectionAbortedError,
                                BrokenPipeError,
                            ):
                                logger.debug(
                                    "SSE write_eof 失败，客户端已断连",
                                )
                        else:
                            # ── Fast path: active_t2p 为空，逐行 text-level 还原 ──
                            byte_buf = bytearray()
                            try:
                                async for chunk in upstream_resp.content.iter_chunked(
                                    SSE_CHUNK_SIZE,
                                ):
                                    byte_buf.extend(chunk)
                                    # 先处理完整行，再检查缓冲区（防截断丢数据）
                                    pos = 0
                                    while (idx := byte_buf.find(
                                        b"\n", pos,
                                    )) >= 0:
                                        line_bytes = bytes(byte_buf[pos:idx])
                                        pos = idx + 1
                                        line = line_bytes.decode(
                                            "utf-8", errors="replace",
                                        ).rstrip("\r")
                                        if line.startswith("data:"):
                                            payload = line[5:]
                                            if payload.startswith(" "):
                                                payload = payload[1:]
                                            restored = "data: " + self._restore(
                                                payload, active_t2p,
                                            )
                                            await resp.write(
                                                (restored + "\n").encode("utf-8"),
                                            )
                                        else:
                                            await resp.write(
                                                (line + "\n").encode("utf-8"),
                                            )
                                    # Trim processed portion
                                    if pos > 0:
                                        byte_buf = (
                                            bytearray(byte_buf[pos:])
                                            if pos < len(byte_buf)
                                            else bytearray()
                                        )
                                    if len(byte_buf) > SSE_MAX_BUF:
                                        logger.warning(
                                            "SSE 缓冲区超过 1MB 上限，"
                                            "保留最后一个部分行",
                                        )
                                        last_nl = byte_buf.rfind(b"\n")
                                        if last_nl >= 0:
                                            byte_buf = bytearray(
                                                byte_buf[last_nl + 1:],
                                            )
                                        if len(byte_buf) > SSE_MAX_BUF:
                                            byte_buf = bytearray()
                            except SSE_CLIENT_GONE as e:
                                logger.debug("SSE 客户端断连: %s", e)
                            # 残余字节 + EOF
                            if byte_buf:
                                try:
                                    residual = byte_buf.decode(
                                        "utf-8", errors="replace",
                                    )
                                    restored = self._restore(
                                        residual, active_t2p,
                                    )
                                    await resp.write(
                                        restored.encode("utf-8"),
                                    )
                                except (
                                    ConnectionResetError,
                                    ConnectionAbortedError,
                                    BrokenPipeError,
                                ):
                                    logger.debug("SSE 残余写入失败")
                            try:
                                await resp.write_eof()
                            except (
                                ConnectionResetError,
                                ConnectionAbortedError,
                                BrokenPipeError,
                            ):
                                logger.debug(
                                    "SSE write_eof 失败，客户端已断连",
                                )
                        return resp
                    else:
                        # ── 非流式 ──
                        resp_body = await upstream_resp.read()
                        resp_text = resp_body.decode(
                            "utf-8", errors="replace",
                        )
                        out_text = self._restore(resp_text, active_t2p)
                        return web.Response(
                            body=out_text.encode("utf-8"),
                            status=upstream_resp.status,
                            headers=self._filter_hop_headers(
                                dict(upstream_resp.headers),
                            ),
                        )
            except Exception:
                logger.exception(
                    "LLM 上游请求失败: %s %s", request.method, target_url,
                )
                raise

        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handler)
        # 注意：不在此处注册 session.close() — _shared_session 由 shutdown() 统一关闭
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", port).start()
        self._runners.append(runner)
        logger.info("LLM 代理 → 0.0.0.0:%d → %s", port, upstream)
