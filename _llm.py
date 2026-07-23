"""LlmMixin — LLM API 反向代理：脱敏请求 → 上游 → 还原响应。"""
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
            target_url = upstream + request.path_qs
            body = await request.read()
            body_text = body.decode("utf-8", errors="replace") if body else ""

            # 拍快照防 "forget secrets" 竞态（需持锁，防快照不一致）
            async with self._lock:
                snapshot_p2t = dict(self.pwd_to_token)
                snapshot_t2p = dict(self.token_to_pwd)

            if body_text:
                out_body = self._redact(body_text, snapshot_p2t).encode("utf-8")
                # 收集本次请求实际使用的 token，仅还原这些（防 LLM 幻觉泄露）
                used_tokens = set()
                for m in TOKEN_RE.finditer(out_body):
                    used_tokens.add(m.group().decode())
                active_t2p = {
                    t: p for t, p in snapshot_t2p.items()
                    if t in used_tokens
                }
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

                        byte_buf = bytearray()
                        try:
                            async for chunk in upstream_resp.content.iter_chunked(
                                SSE_CHUNK_SIZE,
                            ):
                                byte_buf.extend(chunk)
                                # 先处理完整行，再检查缓冲区大小（防止截断丢数据）
                                while (idx := byte_buf.find(b"\n")) >= 0:
                                    line_bytes = bytes(byte_buf[:idx])
                                    del byte_buf[:idx + 1]
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
                                # 处理完后检查残余缓冲区
                                if len(byte_buf) > SSE_MAX_BUF:
                                    logger.warning(
                                        "SSE 缓冲区超过 1MB 上限，保留最后一个部分行"
                                    )
                                    # 保留最后一个 \n 之后的数据（部分行），避免截断丢失数据
                                    last_nl = byte_buf.rfind(b"\n")
                                    if last_nl >= 0:
                                        byte_buf = bytearray(byte_buf[last_nl + 1:])
                                    # 如果退到只剩部分行仍然超 1MB，则硬截断
                                    if len(byte_buf) > SSE_MAX_BUF:
                                        byte_buf = bytearray()
                        except SSE_CLIENT_GONE as e:
                            logger.debug("SSE 客户端断连: %s", e)
                        # 流结束后写入残余字节再 EOF
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
                            except (ConnectionResetError,
                                    ConnectionAbortedError,
                                    BrokenPipeError):
                                logger.debug("SSE 残余写入失败")
                        try:
                            await resp.write_eof()
                        except (ConnectionResetError,
                                ConnectionAbortedError,
                                BrokenPipeError):
                            logger.debug(
                                "SSE write_eof 失败，客户端已断连"
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
                    "LLM 上���请求失败: %s %s", request.method, target_url,
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
