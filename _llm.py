"""LlmMixin — LLM API 反向代理：脱敏请求 → 上游 → 还原响应。"""
import logging

from aiohttp import web, ClientSession, ClientTimeout

from _matrix import SSE_CLIENT_GONE, HOP_HEADERS
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

                        byte_buf = b""
                        try:
                            async for chunk in upstream_resp.content.iter_chunked(
                                SSE_CHUNK_SIZE,
                            ):
                                byte_buf += chunk
                                # 先处理完整行，再检查缓冲区大小（防止截断丢数据）
                                while b"\n" in byte_buf:
                                    line_bytes, byte_buf = byte_buf.split(
                                        b"\n", 1,
                                    )
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
                                        "SSE 缓冲区超过 1MB 上限，丢弃残余数据"
                                    )
                                    byte_buf = b""
                        except SSE_CLIENT_GONE as e:
                            logger.debug(f"SSE 客户端断连: {e}")
                        # 流结束后丢弃不完整的残余行
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
                    f"LLM 上游请求失败: {request.method} {target_url}"
                )
                raise

        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handler)
        # 注意：不在此处注册 session.close() — _shared_session 由 shutdown() 统一关闭
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", port).start()
        self._runners.append(runner)
        logger.info(f"LLM 代理 → 0.0.0.0:{port} → {upstream}")
