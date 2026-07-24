"""LlmMixin — LLM API 反向代理：脱敏请求 → 上游 → 还原响应。"""

import asyncio
import json
import logging
import os
import re as _re
import uuid as _uuid

from aiohttp import ClientSession, ClientTimeout, web

from _sse import SSE_CLIENT_GONE, filter_hop_headers
from _token import TOKEN_RE

logger = logging.getLogger('credential-proxy')

# ── Constants ──
UPSTREAM_TOTAL_TIMEOUT = 600  # 上游总超时 (s)
UPSTREAM_CONNECT_TIMEOUT = 30  # 上游连接超时 (s)
SSE_CHUNK_SIZE = 4096  # SSE 流式块大小
SSE_MAX_BUF = 1_048_576  # SSE 缓冲区上限 (1MB)
# 流末清理：匹配不完整 token 前缀（已还原的完整 token 不会被此匹配）
_PARTIAL_TOKEN_RE = _re.compile(r'__VG_CRED_\d*$')
# Debug 开关：设置环境变量 CREDENTIAL_PROXY_DEBUG_DIR 开启
_DEBUG_DIR = os.environ.get('CREDENTIAL_PROXY_DEBUG_DIR', '')


def _extract_conv_id(data: dict) -> str | None:
    """从 SSE data JSON 中提取 conversation ID。

    兼容 OpenAI 格式 (data.id) 和 Anthropic 格式 (data.message.id)。
    """
    if 'id' in data:
        return data['id']
    if isinstance(data.get('message'), dict):
        return data['message'].get('id')
    return None


def _save_request_body(conv_id: str, body: bytes) -> None:
    """保存原始请求 JSON body 到 debug 目录，以 conversation ID 命名。

    仅在 LLM 对话 endpoint 且 CREDENTIAL_PROXY_DEBUG_DIR 设置时调用。
    单次写入 request.json，不追加，不保存上游响应。
    """
    if not _DEBUG_DIR or not body:
        return
    path = os.path.join(_DEBUG_DIR, conv_id, 'request.json')
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(body)
    except OSError as exc:
        logger.debug('保存调试请求失败: %s', exc)


async def _save_response_line(resp_log_path: str, payload: str) -> None:
    """追加一行原始 payload 到 response.jsonl。

    通过 run_in_executor 异步写入，不阻塞 SSE 流式转发。
    """
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _append_jsonl_line, resp_log_path, payload)


def _append_jsonl_line(path: str, line: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a', encoding='utf-8') as f:
        f.write(line + '\n')


def _mk_sse_event(content: str, finish_reason: str | None = None) -> str:
    """Build OpenAI-compatible SSE data event JSON.

    Content is always included when non-empty — OpenAI allows
    content + finish_reason in the same delta event.
    """
    delta = {'content': content} if content else {}
    event = json.dumps(
        {
            'choices': [{'index': 0, 'delta': delta, 'finish_reason': finish_reason}],
            'object': 'chat.completion.chunk',
        }
    )
    return f'data: {event}\n'


def _sanitize_json(text: str) -> str:
    """Replace unescaped control chars within JSON string values."""
    result = []
    in_string = False
    escape = False
    for ch in text:
        if escape:
            result.append(ch)
            escape = False
            continue
        if ch == '\\':
            result.append(ch)
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            result.append(ch)
            continue
        if in_string and (ord(ch) < 0x20 or ch == '\x7f'):
            # Unescaped control char inside string → replace with escaped \n
            result.append('\\n')
            continue
        result.append(ch)
    return ''.join(result)


class LlmMixin:
    """Mixin: LLM 反向代理，脱敏/还原。"""

    # ── Startup ──

    async def start_llm_proxies(self):
        if not self.proxies:
            logger.info('LLM 代理已禁用（未设置 LLM_* 环境变量）')
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
            req_id = (
                request.headers.get('x-request-id', '')
                or str(_uuid.uuid4()).replace('-', '')[:16]
            )
            tail = request.match_info['tail']
            target_url = f'{upstream.rstrip("/")}/{tail}'
            if request.query_string:
                target_url += '?' + request.query_string
            body = await request.read()
            body_text = body.decode('utf-8', errors='replace') if body else ''

            # 仅对 LLM 对话 endpoint 保存调试原始请求 JSON（非对话如 /v1/models 不保存）
            _debug_save_eligible = bool(_DEBUG_DIR) and (
                tail.rstrip('/').endswith('chat/completions')
                or tail.rstrip('/').endswith('v1/messages')
            )
            _debug_saved = False  # 标记是否已在 SSE 响应中保存过

            # 拍快照防 "forget secrets" 竞态（需持锁，防快照不一致）
            async with self._lock:
                snapshot_p2t = dict(self.pwd_to_token)
                snapshot_t2p = dict(self.token_to_pwd)

            if body_text:
                out_body = self._redact(body_text, snapshot_p2t).encode('utf-8')
                # 快速路径：无 token 时不扫描
                if snapshot_t2p and b'__VG_CRED_' in out_body:
                    # 收集本次请求实际使用的 token，仅还原这些（防 LLM 幻觉泄露）
                    used_tokens = set()
                    for m in TOKEN_RE.finditer(out_body):
                        used_tokens.add(m.group().decode())
                    active_t2p = {
                        t: p for t, p in snapshot_t2p.items() if t in used_tokens
                    }
                else:
                    active_t2p = {}
            else:
                out_body = b''
                active_t2p = {}

            # 透传 Hermes headers（过滤逐跳头）
            headers = filter_hop_headers(dict(request.headers))

            try:
                # async with 确保上游响应在 SSE 客户端断连时正确释放连接
                async with session.request(
                    request.method,
                    target_url,
                    headers=headers,
                    data=out_body,
                ) as upstream_resp:
                    content_type = upstream_resp.content_type or ''

                    if content_type.startswith('text/event-stream'):
                        # ── SSE 流式 ──
                        resp = web.StreamResponse(
                            status=upstream_resp.status,
                            headers=filter_hop_headers(
                                dict(upstream_resp.headers),
                            ),
                        )
                        await resp.prepare(request)

                        if active_t2p:
                            # ── JSON-aware 流式 token 还原（广义 Plan C） ──
                            content_buf = (
                                ''  # 累积 delta.content 片段，O(1) 单字符串追加
                            )
                            byte_buf = bytearray()
                            resp_log_path = None

                            async def _flush(c: str, fr: str | None = None):
                                """flush 内容作为 SSE 事件并清空 content_buf。"""
                                nonlocal content_buf
                                if c or fr:
                                    if c:
                                        c = self._restore(c, active_t2p)
                                    await resp.write(
                                        _mk_sse_event(c, fr).encode(),
                                    )
                                content_buf = ''

                            try:
                                async for chunk in upstream_resp.content.iter_chunked(
                                    SSE_CHUNK_SIZE,
                                ):
                                    byte_buf.extend(chunk)
                                    pos = 0
                                    while (
                                        idx := byte_buf.find(
                                            b'\n',
                                            pos,
                                        )
                                    ) >= 0:
                                        line_bytes = bytes(byte_buf[pos:idx])
                                        pos = idx + 1
                                        line = line_bytes.decode(
                                            'utf-8',
                                            errors='replace',
                                        ).rstrip('\r')

                                        # 非 data 行：还原后透传（防 token 泄漏）
                                        if not line.startswith('data:'):
                                            await resp.write(
                                                (
                                                    self._restore(line, active_t2p)
                                                    + '\n'
                                                ).encode('utf-8'),
                                            )
                                            continue

                                        payload = line[5:]
                                        payload = payload.removeprefix(' ')

                                        # [DONE] 标记：先 flush 累积内容
                                        if payload.strip() == '[DONE]':
                                            await _flush(content_buf)
                                            await resp.write(
                                                b'data: [DONE]\n',
                                            )
                                            continue

                                        # 解析 JSON，提取 delta content
                                        try:
                                            parsed = json.loads(payload)

                                            # 保存原始 SSE payload 到 response.jsonl
                                            if resp_log_path:
                                                asyncio.create_task(
                                                    _save_response_line(
                                                        resp_log_path,
                                                        payload,
                                                    ),
                                                )

                                            # 首次成功解析 SSE data 时提取 conversation ID 保存原始请求
                                            if (
                                                _debug_save_eligible
                                                and not _debug_saved
                                            ):
                                                conv_id = _extract_conv_id(parsed)
                                                if conv_id:
                                                    _save_request_body(conv_id, body)
                                                    _debug_saved = True
                                                    resp_log_path = os.path.join(
                                                        _DEBUG_DIR,
                                                        conv_id,
                                                        'response.jsonl',
                                                    )
                                                    asyncio.create_task(
                                                        _save_response_line(
                                                            resp_log_path,
                                                            payload,
                                                        ),
                                                    )

                                            choices = parsed.get('choices', [])
                                            choice = choices[0] if choices else {}
                                            delta = choice.get('delta', {})
                                            finish_reason = choice.get(
                                                'finish_reason',
                                            )

                                            if delta.get('content') is None:
                                                if 'reasoning_content' in delta:
                                                    # reasoning_content 同 content 一样需要 safe/hold 保护
                                                    content_buf += delta[
                                                        'reasoning_content'
                                                    ]
                                                    restored = self._restore(
                                                        content_buf,
                                                        active_t2p,
                                                    )
                                                    last_us = restored.rfind('__')
                                                    safe = restored
                                                    pending = ''
                                                    if last_us >= 0:
                                                        suffix = restored[last_us:]
                                                        maybe_prefix = any(
                                                            t.startswith(suffix)
                                                            for t in active_t2p
                                                        )
                                                        if maybe_prefix:
                                                            safe = restored[:last_us]
                                                            pending = suffix
                                                    if safe:
                                                        await resp.write(
                                                            _mk_sse_event(
                                                                safe,
                                                            ).encode(),
                                                        )
                                                    content_buf = pending
                                                    if finish_reason:
                                                        content_buf = self._restore(
                                                            content_buf,
                                                            active_t2p,
                                                        )
                                                        await resp.write(
                                                            _mk_sse_event(
                                                                content_buf,
                                                                finish_reason,
                                                            ).encode(),
                                                        )
                                                        content_buf = ''
                                                else:
                                                    # 真正的非 content 事件
                                                    await _flush(content_buf)
                                                    await resp.write(
                                                        (
                                                            self._restore(
                                                                line, active_t2p
                                                            )
                                                            + '\n'
                                                        ).encode('utf-8'),
                                                    )
                                                continue

                                            # 追加 content 片段，还原 token
                                            content_buf += delta['content']
                                            restored = self._restore(
                                                content_buf,
                                                active_t2p,
                                            )

                                            # 找安全 flush 点
                                            last_us = restored.rfind('__')
                                            safe = restored
                                            pending = ''
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
                                                    content_buf,
                                                    active_t2p,
                                                )
                                                await resp.write(
                                                    _mk_sse_event(
                                                        content_buf,
                                                        finish_reason,
                                                    ).encode(),
                                                )
                                                content_buf = ''

                                        except json.JSONDecodeError:
                                            # 尝试从 byte_buf 读取续行重建 JSON
                                            # （处理 \n 在 JSON content 内截断的情况）
                                            accumulated = payload
                                            saved_pos = pos
                                            reconstructed = False
                                            for _ in range(20):
                                                nl = byte_buf.find(b'\n', pos)
                                                if nl < 0:
                                                    break
                                                next_line = (
                                                    bytes(byte_buf[pos:nl])
                                                    .decode('utf-8', errors='replace')
                                                    .rstrip('\r')
                                                )
                                                # 只有不以 data:/event:/id: 开头的行才是续行
                                                if (
                                                    not next_line.strip()
                                                    or next_line.startswith(
                                                        ('data:', 'event:', 'id:')
                                                    )
                                                ):
                                                    break
                                                accumulated += '\n' + next_line
                                                pos = nl + 1
                                                try:
                                                    sanitized = _sanitize_json(
                                                        accumulated,
                                                    )
                                                    parsed = json.loads(sanitized)
                                                    reconstructed = True
                                                    if resp_log_path:
                                                        asyncio.create_task(
                                                            _save_response_line(
                                                                resp_log_path,
                                                                sanitized,
                                                            ),
                                                        )
                                                    break
                                                except json.JSONDecodeError:
                                                    continue
                                            if reconstructed:
                                                choices = parsed.get(
                                                    'choices',
                                                    [],
                                                )
                                                choice = choices[0] if choices else {}
                                                delta = choice.get('delta', {})
                                                content = delta.get('content', '')
                                                finish_reason = choice.get(
                                                    'finish_reason',
                                                )
                                                if content:
                                                    # 合并 content_buf pending 部分
                                                    combined = content_buf + content
                                                    content_buf = ''
                                                    restored = self._restore(
                                                        combined,
                                                        active_t2p,
                                                    )
                                                    await resp.write(
                                                        _mk_sse_event(
                                                            restored,
                                                            finish_reason,
                                                        ).encode(),
                                                    )
                                                elif 'reasoning_content' in delta:
                                                    # 续行重建后的 reasoning_content
                                                    reasoning_text = delta[
                                                        'reasoning_content'
                                                    ]
                                                    combined = (
                                                        content_buf + reasoning_text
                                                    )
                                                    content_buf = ''
                                                    restored = self._restore(
                                                        combined,
                                                        active_t2p,
                                                    )
                                                    await resp.write(
                                                        _mk_sse_event(
                                                            restored,
                                                            finish_reason,
                                                        ).encode(),
                                                    )
                                                else:
                                                    # 非 content 事件
                                                    await resp.write(
                                                        (
                                                            'data: '
                                                            + self._restore(
                                                                sanitized,
                                                                active_t2p,
                                                            )
                                                            + '\n'
                                                        ).encode('utf-8'),
                                                    )
                                            else:
                                                pos = saved_pos  # 回退
                                                logger.warning(
                                                    'SSE JSON 解析失败，'
                                                    '续行重建失败，转发原始行: %s...',
                                                    payload[:80],
                                                )
                                                await resp.write(
                                                    (
                                                        self._restore(line, active_t2p)
                                                        + '\n'
                                                    ).encode('utf-8'),
                                                )
                                        except (KeyError, IndexError, TypeError):
                                            logger.warning(
                                                'SSE 数据结构异常: %s...',
                                                payload[:80],
                                            )
                                            await resp.write(
                                                (
                                                    self._restore(line, active_t2p)
                                                    + '\n'
                                                ).encode('utf-8'),
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
                                            'SSE 缓冲区超过 1MB 上限，'
                                            '保留最后一个部分行',
                                        )
                                        last_nl = byte_buf.rfind(b'\n')
                                        if last_nl >= 0:
                                            byte_buf = bytearray(
                                                byte_buf[last_nl + 1 :],
                                            )
                                        if len(byte_buf) > SSE_MAX_BUF:
                                            byte_buf = bytearray()
                            except SSE_CLIENT_GONE as e:
                                logger.debug('SSE 客户端断连: %s', e)

                            # 流结束：flush 残留（含 partial token 前缀清理）
                            if content_buf:
                                content_buf = self._restore(content_buf, active_t2p)
                                content_buf = _PARTIAL_TOKEN_RE.sub('', content_buf)
                                if content_buf:
                                    try:
                                        await resp.write(
                                            _mk_sse_event(content_buf).encode(),
                                        )
                                    except (
                                        ConnectionResetError,
                                        ConnectionAbortedError,
                                        BrokenPipeError,
                                    ):
                                        logger.debug('SSE 残余写入失败')
                            if byte_buf:
                                try:
                                    residual = byte_buf.decode(
                                        'utf-8',
                                        errors='replace',
                                    )
                                    restored = self._restore(
                                        residual,
                                        active_t2p,
                                    )
                                    await resp.write(
                                        restored.encode('utf-8'),
                                    )
                                except (
                                    ConnectionResetError,
                                    ConnectionAbortedError,
                                    BrokenPipeError,
                                ):
                                    logger.debug('SSE 残余写入失败')
                            try:
                                await resp.write_eof()
                            except (
                                ConnectionResetError,
                                ConnectionAbortedError,
                                BrokenPipeError,
                            ):
                                logger.debug(
                                    'SSE write_eof 失败，客户端已断连',
                                )
                        else:
                            # ── Fast path: active_t2p 为空，逐行 text-level 还原 ──
                            byte_buf = bytearray()
                            resp_log_path = None
                            try:
                                async for chunk in upstream_resp.content.iter_chunked(
                                    SSE_CHUNK_SIZE,
                                ):
                                    byte_buf.extend(chunk)
                                    # 先处理完整行，再检查缓冲区（防截断丢数据）
                                    pos = 0
                                    while (
                                        idx := byte_buf.find(
                                            b'\n',
                                            pos,
                                        )
                                    ) >= 0:
                                        line_bytes = bytes(byte_buf[pos:idx])
                                        pos = idx + 1
                                        line = line_bytes.decode(
                                            'utf-8',
                                            errors='replace',
                                        ).rstrip('\r')
                                        if line.startswith('data:'):
                                            payload = line[5:]
                                            payload = payload.removeprefix(' ')

                                            # 首次 data 事件提取 conversation ID 保存原始请求
                                            if (
                                                _debug_save_eligible
                                                and not _debug_saved
                                            ):
                                                try:
                                                    _parsed = json.loads(payload)
                                                    _cid = _extract_conv_id(_parsed)
                                                    if _cid:
                                                        _save_request_body(_cid, body)
                                                        _debug_saved = True
                                                        resp_log_path = os.path.join(
                                                            _DEBUG_DIR,
                                                            _cid,
                                                            'response.jsonl',
                                                        )
                                                        asyncio.create_task(
                                                            _save_response_line(
                                                                resp_log_path,
                                                                payload,
                                                            ),
                                                        )
                                                except json.JSONDecodeError:
                                                    pass

                                            if resp_log_path:
                                                # 非首个 event 也保存 response 行
                                                asyncio.create_task(
                                                    _save_response_line(
                                                        resp_log_path,
                                                        payload,
                                                    ),
                                                )

                                            restored = 'data: ' + self._restore(
                                                payload,
                                                active_t2p,
                                            )
                                            await resp.write(
                                                (restored + '\n').encode('utf-8'),
                                            )
                                        else:
                                            await resp.write(
                                                (line + '\n').encode('utf-8'),
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
                                            'SSE 缓冲区超过 1MB 上限，'
                                            '保留最后一个部分行',
                                        )
                                        last_nl = byte_buf.rfind(b'\n')
                                        if last_nl >= 0:
                                            byte_buf = bytearray(
                                                byte_buf[last_nl + 1 :],
                                            )
                                        if len(byte_buf) > SSE_MAX_BUF:
                                            byte_buf = bytearray()
                            except SSE_CLIENT_GONE as e:
                                logger.debug('SSE 客户端断连: %s', e)
                            # 残余字节 + EOF
                            if byte_buf:
                                try:
                                    residual = byte_buf.decode(
                                        'utf-8',
                                        errors='replace',
                                    )
                                    restored = self._restore(
                                        residual,
                                        active_t2p,
                                    )
                                    await resp.write(
                                        restored.encode('utf-8'),
                                    )
                                except (
                                    ConnectionResetError,
                                    ConnectionAbortedError,
                                    BrokenPipeError,
                                ):
                                    logger.debug('SSE 残余写入失败')
                            try:
                                await resp.write_eof()
                            except (
                                ConnectionResetError,
                                ConnectionAbortedError,
                                BrokenPipeError,
                            ):
                                logger.debug(
                                    'SSE write_eof 失败，客户端已断连',
                                )
                        return resp
                    else:
                        # ── 非流式 ──
                        resp_body = await upstream_resp.read()

                        if _debug_save_eligible:
                            try:
                                resp_json = json.loads(resp_body)
                                conv_id = resp_json.get('id')
                                if conv_id:
                                    _save_request_body(conv_id, body)
                                    _debug_saved = True
                                    # 非流式 response 写为完整 response.json
                                    resp_path = os.path.join(
                                        _DEBUG_DIR,
                                        conv_id,
                                        'response.json',
                                    )
                                    asyncio.create_task(
                                        _save_response_line(
                                            resp_path,
                                            resp_body.decode('utf-8', errors='replace'),
                                        ),
                                    )
                            except json.JSONDecodeError:
                                pass

                        resp_text = resp_body.decode(
                            'utf-8',
                            errors='replace',
                        )
                        out_text = self._restore(resp_text, active_t2p)
                        return web.Response(
                            body=out_text.encode('utf-8'),
                            status=upstream_resp.status,
                            headers=filter_hop_headers(
                                dict(upstream_resp.headers),
                            ),
                        )
            except Exception:
                if _debug_save_eligible and not _debug_saved:
                    _save_request_body(f'failed-{req_id}', body)
                logger.exception(
                    'LLM 上游请求失败: %s %s',
                    request.method,
                    target_url,
                )
                raise

        app = web.Application()
        app.router.add_route('*', '/{tail:.*}', handler)
        # 注意：不在此处注册 session.close() — _shared_session 由 shutdown() 统一关闭
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, '0.0.0.0', port).start()
        self._runners.append(runner)
        logger.info('LLM 代理 → 0.0.0.0:%d → %s', port, upstream)
