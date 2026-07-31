"""LlmMixin — LLM API 反向代理：脱敏请求 → 上游 → 还原响应。"""

import asyncio
import json
import logging
import os
import re as _re
import uuid as _uuid

from aiohttp import ClientSession, ClientTimeout, web

from _sse import SSE_CLIENT_GONE, filter_hop_headers
from _token import TOKEN_RE, TOKEN_STR_RE

logger = logging.getLogger('credential-proxy')

# ── Constants ──
UPSTREAM_TOTAL_TIMEOUT = 600  # 上游总超时 (s)
UPSTREAM_CONNECT_TIMEOUT = 30  # 上游连接超时 (s)
SSE_CHUNK_SIZE = 4096  # SSE 流式块大小
SSE_MAX_BUF = 1_048_576  # SSE 缓冲区上限 (1MB)
# 流末清理：匹配 token 前缀/残缺形态（含完整但未还原的幻觉 token）。
# 真实 token 会被 _restore 先行还原为明文，不会落此正则。
_PARTIAL_TOKEN_RE = _re.compile(r'__VG_C(?:R(?:E(?:D(?:_?\d*)?)?)?)?_*$')
# 完整 token 形态（行尾）：__VG_CRED_NNNNNN__
_FULL_TOKEN_RE = _re.compile(r'__VG_CRED_\d+__$')
# Debug 开关：设置环境变量 CREDENTIAL_PROXY_DEBUG_DIR 开启
_DEBUG_DIR = os.environ.get('CREDENTIAL_PROXY_DEBUG_DIR', '')


def parse_llm_proxy_env() -> dict[int, str]:
    """从 LLM_<PORT>=<URL> 环境变量读取上游配置。"""
    proxies: dict[int, str] = {}
    for k, v in os.environ.items():
        if not k.startswith('LLM_'):
            continue
        try:
            port = int(k[4:])
        except ValueError:
            continue
        proxies[port] = v.strip().rstrip('/')
        if not proxies[port]:
            del proxies[port]
    return proxies


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
    """保存脱敏后的请求 body 到 debug 目录，以 conversation ID 命名。

    保存的是 redact 后的 out_body（不含明文凭据）。
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


def _mk_sse_event(
    content: str = '',
    finish_reason: str | None = None,
    reasoning_content: str = '',
) -> str:
    """Build OpenAI-compatible SSE data event JSON.

    Supports both content and reasoning_content delta fields.
    Content is always included when non-empty — OpenAI allows
    content + finish_reason in the same delta event.
    """
    delta = {}
    if content:
        delta['content'] = content
    if reasoning_content:
        delta['reasoning_content'] = reasoning_content
    event = json.dumps(
        {
            'choices': [{'index': 0, 'delta': delta, 'finish_reason': finish_reason}],
            'object': 'chat.completion.chunk',
        }
    )
    return f'data: {event}\n'


def _responses_event(parsed: dict) -> tuple[str, str | None] | None:
    """识别 OpenAI Responses API SSE 事件（/v1/responses）。

    返回 (kind, delta_text)：
      kind ∈ {'output_text', 'reasoning_text', 'function_call_arguments', 'other'}
      - delta 事件: delta_text 为文本片段
      - 'other'（response.created / completed / output_item.done 等）: delta_text=None
    非 Responses 事件（chat/completions SSE 等）返回 None。
    """
    evt_type = parsed.get('type') if isinstance(parsed, dict) else None
    if not isinstance(evt_type, str) or not evt_type.startswith('response.'):
        return None
    kind_map = {
        'response.output_text.delta': 'output_text',
        'response.reasoning_text.delta': 'reasoning_text',
        'response.function_call_arguments.delta': 'function_call_arguments',
    }
    kind = kind_map.get(evt_type, 'other')
    delta_text = parsed.get('delta') if kind != 'other' else None
    if kind != 'other' and not isinstance(delta_text, str):
        # delta 字段缺失/非字符串 → 当作普通事件透传
        return 'other', None
    return kind, delta_text


def _mk_responses_sse_event(parsed: dict, delta_text: str) -> str:
    """保持 Responses 事件结构，仅替换 delta 字段（已还原文本）。"""
    out = dict(parsed)
    out['delta'] = delta_text
    return 'data: ' + json.dumps(out, ensure_ascii=False) + '\n'


def _mk_responses_flush_event(event_type: str, delta_text: str) -> str:
    """构造一个 Responses delta 事件（流末/非 delta 事件前 flush 残留用）。"""
    out = {'type': event_type, 'delta': delta_text}
    return 'data: ' + json.dumps(out, ensure_ascii=False) + '\n'


# Anthropic delta 类型 → (字段, 输出时使用的 delta.type)
_ANTHROPIC_DELTA_FIELDS = {
    'text': ('text', 'text_delta'),
    'thinking': ('thinking', 'thinking_delta'),
    'function_args': ('partial_json', 'input_json_delta'),
}
# 字段名 → delta.type（_mk_anthropic_flush_event 用）
_ANTHROPIC_FIELD_DELTA_TYPE = {
    field: dtype for _kind, (field, dtype) in _ANTHROPIC_DELTA_FIELDS.items()
}


def _anthropic_event(parsed: dict) -> tuple[str, str | None] | None:
    """识别 Anthropic Messages API SSE 事件（/v1/messages）。

    返回 (kind, delta_text)：
      kind ∈ {'text', 'thinking', 'function_args', 'other'}
      - 'text': content_block_delta 的 text_delta → delta.text
      - 'thinking': content_block_delta 的 thinking_delta → delta.thinking
      - 'function_args': content_block_delta 的 input_json_delta → delta.partial_json
      - 'other': 其他 content_block_delta 类型（server_tool_use 等）→ delta_text=None
    非 Anthropic 事件（chat/completions、responses SSE 等）返回 None。
    注：message_start / content_block_start / message_delta / message_stop 等
    不含文本 delta 的事件返回 None，走整行透传（原样保留，无需还原）。
    """
    evt_type = parsed.get('type') if isinstance(parsed, dict) else None
    if evt_type != 'content_block_delta':
        return None
    delta = parsed.get('delta')
    if not isinstance(delta, dict):
        return 'other', None
    dtype = delta.get('type')
    if dtype == 'text_delta' and isinstance(delta.get('text'), str):
        return 'text', delta['text']
    if dtype == 'thinking_delta' and isinstance(delta.get('thinking'), str):
        return 'thinking', delta['thinking']
    if dtype == 'input_json_delta' and isinstance(delta.get('partial_json'), str):
        return 'function_args', delta['partial_json']
    return 'other', None


def _mk_anthropic_delta_event(parsed: dict, text: str, field: str) -> str:
    """保持 Anthropic 事件结构，仅替换 delta 文本字段（已还原文本）。

    field ∈ {'text', 'thinking', 'partial_json'} 对应三种 delta 类型。
    """
    out = dict(parsed)
    out['delta'] = dict(parsed['delta'])
    out['delta'][field] = text
    return 'data: ' + json.dumps(out, ensure_ascii=False) + '\n'


def _mk_anthropic_flush_event(parsed: dict, text: str, field: str) -> str:
    """构造 Anthropic content_block_delta 事件（中游/流末 flush 残留用）。"""
    delta_type = _ANTHROPIC_FIELD_DELTA_TYPE[field]
    out = {
        'type': 'content_block_delta',
        'index': parsed.get('index', 0),
        'delta': {'type': delta_type, field: text},
    }
    return 'data: ' + json.dumps(out, ensure_ascii=False) + '\n'


def _split_safe_hold(content: str, active_t2p: dict) -> tuple[str, str]:
    """将累积文本分割为 (safe, hold)。

    - safe: 可安全输出（剥离行中完整 token 形态——未还原的必是幻觉/未知句柄；
       active 内的真实 token 已被 _restore 还原为明文）
    - hold: 保留到下个分片（以 __ 开头且匹配 active token 前缀）
    """
    if not content:
        return '', ''
    # 完整 token 形态但不在 active_t2p（LLM 幻觉/未知句柄）→ 整体 hold，
    # 防止 rfind('__') 把完整 token 拆成两段、后续分片重组泄漏 token 字符串
    m = _FULL_TOKEN_RE.search(content)
    if m:
        token_str = m.group(0)
        if token_str not in active_t2p:
            return TOKEN_STR_RE.sub('', content[: m.start()]), token_str
    last_us = content.rfind('__')
    if last_us < 0:
        return TOKEN_STR_RE.sub('', content), ''
    suffix = content[last_us:]
    maybe_prefix = any(t.startswith(suffix) for t in active_t2p)
    if maybe_prefix:
        return TOKEN_STR_RE.sub('', content[:last_us]), suffix
    return TOKEN_STR_RE.sub('', content), ''


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

    # ── Anthropic Messages API SSE 事件处理 ──

    async def _flush_anthropic_buf(
        self,
        write,
        parsed: dict,
        field: str,
        buf: str,
        active_t2p: dict,
        keep_pending: bool = True,
    ) -> str:
        """flush 单个 Anthropic 缓冲：还原 → safe/pending 分割 → 输出 safe。

        - keep_pending=True（中游）：返回保留的 pending（不完整 token 前缀，
          等待后续分片）；safe 中无法 hold 的残缺 token 形态被 _PARTIAL_TOKEN_RE 清理
        - keep_pending=False（流末）：不保留 pending，所有 partial 形态清理后
          输出残余（如有）
        """
        if not buf:
            return ''
        restored = self._restore(buf, active_t2p)
        if not keep_pending:
            restored = _PARTIAL_TOKEN_RE.sub('', restored)
            if not restored:
                return ''
            try:
                await write(
                    _mk_anthropic_flush_event(parsed, restored, field).encode('utf-8')
                )
            except (
                ConnectionResetError,
                ConnectionAbortedError,
                BrokenPipeError,
            ):
                logger.debug('SSE 残余写入失败')
            return ''
        safe, pending = _split_safe_hold(restored, active_t2p)
        if safe:
            safe = _PARTIAL_TOKEN_RE.sub('', safe)
        if safe:
            try:
                await write(
                    _mk_anthropic_flush_event(parsed, safe, field).encode('utf-8')
                )
            except (
                ConnectionResetError,
                ConnectionAbortedError,
                BrokenPipeError,
            ):
                logger.debug('SSE 残余写入失败')
        return pending

    async def _handle_anthropic_event(
        self,
        write,
        parsed: dict,
        line: str,
        active_t2p: dict,
        content_buf: str,
        reasoning_buf: str,
        arg_buf: str,
    ) -> tuple[str, str, str]:
        """处理单个 Anthropic Messages API 事件，返回更新后的 (content_buf, reasoning_buf, arg_buf)。

        - content_block_delta 文本事件（text_delta / thinking_delta / input_json_delta）：
          累积 → _restore → safe/pending 分割 → 保持 Anthropic 格式输出已还原片段
        - 其他 content_block_delta（server_tool_use 等）：flush 各缓冲 safe 部分
          （pending 保留等待后续分片，未完成的 token 前缀由流末清理），再原样透传
        """
        event = _anthropic_event(parsed)
        if event is None:  # pragma: no cover — 调用方已保证是 Anthropic 事件
            await write((self._restore(line, active_t2p) + '\n').encode('utf-8'))
            return content_buf, reasoning_buf, arg_buf
        kind, delta_text = event

        if kind in ('text', 'thinking', 'function_args'):
            if delta_text is None:  # pragma: no cover — 识别器保证 delta 事件携带 str
                return content_buf, reasoning_buf, arg_buf
            field = _ANTHROPIC_DELTA_FIELDS[kind][0]
            if kind == 'text':
                content_buf += delta_text
            elif kind == 'thinking':
                reasoning_buf += delta_text
            else:
                arg_buf += delta_text
            buf = (
                content_buf
                if kind == 'text'
                else (reasoning_buf if kind == 'thinking' else arg_buf)
            )
            restored = self._restore(buf, active_t2p)
            safe, pending = _split_safe_hold(restored, active_t2p)
            if safe:
                await write(
                    _mk_anthropic_delta_event(parsed, safe, field).encode('utf-8')
                )
            if kind == 'text':
                content_buf = pending
            elif kind == 'thinking':
                reasoning_buf = pending
            else:
                arg_buf = pending
            return content_buf, reasoning_buf, arg_buf

        # 其他 content_block_delta：flush 各缓冲 safe 部分（pending 保留）→ 原样透传
        content_buf = await self._flush_anthropic_buf(
            write, parsed, 'text', content_buf, active_t2p
        )
        reasoning_buf = await self._flush_anthropic_buf(
            write, parsed, 'thinking', reasoning_buf, active_t2p
        )
        arg_buf = await self._flush_anthropic_buf(
            write, parsed, 'partial_json', arg_buf, active_t2p
        )
        await write((self._restore(line, active_t2p) + '\n').encode('utf-8'))
        return content_buf, reasoning_buf, arg_buf

    # ── Responses API SSE 事件处理 ──

    async def _flush_responses_buf(
        self,
        write,
        event_type: str,
        buf: str,
        active_t2p: dict,
        keep_pending: bool = True,
    ) -> str:
        """flush 单个 Responses 缓冲：还原 → safe/pending 分割 → 输出 safe。

        - keep_pending=True（中游）：返回保留的 pending（不完整 token 前缀，
          等待后续分片）；safe 中无法 hold 的残缺 token 形态被 _PARTIAL_TOKEN_RE 清理
        - keep_pending=False（流末）：不保留 pending，所有 partial 形态清理后
          输出残余（如有）
        """
        if not buf:
            return ''
        restored = self._restore(buf, active_t2p)
        if not keep_pending:
            restored = _PARTIAL_TOKEN_RE.sub('', restored)
            if not restored:
                return ''
            try:
                await write(
                    _mk_responses_flush_event(event_type, restored).encode('utf-8')
                )
            except (
                ConnectionResetError,
                ConnectionAbortedError,
                BrokenPipeError,
            ):
                logger.debug('SSE 残余写入失败')
            return ''
        safe, pending = _split_safe_hold(restored, active_t2p)
        if safe:
            safe = _PARTIAL_TOKEN_RE.sub('', safe)
        if safe:
            try:
                await write(_mk_responses_flush_event(event_type, safe).encode('utf-8'))
            except (
                ConnectionResetError,
                ConnectionAbortedError,
                BrokenPipeError,
            ):
                logger.debug('SSE 残余写入失败')
        return pending

    async def _handle_responses_event(
        self,
        write,
        parsed: dict,
        line: str,
        active_t2p: dict,
        content_buf: str,
        reasoning_buf: str,
        arg_buf: str,
    ) -> tuple[str, str, str]:
        """处理单个 Responses API SSE 事件，返回更新后的 (content_buf, reasoning_buf, arg_buf)。

        - output_text / reasoning_text / function_call_arguments 的 delta 事件：
          累积 → _restore → safe/pending 分割 → 保持原格式输出已还原片段
        - 其他 response.* 事件：先 flush 各缓冲的 safe 部分（pending 保留等待
          后续分片，未完成的 token 前缀由流末清理），再原样透传事件行
        """
        kind, delta_text = _responses_event(parsed)
        if kind is None:  # pragma: no cover — 调用方已保证是 Responses 事件
            await write((self._restore(line, active_t2p) + '\n').encode('utf-8'))
            return content_buf, reasoning_buf, arg_buf

        if kind in ('output_text', 'reasoning_text', 'function_call_arguments'):
            if delta_text is None:  # pragma: no cover — 识别器保证 delta 事件携带 str
                return content_buf, reasoning_buf, arg_buf
            if kind == 'output_text':
                content_buf += delta_text
            elif kind == 'reasoning_text':
                reasoning_buf += delta_text
            else:
                arg_buf += delta_text
            buf = (
                content_buf
                if kind == 'output_text'
                else (reasoning_buf if kind == 'reasoning_text' else arg_buf)
            )
            restored = self._restore(buf, active_t2p)
            safe, pending = _split_safe_hold(restored, active_t2p)
            if safe:
                await write(_mk_responses_sse_event(parsed, safe).encode('utf-8'))
            if kind == 'output_text':
                content_buf = pending
            elif kind == 'reasoning_text':
                reasoning_buf = pending
            else:
                arg_buf = pending
            return content_buf, reasoning_buf, arg_buf

        # 其他 response.* 事件：flush 各缓冲 safe 部分（pending 保留）→ 原样透传
        content_buf = await self._flush_responses_buf(
            write, 'response.output_text.delta', content_buf, active_t2p
        )
        reasoning_buf = await self._flush_responses_buf(
            write, 'response.reasoning_text.delta', reasoning_buf, active_t2p
        )
        arg_buf = await self._flush_responses_buf(
            write,
            'response.function_call_arguments.delta',
            arg_buf,
            active_t2p,
        )
        await write((self._restore(line, active_t2p) + '\n').encode('utf-8'))
        return content_buf, reasoning_buf, arg_buf

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
                or tail.rstrip('/').endswith('/v1/responses')
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
                out_body = body
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

                    # Log non-2xx upstream responses, only for chat completion endpoints
                    if upstream_resp.status >= 400 and (
                        tail.rstrip('/').endswith('chat/completions')
                        or tail.rstrip('/').endswith('v1/messages')
                    ):
                        logger.warning(
                            'LLM 上游返回 %d: %s %s',
                            upstream_resp.status,
                            request.method,
                            target_url,
                        )

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
                            reasoning_buf = ''  # 累积 delta.reasoning_content 片段
                            arg_buf = ''  # 累积 responses function_call_arguments / anthropic partial_json 片段
                            is_responses_stream = False  # 本流是否 Responses API SSE
                            is_anthropic_stream = (
                                False  # 本流是否 Anthropic Messages API SSE
                            )
                            byte_buf = bytearray()
                            resp_log_path = None

                            async def _flush(
                                c: str = '',
                                rc: str = '',
                                fr: str | None = None,
                            ):
                                """flush 内容作为 SSE 事件并清空缓冲区。"""
                                nonlocal content_buf, reasoning_buf
                                if c or rc or fr:
                                    if c:
                                        c = self._restore(c, active_t2p)
                                        c = _PARTIAL_TOKEN_RE.sub('', c)
                                    if rc:
                                        rc = self._restore(rc, active_t2p)
                                        rc = _PARTIAL_TOKEN_RE.sub('', rc)
                                    await resp.write(
                                        _mk_sse_event(
                                            content=c,
                                            finish_reason=fr,
                                            reasoning_content=rc,
                                        ).encode(),
                                    )
                                content_buf = ''
                                reasoning_buf = ''

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
                                        line_bytes = byte_buf[pos:idx]
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
                                            if is_responses_stream:
                                                # 兼容网关可能在 responses 流中发 [DONE]：
                                                # 用 responses 格式 flush，避免 chat 格式污染
                                                content_buf = (
                                                    await self._flush_responses_buf(
                                                        resp.write,
                                                        'response.output_text.delta',
                                                        content_buf,
                                                        active_t2p,
                                                    )
                                                )
                                                reasoning_buf = (
                                                    await self._flush_responses_buf(
                                                        resp.write,
                                                        'response.reasoning_text.delta',
                                                        reasoning_buf,
                                                        active_t2p,
                                                    )
                                                )
                                                arg_buf = await self._flush_responses_buf(
                                                    resp.write,
                                                    'response.function_call_arguments.delta',
                                                    arg_buf,
                                                    active_t2p,
                                                )
                                            elif is_anthropic_stream:
                                                # 兼容网关可能在 anthropic 流中发 [DONE]：
                                                # 用 anthropic 格式 flush，避免 chat 格式污染
                                                _dummy = {
                                                    'type': 'content_block_delta',
                                                    'index': 0,
                                                }
                                                content_buf = (
                                                    await self._flush_anthropic_buf(
                                                        resp.write,
                                                        _dummy,
                                                        'text',
                                                        content_buf,
                                                        active_t2p,
                                                    )
                                                )
                                                reasoning_buf = (
                                                    await self._flush_anthropic_buf(
                                                        resp.write,
                                                        _dummy,
                                                        'thinking',
                                                        reasoning_buf,
                                                        active_t2p,
                                                    )
                                                )
                                                arg_buf = (
                                                    await self._flush_anthropic_buf(
                                                        resp.write,
                                                        _dummy,
                                                        'partial_json',
                                                        arg_buf,
                                                        active_t2p,
                                                    )
                                                )
                                            else:
                                                await _flush(
                                                    c=content_buf,
                                                    rc=reasoning_buf,
                                                )
                                            await resp.write(
                                                b'data: [DONE]\n',
                                            )
                                            continue

                                        # 解析 JSON，提取 delta content
                                        try:
                                            parsed = json.loads(payload)
                                            # 非 dict payload（JSON 数组/标量）→
                                            # 原样透传，避免下游 .get 抛 AttributeError
                                            if not isinstance(parsed, dict):
                                                await resp.write(
                                                    (
                                                        self._restore(line, active_t2p)
                                                        + '\n'
                                                    ).encode('utf-8'),
                                                )
                                                continue

                                            # 保存原始 SSE payload 到 response.jsonl
                                            if resp_log_path:
                                                await _save_response_line(
                                                    resp_log_path,
                                                    payload,
                                                )

                                            # 首次成功解析 SSE data 时提取 conversation ID 保存原始请求
                                            if (
                                                _debug_save_eligible
                                                and not _debug_saved
                                            ):
                                                conv_id = _extract_conv_id(parsed)
                                                if conv_id:
                                                    _save_request_body(
                                                        conv_id, out_body
                                                    )
                                                    _debug_saved = True
                                                    resp_log_path = os.path.join(
                                                        _DEBUG_DIR,
                                                        conv_id,
                                                        'response.jsonl',
                                                    )
                                                    await _save_response_line(
                                                        resp_log_path,
                                                        payload,
                                                    )

                                            # ── Responses API 事件（/v1/responses SSE）──
                                            if _responses_event(parsed) is not None:
                                                is_responses_stream = True
                                                (
                                                    content_buf,
                                                    reasoning_buf,
                                                    arg_buf,
                                                ) = await self._handle_responses_event(
                                                    resp.write,
                                                    parsed,
                                                    line,
                                                    active_t2p,
                                                    content_buf,
                                                    reasoning_buf,
                                                    arg_buf,
                                                )
                                                continue

                                            # ── Anthropic Messages API 事件（/v1/messages SSE）──
                                            if _anthropic_event(parsed) is not None:
                                                is_anthropic_stream = True
                                                (
                                                    content_buf,
                                                    reasoning_buf,
                                                    arg_buf,
                                                ) = await self._handle_anthropic_event(
                                                    resp.write,
                                                    parsed,
                                                    line,
                                                    active_t2p,
                                                    content_buf,
                                                    reasoning_buf,
                                                    arg_buf,
                                                )
                                                continue

                                            choices = parsed.get('choices', [])
                                            choice = choices[0] if choices else {}
                                            delta = choice.get('delta', {})
                                            finish_reason = choice.get(
                                                'finish_reason',
                                            )

                                            # ── Reasoning content（独立处理，不受 content 影响）──
                                            rc_val = delta.get('reasoning_content')
                                            if rc_val is not None:
                                                reasoning_buf += rc_val
                                                restored = self._restore(
                                                    reasoning_buf,
                                                    active_t2p,
                                                )
                                                safe, pending = _split_safe_hold(
                                                    restored, active_t2p
                                                )
                                                if safe:
                                                    await resp.write(
                                                        _mk_sse_event(
                                                            reasoning_content=safe,
                                                        ).encode(),
                                                    )
                                                reasoning_buf = pending
                                                if finish_reason and not delta.get(
                                                    'content'
                                                ):
                                                    reasoning_buf = self._restore(
                                                        reasoning_buf,
                                                        active_t2p,
                                                    )
                                                    reasoning_buf = (
                                                        _PARTIAL_TOKEN_RE.sub(
                                                            '',
                                                            reasoning_buf,
                                                        )
                                                    )
                                                    await resp.write(
                                                        _mk_sse_event(
                                                            reasoning_content=reasoning_buf,
                                                            finish_reason=finish_reason,
                                                        ).encode(),
                                                    )
                                                    reasoning_buf = ''

                                            # ── Content / 非 content 事件 ──
                                            if delta.get('content') is not None:
                                                # 追加 content 片段，还原 token
                                                content_buf += delta['content']
                                                restored = self._restore(
                                                    content_buf,
                                                    active_t2p,
                                                )

                                                # 找安全 flush 点
                                                safe, pending = _split_safe_hold(
                                                    restored, active_t2p
                                                )

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
                                                    content_buf = _PARTIAL_TOKEN_RE.sub(
                                                        '',
                                                        content_buf,
                                                    )
                                                    await resp.write(
                                                        _mk_sse_event(
                                                            content_buf,
                                                            finish_reason,
                                                        ).encode(),
                                                    )
                                                    content_buf = ''
                                            elif 'reasoning_content' not in delta:
                                                # 真正的非 content 事件
                                                await _flush(
                                                    c=content_buf,
                                                    rc=reasoning_buf,
                                                )
                                                await resp.write(
                                                    (
                                                        self._restore(line, active_t2p)
                                                        + '\n'
                                                    ).encode('utf-8'),
                                                )

                                        except json.JSONDecodeError:
                                            # 尝试从 byte_buf 读取续行重建 JSON
                                            # （处理 \n 在 JSON content 内截断的情况）
                                            accumulated = payload
                                            reconstructed = False
                                            parsed = None  # 续行重建成功时赋值
                                            sanitized = ''
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
                                                        await _save_response_line(
                                                            resp_log_path,
                                                            sanitized,
                                                        )
                                                    break
                                                except json.JSONDecodeError:
                                                    continue
                                            if reconstructed:
                                                if parsed is None:
                                                    continue  # pragma: no cover
                                                # ── Responses API 事件（续行重建路径）──
                                                if _responses_event(parsed) is not None:
                                                    is_responses_stream = True
                                                    (
                                                        content_buf,
                                                        reasoning_buf,
                                                        arg_buf,
                                                    ) = await self._handle_responses_event(
                                                        resp.write,
                                                        parsed,
                                                        'data: ' + sanitized,
                                                        active_t2p,
                                                        content_buf,
                                                        reasoning_buf,
                                                        arg_buf,
                                                    )
                                                    continue
                                                # ── Anthropic Messages API 事件（续行重建路径）──
                                                if _anthropic_event(parsed) is not None:
                                                    is_anthropic_stream = True
                                                    (
                                                        content_buf,
                                                        reasoning_buf,
                                                        arg_buf,
                                                    ) = await self._handle_anthropic_event(
                                                        resp.write,
                                                        parsed,
                                                        'data: ' + sanitized,
                                                        active_t2p,
                                                        content_buf,
                                                        reasoning_buf,
                                                        arg_buf,
                                                    )
                                                    continue
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

                                                # reasoning_content 独立处理
                                                rc_val = delta.get('reasoning_content')
                                                if rc_val is not None:
                                                    rc_combined = reasoning_buf + rc_val
                                                    reasoning_buf = ''
                                                    rc_restored = self._restore(
                                                        rc_combined,
                                                        active_t2p,
                                                    )
                                                    rc_restored = _PARTIAL_TOKEN_RE.sub(
                                                        '',
                                                        rc_restored,
                                                    )
                                                    await resp.write(
                                                        _mk_sse_event(
                                                            reasoning_content=rc_restored,
                                                            finish_reason=(
                                                                finish_reason
                                                                if not content
                                                                else None
                                                            ),
                                                        ).encode(),
                                                    )

                                                # content / 非 content
                                                if content:
                                                    combined = content_buf + content
                                                    content_buf = ''
                                                    restored = self._restore(
                                                        combined,
                                                        active_t2p,
                                                    )
                                                    restored = _PARTIAL_TOKEN_RE.sub(
                                                        '',
                                                        restored,
                                                    )
                                                    await resp.write(
                                                        _mk_sse_event(
                                                            content=restored,
                                                            finish_reason=finish_reason,
                                                        ).encode(),
                                                    )
                                                elif 'reasoning_content' not in delta:
                                                    # 非 content 事件
                                                    await _flush(
                                                        c=content_buf,
                                                        rc=reasoning_buf,
                                                    )
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
                                                # pos 已越过续行，不回退（续行已在 byte_buf 中被消费）
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

                                    # Trim processed portion (in-place, avoid new allocation)
                                    if pos > 0:
                                        del byte_buf[:pos]

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
                            if is_responses_stream:
                                # ── Responses 流：残留按对应 delta 事件类型输出 ──
                                await self._flush_responses_buf(
                                    resp.write,
                                    'response.output_text.delta',
                                    content_buf,
                                    active_t2p,
                                    keep_pending=False,
                                )
                                await self._flush_responses_buf(
                                    resp.write,
                                    'response.reasoning_text.delta',
                                    reasoning_buf,
                                    active_t2p,
                                    keep_pending=False,
                                )
                                await self._flush_responses_buf(
                                    resp.write,
                                    'response.function_call_arguments.delta',
                                    arg_buf,
                                    active_t2p,
                                    keep_pending=False,
                                )
                            elif is_anthropic_stream:
                                # ── Anthropic 流：残留按对应 delta 类型输出 ──
                                _dummy = {'type': 'content_block_delta', 'index': 0}
                                await self._flush_anthropic_buf(
                                    resp.write,
                                    _dummy,
                                    'text',
                                    content_buf,
                                    active_t2p,
                                    keep_pending=False,
                                )
                                await self._flush_anthropic_buf(
                                    resp.write,
                                    _dummy,
                                    'thinking',
                                    reasoning_buf,
                                    active_t2p,
                                    keep_pending=False,
                                )
                                await self._flush_anthropic_buf(
                                    resp.write,
                                    _dummy,
                                    'partial_json',
                                    arg_buf,
                                    active_t2p,
                                    keep_pending=False,
                                )
                            elif content_buf or reasoning_buf:
                                if content_buf:
                                    content_buf = self._restore(
                                        content_buf,
                                        active_t2p,
                                    )
                                    content_buf = _PARTIAL_TOKEN_RE.sub(
                                        '',
                                        content_buf,
                                    )
                                if reasoning_buf:
                                    reasoning_buf = self._restore(
                                        reasoning_buf,
                                        active_t2p,
                                    )
                                    reasoning_buf = _PARTIAL_TOKEN_RE.sub(
                                        '',
                                        reasoning_buf,
                                    )
                                if content_buf or reasoning_buf:
                                    try:
                                        await resp.write(
                                            _mk_sse_event(
                                                content=content_buf,
                                                reasoning_content=reasoning_buf,
                                            ).encode(),
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
                                        line_bytes = byte_buf[pos:idx]
                                        pos = idx + 1
                                        line = line_bytes.decode(
                                            'utf-8',
                                            errors='replace',
                                        ).rstrip('\r')
                                        if line.startswith('data:'):
                                            payload = line[5:]
                                            payload = payload.removeprefix(' ')

                                            if resp_log_path:
                                                # 后续 event 保存 response 行
                                                await _save_response_line(
                                                    resp_log_path,
                                                    payload,
                                                )

                                            # 首次 data 事件提取 conversation ID 保存原始请求
                                            if (
                                                _debug_save_eligible
                                                and not _debug_saved
                                            ):
                                                try:
                                                    _parsed = json.loads(payload)
                                                    _cid = _extract_conv_id(_parsed)
                                                    if _cid:
                                                        _save_request_body(
                                                            _cid, out_body
                                                        )
                                                        _debug_saved = True
                                                        resp_log_path = os.path.join(
                                                            _DEBUG_DIR,
                                                            _cid,
                                                            'response.jsonl',
                                                        )
                                                        # 首个 event 单独保存（此时 resp_log_path 刚设好）
                                                        # 上面的 generic save 因 resp_log_path=None 已跳过
                                                        await _save_response_line(
                                                            resp_log_path,
                                                            payload,
                                                        )
                                                except json.JSONDecodeError:
                                                    pass

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
                                        del byte_buf[:pos]
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
                                    _save_request_body(conv_id, out_body)
                                    _debug_saved = True
                                    # 非流式 response 写为完整 response.json
                                    resp_path = os.path.join(
                                        _DEBUG_DIR,
                                        conv_id,
                                        'response.json',
                                    )
                                    await _save_response_line(
                                        resp_path,
                                        resp_body.decode('utf-8', errors='replace'),
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
                    _save_request_body(f'failed-{req_id}', out_body)
                logger.exception(
                    'LLM 上游请求失败: %s %s',
                    request.method,
                    target_url,
                )
                raise

        app = web.Application()
        app.router.add_route('*', '/{tail:.*}', handler)
        # 注意：不在此处注册 session.close() — _shared_session 由 shutdown() 统一关闭
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, '0.0.0.0', port).start()
        self._runners.append(runner)
        logger.info('LLM 代理 → 0.0.0.0:%d → %s', port, upstream)
