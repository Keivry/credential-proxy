"""LlmMixin — LLM API 反向代理：脱敏请求 → 上游 → 还原响应。"""

import asyncio
import json
import logging
import os
import re as _re
import uuid as _uuid

from aiohttp import ClientSession, ClientTimeout, web
from aiohttp.client_exceptions import ClientConnectionError, ServerDisconnectedError

from _audit import BLOCK_MESSAGE, AuditMixin, redact_summary
from _sse import SSE_CLIENT_GONE, filter_hop_headers
from _token import (
    _PII_PARTIAL_TOKEN_RE,
    FULL_PII_TOKEN_RE,
    PII_TOKEN_RE,
    PII_TOKEN_STR_RE,
    TOKEN_RE,
    TOKEN_STR_RE,
)

logger = logging.getLogger('credential-proxy')


def _strip_partials(text: str) -> str:
    """流末/安全输出前清理残缺 token 前缀（凭据 + PII 两套）。

    design D2 硬性：PII 残缺形态（`__PII_…` 前缀在分片边界被切断）必须与
    凭据残缺同规则清理，否则 `__PII_1_ab` 等残缺会随 safe 输出泄漏给客户端。
    统一入口替换散落的 `_PARTIAL_TOKEN_RE.sub`，避免新增路径漏接 PII 版。
    """
    out = _PARTIAL_TOKEN_RE.sub('', text)
    return _PII_PARTIAL_TOKEN_RE.sub('', out)


# ── Constants ──
UPSTREAM_TOTAL_TIMEOUT = 600  # 上游总超时 (s)
UPSTREAM_CONNECT_TIMEOUT = 30  # 上游连接超时 (s)
MAX_UPSTREAM_RETRIES = 3  # 上游连接重试次数（含首次）
UPSTREAM_RETRY_BACKOFF = 0.5  # 上游连接重试退避基数 (s)，指数增长
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
      kind ∈ {'output_text', 'reasoning_text', 'function_call_arguments', 'item_done', 'other'}
      - delta 事件: delta_text 为文本片段
      - 'item_done'（response.output_item.done / output_text.done / ...）: delta_text=None，
        表示 item 结束，需清理跨 item 残留
      - 'other'（response.created / completed 等）: delta_text=None
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
    if evt_type.endswith('.done'):
        # 各类型 done 事件：item 结束，arg_buf 中未完成的 token 前缀
        # 不可能再有后续分片，必须清理，否则下一个 item 的
        # function_call_arguments.delta 可能跨 item 拼接伪还原
        kind = 'item_done'
    delta_text = parsed.get('delta') if kind not in ('other', 'item_done') else None
    if kind not in ('other', 'item_done') and not isinstance(delta_text, str):
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
      kind ∈ {'text', 'thinking', 'function_args', 'block_stop', 'block_start', 'other'}
      - 'text': content_block_delta 的 text_delta → delta.text
      - 'thinking': content_block_delta 的 thinking_delta → delta.thinking
      - 'function_args': content_block_delta 的 input_json_delta → delta.partial_json
      - 'block_stop': content_block_stop（块结束，需清理跨块残留）→ delta_text=None
      - 'block_start': content_block_start（tool_use 块开始，携带工具名）→
        delta_text = tool name（非 tool_use 块为 None）
      - 'other': 其他 content_block_delta 类型（server_tool_use 等）→ delta_text=None
    非 Anthropic 事件（chat/completions、responses SSE 等）返回 None。
    注：message_start / message_delta / message_stop 等
    不含文本 delta 的事件返回 None，走整行透传（原样保留，无需还原）。
    """
    evt_type = parsed.get('type') if isinstance(parsed, dict) else None
    if evt_type == 'content_block_stop':
        # 块结束：arg_buf 中未完成的 token 前缀不可能再有后续分片，
        # 必须清理，否则下一个 input_json_delta 可能跨块拼接伪还原
        return 'block_stop', None
    if evt_type == 'content_block_start':
        # tool_use 块开始：捕获工具名供 block_stop 审计用。
        # 无 tool name（text 块等）→ 返回 None（不拦截，走透传）
        cb = parsed.get('content_block')
        if isinstance(cb, dict) and cb.get('type') == 'tool_use':
            name = cb.get('name')
            if isinstance(name, str) and name:
                return 'block_start', name
        return None
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


def _strip_token_forms(content: str) -> str:
    """剥离凭据 + PII token 形态（safe 输出前清理残留 token 字符串）。

    - 凭据 token（TOKEN_STR_RE）完整形态剥离
    - PII token（PII_TOKEN_STR_RE）完整形态剥离——响应期注册的 token
      在还原时被保留（resp_t2p 形态匹配不还原），safe 输出前必须剥离
      防止把 token 字符串发给客户端
    - 残缺形态（流分片边界切断的 __VG_/__PII_ 前缀）由 _strip_partials
      兜底——任何 safe 输出出口都经此函数，统一获得残缺清理
      （Round 17 R4：mid-stream safe flush / 流末残余字节全覆盖）
    """
    out = TOKEN_STR_RE.sub('', content)
    out = PII_TOKEN_STR_RE.sub('', out)
    return _strip_partials(out)


def _split_safe_hold(content: str, active_t2p: dict, pii_scope=None) -> tuple[str, str]:
    """将累积文本分割为 (safe, hold)。

    - safe: 可安全输出（剥离行中完整 token 形态——未还原的必是幻觉/未知句柄；
      active 内的真实 token 已被 _restore 还原为明文）
    - hold: 保留到下个分片（以 __ 开头且匹配 active token 前缀）
    - pii_scope（可选）：提供 PII token 前缀集合，使 __PII_*__ 形态同样
      参与完整形态检测 / hold 判定（防 PII token 跨分片截断泄漏）
    """
    if not content:
        return '', ''
    # 完整 token 形态但不在 active_t2p（LLM 幻觉/未知句柄）→ 整体 hold，
    # 防止 rfind('__') 把完整 token 拆成两段、后续分片重组泄漏 token 字符串
    m = _FULL_TOKEN_RE.search(content)
    if m:
        token_str = m.group(0)
        if token_str not in active_t2p:
            return _strip_token_forms(content[: m.start()]), token_str
    # PII 完整 token 形态（未还原的必是幻觉/未知句柄）→ 整体 hold
    if pii_scope is not None:
        m_pii = FULL_PII_TOKEN_RE.search(content)
        if m_pii:
            token_str = m_pii.group(0)
            return (
                _strip_token_forms(content[: m_pii.start()]),
                token_str,
            )
    last_us = content.rfind('__')
    if last_us < 0:
        return _strip_token_forms(content), ''
    suffix = content[last_us:]
    maybe_prefix = any(t.startswith(suffix) for t in active_t2p)
    if pii_scope is not None:
        # PII token 前缀参与 hold 判定
        pii_tokens = set(pii_scope.pii_t2p) | set(pii_scope.resp_t2p)
        maybe_prefix = maybe_prefix or any(t.startswith(suffix) for t in pii_tokens)
    if maybe_prefix:
        return _strip_token_forms(content[:last_us]), suffix
    return _strip_token_forms(content), ''


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
            # Unescaped control char inside string → replace with escaped \\n
            result.append('\\n')
            continue
        result.append(ch)
    return ''.join(result)


def _accumulate_tool_calls(
    buf: dict[int, dict[str, str]],
    tool_calls,
) -> None:
    """累积 OpenAI chat/completions delta.tool_calls 分片（按 index 分组）。

    - tool_calls: delta.tool_calls 值（list 或 None）；None 跳过
    - 每项含 index / function.name / function.arguments 字段（缺失项跳过）
    - name 通常首个分片出现；arguments 为字符串增量分片（跨分片拼接）
    - null 值防御：function 为 None 或字段为 None 时跳过（不抛异常）
    """
    if not tool_calls or not isinstance(tool_calls, list):
        return
    for tc in tool_calls:
        if not isinstance(tc, dict):
            continue
        idx = tc.get('index')
        if idx is None or not isinstance(idx, int):
            continue
        fn = tc.get('function')
        if not isinstance(fn, dict):
            continue  # function 缺失/None → 不创建 entry（null 值防御）
        entry = buf.setdefault(idx, {'name': '', 'arguments': ''})
        name = fn.get('name')
        if isinstance(name, str) and name:
            entry['name'] += name
        args = fn.get('arguments')
        if isinstance(args, str) and args:
            entry['arguments'] += args


def _extract_tool_calls_non_stream(
    parsed: dict,
    tail: str,
) -> list[tuple[str, str]]:
    """从非流式整包响应提取 tool calls（三协议）。

    返回 [(tool_name, args_json)]：
      - OpenAI chat/completions: choices[0].message.tool_calls[]
      - Anthropic Messages: content[].tool_use（name + input JSON 序列化）
      - Responses: output[] 中 type == 'function_call'（name + arguments）
    提取失败/结构异常返回 []（不抛异常，走透传）。
    """
    if not isinstance(parsed, dict):
        return []
    tail_norm = tail.rstrip('/')
    calls: list[tuple[str, str]] = []

    # OpenAI chat/completions
    if tail_norm.endswith('chat/completions'):
        choices = parsed.get('choices') or []
        for ch in choices:
            if not isinstance(ch, dict):
                continue
            msg = ch.get('message') or {}
            tcs = msg.get('tool_calls') or []
            for tc in tcs:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get('function') or {}
                name = fn.get('name')
                args = fn.get('arguments')
                if isinstance(name, str) and name:
                    calls.append((name, args if isinstance(args, str) else ''))
        return calls

    # Anthropic Messages
    if tail_norm.endswith('v1/messages'):
        content = parsed.get('content') or []
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get('type') != 'tool_use':
                continue
            name = block.get('name')
            inp = block.get('input')
            if isinstance(name, str) and name:
                args = json.dumps(inp, ensure_ascii=False) if inp is not None else ''
                calls.append((name, args))
        return calls

    # Responses
    if tail_norm.endswith('/v1/responses'):
        output = parsed.get('output') or []
        for item in output:
            if not isinstance(item, dict):
                continue
            if item.get('type') != 'function_call':
                continue
            name = item.get('name')
            args = item.get('arguments')
            if isinstance(name, str) and name:
                calls.append((name, args if isinstance(args, str) else ''))
        return calls

    return []


# 规范化分隔符集合（design D2 skip 判定）：[-. ] 连字符、点、空格
_SEP_NORMALIZE_RE = _re.compile(r'[-. ]')


def re_sub_seps(value: str) -> str:
    """去除分隔符（[-. ]）后返回，用于还原产物规范化等价比较。"""
    return _SEP_NORMALIZE_RE.sub('', value)


class LlmMixin(AuditMixin):
    """Mixin: LLM 反向代理，脱敏/还原 + 输出审计。"""

    # ── PII 响应侧处理（还原 → 响应侧检测 → 转发）──

    def _pii_restore(
        self,
        text: str,
        active_t2p: dict,
        pii_scope,
    ) -> tuple[str, list]:
        """还原文本（凭据 + 请求级 PII），返回 (还原后文本, 还原产物区间)。

        PII 还原路径：请求级映射优先；响应期 token 形态匹配也原样保留。
        还原产物区间（restored_spans）供响应侧检测跳过——模型回显请求期
        占位符还原出的明文不得二次掩码（design D2 硬性）。
        """
        # 凭据还原（现有逻辑）
        restored = self._restore(text, active_t2p)
        # PII 请求级还原（仅还原请求期注册 token）
        restored_spans: list = []
        if pii_scope is not None:
            scope = pii_scope

            def _repl_pii(m):
                tok = m.group(0)
                if tok in scope.pii_t2p:
                    start = m.start()
                    plain = scope.pii_t2p[tok]
                    # 记录还原产物区间（原 token 位置 → 明文）
                    restored_spans.append(
                        (start, start + len(plain), plain),
                    )
                    return plain
                if tok in scope.resp_t2p:
                    return tok  # 响应期 token 原样保留
                return tok

            restored = PII_TOKEN_STR_RE.sub(_repl_pii, restored)
        return restored, restored_spans

    async def _pii_response_scan(
        self,
        text: str,
        restored_spans: list,
        pii_scope,
    ) -> str:
        """响应侧 PII 检测：仅跳过还原产物区间，新检测值注册实时映射。

        模型独立输出（非还原产物）的同值明文仍掩码为新占位符——
        不得因值与请求期已注册值等价而放行（design D2 硬性）。
        """
        if not getattr(self, 'pii_enabled', False) or not text:
            return text
        if not getattr(self, 'pii_response_side', True):
            return text
        if pii_scope is None:
            return text
        # 检测（跳过还原产物区间）
        hits = await self._pii_detector.scan(
            text,
            credential_p2t=getattr(self, 'pwd_to_token', None),
        )
        if not hits:
            return text
        # 过滤：命中值若完全落在还原产物区间内（或规范化等价）→ 跳过
        filtered: list[tuple[str, str]] = []
        for typ, value in hits:
            # 值级规范化等价比较（去除 [-. ] 分隔符）仅适用于还原产物
            norm_value = re_sub_seps(value)
            is_restored = False
            for _s, _e, plain in restored_spans:
                if norm_value == re_sub_seps(plain):
                    is_restored = True
                    break
            if not is_restored:
                filtered.append((typ, value))
        if not filtered:
            return text
        # 新检测值注册实时请求级映射（响应期）并替换
        seen: set[str] = set()
        items = []
        for typ, value in filtered:
            if value in seen:
                continue
            seen.add(value)
            items.append((len(value), typ, value))
        items.sort(key=lambda x: x[0], reverse=True)
        for _, typ, value in items:
            token = pii_scope.register(value, response_side=True)
            if token != value:
                text = text.replace(value, token)
        return text

    def _pii_active(self) -> bool:
        """当前请求是否有活跃 PII 作用域（PII 启用且已建 scope）。

        无 PiiMixin 的宿主（测试桩）返回 False——PII 功能完全禁用。
        """
        return bool(getattr(self, '_pii_scope', None))

    def _pii_scope_or_none(self):
        """返回当前请求 PII scope（无则 None）。"""
        return getattr(self, '_pii_scope', None)

    # ── 输出审计钩子（Batch 5：AuditMixin 策略引擎 + 阻断处置）──

    async def _audit_openai_tool_calls(
        self,
        tool_calls_buf: dict[int, dict[str, str]],
        active_t2p: dict,
    ) -> list[str]:
        """审计 OpenAI chat/completions 累积的 tool calls（finish_reason 触发）。

        审计读取**掩码前原始 args**（design D3 审计对抗性）——即累积的
        arguments 原文，不含 PII 占位符（PII 掩码在 flush 阶段）。

        返回：需要注入的拒绝消息 SSE 行列表（deny verdict 时生成，
        由调用方在 tool_calls 事件前 flush；allow 返回空列表）。
        """
        injections: list[str] = []
        if not tool_calls_buf or not self.audit_enabled():
            return injections
        for idx in sorted(tool_calls_buf):
            entry = tool_calls_buf[idx]
            name = entry.get('name', '')
            args = entry.get('arguments', '')
            if not name:
                continue
            verdict = await self.audit_tool_call(name, args)
            if verdict == 'deny':
                if self.audit_mode == 'approve':
                    # 审批模式：发起 Matrix 审批；approved → 放行（不注入拒绝）
                    result = await self._request_audit_approval(name, args)
                    if result == 'approved':
                        # 审批通过：补记审计日志（verdict=allow, note=approved）
                        await self._audit_log_event('allow', name, args, '', '审批通过')
                        continue
                    # rejected/expired/failed → 注入拒绝
                    await self._audit_log_event('deny', name, args, '', f'审批{result}')
                injections.append(self._build_block_event())
        return injections

    async def _request_audit_approval(self, name: str, args_json: str) -> str:
        """审批模式：发起 Matrix ✅/❎ 审批，返回 'approved'/'rejected'/'expired'/'failed'。

        design D4：
        - 审批消息含工具名 + 先脱敏后截断的参数摘要（redact_summary）+ 超时提示
        - 超时默认拒绝（AUDIT_TIMEOUT）
        - _ask 返回 None（发送失败）→ 'failed'（调用方按 rejected 处置 + 清理）
        """
        summary = redact_summary(args_json)
        timeout = getattr(self, 'audit_timeout', 90)
        if not hasattr(self, '_ask'):
            logger.error('审批模式需要 MatrixMixin（_ask 不可用）')
            return 'failed'
        req_id = f'audit-{getattr(self, "_audit_pending_seq", 0)}'
        self._audit_pending_seq = getattr(self, '_audit_pending_seq', 0) + 1
        evt = asyncio.Event()
        entry = {
            'name': name,
            'args': args_json,
            'approved': None,
            'event': evt,
        }
        self._audit_approval_pending[req_id] = entry
        msg_id = await self._ask(
            f'⚠️ 工具调用待审批: {name}\n参数摘要: {summary}\n'
            f'点 ✅ 批准 或 ❎ 拒绝（{timeout}s 超时默认拒绝）',
        )
        if msg_id is None:
            # 发送失败 → 立即按 rejected 处置 + 清理 pending
            self._audit_approval_pending.pop(req_id, None)
            return 'failed'
        self._audit_approval_msgs[msg_id] = req_id
        try:
            await asyncio.wait_for(evt.wait(), timeout=timeout)
        except TimeoutError:
            self._audit_approval_pending.pop(req_id, None)
            self._audit_approval_msgs.pop(msg_id, None)
            return 'expired'
        # reaction 已到达
        ap = self._audit_approval_pending.pop(req_id, None)
        self._audit_approval_msgs.pop(msg_id, None)
        if ap and ap.get('approved') is True:
            return 'approved'
        return 'rejected'

    def _build_block_event(self) -> str:
        """构造 OpenAI chat/completions 阻断拒绝消息 SSE 行。

        design D4：无 tool_calls 的 assistant content，finish_reason: stop——
        客户端按普通助手回复处理，不会尝试执行工具。
        """
        payload = {
            'choices': [
                {
                    'index': 0,
                    'delta': {'role': 'assistant', 'content': BLOCK_MESSAGE},
                    'finish_reason': 'stop',
                }
            ]
        }
        return f'data: {json.dumps(payload, ensure_ascii=False)}\n\n'

    def _build_block_event_anthropic(self) -> str:
        """构造 Anthropic 阻断拒绝消息 SSE 行（content_block + message_delta）。"""
        lines = []
        lines.append(
            'data: '
            + json.dumps(
                {
                    'type': 'content_block_delta',
                    'index': 0,
                    'delta': {'type': 'text_delta', 'text': BLOCK_MESSAGE},
                },
                ensure_ascii=False,
            )
            + '\n\n'
        )
        lines.append(
            'data: '
            + json.dumps(
                {
                    'type': 'message_delta',
                    'delta': {'stop_reason': 'end_turn'},
                    'usage': {'output_tokens': 1},
                },
                ensure_ascii=False,
            )
            + '\n\n'
        )
        return ''.join(lines)

    def _build_block_event_responses(self) -> str:
        """构造 Responses 阻断拒绝消息 SSE 行（output_text.delta + completed）。"""
        lines = []
        lines.append(
            'data: '
            + json.dumps(
                {
                    'type': 'response.output_text.delta',
                    'item_id': 'blocked',
                    'output_index': 0,
                    'content_index': 0,
                    'delta': BLOCK_MESSAGE,
                },
                ensure_ascii=False,
            )
            + '\n\n'
        )
        lines.append(
            'data: '
            + json.dumps(
                {
                    'type': 'response.completed',
                    'response': {
                        'id': 'blocked',
                        'status': 'completed',
                        'output': [
                            {
                                'type': 'message',
                                'role': 'assistant',
                                'content': [
                                    {'type': 'output_text', 'text': BLOCK_MESSAGE}
                                ],
                            }
                        ],
                    },
                },
                ensure_ascii=False,
            )
            + '\n\n'
        )
        return ''.join(lines)

    async def _pii_response_process(
        self,
        text: str,
        active_t2p: dict,
    ) -> str:
        """统一响应侧文本处理：还原（凭据+请求级 PII）→ 响应侧检测 → 输出。

        - PII 未启用/无 scope：等价原 _restore 行为
        - PII 启用：先还原请求级 PII token（占位符→明文，还原产物区间
          标记），再对还原后文本做响应侧 PII 检测（跳过还原产物区间，
          新检测值注册响应期映射并替换为占位符）
        """
        scope = self._pii_scope_or_none()
        if scope is None:
            return self._restore(text, active_t2p)
        restored, restored_spans = self._pii_restore(text, active_t2p, scope)
        return await self._pii_response_scan(restored, restored_spans, scope)

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
        - PII 启用（self._pii_active）：执行「还原 → 响应侧检测 → 转发」
          顺序（design D2），_split_safe_hold 携带 pii_scope
        """
        pii_scope = self._pii_scope_or_none()
        if not buf:
            return ''
        if pii_scope is not None:
            restored, restored_spans = self._pii_restore(buf, active_t2p, pii_scope)
            restored = await self._pii_response_scan(
                restored,
                restored_spans,
                pii_scope,
            )
        else:
            restored = self._restore(buf, active_t2p)
        if not keep_pending:
            restored = _strip_partials(restored)
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
        safe, pending = _split_safe_hold(restored, active_t2p, pii_scope)
        if safe:
            safe = _strip_partials(safe)
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

    async def _resolve_anthropic_hold(
        self,
        write,
        active_t2p: dict,
        line: str,
        content_buf: str,
        reasoning_buf: str,
        arg_buf: str,
    ) -> None:
        """挂起结束（block_stop 到达）：完整审计 + 审批处置。

        design D4 终态表：
        - 预检误判（完整审计 allow）→ 恢复续传：缓冲行 + block_stop 原样放行
        - deny + approve 模式 → Matrix 审批；approved → 放行；其余 → 拒绝
        - deny + block 模式 → 注入拒绝 + 终止事件，缓冲丢弃
        """
        name = self._last_anthropic_tool_name or ''
        args = getattr(self, '_audit_arg_accum', '')
        verdict = await self.audit_tool_call(name, args)
        if verdict == 'allow':
            # 预检误判：完整审计通过 → 恢复续传（缓冲行 + block_stop 放行）
            await self._release_hold(write, active_t2p, extra_line=line)
        else:
            result = 'rejected'
            if self.audit_mode == 'approve':
                result = await self._request_audit_approval(name, args)
            if result == 'approved':
                await self._release_hold(write, active_t2p, extra_line=line)
            else:
                await self._reject_anthropic_hold(write, active_t2p)
        # 清理挂起状态
        self._audit_hold_active = False
        self._audit_hold_buf = []
        self._audit_hold_bytes = 0
        self._audit_arg_accum = ''
        self._last_anthropic_tool_name = None

    async def _release_hold(
        self, write, active_t2p: dict, extra_line: str | None = None
    ) -> None:
        """放行挂起缓冲（approved / 预检误判）。

        design D4：已 flush 部分不可撤回、不得重复拼接；缓冲行按原序放行，
        均经 _pii_response_process（响应侧 PII 掩码在 flush 阶段）。
        """
        buf = getattr(self, '_audit_hold_buf', [])
        for line in buf:
            try:
                await write(
                    (await self._pii_response_process(line, active_t2p) + '\n').encode(
                        'utf-8'
                    )
                )
            except (
                ConnectionResetError,
                ConnectionAbortedError,
                BrokenPipeError,
            ):
                logger.debug('SSE 挂起放行写入失败')
                break
        if extra_line:
            try:
                await write(
                    (
                        await self._pii_response_process(extra_line, active_t2p) + '\n'
                    ).encode('utf-8')
                )
            except (
                ConnectionResetError,
                ConnectionAbortedError,
                BrokenPipeError,
            ):
                logger.debug('SSE 挂起终止写入失败')

    async def _reject_anthropic_hold(self, write, active_t2p: dict) -> None:
        """拒绝挂起（rejected/expired/failed/超限）：注入拒绝 + 终止事件，缓冲丢弃。

        design D4：挂起期间缓冲的 content 一律丢弃（拒绝后不再放行）。
        """
        # 丢弃缓冲（含未 flush 的参数残余）+ 解除挂起（后续事件正常转发）
        self._audit_hold_buf = []
        self._audit_hold_bytes = 0
        self._audit_hold_active = False
        self._audit_arg_accum = ''
        self._last_anthropic_tool_name = None
        try:
            await write(self._build_block_event_anthropic().encode('utf-8'))
        except (
            ConnectionResetError,
            ConnectionAbortedError,
            BrokenPipeError,
        ):
            logger.debug('SSE 挂起拒绝注入失败')

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
            await write(
                (await self._pii_response_process(line, active_t2p) + '\n').encode(
                    'utf-8'
                )
            )
            return content_buf, reasoning_buf, arg_buf
        kind, delta_text = event

        # ── 审计挂起状态（design D4：verdict 前暂停 flush）──
        # 预检命中后：所有事件行缓冲（不 write），block_stop 到达时统一处置
        if getattr(self, '_audit_hold_active', False):
            if kind == 'block_stop':
                # 挂起结束：完整审计 + 审批处置
                await self._resolve_anthropic_hold(
                    write,
                    active_t2p,
                    line,
                    content_buf,
                    reasoning_buf,
                    arg_buf,
                )
                return content_buf, reasoning_buf, ''
            # 挂起期间参数 delta 仍须累积（block_stop 审计读完整参数）
            if kind == 'function_args' and delta_text is not None:
                arg_buf += delta_text
                self._audit_arg_accum = (
                    getattr(self, '_audit_arg_accum', '') + delta_text
                )
            # 缓冲超限 → fail-closed（design D4：超限按 rejected 处置）
            if (
                len(line.encode('utf-8')) + getattr(self, '_audit_hold_bytes', 0)
                > self.audit_hold_max_bytes
            ):
                await self._reject_anthropic_hold(write, active_t2p)
                return content_buf, reasoning_buf, arg_buf
            self._audit_hold_buf.append(line)
            self._audit_hold_bytes = getattr(self, '_audit_hold_bytes', 0) + len(
                line.encode('utf-8')
            )
            return content_buf, reasoning_buf, arg_buf

        if kind == 'block_stop':
            # 工具调用块结束：arg_buf 中未完成的 token 前缀不可能再有
            # 后续分片（token 不会跨两个 tool_use block），清空防伪还原
            # （content/reasoning 保留 pending，由流末统一清理）
            # 审计触发点：读取掩码前原始完整参数累积器（design D3 审计对抗性）
            if getattr(self, '_audit_arg_accum', '') and self.audit_enabled():
                name = self._last_anthropic_tool_name or ''
                verdict = await self.audit_tool_call(
                    name, getattr(self, '_audit_arg_accum', '')
                )
                if verdict == 'deny':
                    if self.audit_mode == 'approve':
                        # 审批模式：发起 Matrix 审批；approved → 放行（不注入拒绝）
                        result = await self._request_audit_approval(
                            name, getattr(self, '_audit_arg_accum', '')
                        )
                        if result == 'approved':
                            verdict = 'allow'
                    if verdict == 'deny':
                        # 阻断：注入拒绝消息 + block_stop 终止事件（design D4 防 dangling）
                        await write(self._build_block_event_anthropic().encode('utf-8'))
            if hasattr(self, '_audit_arg_accum'):
                self._audit_arg_accum = ''
            self._last_anthropic_tool_name = None
            await write(
                (await self._pii_response_process(line, active_t2p) + '\n').encode(
                    'utf-8'
                )
            )
            return content_buf, reasoning_buf, ''

        if kind == 'block_start':
            # tool_use 块开始：记录工具名（block_stop 审计用）
            if delta_text:
                self._last_anthropic_tool_name = delta_text
            await write(
                (await self._pii_response_process(line, active_t2p) + '\n').encode(
                    'utf-8'
                )
            )
            return content_buf, reasoning_buf, arg_buf

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
                # 审计参数累积（掩码前原始完整参数，design D3）
                self._audit_arg_accum = (
                    getattr(self, '_audit_arg_accum', '') + delta_text
                )
                # ── 预检暂停（design D4：暂停先于判定）──
                # 同步廉价前缀匹配，命中即暂停 flush——不 await 异步判定
                # （await 期间后续 delta 会继续走 flush 循环流出）
                if (
                    self.audit_enabled()
                    and not getattr(self, '_audit_hold_active', False)
                    and self.audit_precheck(
                        self._last_anthropic_tool_name or '',
                        self._audit_arg_accum,
                    )
                ):
                    self._audit_hold_active = True
                    self._audit_hold_buf = []
                    self._audit_hold_bytes = 0
                    # 本次 delta 行缓冲（不 flush）
                    self._audit_hold_buf.append(line)
                    self._audit_hold_bytes = len(line.encode('utf-8'))
                    return content_buf, reasoning_buf, arg_buf
            buf = (
                content_buf
                if kind == 'text'
                else (reasoning_buf if kind == 'thinking' else arg_buf)
            )
            restored = await self._pii_response_process(buf, active_t2p)
            safe, pending = _split_safe_hold(
                restored, active_t2p, self._pii_scope_or_none()
            )
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
        await write(
            (await self._pii_response_process(line, active_t2p) + '\n').encode('utf-8')
        )
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
        - PII 启用（self._pii_active）：执行「还原 → 响应侧检测 → 转发」
          顺序（design D2），_split_safe_hold 携带 pii_scope
        """
        pii_scope = self._pii_scope_or_none()
        if not buf:
            return ''
        if pii_scope is not None:
            restored, restored_spans = self._pii_restore(buf, active_t2p, pii_scope)
            restored = await self._pii_response_scan(
                restored,
                restored_spans,
                pii_scope,
            )
        else:
            restored = self._restore(buf, active_t2p)
        if not keep_pending:
            restored = _strip_partials(restored)
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
        safe, pending = _split_safe_hold(restored, active_t2p, pii_scope)
        if safe:
            safe = _strip_partials(safe)
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

    async def _resolve_responses_hold(
        self,
        write,
        active_t2p: dict,
        line: str,
        content_buf: str,
        reasoning_buf: str,
        arg_buf: str,
    ) -> None:
        """挂起结束（item_done 到达）：完整审计 + 审批处置（同 Anthropic）。"""
        name = self._last_responses_tool_name or ''
        args = getattr(self, '_audit_arg_accum', '')
        verdict = await self.audit_tool_call(name, args)
        if verdict == 'allow':
            await self._release_hold(write, active_t2p, extra_line=line)
        else:
            result = 'rejected'
            if self.audit_mode == 'approve':
                result = await self._request_audit_approval(name, args)
            if result == 'approved':
                await self._release_hold(write, active_t2p, extra_line=line)
            else:
                await self._reject_responses_hold(write, active_t2p)
        # 清理挂起状态
        self._audit_hold_active = False
        self._audit_hold_buf = []
        self._audit_hold_bytes = 0
        self._audit_arg_accum = ''
        self._last_responses_tool_name = None

    async def _reject_responses_hold(self, write, active_t2p: dict) -> None:
        """拒绝挂起（rejected/expired/failed/超限）：注入拒绝 + 终止事件，缓冲丢弃。"""
        self._audit_hold_buf = []
        self._audit_hold_bytes = 0
        self._audit_hold_active = False
        self._audit_arg_accum = ''
        self._last_responses_tool_name = None
        try:
            await write(self._build_block_event_responses().encode('utf-8'))
        except (
            ConnectionResetError,
            ConnectionAbortedError,
            BrokenPipeError,
        ):
            logger.debug('SSE 挂起拒绝注入失败')

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
            await write(
                (await self._pii_response_process(line, active_t2p) + '\n').encode(
                    'utf-8'
                )
            )
            return content_buf, reasoning_buf, arg_buf

        # ── 审计挂起状态（design D4：verdict 前暂停 flush）──
        if getattr(self, '_audit_hold_active', False):
            if kind == 'item_done':
                # 挂起结束：完整审计 + 审批处置
                await self._resolve_responses_hold(
                    write,
                    active_t2p,
                    line,
                    content_buf,
                    reasoning_buf,
                    arg_buf,
                )
                return content_buf, reasoning_buf, ''
            # 挂起期间参数 delta 仍须累积（item_done 审计读完整参数）
            if kind == 'function_call_arguments' and delta_text is not None:
                arg_buf += delta_text
                self._audit_arg_accum = (
                    getattr(self, '_audit_arg_accum', '') + delta_text
                )
            # 缓冲超限 → fail-closed
            if (
                len(line.encode('utf-8')) + getattr(self, '_audit_hold_bytes', 0)
                > self.audit_hold_max_bytes
            ):
                await self._reject_responses_hold(write, active_t2p)
                return content_buf, reasoning_buf, arg_buf
            self._audit_hold_buf.append(line)
            self._audit_hold_bytes = getattr(self, '_audit_hold_bytes', 0) + len(
                line.encode('utf-8')
            )
            return content_buf, reasoning_buf, arg_buf

        if kind == 'item_done':
            # item 结束：arg_buf 中未完成的 token 前缀不可能再有后续分片
            # （function call 参数不会跨 item 续写），清空防跨 item 伪还原
            # （content/reasoning 保留 pending，由流末统一清理）
            # 审计触发点：读取掩码前原始完整参数累积器（design D3 审计对抗性）
            if getattr(self, '_audit_arg_accum', '') and self.audit_enabled():
                name = self._last_responses_tool_name or ''
                verdict = await self.audit_tool_call(
                    name, getattr(self, '_audit_arg_accum', '')
                )
                if verdict == 'deny':
                    if self.audit_mode == 'approve':
                        # 审批模式：发起 Matrix 审批；approved → 放行（不注入拒绝）
                        result = await self._request_audit_approval(
                            name, getattr(self, '_audit_arg_accum', '')
                        )
                        if result == 'approved':
                            verdict = 'allow'
                    if verdict == 'deny':
                        # 阻断：注入拒绝消息 + item_done 终止事件（design D4 防 dangling）
                        await write(self._build_block_event_responses().encode('utf-8'))
            if hasattr(self, '_audit_arg_accum'):
                self._audit_arg_accum = ''
            self._last_responses_tool_name = None
            await write(
                (await self._pii_response_process(line, active_t2p) + '\n').encode(
                    'utf-8'
                )
            )
            return content_buf, reasoning_buf, ''

        if kind in ('output_text', 'reasoning_text', 'function_call_arguments'):
            if delta_text is None:  # pragma: no cover — 识别器保证 delta 事件携带 str
                return content_buf, reasoning_buf, arg_buf
            if kind == 'output_text':
                content_buf += delta_text
            elif kind == 'reasoning_text':
                reasoning_buf += delta_text
            else:
                arg_buf += delta_text
                # 审计参数累积（掩码前原始完整参数，design D3）
                self._audit_arg_accum = (
                    getattr(self, '_audit_arg_accum', '') + delta_text
                )
                # ── 预检暂停（design D4：暂停先于判定）──
                if (
                    self.audit_enabled()
                    and not getattr(self, '_audit_hold_active', False)
                    and self.audit_precheck(
                        self._last_responses_tool_name or '',
                        self._audit_arg_accum,
                    )
                ):
                    self._audit_hold_active = True
                    self._audit_hold_buf = []
                    self._audit_hold_bytes = 0
                    # 本次 delta 行缓冲（不 flush）
                    self._audit_hold_buf.append(line)
                    self._audit_hold_bytes = len(line.encode('utf-8'))
                    return content_buf, reasoning_buf, arg_buf
            buf = (
                content_buf
                if kind == 'output_text'
                else (reasoning_buf if kind == 'reasoning_text' else arg_buf)
            )
            restored = await self._pii_response_process(buf, active_t2p)
            safe, pending = _split_safe_hold(
                restored, active_t2p, self._pii_scope_or_none()
            )
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
        # 捕获 function call 工具名（response.function_call 事件，item_done 审计用）
        if isinstance(parsed, dict):
            item = parsed.get('item')
            if isinstance(item, dict) and item.get('type') == 'function_call':
                name = item.get('name')
                if isinstance(name, str) and name:
                    self._last_responses_tool_name = name
        await write(
            (await self._pii_response_process(line, active_t2p) + '\n').encode('utf-8')
        )
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
            # 请求级工具名追踪（Anthropic block_start → block_stop 审计用）
            self._last_anthropic_tool_name = None
            # 请求级工具名追踪（Responses function_call → item_done 审计用）
            self._last_responses_tool_name = None
            # 请求级审计参数累积器（design D3：审计读掩码前原始完整参数，
            # 独立于流式 arg_buf——后者被 safe/hold 分割消费）
            self._audit_arg_accum = ''
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
                # PII 请求侧脱敏（在凭据 redact 前，PII_REDACTION_ENABLED 时）：
                # 检测 PII → 注册请求级映射 → 替换为 __PII_*__ 占位符
                if getattr(self, 'pii_enabled', False):
                    self._pii_request_scope()
                    body_text = await self.pii_redact(body_text)
                out_body = self._redact(body_text, snapshot_p2t).encode('utf-8')
                # 快速路径：无 token 时不扫描（门控扩展：PII token 同样触发还原路径）
                pii_scope = self._pii_scope_or_none()
                has_cred = snapshot_t2p and b'__VG_CRED_' in out_body
                has_pii = bool(pii_scope) and b'__PII_' in out_body
                if has_cred or has_pii:
                    # 收集本次请求实际使用的 token，仅还原这些（防 LLM 幻觉泄露）。
                    # used_tokens 仅收集实际注册产出的 token：凭据注册表命中
                    # （快照中已存在）+ PII 请求级映射——不收集任意 TOKEN_RE
                    # 形态匹配（关闭「prompt 字面量 __VG_CRED_*__ → 回显 → 还原」放大路径）
                    used_tokens = set()
                    for m in TOKEN_RE.finditer(out_body):
                        used_tokens.add(m.group().decode())
                    if pii_scope:
                        for m in PII_TOKEN_RE.finditer(out_body):
                            used_tokens.add(m.group().decode())
                    active_t2p = {
                        t: p for t, p in snapshot_t2p.items() if t in used_tokens
                    }
                else:
                    active_t2p = {}
            else:
                out_body = body
                active_t2p = {}
                pii_scope = None

            # 透传 Hermes headers（过滤逐跳头）
            headers = filter_hop_headers(dict(request.headers))

            try:
                # 上游连接重试：仅对「拿到响应头之前」的瞬时连接异常重试。
                # ServerDisconnectedError（上游主动断开）/ ClientConnectionError（连接层）/
                # TimeoutError（connect 超时）均为瞬时故障，LLM chat 请求重试幂等安全。
                # 一旦拿到 upstream_resp（进入 SSE 转发/读 body），绝不再重试。
                upstream_resp = None
                for attempt in range(MAX_UPSTREAM_RETRIES):
                    try:
                        upstream_resp = await session.request(
                            request.method,
                            target_url,
                            headers=headers,
                            data=out_body,
                        )
                        break
                    except (
                        ServerDisconnectedError,
                        ClientConnectionError,
                        TimeoutError,
                    ) as e:
                        if attempt == MAX_UPSTREAM_RETRIES - 1:
                            raise
                        delay = UPSTREAM_RETRY_BACKOFF * (2**attempt)
                        logger.warning(
                            'LLM 上游连接异常(%s)，%.1fs 后重试 %d/%d: %s %s',
                            type(e).__name__,
                            delay,
                            attempt + 2,
                            MAX_UPSTREAM_RETRIES,
                            request.method,
                            target_url,
                        )
                        await asyncio.sleep(delay)

                # 循环内要么 break 要么 raise，到达此处必非 None
                assert upstream_resp is not None
                # async with 确保上游响应在 SSE 客户端断连时正确释放连接
                async with upstream_resp:
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

                        if active_t2p or self._pii_active() or self.audit_enabled():
                            # ── JSON-aware 流式 token 还原（广义 Plan C） ──
                            content_buf = ''  # 累积 delta.content 片段（每事件经 safe/pending 分割重置为小字符串，摊还 O(1)）
                            reasoning_buf = ''  # 累积 delta.reasoning_content 片段
                            arg_buf = ''  # 累积 responses function_call_arguments / anthropic partial_json 片段
                            is_responses_stream = False  # 本流是否 Responses API SSE
                            is_anthropic_stream = (
                                False  # 本流是否 Anthropic Messages API SSE
                            )
                            byte_buf = bytearray()
                            resp_log_path = None
                            sse_event_count = 0  # 空流检测：统计 data 事件数
                            # OpenAI chat/completions tool_calls 分片累积：
                            # index → {'name': str, 'arguments': str}
                            tool_calls_buf: dict[int, dict[str, str]] = {}
                            tool_calls_audited = (
                                False  # 防止重复审计（finish_reason + 流末双触发）
                            )
                            tool_calls_blocked = (
                                False  # 审计 deny：抑制后续 tool_calls 事件流出
                            )
                            # 审计启用时缓冲 tool_calls SSE 行（design D4：未出 verdict 不流出）
                            tool_calls_pending_events: list[str] = []

                            async def _flush(
                                c: str = '',
                                rc: str = '',
                                fr: str | None = None,
                            ):
                                """flush 内容作为 SSE 事件并清空缓冲区。"""
                                nonlocal content_buf, reasoning_buf
                                if c or rc or fr:
                                    if c:
                                        c = await self._pii_response_process(
                                            c, active_t2p
                                        )
                                        c = _strip_partials(c)
                                    if rc:
                                        rc = await self._pii_response_process(
                                            rc, active_t2p
                                        )
                                        rc = _strip_partials(rc)
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
                                                    await self._pii_response_process(
                                                        line, active_t2p
                                                    )
                                                    + '\n'
                                                ).encode('utf-8'),
                                            )
                                            continue

                                        payload = line[5:]
                                        payload = payload.removeprefix(' ')

                                        sse_event_count += 1

                                        # [DONE] 标记：先 flush 累积内容
                                        if payload.strip() == '[DONE]':
                                            # 流末兜底审计（finish_reason 未触发时）
                                            if (
                                                tool_calls_buf
                                                and not tool_calls_audited
                                            ):
                                                tool_calls_audited = True
                                                injections = (
                                                    await self._audit_openai_tool_calls(
                                                        tool_calls_buf,
                                                        active_t2p,
                                                    )
                                                )
                                                if injections:
                                                    # deny：丢弃缓冲 + 注入拒绝
                                                    tool_calls_blocked = True
                                                    tool_calls_pending_events.clear()
                                                    for ev in injections:
                                                        await resp.write(
                                                            ev.encode('utf-8')
                                                        )
                                                else:
                                                    # allow：verdict 后统一放行缓冲事件
                                                    for ev in tool_calls_pending_events:
                                                        await resp.write(
                                                            (
                                                                await self._pii_response_process(
                                                                    ev, active_t2p
                                                                )
                                                                + '\n'
                                                            ).encode('utf-8')
                                                        )
                                                    tool_calls_pending_events.clear()
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
                                                        await self._pii_response_process(
                                                            line, active_t2p
                                                        )
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

                                            # ── OpenAI tool_calls 分片累积 ──
                                            # 全程缓冲至审计 verdict 前不 flush
                                            # （design D4：未出 verdict 无 tool call 事件流出）
                                            if delta.get('tool_calls') is not None:
                                                _accumulate_tool_calls(
                                                    tool_calls_buf,
                                                    delta['tool_calls'],
                                                )
                                                if self.audit_enabled():
                                                    # 审计启用：缓冲事件行，verdict 后统一放行/丢弃
                                                    tool_calls_pending_events.append(
                                                        line
                                                    )
                                                    continue

                                            # ── finish_reason == tool_calls：审计触发点 ──
                                            if (
                                                finish_reason == 'tool_calls'
                                                and tool_calls_buf
                                                and not tool_calls_audited
                                            ):
                                                tool_calls_audited = True
                                                injections = (
                                                    await self._audit_openai_tool_calls(
                                                        tool_calls_buf,
                                                        active_t2p,
                                                    )
                                                )
                                                if injections:
                                                    # deny：丢弃缓冲的 tool_calls 事件 + 注入拒绝
                                                    tool_calls_blocked = True
                                                    tool_calls_pending_events.clear()
                                                    for ev in injections:
                                                        await resp.write(
                                                            ev.encode('utf-8')
                                                        )
                                                else:
                                                    # allow：verdict 后统一放行缓冲事件
                                                    for ev in tool_calls_pending_events:
                                                        await resp.write(
                                                            (
                                                                await self._pii_response_process(
                                                                    ev, active_t2p
                                                                )
                                                                + '\n'
                                                            ).encode('utf-8')
                                                        )
                                                    tool_calls_pending_events.clear()

                                            # deny：finish_reason: tool_calls 行不透传
                                            # （客户端不应看到 tool_calls 语义——拒绝后
                                            # 只有拒绝消息 + finish_reason: stop）
                                            # 只跳过当前终止行，不得永久跳过后续行
                                            # （阻断后模型可能继续发 content 说明）
                                            if tool_calls_blocked and (
                                                finish_reason == 'tool_calls'
                                            ):
                                                continue

                                            # ── Reasoning content（独立处理，不受 content 影响）──
                                            rc_val = delta.get('reasoning_content')
                                            if rc_val is not None:
                                                reasoning_buf += rc_val
                                                restored = (
                                                    await self._pii_response_process(
                                                        reasoning_buf, active_t2p
                                                    )
                                                )
                                                safe, pending = _split_safe_hold(
                                                    restored,
                                                    active_t2p,
                                                    self._pii_scope_or_none(),
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
                                                    reasoning_buf = await self._pii_response_process(
                                                        reasoning_buf, active_t2p
                                                    )
                                                    reasoning_buf = _strip_partials(
                                                        reasoning_buf
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
                                                restored = (
                                                    await self._pii_response_process(
                                                        content_buf, active_t2p
                                                    )
                                                )

                                                # 找安全 flush 点
                                                safe, pending = _split_safe_hold(
                                                    restored,
                                                    active_t2p,
                                                    self._pii_scope_or_none(),
                                                )

                                                # flush 安全部分
                                                if safe:
                                                    await resp.write(
                                                        _mk_sse_event(safe).encode(),
                                                    )
                                                content_buf = pending

                                                if finish_reason:
                                                    content_buf = await self._pii_response_process(
                                                        content_buf, active_t2p
                                                    )
                                                    content_buf = _strip_partials(
                                                        content_buf
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
                                                # 审计阻断：抑制 tool_calls 事件流出
                                                # （design D4：拒绝后 tool call 不发给客户端）
                                                if tool_calls_blocked and (
                                                    'tool_calls' in delta
                                                    or delta.get('role') == 'assistant'
                                                    and 'content' not in delta
                                                ):
                                                    continue
                                                await resp.write(
                                                    (
                                                        await self._pii_response_process(
                                                            line, active_t2p
                                                        )
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
                                                # 非 dict payload（数组/标量）→ 原样透传
                                                # （与主循环 isinstance 防御对称）
                                                if not isinstance(parsed, dict):
                                                    await resp.write(
                                                        (
                                                            await self._pii_response_process(
                                                                'data: ' + sanitized,
                                                                active_t2p,
                                                            )
                                                            + '\n'
                                                        ).encode('utf-8'),
                                                    )
                                                    continue
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
                                                    rc_restored = await self._pii_response_process(
                                                        rc_combined, active_t2p
                                                    )
                                                    rc_restored = _strip_partials(
                                                        rc_restored
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
                                                    restored = await self._pii_response_process(
                                                        combined, active_t2p
                                                    )
                                                    restored = _strip_partials(restored)
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
                                                            + await self._pii_response_process(
                                                                sanitized, active_t2p
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
                                                        await self._pii_response_process(
                                                            line, active_t2p
                                                        )
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
                                                    await self._pii_response_process(
                                                        line, active_t2p
                                                    )
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

                            # 流结束：未审计 tool call 兜底（design D4 硬性）
                            # EOF/[DONE] 前上游正常结束但无终止事件（不完整
                            # tool call）→ 一律 fail-closed 丢弃 + 注入拒绝；
                            # 连接中断（无 [DONE]）同理——已累积未审计的
                            # tool call 不得静默 flush
                            if (
                                tool_calls_buf
                                and not tool_calls_audited
                                and self.audit_enabled()
                            ):
                                tool_calls_audited = True
                                _inj = await self._audit_openai_tool_calls(
                                    tool_calls_buf,
                                    active_t2p,
                                )
                                if _inj:
                                    tool_calls_blocked = True
                                    tool_calls_pending_events.clear()
                                    for _ev in _inj:
                                        try:
                                            await resp.write(_ev.encode('utf-8'))
                                        except SSE_CLIENT_GONE:
                                            break
                                else:
                                    for _ev in tool_calls_pending_events:
                                        try:
                                            await resp.write(
                                                (
                                                    await self._pii_response_process(
                                                        _ev, active_t2p
                                                    )
                                                    + '\n'
                                                ).encode('utf-8')
                                            )
                                        except SSE_CLIENT_GONE:
                                            break
                                    tool_calls_pending_events.clear()

                            # 流末：Anthropic/Responses 未完成 tool call 兜底
                            # （design D4 硬性：正常结束但无 block_stop/item_done
                            # 终止事件 → 不完整参数不得 flush，fail-closed 丢弃）
                            if (
                                getattr(self, '_audit_arg_accum', '')
                                and self.audit_enabled()
                                and (is_anthropic_stream or is_responses_stream)
                            ):
                                _name = (
                                    self._last_anthropic_tool_name
                                    if is_anthropic_stream
                                    else self._last_responses_tool_name
                                ) or ''
                                _args = getattr(self, '_audit_arg_accum', '')
                                _verdict = await self.audit_tool_call(_name, _args)
                                if _verdict == 'deny' and self.audit_mode == 'approve':
                                    _result = await self._request_audit_approval(
                                        _name, _args
                                    )
                                    if _result != 'approved':
                                        _verdict = 'deny'
                                if _verdict == 'deny':
                                    # 不完整 tool call：丢弃 arg_buf + 注入拒绝
                                    arg_buf = ''
                                    if is_anthropic_stream:
                                        _block = self._build_block_event_anthropic()
                                    else:
                                        _block = self._build_block_event_responses()
                                    try:
                                        await resp.write(_block.encode('utf-8'))
                                    except SSE_CLIENT_GONE:
                                        pass
                                self._audit_arg_accum = ''
                                self._last_anthropic_tool_name = None
                                self._last_responses_tool_name = None

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
                                    content_buf = await self._pii_response_process(
                                        content_buf, active_t2p
                                    )
                                    content_buf = _strip_partials(content_buf)
                                if reasoning_buf:
                                    reasoning_buf = await self._pii_response_process(
                                        reasoning_buf, active_t2p
                                    )
                                    reasoning_buf = _strip_partials(reasoning_buf)
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
                                    restored = await self._pii_response_process(
                                        residual, active_t2p
                                    )
                                    # 流末残余清理（Round 17 R4 收尾）：残余字节可能
                                    # 含分片切断的 token 前缀（__VG_C…/__PII_…），
                                    # _pii_response_process 不清理，这里统一剥除防泄漏。
                                    restored = _strip_partials(restored)
                                    await resp.write(
                                        restored.encode('utf-8'),
                                    )
                                except (
                                    ConnectionResetError,
                                    ConnectionAbortedError,
                                    BrokenPipeError,
                                ):
                                    logger.debug('SSE 残余写入失败')
                            if sse_event_count == 0 and upstream_resp.status == 200:
                                logger.warning(
                                    'LLM 上游返回空流(0 data events, %d bytes): %s %s '
                                    '(client may see EmptyStreamError)',
                                    len(byte_buf),
                                    request.method,
                                    target_url,
                                )
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
                            fast_sse_event_count = 0
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

                                            fast_sse_event_count += 1

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

                                            restored = 'data: ' + (
                                                await self._pii_response_process(
                                                    payload, active_t2p
                                                )
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
                                    restored = await self._pii_response_process(
                                        residual, active_t2p
                                    )
                                    # 流末残余清理（Round 17 R4 收尾）：残余字节可能
                                    # 含分片切断的 token 前缀（__VG_C…/__PII_…），
                                    # _pii_response_process 不清理，这里统一剥除防泄漏。
                                    restored = _strip_partials(restored)
                                    await resp.write(
                                        restored.encode('utf-8'),
                                    )
                                except (
                                    ConnectionResetError,
                                    ConnectionAbortedError,
                                    BrokenPipeError,
                                ):
                                    logger.debug('SSE 残余写入失败')
                            if (
                                fast_sse_event_count == 0
                                and upstream_resp.status == 200
                            ):
                                logger.warning(
                                    'LLM 上游返回空流(0 data events, %d bytes): %s %s '
                                    '(client may see EmptyStreamError)',
                                    len(byte_buf),
                                    request.method,
                                    target_url,
                                )
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

                        if (
                            not resp_body
                            and upstream_resp.status == 200
                            and (
                                tail.rstrip('/').endswith('chat/completions')
                                or tail.rstrip('/').endswith('v1/messages')
                            )
                        ):
                            logger.warning(
                                'LLM 上游返回空响应体(%d bytes): %s %s '
                                '(client may see EmptyStreamError)',
                                len(resp_body),
                                request.method,
                                target_url,
                            )

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
                        # 非流式整包审计（design D4：不因缺 SSE 完成事件跳过）
                        blocked = False
                        if self.audit_enabled() and resp_text:
                            try:
                                _resp_json = json.loads(resp_text)
                                _calls = _extract_tool_calls_non_stream(
                                    _resp_json,
                                    tail,
                                )
                                for _name, _args in _calls:
                                    _verdict = await self.audit_tool_call(_name, _args)
                                    if _verdict == 'deny':
                                        blocked = True
                            except json.JSONDecodeError:
                                pass
                        if blocked:
                            # 阻断：用拒绝消息替换整个响应体（design D4）
                            _tail_norm = tail.rstrip('/')
                            if _tail_norm.endswith('chat/completions'):
                                _block_body = json.dumps(
                                    {
                                        'choices': [
                                            {
                                                'index': 0,
                                                'message': {
                                                    'role': 'assistant',
                                                    'content': BLOCK_MESSAGE,
                                                },
                                                'finish_reason': 'stop',
                                            }
                                        ]
                                    },
                                    ensure_ascii=False,
                                )
                            elif _tail_norm.endswith(('messages', 'v1/messages')):
                                _block_body = json.dumps(
                                    {
                                        'id': 'blocked',
                                        'type': 'message',
                                        'role': 'assistant',
                                        'content': [
                                            {
                                                'type': 'text',
                                                'text': BLOCK_MESSAGE,
                                            }
                                        ],
                                        'stop_reason': 'end_turn',
                                        'usage': {
                                            'input_tokens': 0,
                                            'output_tokens': 1,
                                        },
                                    },
                                    ensure_ascii=False,
                                )
                            else:  # Responses API
                                _block_body = json.dumps(
                                    {
                                        'id': 'blocked',
                                        'status': 'completed',
                                        'output': [
                                            {
                                                'type': 'message',
                                                'role': 'assistant',
                                                'content': [
                                                    {
                                                        'type': 'output_text',
                                                        'text': BLOCK_MESSAGE,
                                                    }
                                                ],
                                            }
                                        ],
                                    },
                                    ensure_ascii=False,
                                )
                            return web.Response(
                                body=_block_body.encode('utf-8'),
                                status=200,
                                headers=filter_hop_headers(
                                    dict(upstream_resp.headers),
                                ),
                            )
                        out_text = await self._pii_response_process(
                            resp_text, active_t2p
                        )
                        # 非流式整包：还原后统一清理残缺/完整幻觉 token 形态
                        # （Round 17 R4：非流式出口缺 _strip_partials）
                        out_text = _strip_partials(out_text)
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
            finally:
                # 请求级 PII 映射清理（无论成功/异常/客户端断连）
                if getattr(self, 'pii_enabled', False):
                    self._pii_cleanup()
                # 请求级审计状态清理（design D4 6.4：审批/挂起与流生命周期绑定）
                # 未决审批 → 取消（置 rejected 语义）；挂起缓冲 → 丢弃
                if getattr(self, 'audit_enabled_flag', False):
                    for _req_id, _ap in list(
                        getattr(self, '_audit_approval_pending', {}).items()
                    ):
                        if _ap.get('approved') is None:
                            _ap['approved'] = False
                            _ap['event'].set()
                    self._audit_approval_pending.clear()
                    self._audit_approval_msgs.clear()
                    self._audit_hold_active = False
                    self._audit_hold_buf = []
                    self._audit_hold_bytes = 0
                    self._audit_arg_accum = ''

        app = web.Application()
        app.router.add_route('*', '/{tail:.*}', handler)
        # 注意：不在此处注册 session.close() — _shared_session 由 shutdown() 统一关闭
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, '0.0.0.0', port).start()
        self._runners.append(runner)
        logger.info('LLM 代理 → 0.0.0.0:%d → %s', port, upstream)
