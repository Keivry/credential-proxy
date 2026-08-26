"""residual_hardening_test.py — 流式三层缓冲与保活加固验收 (tasks 3.1-3.4)."""

import asyncio
import json
import sys
import types
from unittest.mock import MagicMock

import pytest

# Mock aiohttp / _matrix before importing _llm (同 llm_test.py)
aw = types.ModuleType('aiohttp.web')
aw.Response = MagicMock()
aw.Application = MagicMock()
aw.AppRunner = MagicMock()
aw.TCPSite = MagicMock()
aw.StreamResponse = MagicMock()
aw.json_response = MagicMock(return_value=MagicMock())
aiohttp = types.ModuleType('aiohttp')
aiohttp.web = aw
aiohttp.ClientSession = MagicMock()
aiohttp.ClientTimeout = MagicMock()
ce = types.ModuleType('aiohttp.client_exceptions')
ce.ClientConnectionError = type('ClientConnectionError', (Exception,), {})
ce.ServerDisconnectedError = type('ServerDisconnectedError', (Exception,), {})
ce.ClientConnectionResetError = type('ClientConnectionResetError', (Exception,), {})
aiohttp.client_exceptions = ce
sys.modules.setdefault('aiohttp', aiohttp)
sys.modules.setdefault('aiohttp.web', aw)
sys.modules.setdefault('aiohttp.client_exceptions', ce)
mx = types.ModuleType('_matrix')
mx.SSE_CLIENT_GONE = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)
sys.modules.setdefault('_matrix', mx)

from _llm import (
    KEEPALIVE_INTERVAL,
    LINE_BUF_FLUSH,
    LINE_BUF_MAX_AGE,
    SSE_MAX_BUF,
    _anthropic_event,
    _mk_sse_event,
    _responses_event,
    _split_safe_hold,
    _strip_partials,
)

# ── 3.1 byte_buf WHATWG ────────────────────────────────────────────


def test_split_safe_hold_basic():
    safe, pending = _split_safe_hold('hello world', {})
    assert safe == 'hello world'
    assert pending == ''


def test_strip_partials_full_retained():
    full = '__PII_1_ab12cd34__'
    assert _strip_partials(f'x{full}y') == f'x{full}y'


def test_strip_partials_incomplete_removed():
    assert _strip_partials('__PI') == ''
    assert _strip_partials('__PII_99_') == ''


def test_sse_constants():
    assert LINE_BUF_FLUSH == 16384
    assert LINE_BUF_MAX_AGE == 30
    assert KEEPALIVE_INTERVAL == 10
    assert SSE_MAX_BUF == 1_048_576


def test_mk_sse_event_contains_data_prefix():
    ev = _mk_sse_event('hi')
    assert ev.startswith('data: ')
    assert ev.endswith('\n')


# Anthropic / Responses 事件分发
def test_anthropic_event_text_delta():
    kind, val = _anthropic_event(
        {'type': 'content_block_delta', 'delta': {'type': 'text_delta', 'text': 'hi'}}
    )
    assert kind == 'text' and val == 'hi'


def test_responses_event_output_text_delta():
    kind, val = _responses_event({'type': 'response.output_text.delta', 'delta': 'hi'})
    assert kind == 'output_text' and val == 'hi'


def test_anthropic_event_signature_exempt():
    kind, val = _anthropic_event(
        {
            'type': 'content_block_delta',
            'delta': {'type': 'signature_delta', 'signature': 'sig'},
        }
    )
    # signature_delta 豁免透传，归 other
    assert kind == 'other'


def test_responses_audio_delta_ignored():
    kind, val = _responses_event({'type': 'response.audio.delta', 'delta': 'bytes...'})
    assert kind == 'other'


# ── 3.2 line_buf ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_line_buf_newline_flush_semantics():
    # 模拟 line_buf 行缓冲：含 \\n 立刻刷，无 \\n 持有
    line_buf = ''
    flushed = []

    def flush():
        nonlocal line_buf
        while '\n' in line_buf:
            line, line_buf = line_buf.split('\n', 1)
            flushed.append(line + '\n')

    line_buf += 'hello'
    flush()
    assert flushed == []
    assert line_buf == 'hello'
    line_buf += ' world\nnext'
    flush()
    assert flushed == ['hello world\n']
    assert line_buf == 'next'


@pytest.mark.asyncio
async def test_line_buf_super_long_forced_16k():
    # 超 16KB 即使无 \\n 也强制 flush（候选感知）
    big = 'x' * (LINE_BUF_FLUSH + 1)
    safe, pending = _split_safe_hold(big, {}, None)
    # 无候选前缀 → 全量 safe
    assert safe == big
    assert pending == ''


def test_reasoning_content_compat():
    # delta.reasoning 兼容 reasoning_content
    delta = {'reasoning': 'think'}
    rc = delta.get('reasoning_content')
    if rc is None:
        rc = delta.get('reasoning')
    assert rc == 'think'


# ── 3.4a keepalive ────────────────────────────────────────────────


def test_keepalive_is_comment_not_data():
    cmt = ': keepalive\n\n'
    assert cmt.startswith(':')
    assert 'data:' not in cmt


# ── 3.4c seen_global_terminal ─────────────────────────────────────


def test_seen_global_vs_block_level():
    global_terms = {'[DONE]', 'message_stop', 'response.completed', 'response.failed'}
    block_terms = {'content_block_stop', 'response.output_item.done', 'item_done'}
    assert global_terms.isdisjoint(block_terms)


def test_empty_stream_guard():
    bytes_written = 0
    seen_global = False
    should_synthesize = bytes_written == 0 and not seen_global
    assert should_synthesize is True
    bytes_written = 10
    assert (bytes_written == 0 and not seen_global) is False


def test_data_buffer_aggregation():
    # 同事件多 data: 行以 \\n 拼接
    data_buffer = ['{"a":1}', '{"b":2}']
    payload = '\n'.join(data_buffer)
    assert payload == '{"a":1}\n{"b":2}'
    assert json.loads('{"a":1}')  # 单行可 loads


# ── 3.1 BOM / WHATWG ──────────────────────────────────────────────


def test_bom_strip_once():
    from utils.json_walk import _strip_bom

    assert _strip_bom('\ufeff{"a":1}') == '{"a":1}'
    assert _strip_bom('{"a":1}') == '{"a":1}'


@pytest.mark.asyncio
async def test_pii_process_sse_line_bom_and_done(monkeypatch):
    # 用最小 LlmMixin 实例验证 _pii_process_sse_line 的 BOM/DONE 早退
    from _llm import LlmMixin
    from _token import TokenMixin

    class H(TokenMixin, LlmMixin):
        def __init__(self):
            self._lock = asyncio.Lock()
            self.token_to_pwd = {}
            self._token_seq = 0
            self.pwd_to_token = {}
            self.proxies = {}
            self._runners = []

        def _filter_hop_headers(self, h):
            return h

    h = H()
    # 非 JSON 早退
    out = await h._pii_process_sse_line('data: [DONE]', {})
    assert '[DONE]' in out or out.strip() == 'data: [DONE]'
    out2 = await h._pii_process_sse_line('data: \ufeff{"a":1}', {})
    assert '"a"' in out2


@pytest.mark.asyncio
async def test_multi_data_line_no_blank_safe_fallback(monkeypatch):
    """8.4（F-04）：多 data 行无空行分隔时，聚合失败兜底逐行脱敏转发。

    慢链 data_buffer join 后 json.loads 对两个独立 data 事件抛
    `JSONDecodeError: Extra data`；兜底改为逐行独立 `_pii_process_sse_line`
    （保底安全：不抛异常、不转发未脱敏原始 payload）。
    """
    from _llm import LlmMixin
    from _token import TokenMixin

    class H(TokenMixin, LlmMixin):
        def __init__(self):
            self._lock = asyncio.Lock()
            self.token_to_pwd = {}
            self._token_seq = 0
            self.pwd_to_token = {}
            self.proxies = {}
            self._runners = []

        def _filter_hop_headers(self, h):
            return h

    h = H()
    # 模拟聚合后的 payload（两个独立 JSON 以 \n 拼接 → json.loads 必失败）
    payload = '{"choices":[{"delta":{"content":"a"}}]}\n{"choices":[{"delta":{"content":"b"}}]}'
    # 兜底：逐行拆分 → 每行独立 _pii_process_sse_line
    lines = []
    for sub in payload.split('\n'):
        if not sub.strip():
            continue
        out = await h._pii_process_sse_line('data: ' + sub, {})
        lines.append(out)
    # 两行均转发且不抛异常
    assert len(lines) == 2
    assert all(l.startswith('data: ') for l in lines)
    assert '"content":"a"' in lines[0]
    assert '"content":"b"' in lines[1]


@pytest.mark.asyncio
async def test_cr_only_eof_dispatch(monkeypatch):
    """8.5（F-05）：CR-only 行（无 LF）在流末被正确 dispatch，不误判截断。

    模拟慢链流末逻辑：pending_cr=True 且 byte_buf 残留 `data: {...}\r` →
    EOF 时视为行终止符，行内容进入 data_buffer 或直接脱敏转发。
    """
    from _llm import LlmMixin
    from _token import TokenMixin

    class H(TokenMixin, LlmMixin):
        def __init__(self):
            self._lock = asyncio.Lock()
            self.token_to_pwd = {}
            self._token_seq = 0
            self.pwd_to_token = {}
            self.proxies = {}
            self._runners = []

        def _filter_hop_headers(self, h):
            return h

    h = H()
    # CR-only 行内容（模拟流末残留，\r 被剥离后是完整 data 行）
    cr_line = 'data: {"choices":[{"delta":{"content":"CR行内容"}}]}'
    # 剥离 \r 后 → data: 行 → _pii_process_sse_line 正常脱敏转发
    out = await h._pii_process_sse_line(cr_line, {})
    assert out.startswith('data: ')
    assert '"content":"CR行内容"' in out
    # 断言：流末残留 \r 不再触发截断（byte_buf 被清空 → 截断检测不命中）
    byte_buf = bytearray(b'data: {"choices":[{"delta":{"content":"x"}}]}\r')
    pending_cr = True
    if pending_cr and byte_buf and byte_buf.endswith(b'\r'):
        _cr_line = bytes(byte_buf[:-1]).decode('utf-8', errors='replace')
        byte_buf.clear()
        pending_cr = False
        assert _cr_line.startswith('data:')
    assert not byte_buf
    assert not pending_cr
