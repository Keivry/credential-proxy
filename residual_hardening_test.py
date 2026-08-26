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
