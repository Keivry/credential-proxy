import json

import pytest

from _llm import LlmMixin, _fast_rebuild_chunk, _mk_sse_event
from _pii import PiiMixin
from _sse import KEEPALIVE_INTERVAL, LINE_BUF_FLUSH, LINE_BUF_MAX_AGE, SSE_MAX_BUF
from _token import TokenMixin


class _RestoreHarness(LlmMixin, PiiMixin, TokenMixin):
    pass


def _harness():
    obj = _RestoreHarness.__new__(_RestoreHarness)
    obj.token_to_pwd = {}
    return obj


def _chat_parsed():
    return {
        'id': 'chatcmpl-test',
        'object': 'chat.completion.chunk',
        'created': 1,
        'model': 'gpt-4o',
        'choices': [{'index': 0, 'delta': {}, 'finish_reason': None}],
    }


def test_refusal_fragments_rebuild_parseable():
    first = _fast_rebuild_chunk(_chat_parsed(), {0: ''}, refusal={0: '抱歉'})
    second = _fast_rebuild_chunk(_chat_parsed(), {0: ''}, refusal={0: '抱歉不能执行'})
    for event in (first, second):
        payload = json.loads(event)
        delta = payload['choices'][0]['delta']
        assert 'refusal' in delta
    assert '抱歉不能执行' in second
    assert payload['id'] == 'chatcmpl-test'
    assert payload['model'] == 'gpt-4o'


def test_mk_sse_event_refusal_by_index():
    parsed = {
        'id': 'chatcmpl-r',
        'created': 2,
        'model': 'm',
        'choices': [
            {'index': 0, 'delta': {'refusal': 'x'}, 'finish_reason': None},
            {'index': 1, 'delta': {}, 'finish_reason': None},
        ],
    }
    event = _mk_sse_event(parsed=parsed, refusal_by_index={0: 'no'})
    payload = json.loads(event[len('data: ') :])
    assert payload['choices'][0]['delta']['refusal'] == 'no'
    assert payload['choices'][1]['delta'] == {}


@pytest.mark.asyncio
async def test_thinking_and_input_json_delta_json_aware():
    proxy = _harness()
    anthropic_line = (
        'data: {"type": "content_block_delta", "delta": '
        '{"type": "thinking_delta", "thinking": "p@ss\\"quote"}}'
    )
    out = await proxy._pii_process_sse_line(anthropic_line, {})
    assert out.startswith('data: ')
    json.loads(out[len('data: ') :])
    responses_line = (
        'data: {"type": "response.function_call_arguments.delta", '
        '"delta": "{\\"key\\": \\"p@ss\\"}"}'
    )
    out2 = await proxy._pii_process_sse_line(responses_line, {})
    assert out2.startswith('data: ')
    json.loads(out2[len('data: ') :])


@pytest.mark.asyncio
async def test_pending_restore_idempotent_no_drift():
    proxy = _harness()
    active = {'__VG_CRED_000001__': 's3cr3t'}
    line = 'data: {"choices": [{"delta": {"content": "hi __VG_CRED_000001__"}}]}'
    once = await proxy._pii_process_sse_line(line, active)
    assert 's3cr3t' in once
    twice = await proxy._pii_process_sse_line(once, active)
    assert twice == once


def test_stream_thresholds_single_source():
    import _llm

    assert _llm.SSE_MAX_BUF == SSE_MAX_BUF == 1_048_576
    assert _llm.LINE_BUF_FLUSH == LINE_BUF_FLUSH == 16384
    assert _llm.LINE_BUF_MAX_AGE == LINE_BUF_MAX_AGE == 30
    assert _llm.KEEPALIVE_INTERVAL == KEEPALIVE_INTERVAL == 10
