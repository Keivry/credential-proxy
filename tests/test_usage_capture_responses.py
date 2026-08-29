"""usage 捕获回归测试：Responses 协议单层 usage（v0.9.41 修复）。

根因：_capture_usage_ctx 的 Responses 分支只找 obj.response.response.usage
（双层），但 muse-spark（opencode /v1/responses）实际是单层
obj.response.usage → 753 个请求 usage 全部漏捕获。
"""

import json

from _llm import _capture_usage_ctx


def _capture(payload: dict, model: str = 'muse-spark-1.2-contributor'):
    ctx = {'model': model, 'tokens': {}}
    _capture_usage_ctx(json.dumps(payload), ctx, 'responses')
    return ctx['tokens'].get(model, {})


def test_responses_single_layer_usage():
    """response.completed 单层 usage（真实 muse-spark 形态）应捕获。"""
    payload = {
        'type': 'response.completed',
        'response': {
            'id': 'r_1',
            'usage': {
                'input_tokens': 15964,
                'output_tokens': 136,
                'total_tokens': 16100,
                'input_tokens_details': {'cached_tokens': 0},
                'output_tokens_details': {'reasoning_tokens': 33},
            },
        },
    }
    tokens = _capture(payload)
    assert tokens['total'] == 16100
    assert tokens['input'] == 15964
    assert tokens['output'] == 136
    assert tokens['cached_read'] == 0


def test_responses_single_layer_cached():
    """单层 usage 带缓存计数应捕获 cached_read。"""
    payload = {
        'type': 'response.completed',
        'response': {
            'id': 'r_2',
            'usage': {
                'input_tokens': 16159,
                'output_tokens': 274,
                'total_tokens': 16433,
                'input_tokens_details': {'cached_tokens': 4849},
            },
        },
    }
    tokens = _capture(payload)
    assert tokens['total'] == 16433
    assert tokens['cached_read'] == 4849


def test_responses_double_layer_fallback():
    """双层 obj.response.response.usage 历史形态仍兼容（fallback）。"""
    payload = {
        'type': 'response.completed',
        'response': {'response': {'usage': {'input_tokens': 10, 'output_tokens': 20}}},
    }
    tokens = _capture(payload)
    assert tokens['total'] == 30
    assert tokens['input'] == 10
    assert tokens['output'] == 20


def test_responses_no_usage_noop():
    """无 usage 的 response.completed 不产生 token 记录。"""
    payload = {'type': 'response.completed', 'response': {'id': 'r_3'}}
    tokens = _capture(payload)
    assert tokens == {}


def test_openai_chat_unchanged():
    """OpenAI Chat 顶层 usage 路径不受影响。"""
    payload = {
        'usage': {'prompt_tokens': 100, 'completion_tokens': 50, 'total_tokens': 150}
    }
    ctx = {'model': 'deepseek/deepseek-v4-flash', 'tokens': {}}
    _capture_usage_ctx(json.dumps(payload), ctx, 'openai')
    tokens = ctx['tokens']['deepseek/deepseek-v4-flash']
    assert tokens['prompt'] == 100
    assert tokens['completion'] == 50
    assert tokens['total'] == 150


def test_anthropic_unchanged():
    """Anthropic message_delta.usage 路径不受影响。"""
    payload = {
        'type': 'message_delta',
        'usage': {'input_tokens': 5, 'output_tokens': 7},
    }
    ctx = {'model': 'claude-3', 'tokens': {}}
    _capture_usage_ctx(json.dumps(payload), ctx, 'anthropic')
    tokens = ctx['tokens']['claude-3']
    assert tokens['input'] == 5
    assert tokens['output'] == 7
