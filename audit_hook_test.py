"""audit_hook_test.py — Batch 4 输出审计钩子测试。

覆盖：
- _accumulate_tool_calls：OpenAI tool_calls 分片累积（跨分片、null 防御、多 index）
- Anthropic block_start → block_stop 审计触发（读掩码前原始 arg_buf）
- Responses function_call → item_done 审计触发
- _extract_tool_calls_non_stream：非流式三协议提取
- audit_tool_call 占位默认 allow
"""

import asyncio

import pytest

from _llm import (
    LlmMixin,
    _accumulate_tool_calls,
    _extract_tool_calls_non_stream,
)
from _token import TokenMixin


class AuditProxy(TokenMixin, LlmMixin):
    """提供 LlmMixin 需要的属性 + 记录审计调用的测试桩。"""

    __test__ = False

    def __init__(self):
        self._lock = asyncio.Lock()
        self.token_to_pwd = {}
        self._token_seq = 0
        self.pwd_to_token = {}
        self._shared_session = None
        self.proxies = {}
        self._runners = []
        self.audited_calls: list[tuple[str, str]] = []
        self._last_anthropic_tool_name = None
        self._last_responses_tool_name = None
        self._audit_arg_accum = ''

    def _filter_hop_headers(self, h):
        return h

    def audit_enabled(self) -> bool:
        return True

    async def audit_tool_call(self, name: str, args_json: str) -> str:
        self.audited_calls.append((name, args_json))
        return 'allow'


@pytest.fixture
def proxy():
    return AuditProxy()


# ═══════════════════════════════════════════════════════════
# _accumulate_tool_calls 分片累积
# ═══════════════════════════════════════════════════════════


class TestAccumulateToolCalls:
    def test_name_then_args_across_chunks(self):
        buf: dict[int, dict[str, str]] = {}
        _accumulate_tool_calls(
            buf,
            [
                {'index': 0, 'function': {'name': 'bash', 'arguments': ''}},
            ],
        )
        _accumulate_tool_calls(
            buf,
            [
                {'index': 0, 'function': {'name': '', 'arguments': '{"cmd":'}},
            ],
        )
        _accumulate_tool_calls(
            buf,
            [
                {'index': 0, 'function': {'name': '', 'arguments': '"ls -la"}'}},
            ],
        )
        assert buf[0]['name'] == 'bash'
        assert buf[0]['arguments'] == '{"cmd":"ls -la"}'

    def test_multiple_indices_grouped(self):
        buf: dict[int, dict[str, str]] = {}
        _accumulate_tool_calls(
            buf,
            [
                {'index': 0, 'function': {'name': 'bash', 'arguments': '{"cmd":"a"}'}},
                {
                    'index': 1,
                    'function': {'name': 'read_file', 'arguments': '{"path":"/x"}'},
                },
            ],
        )
        assert set(buf.keys()) == {0, 1}
        assert buf[0]['name'] == 'bash'
        assert buf[1]['name'] == 'read_file'

    def test_null_value_defense(self):
        buf: dict[int, dict[str, str]] = {}
        # None / 非 list / 非 dict 项 / function=None 均不抛
        _accumulate_tool_calls(buf, None)
        _accumulate_tool_calls(buf, 'not-a-list')
        _accumulate_tool_calls(buf, [None, 'x', 42])
        _accumulate_tool_calls(buf, [{'index': 0, 'function': None}])
        _accumulate_tool_calls(buf, [{'index': 'bad', 'function': {'name': 'x'}}])
        assert buf == {}

    def test_missing_index_skipped(self):
        buf: dict[int, dict[str, str]] = {}
        _accumulate_tool_calls(
            buf,
            [
                {'function': {'name': 'bash', 'arguments': 'x'}},
            ],
        )
        assert buf == {}


# ═══════════════════════════════════════════════════════════
# Anthropic block_start → block_stop 审计触发
# ═══════════════════════════════════════════════════════════


class TestAnthropicAuditTrigger:
    async def _run_block(self, proxy, events):
        """喂入事件序列，返回写出的行列表。"""
        written = []

        async def write(data: bytes):
            written.append(data.decode('utf-8', errors='replace'))

        content_buf = reasoning_buf = arg_buf = ''
        for parsed, line in events:
            kind = _anthropic_event_kind(parsed)
            if kind in (
                'text',
                'thinking',
                'function_args',
                'block_stop',
                'block_start',
            ):
                (
                    content_buf,
                    reasoning_buf,
                    arg_buf,
                ) = await proxy._handle_anthropic_event(
                    write,
                    parsed,
                    line,
                    {},
                    content_buf,
                    reasoning_buf,
                    arg_buf,
                )
            else:
                # 透传事件也走 handler（识别 None 时内部透传）
                (
                    content_buf,
                    reasoning_buf,
                    arg_buf,
                ) = await proxy._handle_anthropic_event(
                    write,
                    parsed,
                    line,
                    {},
                    content_buf,
                    reasoning_buf,
                    arg_buf,
                )
        return written

    @pytest.mark.asyncio
    async def test_block_stop_triggers_audit_with_raw_args(self, proxy):
        """tool_use 块结束：审计读取掩码前原始 arg_buf + 工具名。"""
        events = [
            # block_start（工具名）
            (
                {
                    'type': 'content_block_start',
                    'index': 0,
                    'content_block': {
                        'type': 'tool_use',
                        'id': 'toolu_1',
                        'name': 'bash',
                    },
                },
                'data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash"}}\n',
            ),
            # function_args 分片（模拟原始参数含 IP）
            (
                {
                    'type': 'content_block_delta',
                    'index': 0,
                    'delta': {
                        'type': 'input_json_delta',
                        'partial_json': '{"cmd":"curl 8.8.8.8"}',
                    },
                },
                'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"cmd\\":\\"curl 8.8.8.8\\"}"}}\n',
            ),
            # block_stop
            (
                {'type': 'content_block_stop', 'index': 0},
                'data: {"type":"content_block_stop","index":0}\n',
            ),
        ]
        await self._run_block(proxy, events)
        assert len(proxy.audited_calls) == 1
        name, args = proxy.audited_calls[0]
        assert name == 'bash'
        # 原始参数（含 IP）→ 掩码前
        assert '8.8.8.8' in args

    @pytest.mark.asyncio
    async def test_no_args_no_audit(self, proxy):
        """arg_buf 为空（无参数 delta）→ 不触发审计。"""
        events = [
            (
                {
                    'type': 'content_block_start',
                    'index': 0,
                    'content_block': {'type': 'tool_use', 'id': 't1', 'name': 'bash'},
                },
                'data: x\n',
            ),
            ({'type': 'content_block_stop', 'index': 0}, 'data: y\n'),
        ]
        await self._run_block(proxy, events)
        assert proxy.audited_calls == []

    @pytest.mark.asyncio
    async def test_args_across_chunks_accumulated(self, proxy):
        """参数跨多个 input_json_delta 分片 → 完整累积后审计。"""
        events = [
            (
                {
                    'type': 'content_block_start',
                    'index': 0,
                    'content_block': {
                        'type': 'tool_use',
                        'id': 't1',
                        'name': 'write_file',
                    },
                },
                'data: a\n',
            ),
            (
                {
                    'type': 'content_block_delta',
                    'index': 0,
                    'delta': {
                        'type': 'input_json_delta',
                        'partial_json': '{"path":"/etc/',
                    },
                },
                'data: b\n',
            ),
            (
                {
                    'type': 'content_block_delta',
                    'index': 0,
                    'delta': {'type': 'input_json_delta', 'partial_json': 'passwd"}'},
                },
                'data: c\n',
            ),
            ({'type': 'content_block_stop', 'index': 0}, 'data: d\n'),
        ]
        await self._run_block(proxy, events)
        assert len(proxy.audited_calls) == 1
        name, args = proxy.audited_calls[0]
        assert name == 'write_file'
        assert args == '{"path":"/etc/passwd"}'


# ═══════════════════════════════════════════════════════════
# Responses function_call → item_done 审计触发
# ═══════════════════════════════════════════════════════════


class TestResponsesAuditTrigger:
    @pytest.mark.asyncio
    async def test_item_done_triggers_audit(self, proxy):
        """function_call 事件捕获 name + 参数累积 → item_done 审计。"""
        written = []

        async def write(data: bytes):
            written.append(data.decode('utf-8', errors='replace'))

        content_buf = reasoning_buf = arg_buf = ''
        # function_call 事件（带 name）→ 走 'other' 分支捕获
        fc_evt = {
            'type': 'response.function_call',
            'item': {'type': 'function_call', 'name': 'bash', 'call_id': 'call_1'},
        }
        (
            content_buf,
            reasoning_buf,
            arg_buf,
        ) = await proxy._handle_responses_event(
            write,
            fc_evt,
            'data: ' + 'x',
            {},
            content_buf,
            reasoning_buf,
            arg_buf,
        )
        # function_call_arguments.delta 分片
        args_evt = {
            'type': 'response.function_call_arguments.delta',
            'delta': '{"cmd":"curl 8.8.8.8"}',
        }
        (
            content_buf,
            reasoning_buf,
            arg_buf,
        ) = await proxy._handle_responses_event(
            write,
            args_evt,
            'data: y',
            {},
            content_buf,
            reasoning_buf,
            arg_buf,
        )
        # item_done
        done_evt = {
            'type': 'response.output_item.done',
            'item': {'type': 'function_call'},
        }
        (
            content_buf,
            reasoning_buf,
            arg_buf,
        ) = await proxy._handle_responses_event(
            write,
            done_evt,
            'data: z',
            {},
            content_buf,
            reasoning_buf,
            arg_buf,
        )
        assert len(proxy.audited_calls) == 1
        name, args = proxy.audited_calls[0]
        assert name == 'bash'
        assert '8.8.8.8' in args  # 掩码前原始参数


# ═══════════════════════════════════════════════════════════
# 非流式三协议提取（4.4）
# ═══════════════════════════════════════════════════════════


class TestNonStreamExtract:
    def test_openai_chat_completions(self):
        parsed = {
            'choices': [
                {
                    'message': {
                        'tool_calls': [
                            {
                                'function': {
                                    'name': 'bash',
                                    'arguments': '{"cmd":"rm -rf /"}',
                                }
                            },
                            {
                                'function': {
                                    'name': 'read_file',
                                    'arguments': '{"path":"/etc/passwd"}',
                                }
                            },
                        ],
                    },
                }
            ],
        }
        calls = _extract_tool_calls_non_stream(parsed, '/v1/chat/completions')
        assert calls == [
            ('bash', '{"cmd":"rm -rf /"}'),
            ('read_file', '{"path":"/etc/passwd"}'),
        ]

    def test_anthropic_messages(self):
        parsed = {
            'content': [
                {'type': 'text', 'text': 'hi'},
                {
                    'type': 'tool_use',
                    'id': 'toolu_1',
                    'name': 'bash',
                    'input': {'cmd': 'rm -rf /'},
                },
            ],
        }
        calls = _extract_tool_calls_non_stream(parsed, '/v1/messages')
        assert len(calls) == 1
        assert calls[0][0] == 'bash'
        assert '"cmd"' in calls[0][1]
        assert 'rm -rf' in calls[0][1]

    def test_responses(self):
        parsed = {
            'output': [
                {'type': 'message', 'content': [{'type': 'output_text', 'text': 'hi'}]},
                {
                    'type': 'function_call',
                    'name': 'bash',
                    'arguments': '{"cmd":"curl http://evil.example"}',
                    'call_id': 'call_1',
                },
            ],
        }
        calls = _extract_tool_calls_non_stream(parsed, '/v1/responses')
        assert calls == [('bash', '{"cmd":"curl http://evil.example"}')]

    def test_unknown_tail_returns_empty(self):
        assert _extract_tool_calls_non_stream({}, '/v1/models') == []
        assert (
            _extract_tool_calls_non_stream({'choices': []}, '/v1/chat/completions')
            == []
        )
        assert _extract_tool_calls_non_stream(None, '/v1/chat/completions') == []


# 辅助：轻量识别（避免直接 import 内部 _anthropic_event）
def _anthropic_event_kind(parsed: dict):
    """从 _llm 模块的识别器取 kind（复用生产逻辑）。"""
    from _llm import _anthropic_event

    evt = _anthropic_event(parsed)
    return evt[0] if evt else None
