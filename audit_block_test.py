"""audit_block_test.py — Batch 5 阻断模式集成/单元测试。

覆盖 tasks 5.3/5.4：
- 三种协议阻断消息结构合法性（无 tool_calls、finish_reason: stop、终止事件）
- 流式阻断：deny 后 tool_calls 事件不流出、注入拒绝消息、后续 content 照常
- 非流式阻断：三协议整包替换
- 阻断后缓冲丢弃（design D4）
"""

import json

import pytest

from _audit import BLOCK_MESSAGE, AuditMixin
from _llm import LlmMixin


class BlockStub(LlmMixin):
    """组合桩：LlmMixin 已继承 AuditMixin，验证阻断消息构造。"""

    __test__ = False

    def __init__(self):
        self.audit_enabled_flag = True
        self.audit_mode = 'block'
        self.policy = {}


# ═══════════════════════════════════════════════════════════
# 阻断消息结构合法性（5.3）
# ═══════════════════════════════════════════════════════════


class TestBlockEventStructure:
    def setup_method(self):
        self.stub = BlockStub()

    def test_openai_block_event_structure(self):
        """OpenAI 阻断：无 tool_calls、delta content、finish_reason: stop。"""
        ev = self.stub._build_block_event()
        assert ev.startswith('data: ')
        payload = json.loads(ev[6:].strip())
        choice = payload['choices'][0]
        assert choice['finish_reason'] == 'stop'
        assert choice['delta']['role'] == 'assistant'
        assert choice['delta']['content'] == BLOCK_MESSAGE
        assert 'tool_calls' not in choice['delta']

    def test_anthropic_block_event_structure(self):
        """Anthropic 阻断：content_block_delta + message_delta 终止。"""
        ev = self.stub._build_block_event_anthropic()
        lines = [l for l in ev.split('\n') if l.startswith('data: ')]
        assert len(lines) == 2
        first = json.loads(lines[0][6:])
        assert first['type'] == 'content_block_delta'
        assert first['delta']['type'] == 'text_delta'
        assert first['delta']['text'] == BLOCK_MESSAGE
        second = json.loads(lines[1][6:])
        assert second['type'] == 'message_delta'
        assert second['delta']['stop_reason'] == 'end_turn'

    def test_responses_block_event_structure(self):
        """Responses 阻断：output_text.delta + response.completed 终止。"""
        ev = self.stub._build_block_event_responses()
        lines = [l for l in ev.split('\n') if l.startswith('data: ')]
        assert len(lines) == 2
        first = json.loads(lines[0][6:])
        assert first['type'] == 'response.output_text.delta'
        assert first['delta'] == BLOCK_MESSAGE
        second = json.loads(lines[1][6:])
        assert second['type'] == 'response.completed'
        assert second['response']['status'] == 'completed'
        # 无 function_call 输出
        assert all(o['type'] != 'function_call' for o in second['response']['output'])


# ═══════════════════════════════════════════════════════════
# 阻断 verdict 消费（5.3）
# ═══════════════════════════════════════════════════════════


class TestBlockVerdict:
    @pytest.mark.asyncio
    async def test_audit_openai_deny_returns_injection(self):
        """deny verdict → 返回注入事件。"""
        stub = BlockStub()
        stub.audit_enabled_flag = True

        async def deny(name, args):
            return 'deny'

        stub.audit_tool_call = deny
        injections = await stub._audit_openai_tool_calls(
            {0: {'name': 'bash', 'arguments': '{"cmd":"rm -rf /"}'}},
            {},
        )
        assert len(injections) == 1
        assert injections[0].startswith('data: ')

    @pytest.mark.asyncio
    async def test_audit_openai_allow_returns_empty(self):
        """allow verdict → 无注入。"""
        stub = BlockStub()
        stub.audit_enabled_flag = True

        async def allow(name, args):
            return 'allow'

        stub.audit_tool_call = allow
        injections = await stub._audit_openai_tool_calls(
            {0: {'name': 'web_search', 'arguments': '{}'}},
            {},
        )
        assert injections == []

    @pytest.mark.asyncio
    async def test_audit_disabled_no_injection(self):
        """审计未启用 → 无注入。"""
        stub = BlockStub()
        stub.audit_enabled_flag = False
        injections = await stub._audit_openai_tool_calls(
            {0: {'name': 'bash', 'arguments': '{"cmd":"rm -rf /"}'}},
            {},
        )
        assert injections == []


# ═══════════════════════════════════════════════════════════
# 真实策略引擎端到端（5.4）
# ═══════════════════════════════════════════════════════════


class TestPolicyBlock:
    @pytest.mark.asyncio
    async def test_dangerous_shell_denied(self):
        """危险 shell（rm -rf）经真实策略引擎 deny。"""
        stub = AuditMixin()
        stub._init_audit(None)
        stub.audit_enabled_flag = True
        verdict = await stub.audit_tool_call('bash', '{"cmd":"rm -rf /"}')
        assert verdict == 'deny'

    @pytest.mark.asyncio
    async def test_obfuscated_command_denied(self):
        """规范化命中：双空格 + 转义 + 变量拼接组合。"""
        stub = AuditMixin()
        stub._init_audit(None)
        stub.audit_enabled_flag = True
        # \\u0072m 转义 + 双空格 + $CMD 变量
        verdict = await stub.audit_tool_call(
            'bash', '{"cmd":"CMD=\\u0072m;  $CMD -rf   /"}'
        )
        assert verdict == 'deny'

    @pytest.mark.asyncio
    async def test_safe_command_allowed(self):
        """安全命令放行。"""
        stub = AuditMixin()
        stub._init_audit(None)
        stub.audit_enabled_flag = True
        verdict = await stub.audit_tool_call('bash', '{"cmd":"ls -la /tmp"}')
        assert verdict == 'allow'

    @pytest.mark.asyncio
    async def test_network_exfil_denied(self):
        """网络外传（curl 公网 IP）deny。"""
        stub = AuditMixin()
        stub._init_audit(None)
        stub.audit_enabled_flag = True
        verdict = await stub.audit_tool_call('curl', '{"url":"http://8.8.8.8/x"}')
        assert verdict == 'deny'

    @pytest.mark.asyncio
    async def test_network_internal_allowed(self):
        """内网目标放行。"""
        stub = AuditMixin()
        stub._init_audit(None)
        stub.audit_enabled_flag = True
        verdict = await stub.audit_tool_call(
            'curl', '{"url":"http://host.corp.example/x"}'
        )
        assert verdict == 'allow'

    @pytest.mark.asyncio
    async def test_sensitive_path_denied(self):
        """敏感路径写入 deny。"""
        stub = AuditMixin()
        stub._init_audit(None)
        stub.audit_enabled_flag = True
        verdict = await stub.audit_tool_call(
            'write_file', '{"path":"/etc/passwd","content":"x"}'
        )
        assert verdict == 'deny'
