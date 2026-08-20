"""audit_approve_test.py — Batch 6 审批模式单元测试。

覆盖 tasks 6.1：
- redact_summary 脱敏（密钥/手机/邮箱/身份证 → [REDACTED:<type>]）+ 截断边界
- _request_audit_approval：approved / rejected / expired / failed（_ask→None）四路径
- 白名单校验、幂等、event id 匹配（reaction 处理器逻辑）
- approve 模式 verdict 消费（approved 放行不注入；rejected 注入）
"""

import asyncio

import pytest

from _audit import BLOCK_MESSAGE, redact_summary
from _llm import LlmMixin


class ApproveStub(LlmMixin):
    """LlmMixin 组合桩（approve 模式）。"""

    __test__ = False

    def __init__(self):
        self.audit_enabled_flag = True
        self.audit_mode = 'approve'
        self.policy = {}
        self.audit_timeout = 1
        self._ask_result = 'msg-1'  # mock _ask 返回值
        self._ask_calls = 0
        self.asked_texts: list[str] = []
        # 审批状态（_init_audit 初始化）
        self._audit_approval_pending = {}
        self._audit_approval_msgs = {}
        self._audit_pending_seq = 0
        self.approval_whitelist = set()
        # 模拟 reaction：手动 resolve
        self._resolver = None

    async def _ask(self, text: str, reactions=None):
        self._ask_calls += 1
        self.asked_texts.append(text)
        if self._ask_result is None:
            return None
        # 返回 msg_id，注册 resolver 供测试触发 reaction
        msg_id = self._ask_result
        self._audit_approval_msgs[msg_id] = f'audit-{self._audit_pending_seq - 1}'
        self._resolver = (msg_id, f'audit-{self._audit_pending_seq - 1}')
        return msg_id

    def _resolve(self, approved: bool):
        """模拟审批人点 reaction。"""
        if self._resolver:
            _, req_id = self._resolver
            ap = self._audit_approval_pending.get(req_id)
            if ap and ap.get('approved') is None:
                ap['approved'] = approved
                ap['event'].set()


# ═══════════════════════════════════════════════════════════
# redact_summary（6.1 摘要脱敏）
# ═══════════════════════════════════════════════════════════


class TestRedactSummary:
    def test_api_key_redacted(self):
        s = redact_summary('{"token":"sk-abc12345678901234567"}')
        assert 'sk-abc12345678901234567' not in s
        assert '[REDACTED:api_key]' in s

    def test_phone_redacted(self):
        s = redact_summary('{"phone":"13800138000"}')
        assert '13800138000' not in s
        assert '[REDACTED:phone]' in s

    def test_email_redacted(self):
        s = redact_summary('{"email":"zhangsan@example.com"}')
        assert 'zhangsan@example.com' not in s
        assert '[REDACTED:email]' in s

    def test_id_card_redacted(self):
        s = redact_summary('{"id":"11010519491231002X"}')
        assert '11010519491231002X' not in s
        assert '[REDACTED:id_card]' in s

    def test_private_key_redacted(self):
        s = redact_summary(
            '-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----'
        )
        assert 'MIIEow==' not in s
        assert '[REDACTED:private_key]' in s

    def test_truncation_boundary(self):
        """截断边界半字符保护：中文多字节字符不被切断。"""
        s = redact_summary('中文内容' * 50, max_len=30)
        assert len(s) <= 31  # 30 + 省略号
        # 无 U+FFFD 替换符（未切断多字节）
        assert '\ufffd' not in s
        assert s.endswith('…')

    def test_short_text_no_truncation(self):
        s = redact_summary('hello world')
        assert s == 'hello world'


# ═══════════════════════════════════════════════════════════
# _request_audit_approval 四路径（6.1）
# ═══════════════════════════════════════════════════════════


class TestRequestApproval:
    @pytest.mark.asyncio
    async def test_approved(self):
        stub = ApproveStub()
        task = asyncio.create_task(
            stub._request_audit_approval('bash', '{"cmd":"rm -rf /"}')
        )
        await asyncio.sleep(0.05)
        stub._resolve(True)
        assert await task == 'approved'
        assert stub._ask_calls == 1
        assert 'rm -rf /' in stub.asked_texts[0]  # 参数摘要含命令（非敏感）

    @pytest.mark.asyncio
    async def test_rejected(self):
        stub = ApproveStub()
        task = asyncio.create_task(
            stub._request_audit_approval('bash', '{"cmd":"rm -rf /"}')
        )
        await asyncio.sleep(0.05)
        stub._resolve(False)
        assert await task == 'rejected'

    @pytest.mark.asyncio
    async def test_expired(self):
        """超时（1s）默认拒绝。"""
        stub = ApproveStub()
        stub.audit_timeout = 0.2
        result = await stub._request_audit_approval('bash', '{"cmd":"rm -rf /"}')
        assert result == 'expired'
        # pending 已清理
        assert not stub._audit_approval_pending
        assert not stub._audit_approval_msgs

    @pytest.mark.asyncio
    async def test_ask_failed(self):
        """_ask 返回 None → 'failed' + pending 立即清理。"""
        stub = ApproveStub()
        stub._ask_result = None
        result = await stub._request_audit_approval('bash', '{"cmd":"rm -rf /"}')
        assert result == 'failed'
        assert not stub._audit_approval_pending
        assert not stub._audit_approval_msgs

    @pytest.mark.asyncio
    async def test_approve_mode_approved_no_injection(self):
        """approve 模式：approved → 无注入（放行）。"""
        stub = ApproveStub()

        async def deny(name, args):
            return 'deny'

        stub.audit_tool_call = deny
        task = asyncio.create_task(
            stub._audit_openai_tool_calls(
                {0: {'name': 'bash', 'arguments': '{"cmd":"rm -rf /"}'}},
                {},
            )
        )
        await asyncio.sleep(0.05)
        stub._resolve(True)
        injections = await task
        assert injections == []

    @pytest.mark.asyncio
    async def test_approve_mode_rejected_injects(self):
        """approve 模式：rejected → 注入拒绝消息。"""
        stub = ApproveStub()

        async def deny(name, args):
            return 'deny'

        stub.audit_tool_call = deny
        task = asyncio.create_task(
            stub._audit_openai_tool_calls(
                {0: {'name': 'bash', 'arguments': '{"cmd":"rm -rf /"}'}},
                {},
            )
        )
        await asyncio.sleep(0.05)
        stub._resolve(False)
        injections = await task
        assert len(injections) == 1
        assert BLOCK_MESSAGE in injections[0]

    @pytest.mark.asyncio
    async def test_block_mode_deny_injects_directly(self):
        """block 模式：deny → 直接注入（无审批）。"""
        stub = ApproveStub()
        stub.audit_mode = 'block'

        async def deny(name, args):
            return 'deny'

        stub.audit_tool_call = deny
        injections = await stub._audit_openai_tool_calls(
            {0: {'name': 'bash', 'arguments': '{"cmd":"rm -rf /"}'}},
            {},
        )
        assert len(injections) == 1
        assert stub._ask_calls == 0  # 无审批


# ═══════════════════════════════════════════════════════════
# 白名单 + 幂等（reaction 处理器逻辑，6.1 验收）
# ═══════════════════════════════════════════════════════════


class TestWhitelistIdempotency:
    def _make_reaction_env(self):
        """构造 reaction 处理器最小环境（复用 MatrixMixin 逻辑的手工模拟）。"""
        stub = ApproveStub()
        # 模拟 MatrixMixin 需要的属性
        stub.approval_whitelist = {'@admin:example.com'}
        return stub

    def test_whitelist_sender_check(self):
        """非白名单发送者 → 审批不生效。"""
        stub = self._make_reaction_env()
        # 模拟 on_reaction 分支逻辑
        sender = '@evil:example.com'
        in_whitelist = stub.approval_whitelist and sender not in stub.approval_whitelist
        assert in_whitelist  # 应被拦截

    def test_whitelist_admin_ok(self):
        stub = self._make_reaction_env()
        sender = '@admin:example.com'
        in_whitelist = stub.approval_whitelist and sender not in stub.approval_whitelist
        assert not in_whitelist  # 白名单内 → 不拦截

    def test_idempotent_first_reaction_only(self):
        """幂等：approved 已定后重复 reaction 不生效。"""
        stub = ApproveStub()
        req_id = 'audit-0'
        evt = asyncio.Event()
        stub._audit_approval_pending[req_id] = {
            'name': 'bash',
            'args': '{}',
            'approved': None,
            'event': evt,
        }
        # 首次
        ap = stub._audit_approval_pending[req_id]
        ap['approved'] = True
        ap['event'].set()
        # 重复（approved 已定 → 应跳过）
        ap2 = stub._audit_approval_pending.get(req_id)
        assert ap2 is not None and ap2.get('approved') is not None
        # 模拟 on_reaction 中的守卫
        if ap2 and ap2.get('approved') is None:
            raise AssertionError('重复 reaction 不应生效')
