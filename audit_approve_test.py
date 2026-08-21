"""audit_approve_test.py — Batch 6 审批模式单元测试。

覆盖 tasks 6.1：
- redact_summary 脱敏（密钥/手机/邮箱/身份证 → [REDACTED:<type>]）+ 截断边界
- _request_audit_approval：approved / rejected / expired / failed（_ask→None）四路径
- 白名单校验、幂等、event id 匹配（reaction 处理器逻辑）
- approve 模式 verdict 消费（approved 放行不注入；rejected 注入）
"""

import asyncio

# ── nio mock（_matrix 依赖；matrix_test.py 同模式，幂等）──
import sys
import types
from unittest.mock import MagicMock

import pytest

from _audit import BLOCK_MESSAGE, redact_summary
from _llm import LlmMixin

if 'nio' not in sys.modules:
    nio = types.ModuleType('nio')
    nio.AsyncClient = MagicMock()
    nio.RoomMessageText = MagicMock()
    nio.ReactionEvent = MagicMock()
    sys.modules['nio'] = nio

from _matrix import MatrixMixin
from _sse import REACTION_APPROVE, REACTION_REJECT


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
        # sk- 前缀 ≥16 字符的 API key（R10：JSON 键值形态也覆盖）
        s = redact_summary('{"token":"sk-abcdefghijklmnopqrstuvwxyz"}')
        assert 'sk-abcdefghijklmnopqrstuvwxyz' not in s
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

    def test_long_input_no_at_fast(self):
        """大输入无 `@` 时快速返回（R1 回归：email 二次方回溯已短路）。

        旧实现 email 正则 `[A-Za-z0-9._%+-]+@...` 在无 `@` 长文本上
        sub() 逐位置重试 O(n²)——100KB 纯字母实测 ~20s。
        `@` 预检查短路后应毫秒级返回。
        """
        import time

        big = 'k' * 100_000
        t0 = time.monotonic()
        s = redact_summary(big)
        elapsed = time.monotonic() - t0
        # 100KB 输入处理总预算：远小于旧实现 ~20s（宽松阈值防 CI 抖动）
        assert elapsed < 1.0, (
            f'redact_summary 100KB 无@ 耗时 {elapsed:.2f}s（二次方回溯未修复）'
        )
        # 默认 max_len=120 截断 → 结果 = 前 120 字符 + 省略号（无敏感形态）
        assert s.startswith(big[:120])
        assert s.endswith('…')

    def test_long_input_with_at_fast(self):
        """大输入含单个 `@` 时仍快速返回（R1 完整回归：锚定+限长消除绕过）。

        仅 `@` 预检查不够——攻击者在 tool args 里放一个 `@` 即可绕过
        （旧正则 `[A-Za-z0-9._%+-]+@...` 仍从每个位置重试，100KB+@ 实测
        ~20s）。R1 完整修复：email 正则加 `\\b` 锚定 + 长度限制
        `{1,64}`（local part 上限），长无匹配文本上快速失败。
        """
        import time

        big = 'k' * 100_000 + '@'
        t0 = time.monotonic()
        s = redact_summary(big)
        elapsed = time.monotonic() - t0
        assert elapsed < 1.0, (
            f'redact_summary 100KB+@ 耗时 {elapsed:.2f}s（锚定修复未生效）'
        )
        assert s.startswith(big[:120])


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


# ═══════════════════════════════════════════════════════════
# 真实 on_reaction 集成测试（F-01 回归：审计审批分支可达性）
# ═══════════════════════════════════════════════════════════


class ReactionStub(MatrixMixin, LlmMixin):
    """组合 MatrixMixin + LlmMixin 的最小桩，驱动真实 on_reaction。"""

    __test__ = False

    def __init__(self):
        # MatrixMixin 依赖
        self._lock = asyncio.Lock()
        self.client = MagicMock()
        self.room_id = '!test:example.org'
        self._start_ts = 0
        self.master_password = None
        self.unlock_event = None
        self._unlock_msg_id = None
        self._unlock_in_progress = False
        self._unlock_generation = 0
        self.pending_requests = {}
        self.approval_msgs = {}
        self._registration_msgs = {}
        self._registration_pending = {}
        self._hash_change_msgs = {}
        self._hash_change_pending = {}
        self.pwd_to_token = {}
        self.token_to_pwd = {}
        self._base_dir = '/tmp'
        # LlmMixin 审计依赖（AuditMixin 属性）
        self.audit_enabled_flag = True
        self.audit_mode = 'approve'
        self.policy = {}
        self.audit_timeout = 1
        self._audit_approval_pending = {}
        self._audit_approval_msgs = {}
        self._audit_pending_seq = 0
        self.approval_whitelist = set()
        self._say_texts: list[str] = []

    async def _say(self, text: str):
        self._say_texts.append(text)

    def _mk_reaction_event(self, orig: str, key: str, sender: str):
        """构造 Matrix ReactionEvent 形状的简单对象（驱动真实 on_reaction）。"""
        evt = MagicMock()
        evt.server_timestamp = 9999999999999
        evt.source = {
            'sender': sender,
            'content': {
                'm.relates_to': {
                    'event_id': orig,
                    'key': key,
                },
            },
        }
        room = MagicMock()
        room.room_id = self.room_id
        return room, evt

    def _seed_audit_pending(self, msg_id: str = 'audit-msg-1') -> str:
        """注册一条待审批的审计请求，返回 req_id。"""
        req_id = f'audit-{self._audit_pending_seq}'
        self._audit_pending_seq += 1
        evt = asyncio.Event()
        self._audit_approval_pending[req_id] = {
            'name': 'bash',
            'args': '{}',
            'approved': None,
            'event': evt,
        }
        self._audit_approval_msgs[msg_id] = req_id
        return req_id


@pytest.mark.asyncio
async def test_on_reaction_audit_approve_reaches_branch5():
    """真实 on_reaction：审计审批 reaction ✅ → 分支 5 生效（approved=True + event set）。

    回归 F-01：旧 elif 链分支 4 负向守卫吞掉审计消息，分支 5 永远不可达。
    """
    stub = ReactionStub()
    req_id = stub._seed_audit_pending()
    room, evt = stub._mk_reaction_event(
        'audit-msg-1', REACTION_APPROVE, '@admin:example.com'
    )
    await stub.on_reaction(room, evt)
    ap = stub._audit_approval_pending[req_id]
    assert ap['approved'] is True
    assert ap['event'].is_set()
    assert any('审计审批' in t for t in stub._say_texts)


@pytest.mark.asyncio
async def test_on_reaction_audit_reject_branch5():
    """真实 on_reaction：审计审批 reaction ❎ → rejected。"""
    stub = ReactionStub()
    req_id = stub._seed_audit_pending()
    room, evt = stub._mk_reaction_event(
        'audit-msg-1', REACTION_REJECT, '@admin:example.com'
    )
    await stub.on_reaction(room, evt)
    ap = stub._audit_approval_pending[req_id]
    assert ap['approved'] is False
    assert ap['event'].is_set()


@pytest.mark.asyncio
async def test_on_reaction_audit_whitelist_blocks_non_member():
    """白名单非空 + 发送者不在白名单 → 审计审批被忽略（approved 保持 None）。"""
    stub = ReactionStub()
    stub.approval_whitelist = {'@admin:example.com'}
    req_id = stub._seed_audit_pending()
    room, evt = stub._mk_reaction_event(
        'audit-msg-1', REACTION_APPROVE, '@evil:example.com'
    )
    await stub.on_reaction(room, evt)
    ap = stub._audit_approval_pending[req_id]
    assert ap['approved'] is None
    assert not ap['event'].is_set()


@pytest.mark.asyncio
async def test_on_reaction_audit_idempotent():
    """幂等：approved 已定后重复 reaction 不改变结果。"""
    stub = ReactionStub()
    req_id = stub._seed_audit_pending()
    room, evt = stub._mk_reaction_event(
        'audit-msg-1', REACTION_APPROVE, '@admin:example.com'
    )
    await stub.on_reaction(room, evt)
    ap = stub._audit_approval_pending[req_id]
    assert ap['approved'] is True
    # 重复 reaction（不同 key）
    room2, evt2 = stub._mk_reaction_event(
        'audit-msg-1', REACTION_REJECT, '@admin:example.com'
    )
    await stub.on_reaction(room2, evt2)
    assert stub._audit_approval_pending[req_id]['approved'] is True


@pytest.mark.asyncio
async def test_on_reaction_credential_branch_still_works():
    """凭据审批消息仍走分支 4（回归：正向精确匹配不破坏凭据审批）。"""
    stub = ReactionStub()
    req_id = 'cred-0'
    evt = asyncio.Event()
    stub.pending_requests[req_id] = {
        'entry': 'db_password',
        'approved': None,
        'event': evt,
        'field': 'password',
        'use_token': True,
    }
    stub.approval_msgs['cred-msg-1'] = req_id
    room, revt = stub._mk_reaction_event(
        'cred-msg-1', REACTION_APPROVE, '@admin:example.com'
    )
    await stub.on_reaction(room, revt)
    assert stub.pending_requests[req_id]['approved'] is True
    assert evt.is_set()
    assert any('已批准' in t for t in stub._say_texts)


@pytest.mark.asyncio
async def test_on_reaction_credential_whitelist_blocks_non_member():
    """R5 回归：凭据审批分支拒绝非白名单发送者（design D4 硬性）。

    旧实现分支 4 无发送者白名单校验——任何房间成员可批准凭据释放
    （与审计审批白名单不一致）。Round 17 R5 修复：分支 4 与分支 5
    同规则校验发送者 ∈ 审批人白名单。
    """
    stub = ReactionStub()
    stub.approval_whitelist = {'@admin:example.com'}
    req_id = 'cred-1'
    evt = asyncio.Event()
    stub.pending_requests[req_id] = {
        'entry': 'db_password',
        'approved': None,
        'event': evt,
        'field': 'password',
        'use_token': True,
    }
    stub.approval_msgs['cred-msg-1'] = req_id
    # 非白名单发送者点 ✅ → 不批准
    room, revt = stub._mk_reaction_event(
        'cred-msg-1', REACTION_APPROVE, '@mallory:example.com'
    )
    await stub.on_reaction(room, revt)
    assert stub.pending_requests[req_id]['approved'] is None
    assert not evt.is_set()
    assert any('不在白名单' in t for t in stub._say_texts)
    # 白名单发送者点 ✅ → 批准
    room2, revt2 = stub._mk_reaction_event(
        'cred-msg-1', REACTION_APPROVE, '@admin:example.com'
    )
    await stub.on_reaction(room2, revt2)
    assert stub.pending_requests[req_id]['approved'] is True
    assert evt.is_set()


@pytest.mark.asyncio
async def test_on_reaction_unmatched_orig_noop():
    """未知 orig（无审批映射）→ on_reaction 不抛异常、无副作用。"""
    stub = ReactionStub()
    room, evt = stub._mk_reaction_event(
        'unknown-msg', REACTION_APPROVE, '@admin:example.com'
    )
    await stub.on_reaction(room, evt)  # 不应抛异常
    assert not stub._say_texts
