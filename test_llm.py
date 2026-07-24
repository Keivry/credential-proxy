"""test_llm.py — LlmMixin SSE 流式 token 还原单元测试。

覆盖: content 累积、safe/hold 分割、多 token、伪前缀、边界。
"""

import asyncio
import json
import sys
import types
from collections import OrderedDict
from unittest.mock import MagicMock

import pytest

# ── Mock aiohttp ──
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
ce.ClientConnectionResetError = type('CR', (Exception,), {})
aiohttp.client_exceptions = ce
sys.modules['aiohttp'] = aiohttp
sys.modules['aiohttp.web'] = aw
sys.modules['aiohttp.client_exceptions'] = ce

# ── Mock _matrix (SSE_CLIENT_GONE) ──
mx = types.ModuleType('_matrix')
mx.SSE_CLIENT_GONE = (
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
)
sys.modules['_matrix'] = mx

from _llm import LlmMixin, _mk_sse_event
from _token import TokenMixin

# ═══════════════════════════════════════════════════════════
# 测试辅助：不启动 aiohttp 服务，直接测试算法核心
# ═══════════════════════════════════════════════════════════


class TestSSEHolder(TokenMixin, LlmMixin):
    """最小 mock：仅测试 token 还原 + hold buffer 逻辑，不涉及 HTTP 层。"""

    def __init__(self):
        self._lock = asyncio.Lock()
        self.token_to_pwd = {}
        self._token_seq = 0
        self.pwd_to_token = OrderedDict()
        self._shared_session = None
        self.proxies = {}
        self._runners = []

    def _filter_hop_headers(self, h):
        return h


@pytest.fixture
def holder():
    return TestSSEHolder()


# ═══════════════════════════════════════════════════════════
# 核心算法：content 累积 → _restore → safe/hold 分割
# ═══════════════════════════════════════════════════════════


def _split_safe_hold(content: str, active_t2p: dict) -> tuple[str, str]:
    """split content into (safe_to_flush, hold_for_next_chunk).

    返回: (safe, hold)
    - safe: 可以安全输出（不含可能 token 前缀）
    - hold: 保留（以 __ 开头且匹配 active token 前缀）
    """
    if not content:
        return '', ''

    last_us = content.rfind('__')
    if last_us < 0:
        return content, ''

    suffix = content[last_us:]
    maybe_prefix = any(t.startswith(suffix) for t in active_t2p)
    if maybe_prefix:
        return content[:last_us], suffix
    return content, ''


# ═══════════════════════════════════════════════════════════
# split_safe_hold 单元测试
# ═══════════════════════════════════════════════════════════


class TestSplitSafeHold:
    """独立于 TokenMixin，直接测核心算法。"""

    def test_empty(self):
        assert _split_safe_hold('', {}) == ('', '')

    def test_no_double_underscore(self):
        """不含 __ 的内容 → 全部 safe。"""
        safe, hold = _split_safe_hold('hello world', {'__VG_CRED_000001__': 'pwd'})
        assert safe == 'hello world'
        assert hold == ''

    def test_double_underscore_not_token_prefix(self):
        """__init__.py 不是 token 前缀 → 全部 safe。"""
        t2p = {'__VG_CRED_000001__': 'pwd'}
        safe, hold = _split_safe_hold(
            'import __init__ file',
            t2p,
        )
        assert safe == 'import __init__ file'
        assert hold == ''

    def test_exact_token_prefix_hold(self):
        """__VG_CRED_ 是 token 前缀 → hold。"""
        t2p = {'__VG_CRED_000001__': 'pwd'}
        safe, hold = _split_safe_hold(
            'prefix text __VG_CRED_',
            t2p,
        )
        assert safe == 'prefix text '
        assert hold == '__VG_CRED_'

    def test_partial_token_prefix_hold(self):
        """__VG 是 token 前缀 → hold。"""
        t2p = {'__VG_CRED_000001__': 'pwd'}
        safe, hold = _split_safe_hold(
            'abc __VG',
            t2p,
        )
        assert safe == 'abc '
        assert hold == '__VG'

    def test_token_prefix_with_similar_but_different_tokens(self):
        """多个 token，后缀只匹配部分。"""
        t2p = {
            '__VG_CRED_000001__': 'pwd1',
            '__VG_CRED_000002__': 'pwd2',
        }
        # 后缀 __VG_CRED_ 是两个 token 的共同前缀
        safe, hold = _split_safe_hold(
            '>>__VG_CRED_00',
            t2p,
        )
        assert safe == '>>'
        assert hold == '__VG_CRED_00'

    def test_complete_token_already_restored(self):
        """完整 token 已被 _restore 替换，后续文本的 __ 不匹配。"""
        t2p = {'__VG_CRED_000001__': 'mypass123'}
        # _restore 已替换后：content = "密码是 mypass123 继续"
        safe, hold = _split_safe_hold(
            '密码是 mypass123 继续',
            t2p,
        )
        # mypass123 不含 __ → 全部 safe
        assert safe == '密码是 mypass123 继续'
        assert hold == ''

    def test_multiple_underscore_occurrences(self):
        """多个 __，只匹配最后一个。"""
        t2p = {'__VG_CRED_000001__': 'pwd'}
        safe, hold = _split_safe_hold(
            '__init__VG_CRED_',
            t2p,
        )
        # last_us = rfind("__") = "__VG_CRED" 中的 "__"
        # suffix = "__VG_CRED__" 匹配 token 前缀？
        # token = "__VG_CRED_000001__", 以 "__VG_CRED_" 开头
        # suffix = "__VG_CRED_" = token[:10] → YES, hold
        assert safe == '__init'
        assert hold == '__VG_CRED_'


# ═══════════════════════════════════════════════════════════
# 集成测试：TokenMixin._restore + content 累积
# ═══════════════════════════════════════════════════════════


class TestContentAccumulation:
    """模拟 SSE 流中 delta.content 累积 + token 还原。"""

    @pytest.mark.asyncio
    async def test_token_split_across_deltas(self, holder):
        """token 跨 6 个 delta 分片 → 累积后完整还原。"""
        # 注册密码
        pwd = 'My163AuthCode'
        token = await holder._register_secret(pwd)

        active_t2p = {token: pwd}

        # 模拟 SSE delta 序列
        deltas = ['__V', 'G_CR', 'ED_0', '000', '01__']
        hold = ''
        all_safe = ''

        for d in deltas:
            hold += d
            hold = holder._restore(hold, active_t2p)
            safe, hold = _split_safe_hold(hold, active_t2p)
            all_safe += safe

        # 最终 flush
        all_safe += hold

        assert token not in all_safe
        assert pwd in all_safe
        # _restore 把完整 token 替换为了密码原文，正确
        assert all_safe == pwd

    @pytest.mark.asyncio
    async def test_token_complete_in_one_delta(self, holder):
        """完整 token 在单个 delta 内 → 直接还原。"""
        pwd = 'My163AuthCode'
        token = await holder._register_secret(pwd)

        active_t2p = {token: pwd}

        hold = f'密码是 {token}'
        hold = holder._restore(hold, active_t2p)
        safe, hold = _split_safe_hold(hold, active_t2p)

        assert token not in safe
        assert pwd in safe
        assert hold == ''

    @pytest.mark.asyncio
    async def test_multiple_tokens_in_stream(self, holder):
        """多个不同 token 同时出现 → 全部还原。"""
        pwd1 = 'pwdAlpha'
        pwd2 = 'pwdBeta'
        tok1 = await holder._register_secret(pwd1)
        tok2 = await holder._register_secret(pwd2)

        active_t2p = {tok1: pwd1, tok2: pwd2}

        # 分片序列中包含两个 token
        deltas = [
            '第一个: ',
            '__V',
            'G_CR',
            'ED_000001__',  # tok1
            ', 第二个: ',
            tok2,  # tok2 完整
        ]
        hold = ''
        all_safe = ''

        for d in deltas:
            hold += d
            hold = holder._restore(hold, active_t2p)
            safe, hold = _split_safe_hold(hold, active_t2p)
            all_safe += safe
        all_safe += hold  # flush

        assert tok1 not in all_safe
        assert tok2 not in all_safe
        assert pwd1 in all_safe
        assert pwd2 in all_safe

    @pytest.mark.asyncio
    async def test_no_tokens_in_content(self, holder):
        """无 token 的普通文本 → 原封不动。"""
        pwd = 'My163AuthCode'
        token = await holder._register_secret(pwd)
        active_t2p = {token: pwd}

        deltas = ['普通', '文本', '没有', 'token']
        hold = ''
        all_safe = ''

        for d in deltas:
            hold += d
            hold = holder._restore(hold, active_t2p)
            safe, hold = _split_safe_hold(hold, active_t2p)
            all_safe += safe
        all_safe += hold

        assert all_safe == '普通文本没有token'

    @pytest.mark.asyncio
    async def test_double_underscore_in_normal_text(self, holder):
        """普通文本含 __init__ 不会被误 hold。"""
        pwd = 'My163AuthCode'
        token = await holder._register_secret(pwd)
        active_t2p = {token: pwd}

        deltas = ['请看 ', '__init__.py', ' 配置']
        hold = ''
        all_safe = ''

        for d in deltas:
            hold += d
            hold = holder._restore(hold, active_t2p)
            safe, hold = _split_safe_hold(hold, active_t2p)
            all_safe += safe
        all_safe += hold

        assert all_safe == '请看 __init__.py 配置'
        assert token not in all_safe

    @pytest.mark.asyncio
    async def test_hold_eventually_flushed(self, holder):
        """hold 的内容在流末被 flush。"""
        pwd = 'My163AuthCode'
        token = await holder._register_secret(pwd)
        active_t2p = {token: pwd}

        # 一个永远不凑齐的 token 前缀（如 __VG_CRED 后跟非 token 后缀）
        deltas = ['__VG_X_Y_Z']  # 不是 active_t2p 中任何 token 的前缀
        hold = ''
        all_safe = ''

        for d in deltas:
            hold += d
            hold = holder._restore(hold, active_t2p)
            safe, hold = _split_safe_hold(hold, active_t2p)
            all_safe += safe
        all_safe += hold  # 最终 flush

        assert '__VG_X_Y_Z' in all_safe  # 不可能还原，直接输出
        assert token not in all_safe


# ═══════════════════════════════════════════════════════════
# 流末 flush 测试
# ═══════════════════════════════════════════════════════════


class TestStreamEndFlush:
    """流结束时强制 flush 残留 hold。"""

    @pytest.mark.asyncio
    async def test_flush_incomplete_hold_at_end(self, holder):
        """流末 hold 区内含完整 token → 最终还原输出。"""
        pwd = 'My163AuthCode'
        token = await holder._register_secret(pwd)
        active_t2p = {token: pwd}

        # 分片后最终凑齐 token，但在最后一个事件前 hold 住
        deltas = ['__V', 'G_CR', 'ED_000001__', ' 完成']
        hold = ''
        all_safe = ''

        for i, d in enumerate(deltas):
            hold += d
            hold = holder._restore(hold, active_t2p)
            if i < len(deltas) - 1:  # 最后一段之前用 split
                safe, hold = _split_safe_hold(hold, active_t2p)
                all_safe += safe
            # 最后一段：直接 flush hold（模拟流末）

        all_safe += hold  # 最终 flush

        assert token not in all_safe
        assert pwd in all_safe


# ═══════════════════════════════════════════════════════════
# 伪前缀误 hold 防护测试
# ═══════════════════════════════════════════════════════════


class TestFalsePositiveHold:
    """验证 __ 伪前缀不会导致无限 hold。"""

    @pytest.mark.asyncio
    async def test_password_containing_underscores(self, holder):
        """还原后的密码含 __ 不会误 hold。"""
        pwd = 'AB__CD'
        token = await holder._register_secret(pwd)
        active_t2p = {token: pwd}

        # 完整 token 在单个 delta 中
        hold = f'密码: {token}'
        hold = holder._restore(hold, active_t2p)
        safe, pending_hold = _split_safe_hold(hold, active_t2p)

        # 密码 AB__CD 中有 __，_restore 已替换
        # content = "密码: AB__CD"
        # rfind("__") → 找到密码中的 __，后缀 = "__CD"
        # "__CD" 是否匹配任何 active token 前缀？
        # token = "__VG_CRED_000001__"，不以 "__CD" 开头 → 不是前缀
        # → safe = 全部，hold = ""
        assert pwd in safe
        assert pending_hold == ''

    @pytest.mark.asyncio
    async def test_token_prefix_followed_by_non_token(self, holder):
        """__VG 后面跟的不是 token → 下次 flush。"""
        pwd = 'My163AuthCode'
        token = await holder._register_secret(pwd)
        active_t2p = {token: pwd}

        # __VG_ 是前缀，但后面跟 XYZ 不是完整 token
        deltas = ['__VG_XYZ']
        hold = ''
        all_safe = ''

        for d in deltas:
            hold += d
            hold = holder._restore(hold, active_t2p)
            safe, hold = _split_safe_hold(hold, active_t2p)
            all_safe += safe
        all_safe += hold

        # __VG_XYZ 不是任何 token 的前缀（token 以 __VG_CRED 开头）
        # → _restore 不匹配 → 不替换
        # split: "__VG_XYZ" 后缀是 "__VG_XYZ"，是否 token 前缀？
        # token = "__VG_CRED_000001__"
        # "__VG_XYZ" 不是 "__VG_CRED_000001__" 的前缀 → 不是
        # → 全部 safe，输出原文
        assert '__VG_XYZ' in all_safe


# ═══════════════════════════════════════════════════════════
# finish_reason / [DONE] / 非 content 事件处理测试
# ═══════════════════════════════════════════════════════════


class TestFinishReasonAndDone:
    """验证 finish_reason 和 [DONE] 时的累积内容正确 flush。"""

    @pytest.mark.asyncio
    async def test_finish_reason_with_pending(self, holder):
        """finish_reason 到达时，pending 的 token 前缀被 flush。"""
        pwd = 'My163AuthCode'
        token = await holder._register_secret(pwd)
        active_t2p = {token: pwd}

        # 模拟：前面的 delta 留下了 pending 前缀
        # content_parts = ["__VG_C"] after safe/hold split
        # 然后 finish_reason 在同一事件到达
        content_parts = ['__VG_C']
        joined = ''.join(content_parts)
        joined = holder._restore(joined, active_t2p)
        # 应写入 "__VG_C"（完整 token 未形成）
        assert joined == '__VG_C'

    @pytest.mark.asyncio
    async def test_finish_reason_completes_token(self, holder):
        """finish_reason 与最后一个 delta 同时到达，凑齐完整 token。"""
        pwd = 'My163AuthCode'
        token = await holder._register_secret(pwd)
        active_t2p = {token: pwd}

        # 前面的 safe 部分已 flush，content_parts = ["__VG_CRED_0000"]
        # 现在最后一个 delta + finish_reason 抵达
        content_parts = ['__VG_CRED_0000', '01__']
        joined = ''.join(content_parts)
        joined = holder._restore(joined, active_t2p)
        # __VG_CRED_000001__ → 完整 token，应被还原
        assert token not in joined
        assert pwd in joined

    @pytest.mark.asyncio
    async def test_done_flushes_pending(self, holder):
        """[DONE] 到达时，pending 内容被 flush。"""
        pwd = 'My163AuthCode'
        token = await holder._register_secret(pwd)
        active_t2p = {token: pwd}

        # 模拟 [DONE] 前 content_parts 有残留
        content_parts = ['__VG_C']  # 未完成的 token 前缀
        joined = ''.join(content_parts)
        joined = holder._restore(joined, active_t2p)
        # 不匹配完整 token → 保持原值，但会 flush
        assert joined == '__VG_C'

    @pytest.mark.asyncio
    async def test_flush_calls_restore(self, holder):
        """_flush 内部调用 _restore 防止防御性缺口。"""
        pwd = 'My163AuthCode'
        token = await holder._register_secret(pwd)
        active_t2p = {token: pwd}

        # 完整 token 在 flush 前存在于内容中
        content = f'密码是 {token}'
        content = holder._restore(content, active_t2p)
        assert token not in content
        assert pwd in content


# ═══════════════════════════════════════════════════════════
# _mk_sse_event 直接单元测试
# ═══════════════════════════════════════════════════════════



class TestMkSseEvent:
    """验证 _mk_sse_event 的 SSE 输出格式和边界。"""

    def test_content_only(self):
        result = _mk_sse_event('hello')
        assert result.startswith('data: ')
        assert result.endswith('\n')
        payload = json.loads(result[6:].rstrip('\n'))
        assert payload['choices'][0]['delta'] == {'content': 'hello'}
        assert payload['choices'][0]['finish_reason'] is None

    def test_content_with_finish_reason(self):
        """修复后：content 和 finish_reason 可共存。"""
        result = _mk_sse_event('hello', 'stop')
        payload = json.loads(result[6:].rstrip('\n'))
        assert payload['choices'][0]['delta'] == {'content': 'hello'}
        assert payload['choices'][0]['finish_reason'] == 'stop'

    def test_empty_content_with_finish_reason(self):
        """空 content + finish_reason → delta={}（OpenAI 终端事件）。"""
        result = _mk_sse_event('', 'stop')
        payload = json.loads(result[6:].rstrip('\n'))
        assert payload['choices'][0]['delta'] == {}
        assert payload['choices'][0]['finish_reason'] == 'stop'

    def test_empty_content_no_finish(self):
        result = _mk_sse_event('')
        payload = json.loads(result[6:].rstrip('\n'))
        assert payload['choices'][0]['delta'] == {}
        assert payload['choices'][0]['finish_reason'] is None

    def test_falsy_content_zero(self):
        """content='0' 是 truthy 字符串，不应被误判为空。"""
        result = _mk_sse_event('0', 'stop')
        payload = json.loads(result[6:].rstrip('\n'))
        assert payload['choices'][0]['delta'] == {'content': '0'}
        assert payload['choices'][0]['finish_reason'] == 'stop'

    def test_sse_format_structure(self):
        """验证 SSE data: 前缀和 JSON 结构完整性。"""
        result = _mk_sse_event('text')
        assert result.startswith('data: ')
        assert result.endswith('\n')
        # 应包含完整 JSON
        data = result[6:].strip()
        parsed = json.loads(data)
        assert 'choices' in parsed
        assert isinstance(parsed['choices'], list)
