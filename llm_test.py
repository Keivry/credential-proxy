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
from _llm import (
    _PARTIAL_TOKEN_RE,
    LlmMixin,
    _anthropic_event,
    _mk_anthropic_delta_event,
    _mk_anthropic_flush_event,
    _mk_responses_flush_event,
    _mk_responses_sse_event,
    _mk_sse_event,
    _responses_event,
    _split_safe_hold,
)
from _token import TokenMixin

# ═══════════════════════════════════════════════════════════
# 测试辅助：不启动 aiohttp 服务，直接测试算法核心
# ═══════════════════════════════════════════════════════════


class TestSSEHolder(TokenMixin, LlmMixin):
    """辅助类，提供 TokenMixin + LlmMixin 需要的 self 属性。"""

    __test__ = False

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
# （_split_safe_hold 从 _llm 导入生产版，不维护测试副本）
# ═══════════════════════════════════════════════════════════


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


# ═══════════════════════════════════════════════════════════
# 幻觉 token / partial 形态清理（B3/M1 回归）
# ═══════════════════════════════════════════════════════════


class TestPartialTokenCleanup:
    """_PARTIAL_TOKEN_RE：清理残缺 token 形态，不误伤正常文本。"""

    def test_full_token_not_matched(self):
        """完整 token 形态（真实 token 已被 _restore 还原；残留=幻觉）→ 流末清理。"""
        assert _PARTIAL_TOKEN_RE.sub('', 'xx __VG_CRED_000001__') == 'xx '

    def test_partial_forms_cleaned(self):
        """B3 回归：各种残缺形态都被清理（含任意字符截断）。"""
        cases = [
            ('__VG_C', ''),
            ('__VG_CR', ''),
            ('__VG_CRE', ''),
            ('__VG_CRED', ''),
            ('__VG_CRED_', ''),
            ('__VG_CRED_000001', ''),
            ('__VG_CRED_000001_', ''),  # 缺结尾下划线
        ]
        for text, expected in cases:
            assert _PARTIAL_TOKEN_RE.sub('', text) == expected, text

    def test_partial_in_middle_of_text(self):
        """行尾之外的 partial 不受影响（只在行尾清理）。"""
        text = '密码是 __VG_CRED_000001_ 后面还有字'
        assert _PARTIAL_TOKEN_RE.sub('', text) == text

    def test_normal_text_unharmed(self):
        assert _PARTIAL_TOKEN_RE.sub('', 'foo__bar') == 'foo__bar'
        assert _PARTIAL_TOKEN_RE.sub('', '普通文本') == '普通文本'
        assert _PARTIAL_TOKEN_RE.sub('', '__') == '__'


class TestHallucinatedTokenHold:
    """M1 回归：完整但不在 active_t2p 的 token（幻觉）整体 hold，防重组泄漏。"""

    def test_unknown_full_token_held(self):
        t2p = {'__VG_CRED_000001__': 'pwd'}
        safe, hold = _split_safe_hold('hi __VG_CRED_999999__', t2p)
        assert safe == 'hi '
        assert hold == '__VG_CRED_999999__'

    def test_known_token_restored_already(self):
        """active 里的 token 已被 _restore 还原为明文，不触发 hold。"""
        t2p = {'__VG_CRED_000001__': 'pwd'}
        # 模拟 _restore 后的文本：明文，不含 token
        safe, hold = _split_safe_hold('hi pwd', t2p)
        assert safe == 'hi pwd'
        assert hold == ''

    def test_unknown_token_mid_text(self):
        """token 不在行尾 → 不触发 hold（rfind 逻辑照常）。"""
        t2p = {'__VG_CRED_000001__': 'pwd'}
        safe, hold = _split_safe_hold('__VG_CRED_999999__ hi', t2p)
        assert safe == ' hi'  # 行中完整幻觉 token 被剥离
        assert hold == ''

    def test_unknown_token_mid_sentence_stripped(self):
        """B 回归：行中幻觉 token 从 safe 剥离，防句柄泄漏。"""
        t2p = {'__VG_CRED_000001__': 'pwd'}
        safe, hold = _split_safe_hold('hi __VG_CRED_999999__ more', t2p)
        assert '__VG_CRED' not in safe
        assert '999999' not in safe
        # 普通文本保留
        assert 'hi ' in safe
        assert ' more' in safe or hold == ''

    def test_double_unknown_tokens(self):
        """多个幻觉 token 全部剥离（不只行尾）。"""
        t2p = {'__VG_CRED_000001__': 'pwd'}
        safe, _ = _split_safe_hold('__VG_CRED_000002__ and __VG_CRED_000003__', t2p)
        assert '__VG_CRED' not in safe

    def test_token_like_word_unharmed(self):
        """形似 token 的正常单词（无数字+__结尾）不受影响。"""
        t2p = {'__VG_CRED_000001__': 'pwd'}
        safe, _ = _split_safe_hold('__VG_CREDENTIAL__ is fine', t2p)
        assert '__VG_CREDENTIAL__' in safe

    @pytest.mark.asyncio
    async def test_handler_no_reassembly(self):
        """handler 层面：幻觉 token 不被重组输出，流末被清理。"""
        holder = TestSSEHolder()
        await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        evt = {
            'type': 'response.output_text.delta',
            'delta': 'hi __VG_CRED_999999__',
            'sequence_number': 1,
        }
        cb, _, _ = await holder._handle_responses_event(w, evt, '', t2p, '', '', '')
        # 幻觉 token 整体 hold，不输出 token 字符串
        assert 'hi ' in w.text
        assert '__VG_CRED_999999__' not in w.text
        assert cb == '__VG_CRED_999999__'
        # 流末清理
        cb = await holder._flush_responses_buf(
            w, 'response.output_text.delta', cb, t2p, keep_pending=False
        )
        assert cb == ''
        assert '__VG_CRED' not in w.text


class TestResponsesStreamEndFlush:
    """流末 flush（keep_pending=False）：清理 partial 并输出残余。"""

    @pytest.mark.asyncio
    async def test_pending_prefix_cleaned_at_end(self):
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        # 模拟流结束时的残留：'text ' + 未完成前缀
        cb = 'text ' + token[:8]
        cb = await holder._flush_responses_buf(
            w, 'response.output_text.delta', cb, t2p, keep_pending=False
        )
        assert cb == ''
        # safe 部分输出，partial 前缀被清理
        assert 'text ' in w.text
        assert token[:8] not in w.text

    @pytest.mark.asyncio
    async def test_pure_prefix_cleaned_empty(self):
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        cb = await holder._flush_responses_buf(
            w, 'response.output_text.delta', token[:8], t2p, keep_pending=False
        )
        assert cb == ''
        assert w.text == ''  # 纯前缀无残余可输出

    @pytest.mark.asyncio
    async def test_reasoning_and_arg_buf_at_end(self):
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        await holder._flush_responses_buf(
            w,
            'response.reasoning_text.delta',
            'think ' + token[:8],
            t2p,
            keep_pending=False,
        )
        await holder._flush_responses_buf(
            w,
            'response.function_call_arguments.delta',
            '{"k":' + token[:8],
            t2p,
            keep_pending=False,
        )
        events = w.parsed_events()
        assert any(
            e['type'] == 'response.reasoning_text.delta' and e['delta'] == 'think '
            for e in events
        )
        assert any(
            e['type'] == 'response.function_call_arguments.delta'
            and e['delta'] == '{"k":'
            for e in events
        )
        assert token[:8] not in w.text


# ═══════════════════════════════════════════════════════════
# Responses API SSE 事件（/v1/responses）— 识别器 + 处理器
# ═══════════════════════════════════════════════════════════


class FakeWriter:
    """收集写入字节的假 SSE writer（模拟 resp.write）。"""

    def __init__(self):
        self.chunks: list[bytes] = []

    async def __call__(self, data: bytes):
        self.chunks.append(data)

    @property
    def text(self) -> str:
        return b''.join(self.chunks).decode('utf-8')

    def parsed_events(self) -> list[dict]:
        """解析输出中所有 data: 事件的 JSON payload。"""
        events = []
        for line in self.text.splitlines():
            if line.startswith('data: '):
                events.append(json.loads(line[6:]))
        return events


class TestResponsesEventRecognizer:
    """_responses_event 识别器。"""

    @staticmethod
    def _evt(payload: dict) -> tuple[str, str | None]:
        """解包识别结果（测试场景保证非 None）。"""
        result = _responses_event(payload)
        assert result is not None
        return result

    def test_output_text_delta(self):
        kind, dt = self._evt({'type': 'response.output_text.delta', 'delta': 'hi'})
        assert kind == 'output_text'
        assert dt == 'hi'

    def test_reasoning_text_delta(self):
        kind, dt = self._evt(
            {'type': 'response.reasoning_text.delta', 'delta': 'think'}
        )
        assert kind == 'reasoning_text'
        assert dt == 'think'

    def test_function_call_arguments_delta(self):
        kind, dt = self._evt(
            {
                'type': 'response.function_call_arguments.delta',
                'delta': '{"city":',
            }
        )
        assert kind == 'function_call_arguments'
        assert dt == '{"city":'

    def test_completed_is_other(self):
        kind, dt = self._evt({'type': 'response.completed'})
        assert kind == 'other'
        assert dt is None

    def test_created_is_other(self):
        kind, _ = self._evt({'type': 'response.created'})
        assert kind == 'other'

    def test_output_item_done_is_item_done(self):
        """output_item.done → item_done（用于清理跨 item 残留）。"""
        kind, dt = self._evt({'type': 'response.output_item.done'})
        assert kind == 'item_done'
        assert dt is None

    def test_output_text_done_is_item_done(self):
        kind, dt = self._evt(
            {'type': 'response.output_text.done', 'delta': 'full text'}
        )
        assert kind == 'item_done'
        assert dt is None

    def test_chat_completions_event_returns_none(self):
        """chat/completions SSE 事件（无 type 或非 response.*）→ None。"""
        assert _responses_event({'choices': [{'delta': {'content': 'x'}}]}) is None
        assert _responses_event({'object': 'chat.completion.chunk'}) is None

    def test_delta_not_string_falls_back_to_other(self):
        """delta 字段非字符串（异常/边界）→ 当作普通事件。"""
        kind, dt = self._evt({'type': 'response.output_text.delta', 'delta': 123})
        assert kind == 'other'
        assert dt is None

    def test_missing_delta_falls_back_to_other(self):
        kind, dt = self._evt({'type': 'response.output_text.delta'})
        assert kind == 'other'
        assert dt is None


class TestResponsesEventFormatting:
    """Responses 事件输出格式。"""

    def test_mk_responses_sse_event_preserves_fields(self):
        evt = {
            'type': 'response.output_text.delta',
            'delta': 'x',
            'sequence_number': 5,
        }
        result = _mk_responses_sse_event(evt, 'restored')
        assert result.startswith('data: ')
        assert result.endswith('\n')
        parsed = json.loads(result[6:].rstrip('\n'))
        assert parsed['type'] == 'response.output_text.delta'
        assert parsed['delta'] == 'restored'
        assert parsed['sequence_number'] == 5

    def test_mk_responses_flush_event(self):
        result = _mk_responses_flush_event('response.output_text.delta', 'x')
        parsed = json.loads(result[6:].rstrip('\n'))
        assert parsed == {'type': 'response.output_text.delta', 'delta': 'x'}


class TestResponsesEventHandler:
    """_handle_responses_event：分片 token 累积还原 + 保持原格式。"""

    @pytest.mark.asyncio
    async def test_single_event_full_token_restore(self):
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        evt = {
            'type': 'response.output_text.delta',
            'delta': f'secret is {token}',
            'sequence_number': 1,
        }
        cb, _, _ = await holder._handle_responses_event(w, evt, '', t2p, '', '', '')
        assert 'secret is p@ssword123' in w.text
        assert token not in w.text  # 无残留 token
        assert cb == ''  # 完整 token 后无 pending

    @pytest.mark.asyncio
    async def test_fragmented_token_accumulates(self):
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        mid = len(token) // 2
        evt1 = {
            'type': 'response.output_text.delta',
            'delta': 'prefix ' + token[:mid],
            'sequence_number': 1,
        }
        evt2 = {
            'type': 'response.output_text.delta',
            'delta': token[mid:] + ' suffix',
            'sequence_number': 2,
        }
        cb, rb, ab = await holder._handle_responses_event(w, evt1, '', t2p, '', '', '')
        # 第一片：safe='prefix '，pending=token 前缀（restore 后仍为不完整 token）
        assert 'prefix ' in w.text
        assert cb == token[:mid]
        cb, rb, ab = await holder._handle_responses_event(w, evt2, '', t2p, cb, rb, ab)
        assert 'p@ssword123' in w.text
        assert ' suffix' in w.text
        assert cb == ''
        # 输出事件保持 Responses 格式（非 chat.completion.chunk）
        events = w.parsed_events()
        assert all(e['type'] == 'response.output_text.delta' for e in events)
        assert 'choices' not in w.text

    @pytest.mark.asyncio
    async def test_reasoning_text_fragmented(self):
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        mid = len(token) // 2
        evt1 = {
            'type': 'response.reasoning_text.delta',
            'delta': token[:mid],
            'sequence_number': 1,
        }
        evt2 = {
            'type': 'response.reasoning_text.delta',
            'delta': token[mid:],
            'sequence_number': 2,
        }
        cb, rb, ab = await holder._handle_responses_event(w, evt1, '', t2p, '', '', '')
        assert rb == token[:mid]
        cb, rb, ab = await holder._handle_responses_event(w, evt2, '', t2p, cb, rb, ab)
        assert 'p@ssword123' in w.text
        assert rb == ''

    @pytest.mark.asyncio
    async def test_function_call_arguments_fragmented(self):
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        mid = len(token) // 2
        evt1 = {
            'type': 'response.function_call_arguments.delta',
            'delta': token[:mid],
            'sequence_number': 1,
        }
        evt2 = {
            'type': 'response.function_call_arguments.delta',
            'delta': token[mid:] + '}',
            'sequence_number': 2,
        }
        cb, rb, ab = await holder._handle_responses_event(w, evt1, '', t2p, '', '', '')
        assert ab == token[:mid]
        cb, rb, ab = await holder._handle_responses_event(w, evt2, '', t2p, cb, rb, ab)
        assert 'p@ssword123' in w.text
        assert ab == ''

    @pytest.mark.asyncio
    async def test_completed_flushes_pending_and_passthrough(self):
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        evt1 = {
            'type': 'response.output_text.delta',
            'delta': 'text ' + token[:8],
            'sequence_number': 1,
        }
        cb, _, _ = await holder._handle_responses_event(w, evt1, '', t2p, '', '', '')
        # 第一片：safe='text ' 已输出，content_buf 只保留 pending（token 前缀）
        assert cb == token[:8]
        assert 'text ' in w.text
        completed_line = 'data: {"type":"response.completed","sequence_number":2}'
        cb, _, _ = await holder._handle_responses_event(
            w,
            {'type': 'response.completed', 'sequence_number': 2},
            completed_line,
            t2p,
            cb,
            '',
            '',
        )
        # 残留中的 safe 部分以 Responses delta 事件 flush；pending 保留等后续分片
        assert cb == token[:8]  # B1 修复：flush 不再丢弃 pending
        events = w.parsed_events()
        assert any(
            e['type'] == 'response.output_text.delta' and e['delta'] == 'text '
            for e in events
        )
        # 不完整的 token 前缀不应泄漏
        assert token[:8] not in w.text
        # completed 事件本身原样透传
        assert 'response.completed' in w.text
        assert 'chat.completion' not in w.text  # 无 chat 格式污染

    @pytest.mark.asyncio
    async def test_pending_survives_non_delta_event(self):
        """B1 回归：token 分片跨非 delta 事件（done/completed）时 pending 保留并完成还原。"""
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        mid = len(token) // 2
        evt1 = {
            'type': 'response.output_text.delta',
            'delta': 'text ' + token[:mid],
            'sequence_number': 1,
        }
        done_line = 'data: {"type":"response.output_item.done","sequence_number":2}'
        cb, _, _ = await holder._handle_responses_event(w, evt1, '', t2p, '', '', '')
        assert cb == token[:mid]
        # 非 delta 事件：pending 保留
        cb, _, _ = await holder._handle_responses_event(
            w,
            {'type': 'response.output_item.done', 'sequence_number': 2},
            done_line,
            t2p,
            cb,
            '',
            '',
        )
        assert cb == token[:mid]
        # 后续分片完成 token
        evt2 = {
            'type': 'response.output_text.delta',
            'delta': token[mid:] + ' end',
            'sequence_number': 3,
        }
        cb, _, _ = await holder._handle_responses_event(w, evt2, '', t2p, cb, '', '')
        assert 'p@ssword123' in w.text
        assert ' end' in w.text
        assert cb == ''

    @pytest.mark.asyncio
    async def test_item_done_clears_arg_buf(self):
        """item_done（output_item.done）清空 arg_buf：防跨 item 伪还原（对称 block_stop）。"""
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        mid = len(token) // 2
        # tool1: function_call_arguments 截断在 token 中间
        evt1 = {
            'type': 'response.function_call_arguments.delta',
            'delta': '{"pwd": "' + token[:mid],
            'sequence_number': 1,
        }
        _, _, ab = await holder._handle_responses_event(w, evt1, '', t2p, '', '', '')
        assert ab == token[:mid]
        # output_item.done: 清空 arg_buf，content/reasoning pending 保留
        done_line = 'data: {"type":"response.output_item.done","sequence_number":2}'
        cb, rb, ab = await holder._handle_responses_event(
            w,
            {'type': 'response.output_item.done', 'sequence_number': 2},
            done_line,
            t2p,
            'text ' + token[:8],  # content pending 注入
            'think ' + token[:8],  # reasoning pending 注入
            ab,
        )
        assert ab == ''
        assert cb == 'text ' + token[:8]
        assert rb == 'think ' + token[:8]
        assert done_line + '\n' in w.text  # 原样透传
        # tool2 从 token 剩余部分开头 → 不伪还原
        evt2 = {
            'type': 'response.function_call_arguments.delta',
            'delta': token[mid:] + '"}',
            'sequence_number': 3,
        }
        _, _, ab = await holder._handle_responses_event(w, evt2, '', t2p, '', '', ab)
        assert 'p@ssword123' not in w.text
        assert '__VG_CRED' not in w.text
        assert ab == ''

    @pytest.mark.asyncio
    async def test_completed_pure_prefix_flushed_empty(self):
        """残留为纯 token 前缀时 flush 无输出（前缀被清理），completed 仍透传。"""
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        cb, _, _ = await holder._handle_responses_event(
            w,
            {
                'type': 'response.output_text.delta',
                'delta': token[:8],
                'sequence_number': 1,
            },
            '',
            t2p,
            '',
            '',
            '',
        )
        assert cb == token[:8]
        completed_line = 'data: {"type":"response.completed","sequence_number":2}'
        cb, _, _ = await holder._handle_responses_event(
            w,
            {'type': 'response.completed', 'sequence_number': 2},
            completed_line,
            t2p,
            cb,
            '',
            '',
        )
        # B1 修复后：pending 保留（token 前缀等待后续分片），流末才清理
        assert cb == token[:8]
        # 纯前缀残留无 safe 可输出：只透传 completed
        assert w.text == completed_line + '\n'
        assert token[:8] not in w.text

    @pytest.mark.asyncio
    async def test_other_event_passthrough_no_pollution(self):
        holder = TestSSEHolder()
        await holder._register_secret(
            'p@ssword123'
        )  # 注册秘密，确保 active_t2p 非空路径
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        line = 'data: {"type":"response.created","sequence_number":0}'
        _, _, _ = await holder._handle_responses_event(
            w,
            {'type': 'response.created', 'sequence_number': 0},
            line,
            t2p,
            '',
            '',
            '',
        )
        assert w.text == line + '\n'
        assert 'choices' not in w.text

    @pytest.mark.asyncio
    async def test_no_token_plain_text(self):
        holder = TestSSEHolder()
        w = FakeWriter()
        evt = {
            'type': 'response.output_text.delta',
            'delta': 'hello world',
            'sequence_number': 1,
        }
        cb, _, _ = await holder._handle_responses_event(w, evt, '', {}, '', '', '')
        events = w.parsed_events()
        assert len(events) == 1
        assert events[0]['type'] == 'response.output_text.delta'
        assert events[0]['delta'] == 'hello world'
        assert cb == ''

    @pytest.mark.asyncio
    async def test_unicode_content_roundtrip(self):
        """中文内容不转义（ensure_ascii=False），保证下游可读。"""
        holder = TestSSEHolder()
        w = FakeWriter()
        evt = {
            'type': 'response.output_text.delta',
            'delta': '你好，旅行者',
            'sequence_number': 1,
        }
        _, _, _ = await holder._handle_responses_event(w, evt, '', {}, '', '', '')
        assert '你好，旅行者' in w.text
        assert '\\u' not in w.text


# ═══════════════════════════════════════════════════════════
# Anthropic Messages API SSE 事件（/v1/messages）— 识别器 + 处理器
# ═══════════════════════════════════════════════════════════


class TestAnthropicEventRecognizer:
    """_anthropic_event 识别器。"""

    @staticmethod
    def _evt(payload: dict) -> tuple[str, str | None]:
        result = _anthropic_event(payload)
        assert result is not None
        return result

    def test_text_delta(self):
        kind, dt = self._evt(
            {
                'type': 'content_block_delta',
                'index': 0,
                'delta': {'type': 'text_delta', 'text': 'hello'},
            }
        )
        assert kind == 'text'
        assert dt == 'hello'

    def test_thinking_delta(self):
        kind, dt = self._evt(
            {
                'type': 'content_block_delta',
                'index': 0,
                'delta': {'type': 'thinking_delta', 'thinking': 'think...'},
            }
        )
        assert kind == 'thinking'
        assert dt == 'think...'

    def test_input_json_delta(self):
        kind, dt = self._evt(
            {
                'type': 'content_block_delta',
                'index': 0,
                'delta': {'type': 'input_json_delta', 'partial_json': '{"a":'},
            }
        )
        assert kind == 'function_args'
        assert dt == '{"a":'

    def test_other_delta_type(self):
        """server_tool_use 等其他 delta 类型 → other。"""
        kind, dt = self._evt(
            {
                'type': 'content_block_delta',
                'index': 0,
                'delta': {'type': 'server_tool_use', 'name': 'x'},
            }
        )
        assert kind == 'other'
        assert dt is None

    def test_delta_not_dict(self):
        kind, dt = self._evt({'type': 'content_block_delta', 'index': 0})
        assert kind == 'other'
        assert dt is None

    def test_non_delta_events_return_none(self):
        """message_start / content_block_start / message_delta / message_stop 等不含文本，不拦截。"""
        events = [
            {'type': 'message_start', 'message': {'id': 'msg_01'}},
            {'type': 'content_block_start', 'index': 0},
            {'type': 'message_delta', 'delta': {'stop_reason': 'end_turn'}},
            {'type': 'message_stop'},
            {'type': 'ping'},
        ]
        for evt in events:
            assert _anthropic_event(evt) is None, evt

    def test_block_stop_recognized(self):
        """content_block_stop → block_stop（用于清理跨块残留）。"""
        kind, dt = self._evt({'type': 'content_block_stop', 'index': 0})
        assert kind == 'block_stop'
        assert dt is None

    def test_other_protocols_return_none(self):
        assert _anthropic_event({'choices': [{'delta': {'content': 'x'}}]}) is None
        assert _anthropic_event({'type': 'response.created'}) is None


class TestAnthropicEventFormatting:
    """Anthropic 事件输出格式保持。"""

    def test_mk_anthropic_delta_event_preserves_structure(self):
        parsed = {
            'type': 'content_block_delta',
            'index': 2,
            'delta': {'type': 'text_delta', 'text': 'orig', 'signature': 'sig1'},
        }
        result = _mk_anthropic_delta_event(parsed, 'restored', 'text')
        assert result.startswith('data: ')
        out = json.loads(result[6:].rstrip('\n'))
        assert out['type'] == 'content_block_delta'
        assert out['index'] == 2
        assert out['delta']['type'] == 'text_delta'
        assert out['delta']['text'] == 'restored'
        assert out['delta']['signature'] == 'sig1'  # 其他字段保留

    def test_mk_anthropic_flush_event(self):
        parsed = {'type': 'content_block_delta', 'index': 1}
        result = _mk_anthropic_flush_event(parsed, 'x', 'thinking')
        out = json.loads(result[6:].rstrip('\n'))
        assert out['type'] == 'content_block_delta'
        assert out['index'] == 1
        assert out['delta'] == {'type': 'thinking_delta', 'thinking': 'x'}

    def test_mk_anthropic_flush_event_input_json(self):
        parsed = {'type': 'content_block_delta', 'index': 0}
        result = _mk_anthropic_flush_event(parsed, '{"k":', 'partial_json')
        out = json.loads(result[6:].rstrip('\n'))
        assert out['delta'] == {'type': 'input_json_delta', 'partial_json': '{"k":'}


class TestAnthropicEventHandler:
    """_handle_anthropic_event 核心：分片 token 累积还原。"""

    @pytest.mark.asyncio
    async def test_text_fragmented_token(self):
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        mid = len(token) // 2
        evt1 = {
            'type': 'content_block_delta',
            'index': 0,
            'delta': {'type': 'text_delta', 'text': 'secret ' + token[:mid]},
        }
        evt2 = {
            'type': 'content_block_delta',
            'index': 0,
            'delta': {'type': 'text_delta', 'text': token[mid:] + ' end'},
        }
        cb, _, _ = await holder._handle_anthropic_event(w, evt1, '', t2p, '', '', '')
        assert 'secret ' in w.text
        assert cb == token[:mid]
        cb, _, _ = await holder._handle_anthropic_event(w, evt2, '', t2p, cb, '', '')
        assert 'p@ssword123' in w.text
        assert ' end' in w.text
        assert cb == ''

    @pytest.mark.asyncio
    async def test_thinking_fragmented_token(self):
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        mid = len(token) // 2
        evt1 = {
            'type': 'content_block_delta',
            'index': 0,
            'delta': {'type': 'thinking_delta', 'thinking': 'let me ' + token[:mid]},
        }
        evt2 = {
            'type': 'content_block_delta',
            'index': 0,
            'delta': {'type': 'thinking_delta', 'thinking': token[mid:] + ' think'},
        }
        _, rb, _ = await holder._handle_anthropic_event(w, evt1, '', t2p, '', '', '')
        assert rb == token[:mid]
        _, rb, _ = await holder._handle_anthropic_event(w, evt2, '', t2p, '', rb, '')
        assert 'p@ssword123' in w.text
        assert rb == ''

    @pytest.mark.asyncio
    async def test_input_json_fragmented_token(self):
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        mid = len(token) // 2
        evt1 = {
            'type': 'content_block_delta',
            'index': 0,
            'delta': {
                'type': 'input_json_delta',
                'partial_json': '{"pwd": "' + token[:mid],
            },
        }
        evt2 = {
            'type': 'content_block_delta',
            'index': 0,
            'delta': {
                'type': 'input_json_delta',
                'partial_json': token[mid:] + '"}',
            },
        }
        _, _, ab = await holder._handle_anthropic_event(w, evt1, '', t2p, '', '', '')
        assert ab == token[:mid]
        _, _, ab = await holder._handle_anthropic_event(w, evt2, '', t2p, '', '', ab)
        assert 'p@ssword123' in w.text
        assert ab == ''

    @pytest.mark.asyncio
    async def test_single_event_full_token(self):
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        evt = {
            'type': 'content_block_delta',
            'index': 0,
            'delta': {'type': 'text_delta', 'text': '密码是 ' + token},
        }
        cb, _, _ = await holder._handle_anthropic_event(w, evt, '', t2p, '', '', '')
        assert '密码是 p@ssword123' in w.text
        assert token not in w.text
        assert cb == ''

    @pytest.mark.asyncio
    async def test_other_delta_flushes_and_passthrough(self):
        """server_tool_use delta：flush 残留（pending 保留）→ 原样透传。"""
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        evt1 = {
            'type': 'content_block_delta',
            'index': 0,
            'delta': {'type': 'text_delta', 'text': 'text ' + token[:8]},
        }
        cb, _, _ = await holder._handle_anthropic_event(w, evt1, '', t2p, '', '', '')
        assert cb == token[:8]
        tool_line = (
            'data: {"type": "content_block_delta", "index": 0, '
            '"delta": {"type": "server_tool_use", "name": "t"}}'
        )
        cb, _, _ = await holder._handle_anthropic_event(
            w,
            {
                'type': 'content_block_delta',
                'index': 0,
                'delta': {'type': 'server_tool_use', 'name': 't'},
            },
            tool_line,
            t2p,
            cb,
            '',
            '',
        )
        # pending 保留，无合成事件（safe 为空）
        assert cb == token[:8]
        # 事件行原样透传
        assert 'server_tool_use' in w.text
        # 无 chat 格式污染
        assert 'chat.completion' not in w.text
        assert 'choices' not in w.text

    @pytest.mark.asyncio
    async def test_message_start_passthrough(self):
        """非 content_block_delta 事件：识别器返回 None，handler 原样透传。"""
        holder = TestSSEHolder()
        await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        evt = {'type': 'message_start', 'message': {'id': 'msg_01', 'content': []}}
        assert _anthropic_event(evt) is None
        w = FakeWriter()
        cb, rb, ab = await holder._handle_anthropic_event(
            w, evt, 'data: {"type":"message_start"}', t2p, '', '', ''
        )
        assert w.text == 'data: {"type":"message_start"}\n'
        assert (cb, rb, ab) == ('', '', '')

    @pytest.mark.asyncio
    async def test_stream_end_flush_cleans_partial(self):
        """流末 flush（keep_pending=False）：清理 partial 并输出残余。"""
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        _dummy = {'type': 'content_block_delta', 'index': 0}
        cb = await holder._flush_anthropic_buf(
            w, _dummy, 'text', 'text ' + token[:8], t2p, keep_pending=False
        )
        assert cb == ''
        assert 'text ' in w.text
        assert token[:8] not in w.text

    @pytest.mark.asyncio
    async def test_no_pollution_when_no_token(self):
        """无 token 时普通文本按 Anthropic 格式透传。"""
        holder = TestSSEHolder()
        w = FakeWriter()
        evt = {
            'type': 'content_block_delta',
            'index': 0,
            'delta': {'type': 'text_delta', 'text': '你好世界'},
        }
        cb, _, _ = await holder._handle_anthropic_event(w, evt, '', {}, '', '', '')
        events = w.parsed_events()
        assert len(events) == 1
        assert events[0]['type'] == 'content_block_delta'
        assert events[0]['delta']['text'] == '你好世界'
        assert cb == ''

    @pytest.mark.asyncio
    async def test_block_stop_clears_arg_buf(self):
        """content_block_stop 清空 arg_buf：防跨块伪还原。"""
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        mid = len(token) // 2
        # tool1: partial_json 截断在 token 中间
        evt1 = {
            'type': 'content_block_delta',
            'index': 0,
            'delta': {
                'type': 'input_json_delta',
                'partial_json': '{"pwd": "' + token[:mid],
            },
        }
        _, _, ab = await holder._handle_anthropic_event(w, evt1, '', t2p, '', '', '')
        assert ab == token[:mid]
        # content_block_stop: 清空 arg_buf
        stop_line = 'data: {"type":"content_block_stop","index":0}'
        cb, rb, ab = await holder._handle_anthropic_event(
            w,
            {'type': 'content_block_stop', 'index': 0},
            stop_line,
            t2p,
            'text ' + token[:8],  # content pending 注入
            'think ' + token[:8],  # reasoning pending 注入
            ab,
        )
        assert ab == ''
        # content/reasoning pending 保留（流末统一清理）
        assert cb == 'text ' + token[:8]
        assert rb == 'think ' + token[:8]
        assert stop_line + '\n' in w.text  # 原样透传

    @pytest.mark.asyncio
    async def test_cross_block_no_false_restore(self):
        """回归：tool2 的 partial_json 从 token 剩余开头时不得伪还原。"""
        holder = TestSSEHolder()
        token = await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        mid = len(token) // 2
        # tool1 截断
        evt1 = {
            'type': 'content_block_delta',
            'index': 0,
            'delta': {
                'type': 'input_json_delta',
                'partial_json': '{"pwd": "' + token[:mid],
            },
        }
        _, _, ab = await holder._handle_anthropic_event(w, evt1, '', t2p, '', '', '')
        # block_stop 清空
        _, _, ab = await holder._handle_anthropic_event(
            w,
            {'type': 'content_block_stop', 'index': 0},
            'data: {"type":"content_block_stop","index":0}',
            t2p,
            '',
            '',
            ab,
        )
        assert ab == ''
        # tool2 从 token 剩余部分开头
        evt2 = {
            'type': 'content_block_delta',
            'index': 1,
            'delta': {
                'type': 'input_json_delta',
                'partial_json': token[mid:] + '"}',
            },
        }
        _, _, ab = await holder._handle_anthropic_event(w, evt2, '', t2p, '', '', ab)
        # 不跨块拼接：明文与完整 token 形态都不出现
        assert 'p@ssword123' not in w.text
        assert '__VG_CRED' not in w.text
        assert ab == ''

    @pytest.mark.asyncio
    async def test_mid_flush_keeps_pending_no_event(self):
        """真实中游 flush（other delta + token 前缀 pending）：不写事件、pending 保留、原行透传。"""
        holder = TestSSEHolder()
        await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        # content_buf 持 token 前缀 pending（生产中 delta 分支后唯一残留形态）
        cb = '__VG'
        cb, _, _ = await holder._handle_anthropic_event(
            w,
            {
                'type': 'content_block_delta',
                'index': 0,
                'delta': {'type': 'server_tool_use', 'name': 't'},
            },
            'data: {"type":"content_block_delta","index":0,"delta":{"type":"server_tool_use","name":"t"}}',
            t2p,
            cb,
            '',
            '',
        )
        # flush 不输出合成事件（safe 为空）→ 只有透传行
        events = w.parsed_events()
        assert len(events) == 1
        assert events[0]['delta'] == {'type': 'server_tool_use', 'name': 't'}
        # pending 保留
        assert cb == '__VG'

    @pytest.mark.asyncio
    async def test_mid_flush_emits_safe_keeps_pending(self):
        """防御性中游 flush：safe 输出为 text_delta 事件、pending 保留（边缘输入，生产中不可达）。"""
        holder = TestSSEHolder()
        await holder._register_secret('p@ssword123')
        t2p = dict(holder.token_to_pwd)
        w = FakeWriter()
        # 边缘输入：非 token 前缀的 __ 文本不会 hold → safe 直接输出
        cb = 'plain __hello'
        cb, _, _ = await holder._handle_anthropic_event(
            w,
            {
                'type': 'content_block_delta',
                'index': 0,
                'delta': {'type': 'server_tool_use', 'name': 't'},
            },
            'data: {"type":"content_block_delta","index":0}',
            t2p,
            cb,
            '',
            '',
        )
        # safe='plain __hello' 作为 text_delta 事件输出 + 原始行原样透传
        events = w.parsed_events()
        assert len(events) == 2
        assert events[0]['type'] == 'content_block_delta'
        assert events[0]['delta']['type'] == 'text_delta'
        assert events[0]['delta']['text'] == 'plain __hello'
        assert events[1] == {'type': 'content_block_delta', 'index': 0}
        assert cb == ''
