"""pii_llm_test.py — PiiMixin + LlmMixin 集成测试（Batch 3）。

覆盖 design D2 硬性要求：
1. 请求侧 PII 脱敏 → 上游收到 __PII_*__ 占位符（凭据 redact 之前）
2. 响应侧「先还原后检测」：模型回显占位符 → 还原为明文，不再二次掩码
3. 模型独立输出同值明文 → 掩码为新占位符（非还原产物，必须掩码）
4. 流式分片：__PII_ token 跨分片不泄漏、safe/hold 分割携带 PII scope
5. 请求结束 scope 清理（不跨请求残留）
"""

import asyncio

import pytest

from _llm import (
    LlmMixin,
    _split_safe_hold,
    _strip_partials,
)
from _pii import PiiMixin
from _token import RequestScopedTokens, TokenMixin


class PiiProxy(TokenMixin, PiiMixin, LlmMixin):
    """组合 PiiMixin 的测试桩（模拟 CredentialProxy 的 mixin 组合）。"""

    __test__ = False

    def __init__(self):
        self._lock = asyncio.Lock()
        self.token_to_pwd = {}
        self._token_seq = 0
        self.pwd_to_token = {}
        self._shared_session = None
        self.proxies = {}
        self._runners = []
        self._init_pii()
        self.pii_enabled = True
        self.pii_response_side = True

    def _filter_hop_headers(self, h):
        return h

    # TokenMixin 需要的最小实现
    def _redact(self, text, snapshot_p2t=None):
        return text

    def _restore(self, text, active_t2p):
        for tok, plain in (active_t2p or {}).items():
            text = text.replace(tok, plain)
        return text


@pytest.fixture
def proxy():
    return PiiProxy()


# ═══════════════════════════════════════════════════════════
# 请求侧：PII 脱敏 → 占位符
# ═══════════════════════════════════════════════════════════


class TestRequestSide:
    @pytest.mark.asyncio
    async def test_request_redact_creates_scope_and_tokens(self, proxy):
        scope = proxy._pii_request_scope()
        body = '我的邮箱是 zhangsan@example.com，电话 13800138000'
        out = await proxy.pii_redact(body)
        # 邮箱 + 电话都被替换
        assert 'zhangsan@example.com' not in out
        assert '13800138000' not in out
        assert '__PII_' in out
        # 请求级映射注册
        assert len(scope.pii_t2p) >= 2
        # 还原验证
        restored = scope.restore(out)
        assert 'zhangsan@example.com' in restored
        assert '13800138000' in restored
        proxy._pii_cleanup()

    @pytest.mark.asyncio
    async def test_request_redact_no_scope_no_tokens(self, proxy):
        """未建 scope 时 pii_redact 直接替换为 [REDACTED:type]（降级路径）。"""
        body = '邮箱 zhangsan@example.com'
        out = await proxy.pii_redact(body)
        assert 'zhangsan@example.com' not in out
        assert '[REDACTED:' in out

    @pytest.mark.asyncio
    async def test_cleanup_resets_scope(self, proxy):
        proxy._pii_request_scope()
        assert proxy._pii_active()
        proxy._pii_cleanup()
        assert not proxy._pii_active()
        assert proxy._pii_scope_or_none() is None


# ═══════════════════════════════════════════════════════════
# 响应侧：先还原后检测（D2 硬性）
# ═══════════════════════════════════════════════════════════


class TestResponseSide:
    @pytest.mark.asyncio
    async def test_restore_echoed_placeholder_then_no_remask(self, proxy):
        """模型回显请求期占位符 → 还原为明文，不二次掩码（D2 硬性）。"""
        scope = proxy._pii_request_scope()
        body = '我的电话是 13800138000'
        await proxy.pii_redact(body)
        token = next(iter(scope.pii_t2p))
        plain = scope.pii_t2p[token]

        # 模型回显占位符
        echo = f'好的，你的电话是 {token}'
        out = await proxy._pii_response_process(echo, {})
        # 还原为明文
        assert plain in out
        assert token not in out
        # 且明文未被二次掩码（还原产物区间跳过）
        assert '__PII_' not in out
        proxy._pii_cleanup()

    @pytest.mark.asyncio
    async def test_model_independent_output_same_plain_is_masked(self, proxy):
        """模型独立输出同值明文（非还原产物）→ 必须掩码（D2 硬性）。"""
        scope = proxy._pii_request_scope()
        body = '我的电话是 13800138000'
        await proxy.pii_redact(body)

        # 模型独立输出同值明文（不是回显占位符）
        out = await proxy._pii_response_process('这是新内容 13800138000', {})
        assert '13800138000' not in out
        assert '__PII_' in out
        # 且注册到响应期映射（不还原）
        assert len(scope.resp_t2p) >= 1
        proxy._pii_cleanup()

    @pytest.mark.asyncio
    async def test_response_scan_disabled_returns_text(self, proxy):
        proxy.pii_response_side = False
        proxy._pii_request_scope()
        body = '电话 13800138000'
        await proxy.pii_redact(body)
        out = await proxy._pii_response_process('新内容 13900139000', {})
        # 响应侧检测关闭 → 明文透传
        assert '13900139000' in out
        proxy._pii_cleanup()

    @pytest.mark.asyncio
    async def test_no_scope_falls_back_to_restore(self, proxy):
        """无 scope 时 _pii_response_process 等价 _restore。"""
        out = await proxy._pii_response_process(
            'abc __VG_CRED_000001__ def',
            {
                '__VG_CRED_000001__': 'secret',
            },
        )
        assert 'secret' in out


# ═══════════════════════════════════════════════════════════
# 流式：_split_safe_hold PII 支持
# ═══════════════════════════════════════════════════════════


class TestSplitSafeHoldPii:
    def test_pii_full_token_hold(self):
        """完整 PII token 但未在映射 → 整体 hold。"""
        scope = RequestScopedTokens()
        # 注册一个 token 让 scope 非空（模拟响应期注册）
        scope.register('13800138000', response_side=True)
        token = next(iter(scope.resp_t2p))
        safe, hold = _split_safe_hold(f'text {token}', {}, scope)
        assert safe == 'text '
        assert hold == token

    def test_pii_partial_prefix_hold(self):
        """__PII_ 前缀（部分）→ hold。"""
        scope = RequestScopedTokens()
        scope.register('13800138000', response_side=True)
        token = next(iter(scope.resp_t2p))
        prefix = token[:9]  # __PII_123_
        _safe, hold = _split_safe_hold(f'text {prefix}', {}, scope)
        assert hold == prefix

    def test_pii_token_stripped_from_safe(self):
        """safe 输出前 PII token 形态剥离（响应期 token 不泄漏）。"""
        scope = RequestScopedTokens()
        scope.register('13800138000', response_side=True)
        token = next(iter(scope.resp_t2p))
        # 完整 token 在 safe 区（非 hold 场景）→ 被 _strip_token_forms 剥离
        safe, _hold = _split_safe_hold(f'hello {token} world', {}, scope)
        assert token not in safe
        assert 'hello' in safe

    def test_safe_output_strips_partial_forms(self):
        """R4 回归：safe 输出统一剥离残缺形态（mid-stream 出口全覆盖）。

        旧实现 `_strip_token_forms` 只剥完整 token；不匹配任何已注册
        前缀的残缺形态（幻觉 `__PII_9_ab` 等）随 safe 输出泄漏。
        Round 17 R4 修复：`_strip_token_forms` 末尾追加 `_strip_partials`，
        所有 safe 输出出口统一获得残缺清理。

        注：`_PII_PARTIAL_TOKEN_RE` 行尾锚定（`$`）——残缺只在
        流分片边界（行尾）出现，行中形态是正常文本不清除。
        """
        scope = RequestScopedTokens()
        scope.register('13800138000', response_side=True)
        # 不匹配任何已注册前缀的幻觉残缺形态（__PII_9_ 不在映射，
        # rand8 段是 hex，且位于行尾=流分片边界）
        safe, hold = _split_safe_hold('text __PII_9_ab', {}, scope)
        # 残缺被剥离，hold 不残留（非前缀匹配）
        assert '__PII_9_ab' not in safe
        assert safe == 'text '
        assert hold == ''
        # 正常文本不受影响
        safe2, _ = _split_safe_hold('hello world', {}, scope)
        assert safe2 == 'hello world'


# ═══════════════════════════════════════════════════════════
# 请求级映射生命周期
# ═══════════════════════════════════════════════════════════


class TestScopeLifecycle:
    @pytest.mark.asyncio
    async def test_scope_isolated_between_requests(self, proxy):
        """请求间 scope 隔离：第一个请求的 token 不残留。"""
        s1 = proxy._pii_request_scope()
        body = '电话 13800138000'
        await proxy.pii_redact(body)
        tok1 = next(iter(s1.pii_t2p))
        proxy._pii_cleanup()

        s2 = proxy._pii_request_scope()
        body2 = '邮箱 zhangsan@example.com'
        await proxy.pii_redact(body2)
        tok2 = next(iter(s2.pii_t2p))
        # 新 token 不与旧 token 相同（seq 独立）
        assert tok1 != tok2
        # 旧 token 在新 scope 中不存在
        assert tok1 not in s2.pii_t2p
        proxy._pii_cleanup()

    @pytest.mark.asyncio
    async def test_restore_only_registered_request_tokens(self, proxy):
        """restore 只还原请求期注册 token，响应期 token 原样保留。"""
        scope = proxy._pii_request_scope()
        # 请求期注册
        await proxy.pii_redact('电话 13800138000')
        req_tok = next(iter(scope.pii_t2p))
        # 响应期注册
        resp_tok = scope.register('zhangsan@example.com', response_side=True)

        out = scope.restore(f'{req_tok} {resp_tok}')
        assert '13800138000' in out
        assert resp_tok in out  # 响应期 token 不还原
        proxy._pii_cleanup()


# ═══════════════════════════════════════════════════════════
# 流式分片语义（design D2 明文分片累积 / 候选值感知切分）
# ═══════════════════════════════════════════════════════════


class TestStreamingChunking:
    """模拟 SSE 流式 chunk 的「累积 → 还原 → safe/hold 分割 → 输出」循环。"""

    def _process_chunk(
        self,
        proxy,
        acc: str,
        new_chunk: str,
    ) -> tuple[str, str]:
        """返回 (更新后累积缓冲, 本次输出 safe)。

        同步简化版：真实路径是 async _pii_response_process + split。
        """
        combined = acc + new_chunk
        return combined, ''

    @pytest.mark.asyncio
    async def test_pii_placeholder_split_across_chunks_no_leak(self, proxy):
        """请求期占位符跨 chunk 切断 → 累积还原，客户端看不到 token 中间态。"""
        scope = proxy._pii_request_scope()
        body = '我的电话是 13800138000'
        await proxy.pii_redact(body)
        token = next(iter(scope.pii_t2p))
        plain = scope.pii_t2p[token]

        # 模拟模型回显占位符，分 3 chunk 到达
        chunk1, chunk2, chunk3 = token[:5], token[5:12], token[12:]
        acc = ''
        out_parts = []
        for chunk in (chunk1, chunk2, chunk3):
            acc += chunk
            processed = await proxy._pii_response_process(acc, {})
            safe, pending = _split_safe_hold(processed, {}, proxy._pii_scope_or_none())
            if safe:
                out_parts.append(safe)
            acc = pending
        # 最终还原为明文（D2：回显还原，不掩码）
        assert plain in ''.join(out_parts)
        assert '__PII_' not in ''.join(out_parts)
        proxy._pii_cleanup()

    @pytest.mark.asyncio
    async def test_ipv4_partial_forms_no_false_hit(self, proxy):
        """候选值感知切分：8. / 8.8. / 8.8.8. 部分 IP 形态不触发检测。

        只有拼回完整 IP 8.8.8.8 才命中。
        """
        _scope = proxy._pii_request_scope()
        # 部分形态 → 无命中
        for partial in ('8.', '8.8.', '8.8.8.'):
            hits = await proxy.pii_scan(f'连接 {partial}')
            assert hits == []
        # 完整 IP → 命中
        hits = await proxy.pii_scan('连接 8.8.8.8')
        assert any(t == 'ipv4' for t, _ in hits)
        proxy._pii_cleanup()

    @pytest.mark.asyncio
    async def test_ipv6_partial_form_fe80(self, proxy):
        """IPv6 部分形态 fe80:: 不触发检测（保留地址 + 不完整）。"""
        _scope = proxy._pii_request_scope()
        hits = await proxy.pii_scan('链路本地 fe80::a1 地址')
        # fe80:: 是保留地址豁免（即使完整 fe80::a1 也不命中）
        assert hits == []
        proxy._pii_cleanup()

    @pytest.mark.asyncio
    async def test_long_api_key_across_chunks_no_plain_leak(self, proxy):
        """超长明文 API key 跨 3 chunk 切断 → 不泄漏明文片段。"""
        _scope = proxy._pii_request_scope()
        key = 'sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmn'
        # 模拟模型独立输出 key，分 3 chunk
        n = len(key)
        cuts = (n // 3, 2 * n // 3)
        chunks = (key[: cuts[0]], key[cuts[0] : cuts[1]], key[cuts[1] :])
        acc = ''
        out_parts = []
        for chunk in chunks:
            acc += chunk
            processed = await proxy._pii_response_process(acc, {})
            safe, pending = _split_safe_hold(processed, {}, proxy._pii_scope_or_none())
            if safe:
                out_parts.append(safe)
            acc = pending
        combined = ''.join(out_parts) + acc
        # 完整 key 或 key 明文片段都不得泄漏（响应侧掩码）
        assert key not in combined
        assert 'sk-ant-api03-' not in combined
        proxy._pii_cleanup()

    @pytest.mark.asyncio
    async def test_trailing_punctuation_partial_token(self, proxy):
        """残缺 token 尾部标点形态 __PII_0001_ab, 不泄漏结构。"""
        scope = proxy._pii_request_scope()
        token = scope.register('13800138000')  # 请求期注册
        # 完整 token + 逗号 → 还原为明文 + 逗号
        out = scope.restore(f'{token},')
        assert '13800138000,' in out
        proxy._pii_cleanup()


# ═══════════════════════════════════════════════════════════
# 混合凭据 + PII 重叠值策略
# ═══════════════════════════════════════════════════════════


class TestOverlapCredential:
    @pytest.mark.asyncio
    async def test_credential_overlap_pii_skipped(self, proxy):
        """同一明文既在凭据注册表又在 PII 模式 → PII 跳过（凭据优先）。"""
        _scope = proxy._pii_request_scope()
        # 模拟凭据注册表已注册某明文
        proxy.pwd_to_token = {'supersecret@example.com': '__VG_CRED_000001__'}
        body = '密码是 supersecret@example.com'
        out = await proxy.pii_redact(body)
        # PII 检测应跳过凭据命中的明文 → 不产生 PII token 替换
        assert 'supersecret@example.com' in out
        assert '__PII_' not in out
        proxy._pii_cleanup()

    @pytest.mark.asyncio
    async def test_mixed_request_two_token_families_no_cross(self, proxy):
        """混合请求：凭据 token + PII token 各还原各的，互不串扰。"""
        scope = proxy._pii_request_scope()
        await proxy.pii_redact('电话 13800138000')
        pii_tok = next(iter(scope.pii_t2p))
        cred_tok = '__VG_CRED_000002__'
        cred_plain = 'mysql-password-123'

        active = {cred_tok: cred_plain}
        text = f'电话 {pii_tok} 密码 {cred_tok}'
        out = await proxy._pii_response_process(text, active)
        assert '13800138000' in out  # PII 还原
        assert 'mysql-password-123' in out  # 凭据还原
        assert pii_tok not in out
        assert cred_tok not in out
        proxy._pii_cleanup()


# ═══════════════════════════════════════════════════════════
# 增量扫描性能锚点（design D2：每 chunk 只扫新增 + 尾部持有）
# ═══════════════════════════════════════════════════════════


class TestIncrementalScan:
    @pytest.mark.asyncio
    async def test_incremental_scan_faster_than_full_rescan(self, proxy):
        """200 chunk 流增量扫描耗时 < 全量重扫 1/10（性能断言）。

        增量模式：safe 已 flush，每次只扫「尾部持有(≤32B) + 新 chunk」。
        全量模式：每次扫全部累积文本（O(n²)）。
        """
        chunks = [f'普通文本内容第{i}段，没有敏感信息 ' + 'x' * 40 for i in range(200)]
        detector = proxy._pii_detector
        scope = proxy._pii_request_scope()
        detector.request_tokens = scope

        # 增量模式
        t0 = asyncio.get_event_loop().time()
        acc = ''
        for ch in chunks:
            acc = acc[-32:] + ch
            await detector.scan(acc)
        t_inc = asyncio.get_event_loop().time() - t0

        # 全量重扫模式
        t0 = asyncio.get_event_loop().time()
        acc = ''
        for ch in chunks:
            acc += ch
            await detector.scan(acc)
        t_full = asyncio.get_event_loop().time() - t0

        assert t_inc < t_full / 10, (
            f'incremental {t_inc * 1000:.1f}ms not < 1/10 of full {t_full * 1000:.1f}ms'
        )
        proxy._pii_cleanup()


# ═══════════════════════════════════════════════════════════
# F-02 回归：PII 残缺 token 流式清理生产接线
# ═══════════════════════════════════════════════════════════


def test_strip_partials_removes_pii_partial_forms():
    """生产清理入口 _strip_partials 必须剥离 __PII_ 残缺前缀。

    回归 F-02：此前所有 flush 路径只用凭据版 _PARTIAL_TOKEN_RE，
    `__PII_1_ab` 等残缺随 safe 输出泄漏。_strip_partials 统一两套正则。
    """
    cases = [
        ('text __PII', 'text '),
        ('text __PII_', 'text '),
        ('text __PII_0001', 'text '),
        ('text __PII_0001_', 'text '),
        ('text __PII_0001_ab', 'text '),
        ('text __PII_1_ab12cd34__', 'text '),  # 幻觉完整 token 也剥离
    ]
    for inp, expected in cases:
        assert _strip_partials(inp) == expected, f'{inp!r} -> {_strip_partials(inp)!r}'


def test_strip_partials_keeps_cred_partials_and_plain():
    """凭据残缺同样清理；普通文本/带标点完整 token 不受影响。"""
    # 凭据残缺
    assert _strip_partials('x __VG_CRED_0001') == 'x '
    # 普通文本（__ 开头但不是 token 前缀）
    assert _strip_partials('__Python__ 和 __PIIX') == '__Python__ 和 __PIIX'
    # 带尾部标点的完整 token（流末清理只剥离真正残缺前缀）
    assert _strip_partials('__PII_0001_ab,') == '__PII_0001_ab,'
    # 空输入
    assert _strip_partials('') == ''
