"""pii_token_test.py — RequestScopedTokens 请求级映射单元测试。

覆盖 (tasks 1.2 / 1.3):
- 请求级映射生命周期（创建/还原/清理）
- 与全局凭据映射互不串扰
- token 前缀不冲突
- 越界/格式不符 token 原样保留并记审计事件（聚合限流）
- PII 正则等价物（残缺前缀清理 / 完整幻觉 token 剥离）

"""

import re

import pytest

from _token import (
    _PII_PARTIAL_TOKEN_RE,
    FULL_PII_TOKEN_RE,
    PII_TOKEN_PREFIX,
    PII_TOKEN_RE,
    PII_TOKEN_STR_RE,
    RequestScopedTokens,
    _make_pii_token,
)

# ═══════════════════════════════════════════════════════════
# 基础格式
# ═══════════════════════════════════════════════════════════


def test_pii_token_format():
    tok = _make_pii_token(1, 'ab12cd34')
    assert tok == '__PII_1_ab12cd34__'
    assert PII_TOKEN_STR_RE.fullmatch(tok)
    assert PII_TOKEN_RE.fullmatch(tok.encode())


@pytest.mark.asyncio
async def test_pii_token_rand8_is_hex():
    t = RequestScopedTokens()
    tok = await t.register('13812345678')
    m = re.fullmatch(r'__PII_\d+_([0-9a-f]{8})__', tok)
    assert m, f'token 格式不符: {tok}'


def test_pii_token_prefix_distinct_from_cred():
    """PII token 前缀与凭据前缀不冲突。"""
    assert PII_TOKEN_PREFIX != '__VG_CRED_'
    assert not PII_TOKEN_STR_RE.fullmatch('__VG_CRED_000001__')


# ═══════════════════════════════════════════════════════════
# 注册 / 去重 / 序列
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_register_creates_mapping():
    t = RequestScopedTokens()
    tok = await t.register('13812345678')
    assert tok in t.pii_t2p
    assert t.pii_p2t['13812345678'] == tok


@pytest.mark.asyncio
async def test_register_duplicate_reuses_token():
    t = RequestScopedTokens()
    tok1 = await t.register('13812345678')
    tok2 = await t.register('13812345678')
    assert tok1 == tok2
    assert len(t.pii_p2t) == 1


@pytest.mark.asyncio
async def test_register_sequential_distinct():
    t = RequestScopedTokens()
    tok1 = await t.register('13812345678')
    tok2 = await t.register('zhangsan@example.com')
    assert tok1 != tok2
    assert t._seq == 2


@pytest.mark.asyncio
async def test_register_empty():
    t = RequestScopedTokens()
    assert await t.register('') == ''
    assert len(t.pii_p2t) == 0


@pytest.mark.asyncio
async def test_register_rejects_token_shape_value():
    """值注册校验：拒绝 token 形态值及包含 token 形态子串的值。"""
    t = RequestScopedTokens()
    with pytest.raises(ValueError):
        await t.register('__PII_1_ab12cd34__')
    with pytest.raises(ValueError):
        await t.register('__VG_CRED_000001__')
    with pytest.raises(ValueError):
        await t.register('prefix __PII_1_ab12cd34__ suffix')  # 包含子串即拒


# ═══════════════════════════════════════════════════════════
# 还原（请求期优先、响应期不还原、格式不符审计限流）
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_restore_request_scoped_token():
    t = RequestScopedTokens()
    tok = await t.register('13812345678')
    assert t.restore(f'号码 {tok} 结束') == '号码 13812345678 结束'


@pytest.mark.asyncio
async def test_restore_response_side_token_kept():
    """响应期注册 token 形态匹配也原样保留（不还原为明文）。"""
    t = RequestScopedTokens()
    resp_tok = await t.register('13900001111', response_side=True)
    assert resp_tok in t.resp_t2p
    assert resp_tok not in t.pii_t2p
    assert t.restore(f'输出 {resp_tok}') == f'输出 {resp_tok}'


def test_restore_malformed_kept_and_audited():
    """越界/格式不符 token 原样保留并记审计事件（聚合限流）。"""
    events = []
    t = RequestScopedTokens(audit_cb=lambda ev, ctx: events.append((ev, ctx)))
    text = '__PII_999_ab12cd34__ __PII_999_ab12cd34__ __PII_1_zz__'
    out = t.restore(text)
    assert out == text  # 原样保留
    # 聚合限流：同类只记一次
    assert len(events) == 2  # unregistered(999) + malformed(zz)


def test_restore_malformed_counter():
    t = RequestScopedTokens(audit_cb=lambda ev, ctx: None)
    t.restore('__PII_1_xx__ __PII_1_xx__')
    assert t._malformed_counts['malformed'] == 2


def test_restore_empty_or_no_mapping():
    t = RequestScopedTokens()
    assert t.restore('') == ''
    assert t.restore('__PII_1_ab12cd34__') == '__PII_1_ab12cd34__'  # 无映射不还原


def test_restore_never_touches_global():
    """PII 还原路径不触达全局凭据映射（代码级隔离断言）。"""
    t = RequestScopedTokens()
    # 凭据 token 形态在 PII restore 中必须原样保留（没有全局兜底）
    assert t.restore('__VG_CRED_000001__') == '__VG_CRED_000001__'


# ═══════════════════════════════════════════════════════════
# 生命周期：clear
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_clear_removes_all():
    t = RequestScopedTokens()
    await t.register('13812345678')
    await t.register('13900001111', response_side=True)
    t.restore('__PII_9_bad__')
    t.clear()
    assert not t.pii_p2t
    assert not t.pii_t2p
    assert not t.resp_p2t
    assert not t.resp_t2p
    assert not t._malformed_counts


@pytest.mark.asyncio
async def test_clear_then_restore_noop():
    t = RequestScopedTokens()
    tok = await t.register('13812345678')
    t.clear()
    assert t.restore(tok) == tok  # 清理后无法还原


# ═══════════════════════════════════════════════════════════
# PII 正则等价物（task 1.3）
# ═══════════════════════════════════════════════════════════


def test_full_pii_token_re_line_end():
    assert FULL_PII_TOKEN_RE.search('abc __PII_1_ab12cd34__')
    assert FULL_PII_TOKEN_RE.search('__PII_123_ab12cd34__')
    assert not FULL_PII_TOKEN_RE.search('__PII_1_ab12cd34__ rest')  # 非行尾
    assert not FULL_PII_TOKEN_RE.search('__VG_CRED_000001__')


def test_pii_partial_token_re_prefixes():
    """残缺前缀各阶段形态均命中（仿 _PARTIAL_TOKEN_RE 语义）。

    对齐原版：从 token 前缀确定起始（__PII）起匹配，__P/__PI 太泛
    （会误伤 __Python 之类普通文本），与凭据版 __VG_C 起一致。
    """
    cases = [
        '__PII',
        '__PII_',
        '__PII_0',
        '__PII_0001',
        '__PII_0001_',
        '__PII_0001_ab',
        '__PII_0001_ab12',
    ]
    for c in cases:
        assert _PII_PARTIAL_TOKEN_RE.search(c), f'{c} 应命中残缺正则'
    # 完整 token 可被匹配（对齐原版语义：完整 token 已被 _restore 还原为明文，
    # 到此处的完整 token 必是模型幻觉，剥离正确）
    assert _PII_PARTIAL_TOKEN_RE.search('__PII_1_ab12cd34__')
    # 凭据 token 形态不受影响
    assert not _PII_PARTIAL_TOKEN_RE.search('__VG_CRED_000001__')
    # 普通文本不误伤
    assert not _PII_PARTIAL_TOKEN_RE.search('__Python__')


def test_pii_partial_re_with_trailing_punct():
    """尾部标点形态：__PII_0001_ab, 的 suffix 含逗号不再是完整 token 前缀。"""
    # 残缺后缀剥离发生在 strip 标点之后；此处验证正则不会把带标点的
    # 完整 token 误判为残缺（流末清理只剥离真正的残缺前缀）
    assert _PII_PARTIAL_TOKEN_RE.search('__PII_0001_')
    assert not _PII_PARTIAL_TOKEN_RE.search('__PII_0001_ab,')


def test_pii_regex_independent_of_cred_regex():
    """PII 正则等价物独立常量，不 import 凭据正则（代码级断言）。"""
    import _token

    assert _token._PII_PARTIAL_TOKEN_RE is not _token.TOKEN_RE
    assert _token.PII_TOKEN_STR_RE.pattern != _token.TOKEN_STR_RE.pattern


# ═══════════════════════════════════════════════════════════
# F-03 回归：PiiMixin._pii_request_scope 必须接线 audit_cb
# ═══════════════════════════════════════════════════════════


class _AuditHost:
    """模拟组合 AuditMixin 的宿主（提供 audit_log_path + _audit_log_ring）。"""

    __test__ = False

    def __init__(self):
        self.audit_log_path = ''
        self._audit_log_ring: list[dict] = []
        self._audit_log_ring_max = 100
        self.warnings: list[str] = []

    def _pii_scope_or_none(self):
        return getattr(self, '_pii_scope', None)


def test_pii_request_scope_wires_audit_cb():
    """_pii_request_scope 创建的 scope 必须带 audit_cb（接线断言）。"""
    from _pii import PiiMixin

    class Host(PiiMixin):
        def __init__(self):
            self._pii_detector = None
            self.pii_enabled = True
            self._pii_scope = None

    h = Host()
    # 手动初始化 detector（简化：复用 PiiMixin._init_pii 逻辑需要完整依赖）
    from _pii import PiiDetector

    h._pii_detector = PiiDetector()
    scope = h._pii_request_scope()
    # 核心断言：audit_cb 已接线（F-03 修复前为 None）
    assert scope._audit_cb is not None
    # 触发格式不符 token 还原 → 审计事件真实回调（聚合限流：同类只记一次）
    scope.restore('__PII_1_zz__')
    scope.restore('__PII_1_zz__')  # 重复 → 不重复回调
    assert scope._malformed_counts['malformed'] == 2
    assert scope._audit_cb is not None
    # 宿主无审计路径（audit_log_path=''）→ 不抛异常（logger.warning 路径）
    scope.clear()


def test_pii_audit_cb_writes_ring_when_host_has_ring():
    """宿主有 _audit_log_ring → 审计事件进入内存环形（可查询）。"""
    from _pii import PiiDetector, PiiMixin

    class Host(PiiMixin):
        def __init__(self):
            self._pii_detector = None
            self.pii_enabled = True
            self._pii_scope = None

    h = Host()
    h._pii_detector = PiiDetector()
    # 给宿主挂审计环形（模拟 AuditMixin 组合）
    h.audit_log_path = ''
    h._audit_log_ring = []
    h._audit_log_ring_max = 100
    scope = h._pii_request_scope()
    scope.restore('__PII_2_bad__')
    assert len(h._audit_log_ring) == 1
    rec = h._audit_log_ring[0]
    assert rec['tool'] == 'pii_restore'
    assert rec['verdict'] == 'malformed'
    assert rec['rule'] == 'malformed'


def test_pii_audit_cb_note_no_raw_token():
    """R3 回归：审计 note 不得包含原始 token（防明文敏感值泄漏）。

    格式不符 token 可含明文敏感值（如 `__PII_999_myPassword__`），
    原样落盘即泄漏（Round 17 R3）。note 只记类别 + 长度特征。
    """
    from _pii import PiiDetector, PiiMixin

    class Host(PiiMixin):
        def __init__(self):
            self._pii_detector = None
            self.pii_enabled = True
            self._pii_scope = None

    h = Host()
    h._pii_detector = PiiDetector()
    h.audit_log_path = ''
    h._audit_log_ring = []
    h._audit_log_ring_max = 100
    scope = h._pii_request_scope()
    # 明文密码形态 token（宽松匹配，含敏感串）
    scope.restore('__PII_999_myPassword__')
    assert len(h._audit_log_ring) == 1
    rec = h._audit_log_ring[0]
    note = rec['note']
    # 原始 token / 敏感串不得出现在审计记录任何字段
    assert '__PII_999_myPassword__' not in note
    assert 'myPassword' not in note
    assert 'token_len=' in note
    assert 'category=malformed' in note


def test_pii_audit_cb_executor_offloads_io():
    """R8 回归：有运行循环时文件写走 run_in_executor（不阻塞事件循环）。

    Round 17 R8：同步回调不能 await，但必须把 _append_audit_log 移出
    事件循环线程（与 _audit_log_event 对齐，防 10MB 轮转阻塞还原热路径）。
    """
    import asyncio
    import tempfile
    from pathlib import Path

    from _pii import PiiDetector, PiiMixin

    class Host(PiiMixin):
        def __init__(self):
            self._pii_detector = None
            self.pii_enabled = True
            self._pii_scope = None

    async def _run():
        h = Host()
        h._pii_detector = PiiDetector()
        with tempfile.TemporaryDirectory() as d:
            log_path = str(Path(d) / 'audit.log')
            h.audit_log_path = log_path
            h._audit_log_ring = []
            h._audit_log_ring_max = 100
            scope = h._pii_request_scope()
            scope.restore('__PII_3_zz__')
            # 等 executor 完成写盘（fire-and-forget → 轮询文件出现）
            for _ in range(100):
                if Path(log_path).exists():
                    break
                await asyncio.sleep(0.01)
            assert Path(log_path).exists(), 'run_in_executor 写盘未发生'
            content = Path(log_path).read_text(encoding='utf-8')
            assert 'pii_restore' in content
            assert '__PII_3_zz__' not in content  # note 无原始 token

    asyncio.run(_run())


@pytest.mark.asyncio
async def test_global_lru_eviction_true_lru():
    """PII_MAX_ENTRIES=1000 真 LRU：超限淘汰最久未用，命中 move_to_end 提升。"""
    from _token import GlobalPiiTokens, PII_MAX_ENTRIES

    g = GlobalPiiTokens()
    # 填满 1000
    for i in range(PII_MAX_ENTRIES):
        await g.register(f'1380000{i:04d}')
    assert len(g.pii_p2t) == PII_MAX_ENTRIES
    first_val = '13800000000'
    first_tok = g.pii_p2t[first_val]
    # 命中 first_val，应 move_to_end 提升为最新
    tok_again = await g.register(first_val)
    assert tok_again == first_tok
    assert list(g.pii_p2t.keys())[-1] == first_val
    # 再注册新值，应淘汰最旧（非 first_val，而是第二旧）
    # 此时最旧应为 13800000001
    second_val = '13800000001'
    assert second_val in g.pii_p2t
    await g.register('13999999999')
    assert len(g.pii_p2t) == PII_MAX_ENTRIES
    assert second_val not in g.pii_p2t, (
        'LRU 应淘汰最久未用的 second_val，而非 first_val'
    )
    assert first_val in g.pii_p2t, '命中的 first_val 已提升，不应被淘汰'
    assert '13999999999' in g.pii_p2t


@pytest.mark.asyncio
async def test_global_lru_1000_distinct_from_credential_5000():
    """PII 1000 与凭据 5000 上限区分。"""
    from _token import PII_MAX_ENTRIES
    from _token import MAX_TOKEN_ENTRIES

    assert PII_MAX_ENTRIES == 1000
    assert MAX_TOKEN_ENTRIES == 5000
    assert PII_MAX_ENTRIES != MAX_TOKEN_ENTRIES
