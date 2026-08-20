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


def test_pii_token_rand8_is_hex():
    t = RequestScopedTokens()
    tok = t.register('13812345678')
    m = re.fullmatch(r'__PII_\d+_([0-9a-f]{8})__', tok)
    assert m, f'token 格式不符: {tok}'


def test_pii_token_prefix_distinct_from_cred():
    """PII token 前缀与凭据前缀不冲突。"""
    assert PII_TOKEN_PREFIX != '__VG_CRED_'
    assert not PII_TOKEN_STR_RE.fullmatch('__VG_CRED_000001__')


# ═══════════════════════════════════════════════════════════
# 注册 / 去重 / 序列
# ═══════════════════════════════════════════════════════════


def test_register_creates_mapping():
    t = RequestScopedTokens()
    tok = t.register('13812345678')
    assert tok in t.pii_t2p
    assert t.pii_p2t['13812345678'] == tok


def test_register_duplicate_reuses_token():
    t = RequestScopedTokens()
    tok1 = t.register('13812345678')
    tok2 = t.register('13812345678')
    assert tok1 == tok2
    assert len(t.pii_p2t) == 1


def test_register_sequential_distinct():
    t = RequestScopedTokens()
    tok1 = t.register('13812345678')
    tok2 = t.register('zhangsan@example.com')
    assert tok1 != tok2
    assert t._seq == 2


def test_register_empty():
    t = RequestScopedTokens()
    assert t.register('') == ''
    assert len(t.pii_p2t) == 0


def test_register_rejects_token_shape_value():
    """值注册校验：拒绝 token 形态值及包含 token 形态子串的值。"""
    t = RequestScopedTokens()
    with pytest.raises(ValueError):
        t.register('__PII_1_ab12cd34__')
    with pytest.raises(ValueError):
        t.register('__VG_CRED_000001__')
    with pytest.raises(ValueError):
        t.register('prefix __PII_1_ab12cd34__ suffix')  # 包含子串即拒


# ═══════════════════════════════════════════════════════════
# 还原（请求期优先、响应期不还原、格式不符审计限流）
# ═══════════════════════════════════════════════════════════


def test_restore_request_scoped_token():
    t = RequestScopedTokens()
    tok = t.register('13812345678')
    assert t.restore(f'号码 {tok} 结束') == '号码 13812345678 结束'


def test_restore_response_side_token_kept():
    """响应期注册 token 形态匹配也原样保留（不还原为明文）。"""
    t = RequestScopedTokens()
    resp_tok = t.register('13900001111', response_side=True)
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


def test_clear_removes_all():
    t = RequestScopedTokens()
    t.register('13812345678')
    t.register('13900001111', response_side=True)
    t.restore('__PII_9_bad__')
    t.clear()
    assert not t.pii_p2t
    assert not t.pii_t2p
    assert not t.resp_p2t
    assert not t.resp_t2p
    assert not t._malformed_counts


def test_clear_then_restore_noop():
    t = RequestScopedTokens()
    tok = t.register('13812345678')
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
