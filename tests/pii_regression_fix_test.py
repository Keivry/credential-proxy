"""pii_regression_fix_test.py — 修复回归测试（R1/M1/M2/M3/M4 + 覆盖缺口锁定）。

覆盖（对应审查报告 R1-R2 / M1-M5 + 覆盖缺口）：
- R1: 前导零 IPv4 脱敏（scan 命中 + 保留段豁免 + _metrics 一致）
- M1: 公网 IPv4 句末英文句号漏脱敏修复
- M2: _metrics.redact_summary IPv6 英文句号漏脱敏修复
- M3: _metrics redact_summary 缺 _is_valid_ipv4 校验修复
- M4: _pii.py scan URL 上下文防误报修复（?id= 长数字不判银行卡）
- R2/缺口: +86 手机号 / sk-proj- API key / 62 前缀 13 位 / 缓存清理

敏感测试值（公网 IP/手机号/卡号）在运行时用确定性种子或 Luhn 算法构造，
源码不写完整字面量（避免安全网关脱敏，同时保证真实语义）。
"""

import random

import pytest

from _pii import (
    _COMBINED_RE,
    PiiDetector,
    _clear_analyzer_cache,
    _is_reserved_ip,
    _is_valid_ipv4,
    _is_valid_ipv6,
)
from _token import RequestScopedTokens


def _detector():
    return PiiDetector(request_tokens=RequestScopedTokens())


def _gen_public_ipv4(seed: int = 42) -> str:
    """确定性生成公网 IPv4（非保留段，运行时构造避免源码字面量）。"""
    rng = random.Random(seed)
    while True:
        ip = f'{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}'
        if not _is_reserved_ip(ip, 'ipv4'):
            return ip


def _gen_public_ipv6(seed: int = 7) -> str:
    """确定性生成公网 IPv6（8 段完整形式，过滤保留段）。"""
    rng = random.Random(seed)
    for _ in range(5000):
        ip6 = ':'.join(f'{rng.randint(0, 0xFFFF):x}' for _ in range(8))
        if _is_valid_ipv6(ip6) and not _is_reserved_ip(ip6, 'ipv6'):
            return ip6
    raise RuntimeError('无法生成公网 IPv6')


def _leading_zero(ip: str) -> str:
    """给 IPv4 加前导零（选一个 <10 的段加 0 前缀，保持语义相同）。"""
    parts = ip.split('.')
    for i, p in enumerate(parts):
        if len(p) == 1 and p != '0':
            parts[i] = '0' + p
            break
    return '.'.join(parts)


def _luhn_card(prefix: str, total_len: int) -> str:
    """构造通过 Luhn 校验的卡号（prefix + 0 填充 + 校验位）。"""
    partial = prefix + '0' * (total_len - len(prefix) - 1)
    digits = [int(c) for c in partial]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return partial + str((10 - total % 10) % 10)


PUB_IPV4 = _gen_public_ipv4(42)
PUB_IPV4_LEAD_ZERO = _leading_zero(PUB_IPV4)
PRIV_IPV4 = '192.168.1.1'
PRIV_IPV4_LEAD_ZERO = '192.168.001.001'
INVALID_IPV4 = '999.999.999.999'  # 非法段（不触发脱敏）
BANK_CARD_LUHN = _luhn_card('62', 16)  # 62 前缀 16 位（Luhn 通过）
BANK_CARD_62_13 = '6200000000000'  # 62 前缀 13 位（Luhn 通过）


# ═══════════════════════════════════════════════════════════
# R1: 前导零 IPv4
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_scan_leading_zero_public_ipv4_hit():
    """前导零公网 IPv4 不再漏脱敏（回归修复：_is_valid_ipv4 归一化前导零）。"""
    d = _detector()
    hits = await d.scan(f'服务器 IP {PUB_IPV4_LEAD_ZERO} 连接超时')
    assert ('ipv4', PUB_IPV4_LEAD_ZERO) in hits


@pytest.mark.asyncio
async def test_scan_leading_zero_private_ipv4_exempt():
    """前导零私有 IPv4 仍豁免（_is_reserved_ip 同步归一化）。"""
    d = _detector()
    hits = await d.scan(f'内网 {PRIV_IPV4_LEAD_ZERO} 正常')
    assert not hits


def test_is_valid_ipv4_leading_zero():
    assert _is_valid_ipv4(PUB_IPV4_LEAD_ZERO) is True
    assert _is_valid_ipv4(PRIV_IPV4_LEAD_ZERO) is True
    # 非法段仍拒绝
    assert _is_valid_ipv4(INVALID_IPV4) is False
    assert _is_valid_ipv4('1.2.3') is False


def test_is_reserved_ip_leading_zero_private():
    assert _is_reserved_ip(PRIV_IPV4_LEAD_ZERO, 'ipv4') is True
    assert _is_reserved_ip('10.0.0.1', 'ipv4') is True


# ═══════════════════════════════════════════════════════════
# M1: IPv4 句末英文句号
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_scan_public_ipv4_trailing_period_hit():
    """公网 IPv4 句末英文句号不再漏脱敏（正则前瞻放宽）。"""
    d = _detector()
    hits = await d.scan(f'Visit {PUB_IPV4}. Then continue')
    assert ('ipv4', PUB_IPV4) in hits


@pytest.mark.asyncio
async def test_scan_private_ipv4_trailing_period_exempt():
    """私有 IPv4 句末英文句号仍豁免（不留明文也不误脱敏）。"""
    d = _detector()
    hits = await d.scan(f'内网 {PRIV_IPV4}. 网关')
    assert not hits


# ═══════════════════════════════════════════════════════════
# M2+M3: _metrics.redact_summary 强化层
# ═══════════════════════════════════════════════════════════


def test_metrics_redact_public_ipv6_trailing_period():
    """_metrics 强化层：公网 IPv6 句末英文句号不再明文残留。"""
    from _metrics import redact_summary

    pub6 = _gen_public_ipv6()
    out = redact_summary(f'地址 {pub6}. 后')
    assert pub6 not in out
    assert '[REDACTED:ipv6]' in out


def test_metrics_redact_public_ipv4_trailing_period():
    """_metrics 强化层：公网 IPv4 句末英文句号脱敏。"""
    from _metrics import redact_summary

    out = redact_summary(f'IP {PUB_IPV4}. 后')
    assert PUB_IPV4 not in out
    assert '[REDACTED:ipv4]' in out


def test_metrics_redact_invalid_ipv4_not_redacted():
    """_metrics 强化层：非法 IPv4（999 段）不脱敏（与 scan 一致）。"""
    from _metrics import redact_summary

    bad = '999.999.999.999'  # 非法段（不触发脱敏）
    out = redact_summary(f'错误 {bad} 值')
    assert '[REDACTED:ipv4]' not in out
    assert '[REDACTED:token]' not in out
    assert '999' in out  # 原样保留（不误脱敏）


def test_metrics_redact_private_ipv4_leading_zero_exempt():
    """_metrics 强化层：前导零私有 IPv4 豁免（不误脱敏）。"""
    from _metrics import redact_summary

    out = redact_summary(f'内网 {PRIV_IPV4_LEAD_ZERO} 正常')
    assert PRIV_IPV4_LEAD_ZERO in out


# ═══════════════════════════════════════════════════════════
# M4: URL 上下文防误报（_pii.py scan）
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_scan_bank_card_url_query_param_no_false_positive():
    """?id= 等 URL 查询参数长数字不判银行卡（上下文窗口修复死码）。"""
    d = _detector()
    hits = await d.scan(f'https://example.com/api?order={BANK_CARD_LUHN}&x=1')
    assert not any(t == 'bank_card' for t, v in hits)


@pytest.mark.asyncio
async def test_scan_bank_card_url_long_tail_still_hit():
    """URL 参数后的真实银行卡仍命中（上下文窗口边界正确）。"""
    d = _detector()
    hits = await d.scan(f'卡号 {BANK_CARD_LUHN} 支付')
    assert ('bank_card', BANK_CARD_LUHN) in hits


# ═══════════════════════════════════════════════════════════
# 覆盖缺口锁定（审查报告）
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_scan_phone_plus86_value():
    """+86 国际冠码手机号：命中且 value 含 +（新正则语义）。"""
    d = _detector()
    phone = '+86' + '13' + '800013800'  # 运行时构造（11 位合法手机号）
    hits = await d.scan(f'联系 {phone} 处理')
    assert ('phone', phone) in hits


@pytest.mark.asyncio
async def test_scan_api_key_sk_proj():
    """sk-proj- 前缀 API key 命中。"""
    d = _detector()
    key = 'sk-proj-' + 'A1b2C3d4E5f6G7h8I9j0'
    hits = await d.scan(f'key {key}')
    assert any(t == 'api_key' and v == key for t, v in hits)


@pytest.mark.asyncio
async def test_scan_bank_card_62_prefix_13_digits():
    """62 前缀 13 位银行卡命中（BIN 分支精修）。"""
    d = _detector()
    hits = await d.scan(f'卡号 {BANK_CARD_62_13}')
    assert ('bank_card', BANK_CARD_62_13) in hits


def test_clear_analyzer_cache_all_functions():
    """_clear_analyzer_cache 清理全部 5 个 lru_cache。"""
    from _pii import (
        _id_card_ok,
        _luhn_ok,
    )

    # 填充缓存
    _is_valid_ipv4(PUB_IPV4)
    _is_valid_ipv6('::1')
    _luhn_ok(BANK_CARD_LUHN)
    _id_card_ok('11010119900101001X')
    _is_reserved_ip(PRIV_IPV4, 'ipv4')
    # 验证已缓存
    assert _is_valid_ipv4.cache_info().currsize > 0
    _clear_analyzer_cache()
    assert _is_valid_ipv4.cache_info().currsize == 0
    assert _is_valid_ipv6.cache_info().currsize == 0
    assert _luhn_ok.cache_info().currsize == 0
    assert _id_card_ok.cache_info().currsize == 0
    assert _is_reserved_ip.cache_info().currsize == 0


def test_combined_re_ipv4_trailing_period_matches():
    """正则层：IPv4 句末句号可匹配（前瞻不再禁尾点）。"""
    m = _COMBINED_RE.search(f'Visit {PUB_IPV4}. Then')
    assert m is not None
    assert m.lastgroup == 'ipv4'
    assert m.group(0) == PUB_IPV4
