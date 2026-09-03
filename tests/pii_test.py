"""pii_test.py — PiiDetector 单元测试。

覆盖 (tasks 2.1 / 2.2 / 2.5):
- 每种 recognizer 命中/漏报/边界（误报如纯数字订单号、连续数字串）
- 校验位验证（身份证/银行卡 Luhn）
- 保留地址豁免（前缀匹配 + 段内边界值 + IPv6 lower）
- URL 上下文防误报
- base64 data URL 不误报
- 重复 PII 去重复用 token
- lastgroup 分类

"""

import re

import pytest

from _pii import (
    _COMBINED_RE,
    PiiDetector,
    _is_reserved_ip,
)
from _token import RequestScopedTokens


def _detector():
    return PiiDetector(request_tokens=RequestScopedTokens())


# ═══════════════════════════════════════════════════════════
# 各 recognizer 命中
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_scan_phone():
    d = _detector()
    hits = await d.scan('联系13812345678处理')
    assert ('phone', '13812345678') in hits


@pytest.mark.asyncio
async def test_scan_phone_with_prefix():
    d = _detector()
    hits = await d.scan('+86 13812345678')
    assert any(t == 'phone' and '13812345678' in v for t, v in hits)


@pytest.mark.asyncio
async def test_scan_phone_invalid_prefix():
    d = _detector()
    hits = await d.scan('12812345678')  # 12x 非手机前缀
    assert not any(t == 'phone' for t, v in hits)


@pytest.mark.asyncio
async def test_scan_id_card_valid():
    d = _detector()
    # 校验位有效身份证
    valid = '11010519491231002X'
    hits = await d.scan(f'身份证号{valid}')
    assert ('id_card', valid) in hits


@pytest.mark.asyncio
async def test_scan_id_card_invalid_checksum():
    d = _detector()
    # 校验位无效：18 位随机数字不脱敏（低置信不脱敏）
    invalid = '123456789012345678'
    hits = await d.scan(f'订单号{invalid}')
    assert not any(t == 'id_card' for t, v in hits)


@pytest.mark.asyncio
async def test_scan_email():
    d = _detector()
    hits = await d.scan('联系 zhangsan@example.com 处理')
    assert ('email', 'zhangsan@example.com') in hits


@pytest.mark.asyncio
async def test_scan_bank_card_luhn_valid():
    d = _detector()
    valid = '6222021234567890128'  # 19 位，Luhn 校验通过
    hits = await d.scan(f'卡号{valid}')
    assert any(t == 'bank_card' and v == valid for t, v in hits)


@pytest.mark.asyncio
async def test_scan_bank_card_luhn_invalid():
    d = _detector()
    hits = await d.scan('6222021234567890124')  # Luhn 无效
    assert not any(t == 'bank_card' for t, v in hits)


@pytest.mark.asyncio
async def test_scan_ipv4_public():
    d = _detector()
    hits = await d.scan('服务器 8.8.8.8 已连接')
    assert ('ipv4', '8.8.8.8') in hits


@pytest.mark.asyncio
async def test_scan_ipv4_reserved_exempt():
    d = _detector()
    for ip in ('192.168.1.1', '10.0.0.8', '127.0.0.1', '169.254.1.1'):
        hits = await d.scan(f'IP {ip}')
        assert not any(t == 'ipv4' for t, v in hits), f'{ip} 应豁免'


@pytest.mark.asyncio
async def test_scan_ipv4_reserved_boundary():
    """段内边界值全部豁免（design D1 硬性）。"""
    d = _detector()
    for ip in (
        '172.16.0.1',
        '172.31.255.255',
        '225.0.0.1',
        '241.0.0.1',
        '100.64.0.1',
        '100.127.255.255',
        '192.0.2.1',
        '198.51.100.1',
        '203.0.113.1',
        '0.0.0.1',
    ):
        assert _is_reserved_ip(ip, 'ipv4'), f'{ip} 应保留'
        hits = await d.scan(f'IP {ip}')
        assert not any(t == 'ipv4' for t, v in hits), f'{ip} 应豁免'


@pytest.mark.asyncio
async def test_scan_ipv4_non_reserved_boundary():
    """段外边界值应被脱敏。"""
    d = _detector()
    for ip in ('100.128.0.1', '172.32.0.1', '223.255.255.255'):
        hits = await d.scan(f'IP {ip}')
        assert any(t == 'ipv4' for t, v in hits), f'{ip} 应脱敏'


@pytest.mark.asyncio
async def test_scan_ipv6_public():
    d = _detector()
    hits = await d.scan('IPv6 2001:4860:4860::8888 已连接')
    assert any(t == 'ipv6' for t, v in hits)


@pytest.mark.asyncio
async def test_scan_ipv6_reserved_exempt():
    d = _detector()
    for ip in ('::1', 'fd00::1', 'fe80::a1', '2001:db8::1', 'febf::1', 'FC00::1'):
        hits = await d.scan(f'IP {ip}')
        assert not any(t == 'ipv6' for t, v in hits), f'{ip} 应豁免'


@pytest.mark.asyncio
async def test_scan_ipv6_doc_prefix_requires_colon():
    """裸 2001:db8 不误豁免 2001:db80::（design D1 硬性）。"""
    assert not _is_reserved_ip('2001:db80::1', 'ipv6')
    assert _is_reserved_ip('2001:db8::1', 'ipv6')


@pytest.mark.asyncio
async def test_scan_api_key_sk():
    d = _detector()
    key = 'sk-ant-abcdefghijklmnopqrstuvwxyz123456'
    hits = await d.scan(f'key={key}')
    assert any(t == 'api_key' and v == key for t, v in hits)


@pytest.mark.asyncio
async def test_scan_api_key_ghp():
    d = _detector()
    key = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
    hits = await d.scan(f'token {key}')
    assert any(t == 'api_key' for t, v in hits)


@pytest.mark.asyncio
async def test_scan_api_key_too_short():
    d = _detector()
    hits = await d.scan('sk-abcdefgh')  # 不足 16 字符
    assert not any(t == 'api_key' for t, v in hits)


# ═══════════════════════════════════════════════════════════
# 误报防护
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_scan_order_number_not_bank_card():
    d = _detector()
    hits = await d.scan('订单号 6222021234567890123')
    # 长数字串前后无 URL 参数但 Luhn 校验通过才算银行卡；此处构造 Luhn 无效
    assert not any(t == 'bank_card' for t, v in hits)


@pytest.mark.asyncio
async def test_scan_url_query_param_not_bank_card():
    d = _detector()
    # ?id= 长数字不判银行卡（防误报优先）
    hits = await d.scan('https://example.com/api?id=6222021234567890123')
    assert not any(t == 'bank_card' for t, v in hits)


@pytest.mark.asyncio
async def test_scan_base64_data_url_not_redacted():
    d = _detector()
    b64 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ'
    hits = await d.scan(f'<img src="{b64}">')
    assert not hits  # base64 内数字/字符不误报


@pytest.mark.asyncio
async def test_scan_consecutive_digits_not_phone():
    d = _detector()
    hits = await d.scan('编号 12345678901234567890')
    assert not any(t in ('phone', 'bank_card', 'id_card') for t, v in hits)


# ═══════════════════════════════════════════════════════════
# lastgroup 分类
# ═══════════════════════════════════════════════════════════


def test_lastgroup_classification():
    """每种类型至少一例命中且 lastgroup 分类正确。"""
    cases = [
        ('13812345678', 'phone'),
        ('zhangsan@example.com', 'email'),
        ('8.8.8.8', 'ipv4'),
        ('sk-abcdefghijklmnop', 'api_key'),
    ]
    for text, expect in cases:
        m = _COMBINED_RE.search(text)
        assert m is not None, f'{text} 应命中'
        assert m.lastgroup == expect, f'{text} 分类应为 {expect}，实际 {m.lastgroup}'


# ═══════════════════════════════════════════════════════════
# detect_and_redact + 去重
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_redact_phone_to_token():
    d = _detector()
    out = await d.detect_and_redact('联系13812345678处理')
    assert '13812345678' not in out
    assert '__PII_' in out
    assert out.startswith('联系') and out.endswith('处理')


@pytest.mark.asyncio
async def test_redact_duplicate_reuses_token():
    d = _detector()
    out = await d.detect_and_redact('13812345678 和 13812345678')
    # 同一值去重：两个占位符相同
    tokens = re.findall(r'__PII_\d+_[0-9a-f]{8}__', out)
    assert len(tokens) == 2
    assert tokens[0] == tokens[1]


@pytest.mark.asyncio
async def test_redact_mixed_types_distinct_tokens():
    d = _detector()
    out = await d.detect_and_redact('手机13812345678 邮箱zhangsan@example.com')
    tokens = re.findall(r'__PII_\d+_[0-9a-f]{8}__', out)
    assert len(tokens) == 2
    assert tokens[0] != tokens[1]


@pytest.mark.asyncio
async def test_redact_reserved_ip_not_registered():
    d = _detector()
    out = await d.detect_and_redact('IP 192.168.1.1')
    assert out == 'IP 192.168.1.1'
    assert len(d.request_tokens.pii_p2t) == 0


@pytest.mark.asyncio
async def test_redact_empty_and_clean():
    d = _detector()
    assert await d.detect_and_redact('') == ''
    assert await d.detect_and_redact('纯中文文本无敏感信息') == '纯中文文本无敏感信息'


# ═══════════════════════════════════════════════════════════
# 重叠值策略：凭据注册表命中的值 PII 跳过
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_credential_overlap_skipped():
    d = _detector()
    # 构造凭据映射：某手机号已注册为凭据
    cred_p2t = {'13812345678': '__VG_CRED_000001__'}
    hits = await d.scan('13812345678', credential_p2t=cred_p2t)
    assert not hits  # PII 跳过
    out = await d.detect_and_redact(
        '13812345678',
        credential_p2t=cred_p2t,
    )
    assert out == '13812345678'  # 原样保留（凭据路径后续处理）


# ═══════════════════════════════════════════════════════════
# 自定义正则 + ReDoS
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_custom_pattern_hit():
    d = _detector()
    d.load_custom_patterns([('emp_no', r'(?P<emp_no>工号\d{6})')])
    hits = await d.scan('我的工号123456')
    assert any(t == 'emp_no' for t, v in hits)


@pytest.mark.asyncio
async def test_custom_duplicate_name_rejected():
    d = _detector()
    d.load_custom_patterns([('phone', r'(?P<phone>\d{3})')])
    assert 'phone' not in d.custom_names  # 与内置重名拒绝加载


@pytest.mark.asyncio
async def test_custom_nested_group_rejected():
    d = _detector()
    d.load_custom_patterns(
        [('outer', r'(?P<outer>(?P<inner>\d{3}))')],
    )
    assert 'outer' not in d.custom_names


@pytest.mark.asyncio
async def test_custom_redos_timeout_skipped():
    """恶意模式 (a|aa)+$ 100ms 内被拦截不卡死且告警。

    用失败路径触发回溯爆炸（a×N+! 不匹配 $，指数回溯）：
    32 个 a + ! 实测 ~500ms > 100ms 预算。
    """
    d = _detector()
    d.load_custom_patterns([('evil', r'(?P<evil>^(a|aa)+$)')])
    hits = await d.scan('a' * 32 + '!')
    # 超时被跳过（fail-open）：不返回命中，不抛异常
    assert isinstance(hits, list)
    assert 'evil' in d.custom_strikes


@pytest.mark.asyncio
async def test_custom_word_boundary_rejected():
    """含 \\b 的自定义正则被拒绝加载（fail-closed，中文环境失效）。"""
    d = _detector()
    d.load_custom_patterns([('bad', r'(?P<bad>\\b\\d{6}\\b)')])
    assert 'bad' not in d.custom_names


@pytest.mark.asyncio
async def test_custom_consecutive_timeout_disables(monkeypatch):
    """连续 3 次超时临时停用该规则。"""
    # 确定性超时：timeout 上下文恒抛 TimeoutError，
    # 测连续计数→停用逻辑本身，不依赖回溯耗时抖动
    import asyncio as _asyncio

    class _AlwaysTimeout:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            raise TimeoutError

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(_asyncio, 'timeout', _AlwaysTimeout)
    d = _detector()
    d.load_custom_patterns([('slow', r'(?P<slow>^(a|aa)+$)')])
    # 连续 3 次超时后停用
    for _ in range(3):
        await d.scan('a' * 32 + '!')
    assert 'slow' in d.custom_disabled
    # 停用后不再扫描（不产生超时）
    hits = await d.scan('a' * 32 + '!')
    assert isinstance(hits, list)


# ═══════════════════════════════════════════════════════════
# 字典 recognizer
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_dict_name_hit():
    d = _detector()
    d.load_dict([('张三', 'name')])
    hits = await d.scan('联系人：张三')
    assert ('name', '张三') in hits


@pytest.mark.asyncio
async def test_dict_same_shape_not_false_positive():
    d = _detector()
    d.load_dict([('张三', 'name'), ('张伟', 'name')])
    hits = await d.scan('张三丰 张伟强')
    names = [v for t, v in hits]
    assert '张三' not in names
    assert '张伟' not in names
    assert not names  # 同形词不误伤


@pytest.mark.asyncio
async def test_dict_5000_scan_perf():
    """5000 名单单 chunk 扫描 <1ms（独立扫描锚点）。"""
    import time

    d = _detector()
    entries = [(f'员工{i:04d}', 'emp_no') for i in range(5000)]
    d.load_dict(entries)
    t0 = time.perf_counter()
    hits = d._scan_dict('这是一段普通文本员工4999在最后')
    dt = (time.perf_counter() - t0) * 1000
    assert dt < 1.0, f'5000 名单扫描耗时 {dt:.3f}ms 超过 1ms 锚点'
    assert ('emp_no', '员工4999') in hits


@pytest.mark.asyncio
async def test_dict_reload_invalidates_cache():
    d = _detector()
    d.load_dict([('张三', 'name')])
    ver1 = d.dict_ver
    d.load_dict([('张三', 'name'), ('李四', 'name')])
    assert d.dict_ver > ver1
    hits = d._scan_dict('李四')
    assert ('name', '李四') in hits


# ═══════════════════════════════════════════════════════════
# 占位符区间重叠排除（硬性）
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_placeholder_span_overlap_excluded():
    """占位符区间内 PII 不得匹配（自定义正则匹配含占位符长文本）。"""
    d = _detector()
    d.load_custom_patterns([('wide', r'(?P<wide>[\w:]{10,})')])
    text = '前缀__PII_1_ab12cd34__后缀'
    hits = await d.scan(text)
    # wide 正则可能匹配 前缀__PII_1_ab12cd34__后缀，但占位符区间必须排除：
    # 任何与占位符区间重叠的匹配整体跳过 → 无命中（前缀/后缀单独不够长）
    assert not hits
