"""ipv6 误判回归测试：时间戳 HH:MM:SS 不得命中 ipv6（v0.9.41 修复）。

根因：旧正则 `(?:[0-9a-fA-F]{1,4}:){2,7}...` 不要求 ::，
把 3 段时间戳也匹配成 IPv6（日志里大量误报）。
修复：无 :: 时必须是完整 8 段；含 :: 才允许压缩。

注意：测试用「非保留段」真实公网 IPv6（保留段会被 _is_reserved_ip 豁免，
无法验证正则命中）。
"""

from _pii import _COMBINED_RE, _is_reserved_ip


def _ipv6_hits(text: str) -> list[str]:
    """端到端判定：调用真实 PiiDetector.scan()，返回 ipv6 命中值。

    走生产路径（正则粗筛 + 标点剥离 + 标准库校验 + 保留段豁免），
    不在此处重写逻辑——保证回归测试锁住真实 scan 行为。
    """
    import asyncio

    from _pii import PiiDetector

    d = PiiDetector()
    hits = asyncio.run(d.scan(text))
    return [v for k, v in hits if k == 'ipv6']


# 非保留段真实公网 IPv6 样例
PUB_IPV6_FULL = '3900:cce:8cd0:7d62:7248:4771:347a:2c83'
PUB_IPV6_COMPRESSED = '3900::347a:2c83'
PUB_IPV6_MID = '3900:cce:0:0:0:0:347a:2c83'
PUB_IPV6_TAIL = '3900:cce:8cd0:7d62:7248::'


# ── 时间戳/时间形态不得命中 ipv6 ──────────────────────────────
def test_time_hhmmss_not_ipv6():
    assert _ipv6_hits('21:42:05') == []
    assert _ipv6_hits('2026-08-27 21:42:05 2026') == []


def test_time_millis_not_ipv6():
    assert _ipv6_hits('21:42,728') == []


def test_time_single_digit_not_ipv6():
    assert _ipv6_hits('9:05:07') == []
    assert _ipv6_hits('3:4:5') == []


def test_time_in_log_line_not_ipv6():
    assert _ipv6_hits('Date:   Thu Aug 27 21:42:05 2026 +0800') == []
    assert _ipv6_hits('WARNING LLM 流截断: bytes_buf_len=1074 at 21:42,728') == []


# ── 合法 IPv6 仍命中 ─────────────────────────────────────────
def test_full_8_hextets_hit():
    hits = _ipv6_hits(PUB_IPV6_FULL)
    assert len(hits) == 1


def test_compressed_leading_double_colon_hit():
    hits = _ipv6_hits(PUB_IPV6_COMPRESSED)
    assert len(hits) == 1


def test_compressed_middle_double_colon_hit():
    hits = _ipv6_hits(PUB_IPV6_MID)
    assert len(hits) == 1


def test_compressed_trailing_double_colon_hit():
    hits = _ipv6_hits(PUB_IPV6_TAIL)
    assert len(hits) == 1


# ── 句末标点剥离（Y-1 回归：粗筛贪婪尾串粘连句号导致漏检）──
def test_sentence_end_period_hit():
    # 真实公网 IPv6 后跟句号：粗筛吞掉句号 → 剥离后应命中
    hits = _ipv6_hits(f'{PUB_IPV6_FULL}.')
    assert len(hits) == 1
    assert hits[0] == PUB_IPV6_FULL


def test_sentence_end_comma_hit():
    hits = _ipv6_hits(f'use {PUB_IPV6_COMPRESSED}, then continue')
    assert len(hits) == 1
    assert hits[0] == PUB_IPV6_COMPRESSED


def test_trailing_double_colon_kept():
    # rstrip 不能剥 `:`（双冒号结尾是合法压缩 IPv6）
    hits = _ipv6_hits(f'prefix {PUB_IPV6_TAIL}')
    assert len(hits) == 1
    assert hits[0] == PUB_IPV6_TAIL


def test_loopback_hit_then_reserved():
    m = _COMBINED_RE.search('::1')
    assert m is not None and m.lastgroup == 'ipv6'
    assert _is_reserved_ip('::1', 'ipv6') is True


def test_ula_reserved():
    assert _is_reserved_ip('fd00::1', 'ipv6') is True
    assert _is_reserved_ip('fc00::1', 'ipv6') is True


def test_doc_range_reserved():
    assert _is_reserved_ip('2001:db8::1', 'ipv6') is True


# ── 边界：伪 IPv6（时间戳、URL 端口、畸形段）不命中 ───────────
def test_url_port_not_ipv6():
    assert _ipv6_hits('http://host:8080/path') == []
    assert _ipv6_hits('127.0.0.1:8080') == []


def test_malformed_short_no_coloncolon_not_ipv6():
    # 3 段无 ::（时间戳形态）不命中
    assert _ipv6_hits('21:42:05') == []
    # 2 段无 :: 不命中
    assert _ipv6_hits('aa:bb') == []


def test_malformed_long_no_coloncolon_not_ipv6():
    # 7 段无 ::（缺 1 段，非合法完整 IPv6）不命中
    assert _ipv6_hits('2001:db8:0:1:2:3:4') == []
