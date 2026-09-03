"""redact_summary 强化层回归测试（2026-08-29 四维审查 F-1/Y-9 + Y-5/Y-7）。

覆盖：
- F-1：id_card/bank_card/ipv4/ipv6 明文兜底脱敏（校验位/Luhn/保留段防误伤）
- Y-9：大文本预截断（性能）后脱敏完整性
- Y-5：_flush_sync 去抖（2s 内重复跳过）
- Y-7：model 白名单含冒号版本号
"""

from __future__ import annotations

import asyncio
import time

import pytest

from _metrics import FLUSH_DEBOUNCE_S, MetricsCollector, redact_summary


@pytest.fixture
def collector(tmp_path):
    c = MetricsCollector(str(tmp_path))
    yield c
    asyncio.run(c.close())


def run(coro):
    return asyncio.run(coro)


def _gen_id_card(prefix: str = '11010119900307') -> str:
    """生成校验位合法的身份证号（GB 11643-1999）。"""
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    checks = '10X98765432'
    body = prefix + '883'
    total = sum(int(body[i]) * weights[i] for i in range(17))
    return body + checks[total % 11]


def _gen_luhn_card(prefix: str = '6222') -> str:
    """生成 Luhn 校验合法的银行卡号。"""
    import random

    random.seed(42)
    while True:
        body = prefix + ''.join(random.choice('0123456789') for _ in range(11))
        total = 0
        for i, ch in enumerate(reversed(body + '0')):
            d = ord(ch) - 48
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        candidate = body + str((10 - total % 10) % 10)
        t = 0
        for i, ch in enumerate(reversed(candidate)):
            d = ord(ch) - 48
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            t += d
        if t % 10 == 0:
            return candidate


class TestRedactExtraPii:
    def test_id_card_valid_checksum(self):
        idc = _gen_id_card()
        out = redact_summary(f'用户身份证号是 {idc}，请处理', 200)
        assert idc not in out
        assert '[REDACTED:id_card]' in out

    def test_id_card_invalid_checksum_kept(self):
        # 非法校验位不替换（防误伤普通 18 位数字串）
        fake = '110101199003078837'
        out = redact_summary(f'身份证号是 {fake}（假号码）', 200)
        assert fake in out

    def test_bank_card_valid_luhn(self):
        card = _gen_luhn_card()
        out = redact_summary(f'卡号 {card} 已绑定', 200)
        assert card not in out
        assert '[REDACTED:bank_card]' in out

    def test_bank_card_invalid_luhn_kept(self):
        fake = '1234567890123456789'
        out = redact_summary(f'卡号 {fake} 无效', 200)
        assert fake in out

    def test_ipv4_public_redacted(self):
        # 程序生成确定公网 IP（避开保留段），自包含不依赖占位符
        import random

        from _pii import _is_reserved_ip

        random.seed(7)
        while True:
            ip = f'{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}'
            if not _is_reserved_ip(ip, 'ipv4'):
                break
        out = redact_summary(f'访问 {ip} 正常', 200)
        assert '[REDACTED:ipv4]' in out
        assert ip not in out

    def test_ipv4_reserved_kept(self):
        # 保留段（RFC1918）不替换
        out = redact_summary('内网 192.168.1.100', 200)
        assert '192.168.1.100' in out

    def test_ipv6_public_redacted(self):
        # 程序生成确定公网 IPv6（避开保留段），自包含不依赖占位符
        import random

        from _pii import _is_reserved_ip

        rnd = random.Random(7)
        while True:
            ip6 = ':'.join(f'{rnd.randint(0, 0xFFFF):x}' for _ in range(8))
            if not _is_reserved_ip(ip6, 'ipv6'):
                break
        out = redact_summary(f'访问 {ip6} 正常', 200)
        assert '[REDACTED:ipv6]' in out
        assert ip6 not in out

    def test_ipv6_reserved_kept(self):
        # 保留 IPv6（::1 环回 / fc00::/7 ULA / 2001:db8::/32 文档）不替换
        for ip6 in ('::1', 'fc00::1', '2001:db8::1'):
            out = redact_summary(f'地址 {ip6} 保留', 200)
            assert ip6 in out, f'{ip6} 不应被替换'

    def test_url_param_bankcard_not_redacted(self):
        # Y-13b：URL 查询参数里的长数字（订单号）不判银行卡
        order = '6225880123456789'
        out = redact_summary(f'https://x.com/order?id={order}&amount=100', 200)
        assert order in out, 'URL 参数订单号不应被替换'
        assert '[REDACTED:bank_card]' not in out

    def test_placeholder_span_protected(self):
        # 占位符区间不被 bank_card 误命中（直调 _redact_extra_pii，绕过 token 预替换）
        from _metrics import _redact_extra_pii

        # 占位符内部含 16 位数字（模拟 Luhn 可过的卡号子串）→ 不应被替换
        ph = '__PII_96_6222020200123456__'
        out = _redact_extra_pii(f'token {ph} 已注册')
        assert ph in out, '占位符整体不应被破坏'
        assert '[REDACTED:bank_card]' not in out

    def test_plain_phone_email_redacted(self):
        # 明文手机号/邮箱 → [REDACTED:phone]/[REDACTED:email]
        out = redact_summary('联系 13800138000 或 user@example.com', 200)
        assert '[REDACTED:phone]' in out
        assert '[REDACTED:email]' in out

    def test_placeholder_token_redacted(self):
        # 占位符形态 → [REDACTED:token]
        out = redact_summary('token __PII_1_12345678__ 已脱敏', 200)
        assert '[REDACTED:token]' in out
        assert '__PII_1_12345678__' not in out

    def test_large_text_pre_truncated(self):
        # Y-9：大文本预截断后脱敏仍完整（性能 + 正确性）
        # 敏感值放前面（预截断保留前 limit*3+512 字符窗口）
        idc = _gen_id_card()
        big = ' 身份证号是 ' + idc + ' 结束' + 'A' * 20000
        out = redact_summary(big, 120)
        assert '[REDACTED:id_card]' in out  # 预截断窗口内敏感值仍被脱敏
        assert idc not in out
        assert len(out) <= 121
        # 预截断路径不崩
        assert '\ufffd' not in out


class TestFlushDebounce:
    def test_debounce_skips_within_2s(self, collector):
        """Y-5：2s 内重复 _flush_sync 跳过（去抖游标独立于 health age 游标）。"""
        run(
            collector.incr_event(
                upstream='8878', status=200, request_id='d1', tail='chat/completions'
            )
        )
        assert collector._last_flush_debounce_ts == 0.0  # 初始 0（从未 flush）
        collector._flush_sync()
        assert collector._last_flush_debounce_ts > 0.0
        # 立即再 flush → 去抖跳过
        ts_before = collector._last_flush_debounce_ts
        collector._flush_sync()
        assert collector._last_flush_debounce_ts == ts_before
        # 24h 查询仍能读到数据（首次 flush 已落盘）
        data = collector.query_range('24h')
        assert data['requests'] == 1

    def test_flush_after_debounce_window(self, collector):
        """Y-5：超过 2s 后 flush 正常执行。"""
        run(
            collector.incr_event(
                upstream='8878', status=200, request_id='d2', tail='chat/completions'
            )
        )
        collector._last_flush_debounce_ts = time.time() - FLUSH_DEBOUNCE_S - 1
        collector._flush_sync()
        data = collector.query_range('24h')
        assert data['requests'] == 1


class TestModelColon:
    def test_model_with_version_colon(self, collector):
        """Y-7：gpt-4o:2024-08-06 不再归 unknown_model。"""
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                model='gpt-4o:2024-08-06',
                request_id='m1',
                tail='chat/completions',
                tokens={'gpt-4o:2024-08-06': {'prompt': 10}},
            )
        )
        m = collector.query_range('1h', model_filter='gpt-4o:2024-08-06')
        assert m['requests'] == 1
        assert 'gpt-4o:2024-08-06' in m['tokens']
        assert 'unknown_model' not in m['tokens']
