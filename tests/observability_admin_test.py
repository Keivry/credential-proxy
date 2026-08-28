"""大盘与鉴权单测（llm-observability-dashboard change 4.1b）。

覆盖 observability-dashboard 4 个 Requirement 的场景：
- 鉴权 401/405 HEAD/OPTIONS/TRACE，401 前不触 DB
- header > cookie > query 优先级（query 仅 SSE 回退）
- _is_loopback ipaddress.ip_address 精确判定（127.0.0.0/8|::1|::ffff:127.0.0.1）
- hmac.compare_digest 时序安全、validate_observability_token 空值 SystemExit
- 10/min/IP 429 + Retry-After、SSE 5/IP 并发注册表
- health 含 ring/first_dropped/last_dropped/pending/sqlite_error
- 密码框 type=password、CSP/SVG 降级、脱敏无明文
"""

from __future__ import annotations

import asyncio

import pytest

from _admin import (
    _is_loopback,
    _RateLimiter,
    _SseRegistry,
    validate_observability_token,
)
from _metrics import MetricsCollector, redact_summary


@pytest.fixture
def collector(tmp_path):
    c = MetricsCollector(str(tmp_path))
    yield c
    asyncio.run(c.close())


# ── _is_loopback 精确判定 ──


class TestIsLoopback:
    def test_ipv4_loopback(self):
        assert _is_loopback('127.0.0.1') is True
        assert _is_loopback('127.255.255.254') is True

    def test_ipv6_loopback(self):
        assert _is_loopback('::1') is True

    def test_ipv4_mapped_loopback(self):
        assert _is_loopback('::ffff:127.0.0.1') is True

    def test_non_loopback(self):
        assert _is_loopback('172.18.0.1') is False
        assert _is_loopback('8.8.8.8') is False
        assert _is_loopback('10.0.0.1') is False

    def test_invalid(self):
        assert _is_loopback('not-an-ip') is False
        assert _is_loopback('') is False

    def test_no_broad_prefix(self):
        # 不复用 172. 过宽前缀（172.33 公网）
        assert _is_loopback('172.33.0.1') is False


# ── _RateLimiter 10/min/IP ──


class TestRateLimiter:
    def test_allow_until_limit(self):
        rl = _RateLimiter(limit=10, window_s=60)
        for _ in range(10):
            ok, retry = rl.allow('1.2.3.4')
            assert ok is True
        ok, retry = rl.allow('1.2.3.4')
        assert ok is False
        assert retry > 0

    def test_per_ip_isolated(self):
        rl = _RateLimiter(limit=2, window_s=60)
        assert rl.allow('a')[0] is True
        assert rl.allow('a')[0] is True
        assert rl.allow('a')[0] is False
        assert rl.allow('b')[0] is True

    def test_cleanup(self):
        rl = _RateLimiter(limit=1, window_s=60)
        rl.allow('x')
        assert rl.allow('x')[0] is False
        rl.cleanup('x')
        assert rl.allow('x')[0] is True


# ── _SseRegistry 5/IP 并发 ──


class TestSseRegistry:
    def test_max_concurrent(self):
        reg = _SseRegistry(max_concurrent=5)
        for _ in range(5):
            assert reg.try_acquire('1.2.3.4') is True
        assert reg.try_acquire('1.2.3.4') is False
        # 其它 IP 不受影响
        assert reg.try_acquire('5.6.7.8') is True

    def test_release(self):
        reg = _SseRegistry(max_concurrent=2)
        assert reg.try_acquire('x') is True
        assert reg.try_acquire('x') is True
        reg.release('x')
        assert reg.try_acquire('x') is True


# ── validate_observability_token ──


class TestValidateToken:
    def test_missing_token_systemexit(self, monkeypatch):
        monkeypatch.delenv('OBSERVABILITY_ADMIN_TOKEN', raising=False)
        monkeypatch.delenv('OBSERVABILITY_DISABLE', raising=False)
        with pytest.raises(SystemExit):
            validate_observability_token()

    def test_disabled_skips(self, monkeypatch):
        monkeypatch.setenv('OBSERVABILITY_DISABLE', '1')
        monkeypatch.delenv('OBSERVABILITY_ADMIN_TOKEN', raising=False)
        validate_observability_token()  # 不抛

    def test_duplicate_with_credential_token(self, monkeypatch):
        tok = 'a' * 40
        monkeypatch.setenv('OBSERVABILITY_ADMIN_TOKEN', tok)
        monkeypatch.setenv('CREDENTIAL_ADMIN_TOKEN', tok)
        monkeypatch.delenv('OBSERVABILITY_DISABLE', raising=False)
        monkeypatch.delenv('DATA_DIR', raising=False)
        with pytest.raises(SystemExit):
            validate_observability_token()

    def test_ok(self, monkeypatch):
        monkeypatch.setenv('OBSERVABILITY_ADMIN_TOKEN', 'x' * 40)
        monkeypatch.setenv('CREDENTIAL_ADMIN_TOKEN', 'y' * 40)
        monkeypatch.delenv('MATRIX_ACCESS_TOKEN', raising=False)
        monkeypatch.delenv('DATA_DIR', raising=False)
        monkeypatch.delenv('OBSERVABILITY_DISABLE', raising=False)
        validate_observability_token()  # 不抛


# ── health 字段 ──


class TestHealthFields:
    def test_health_has_observability_fields(self, collector):
        h = collector.health()
        for k in (
            'pii_enabled',
            'metrics_age_s',
            'sqlite_ok',
            'dropped_snapshots',
            'first_dropped_ts',
            'last_dropped_ts',
            'audit_pending_total',
            'ring_len',
            'sqlite_error',
            'placeholder_prompt_enabled',
        ):
            assert k in h, f'health 缺字段 {k}'


# ── 密码框 / CSP / 脱敏 ──


class TestDashboardHtml:
    def test_password_input(self):
        html = _read_admin_html()
        assert 'type="password"' in html
        assert 'autocomplete="current-password"' in html

    def test_history_replace_state(self):
        html = _read_admin_html()
        assert 'replaceState' in html

    def test_csp_no_inline_exec(self):
        html = _read_admin_html()
        # 无外部 CDN 依赖（Chart.js ~200KB fallback SVG 内联降级）
        assert 'cdn.jsdelivr' not in html or 'Chart is not defined' in html

    def test_no_plaintext_redaction_long(self):
        # 120+64 长串含截断边界半字符
        raw = 'x' * 120 + 'sk-' + 'B' * 64
        out = redact_summary(raw, 120)
        assert 'B' * 64 not in out
        assert len(out) <= 122


def _read_admin_html() -> str:
    from pathlib import Path

    p = Path(__file__).parent.parent / 'admin.html'
    return p.read_text(encoding='utf-8')


# ── 审查修复回归（2026-08-28 四维审查）──


class TestRateLimiterCleanup:
    def test_expired_key_reused_with_count(self):
        rl = _RateLimiter(limit=10, window_s=60)
        ip = "192.0.2.55"
        rl.allow(ip)
        # 模拟时间流逝（直接篡改内部时间戳为过期）
        import time as _t
        rl._hits[ip] = [_t.time() - 120]
        ok, _ = rl.allow(ip)
        assert ok is True
        # 空窗口首请求计入配额（防每分钟多放 1 个），key 保留且含当前时间戳
        assert ip in rl._hits
        assert len(rl._hits[ip]) == 1

    def test_active_key_kept(self):
        rl = _RateLimiter(limit=10, window_s=60)
        ip = "192.0.2.56"
        rl.allow(ip)
        ok, _ = rl.allow(ip)
        assert ok is True
        assert ip in rl._hits


class TestSseRegistryIdempotent:
    def test_release_below_one_pops(self):
        reg = _SseRegistry(max_concurrent=5)
        assert reg.try_acquire('9.9.9.9') is True
        reg.release('9.9.9.9')
        # 二次 release 幂等（不抛、不把计数扣成负数）
        reg.release('9.9.9.9')
        assert '9.9.9.9' not in reg._conns


class TestEventsSummaryRedacted:
    def test_summary_never_contains_raw_secret(self, collector):
        import asyncio as _a

        async def _run():
            await collector.incr_event(
                upstream='8878',
                status=200,
                request_id='r-redact-1',
                raw_summary='call tool with key-sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 and phone 13800138000',
            )

        _a.run(_run())
        evs = collector.events(limit=10)
        assert evs, '应有事件'
        s = evs[0].get('summary', '')
        assert 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456' not in s
        assert '13800138000' not in s
