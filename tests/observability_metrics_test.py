"""采集层单测（llm-observability-dashboard change 4.1a）。

覆盖 observability-metrics 4 个 Requirement 的场景：
- PII/凭据计数口径（detected 按次、cache hit/miss 按值、LRU 批量）
- sanitize_kind custom_other 归一
- 上游/token/守门（normalize_usage、空体守门、JSON-aware 三态）
- 聚合与窗口化（覆盖式 UPSERT 不翻倍、ENOSPC 降级、p95 独立 executor）
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from pathlib import Path

import pytest

from _metrics import (
    LATENCY_BUCKETS,
    MetricsCollector,
    _day_key,
    _utc_now,
    metrics_bucket,
    normalize_usage,
    redact_summary,
    sanitize_kind,
)

# ── sanitize_kind ──


class TestSanitizeKind:
    def test_builtin_kinds_passthrough(self):
        assert sanitize_kind('phone', {'phone'}) == 'phone'
        assert sanitize_kind('api_key', set()) == 'api_key'
        assert sanitize_kind('id_card', set()) == 'id_card'

    def test_custom_names_passthrough(self):
        assert sanitize_kind('my_pattern', {'my_pattern'}) == 'my_pattern'

    def test_custom_other_cases(self):
        assert sanitize_kind('__weird__kind', set()) == 'custom_other'
        assert sanitize_kind('x' * 40, set()) == 'custom_other'
        assert sanitize_kind('bad\x00kind', set()) == 'custom_other'
        assert sanitize_kind('unknown_kind', set()) == 'custom_other'
        assert sanitize_kind('', set()) == 'custom_other'
        assert sanitize_kind(None, set()) == 'custom_other'

    def test_case_normalized(self):
        assert sanitize_kind('PHONE', set()) == 'phone'


# ── normalize_usage ──


class TestNormalizeUsage:
    def test_openai_chat(self):
        u = normalize_usage(
            {
                'prompt_tokens': 10,
                'completion_tokens': 20,
                'total_tokens': 30,
                'prompt_tokens_details': {'cached_tokens': 5},
            },
            'openai',
        )
        assert u['prompt'] == 10
        assert u['completion'] == 20
        assert u['total'] == 30
        assert u['cached_read'] == 5
        assert u['cached_write'] == 0
        assert u['unknown'] is False

    def test_openai_null_details(self):
        u = normalize_usage(
            {'prompt_tokens': 10, 'completion_tokens': 20, 'total_tokens': 30},
            'openai',
        )
        assert u['cached_read'] == 0

    def test_anthropic(self):
        u = normalize_usage(
            {
                'input_tokens': 10,
                'output_tokens': 20,
                'cache_read_input_tokens': 50,
                'cache_creation_input_tokens': 10,
            },
            'anthropic',
        )
        assert u['input'] == 10
        assert u['output'] == 20
        assert u['total'] == 30  # 求和
        assert u['cached_read'] == 50
        assert u['cached_write'] == 10

    def test_responses(self):
        u = normalize_usage(
            {
                'input_tokens': 10,
                'output_tokens': 20,
                'input_tokens_details': {'cached_tokens': 50},
            },
            'responses',
        )
        assert u['cached_read'] == 50
        assert u['cached_write'] == 0
        assert u['total'] == 30

    def test_unknown(self):
        u = normalize_usage(None, 'openai')
        assert u['unknown'] is True
        u = normalize_usage({}, 'openai')
        assert u['unknown'] is True

    def test_total_tokens_precedence(self):
        u = normalize_usage(
            {'prompt_tokens': 10, 'completion_tokens': 20, 'total_tokens': 99},
            'openai',
        )
        assert u['total'] == 99


# ── metrics_bucket ──


class TestMetricsBucket:
    def test_bucket_hit(self):
        assert metrics_bucket(5) == 10
        assert metrics_bucket(10) == 10
        assert metrics_bucket(11) == 25
        assert metrics_bucket(250) == 400
        assert metrics_bucket(20000) == float('inf')

    def test_12_buckets(self):
        assert len(LATENCY_BUCKETS) == 12


# ── redact_summary ──


class TestRedactSummary:
    def test_no_plaintext(self):
        raw = 'my phone is __PII_491_57fbc05b__ and key sk-abc...6789 and email __PII_539_d2d93156__'
        out = redact_summary(raw, 120)
        assert '__PII_491_57fbc05b__' not in out
        assert 'sk-abc...mnop' not in out
        assert '__PII_539_d2d93156__' not in out
        assert 'sk-abcdefghijklmnop' not in out
        assert 'a@b.com' not in out

    def test_truncation(self):
        raw = 'sk-' + 'A' * 64 + ' tail'
        out = redact_summary(raw, 120)
        assert 'A' * 64 not in out  # 密钥形态已脱敏
        assert len(out) <= 122  # 120 + 省略号

    def test_truncation_boundary(self):
        # 注入 120+64 长串：截断边界半字符保护
        raw = 'x' * 120 + 'sk-' + 'B' * 64
        out = redact_summary(raw, 120)
        assert 'B' * 64 not in out


# ── MetricsCollector 核心 ──


@pytest.fixture
def collector(tmp_path):
    c = MetricsCollector(str(tmp_path))
    yield c
    asyncio.run(c.close())


def run(coro):
    return asyncio.run(coro)


class TestCollectorCore:
    def test_incr_event_basic(self, collector):
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                latency_ms=50,
                request_id='r1',
                tail='chat/completions',
            )
        )
        data = collector.query_range('1h')
        assert data['requests'] == 1
        assert data['requests_by_status'].get('200') == 1
        assert collector.ring_stats()['ring_len'] == 1

    def test_pii_requests_same_source(self, collector):
        """脱敏占比 = pii_requests/requests 必须同数据源（recent_events），且 ≤100%。"""
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                pii_found=True,
                pii_by_type={'ipv6': 2},
                pii_hits=1,
                pii_miss=0,
                request_id='p1',
                tail='chat/completions',
            )
        )
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                pii_found=True,
                pii_by_type={'email': 1},
                pii_hits=0,
                pii_miss=1,
                request_id='p2',
                tail='chat/completions',
            )
        )
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                request_id='p3',
                tail='chat/completions',
            )
        )
        data = collector.query_range('1h')
        assert data['requests'] == 3
        assert data['pii_requests'] == 2
        assert data['pii_hits'] == 1
        assert data['pii_miss'] == 1
        ratio = data['pii_requests'] / data['requests']
        assert ratio <= 1.0
        assert abs(ratio - 2 / 3) < 1e-9
        # 24h 窗口从 DB 读取同一语义（先 flush 落库）
        collector._flush_sync()
        data24 = collector.query_range('24h')
        assert data24['pii_requests'] == 2
        assert data24['pii_hits'] == 1

    def test_event_detail_hit_miss_from_ctx(self, collector):
        """事件详情的 pii_hits/pii_miss/cred_hits/cred_miss 来自 per-request ContextVar。"""
        from _metrics import (
            accumulate_cred,
            accumulate_pii_cache,
            reset_req_pii_ctx,
            _req_pii_ctx,
        )

        _req_pii_ctx()
        accumulate_pii_cache(hit=1, miss=0)
        accumulate_pii_cache(hit=0, miss=2)
        accumulate_cred(hit=1, miss=0)
        try:
            run(
                collector.incr_event(
                    upstream='8879',
                    status=200,
                    pii_found=True,
                    request_id='evt-ctx-1',
                    tail='chat/completions',
                )
            )
        finally:
            reset_req_pii_ctx()
        ev = collector.recent_events[-1]
        assert ev['pii_hits'] == 1
        assert ev['pii_miss'] == 2
        assert ev['cred_hits'] == 1
        assert ev['cred_miss'] == 0
        q = collector.query_range('1h')
        assert q['pii_hits'] == 1
        assert q['pii_miss'] == 2

    def test_sanitize_kind_db_no_raw_label(self, collector):
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                request_id='r1',
                pii_by_type={'__weird__kind': 1, 'x' * 40: 2, 'phone': 1},
            )
        )
        run(collector.flush())
        run(collector.close())
        conn = sqlite3.connect(collector.db_path)
        row = conn.execute('SELECT pii_by_type FROM daily_agg LIMIT 1').fetchone()
        pii = json.loads(row[0])
        assert 'custom_other' in pii
        assert '__weird__kind' not in pii
        assert 'x' * 40 not in pii
        conn.close()

    def test_upsert_no_double_count(self, collector):
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                request_id='r1',
            )
        )
        run(collector.flush())
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                request_id='r2',
            )
        )
        run(collector.flush())
        run(collector.close())
        conn = sqlite3.connect(collector.db_path)
        row = conn.execute(
            'SELECT requests FROM daily_agg WHERE date=? AND upstream=?',
            (_day_key(_utc_now()), '8878'),
        ).fetchone()
        assert row[0] == 2  # 两次 flush 不翻倍
        conn.close()

    def test_queue_full_dropped(self, collector):
        # 填满队列（maxsize=512）：直接塞 520 个快照触发 dropped（丢最老再入队）
        snap = [{'date': '2026-08-28', 'upstream': '8878', 'requests': 1}]
        for _ in range(520):
            collector._enqueue(snap)
        assert collector._dropped_snapshots > 0
        assert collector._first_dropped_ts is not None
        assert collector._last_dropped_ts is not None
        # 队列内仍保留最新（丢最老）且不超过 maxsize
        assert collector._queue.qsize() <= 512

    def test_incr_event_summary_redacted(self, collector):
        """raw_summary 经 redact_summary 脱敏后入 recent_events（PII 占位符 → [REDACTED:token]）。"""
        run(
            collector.incr_event(
                request_id='req-1',
                upstream='8878',
                status=200,
                raw_summary=(
                    'user said __PII_608_f7cff63a__ and __PII_123_abcdef12__ '
                    'and __PII_609_b1f9c4ca__'
                ),
            )
        )
        ev = collector.events(limit=5)[-1]
        assert '__PII_608_f7cff63a__' not in ev['summary']
        assert '__PII_123_abcdef12__' not in ev['summary']
        assert '__PII_609_b1f9c4ca__' not in ev['summary']
        assert '[REDACTED:token]' in ev['summary']

    def test_incr_event_tokens_deep_copy(self, collector):
        """tokens 内层 dict 也须防御性拷贝：外部突变不污染 recent_events/聚合。"""
        tokens = {'gpt-4o': {'prompt': 10, 'completion': 5}}
        run(
            collector.incr_event(
                request_id='req-t', upstream='8878', status=200, tokens=tokens
            )
        )
        tokens['gpt-4o']['prompt'] = 999
        tokens['gpt-4o']['new'] = 1
        ev = collector.events(limit=5)[-1]
        assert ev['tokens']['gpt-4o']['prompt'] == 10
        assert 'new' not in ev['tokens']['gpt-4o']

    def test_wal_and_version(self, collector):
        run(collector.flush())
        run(collector.close())
        conn = sqlite3.connect(collector.db_path)
        assert conn.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'
        assert conn.execute('PRAGMA user_version').fetchone()[0] == 1
        conn.close()

    def test_chmod_0600(self, collector):
        run(collector.flush())
        run(collector.close())
        for suffix in ('', '-wal', '-shm'):
            p = collector.db_path + suffix
            if os.path.exists(p):
                assert (os.stat(p).st_mode & 0o777) == 0o600

    def test_events_filter(self, collector):
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                request_id='a',
                verdict='allow',
                tail='chat/completions',
            )
        )
        run(
            collector.incr_event(
                upstream='8879',
                status=200,
                request_id='b',
                verdict='deny',
                tail='chat/completions',
            )
        )
        evs = collector.events(verdict='deny')
        assert len(evs) == 1
        assert evs[0]['request_id'] == 'b'
        evs = collector.events(upstream='8878')
        assert len(evs) == 1

    def test_p95_async(self, collector):
        for i in range(150):
            run(
                collector.incr_event(
                    upstream='8878',
                    status=200,
                    latency_ms=i % 100,
                    request_id=f'r{i}',
                )
            )
        stats = run(collector.p95_async())
        assert stats['p95'] is not None
        assert stats['ring_len'] == 150

    def test_ring_precise_gate(self, collector):
        # 仅 50 条且时间短 → is_precise False（len>=100 门限）
        for i in range(50):
            run(
                collector.incr_event(
                    upstream='8878',
                    status=200,
                    latency_ms=10,
                    request_id=f'r{i}',
                )
            )
        stats = collector.ring_stats()
        assert stats['is_precise'] is False

    def test_lock_no_await(self):
        src = Path(__file__).parent.parent / '_metrics.py'
        s = src.read_text()
        idx = s.index('async with self._lock')
        assert 'await' not in s[idx : idx + 300]

    def test_p95_worker_independent(self):
        src = Path(__file__).parent.parent / '_metrics.py'
        s = src.read_text()
        assert 'p95-worker' in s
        assert 'metrics-writer' in s

    def test_do_update_excluded(self):
        src = Path(__file__).parent.parent / '_metrics.py'
        s = src.read_text()
        assert (
            'DO UPDATE SET col=excluded.col' in s.replace(' ', '') or 'excluded.' in s
        )
        assert 'col+excluded.col' not in s

    def test_hourly_daily_window(self, collector):
        for i in range(3):
            run(
                collector.incr_event(
                    upstream='8878',
                    status=200,
                    latency_ms=50,
                    request_id=f'r{i}',
                )
            )
        collector._flush_sync()  # 同步落盘（flush() 异步入队，writer 未完成不可见）
        data = collector.query_range('24h')
        assert data['requests'] == 3
        data = collector.query_range('30d')
        assert data['requests'] == 3


# ── ENOSPC 降级 ──


class TestEnospc:
    def test_enospc_degrades(self, tmp_path):
        c = MetricsCollector(str(tmp_path))
        # 模拟磁盘满：把 _conn 替换为只读（或注入 sqlite 错误）
        c._sqlite_ok = False
        c._sqlite_error = 'database or disk is full (28)'
        # 降级后 incr 仍工作（内存-only）
        asyncio.run(c.incr_event(upstream='8878', status=200, request_id='r1'))
        h = c.health()
        assert h['sqlite_ok'] is False
        assert h['sqlite_error']
        asyncio.run(c.close())
