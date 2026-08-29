"""series 时间桶序列单测（dashboard-filter-charts change 5.1）。

覆盖 metrics-time-series spec：
- 各范围粒度 60/24/168/30 桶
- 空桶补零（无流量桶 requests:0 不缺桶）
- 1h 分钟级精确聚合（sum(requests)==ring 事件数）
- model/upstream 过滤
- is_precise 翻转（ring 未覆盖 1h 时 false）
"""

from __future__ import annotations

import asyncio

import pytest

from _metrics import MetricsCollector


@pytest.fixture
def collector(tmp_path):
    c = MetricsCollector(str(tmp_path))
    yield c
    asyncio.run(c.close())


def run(coro):
    return asyncio.run(coro)


class TestSeries:
    def test_1h_bucket_count_and_sum(self, collector):
        for i in range(5):
            run(
                collector.incr_event(
                    upstream='8878',
                    status=200,
                    latency_ms=100 + i,
                    model='gpt-4o',
                    tokens={
                        'gpt-4o': {'prompt': 10, 'completion': 5, 'cached_read': 2}
                    },
                    request_id=f'r{i}',
                    tail='chat/completions',
                    pii_found=(i == 0),
                )
            )
        s = collector.series('1h')
        assert len(s['buckets']) == 60
        assert sum(b['requests'] for b in s['buckets']) == 5
        assert sum(b['tokens_prompt'] for b in s['buckets']) == 50
        assert sum(b['pii_requests'] for b in s['buckets']) == 1
        # is_precise：刚启动 ring 未覆盖 1h → False
        assert s['is_precise'] is False

    def test_24h_7d_30d_bucket_counts(self, collector):
        run(
            collector.incr_event(
                upstream='8878', status=200, request_id='a', tail='chat/completions'
            )
        )
        assert len(collector.series('24h')['buckets']) == 24
        assert len(collector.series('7d')['buckets']) == 168
        assert len(collector.series('30d')['buckets']) == 30

    def test_empty_buckets_zero(self, collector):
        s = collector.series('24h')
        # 空桶补零：requests 全 0 且桶不缺
        assert len(s['buckets']) == 24
        assert all(b['requests'] == 0 for b in s['buckets'])

    def test_model_upstream_filter(self, collector):
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                model='gpt-4o',
                request_id='a',
                tail='chat/completions',
            )
        )
        run(
            collector.incr_event(
                upstream='8879',
                status=200,
                model='gpt-4o-mini',
                request_id='b',
                tail='chat/completions',
            )
        )
        s = collector.series('1h', model_filter='gpt-4o')
        assert sum(b['requests'] for b in s['buckets']) == 1
        s = collector.series('1h', upstream_filter='8879')
        assert sum(b['requests'] for b in s['buckets']) == 1
        s = collector.series('1h', upstream_filter='9999')
        assert sum(b['requests'] for b in s['buckets']) == 0

    def test_cached_read_aggregation(self, collector):
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                model='gpt-4o',
                request_id='a',
                tail='chat/completions',
                tokens={'gpt-4o': {'prompt': 100, 'completion': 20, 'cached_read': 30}},
            )
        )
        s = collector.series('1h')
        assert sum(b['cached_read'] for b in s['buckets']) == 30
