"""upstream 过滤单测（dashboard-filter-charts change 5.3）。

覆盖 observability-metrics upstream_filter 语义：
- 1h ring 过滤
- 24h DB 过滤
- metrics+events+series 三端一致
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


class TestUpstreamFilter:
    def test_1h_upstream_filter(self, collector):
        run(
            collector.incr_event(
                upstream='8878', status=200, request_id='a', tail='chat/completions'
            )
        )
        run(
            collector.incr_event(
                upstream='8879', status=200, request_id='b', tail='chat/completions'
            )
        )
        m = collector.query_range('1h', upstream_filter='8878')
        assert m['requests'] == 1
        assert m['requests_by_status'].get('200') == 1

    def test_24h_upstream_filter_db(self, collector):
        run(
            collector.incr_event(
                upstream='8878', status=200, request_id='a', tail='chat/completions'
            )
        )
        run(
            collector.incr_event(
                upstream='8879', status=200, request_id='b', tail='chat/completions'
            )
        )
        run(collector.flush())
        m = collector.query_range('24h', upstream_filter='8878')
        assert m['requests'] == 1

    def test_three_end_consistency(self, collector):
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
        m = collector.query_range('1h', upstream_filter='8878')
        evs = collector.events(upstream='8878')
        s = collector.series('1h', upstream_filter='8878')
        assert m['requests'] == 1
        assert len(evs) == 1
        assert evs[0]['upstream'] == '8878'
        assert sum(b['requests'] for b in s['buckets']) == 1
