"""model 过滤单测（dashboard-filter-charts change 5.2）。

覆盖 observability-metrics model_filter 语义：
- 1h 精确：requests/requests_by_status/pii_*/audit_* 只含该 model 事件
- 24h 历史近似：tokens 只含指定 model 键（反向用例）
- unknown_model 过滤
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


class TestModelFilter:
    def test_1h_model_filter_all_metrics(self, collector):
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                model='gpt-4o',
                pii_hits=2,
                pii_found=True,
                request_id='a',
                tail='chat/completions',
                tokens={'gpt-4o': {'prompt': 10}},
            )
        )
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                model='gpt-4o-mini',
                pii_hits=1,
                request_id='b',
                tail='chat/completions',
                tokens={'gpt-4o-mini': {'prompt': 20}},
            )
        )
        m = collector.query_range('1h', model_filter='gpt-4o')
        assert m['requests'] == 1
        assert m['requests_by_status'].get('200') == 1
        assert m['pii_hits'] == 2
        assert m['pii_requests'] == 1
        assert list(m['tokens'].keys()) == ['gpt-4o']

    def test_24h_model_filter_approximate(self, collector):
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                model='gpt-4o',
                request_id='a',
                tail='chat/completions',
                tokens={'gpt-4o': {'prompt': 10}},
            )
        )
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                model='gpt-4o-mini',
                request_id='b',
                tail='chat/completions',
                tokens={'gpt-4o-mini': {'prompt': 20}},
            )
        )
        collector.flush()
        m = collector.query_range('24h', model_filter='gpt-4o')
        assert list(m['tokens'].keys()) == ['gpt-4o']
        assert m['tokens']['gpt-4o']['prompt'] == 10

    def test_unknown_model_filter(self, collector):
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                model='unknown_model',
                request_id='a',
                tail='chat/completions',
            )
        )
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                model='gpt-4o',
                request_id='b',
                tail='chat/completions',
            )
        )
        m = collector.query_range('1h', model_filter='unknown_model')
        assert m['requests'] == 1
        assert m['requests_by_status'].get('200') == 1

    def test_model_whitelist_sanitize(self, collector):
        # 非法 model 归 unknown_model（防属性注入）
        run(
            collector.incr_event(
                upstream='8878',
                status=200,
                model='<svg onload=alert(1)>',
                request_id='a',
                tail='chat/completions',
            )
        )
        evs = collector.events()
        assert evs[0]['model'] == 'unknown_model'
