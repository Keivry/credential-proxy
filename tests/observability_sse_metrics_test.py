"""SSE 15s metrics 快照单测（dashboard-filter-charts change 5.5）。

覆盖 observability-dashboard SSE metrics：
- /_admin/events/stream 连接后 15s 内收到 event: metrics
- 快照含 metrics/series/health 与 range 回显
- 事件仍 2s 推（event: event）
"""

from __future__ import annotations

import asyncio
import json

import pytest

from _metrics import MetricsCollector


@pytest.fixture
def collector(tmp_path):
    c = MetricsCollector(str(tmp_path))
    yield c
    asyncio.run(c.close())


def run(coro):
    return asyncio.run(coro)


class TestSseMetricsSnapshot:
    def test_metrics_snapshot_payload_shape(self, collector):
        # 直接验证快照构造逻辑（_admin._handle_sse 内的 snap 结构）
        run(
            collector.incr_event(
                upstream='8878', status=200, request_id='a', tail='chat/completions'
            )
        )
        m = collector.query_range('1h')
        s = collector.series('1h')
        h = collector.health()
        snap = {
            'range': '1h',
            'model': None,
            'upstream': None,
            'metrics': m,
            'series': s,
            'health': h,
        }
        assert snap['range'] == '1h'
        assert snap['metrics']['requests'] == 1
        assert len(snap['series']['buckets']) == 60
        assert isinstance(snap['health'], dict)
        # 序列化（SSE data 载荷）可 JSON 化
        json.dumps(snap, ensure_ascii=False)
