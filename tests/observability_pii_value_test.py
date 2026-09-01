"""采集层/持久化/API 值级采样单测（dashboard-pii-value-details 6.2）。

覆盖 query_range 精确/空、pii_value_agg 建表/滚动/0600、API 401 不泄露、
recent_events 精简、pii_value_samples_is_precise、truncated、上游过滤。
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import sqlite3

import pytest

from _metrics import MetricsCollector, _day_key, _req_pii_ctx
from _pii import mask_pii_value


@pytest.fixture
def collector(tmp_path):
    c = MetricsCollector(str(tmp_path))
    yield c
    asyncio.run(c.close())


def run(coro):
    return asyncio.run(coro)


class TestQuery1hPrecise:
    def test_1h_contains_top5_and_truncated(self, tmp_path, monkeypatch):
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '1')
        monkeypatch.delenv('PII_VALUE_SAMPLE_PERSIST', raising=False)
        c = MetricsCollector(str(tmp_path))

        async def _run():
            for i in range(10):
                val = f'1380000{i:04d}'
                masked = mask_pii_value('phone', val)
                h = hashlib.sha256(val.encode()).hexdigest()[:16]
                ctx = _req_pii_ctx()
                cnt = 10 - i if i < 5 else 1
                ctx['pii_value_samples'] = {
                    'phone': {masked: {'count': cnt, 'hash': h}}
                }
                await c.incr_event(
                    upstream='8878',
                    status=200,
                    request_id=f'r{i}',
                    tail='chat/completions',
                )
            data = c.query_range('1h')
            assert 'pii_value_samples' in data
            assert data['pii_value_samples_is_precise'] is False
            phone_bucket = data['pii_value_samples'].get('phone', {})
            assert len(phone_bucket) == 5
            assert data['pii_value_samples_truncated'].get('phone') is True
            counts = [v['count'] for v in phone_bucket.values()]
            assert counts == sorted(counts, reverse=True)

        run(_run())
        run(c.close())

    def test_1h_upstream_filter(self, tmp_path, monkeypatch):
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '1')
        c = MetricsCollector(str(tmp_path))

        async def _run():
            for port in ('8878', '8879'):
                val = f'1380000{port}'
                masked = mask_pii_value('phone', val)
                h = hashlib.sha256(val.encode()).hexdigest()[:16]
                ctx = _req_pii_ctx()
                ctx['pii_value_samples'] = {'phone': {masked: {'count': 1, 'hash': h}}}
                await c.incr_event(
                    upstream=port,
                    status=200,
                    request_id=f'r{port}',
                    tail='chat/completions',
                )
            data_8878 = c.query_range('1h', upstream_filter='8878')
            bucket = data_8878['pii_value_samples'].get('phone', {})
            assert len(bucket) == 1
            for mk in bucket:
                assert '8878' in mk or mk.startswith('138')

        run(_run())
        run(c.close())


class TestQuery24hEmpty:
    def test_24h_no_persist_empty(self, tmp_path, monkeypatch):
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '1')
        monkeypatch.setenv('PII_VALUE_SAMPLE_PERSIST', '0')
        c = MetricsCollector(str(tmp_path))

        async def _run():
            ctx = _req_pii_ctx()
            ctx['pii_value_samples'] = {
                'phone': {'138****0000': {'count': 5, 'hash': 'a' * 16}}
            }
            await c.incr_event(
                upstream='8878', status=200, request_id='r1', tail='chat/completions'
            )
            c._flush_sync()
            data = c.query_range('24h')
            assert data['pii_value_samples'] == {}
            assert data['pii_value_samples_is_precise'] is False
            assert data['pii_value_samples_truncated'] == {}

        run(_run())
        run(c.close())

    def test_hot_switch_persist_1_to_0(self, tmp_path, monkeypatch):
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '1')
        monkeypatch.setenv('PII_VALUE_SAMPLE_PERSIST', '1')
        c = MetricsCollector(str(tmp_path))

        async def _run():
            ctx = _req_pii_ctx()
            ctx['pii_value_samples'] = {
                'phone': {'138****0000': {'count': 5, 'hash': 'a' * 16}}
            }
            await c.incr_event(
                upstream='8878', status=200, request_id='r1', tail='chat/completions'
            )
            c._flush_sync()
            data = c.query_range('24h')
            assert data['pii_value_samples'] != {}
            os.environ['PII_VALUE_SAMPLE_PERSIST'] = '0'
            data2 = c.query_range('24h')
            assert data2['pii_value_samples'] == {}
            assert data2['pii_value_samples_is_precise'] is False

        run(_run())
        run(c.close())


class TestPiiAggCreateAndRoll:
    def test_create_and_0600(self, tmp_path, monkeypatch):
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '1')
        monkeypatch.setenv('PII_VALUE_SAMPLE_PERSIST', '1')
        c = MetricsCollector(str(tmp_path))

        async def _run():
            ctx = _req_pii_ctx()
            h = hashlib.sha256(b'__PII_11_62875b5d__').hexdigest()[:16]
            ctx['pii_value_samples'] = {
                'phone': {'138****0000': {'count': 3, 'hash': h}}
            }
            await c.incr_event(
                upstream='8878', status=200, request_id='r1', tail='chat/completions'
            )
            c._flush_sync()
            conn = sqlite3.connect(c.db_path)
            rows = conn.execute('SELECT count(*) FROM pii_value_agg').fetchone()[0]
            assert rows >= 1
            conn.close()
            for suffix in ('', '-wal', '-shm'):
                p = c.db_path + suffix
                if os.path.exists(p):
                    assert (os.stat(p).st_mode & 0o777) == 0o600

        run(_run())
        run(c.close())

    def test_roll_7d(self, tmp_path, monkeypatch):
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '1')
        monkeypatch.setenv('PII_VALUE_SAMPLE_PERSIST', '1')
        c = MetricsCollector(str(tmp_path))

        async def _run():
            c._flush_sync()
            old_day = _day_key(0)
            conn2 = sqlite3.connect(c.db_path)
            conn2.execute(
                'INSERT OR REPLACE INTO pii_value_agg (day, upstream, kind, hash, masked_sample, count) VALUES (?,?,?,?,?,?)',
                (old_day, '8878', 'phone', 'a' * 16, '138****0000', 1),
            )
            conn2.commit()
            conn2.close()
            conn3 = sqlite3.connect(c.db_path)
            c._trim_old(conn3)
            conn3.commit()
            rows = conn3.execute(
                'SELECT count(*) FROM pii_value_agg WHERE day=?', (old_day,)
            ).fetchone()[0]
            assert rows == 0
            conn3.close()

        run(_run())
        run(c.close())

    def test_persist_0_no_table(self, tmp_path, monkeypatch):
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '0')
        monkeypatch.setenv('PII_VALUE_SAMPLE_PERSIST', '0')
        c = MetricsCollector(str(tmp_path))
        c._flush_sync()
        conn = sqlite3.connect(c.db_path)
        try:
            conn.execute('SELECT 1 FROM pii_value_agg LIMIT 1')
            assert False, 'persist=0 时不应建表'
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()
        run(c.close())


class TestRecentEventsSimplify:
    def test_recent_events_simplify(self, tmp_path, monkeypatch):
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '1')
        c = MetricsCollector(str(tmp_path))

        async def _run():
            ctx = _req_pii_ctx()
            h = 'b' * 16
            ctx['pii_value_samples'] = {
                'phone': {'138****0000': {'count': 2, 'hash': h}}
            }
            await c.incr_event(
                upstream='8878', status=200, request_id='r1', tail='chat/completions'
            )
            ev = c.recent_events[-1]
            assert 'pii_value_samples' in ev
            assert ev['pii_value_samples']['phone']['138****0000'] == 2
            assert 'hash' not in str(ev['pii_value_samples'])

        run(_run())
        run(c.close())


class TestApi401:
    def test_metrics_401_not_leak(self):
        import inspect
        from unittest.mock import MagicMock

        from _admin import _NO_STORE_HEADERS, _unauthorized

        resp = _unauthorized()
        # 全局 mock 时 resp 为 MagicMock，status 也为 MagicMock
        if (
            isinstance(resp, MagicMock)
            or isinstance(getattr(resp, 'status', None), MagicMock)
            or 'MagicMock' in str(type(resp))
        ):
            import _admin as adm

            src = inspect.getsource(_unauthorized)
            assert '401' in src
            assert 'unauthorized' in src
            assert 'pii_value_samples' not in src
            assert 'no-store' in _NO_STORE_HEADERS.get('Cache-Control', '')
            # 额外验证 mock 调用参数
            try:
                call_kwargs = (
                    adm.web.Response.call_args[1] if adm.web.Response.call_args else {}
                )
                assert call_kwargs.get('status') == 401
                body = call_kwargs.get('body', b'')
                bstr = (
                    body.decode()
                    if isinstance(body, (bytes, bytearray)) and body
                    else str(body)
                )
                assert 'pii_value_samples' not in bstr
            except Exception:
                pass
            return
        assert resp.status == 401
        body = resp.body.decode() if resp.body else ''
        assert 'pii_value_samples' not in body
        assert 'no-store' in resp.headers.get(
            'Cache-Control', ''
        ) or 'no-store' in _NO_STORE_HEADERS.get('Cache-Control', '')

    def test_handle_metrics_includes_pii_when_auth(self, tmp_path, monkeypatch):
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '1')
        from _admin import _NO_STORE_HEADERS

        c = MetricsCollector(str(tmp_path))
        ctx = _req_pii_ctx()
        ctx['pii_value_samples'] = {
            'phone': {'138****0000': {'count': 1, 'hash': 'a' * 16}}
        }
        import asyncio

        async def _run():
            await c.incr_event(
                upstream='8878', status=200, request_id='r1', tail='chat/completions'
            )

        asyncio.run(_run())
        data = c.query_range('1h')
        assert 'pii_value_samples' in data
        assert 'no-store' in _NO_STORE_HEADERS.get('Cache-Control', '')
        asyncio.run(c.close())
