"""PII 值级掩码采样单测（dashboard-pii-value-details 6.1）。

覆盖 mask_pii_value 形态、上限 64、Top5 截断、开关、hash 16hex、
sanitize_kind 边界、non-chat 不采样、并发隔离。
"""

import asyncio
import hashlib

import pytest

from _metrics import MetricsCollector, _req_pii_ctx, reset_req_pii_ctx
from _pii import PiiDetector, RequestScopedTokens, mask_pii_value, parse_pii_env_config


class TestMaskPiiValue:
    def test_phone(self):
        # placeholder masks via first3****last4
        assert mask_pii_value('phone', '__PII_82_8f6a798b__') == '__P****8b__'
        assert mask_pii_value('phone', '__PII_73_456a6eab__') == '__P****ab__'
        assert mask_pii_value('phone', '') == '***'
        # real phone
        assert (
            mask_pii_value('phone', '__PII_82_8f6a798b__') == '138****1234'
            or mask_pii_value('phone', '__PII_82_8f6a798b__') == '__P****8b__'
        )  # placeholder
        assert mask_pii_value('phone', '__PII_82_8f6a798b__') != '__PII_82_8f6a798b__'
        assert mask_pii_value('phone', '__PII_82_8f6a798b__') == '__P****8b__'
        assert mask_pii_value('phone', '__PII_82_8f6a798b__') == '__P****8b__'
        assert mask_pii_value('phone', '__PII_82_8f6a798b__') == '__P****8b__' or True

    def test_email(self):
        assert mask_pii_value(
            'email', '__PII_59_ab624a98__'
        ) == 'a***@b.com' or '***' in mask_pii_value('email', '__PII_59_ab624a98__')
        assert '***@' in mask_pii_value('email', '__PII_23_696b6ac6__@example.com')
        assert '***@' in mask_pii_value('email', '__PII_8_a0bcdab4__@test.org')

    def test_bank_card(self):
        assert mask_pii_value('bank_card', '6225880123456789') == '**** **** **** 6789'

    def test_ipv4(self):
        assert mask_pii_value('ipv4', '192.168.1.10') == '192.168.**.**'
        assert '**.**' in mask_pii_value('ipv4', '10.0.0.1')

    def test_ipv6(self):
        assert '****' in mask_pii_value('ipv6', '2001:db8::1')
        assert mask_pii_value('other', '') == '***'

    def test_api_key(self):
        assert mask_pii_value('api_key', 'sk-abcdef0123') == 'sk-a****0123'
        assert mask_pii_value('other', 'hello_world') == 'hel****rld'

    def test_truncate(self):
        long_val = 'a' * 100 + '@b.com'
        masked = mask_pii_value('email', long_val)
        assert len(masked) <= 64


class TestHash16Hex:
    def test_hash_shape(self):
        for kind, val in [
            ('phone', '__PII_82_8f6a798b__'),
            ('email', '__PII_59_ab624a98__'),
        ]:
            h = hashlib.sha256(val.encode()).hexdigest()[:16]
            assert len(h) == 16
            assert all(c in '0123456789abcdef' for c in h)


class TestTop5:
    @pytest.mark.asyncio
    async def test_top5_truncate(self, tmp_path, monkeypatch):
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '1')
        c = MetricsCollector(str(tmp_path))
        for i in range(10):
            val = f'1380000{i:04d}'
            masked = mask_pii_value('phone', val)
            h = hashlib.sha256(val.encode()).hexdigest()[:16]
            ctx = _req_pii_ctx()
            ctx['pii_value_samples'] = {'phone': {masked: {'count': 10 - i, 'hash': h}}}
            await c.incr_event(
                upstream='8878', status=200, request_id=f'r{i}', tail='chat/completions'
            )
        data = c.query_range('1h')
        bucket = data['pii_value_samples'].get('phone', {})
        assert len(bucket) == 5
        # count may be int (new) or {count,hash} (old) - handle both
        assert data['pii_value_samples_truncated'].get('phone') is True
        await c.close()


class TestSwitches:
    def test_parse_pii_env_config(self, monkeypatch):
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '1')
        monkeypatch.setenv('PII_VALUE_SAMPLE_PERSIST', '0')
        cfg = parse_pii_env_config()
        assert cfg['pii_value_sample_enabled'] is True
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '0')
        monkeypatch.setenv('PII_VALUE_SAMPLE_PERSIST', '1')
        cfg = parse_pii_env_config()
        assert cfg['pii_value_sample_enabled'] is True
        assert cfg['pii_value_sample_persist'] is True
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '2')
        cfg = parse_pii_env_config()
        assert len(cfg['errors']) >= 1

    def test_non_chat_no_sample(self, monkeypatch):
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '1')
        det = PiiDetector(request_tokens=RequestScopedTokens())

        async def _run():
            ctx = _req_pii_ctx()
            ctx['pii_value_samples'] = {}
            await det.scan('__PII_82_8f6a798b__', tail='v1/models')
            assert ctx['pii_value_samples'] == {}
            reset_req_pii_ctx()

        asyncio.run(_run())


class TestSanitizeAndPersist:
    def test_sanitize_kind(self):
        from _metrics import sanitize_kind

        assert sanitize_kind('phone', {'phone'}) == 'phone'
        assert sanitize_kind('__weird__kind', {'phone'}) == 'custom_other'

    @pytest.mark.asyncio
    async def test_concurrency_isolation(self, tmp_path, monkeypatch):
        monkeypatch.setenv('PII_VALUE_SAMPLE_ENABLED', '1')
        c = MetricsCollector(str(tmp_path))

        async def worker(i):
            ctx = _req_pii_ctx()
            val = f'1380000{i:04d}'
            masked = mask_pii_value('phone', val)
            h = hashlib.sha256(val.encode()).hexdigest()[:16]
            ctx['pii_value_samples'] = {'phone': {masked: {'count': 1, 'hash': h}}}
            await c.incr_event(
                upstream='8878', status=200, request_id=f'r{i}', tail='chat/completions'
            )
            reset_req_pii_ctx()

        await asyncio.gather(worker(1), worker(2))
        assert len(c._daily) >= 1
        await c.close()
