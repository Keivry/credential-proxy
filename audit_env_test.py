"""Batch 8.1: 环境变量配置解析与校验测试。

覆盖 parse_audit_env_config / parse_pii_env_config 的合法/非法取值。
"""

import asyncio
import os

import pytest

from _audit import parse_audit_env_config
from _pii import PII_HOLD_MAX_DEFAULT, parse_pii_env_config


@pytest.fixture(autouse=True)
def _clean_env():
    """每个测试前清空相关 env，测试后恢复。"""
    keys = [
        'AUDIT_ENABLED',
        'AUDIT_MODE',
        'AUDIT_TIMEOUT',
        'AUDIT_HOLD_MAX_BYTES',
        'AUDIT_POLICY_FILE',
        'APPROVAL_WHITELIST',
        'PII_REDACTION_ENABLED',
        'PII_RESPONSE_SIDE',
        'PII_HOLD_MAX',
    ]
    saved = {k: os.environ.get(k) for k in keys}
    for k in keys:
        os.environ.pop(k, None)
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


class TestParseAuditEnvConfig:
    def test_default_off(self):
        cfg = parse_audit_env_config()
        assert cfg['mode'] == 'off'
        assert cfg['errors'] == []
        assert cfg['whitelist'] == set()
        assert cfg['timeout'] == 90
        assert cfg['hold_max'] == 1048576

    def test_legacy_audit_enabled_means_block(self):
        os.environ['AUDIT_ENABLED'] = '1'
        cfg = parse_audit_env_config()
        assert cfg['mode'] == 'block'
        assert cfg['errors'] == []

    def test_mode_off_disables(self):
        os.environ['AUDIT_MODE'] = 'off'
        cfg = parse_audit_env_config()
        assert cfg['mode'] == 'off'
        assert cfg['errors'] == []

    def test_mode_approve_ok_with_whitelist(self):
        os.environ['AUDIT_MODE'] = 'approve'
        os.environ['APPROVAL_WHITELIST'] = '@a:example,@b:example'
        cfg = parse_audit_env_config()
        assert cfg['mode'] == 'approve'
        assert cfg['errors'] == []
        assert cfg['whitelist'] == {'@a:example', '@b:example'}

    def test_mode_approve_requires_whitelist_when_requested(self):
        os.environ['AUDIT_MODE'] = 'approve'
        cfg = parse_audit_env_config(require_whitelist=True)
        assert cfg['errors']  # 至少一条错误
        assert any('WHITELIST' in e for e in cfg['errors'])

    def test_mode_approve_without_whitelist_ok_when_not_required(self):
        # require_whitelist=False 时不报错（轻量入口降级 block 用）
        os.environ['AUDIT_MODE'] = 'approve'
        cfg = parse_audit_env_config(require_whitelist=False)
        assert cfg['errors'] == []
        assert cfg['mode'] == 'approve'

    def test_timeout_zero_rejected(self):
        os.environ['AUDIT_TIMEOUT'] = '0'
        cfg = parse_audit_env_config()
        assert any('≥1' in e or '≥ 1' in e or '竞态' in e for e in cfg['errors'])

    def test_timeout_negative_rejected(self):
        os.environ['AUDIT_TIMEOUT'] = '-5'
        cfg = parse_audit_env_config()
        assert cfg['errors']

    def test_timeout_in_race_window_rejected(self):
        for v in ('110', '120', '130'):
            os.environ['AUDIT_TIMEOUT'] = v
            cfg = parse_audit_env_config()
            assert cfg['errors'], f'{v}s 应在竞态区间被拒绝'
            assert any('竞态' in e for e in cfg['errors'])

    def test_timeout_outside_race_window_ok(self):
        for v in ('109', '131', '300'):
            os.environ['AUDIT_TIMEOUT'] = v
            cfg = parse_audit_env_config()
            assert cfg['errors'] == [], f'{v}s 不应报错'
            assert cfg['timeout'] == int(v)

    def test_timeout_non_int_rejected(self):
        os.environ['AUDIT_TIMEOUT'] = 'abc'
        cfg = parse_audit_env_config()
        assert cfg['errors']

    def test_hold_max_zero_rejected(self):
        os.environ['AUDIT_HOLD_MAX_BYTES'] = '0'
        cfg = parse_audit_env_config()
        assert cfg['errors']

    def test_hold_max_negative_rejected(self):
        os.environ['AUDIT_HOLD_MAX_BYTES'] = '-1'
        cfg = parse_audit_env_config()
        assert cfg['errors']

    def test_hold_max_non_int_rejected(self):
        os.environ['AUDIT_HOLD_MAX_BYTES'] = '1.5'
        cfg = parse_audit_env_config()
        assert cfg['errors']

    def test_hold_max_valid(self):
        os.environ['AUDIT_HOLD_MAX_BYTES'] = '2048'
        cfg = parse_audit_env_config()
        assert cfg['errors'] == []
        assert cfg['hold_max'] == 2048

    def test_invalid_mode_rejected(self):
        os.environ['AUDIT_MODE'] = 'bogus'
        cfg = parse_audit_env_config()
        assert cfg['errors']
        assert any('AUDIT_MODE' in e for e in cfg['errors'])


class TestParsePiiEnvConfig:
    def test_defaults(self):
        cfg = parse_pii_env_config()
        assert cfg['enabled'] is False
        assert cfg['response_side'] is True
        assert cfg['hold_max'] == PII_HOLD_MAX_DEFAULT == 64
        assert cfg['errors'] == []

    def test_enabled_true_forms(self):
        for v in ('1', 'true', 'True', 'yes'):
            os.environ['PII_REDACTION_ENABLED'] = v
            assert parse_pii_env_config()['enabled'] is True
        os.environ['PII_REDACTION_ENABLED'] = '0'
        assert parse_pii_env_config()['enabled'] is False
        os.environ['PII_REDACTION_ENABLED'] = 'bogus'
        assert parse_pii_env_config()['enabled'] is False

    def test_response_side_default_true(self):
        assert parse_pii_env_config()['response_side'] is True

    def test_response_side_false(self):
        os.environ['PII_RESPONSE_SIDE'] = '0'
        assert parse_pii_env_config()['response_side'] is False

    def test_hold_max_default_64(self):
        assert parse_pii_env_config()['hold_max'] == 64

    def test_hold_max_valid(self):
        os.environ['PII_HOLD_MAX'] = '128'
        cfg = parse_pii_env_config()
        assert cfg['errors'] == []
        assert cfg['hold_max'] == 128

    def test_hold_max_zero_rejected(self):
        os.environ['PII_HOLD_MAX'] = '0'
        cfg = parse_pii_env_config()
        assert cfg['errors']

    def test_hold_max_negative_rejected(self):
        os.environ['PII_HOLD_MAX'] = '-3'
        cfg = parse_pii_env_config()
        assert cfg['errors']

    def test_hold_max_non_int_rejected(self):
        os.environ['PII_HOLD_MAX'] = 'abc'
        cfg = parse_pii_env_config()
        assert cfg['errors']
        # 回落到默认 64
        assert cfg['hold_max'] == 64

    def test_hold_max_empty_rejected(self):
        os.environ['PII_HOLD_MAX'] = ''
        cfg = parse_pii_env_config()
        assert cfg['errors']


class TestEnsureAuditInitDefensive:
    """R6 回归：_ensure_audit_init 防御性校验（approve + 空白名单降级 block）。"""

    def _make_host(self):
        from _audit import AuditMixin

        class Host(AuditMixin):
            def __init__(self):
                # 模拟真实组合宿主：不预调 _init_audit，
                # 由 _ensure_audit_init lazy 初始化（与 proxy.py 一致）
                pass

        return Host()

    def test_approve_without_whitelist_degrades_to_block(self):
        """approve + 无 APPROVAL_WHITELIST → 降级 block（防任何入口绕过）。

        proxy.py 启动时已强制（parse_audit_env_config(require_whitelist=True)）；
        _ensure_audit_init 双保险——轻量入口/未来新入口走到这里也不能以
        「approve + 空白名单」运行（空白名单 = 任何房间成员可审批）。
        """
        os.environ['AUDIT_MODE'] = 'approve'
        h = self._make_host()
        h._ensure_audit_init()
        assert h.audit_mode == 'block'  # 已降级
        assert h.audit_enabled_flag is True  # 审计仍启用（block 模式）

    @pytest.mark.asyncio
    async def test_approve_with_whitelist_stays_approve(self):
        """approve + 有 APPROVAL_WHITELIST → 保持 approve。"""
        os.environ['AUDIT_MODE'] = 'approve'
        os.environ['APPROVAL_WHITELIST'] = '@admin:example.com'
        h = self._make_host()
        # approve 模式会启动审批孤儿清扫 task（asyncio.create_task）→ 需运行循环
        h._ensure_audit_init()
        assert h.audit_mode == 'approve'
        assert h.approval_whitelist == {'@admin:example.com'}
        # 清理清扫 task（防测试泄漏）
        if hasattr(h, '_approval_sweep_task'):
            h._approval_sweep_task.cancel()
            try:
                await h._approval_sweep_task
            except (asyncio.CancelledError, RuntimeError):
                pass
