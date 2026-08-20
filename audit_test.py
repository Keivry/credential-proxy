"""audit_test.py — Batch 5 策略引擎 + 阻断模式单元测试。

覆盖 tasks 5.1-5.4：
- 策略匹配（allow/deny/危险模式/边界）
- 参数规范化命中（双空格、转义、变量拼接、multiline、`..` 路径）
- 外部域名判定（IP 字面量/内网后缀/公网）
- 策略文件加载（JSON/YAML/非法文件三路径）
- 预检前缀匹配
"""

import json
import os
import tempfile

import pytest

from _audit import (
    AuditMixin,
    is_external_host,
    load_policy_file,
    normalize_args,
)


class AuditStub(AuditMixin):
    """测试桩。"""

    __test__ = False

    def __init__(self, policy_file=None):
        self._init_audit(policy_file)


# ═══════════════════════════════════════════════════════════
# 策略匹配
# ═══════════════════════════════════════════════════════════


class TestPolicyMatch:
    @pytest.mark.asyncio
    async def test_disabled_returns_allow(self):
        stub = AuditStub()
        stub.audit_enabled_flag = False
        assert await stub.audit_tool_call('bash', '{"cmd":"rm -rf /"}') == 'allow'

    @pytest.mark.asyncio
    async def test_allow_list_exact(self):
        stub = AuditStub()
        stub.audit_enabled_flag = True
        assert await stub.audit_tool_call('web_search', '{}') == 'allow'

    @pytest.mark.asyncio
    async def test_deny_list_exact(self):
        stub = AuditStub()
        stub.audit_enabled_flag = True
        stub.policy['deny'] = ['dangerous_tool']
        assert await stub.audit_tool_call('dangerous_tool', '{}') == 'deny'

    @pytest.mark.asyncio
    async def test_dangerous_rm_rf(self):
        stub = AuditStub()
        stub.audit_enabled_flag = True
        assert await stub.audit_tool_call('bash', '{"cmd":"rm -rf /"}') == 'deny'

    @pytest.mark.asyncio
    async def test_safe_bash_allowed(self):
        stub = AuditStub()
        stub.audit_enabled_flag = True
        # ls 不在 allow 名单，但也不命中危险模式 → allow
        assert await stub.audit_tool_call('bash', '{"cmd":"ls -la"}') == 'allow'

    @pytest.mark.asyncio
    async def test_sensitive_path_write(self):
        stub = AuditStub()
        stub.audit_enabled_flag = True
        assert (
            await stub.audit_tool_call(
                'write_file', '{"path":"/etc/passwd","content":"x"}'
            )
            == 'deny'
        )


# ═══════════════════════════════════════════════════════════
# 参数规范化（design D3 审计对抗性）
# ═══════════════════════════════════════════════════════════


class TestNormalizeArgs:
    def test_merge_duplicate_whitespace(self):
        """双空格/多空白合并 → 规则命中。"""
        norm = normalize_args('{"cmd":"rm   -rf   /"}')
        assert 'rm -rf' in norm
        # 原始含双空格不命中单空格模式 → 规范化后命中
        import re

        raw = '{"cmd":"rm   -rf   /"}'
        assert not re.search(r'\brm -rf\b', raw)
        assert re.search(r'\brm -rf\b', norm)

    def test_unicode_escape(self):
        """\\u0072m 转义 → rm。"""
        norm = normalize_args(r'{"cmd":"\u0072m -rf /"}')
        assert 'rm -rf' in norm

    def test_hex_escape(self):
        """\\x72m 转义 → rm。"""
        norm = normalize_args(r'{"cmd":"\x72m -rf /"}')
        assert 'rm -rf' in norm

    def test_variable_concat(self):
        """CMD=rm;$CMD -rf → rm -rf。"""
        norm = normalize_args('{"cmd":"CMD=rm;$CMD -rf /"}')
        assert 'rm -rf' in norm

    def test_multiline(self):
        """多行命令合并 → 规则命中。"""
        norm = normalize_args('{"cmd":"rm\\n-rf\\n/"}')
        assert 'rm -rf' in norm

    def test_dotdot_path_normalize(self):
        """/tmp/../etc → /etc（路径规范化后命中敏感路径）。"""
        norm = normalize_args('{"path":"/tmp/../etc/passwd"}')
        assert '/etc/passwd' in norm

    def test_alias_bin_rm(self):
        """/bin/rm -rf → rm -rf。"""
        norm = normalize_args('{"cmd":"/bin/rm -rf /"}')
        assert 'rm -rf' in norm

    def test_find_delete_alias(self):
        """find / -delete → rm -rf /。"""
        norm = normalize_args('{"cmd":"find / -delete"}')
        assert 'rm -rf' in norm


# ═══════════════════════════════════════════════════════════
# 外部域名判定
# ═══════════════════════════════════════════════════════════


class TestExternalHost:
    def test_rfc1918_internal(self):
        assert is_external_host('192.168.1.1') is False
        assert is_external_host('10.0.0.1') is False
        assert is_external_host('172.16.5.5') is False

    def test_public_ip_external(self):
        assert is_external_host('8.8.8.8') is True
        assert is_external_host('114.114.114.114') is True

    def test_loopback_linklocal_internal(self):
        assert is_external_host('127.0.0.1') is False
        assert is_external_host('169.254.1.1') is False
        assert is_external_host('::1') is False
        assert is_external_host('fe80::a1') is False

    def test_domain_heuristics(self):
        assert is_external_host('localhost') is False
        assert is_external_host('db.internal') is False
        assert is_external_host('host.local') is False
        assert is_external_host('evil.com') is True

    def test_internal_suffixes_config(self):
        assert is_external_host('host.corp.example', ('.corp.example',)) is False
        assert is_external_host('host.other.example', ('.corp.example',)) is True

    def test_empty_returns_none(self):
        assert is_external_host('') is None


# ═══════════════════════════════════════════════════════════
# 策略文件加载（5.2）
# ═══════════════════════════════════════════════════════════


class TestPolicyFile:
    def test_json_load(self):
        with tempfile.NamedTemporaryFile(
            'w', suffix='.json', delete=False, encoding='utf-8'
        ) as f:
            json.dump({'allow': ['test_tool'], 'deny': [], 'dangerous': []}, f)
            path = f.name
        try:
            policy = load_policy_file(path)
            assert policy['allow'] == ['test_tool']
        finally:
            os.unlink(path)

    def test_yaml_load(self):
        yaml_text = """\
allow:
  - web_search
  - read_file
deny:
  - evil_tool
dangerous:
  - pattern: '\\brm\\s+-rf\\b'
    reason: 危险删除
internal_suffixes:
  - .internal
"""
        with tempfile.NamedTemporaryFile(
            'w', suffix='.yaml', delete=False, encoding='utf-8'
        ) as f:
            f.write(yaml_text)
            path = f.name
        try:
            policy = load_policy_file(path)
            assert policy['allow'] == ['web_search', 'read_file']
            assert policy['deny'] == ['evil_tool']
            assert policy['dangerous'][0]['pattern'] == '\\brm\\s+-rf\\b'
            assert policy['internal_suffixes'] == ['.internal']
        finally:
            os.unlink(path)

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_policy_file('/nonexistent/policy.yaml')

    def test_invalid_file_raises(self):
        with tempfile.NamedTemporaryFile(
            'w', suffix='.yaml', delete=False, encoding='utf-8'
        ) as f:
            f.write(':::not:valid:yaml:::\n  - bad')
            path = f.name
        try:
            with pytest.raises(ValueError):
                load_policy_file(path)
        finally:
            os.unlink(path)

    def test_example_policy_parses(self):
        """examples/audit-policy.yaml 可被 loader 解析。"""
        path = os.path.join(os.path.dirname(__file__), 'examples', 'audit-policy.yaml')
        policy = load_policy_file(path)
        assert 'allow' in policy
        assert 'dangerous' in policy
        assert len(policy['dangerous']) >= 4

    def test_invalid_policy_disables_audit(self):
        """非法策略文件 → fail-closed（审计禁用）。"""
        with tempfile.NamedTemporaryFile(
            'w', suffix='.yaml', delete=False, encoding='utf-8'
        ) as f:
            f.write('::bad::')
            path = f.name
        try:
            stub = AuditStub(policy_file=path)
            assert stub.audit_enabled() is False
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════
# 预检（design D4：暂停先于判定）
# ═══════════════════════════════════════════════════════════


class TestPrecheck:
    def test_dangerous_name_precheck(self):
        stub = AuditStub()
        stub.audit_enabled_flag = True
        assert stub.audit_precheck('bash', 'ls') is True

    def test_dangerous_prefix_precheck(self):
        """rm 是 rm -rf 的前缀 → 预检触发。"""
        stub = AuditStub()
        stub.audit_enabled_flag = True
        assert stub.audit_precheck('tool', 'rm') is True
        assert stub.audit_precheck('tool', 'rm -rf /') is True

    def test_safe_prefix_no_precheck(self):
        stub = AuditStub()
        stub.audit_enabled_flag = True
        assert stub.audit_precheck('tool', 'ls -la') is False

    def test_disabled_no_precheck(self):
        stub = AuditStub()
        stub.audit_enabled_flag = False
        assert stub.audit_precheck('bash', 'rm -rf') is False
