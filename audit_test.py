"""audit_test.py — Batch 5 策略引擎 + 阻断模式单元测试。

覆盖 tasks 5.1-5.4：
- 策略匹配（allow/deny/危险模式/边界）
- 参数规范化命中（双空格、转义、变量拼接、multiline、`..` 路径）
- 外部域名判定（IP 字面量/内网后缀/公网）
- 策略文件加载（JSON/YAML/非法文件三路径）
- 预检前缀匹配
"""

import asyncio
import json
import os
import tempfile

import pytest

from _audit import (
    AuditMixin,
    _append_audit_log,
    _expand_aliases,
    is_external_host,
    load_policy_file,
    normalize_args,
)


class AuditStub(AuditMixin):
    """测试桩。"""

    __test__ = False

    def __init__(self, policy_file=None):
        self._init_audit(policy_file)
        # 测试桩默认不落盘（仅内存环形计数）
        self.audit_log_path = ''


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

    def test_single_pipe_split(self):
        """单管道命令链拆分（F-06 回归：`rm -rf / | sh` 必须拆开）。

        旧实现拆链正则缺单 `|`，管道后的命令段与管道前粘连。
        """
        norm = normalize_args('{"cmd":"rm -rf /tmp | sh"}')
        # 管道被空格替代，命令段独立
        assert '|' not in norm
        assert 'rm -rf /tmp' in norm
        assert ' sh' in norm

    def test_double_pipe_priority(self):
        """`||` 作为整体拆分（不被单 `|` 误拆为两段）。"""
        norm = normalize_args('{"cmd":"a || b"}')
        assert '||' not in norm
        assert 'a' in norm and 'b' in norm

    def test_dotdot_path_normalize(self):
        """/tmp/../etc → /etc（路径规范化后命中敏感路径）。"""
        norm = normalize_args('{"path":"/tmp/../etc/passwd"}')
        assert '/etc/passwd' in norm

    def test_long_input_no_dotdot_fast(self):
        """大输入无 `/../` 时快速返回（R2 回归：二次方回溯已短路）。

        旧实现 `_normalize_dotdot` 的裸路径正则（非空白字符 + /../ + 非空白字符）
        在长无匹配文本上逐位置贪吃+回退 O(n²)——100KB 实测 ~27s。
        `/../` 预检查短路后应毫秒级返回。
        """
        import time

        big = 'cat /etc/passwd ' + 'a' * 100_000
        t0 = time.monotonic()
        norm = normalize_args(big)
        elapsed = time.monotonic() - t0
        # 100KB 输入处理总预算：远小于旧实现 ~27s（宽松阈值防 CI 抖动）
        assert elapsed < 1.0, (
            f'normalize_args 100KB 无 /../ 耗时 {elapsed:.2f}s（二次方回溯未修复）'
        )
        assert '/etc/passwd' in norm

    def test_long_input_with_dotdot_fast(self):
        """大输入含 `..`（无 /../）仍快速返回（R2 完整回归：绕过形态）。

        仅 `..` 预检查不够——攻击者在参数里放一个 `..`（如 echo ...）即
        可绕过（旧正则仍从每个位置重试，100KB+.. 实测 ~27s）。
        R2 完整修复：`/../` 精确预检查 + 「定位+局部规范化」O(n) 算法，
        长文本上快速失败。
        """
        import time

        big = 'cat /etc/passwd ' + 'a' * 100_000 + ' ..'
        t0 = time.monotonic()
        norm = normalize_args(big)
        elapsed = time.monotonic() - t0
        assert elapsed < 1.0, (
            f'normalize_args 100KB+.. 耗时 {elapsed:.2f}s（O(n) 算法未生效）'
        )
        assert '/etc/passwd' in norm

    def test_long_input_with_trail_dotdot_fast(self):
        """`/../` 在长前缀末尾时仍快速返回（R2 完整回归：贪吃+回退形态）。

        旧正则（非空白字符 + /../ + 非空白字符）的贪吃部分先吞整个长前缀
        再回退找 `/../`（O(n²)）——100KB 前缀 + 末尾 /../ 实测 ~27s。
        O(n) 定位算法消除该形态。
        """
        import time

        big = 'a' * 100_000 + ' /tmp/../etc'
        t0 = time.monotonic()
        norm = normalize_args(big)
        elapsed = time.monotonic() - t0
        assert elapsed < 1.0, (
            f'normalize_args 100KB+/../末尾 耗时 {elapsed:.2f}s（O(n) 算法未生效）'
        )
        assert '/etc' in norm

    def test_find_delete_alias_with_args(self):
        """find -delete 带参数 → rm -rf 别名展开（R9 回归）。"""
        s = _expand_aliases('find /tmp -name "*.log" -delete')
        assert 'rm -rf /tmp -name "*.log"' in s

    def test_find_flood_fast(self):
        """大量 `find` 无 `-delete` 仍快速返回（R9 回归：find 二次方回溯）。

        旧实现 `\\bfind\\s+([^;|&]*?)\\s+-delete\\b` 懒惰 `[^;|&]*?` 在
        大量 `find` 但无 `-delete` 的文本上每个位置回溯 O(n²)——60KB
        实测 3.2s / 120KB 12.9s。改为「-delete 定位 + 向前找 find」
        O(n) 算法后应毫秒级返回。
        """
        import time

        big = 'find /usr/bin/foo ' * 6667  # ~120KB
        t0 = time.monotonic()
        _expand_aliases(big)
        elapsed = time.monotonic() - t0
        assert elapsed < 1.0, (
            f'_expand_aliases find-flood 120KB 耗时 {elapsed:.2f}s（O(n) 算法未生效）'
        )

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


# ═══════════════════════════════════════════════════════════
# 审计日志（7.1/7.2：JSONL、脱敏、0600、轮转、fail-closed）
# ═══════════════════════════════════════════════════════════


class TestAuditLog:
    def _stub(self, tmp_path):
        stub = AuditStub()
        stub.audit_enabled_flag = True
        stub.audit_log_path = str(tmp_path / 'audit.log')
        return stub

    @pytest.mark.asyncio
    async def test_log_format_valid_json(self, tmp_path):
        """日志行合法单 JSON，含时间/工具/处置/摘要。"""
        stub = self._stub(tmp_path)
        await stub._audit_log_event(
            'deny', 'bash', '{"cmd":"rm -rf /"}', 'dangerous-shell'
        )
        lines = (tmp_path / 'audit.log').read_text().strip().split('\n')
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec['tool'] == 'bash'
        assert rec['verdict'] == 'deny'
        assert rec['rule'] == 'dangerous-shell'
        assert 'rm' in rec['summary']

    @pytest.mark.asyncio
    async def test_secret_not_in_log(self, tmp_path):
        """敏感值不落盘：密钥形态 → [REDACTED:<type>]。"""
        stub = self._stub(tmp_path)
        await stub._audit_log_event(
            'deny',
            'bash',
            '{"cmd":"curl http://x -H \\"Authorization: Bearer sk-abc123def456abcdef\\""}',
            'dangerous-shell',
        )
        text = (tmp_path / 'audit.log').read_text()
        assert 'sk-abc123def456abcdef' not in text
        assert '[REDACTED:api_key]' in text

    @pytest.mark.asyncio
    async def test_ctrl_chars_stripped(self, tmp_path):
        """控制字符被剥离（防日志注入伪造条目）。"""
        stub = self._stub(tmp_path)
        await stub._audit_log_event(
            'deny', 'bash', '{"cmd":"rm -rf /\\n\\x00\\x1f\\nFAKE"}', 'dangerous-shell'
        )
        lines = (tmp_path / 'audit.log').read_text().strip().split('\n')
        # 原始输入含 \n → 不产生多行（json 转义）；\x00\x1f 被剥离
        assert len(lines) == 1
        assert '\x00' not in lines[0] and '\x1f' not in lines[0]

    @pytest.mark.asyncio
    async def test_append_and_concurrent_safe(self, tmp_path):
        """追加写 + 并发安全：多条记录都在，无覆盖。"""
        stub = self._stub(tmp_path)
        await asyncio.gather(
            *[
                stub._audit_log_event('allow', f'tool{i}', f'{{"x":{i}}}', '')
                for i in range(20)
            ]
        )
        lines = (tmp_path / 'audit.log').read_text().strip().split('\n')
        assert len(lines) == 20
        tools = {json.loads(l)['tool'] for l in lines}
        assert tools == {f'tool{i}' for i in range(20)}

    def test_permissions_0600(self, tmp_path):
        """新建文件权限 0600。"""
        path = str(tmp_path / 'audit.log')
        assert _append_audit_log(path, {'ts': 1, 'tool': 'x', 'verdict': 'allow'})
        assert (os.stat(path).st_mode & 0o777) == 0o600

    def test_rotation(self, tmp_path):
        """大小轮转：超 10MB → .1/.2 滚动，最老删除。"""
        path = str(tmp_path / 'audit.log')
        # 直接写小记录验证轮转逻辑（用 monkeypatch 缩小阈值）
        import _audit as _audit_mod

        old_max = _audit_mod.AUDIT_LOG_MAX_BYTES
        old_bk = _audit_mod.AUDIT_LOG_BACKUPS
        _audit_mod.AUDIT_LOG_MAX_BYTES = 100
        _audit_mod.AUDIT_LOG_BACKUPS = 3
        try:
            for i in range(30):
                assert _append_audit_log(
                    path, {'ts': i, 'tool': 't', 'verdict': 'allow', 'pad': 'x' * 40}
                )
            assert os.path.exists(path)
            # 应有轮转备份
            backups = [p for p in os.listdir(tmp_path) if p.startswith('audit.log.')]
            assert backups, '轮转应产生备份'
        finally:
            _audit_mod.AUDIT_LOG_MAX_BYTES = old_max
            _audit_mod.AUDIT_LOG_BACKUPS = old_bk

    @pytest.mark.asyncio
    async def test_write_fail_deny_still_blocks(self, tmp_path, caplog):
        """危险调用日志写失败 → 仍阻断（verdict 照常 deny）+ 告警。"""
        stub = self._stub(tmp_path)
        stub.audit_log_path = '/nonexistent-dir/audit.log'  # 写失败
        verdict = await stub.audit_tool_call('bash', '{"cmd":"rm -rf /"}')
        assert verdict == 'deny'  # 仍阻断
        assert any('写失败' in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_allow_write_fail_warns_not_blocks(self, tmp_path):
        """放行调用日志写失败 → 告警不阻断 + 内存环形计数。"""
        stub = self._stub(tmp_path)
        stub.audit_log_path = '/nonexistent-dir/audit.log'
        verdict = await stub.audit_tool_call('bash', '{"cmd":"ls -la"}')
        assert verdict == 'allow'  # 不阻断
        assert len(stub._audit_log_ring) >= 1  # 内存计数

    @pytest.mark.asyncio
    async def test_ring_buffer_caps(self, tmp_path):
        """内存环形计数有上限（防无限增长）。"""
        stub = self._stub(tmp_path)
        stub.audit_log_path = ''
        stub._audit_log_ring_max = 5
        for i in range(12):
            await stub._audit_log_event('allow', f't{i}', '{}', '')
        assert len(stub._audit_log_ring) == 5

    @pytest.mark.asyncio
    async def test_live_scope_redact_phone(self, tmp_path):
        """实时请求级映射脱敏：请求期/响应期新注册 PII 明文不落盘。"""
        stub = self._stub(tmp_path)

        # 模拟 LlmMixin scope（含请求期 + 响应期新注册映射）
        class FakeScope:
            def __init__(self):
                self.pii_t2p = {'__PII_0_ab12cd34__': '13800138000'}
                self.resp_t2p = {'__PII_1_ef56gh78__': '13900139000'}

        stub._pii_scope_or_none = lambda: FakeScope()  # type: ignore[attr-defined]
        # 参数含占位符 + 真实响应期明文（脱敏前）
        await stub._audit_log_event(
            'deny',
            'bash',
            '{"cmd":"curl http://x -d \\"13800138000 __PII_0_ab12cd34__ 13900139000 __PII_1_ef56gh78__\\""}',
            'dangerous-shell',
        )
        text = (tmp_path / 'audit.log').read_text()
        assert '13800138000' not in text  # 请求期 PII 明文不落盘
        assert '13900139000' not in text  # 响应期新 PII 明文不落盘
        assert 'REDACTED' in text  # 均被脱敏形态替换
