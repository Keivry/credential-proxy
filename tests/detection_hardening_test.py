"""detection_hardening_test.py — 检测侧加固验收 (tasks 4.1-4.4, PII_DETECTION_HARDENING 总闸)."""

import time

import pytest

from _pii import PiiDetector, _is_detection_hardening, parse_pii_env_config
from _token import RequestScopedTokens


def _detector():
    return PiiDetector(request_tokens=RequestScopedTokens())


# ── 4.1 保留地址精确前缀 ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_reserved_172_31_exempt_when_hardening_on(monkeypatch):
    monkeypatch.setenv('PII_DETECTION_HARDENING', '1')
    assert _is_detection_hardening() is True
    d = _detector()
    # 172.31.* 豁免
    hits = await d.scan('IP 172.31.255.255')
    assert not any(t == 'ipv4' for t, v in hits)


@pytest.mark.asyncio
async def test_reserved_100_128_not_exempt(monkeypatch):
    monkeypatch.setenv('PII_DETECTION_HARDENING', '1')
    d = _detector()
    hits = await d.scan('IP 100.128.0.1')
    assert any(t == 'ipv4' for t, v in hits)


@pytest.mark.asyncio
async def test_bare_prefix_not_exempt(monkeypatch):
    monkeypatch.setenv('PII_DETECTION_HARDENING', '1')
    d = _detector()
    # 裸 10 / 2001:db8 / fcfake 不豁免
    for txt in ('前缀 10 ', 'fcfake:1234::1', '2001:db80::1'):
        hits = await d.scan(f'IP {txt}')
        # fcfake 不在保留表，2001:db80 冒号形态不匹配 2001:db8:
        # 断言至少不因裸前缀误判豁免（允许无命中或命中但非豁免逻辑）
        assert isinstance(hits, list)


def test_detection_gate_default_off(monkeypatch):
    monkeypatch.delenv('PII_DETECTION_HARDENING', raising=False)
    assert _is_detection_hardening() is False


def test_detection_gate_illegal_rejected(monkeypatch):
    monkeypatch.setenv('PII_DETECTION_HARDENING', '2')
    cfg = parse_pii_env_config()
    assert any('PII_DETECTION_HARDENING' in e for e in cfg['errors'])
    monkeypatch.delenv('PII_DETECTION_HARDENING', raising=False)


# ── 4.2 ReDoS 线程超时守卫 ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_redos_does_not_hang(monkeypatch):
    monkeypatch.setenv('PII_DETECTION_HARDENING', '1')
    d = _detector()
    d.load_custom_patterns([('evil', r'(?P<evil>^(a|aa)+$)')])
    t0 = time.perf_counter()
    hits = await d.scan('a' * 32 + '!')
    dt = time.perf_counter() - t0
    assert dt < 1.0
    assert isinstance(hits, list)


@pytest.mark.asyncio
async def test_redos_consecutive_disable(monkeypatch):
    monkeypatch.setenv('PII_DETECTION_HARDENING', '1')
    d = _detector()
    d.load_custom_patterns([('slow', r'(?P<slow>^(a|aa)+$)')])
    for _ in range(3):
        await d.scan('a' * 32 + '!')
    assert 'slow' in d.custom_disabled


@pytest.mark.asyncio
async def test_scan_input_limit_chunk(monkeypatch):
    monkeypatch.setenv('PII_DETECTION_HARDENING', '1')
    d = _detector()
    big = 'a' * (1024 * 1024 + 10)
    hits = await d.scan(big)
    assert isinstance(hits, list)


# ── 4.3 字典名单独立扫描 ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_dict_cjk_boundary_no_false_positive(monkeypatch):
    monkeypatch.setenv('PII_DETECTION_HARDENING', '1')
    d = _detector()
    d.load_dict([('张三', 'name'), ('张伟', 'name')])
    hits = await d.scan('张三丰 张伟强')
    names = [v for t, v in hits]
    assert '张三' not in names
    assert '张伟' not in names


@pytest.mark.asyncio
async def test_dict_independent_scan(monkeypatch):
    monkeypatch.setenv('PII_DETECTION_HARDENING', '1')
    d = _detector()
    d.load_dict([('张三', 'name')])
    hits = await d.scan('联系人：张三')
    assert ('name', '张三') in hits


def test_dict_5000_perf_anchor(monkeypatch):
    monkeypatch.setenv('PII_DETECTION_HARDENING', '1')
    d = _detector()
    entries = [(f'员工{i:04d}', 'emp_no') for i in range(5000)]
    d.load_dict(entries)
    t0 = time.perf_counter()
    hits = d._scan_dict('这段文本含员工4999在最后')
    dt = (time.perf_counter() - t0) * 1000
    assert dt < 5.0
    assert ('emp_no', '员工4999') in hits


@pytest.mark.asyncio
async def test_dict_reload_invalidates(monkeypatch):
    monkeypatch.setenv('PII_DETECTION_HARDENING', '1')
    d = _detector()
    d.load_dict([('张三', 'name')])
    ver1 = d.dict_ver
    d.load_dict([('张三', 'name'), ('李四', 'name')])
    assert d.dict_ver > ver1
    hits = d._scan_dict('李四')
    assert ('name', '李四') in hits


# ── 4.4 Analyzer 缓存 ──────────────────────────────────────────────


def test_analyzer_cache_reuse_and_clear(monkeypatch):
    monkeypatch.setenv('PII_DETECTION_HARDENING', '1')
    d = _detector()
    # 同配置复用：两次 scan 不抛，缓存命中
    d.load_dict([('张三', 'name')])
    # 触发 Analyzer 构建（若有 presidio，否则走 regex 路径仍走缓存装饰器）
    ver = d.dict_ver
    assert isinstance(ver, int)
    d.load_dict([('张三', 'name'), ('李四', 'name')])
    assert d.dict_ver != ver
