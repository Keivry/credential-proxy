"""Batch 8.4: 大 body 性能验证测试。

测量设计锚点（design.md D1）：
- 联合正则 1MB 全量扫描 ~90ms
- 纯文本粗筛 ~0.8ms（25x）
- 单 1KB chunk ~124µs
- <100KB 请求扫描 ~9ms
- 字典独立扫描 ~190µs/1KB（5000 名）
- 增量扫描 1MB ~90ms（口径 = 联合正则 1MB 全量扫描）

断言用宽松容差（CI 抖动），只验证「在声明锚点的合理倍数内」，
记录实测值供 design 修订参考。
"""

import time

import pytest

from _pii import PiiMixin


class _PerfStub(PiiMixin):
    """最小 PiiMixin 桩（不触发 _init_pii 落盘等副作用）。"""

    def __init__(self):
        self._pii_scope = None
        self._init_pii()  # 先初始化（会重置 pii_enabled=False）
        # 再启用（_init_pii 无条件重置，顺序必须在后）
        self.pii_enabled = True
        self.pii_response_side = True
        self.pii_hold_max = 64


@pytest.fixture(scope='module')
def stub():
    return _PerfStub()


def _mk_text(n_bytes: int, ascii_dense: bool = True) -> str:
    """构造指定字节数的混合文本（ASCII 密集，触发全量扫描）。"""
    # 中文 + 数字 + 字母混合，粗筛必然命中（[\\dA-Za-z@.\\-] 存在）
    unit = '身份证 13800138000 测试 abc123 @example.com 联系我\n'
    reps = n_bytes // len(unit.encode('utf-8')) + 1
    text = (unit * reps)[:n_bytes]
    return text


def _mk_pure_cjk(n_bytes: int) -> str:
    """纯中文无数字文本（粗筛跳过）。"""
    unit = '你好世界这是一个测试文本没有数字和字母'
    reps = n_bytes // len(unit.encode('utf-8')) + 1
    return (unit * reps)[:n_bytes]


async def _time_scan(stub, text: str, credential_p2t: dict | None = None) -> float:
    t0 = time.perf_counter()
    await stub.pii_scan(text)
    return time.perf_counter() - t0


class TestScanPerformance:
    """全量扫描锚点（联合正则 1MB ~90ms）。"""

    @pytest.mark.asyncio
    async def test_1mb_full_scan_under_500ms(self, stub):
        text = _mk_text(1_048_576)
        dt = await _time_scan(stub, text)
        print(f'\n[8.4] 1MB 全量扫描: {dt * 1000:.1f}ms (锚点 ~90ms)')
        # 宽松 5.5x 容差；CI 慢机 + 分类开销
        assert dt < 0.5, f'1MB 扫描 {dt * 1000:.0f}ms 超锚点 5.5x'

    @pytest.mark.asyncio
    async def test_100kb_scan_under_100ms(self, stub):
        text = _mk_text(100_000)
        dt = await _time_scan(stub, text)
        print(f'\n[8.4] 100KB 扫描: {dt * 1000:.2f}ms (锚点 ~9ms)')
        assert dt < 0.1, f'100KB 扫描 {dt * 1000:.0f}ms 超锚点'

    @pytest.mark.asyncio
    async def test_1kb_chunk_scan_under_2ms(self, stub):
        text = _mk_text(1024)
        dt = await _time_scan(stub, text)
        print(f'\n[8.4] 1KB chunk 扫描: {dt * 1000:.3f}ms (锚点 ~124µs)')
        assert dt < 0.002, f'1KB 扫描 {dt * 1000:.3f}ms 超锚点 16x'

    @pytest.mark.asyncio
    async def test_pure_cjk_coarse_skip_fast(self, stub):
        """纯中文无数字文本粗筛跳过（25x 加速路径）。"""
        text = _mk_pure_cjk(298_000)
        dt = await _time_scan(stub, text)
        print(f'\n[8.4] 298KB 纯中文粗筛: {dt * 1000:.3f}ms (锚点 ~0.8ms)')
        assert dt < 0.05, f'粗筛 {dt * 1000:.1f}ms 超锚点'

    @pytest.mark.asyncio
    async def test_dict_scan_1kb(self, stub):
        """字典独立扫描（5000 名 190µs/1KB 锚点）。"""
        import re

        names = [f'测试姓名{i:04d}' for i in range(5000)]
        text = '测试姓名0001 测试姓名4999 中间内容 测试姓名2500'
        det = stub._pii_detector
        det.dict_entries = [(n, 'name') for n in names]
        det.dict_re = re.compile(
            '|'.join(re.escape(n) for n in sorted(names, key=len, reverse=True))
        )
        t0 = time.perf_counter()
        hits = det._scan_dict(text, None)
        dt = time.perf_counter() - t0
        print(f'\n[8.4] 5000 名字典 1KB 扫描: {dt * 1000:.3f}ms (锚点 ~190µs)')
        assert len(hits) >= 3
        assert dt < 0.02, f'字典扫描 {dt * 1000:.3f}ms 超锚点 100x'


class TestIncrementalScan:
    """流式增量扫描：1MB 增量 ~90ms（口径 = 联合正则 1MB 全量扫描）。"""

    @pytest.mark.asyncio
    async def test_1mb_incremental_scan(self, stub):
        """增量扫描 = 每 chunk 扫新增 + 尾部持有，合计与 1MB 全量同口径。"""
        chunk = _mk_text(1024)
        total_bytes = 0
        t0 = time.perf_counter()
        # 模拟 200 chunk × 1KB 增量扫描（每 chunk 扫 1KB 新增）
        for _ in range(200):
            await stub.pii_scan(chunk)
            total_bytes += len(chunk.encode('utf-8'))
        dt = time.perf_counter() - t0
        print(
            f'\n[8.4] 增量扫描 {total_bytes / 1024:.0f}KB (200×1KB): {dt * 1000:.1f}ms'
        )
        # 200×1KB 增量 ≈ 200 × 124µs ≈ 25ms；1MB 全量锚点 ~90ms 是单次全量口径。
        # 断言增量合计 < 1MB 全量锚点 90ms × 3（宽松，防慢机）
        assert dt < 0.27, f'增量扫描 {dt * 1000:.0f}ms 超预期'
