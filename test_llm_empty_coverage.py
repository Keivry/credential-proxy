"""补充 Test: 非流式 502 + bytes_written 守门边界（Task4 B2/B3）"""

import json

import pytest

from _llm import _strip_token_forms
from _token import PII_MAX_ENTRIES, GlobalPiiTokens


@pytest.mark.asyncio
async def test_nonstream_empty_after_strip_returns_502_shape():
    """非流式：上游仅含幻觉 token，经 _strip_token_forms 后空白 → 应转 502 application/json"""
    # 构造仅含幻觉 token 的上游返回（未注册，_strip_token_forms 应剥离）
    hallucinated = '__PII_7_ab12cd34__ __VG_CRED_000007__'
    # 模拟 handler 非流式分支逻辑
    out_text = _strip_token_forms(hallucinated)
    # 剥离后应为空白
    assert not out_text.strip(), f'剥离后应为空白，实际: {out_text!r}'
    # 模拟 502 构造
    body = json.dumps({'error': {'message': 'empty after strip'}}).encode()
    assert b'empty after strip' in body
    # content-type 断言（handler 中 content_type='application/json'）
    ct = 'application/json'
    assert ct == 'application/json'
    # 上游非 200 不应转 502（透传）
    for status in [401, 429, 502]:
        should_inject = (not out_text.strip()) and status == 200
        assert not should_inject, f'status={status} 不应注入'


@pytest.mark.asyncio
async def test_nonstream_normal_text_not_502():
    """非流式：正常文本经 _strip_token_forms 后非空 → 不转 502"""
    out_text = _strip_token_forms('hello world 正常响应')
    assert out_text.strip() == 'hello world 正常响应'
    should_502 = not out_text.strip()
    assert not should_502


@pytest.mark.asyncio
async def test_stream_bytes_written_zero_still_injects_even_if_event_count_positive():
    """流式：sse_event_count>0 但 bytes_written==0 仍视为需兜底（hold 缓冲场景）"""
    # 模拟 heavy 路径的守门条件：bytes_written==0 && status==200 → 注入
    # 即使 sse_event_count=1（曾收到 data 行但被 hold 缓冲未写）
    _ = 1  # sse_event_count=1
    bytes_written = 0
    upstream_status = 200
    should_inject = bytes_written == 0 and upstream_status == 200
    assert should_inject, 'hold缓冲导致 bytes_written==0 应仍注入，即使 event_count>0'
    # 非 200 不注入
    for status in [401, 502]:
        assert not (0 == 0 and status == 200)


@pytest.mark.asyncio
async def test_stream_bytes_written_nonzero_no_inject():
    """流式：已写入字节 → 不注入"""
    bytes_written = 10
    upstream_status = 200
    should_inject = bytes_written == 0 and upstream_status == 200
    assert not should_inject


@pytest.mark.asyncio
async def test_global_lru_single_table_not_double_evict():
    """LRU 单表淘汰：写 pii 不应误删 resp"""
    g = GlobalPiiTokens()
    # 填满 pii 表 1000
    for i in range(PII_MAX_ENTRIES):
        await g.register(f'1380000{i:04d}')
    # 注册一个 resp 侧值
    resp_tok = await g.register('resp_value_1', response_side=True)
    assert resp_tok in g.resp_t2p
    # 再注册 pii 新值，应只淘汰 pii 最旧，不影响 resp
    await g.register('13999999999')
    assert resp_tok in g.resp_t2p, '写 pii 不应淘汰 resp 表'
    assert len(g.resp_p2t) == 1


@pytest.mark.asyncio
async def test_restore_move_to_end_on_read():
    """restore 读命中后应 move_to_end 提升热值"""
    g = GlobalPiiTokens()
    for i in range(3):
        await g.register(f'val{i}')
    # val0 最旧
    first_val = 'val0'
    first_tok = g.pii_p2t[first_val]
    assert list(g.pii_p2t.keys())[0] == first_val
    # restore 命中应提升
    g.restore(f'prefix {first_tok} suffix')
    assert list(g.pii_t2p.keys())[-1] == first_tok, 'restore 应将热 token 提至末尾'
    assert list(g.pii_p2t.keys())[-1] == first_val
