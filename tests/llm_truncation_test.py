"""llm_truncation_test.py — 截断流终止事件策略测试（TSS-01~04）。

覆盖 openspec change truncated-stream-safe-terminal 的 spec 场景：
- TSS-01: 已 complete（seen_global_terminal=true）残留静默丢弃（不合成、不告警）
- TSS-02: 未 complete 文本截断 → open-ended（不合成 finish_reason:stop / [DONE]）
- TSS-03: 未 complete tool_calls 截断 → 丢弃残缺参数 + 不伪造成功
- TSS-04: responses 未 complete 截断 → 合成 response.failed（保留）

与 api_spec_conformance_test.py 同模式：真实 aiohttp，先清 mock。
"""

import asyncio
import json
import sys

# 清除 llm_test 的 aiohttp mock（与 sse_stream_loop_test.py 一致）
for _mod in [m for m in sys.modules if m == 'aiohttp' or m.startswith('aiohttp.')]:
    del sys.modules[_mod]
for _mod in ['_llm', '_token', '_sse']:
    sys.modules.pop(_mod, None)

from contextlib import asynccontextmanager

import pytest
from aiohttp import ClientSession, web

sys.path.insert(0, '.')

from _llm import LlmMixin
from _token import TokenMixin

CHAT_UP = 9972
CHAT_PROXY = 9971
CHAT_BASE = f'http://127.0.0.1:{CHAT_PROXY}/v1/chat/completions'
RESP_UP = 9974
RESP_PROXY = 9973
RESP_BASE = f'http://127.0.0.1:{RESP_PROXY}/v1/responses'
HEADERS = {'Content-Type': 'application/json', 'x-api-key': 'sk-test'}


def sse_blocks(raw: str):
    """按 SSE 规范（空行分隔）解析为 (event_name, data) 块列表。"""
    blocks = []
    for chunk in raw.split('\n\n'):
        chunk = chunk.strip('\n')
        if not chunk:
            continue
        event = None
        data_lines = []
        for ln in chunk.split('\n'):
            if ln.startswith('event:'):
                event = ln[6:].lstrip()
            elif ln.startswith('data:'):
                data_lines.append(ln[5:].lstrip())
        if data_lines:
            blocks.append((event, '\n'.join(data_lines)))
    return blocks


async def make_proxy(port: int, up_port: int):
    class Proxy(TokenMixin, LlmMixin):
        pass

    proxy = Proxy()
    proxy._lock = asyncio.Lock()
    proxy.token_to_pwd = {}
    proxy._token_seq = 0
    proxy.pwd_to_token = {}
    proxy.proxies = {port: f'http://127.0.0.1:{up_port}'}
    proxy._runners = []
    await proxy.start_llm_proxies()
    return proxy


async def make_upstream(up_port: int, handler):
    app = web.Application()
    app.router.add_route('*', '/{tail:.*}', handler)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', up_port)
    await site.start()
    return runner


@asynccontextmanager
async def env(proxy_port: int, up_port: int, handler):
    up_runner = await make_upstream(up_port, handler)
    proxy = await make_proxy(proxy_port, up_port)
    try:
        yield proxy
    finally:
        for r in proxy._runners:
            await r.cleanup()
        await up_runner.cleanup()


# ── TSS-01: 已 complete 残留静默丢弃 ────────────────────────────────


async def _upstream_complete_then_ping(request):
    """上游发送 finish_reason:stop + [DONE] 后，再发半个 ping 事件然后 EOF（残留）。"""
    resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
    await resp.prepare(request)
    await resp.write(
        b'data: {"id":"gen_1","object":"chat.completion.chunk","created":1,'
        b'"model":"m","choices":[{"index":0,"delta":{"content":"hi"},'
        b'"finish_reason":null}]}\n\n'
    )
    await resp.write(
        b'data: {"id":"gen_1","object":"chat.completion.chunk","created":1,'
        b'"model":"m","choices":[{"index":0,"delta":{},'
        b'"finish_reason":"stop"}]}\n\n'
    )
    await resp.write(b'data: [DONE]\n\n')
    # 已 complete 后的半个 ping 事件（无 \n\n，EOF 时 byte_buf 残留）
    await resp.write(b'event: ping\ndata: {"type":"ping","cost":"0"}')
    # 正常 EOF（循环正常结束 → 走截断检测；已 complete 不判截断 → 静默丢弃残留）
    await resp.write_eof()
    return resp


@pytest.mark.asyncio
async def test_tss01_complete_residual_silent_discard():
    """已 complete + 尾部 ping 残留 → 静默丢弃，无合成，无 [DONE] 重复。"""
    async with (
        env(CHAT_PROXY, CHAT_UP, _upstream_complete_then_ping) as _proxy,
        ClientSession() as s,
    ):
        body = json.dumps(
            {
                'case': 'complete_then_ping',
                'messages': [{'role': 'user', 'content': 'hi'}],
            }
        )
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()

    blocks = sse_blocks(raw)
    # 必须恰 1 个 [DONE]（上游发的），无合成事件
    assert sum(1 for _, d in blocks if d == '[DONE]') == 1, f'[DONE] 数量异常: {blocks}'
    # 无截断合成文本
    assert '被截断' not in raw, f'误判截断合成: {raw!r}'
    # 无重复合成 finish_reason:stop（上游已发，proxy 不补）
    stops = [d for _, d in blocks if '"finish_reason":"stop"' in d]
    assert len(stops) == 1, f'finish_reason:stop 数量异常: {blocks}'
    # 尾部残留的半个 ping：event 行经 slow_event_pending 保真透传（无害，非合成终止），
    # data 行丢弃；核心是「已 complete 不合成截断事件」
    assert 'event: ping' in raw  # slow_event_pending 保真透传（既有行为）
    assert '{"type":"ping"' not in raw  # data 残留被丢弃
    # 无合成事件（已 complete 不注入：blocks 恰 3 个 = content + stop + [DONE]）
    assert len(blocks) == 3, f'合成事件被注入: {blocks}'


# ── TSS-02: 未 complete 文本截断 → open-ended ──────────────────────


async def _upstream_mid_reasoning_cut(request):
    """上游发 reasoning 分片后 EOF（无 finish_reason / [DONE]，byte_buf 残留半截行）。"""
    resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
    await resp.prepare(request)
    await resp.write(
        b'data: {"id":"gen_2","object":"chat.completion.chunk","created":1,'
        b'"model":"m","choices":[{"index":0,"delta":{"reasoning":"step1"},'
        b'"finish_reason":null}]}\n\n'
    )
    await resp.write(
        b'data: {"id":"gen_2","object":"chat.completion.chunk","created":1,'
        b'"model":"m","choices":[{"index":0,"delta":{"reasoning":"step2"},'
        b'"finish_reason":null}]}\n\n'
    )
    # 残留半截行（无 \n\n，EOF 时 byte_buf 残留）
    await resp.write(b'data: {"id":"gen_2","object":"chat.completion.chunk"')
    await resp.write_eof()
    return resp


@pytest.mark.asyncio
async def test_tss02_mid_text_truncation_open_ended():
    """未 complete 文本截断 → 不合成 finish_reason:stop / [DONE]，流 open-ended。"""
    async with (
        env(CHAT_PROXY, CHAT_UP, _upstream_mid_reasoning_cut) as _proxy,
        ClientSession() as s,
    ):
        body = json.dumps(
            {'case': 'mid_cut', 'messages': [{'role': 'user', 'content': 'x'}]}
        )
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()

    # 已透传的 reasoning 分片保留
    assert 'step1' in raw and 'step2' in raw, f'已透传分片丢失: {raw!r}'
    # 不合成 finish_reason:stop
    assert '"finish_reason":"stop"' not in raw, f'伪造成功终止: {raw!r}'
    # 不补发 [DONE]
    assert '[DONE]' not in raw, f'伪造 [DONE]: {raw!r}'
    # 无截断合成文本
    assert '被截断' not in raw, f'截断合成: {raw!r}'


# ── TSS-03: 未 complete tool_calls 截断 → 丢弃残缺参数 ─────────────


async def _upstream_mid_tool_calls_cut(request):
    """上游发 tool_calls arguments 分片后 EOF（无 finish_reason / [DONE]，残留半截行）。"""
    resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
    await resp.prepare(request)
    await resp.write(
        b'data: {"id":"gen_3","object":"chat.completion.chunk","created":1,'
        b'"model":"m","choices":[{"index":0,"delta":{"tool_calls":['
        b'{"index":0,"id":"call_1","type":"function",'
        b'"function":{"name":"bash","arguments":"{\\"cmd\\":\\"rm"}}]},'
        b'"finish_reason":null}]}\n\n'
    )
    await resp.write(
        b'data: {"id":"gen_3","object":"chat.completion.chunk","created":1,'
        b'"model":"m","choices":[{"index":0,"delta":{"tool_calls":['
        b'{"index":0,"function":{"arguments":" -rf /"}}]},'
        b'"finish_reason":null}]}\n\n'
    )
    # 残留半截行
    await resp.write(b'data: {"id":"gen_3","object":"chat.completion.chunk"')
    await resp.write_eof()
    return resp


@pytest.mark.asyncio
async def test_tss03_mid_tool_calls_truncation_drop():
    """未 complete tool_calls 截断 → 不伪造 finish_reason:stop / [DONE]。"""
    async with (
        env(CHAT_PROXY, CHAT_UP, _upstream_mid_tool_calls_cut) as _proxy,
        ClientSession() as s,
    ):
        body = json.dumps(
            {'case': 'mid_tool_cut', 'messages': [{'role': 'user', 'content': 'x'}]}
        )
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()

    # 不合成 finish_reason:stop（下游 Hermes 会因 finish_reason is None 走 drop 保护）
    assert '"finish_reason":"stop"' not in raw, f'伪造成功终止: {raw!r}'
    # 不补发 [DONE]
    assert '[DONE]' not in raw, f'伪造 [DONE]: {raw!r}'
    # 无截断合成文本
    assert '被截断' not in raw, f'截断合成: {raw!r}'


# ── TSS-04: responses 未 complete 截断 → 合成 failed ───────────────


async def _upstream_responses_mid_cut(request):
    """responses 上游发 output_text.delta 后 EOF（无 response.completed，残留半截行）。"""
    resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
    await resp.prepare(request)
    await resp.write(
        b'event: response.output_text.delta\ndata: {"type":"response.output_text.delta",'
        b'"sequence_number":0,"delta":"Hel","item_id":"it_1","output_index":0}\n\n'
    )
    await resp.write(
        b'event: response.output_text.delta\ndata: {"type":"response.output_text.delta",'
        b'"sequence_number":1,"delta":"lo","item_id":"it_1","output_index":0}\n\n'
    )
    # 残留半截行
    await resp.write(b'event: response.output_text.delta\ndata: {"type":"response.')
    await resp.write_eof()
    return resp


@pytest.mark.asyncio
async def test_tss04_responses_truncation_synthesizes_failed():
    """responses 未 complete 截断 → 合成 response.failed（协议失败语义保留）。"""
    async with (
        env(RESP_PROXY, RESP_UP, _upstream_responses_mid_cut) as _proxy,
        ClientSession() as s,
    ):
        body = json.dumps({'case': 'resp_mid_cut', 'input': 'x'})
        async with s.post(RESP_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()

    # 已透传的 delta 保留
    assert 'Hel' in raw and 'lo' in raw, f'已透传 delta 丢失: {raw!r}'
    # 合成 response.failed
    assert 'response.failed' in raw, f'未合成 response.failed: {raw!r}'
    # 且包含截断语义
    assert '被截断' in raw or 'truncated' in raw, f'failed 无截断语义: {raw!r}'
