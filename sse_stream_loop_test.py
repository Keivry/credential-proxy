"""test_sse_stream_loop.py — SSE 主循环集成测试（续行重建路径）。

覆盖: 跨行 JSON 数组/字符串（non-dict payload）原样透传不崩溃、
正常 Anthropic 流、[DONE] 后透传。

注意: 本文件使用真实 aiohttp（起 mock 上游 + 真实代理），
与 test_llm.py（mock aiohttp 的纯单元测试）互补。
"""

import asyncio
import json
import sys
from contextlib import asynccontextmanager

# test_llm.py 的模块级 aiohttp mock 会污染同一进程（按字母序 test_llm 先导入）；
# 本文件需要真实 aiohttp，先清除 mock 再重新导入真实模块与 _llm/_token
for _mod in [m for m in sys.modules if m == 'aiohttp' or m.startswith('aiohttp.')]:
    del sys.modules[_mod]
for _mod in ['_llm', '_token', '_sse']:
    sys.modules.pop(_mod, None)

import pytest
from aiohttp import ClientSession, web

sys.path.insert(0, '.')

from _llm import LlmMixin
from _token import TokenMixin

UPSTREAM_PORT = 9932
PROXY_PORT = 9931
BASE = f'http://127.0.0.1:{PROXY_PORT}/v1/messages'
HEADERS = {'Content-Type': 'application/json', 'x-api-key': 'sk-test'}


async def make_upstream():
    """起 mock 上游：按请求 body 的 case 返回不同 SSE 流。"""

    async def handler(request):
        body = json.loads(await request.read())
        case = body.get('case', 'normal')
        resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
        await resp.prepare(request)
        if case == 'multi_line_array':
            # 续行重建路径：跨行 JSON 数组（non-dict payload）
            await resp.write(b'data: [1,\n')
            await resp.write(b'2]\n\n')
            await resp.write(b'data: {"type":"message_stop"}\n\n')
        elif case == 'multi_line_string':
            # 续行重建路径：跨行 JSON 字符串
            await resp.write(b'data: "hel\n')
            await resp.write(b'lo"\n\n')
            await resp.write(b'data: {"type":"message_stop"}\n\n')
        elif case == 'normal':
            # 正常 Anthropic 流
            await resp.write(b'event: message_start\n')
            await resp.write(
                b'data: {"type":"message_start","message":{"id":"msg_1"}}\n\n'
            )
            await resp.write(b'event: content_block_delta\n')
            await resp.write(
                b'data: {"type":"content_block_delta","index":0,'
                b'"delta":{"type":"text_delta","text":"hello"}}\n\n'
            )
            await resp.write(b'event: message_stop\n')
            await resp.write(b'data: {"type":"message_stop"}\n\n')
        elif case == 'done_marker':
            # 兼容网关发 [DONE]
            await resp.write(
                b'data: {"type":"content_block_delta","index":0,'
                b'"delta":{"type":"text_delta","text":"hi"}}\n\n'
            )
            await resp.write(b'data: [DONE]\n\n')
        await resp.write_eof()
        return resp

    app = web.Application()
    app.router.add_route('*', '/{tail:.*}', handler)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, '127.0.0.1', UPSTREAM_PORT).start()
    return runner


async def make_proxy():
    class Proxy(TokenMixin, LlmMixin):
        pass

    proxy = Proxy()
    proxy._lock = asyncio.Lock()
    proxy.token_to_pwd = {}
    proxy._token_seq = 0
    proxy.pwd_to_token = {}
    proxy.proxies = {PROXY_PORT: f'http://127.0.0.1:{UPSTREAM_PORT}'}
    proxy._runners = []
    await proxy.start_llm_proxies()
    return proxy


@asynccontextmanager
async def env():
    up_runner = await make_upstream()
    proxy = await make_proxy()
    try:
        yield proxy
    finally:
        for r in proxy._runners:
            await r.cleanup()
        if proxy._shared_session:
            await proxy._shared_session.close()
        await up_runner.cleanup()


@pytest.mark.asyncio
async def test_multiline_array_passthrough():
    """🟡-1 回归：跨行 JSON 数组不崩溃、原样透传。"""
    async with env(), ClientSession() as s:
        body = json.dumps({'case': 'multi_line_array'})
        async with s.post(BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
            assert 'data: [1,' in raw
            assert '2]' in raw
            assert 'message_stop' in raw


@pytest.mark.asyncio
async def test_multiline_string_passthrough():
    """跨行 JSON 字符串同样透传。"""
    async with env(), ClientSession() as s:
        body = json.dumps({'case': 'multi_line_string'})
        async with s.post(BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
            assert '"hel' in raw
            assert 'lo"' in raw
            assert 'message_stop' in raw


@pytest.mark.asyncio
async def test_normal_anthropic_stream():
    """正常 Anthropic 流：事件行 + data 行保持。"""
    async with env(), ClientSession() as s:
        body = json.dumps({'case': 'normal'})
        async with s.post(BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
            assert 'event: message_start' in raw
            assert '"type":"message_stop"' in raw
            assert '"type":"content_block_delta"' in raw
            assert '"text":"hello"' in raw


@pytest.mark.asyncio
async def test_done_marker_passthrough():
    """兼容网关 [DONE] 标记透传，不破坏流。"""
    async with env(), ClientSession() as s:
        body = json.dumps({'case': 'done_marker'})
        async with s.post(BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
            assert 'data: [DONE]' in raw
            assert '"text":"hi"' in raw
