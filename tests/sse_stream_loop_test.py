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

# 重试测试专用端口（避免与 env() fixture 冲突）
FLAKY_UPSTREAM_PORT = 9934
FLAKY_PROXY_PORT = 9933
FLAKY_BASE = f'http://127.0.0.1:{FLAKY_PROXY_PORT}/v1/messages'


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
        elif case == 'whatwg_framing':
            # 3.2 分帧语义对齐：注释透传 / retry 仅 ASCII 数字 /
            # data 冒号后单空格剥离（快链与慢链同口径）
            await resp.write(b': keepalive-marker-32xyz\n\n')
            await resp.write(b'retry: 250\n\n')
            await resp.write(b'retry: abc\n\n')
            await resp.write('retry: ２５０\n\n'.encode())
            await resp.write(b'data:{"type":"message_stop"}\n\n')
            await resp.write(
                b'data:  {"type":"content_block_delta","index":0,'
                b'"delta":{"type":"text_delta","text":"spaced"}}\n\n'
            )
            await resp.write(b'data: {"type":"message_stop"}\n\n')
        elif case == 'restore_fidelity':
            # 5.2 事件重建保真：上游 chunk 含 id/created/model/usage
            await resp.write(
                b'data: {"id":"chatcmpl_1","object":"chat.completion.chunk",'
                b'"created":1234567890,"model":"gpt-4o","choices":[{"index":0,'
                b'"delta":{"content":"hello"},"finish_reason":null}]}\n\n'
            )
            await resp.write(
                b'data: {"id":"chatcmpl_1","object":"chat.completion.chunk",'
                b'"created":1234567890,"model":"gpt-4o","choices":[{"index":0,'
                b'"delta":{"content":" world"},"finish_reason":"stop"}],'
                b'"usage":{"prompt_tokens":10,"completion_tokens":5,'
                b'"total_tokens":15}}\n\n'
            )
        elif case == 'choices_n2':
            # 5.2 n=2 双路：同事件两路不同 content/finish_reason
            await resp.write(
                b'data: {"id":"chatcmpl_1","object":"chat.completion.chunk",'
                b'"created":1234567890,"model":"gpt-4o","choices":[{"index":0,'
                b'"delta":{"content":"alpha"},"finish_reason":"stop"},'
                b'{"index":1,'
                b'"delta":{"content":"beta"},"finish_reason":"tool_calls"}]}\n\n'
            )
        elif case == 'whatwg_cr':
            # 3.2 CR-only 分隔流：\r 与 \n 同为行分隔符
            # （每事件 data 行后跟 \r 空行分隔，与 LF 流等价）
            await resp.write(
                b'data: {"type":"content_block_delta","index":0,'
                b'"delta":{"type":"text_delta","text":"cr-one"}}\r\r'
            )
            await resp.write(
                b'data: {"type":"content_block_delta","index":0,'
                b'"delta":{"type":"text_delta","text":"cr-two"}}\r\r'
            )
            await resp.write(b'data: {"type":"message_stop"}\r\r')
        elif case == 'multi_data_lines':
            # 5.5 同事件多行 data：两 data 行同属一事件块（一次空行分隔）
            await resp.write(
                b'data: {"type":"content_block_delta","index":0,'
                b'"delta":{"type":"text_delta","text":"multi-one"}}\n'
                b'data: {"type":"content_block_delta","index":0,'
                b'"delta":{"type":"text_delta","text":"multi-two"}}\n\n'
            )
            await resp.write(b'data: {"type":"message_stop"}\n\n')
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


@pytest.mark.asyncio
async def test_fast_whatwg_framing_parity():
    """3.2 分帧语义对齐：快链与慢链同款 WHATWG 三语义（三个独立 assert）。"""
    async with env(), ClientSession() as s:
        body = json.dumps({'case': 'whatwg_framing'})
        async with s.post(BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
    assert ': keepalive-marker-32xyz' in raw
    assert 'retry: 250' in raw
    assert 'retry: abc' not in raw
    assert '２５０' not in raw
    data_lines = [ln for ln in raw.splitlines() if ln.startswith('data:')]
    assert len(data_lines) >= 3
    for ln in data_lines:
        json.loads(ln[5:].lstrip())
    assert '"text":"spaced"' in raw
    assert 'data: {"type":"message_stop"}' in raw


@pytest.mark.asyncio
async def test_fast_cr_split_parity():
    """3.2 回车分隔流快慢一致：CR-only 行按行切分且每行可解析。"""
    async with env(), ClientSession() as s:
        body = json.dumps({'case': 'whatwg_cr'})
        async with s.post(BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
    assert '"text":"cr-one"' in raw
    assert '"text":"cr-two"' in raw
    data_lines = [ln for ln in raw.splitlines() if ln.startswith('data:')]
    assert len(data_lines) >= 3
    for ln in data_lines:
        json.loads(ln[5:].lstrip())


@pytest.mark.asyncio
async def test_restore_fidelity_fields():
    """5.2 保真断言必需：下游同事件 id/created/model 一致、usage 数值不变。"""
    async with env(), ClientSession() as s:
        body = json.dumps({'case': 'restore_fidelity'})
        async with s.post(BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
    data_lines = [ln for ln in raw.splitlines() if ln.startswith('data:')]
    assert len(data_lines) >= 2
    objs = [json.loads(ln[5:].lstrip()) for ln in data_lines]
    for obj in objs:
        assert obj['id'] == 'chatcmpl_1'
        assert obj['created'] == 1234567890
        assert obj['model'] == 'gpt-4o'
    usages = [o.get('usage') for o in objs if o.get('usage') is not None]
    assert len(usages) >= 1
    assert usages[-1] == {
        'prompt_tokens': 10,
        'completion_tokens': 5,
        'total_tokens': 15,
    }


@pytest.mark.asyncio
async def test_choices_n2_no_broadcast():
    """5.2 独立断言必需：n=2 各路各自文本且 finish_reason 按 index 保留。"""
    async with env(), ClientSession() as s:
        body = json.dumps({'case': 'choices_n2'})
        async with s.post(BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
    data_lines = [ln for ln in raw.splitlines() if ln.startswith('data:')]
    assert len(data_lines) >= 1
    obj = json.loads(data_lines[0][5:].lstrip())
    by_index = {c['index']: c for c in obj['choices']}
    assert by_index[0]['delta']['content'] == 'alpha'
    assert by_index[0]['finish_reason'] == 'stop'
    assert by_index[1]['delta']['content'] == 'beta'
    assert by_index[1]['finish_reason'] == 'tool_calls'
    assert 'beta' not in by_index[0]['delta']['content']
    assert 'alpha' not in by_index[1]['delta']['content']


@pytest.mark.asyncio
async def test_multi_data_lines_dispatched_per_line():
    """5.5 多 data 行逐条解析：同事件两 data 行按原序输出，每行可解析。"""
    async with env(), ClientSession() as s:
        body = json.dumps({'case': 'multi_data_lines'})
        async with s.post(BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
    assert raw.index('multi-one') < raw.index('multi-two')
    data_lines = [ln for ln in raw.splitlines() if ln.startswith('data:')]
    assert len(data_lines) >= 3
    for ln in data_lines:
        json.loads(ln[5:].lstrip())


@pytest.mark.asyncio
async def test_upstream_disconnect_retry():
    """上游首次在响应头前断开连接（ServerDisconnectedError）→ 代理重试第二次成功。

    模拟用户环境现象：opencode-go 网关间歇性 Server disconnected。
    断言：客户端最终拿到 200 + 正常 SSE；上游被调用 2 次（1 次断开 + 1 次重试）。
    """
    call_count = 0

    async def flaky_handler(request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # 在响应头发送前关闭 TCP 连接，模拟上游主动断开（FIN → ServerDisconnectedError）
            request.transport.close()
            return web.Response(status=503)
        resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
        await resp.prepare(request)
        await resp.write(b'event: message_start\n')
        await resp.write(
            b'data: {"type":"message_start","message":{"id":"msg_retry"}}\n\n'
        )
        await resp.write(b'data: {"type":"message_stop"}\n\n')
        await resp.write_eof()
        return resp

    app = web.Application()
    app.router.add_route('*', '/{tail:.*}', flaky_handler)
    up_runner = web.AppRunner(app, access_log=None)
    await up_runner.setup()
    await web.TCPSite(up_runner, '127.0.0.1', FLAKY_UPSTREAM_PORT).start()

    class Proxy(TokenMixin, LlmMixin):
        pass

    proxy = Proxy()
    proxy._lock = asyncio.Lock()
    proxy.token_to_pwd = {}
    proxy._token_seq = 0
    proxy.pwd_to_token = {}
    proxy.proxies = {FLAKY_PROXY_PORT: f'http://127.0.0.1:{FLAKY_UPSTREAM_PORT}'}
    proxy._runners = []
    await proxy.start_llm_proxies()
    try:
        async with ClientSession() as s:
            body = json.dumps({'case': 'normal'})
            async with s.post(FLAKY_BASE, headers=HEADERS, data=body) as r:
                assert r.status == 200
                raw = await r.text()
                assert '"type":"message_stop"' in raw
        assert call_count == 2, (
            f'上游应被调用 2 次（1 次断开 + 1 次重试），实际 {call_count}'
        )
    finally:
        for r in proxy._runners:
            await r.cleanup()
        if proxy._shared_session:
            await proxy._shared_session.close()
        await up_runner.cleanup()
