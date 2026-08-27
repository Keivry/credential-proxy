"""真实截断 session dump 隔离回归（TSS-05）。

用 2026-08-27 真实截断请求的 response_original.jsonl 尾部子集喂给 proxy，
验证 TSS-01~04 修复后行为符合 spec：
- req_1492e320eafb451c（chat reasoning 截断，seen_terminal:false）→ open-ended
- req_ffaa34a13da4403d（chat tool_calls 截断，seen_terminal:false）→ 不伪造成功

只取尾部子集（~8 行 + 半截残留），不喂全量（5881/1038 行）。
"""

import asyncio
import json
import sys

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

CHAT_UP = 9982
CHAT_PROXY = 9981
CHAT_BASE = f'http://127.0.0.1:{CHAT_PROXY}/v1/chat/completions'
HEADERS = {'Content-Type': 'application/json', 'x-api-key': 'sk-test'}

# 真实尾部子集（来自 req_1492e320eafb451c，reasoning 截断）
REAL_REASONING_TAIL = [
    '{"id":"gen_01M11VGC8TCVG6B0AHGF2GPK2K","object":"chat.completion.chunk","created":1787842540,"model":"deepseek/deepseek-v4-flash","choices":[{"index":0,"delta":{"reasoning":"```\\n","reasoning_details":[{"type":"reasoning.text","text":"```\\n","format":"unknown","index":0}]},"logprobs":null,"finish_reason":null}],"system_fingerprint":"fp_cup16snbjn"}',
    '{"id":"gen_01M11VGC8TCVG6B0AHGF2GPK2K","object":"chat.completion.chunk","created":1787842540,"model":"deepseek/deepseek-v4-flash","choices":[{"index":0,"delta":{"reasoning":"-" },"logprobs":null,"finish_reason":null}],"system_fingerprint":"fp_cup16snbjn"}',
]

# 真实尾部子集（来自 req_ffaa34a13da4403d，tool_calls 截断）
REAL_TOOLCALLS_TAIL = [
    '{"id":"gen_01M11RXCVQRSRCVCTEG1JBMFST","object":"chat.completion.chunk","created":1787839821,"model":"deepseek/deepseek-v4-flash","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":" ≠"}}]},"logprobs":null,"finish_reason":null}],"system_fingerprint":"fp_n5ppn70myq"}',
    '{"id":"gen_01M11RXCVQRSRCVCTEG1JBMFST","object":"chat.completion.chunk","created":1787839821,"model":"deepseek/deepseek-v4-flash","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":" "}}]},"logprobs":null,"finish_reason":null}],"system_fingerprint":"fp_n5ppn70myq"}',
]


def sse_blocks(raw: str):
    blocks = []
    for chunk in raw.split('\n\n'):
        chunk = chunk.strip('\n')
        if not chunk:
            continue
        data_lines = []
        for ln in chunk.split('\n'):
            if ln.startswith('data:'):
                data_lines.append(ln[5:].lstrip())
        if data_lines:
            blocks.append('\n'.join(data_lines))
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


def _make_handler(tail_lines: list):
    async def handler(request):
        resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
        await resp.prepare(request)
        for ln in tail_lines:
            await resp.write(f'data: {ln}\n\n'.encode())
        # 半截残留（EOF 时 byte_buf 残留）
        await resp.write(b'data: {"id":"gen_real","object":"chat.completion.chunk"')
        await resp.write_eof()
        return resp

    return handler


@pytest.mark.asyncio
async def test_real_reasoning_truncation_open_ended():
    """真实 reasoning 截断（req_1492）→ open-ended，不伪造成功终止。"""
    async with (
        env(CHAT_PROXY, CHAT_UP, _make_handler(REAL_REASONING_TAIL)) as _proxy,
        ClientSession() as s,
    ):
        body = json.dumps(
            {'case': 'real_reasoning', 'messages': [{'role': 'user', 'content': 'x'}]}
        )
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()

    # 已透传的 reasoning 保留
    assert 'reasoning' in raw, f'reasoning 丢失: {raw!r}'
    # 不合成 finish_reason:stop / [DONE]
    assert '"finish_reason":"stop"' not in raw, f'伪造成功终止: {raw!r}'
    assert 'data: [DONE]' not in raw, f'伪造 [DONE]: {raw!r}'
    # 无截断合成文本
    assert '被截断' not in raw, f'截断合成: {raw!r}'


@pytest.mark.asyncio
async def test_real_toolcalls_truncation_no_fake_success():
    """真实 tool_calls 截断（req_ffaa）→ 不伪造成功，残缺参数不执行。"""
    async with (
        env(CHAT_PROXY, CHAT_UP, _make_handler(REAL_TOOLCALLS_TAIL)) as _proxy,
        ClientSession() as s,
    ):
        body = json.dumps(
            {'case': 'real_toolcalls', 'messages': [{'role': 'user', 'content': 'x'}]}
        )
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()

    # 已透传的 tool_calls 分片保留
    assert 'tool_calls' in raw, f'tool_calls 丢失: {raw!r}'
    # 不合成 finish_reason:stop / [DONE]（下游 Hermes 走 mid-tool-call drop 保护）
    assert '"finish_reason":"stop"' not in raw, f'伪造成功终止: {raw!r}'
    assert 'data: [DONE]' not in raw, f'伪造 [DONE]: {raw!r}'
    # 无截断合成文本
    assert '被截断' not in raw, f'截断合成: {raw!r}'
