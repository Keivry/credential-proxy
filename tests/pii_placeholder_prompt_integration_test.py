"""pii_placeholder_prompt_integration_test.py — 三协议注入端到端集成测试。

覆盖 pii-placeholder-prompt change 任务 5.1/5.2：
- OpenAI chat/completions：脱敏后注入 system 说明 → 上游收到
- Anthropic /v1/messages：顶层 system 注入（字符串/数组）
- Responses API：input[] 注入
- 零脱敏零注入 / 开关关闭零注入 / 自定义文案 / 非 JSON 透传

模式与 pii_stream_integration_test.py 相同：真实 aiohttp 代理 + mock 上游。
"""

import asyncio
import json
import sys
from contextlib import asynccontextmanager

# 清除 aiohttp mock（与 sse_stream_loop_test.py 一致）
for _mod in [m for m in sys.modules if m == 'aiohttp' or m.startswith('aiohttp.')]:
    del sys.modules[_mod]
for _mod in ['_llm', '_token', '_sse', '_pii']:
    sys.modules.pop(_mod, None)

import pytest
from aiohttp import ClientSession, web

sys.path.insert(0, '.')

from _llm import LlmMixin
from _pii import PII_PLACEHOLDER_PROMPT_DEFAULT, PiiMixin
from _token import TokenMixin

UPSTREAM_PORT = 9982
PROXY_PORT = 9981
CHAT_BASE = f'http://127.0.0.1:{PROXY_PORT}/v1/chat/completions'
ANTH_BASE = f'http://127.0.0.1:{PROXY_PORT}/v1/messages'
RESP_BASE = f'http://127.0.0.1:{PROXY_PORT}/v1/responses'
HEADERS = {'Content-Type': 'application/json', 'x-api-key': 'sk-test'}

# 上游捕获脱敏后请求 body，供断言注入
_captured: dict = {}


async def make_upstream():
    """mock 上游：捕获脱敏后请求 body + 回显 token 还原。"""

    def _extract_pii_token(body: dict) -> str:
        raw = json.dumps(body, ensure_ascii=False)
        import re

        m = re.search(r'__PII_\d+_[0-9a-f]{8}__', raw)
        return m.group(0) if m else '__PII_1_ab12cd34__'

    async def handler(request):
        body = json.loads(await request.read())
        _captured['body'] = body
        case = body.get('case', 'echo')
        tok = _extract_pii_token(body)
        resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
        await resp.prepare(request)
        if case == 'chat_echo':
            await resp.write(
                (
                    'data: {"choices":[{"index":0,"delta":{"role":"assistant",'
                    '"content":"号码是 ' + tok + '"}}]}\n\n'
                ).encode()
            )
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'
            )
            await resp.write(b'data: [DONE]\n\n')
        elif case == 'anth_echo':
            await resp.write(b'event: content_block_delta\n')
            await resp.write(
                (
                    'data: {"type":"content_block_delta","index":0,'
                    '"delta":{"type":"text_delta","text":"号码 ' + tok + '"}}\n\n'
                ).encode()
            )
            await resp.write(b'event: message_stop\n')
            await resp.write(b'data: {"type":"message_stop"}\n\n')
        elif case == 'resp_echo':
            await resp.write(
                (
                    'data: {"type":"response.output_text.delta",'
                    '"delta":"号码 ' + tok + '"}\n\n'
                ).encode()
            )
            await resp.write(b'data: {"type":"response.completed"}\n\n')
        else:
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'
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


async def make_proxy(**pii_overrides):
    class Proxy(TokenMixin, PiiMixin, LlmMixin):
        pass

    proxy = Proxy()
    proxy._lock = asyncio.Lock()
    proxy.token_to_pwd = {}
    proxy._token_seq = 0
    proxy.pwd_to_token = {}
    proxy.proxies = {PROXY_PORT: f'http://127.0.0.1:{UPSTREAM_PORT}'}
    proxy._runners = []
    proxy._init_pii()
    proxy.pii_enabled = True
    proxy.pii_response_side = True
    for k, v in pii_overrides.items():
        setattr(proxy, k, v)
    await proxy.start_llm_proxies()
    return proxy


@asynccontextmanager
async def env(**pii_overrides):
    up_runner = await make_upstream()
    proxy = await make_proxy(**pii_overrides)
    _captured.clear()
    try:
        yield proxy
    finally:
        for r in proxy._runners:
            await r.cleanup()
        if proxy._shared_session:
            await proxy._shared_session.close()
        await up_runner.cleanup()


# ═══════════════════════════════════════════════════════════
# 三协议注入
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_integration_openai_injected():
    """OpenAI chat/completions：脱敏后注入 system 说明 → 上游收到。"""
    async with env(), ClientSession() as s:
        body = json.dumps(
            {
                'case': 'chat_echo',
                'messages': [{'role': 'user', 'content': '我的号码是 13800138000'}],
            }
        )
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
        # 上游收到注入的 system 说明
        assert PII_PLACEHOLDER_PROMPT_DEFAULT in json.dumps(
            _captured.get('body', {}), ensure_ascii=False
        )
        msgs = _captured['body']['messages']
        assert msgs[0]['role'] == 'system'
        assert PII_PLACEHOLDER_PROMPT_DEFAULT in msgs[0]['content']
        # 响应侧还原正常
        assert '13800138000' in raw


@pytest.mark.asyncio
async def test_integration_anthropic_injected():
    """Anthropic /v1/messages：顶层 system 注入。"""
    async with env(), ClientSession() as s:
        body = json.dumps(
            {
                'case': 'anth_echo',
                'system': '你是助手',
                'messages': [{'role': 'user', 'content': '我的号码是 13800138000'}],
            }
        )
        async with s.post(ANTH_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
        cap = _captured.get('body', {})
        assert PII_PLACEHOLDER_PROMPT_DEFAULT in cap.get('system', '')
        assert '13800138000' in raw


@pytest.mark.asyncio
async def test_integration_anthropic_system_array_injected():
    """Anthropic /v1/messages：顶层 system 为数组时注入 text block。"""
    async with env(), ClientSession() as s:
        body = json.dumps(
            {
                'case': 'anth_echo',
                'system': [{'type': 'text', 'text': '你是助手'}],
                'messages': [{'role': 'user', 'content': '我的号码是 13800138000'}],
            }
        )
        async with s.post(ANTH_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
        cap = _captured.get('body', {})
        assert isinstance(cap.get('system'), list)
        assert any(
            PII_PLACEHOLDER_PROMPT_DEFAULT in b.get('text', '')
            for b in cap['system']
            if isinstance(b, dict)
        )


@pytest.mark.asyncio
async def test_integration_responses_injected():
    """Responses API：input[] 注入。"""
    async with env(), ClientSession() as s:
        body = json.dumps(
            {
                'case': 'resp_echo',
                'input': [{'role': 'user', 'content': '我的号码是 13800138000'}],
            }
        )
        async with s.post(RESP_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
        cap = _captured.get('body', {})
        assert PII_PLACEHOLDER_PROMPT_DEFAULT in json.dumps(cap, ensure_ascii=False)
        assert cap['input'][0]['role'] == 'system'
        assert '13800138000' in raw


# ═══════════════════════════════════════════════════════════
# 零注入场景
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_integration_no_pii_no_injection():
    """无 PII（无占位符）→ 零注入，请求原样转发。"""
    async with env(), ClientSession() as s:
        body = json.dumps(
            {
                'case': 'plain',
                'messages': [{'role': 'user', 'content': '你好'}],
            }
        )
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
        cap = _captured.get('body', {})
        assert len(cap.get('messages', [])) == 1
        assert cap['messages'][0]['role'] == 'user'


@pytest.mark.asyncio
async def test_integration_switch_disabled_no_injection():
    """PII_PLACEHOLDER_PROMPT 关闭 → 零注入（即使有占位符）。"""
    async with env(pii_placeholder_prompt_enabled=False), ClientSession() as s:
        body = json.dumps(
            {
                'case': 'chat_echo',
                'messages': [{'role': 'user', 'content': '我的号码是 13800138000'}],
            }
        )
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
        cap = _captured.get('body', {})
        raw = json.dumps(cap, ensure_ascii=False)
        assert PII_PLACEHOLDER_PROMPT_DEFAULT not in raw
        # 脱敏仍发生（占位符存在），但说明未注入
        assert '__PII_' in raw


@pytest.mark.asyncio
async def test_integration_custom_prompt_used():
    """自定义文案 → 注入自定义文本而非内置。"""
    custom = 'Keep tokens verbatim please'
    async with env(pii_placeholder_prompt_text=custom), ClientSession() as s:
        body = json.dumps(
            {
                'case': 'chat_echo',
                'messages': [{'role': 'user', 'content': '我的号码是 13800138000'}],
            }
        )
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
        cap = _captured.get('body', {})
        raw = json.dumps(cap, ensure_ascii=False)
        assert custom in raw
        assert PII_PLACEHOLDER_PROMPT_DEFAULT not in raw
