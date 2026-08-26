"""audit_stream_test.py — Batch 4 真实 aiohttp 流式审计集成测试。

覆盖 design D4 触发点：
- OpenAI chat/completions：delta.tool_calls 分片累积 → finish_reason=='tool_calls' 审计触发
- OpenAI 流末 [DONE] 兜底审计（finish_reason 未出现）
- Anthropic Messages：block_start → input_json_delta 分片 → block_stop 审计
- 非流式 chat/completions：整包 tool_calls 提取 + 审计

注意：与 sse_stream_loop_test.py 同模式（真实 aiohttp，先清 mock）。
"""

import asyncio
import json
import sys
from contextlib import asynccontextmanager

# 与 sse_stream_loop_test.py 一致：清除 llm_test 的 aiohttp mock
for _mod in [m for m in sys.modules if m == 'aiohttp' or m.startswith('aiohttp.')]:
    del sys.modules[_mod]
for _mod in ['_llm', '_token', '_sse']:
    sys.modules.pop(_mod, None)

import pytest
from aiohttp import ClientSession, web

sys.path.insert(0, '.')

from _llm import LlmMixin
from _token import TokenMixin

UPSTREAM_PORT = 9942
PROXY_PORT = 9941
CHAT_BASE = f'http://127.0.0.1:{PROXY_PORT}/v1/chat/completions'
ANTH_BASE = f'http://127.0.0.1:{PROXY_PORT}/v1/messages'
HEADERS = {'Content-Type': 'application/json', 'x-api-key': 'sk-test'}


async def make_upstream():
    """mock 上游：按 case 返回不同响应。"""

    async def handler(request):
        body = json.loads(await request.read())
        case = body.get('case', 'normal')
        # 非流式 chat/completions（危险 tool call）
        if case == 'non_stream_danger':
            return web.json_response(
                {
                    'id': 'chatcmpl-1',
                    'choices': [
                        {
                            'index': 0,
                            'finish_reason': 'tool_calls',
                            'message': {
                                'role': 'assistant',
                                'content': None,
                                'tool_calls': [
                                    {
                                        'id': 'call_1',
                                        'type': 'function',
                                        'function': {
                                            'name': 'bash',
                                            'arguments': '{"cmd":"rm -rf /"}',
                                        },
                                    }
                                ],
                            },
                        }
                    ],
                }
            )
        # 流式 OpenAI tool_calls 分片（finish_reason 触发审计）
        if case == 'stream_tool_calls':
            resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
            await resp.prepare(request)
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"role":"assistant","content":null}}]}\n\n'
            )
            # name 分片 1
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"bas","arguments":""}}]}}]}\n\n'
            )
            # name 分片 2 + args 开头
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"h","arguments":"{\\"cmd\\":"}}]}}]}\n\n'
            )
            # args 继续
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\\"ls -la\\"}"}}]}}]}\n\n'
            )
            # finish_reason
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n'
            )
            await resp.write(b'data: [DONE]\n\n')
            await resp.write_eof()
            return resp
        # 流式 OpenAI tool_calls 无 finish_reason（[DONE] 兜底审计）
        if case == 'stream_tool_calls_no_finish':
            resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
            await resp.prepare(request)
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\\"path\\":\\"/etc/passwd\\"}"}}]}}]}\n\n'
            )
            await resp.write(b'data: [DONE]\n\n')
            await resp.write_eof()
            return resp
        # 流式 OpenAI tool_calls + 阻断后 content（真实流量发现的回归：
        # tool_calls_blocked 曾永久跳过后续行，后续 content 丢失）
        if case == 'stream_tool_calls_then_content':
            resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
            await resp.prepare(request)
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"role":"assistant","content":null}}]}\n\n'
            )
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"bash","arguments":"{\\"cmd\\":\\"rm -rf /important\\"}"}}]},"finish_reason":null}]}\n\n'
            )
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n'
            )
            # 阻断后模型继续输出说明文字
            await resp.write(
                'data: {"choices":[{"index":0,"delta":{"content":"我已执行该命令，输出如下。"},"finish_reason":null}]}\n\n'.encode()
            )
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'
            )
            await resp.write(b'data: [DONE]\n\n')
            await resp.write_eof()
            return resp
        # Anthropic tool_use 流
        if case == 'anthropic_tool_use':
            resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
            await resp.prepare(request)
            await resp.write(b'event: content_block_start\n')
            await resp.write(
                b'data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash"}}\n\n'
            )
            await resp.write(b'event: content_block_delta\n')
            await resp.write(
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"cmd\\":\\"curl 8.8.8.8\\"}"}}\n\n'
            )
            await resp.write(b'event: content_block_stop\n')
            await resp.write(b'data: {"type":"content_block_stop","index":0}\n\n')
            await resp.write(b'event: message_stop\n')
            await resp.write(b'data: {"type":"message_stop"}\n\n')
            await resp.write_eof()
            return resp
        # 默认正常流
        resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
        await resp.prepare(request)
        await resp.write(
            b'data: {"choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":"stop"}]}\n\n'
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
    proxy.audited_calls: list[tuple[str, str]] = []
    proxy._audit_arg_accum = ''
    proxy._last_anthropic_tool_name = None
    proxy._last_responses_tool_name = None
    await proxy.start_llm_proxies()
    return proxy


class AuditProxy:
    """包装 Proxy 提供 audit 覆盖。"""

    def __init__(self, proxy):
        self._p = proxy

    def audit_enabled(self):
        return True

    async def audit_tool_call(self, name, args_json):
        self._p.audited_calls.append((name, args_json))
        return 'allow'

    @property
    def audited_calls(self):
        return self._p.audited_calls


@asynccontextmanager
async def env():
    up_runner = await make_upstream()
    proxy = await make_proxy()
    # 注入审计覆盖
    ap = AuditProxy(proxy)
    proxy.audit_enabled = ap.audit_enabled
    proxy.audit_tool_call = ap.audit_tool_call
    try:
        yield proxy
    finally:
        for r in proxy._runners:
            await r.cleanup()
        if proxy._shared_session:
            await proxy._shared_session.close()
        await up_runner.cleanup()


@pytest.mark.asyncio
async def test_stream_tool_calls_audit_triggered():
    """OpenAI 流式 tool_calls 分片累积 → finish_reason 审计（读完整原始参数）。"""
    async with env() as proxy, ClientSession() as s:
        body = json.dumps({'case': 'stream_tool_calls'})
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            await r.text()
        assert len(proxy.audited_calls) == 1
        name, args = proxy.audited_calls[0]
        assert name == 'bash'  # 跨分片拼接
        assert 'ls -la' in args  # 完整原始参数


@pytest.mark.asyncio
async def test_stream_tool_calls_done_fallback_audit():
    """无 finish_reason → [DONE] 流末兜底审计。"""
    async with env() as proxy, ClientSession() as s:
        body = json.dumps({'case': 'stream_tool_calls_no_finish'})
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            await r.text()
        assert len(proxy.audited_calls) == 1
        name, args = proxy.audited_calls[0]
        assert name == 'read_file'
        assert '/etc/passwd' in args


@pytest.mark.asyncio
async def test_anthropic_tool_use_audit_triggered():
    """Anthropic block_start → input_json_delta → block_stop 审计。"""
    async with env() as proxy, ClientSession() as s:
        body = json.dumps({'case': 'anthropic_tool_use'})
        async with s.post(ANTH_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            await r.text()
        assert len(proxy.audited_calls) == 1
        name, args = proxy.audited_calls[0]
        assert name == 'bash'
        assert '8.8.8.8' in args  # 掩码前原始参数


@pytest.mark.asyncio
async def test_non_stream_danger_audit():
    """非流式整包响应：tool_calls 提取 + 审计（不因缺 SSE 事件跳过）。"""
    async with env() as proxy, ClientSession() as s:
        body = json.dumps({'case': 'non_stream_danger'})
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            await r.text()
        assert len(proxy.audited_calls) == 1
        name, args = proxy.audited_calls[0]
        assert name == 'bash'
        assert 'rm -rf' in args


@asynccontextmanager
async def deny_env():
    """与 env() 同构，但 audit_tool_call 返回 'deny'（阻断路径）。"""
    up_runner = await make_upstream()
    proxy = await make_proxy()
    # 与 AuditProxy 同构：同步方法（_llm.py 调用点有 await 也有真值判断，
    # async 函数会留 coroutine 不 await → 警告）；deny 路径还会读 audit_mode
    proxy.audit_mode = 'block'

    async def deny_tool_call(name, args_json):
        proxy.audited_calls.append((name, args_json))
        return 'deny'

    def deny_enabled():
        return True

    proxy.audit_enabled = deny_enabled
    proxy.audit_tool_call = deny_tool_call
    try:
        yield proxy
    finally:
        for r in proxy._runners:
            await r.cleanup()
        if proxy._shared_session:
            await proxy._shared_session.close()
        await up_runner.cleanup()


@pytest.mark.asyncio
async def test_stream_deny_then_content_forwarded():
    """回归：阻断（tool_calls_blocked）后模型继续发的 content 必须转发。

    曾在真实流量中发现：`if tool_calls_blocked: continue` 永久跳过后续行，
    阻断后 content 全部丢失。修复后仅跳过 finish_reason: tool_calls 行本身。
    """
    async with deny_env() as proxy, ClientSession() as s:
        body = json.dumps({'case': 'stream_tool_calls_then_content'})
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            text = await r.text()
        # 审计被触发且判 deny
        assert len(proxy.audited_calls) == 1
        assert 'rm -rf' in proxy.audited_calls[0][1]
        # 阻断响应：拒绝消息 + 后续 content 都在，tool_calls 不透传
        assert '审计拒绝' in text
        # content 是 JSON \u 转义形式（_mk_sse_event ensure_ascii），需解码后断言
        import re as _re

        contents = _re.findall(r'"content":\s*"((?:[^"\\]|\\.)*)"', text)
        joined = ''.join(json.loads('"' + c + '"') if c else '' for c in contents)
        assert '我已执行该命令' in joined
        assert '"tool_calls"' not in text
        assert '[DONE]' in text
