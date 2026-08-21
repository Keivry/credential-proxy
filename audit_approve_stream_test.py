"""audit_approve_stream_test.py — Batch 6.3 审批模式流式集成测试（真实 aiohttp）。

覆盖 tasks 6.3 验收：
- 审批通过（approved）→ 放行：tool_calls 事件完整流出，无拒绝消息
- 审批拒绝（rejected）→ 注入拒绝消息，tool_calls 不流出
- 审批超时（expired）→ 默认拒绝注入
- Anthropic 预检暂停：function_args 前缀命中 → 挂起 → block_stop 审计
- 预检误判恢复：完整审计 allow → 缓冲 + block_stop 原样放行
- 挂起中 content 缓冲：rejected → 缓冲 content 丢弃（不流出）
- 缓冲超限 AUDIT_HOLD_MAX_BYTES → fail-closed 拒绝

与 audit_stream_test.py 同模式（真实 aiohttp，先清 mock）。
"""

import asyncio
import json
import sys
from contextlib import asynccontextmanager

# 清除 aiohttp mock（与 sse_stream_loop_test.py 一致）
for _mod in [m for m in sys.modules if m == 'aiohttp' or m.startswith('aiohttp.')]:
    del sys.modules[_mod]
for _mod in ['_llm', '_token', '_sse']:
    sys.modules.pop(_mod, None)

import pytest
from aiohttp import ClientError, ClientSession, web

sys.path.insert(0, '.')

from _audit import BLOCK_MESSAGE
from _llm import LlmMixin
from _token import TokenMixin

UPSTREAM_PORT = 9952
PROXY_PORT = 9951
CHAT_BASE = f'http://127.0.0.1:{PROXY_PORT}/v1/chat/completions'
ANTH_BASE = f'http://127.0.0.1:{PROXY_PORT}/v1/messages'
HEADERS = {'Content-Type': 'application/json', 'x-api-key': 'sk-test'}


# ── mock 上游：审批场景 SSE 流 ──


async def make_upstream():
    async def handler(request):
        body = json.loads(await request.read())
        case = body.get('case', 'normal')
        resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
        await resp.prepare(request)
        if case == 'openai_danger':
            # OpenAI 流式危险 tool call（bash rm -rf）→ finish_reason 审计
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"role":"assistant","content":null}}]}\n\n'
            )
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"bash","arguments":"{\\"cmd\\":\\"rm -rf /\\"}"}}]}}]}\n\n'
            )
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n'
            )
            await resp.write(b'data: [DONE]\n\n')
            await resp.write_eof()
            return resp
        if case == 'openai_safe':
            # OpenAI 流式安全 tool call（read_file）→ 不触发审批
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\\"path\\":\\"/tmp/x\\"}"}}]}}]}\n\n'
            )
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n'
            )
            await resp.write(b'data: [DONE]\n\n')
            await resp.write_eof()
            return resp
        if case == 'anthropic_danger':
            # Anthropic 危险 tool_use：bash rm -rf（前缀预检命中）
            await resp.write(b'event: content_block_start\n')
            await resp.write(
                b'data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash"}}\n\n'
            )
            # 参数分片：先 rm（预检命中）再 -rf
            await resp.write(b'event: content_block_delta\n')
            await resp.write(
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"cmd\\":\\"rm"}}\n\n'
            )
            await resp.write(b'event: content_block_delta\n')
            await resp.write(
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":" -rf /\\"}"}}\n\n'
            )
            # 挂起期间到达的 content（verdict 前缓冲；rejected 应丢弃）
            await resp.write(b'event: content_block_delta\n')
            await resp.write(
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"during hold"}}\n\n'
            )
            await resp.write(b'event: content_block_stop\n')
            await resp.write(b'data: {"type":"content_block_stop","index":0}\n\n')
            # 挂起解除后到达的 content（拒绝后新内容照常转发）
            await resp.write(b'event: content_block_delta\n')
            await resp.write(
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"after tool"}}\n\n'
            )
            await resp.write(b'event: message_stop\n')
            await resp.write(b'data: {"type":"message_stop"}\n\n')
            await resp.write_eof()
            return resp
        if case == 'anthropic_false_positive':
            # Anthropic 预检误判：bash 前缀命中但参数安全（ls）→ 完整审计 allow
            await resp.write(b'event: content_block_start\n')
            await resp.write(
                b'data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash"}}\n\n'
            )
            await resp.write(b'event: content_block_delta\n')
            await resp.write(
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"cmd\\":\\"ls"}}\n\n'
            )
            await resp.write(b'event: content_block_delta\n')
            await resp.write(
                b'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":" -la /tmp\\"}"}}\n\n'
            )
            await resp.write(b'event: content_block_stop\n')
            await resp.write(b'data: {"type":"content_block_stop","index":0}\n\n')
            await resp.write(b'event: message_stop\n')
            await resp.write(b'data: {"type":"message_stop"}\n\n')
            await resp.write_eof()
            return resp
        # 默认正常流
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


# ── mock _ask 审批（可编程 approve/reject/None）──


class AskMock:
    """Mock _ask：记录请求文本，返回可编程结果。"""

    def __init__(self):
        self.result = 'msg-1'
        self.requests: list[str] = []
        self.resolver = None
        self._approved: bool | None = None

    async def ask(self, text: str, reactions=None):
        self.requests.append(text)
        if self.result is None:
            return None
        msg_id = self.result
        self.resolver = msg_id
        return msg_id

    def resolve(self, approved: bool):
        """手动触发审批 verdict（模拟审批人点 reaction）。"""
        self._approved = approved
        # 由 proxy 侧把 verdict 写入 pending
        return approved


async def make_proxy(ask_mock=None, audit_mode='approve', hold_max=1048576, timeout=3):
    class Proxy(TokenMixin, LlmMixin):
        pass

    proxy = Proxy()
    proxy._lock = asyncio.Lock()
    proxy.token_to_pwd = {}
    proxy._token_seq = 0
    proxy.pwd_to_token = {}
    proxy.proxies = {PROXY_PORT: f'http://127.0.0.1:{UPSTREAM_PORT}'}
    proxy._runners = []
    proxy._audit_arg_accum = ''
    proxy._last_anthropic_tool_name = None
    proxy._last_responses_tool_name = None
    # 审计启用 + approve 模式
    proxy.audit_enabled_flag = True
    proxy.audit_mode = audit_mode
    proxy.audit_timeout = timeout
    proxy.audit_hold_max_bytes = hold_max
    # 真实默认策略（危险模式含 rm/curl 等）
    from _audit import DEFAULT_POLICY

    proxy.policy = json.loads(json.dumps(DEFAULT_POLICY))
    proxy.approval_whitelist = set()
    proxy._audit_approval_pending = {}
    proxy._audit_approval_msgs = {}
    proxy._audit_pending_seq = 0
    # mock _ask
    if ask_mock is not None:
        proxy._ask = ask_mock.ask
    await proxy.start_llm_proxies()
    return proxy


async def wait_pending(proxy, timeout=5.0):
    """等待审批 pending 出现，返回 req_id。"""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        for _req_id, ap in proxy._audit_approval_pending.items():
            if ap.get('approved') is None:
                return _req_id
        await asyncio.sleep(0.005)
    raise AssertionError('无 pending 审批')


async def resolve_pending(proxy, approved: bool):
    """找到 pending 审批并置 verdict。"""
    req_id = await wait_pending(proxy)
    ap = proxy._audit_approval_pending[req_id]
    ap['approved'] = approved
    ap['event'].set()


@asynccontextmanager
async def env(**kw):
    up_runner = await make_upstream()
    proxy = await make_proxy(**kw)
    try:
        yield proxy
    finally:
        for r in proxy._runners:
            await r.cleanup()
        if proxy._shared_session:
            await proxy._shared_session.close()
        await up_runner.cleanup()


# ═══════════════════════════════════════════════════════════
# OpenAI 审批（6.3）
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_openai_approve_approved_releases():
    """OpenAI 危险 tool call + 审批通过 → tool_calls 事件放行，无拒绝消息。"""
    am = AskMock()
    async with env(ask_mock=am) as proxy, ClientSession() as s:
        body = json.dumps({'case': 'openai_danger'})

        # 在后台驱动审批（客户端读响应时审批进行中）
        async def approve_later():
            await wait_pending(proxy)
            await resolve_pending(proxy, True)

        task = asyncio.create_task(approve_later())
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            text = await r.text()
        await task
        # 审批消息已发送（mock _ask 被调用）
        assert len(am.requests) == 1
        assert 'bash' in am.requests[0]
        # 放行：客户端收到 tool_calls 事件（无拒绝消息）
        assert BLOCK_MESSAGE not in text
        assert 'tool_calls' in text
        assert 'rm -rf /' in text or 'rm' in text


@pytest.mark.asyncio
async def test_openai_approve_rejected_injects():
    """OpenAI 危险 tool call + 审批拒绝 → 注入拒绝消息，tool_calls 不流出。"""
    am = AskMock()
    async with env(ask_mock=am) as proxy, ClientSession() as s:
        body = json.dumps({'case': 'openai_danger'})

        async def reject_later():
            await wait_pending(proxy)
            await resolve_pending(proxy, False)

        task = asyncio.create_task(reject_later())
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            text = await r.text()
        await task
        assert BLOCK_MESSAGE in text
        assert 'tool_calls' not in text


@pytest.mark.asyncio
async def test_openai_approve_expired_injects():
    """OpenAI 审批超时 → 默认拒绝注入。"""
    am = AskMock()
    async with env(ask_mock=am, timeout=0.2), ClientSession() as s:
        body = json.dumps({'case': 'openai_danger'})
        # 不 resolve，让超时
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            text = await r.text()
        assert BLOCK_MESSAGE in text
        assert 'tool_calls' not in text


@pytest.mark.asyncio
async def test_openai_safe_no_approval():
    """OpenAI 安全 tool call → 无审批请求，事件原样流出。"""
    am = AskMock()
    async with env(ask_mock=am), ClientSession() as s:
        body = json.dumps({'case': 'openai_safe'})
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            text = await r.text()
        assert len(am.requests) == 0  # 无审批
        assert 'read_file' in text


# ═══════════════════════════════════════════════════════════
# Anthropic 预检暂停 + 审批（6.3 硬性）
# ═══════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_anthropic_precheck_hold_approved():
    """Anthropic 预检命中（bash rm）→ 挂起 → 审批通过 → 缓冲放行。"""
    am = AskMock()
    async with env(ask_mock=am) as proxy, ClientSession() as s:
        body = json.dumps({'case': 'anthropic_danger'})

        async def approve_later():
            await wait_pending(proxy)
            await resolve_pending(proxy, True)

        task = asyncio.create_task(approve_later())
        async with s.post(ANTH_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            text = await r.text()
        await task
        # 调试：检查挂起状态是否被激活
        print('DEBUG hold_active:', getattr(proxy, '_audit_hold_active', None))
        print('DEBUG arg_accum:', repr(getattr(proxy, '_audit_arg_accum', None)))
        print('DEBUG last_name:', getattr(proxy, '_last_anthropic_tool_name', None))
        # 放行：缓冲参数 delta + 挂起 content + block_stop 流出
        assert BLOCK_MESSAGE not in text
        assert 'rm' in text
        assert 'block_stop' in text or 'content_block_stop' in text
        assert 'during hold' in text  # 挂起期间 content 放行（approved）


@pytest.mark.asyncio
async def test_anthropic_precheck_hold_rejected_discards():
    """Anthropic 预检命中 + 审批拒绝 → 注入拒绝，缓冲 content 丢弃。"""
    am = AskMock()
    async with env(ask_mock=am) as proxy, ClientSession() as s:
        body = json.dumps({'case': 'anthropic_danger'})

        async def reject_later():
            await wait_pending(proxy)
            await resolve_pending(proxy, False)

        task = asyncio.create_task(reject_later())
        async with s.post(ANTH_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            text = await r.text()
        await task
        # 拒绝：BLOCK_MESSAGE 注入；挂起期间缓冲（参数残余 + content）丢弃
        assert BLOCK_MESSAGE in text
        assert 'during hold' not in text  # 挂起期间 content 丢弃
        assert '-rf' not in text  # 参数残余不流出
        assert 'after tool' in text  # 拒绝后新 content 照常转发（design D4）


@pytest.mark.asyncio
async def test_anthropic_precheck_false_positive_releases():
    """Anthropic 预检命中但完整审计 allow（误判）→ 缓冲 + block_stop 恢复放行。"""
    am = AskMock()
    # 完整审计 allow：覆盖 audit_tool_call
    async with env(ask_mock=am) as proxy, ClientSession() as s:
        # 覆盖 audit_tool_call 为 allow（预检命中但完整判定通过）
        async def audit_allow(name, args):
            return 'allow'

        proxy.audit_tool_call = audit_allow
        body = json.dumps({'case': 'anthropic_false_positive'})
        async with s.post(ANTH_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            text = await r.text()
        # 无审批请求（完整审计直接 allow，不进入 approve）
        assert len(am.requests) == 0
        # 缓冲放行 + block_stop 正常
        assert 'ls' in text
        assert 'content_block_stop' in text
        assert BLOCK_MESSAGE not in text


@pytest.mark.asyncio
async def test_anthropic_hold_overflow_fail_closed():
    """挂起缓冲超限 AUDIT_HOLD_MAX_BYTES → fail-closed 拒绝。"""
    am = AskMock()
    # hold_max=250：delta1(~120B)+delta2(~110B)+during(~110B) 累计超限
    async with env(ask_mock=am, hold_max=250), ClientSession() as s:
        body = json.dumps({'case': 'anthropic_danger'})
        async with s.post(ANTH_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            text = await r.text()
        # 超限 → 立即拒绝（无审批等待）
        assert BLOCK_MESSAGE in text
        assert 'during hold' not in text  # 挂起缓冲被丢弃
        assert 'after tool' in text  # 挂起解除后新内容照常转发


# ═══════════════════════════════════════════════════════════
# 6.5 异常路径测试组
# ═══════════════════════════════════════════════════════════


async def make_upstream_error():
    """异常上游：按 case 返回断连/坏 JSON/空流/中途断连。"""

    async def handler(request):
        body = json.loads(await request.read())
        case = body.get('case', 'normal')
        resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
        await resp.prepare(request)
        if case == 'abort_mid_toolcall':
            # 流式 tool call 中途上游断连（无 finish_reason/[DONE]）
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"bash","arguments":"{\\"cmd\\":\\"rm -rf /\\"}"}}]}}]}\n\n'
            )
            await resp.write_eof()  # 正常 EOF 但无终止事件
            return resp
        if case == 'bad_json':
            # 坏 JSON SSE 行（透传分支）
            await resp.write(b'data: {invalid json\n\n')
            await resp.write(b'data: [DONE]\n\n')
            await resp.write_eof()
            return resp
        if case == 'empty_stream':
            # 空流（无任何事件）
            await resp.write_eof()
            return resp
        if case == 'abrupt_disconnect':
            # 中途连接异常断开（在 tool call 后）
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"bash","arguments":"{\\"cmd\\":\\"rm -rf /\\"}"}}]}}]}\n\n'
            )
            # 模拟断连：直接关闭连接（不 write_eof）
            resp._payload_writer.transport.close()
            return resp
        # 默认
        await resp.write(b'data: [DONE]\n\n')
        await resp.write_eof()
        return resp

    app = web.Application()
    app.router.add_route('*', '/{tail:.*}', handler)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, '127.0.0.1', UPSTREAM_PORT).start()
    return runner


@asynccontextmanager
async def env_error(**kw):
    up_runner = await make_upstream_error()
    proxy = await make_proxy(**kw)
    try:
        yield proxy
    finally:
        for r in proxy._runners:
            await r.cleanup()
        if proxy._shared_session:
            await proxy._shared_session.close()
        await up_runner.cleanup()


@pytest.mark.asyncio
async def test_abort_mid_toolcall_fail_closed():
    """上游正常 EOF 但无终止事件（不完整 tool call）→ fail-closed 丢弃 + 注入终止。"""
    am = AskMock()
    async with env_error(ask_mock=am), ClientSession() as s:
        body = json.dumps({'case': 'abort_mid_toolcall'})
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            text = await r.text()
        # 无终止事件 → 不完整 tool call 丢弃 + 注入拒绝（fail-closed）
        assert BLOCK_MESSAGE in text
        assert 'tool_calls' not in text


@pytest.mark.asyncio
async def test_bad_json_passthrough():
    """坏 JSON SSE 行 → 透传分支不崩溃。"""
    am = AskMock()
    async with env_error(ask_mock=am), ClientSession() as s:
        body = json.dumps({'case': 'bad_json'})
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            text = await r.text()
        assert '[DONE]' in text  # 流正常结束


@pytest.mark.asyncio
async def test_empty_stream_no_crash():
    """空流（无事件）→ 不崩溃，A 方案永不空流：兜底注入 BLOCK_MESSAGE。"""
    am = AskMock()
    async with env_error(ask_mock=am), ClientSession() as s:
        body = json.dumps({'case': 'empty_stream'})
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            text = await r.text()
        # A 方案：空流不再返回 0 bytes（会致 hermes JSONDecodeError），而是注入拒绝消息
        assert BLOCK_MESSAGE in text


@pytest.mark.asyncio
async def test_approve_timeout_vs_disconnect_race_idempotent():
    """审批超时与上游断连竞态：后到者跳过（处置幂等）。"""
    am = AskMock()
    # 审批不 resolve → 超时（0.2s）；上游也断连
    async with env_error(ask_mock=am, timeout=0.2) as proxy, ClientSession() as s:
        body = json.dumps({'case': 'abrupt_disconnect'})
        try:
            async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
                assert r.status == 200
                await r.text()
        except ClientError:
            pass  # 断连可能抛异常，接受
        # pending 已被清理（超时或断连路径至少一个清理）
        assert not proxy._audit_approval_pending


@pytest.mark.asyncio
async def test_client_early_disconnect_cleanup():
    """客户端提前断连（SSE_CLIENT_GONE）→ 服务端不崩溃 + pending 清理。"""
    am = AskMock()
    async with env_error(ask_mock=am) as proxy:
        body = json.dumps({'case': 'abort_mid_toolcall'}).encode()
        # 客户端 raw socket 发请求后立即关闭（不等响应）
        _, writer = await asyncio.open_connection('127.0.0.1', PROXY_PORT)
        writer.write(
            (
                f'POST /v1/chat/completions HTTP/1.1\r\n'
                f'Host: 127.0.0.1:{PROXY_PORT}\r\n'
                f'Content-Type: application/json\r\n'
                f'x-api-key: sk-test\r\n'
                f'Content-Length: {len(body)}\r\n'
                f'Connection: close\r\n\r\n'
            ).encode()
            + body
        )
        await writer.drain()
        # 立即关闭——不等任何响应（模拟客户端断连）
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        # 等代理处理完断连
        await asyncio.sleep(0.3)
        # 审批 pending 应被清理（断连路径 finally 清理）
        assert not proxy._audit_approval_pending
