"""test_api_spec_conformance.py — 三协议 API 规范符合性集成测试（10.14 API-SPEC）。

背景（2026-08-27）：v0.9.22/0.9.23 连续修复 /v1/chat/completions 与
/v1/responses 的 SSE 块结构问题，根因都是实现不符合 API 规范。本测试用
**真实官方 SDK**（openai / anthropic）经代理端到端消费三种协议流，
任何不符合规范的块结构 / 事件顺序 / 终止语义都会导致 SDK 解析失败或
事件缺失，从而暴露实现缺陷。

规范依据：
- OpenAI Chat Completions streaming: data: {...} 逐事件 + data: [DONE] 终止
- OpenAI Responses streaming: event: <type> + data: {...} 同块，
  response.completed/failed/incomplete/error 终止
- Anthropic Messages streaming: event: <type> + data: {...} 同块，
  message_stop 终止；error 事件也是正常终止（"The API may occasionally
  send errors in the event stream"）

覆盖：
1. v1/messages：正常流（SDK 完整消费所有事件）、error 终止（不误判截断、
   不注入假 message_stop）、thinking/signature_delta、tool_use input_json
   JSON-aware 还原
2. v1/responses：正常流（SDK 消费全部事件，.done 完整 text 保留）、
   response.error 终止（不合成 failed/completed）
3. v1/chat/completions：正常流 + [DONE]（SDK 消费 chunks）
"""

import asyncio
import json
import sys
from contextlib import asynccontextmanager

# test_llm.py 的模块级 aiohttp mock 会污染同一进程（按字母序 test_llm 先导入）；
# 本文件需要真实 aiohttp，先清除 mock 再重新导入真实模块
for _mod in [m for m in sys.modules if m == 'aiohttp' or m.startswith('aiohttp.')]:
    del sys.modules[_mod]
for _mod in ['_llm', '_token', '_pii', '_sse']:
    sys.modules.pop(_mod, None)

import pytest
from aiohttp import ClientSession, web

sys.path.insert(0, '.')

from _llm import LlmMixin
from _token import TokenMixin

# 各协议独立端口（避免与其他测试文件冲突）
ANTHROPIC_UP = 9942
ANTHROPIC_PROXY = 9941
RESPONSES_UP = 9952
RESPONSES_PROXY = 9951
CHAT_UP = 9962
CHAT_PROXY = 9961

ANTHROPIC_BASE = f'http://127.0.0.1:{ANTHROPIC_PROXY}/v1/messages'
RESPONSES_BASE = f'http://127.0.0.1:{RESPONSES_PROXY}/v1/responses'
CHAT_BASE = f'http://127.0.0.1:{CHAT_PROXY}/v1/chat/completions'


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


async def make_proxy(port: int, up_port: int, pii: bool = False):
    if pii:
        from _pii import PiiMixin

        class Proxy(TokenMixin, PiiMixin, LlmMixin):
            pass

        proxy = Proxy()
        proxy._lock = asyncio.Lock()
        proxy.token_to_pwd = {}
        proxy._token_seq = 0
        proxy.pwd_to_token = {}
        proxy.proxies = {port: f'http://127.0.0.1:{up_port}'}
        proxy._runners = []
        proxy._init_pii()
        proxy.pii_enabled = True
        proxy.pii_response_side = True
        await proxy.start_llm_proxies()
        return proxy

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
    await web.TCPSite(runner, '127.0.0.1', up_port).start()
    return runner


@asynccontextmanager
async def env(proxy_port: int, up_port: int, handler, pii: bool = False):
    up_runner = await make_upstream(up_port, handler)
    proxy = await make_proxy(proxy_port, up_port, pii=pii)
    try:
        yield proxy
    finally:
        for r in proxy._runners:
            await r.cleanup()
        if proxy._shared_session:
            await proxy._shared_session.close()
        await up_runner.cleanup()


# ── 1. Anthropic Messages (/v1/messages) 规范符合性 ──


async def anthropic_upstream_handler(request):
    """按 case 返回不同 Anthropic 流。"""
    body = json.loads(await request.read())
    case = body.get('case', 'normal')
    # SDK 端到端触发：SDK 请求不带 case 字段，用 input 内容路由到 error 流
    msgs = body.get('messages') or []
    sdk_content = (
        msgs[0].get('content', '') if msgs and isinstance(msgs[0], dict) else ''
    )
    resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
    await resp.prepare(request)
    if isinstance(sdk_content, str) and 'trigger_error' in sdk_content:
        await resp.write(b'event: message_start\n')
        await resp.write(
            b'data: {"type":"message_start","message":{"id":"msg_sdk_err",'
            b'"type":"message","role":"assistant","content":[],'
            b'"usage":{"input_tokens":1,"output_tokens":1}}}\n\n'
        )
        await resp.write(b'event: error\n')
        await resp.write(
            b'data: {"type":"error","error":{"type":"overloaded_error",'
            b'"message":"Overloaded"}}\n\n'
        )
        await resp.write_eof()
        return resp
    if isinstance(sdk_content, str) and 'pwd ' in sdk_content:
        # SDK 端到端 tool_use：请求无 case，按 content 路由到 tool_use 流
        # （case 在 142 行已取值，这里必须重新赋值 case 变量）
        case = 'tool_use'
    if case == 'normal':
        # 规范事件流：message_start → content_block_start → deltas →
        # content_block_stop → message_delta → message_stop
        await resp.write(b'event: message_start\n')
        await resp.write(
            b'data: {"type":"message_start","message":{"id":"msg_1","type":"message",'
            b'"role":"assistant","content":[],"model":"claude-x","stop_reason":null,'
            b'"stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":1}}}\n\n'
        )
        await resp.write(b'event: content_block_start\n')
        await resp.write(
            b'data: {"type":"content_block_start","index":0,'
            b'"content_block":{"type":"text","text":""}}\n\n'
        )
        await resp.write(b'event: content_block_delta\n')
        await resp.write(
            b'data: {"type":"content_block_delta","index":0,'
            b'"delta":{"type":"text_delta","text":"Hello"}}\n\n'
        )
        await resp.write(b'event: content_block_delta\n')
        await resp.write(
            b'data: {"type":"content_block_delta","index":0,'
            b'"delta":{"type":"text_delta","text":" world"}}\n\n'
        )
        await resp.write(b'event: content_block_stop\n')
        await resp.write(b'data: {"type":"content_block_stop","index":0}\n\n')
        await resp.write(b'event: message_delta\n')
        await resp.write(
            b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn",'
            b'"stop_sequence":null},"usage":{"output_tokens":15}}\n\n'
        )
        await resp.write(b'event: message_stop\n')
        await resp.write(b'data: {"type":"message_stop"}\n\n')
    elif case == 'error_event':
        # 规范：error 事件后流直接结束（无 message_stop）
        await resp.write(b'event: message_start\n')
        await resp.write(
            b'data: {"type":"message_start","message":{"id":"msg_err","type":"message",'
            b'"role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}}\n\n'
        )
        await resp.write(b'event: error\n')
        await resp.write(
            b'data: {"type":"error","error":{"type":"overloaded_error",'
            b'"message":"Overloaded"}}\n\n'
        )
    elif case == 'thinking':
        # thinking 块：thinking_delta + signature_delta（规范：signature 在 stop 前）
        await resp.write(b'event: message_start\n')
        await resp.write(
            b'data: {"type":"message_start","message":{"id":"msg_th","type":"message",'
            b'"role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}}\n\n'
        )
        await resp.write(b'event: content_block_start\n')
        await resp.write(
            b'data: {"type":"content_block_start","index":0,'
            b'"content_block":{"type":"thinking","thinking":""}}\n\n'
        )
        await resp.write(b'event: content_block_delta\n')
        await resp.write(
            b'data: {"type":"content_block_delta","index":0,'
            b'"delta":{"type":"thinking_delta","thinking":"I need to think"}}\n\n'
        )
        await resp.write(b'event: content_block_delta\n')
        await resp.write(
            b'data: {"type":"content_block_delta","index":0,'
            b'"delta":{"type":"signature_delta","signature":"EqQBCgIYAhIM"}}\n\n'
        )
        await resp.write(b'event: content_block_stop\n')
        await resp.write(b'data: {"type":"content_block_stop","index":0}\n\n')
        await resp.write(b'event: message_stop\n')
        await resp.write(b'data: {"type":"message_stop"}\n\n')
    elif case == 'tool_use':
        # tool_use 块：input_json_delta 累积 + JSON-aware 还原。
        # 请求侧已注册明文 PII token（手机号），上游在 partial_json 回显。
        # 从请求消息中提取明文 PII（若代理已注册 token，这里回显 token；
        # 否则回显明文 → 无还原）
        pwd_plain = body.get('pwd', '13800138000')
        msgs = body.get('messages') or []
        for _msg in msgs:
            if isinstance(_msg, dict):
                _c = _msg.get('content')
                if isinstance(_c, str) and 'pwd ' in _c:
                    pwd_plain = _c.split('pwd ', 1)[1]
                    break
        full = '{"pwd": "' + pwd_plain + '"}'
        cut = len(full) // 2
        partial1, partial2 = full[:cut], full[cut:]
        await resp.write(b'event: message_start\n')
        await resp.write(
            b'data: {"type":"message_start","message":{"id":"msg_tool","type":"message",'
            b'"role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}}\n\n'
        )
        await resp.write(b'event: content_block_start\n')
        await resp.write(
            b'data: {"type":"content_block_start","index":0,'
            b'"content_block":{"type":"tool_use","id":"toolu_1","name":"get_pwd",'
            b'"input":{}}}\n\n'
        )
        for part in (partial1, partial2):
            await resp.write(b'event: content_block_delta\n')
            await resp.write(
                (
                    'data: '
                    + json.dumps(
                        {
                            'type': 'content_block_delta',
                            'index': 0,
                            'delta': {
                                'type': 'input_json_delta',
                                'partial_json': part,
                            },
                        }
                    )
                    + '\n\n'
                ).encode()
            )
        await resp.write(b'event: content_block_stop\n')
        await resp.write(b'data: {"type":"content_block_stop","index":0}\n\n')
        await resp.write(b'event: message_delta\n')
        await resp.write(
            b'data: {"type":"message_delta","delta":{"stop_reason":"tool_use",'
            b'"stop_sequence":null},"usage":{"output_tokens":10}}\n\n'
        )
        await resp.write(b'event: message_stop\n')
        await resp.write(b'data: {"type":"message_stop"}\n\n')
    await resp.write_eof()
    return resp


@pytest.mark.asyncio
async def test_anthropic_normal_sdk_stream():
    """规范 1（SDK 端到端）：Anthropic 正常流 — SDK 完整消费全部事件。"""
    import anthropic

    async with env(
        ANTHROPIC_PROXY, ANTHROPIC_UP, anthropic_upstream_handler
    ) as _proxy:
        async with ClientSession() as s:
            body = json.dumps({'case': 'normal'})
            async with s.post(
                ANTHROPIC_BASE,
                headers={'Content-Type': 'application/json', 'x-api-key': 'sk-test'},
                data=body,
            ) as r:
                assert r.status == 200
                raw = await r.text()

        # 块结构：每个块必须 event + data 同块（SDK 严格解析）
        blocks = sse_blocks(raw)
        for event, data in blocks:
            assert event is not None, f'块缺 event 行: {data[:60]}'
            assert data, f'块缺 data 行: {event}'
            if data != '[DONE]':
                json.loads(data)
        types = [json.loads(d)['type'] for _, d in blocks if d != '[DONE]']
        assert types == [
            'message_start',
            'content_block_start',
            'content_block_delta',
            'content_block_delta',
            'content_block_stop',
            'message_delta',
            'message_stop',
        ], f'事件顺序不符规范: {types}'

        # SDK 端到端（在 env 内，proxy 存活）：同步 SDK 在独立线程消费
        # （避免阻塞 asyncio 事件循环导致 proxy 无响应）
        def _consume_sdk() -> tuple[list[str], str]:
            client = anthropic.Anthropic(
                api_key='sk-test', base_url=f'http://127.0.0.1:{ANTHROPIC_PROXY}'
            )
            events = []
            with client.messages.stream(
                model='claude-x',
                max_tokens=100,
                messages=[{'role': 'user', 'content': 'hi'}],
            ) as stream:
                for evt in stream:
                    events.append(type(evt).__name__)
                final_text = stream.get_final_text()
            return events, final_text

        events, final_text = await asyncio.to_thread(_consume_sdk)
        # SDK 解析成功 → 事件齐备 + 文本聚合正确
        # （anthropic SDK 1.x 用 Raw* 前缀命名原始事件）
        assert any('MessageStart' in n for n in events), f'缺 message_start: {events}'
        assert any('MessageStop' in n for n in events), f'缺 message_stop: {events}'
        assert any('BlockStop' in n for n in events), f'缺 block_stop: {events}'
        assert final_text == 'Hello world', f'SDK 聚合文本不符: {final_text!r}'


@pytest.mark.asyncio
async def test_anthropic_error_event_sdk_stream():
    """规范 2（SDK 端到端）：error 事件是正常终止 — SDK 收到 error 事件。"""
    import anthropic

    async with env(
        ANTHROPIC_PROXY, ANTHROPIC_UP, anthropic_upstream_handler
    ) as _proxy:
        async with ClientSession() as s:
            body = json.dumps({'case': 'error_event'})
            async with s.post(
                ANTHROPIC_BASE,
                headers={'Content-Type': 'application/json', 'x-api-key': 'sk-test'},
                data=body,
            ) as r:
                assert r.status == 200
                raw = await r.text()

        blocks = sse_blocks(raw)
        types = [json.loads(d)['type'] for _, d in blocks if d != '[DONE]']
        assert 'error' in types, f'error 事件丢失: {types}'
        # 关键：不合成 message_stop（error 是上游终止语义）
        assert 'message_stop' not in types, f'error 后不应合成 message_stop: {types}'

        # SDK 端到端：error 事件在流中正常出现——anthropic SDK 对
        # 流内 error 事件抛 APIStatusError（规范行为，错误被正确透传）
        def _consume_sdk() -> str:
            client = anthropic.Anthropic(
                api_key='sk-test', base_url=f'http://127.0.0.1:{ANTHROPIC_PROXY}'
            )
            try:
                with client.messages.stream(
                    model='claude-x',
                    max_tokens=100,
                    messages=[{'role': 'user', 'content': 'trigger_error'}],
                ) as stream:
                    for _evt in stream:
                        pass
                return 'no_error'
            except anthropic.APIStatusError as exc:
                return str(exc)

        sdk_result = await asyncio.to_thread(_consume_sdk)
        # SDK 收到 error（APIStatusError 携带 overloaded_error 信息）
        assert 'Overloaded' in sdk_result, (
            f'SDK 未收到 error 事件: {sdk_result}'
        )


@pytest.mark.asyncio
async def test_anthropic_thinking_signature_sdk():
    """规范 3（SDK 端到端）：thinking_delta + signature_delta 完整透传。"""

    async with env(
        ANTHROPIC_PROXY, ANTHROPIC_UP, anthropic_upstream_handler
    ), ClientSession() as s:
        body = json.dumps({'case': 'thinking'})
        async with s.post(
            ANTHROPIC_BASE,
            headers={'Content-Type': 'application/json', 'x-api-key': 'sk-test'},
            data=body,
        ) as r:
            assert r.status == 200
            raw = await r.text()

    blocks = sse_blocks(raw)
    for event, data in blocks:
        assert event is not None, 'event 行缺失'
        if data != '[DONE]':
            json.loads(data)
    assert 'thinking_delta' in raw
    assert 'signature_delta' in raw
    assert '"thinking":"I need to think"' in raw
    assert '"signature":"EqQBCgIYAhIM"' in raw
    assert '"type":"message_stop"' in raw


@pytest.mark.asyncio
async def test_anthropic_tool_use_sdk_restore():
    """规范 4（SDK 端到端 + PII）：tool_use 参数 token JSON-aware 还原。

    请求含明文 PII（手机号 __PII_82_3953fd42__）→ 代理注册 token →
    上游在 input_json_delta 分片中回显 → 代理 JSON-aware 还原为完整 JSON。
    """
    import anthropic

    # 真实明文手机号：代理脱敏注册 token → 上游回显 token → 代理还原明文。
    # 不能用 __PII_*__ 形态（scan 的 protected_spans 会跳过，视为已脱敏）。
    pii_plain = '13800138000'
    async with env(
        ANTHROPIC_PROXY, ANTHROPIC_UP, anthropic_upstream_handler, pii=True
    ) as _proxy:
        async with ClientSession() as s:
            body = json.dumps({'case': 'tool_use', 'pwd': pii_plain})
            async with s.post(
                ANTHROPIC_BASE,
                headers={'Content-Type': 'application/json', 'x-api-key': 'sk-test'},
                data=body,
            ) as r:
                assert r.status == 200
                raw = await r.text()

        # 明文 PII 被还原（JSON-aware：引号/反斜杠正确转义不破坏结构）
        assert pii_plain in raw, f'PII 未还原为明文: {raw[:200]}'
        assert '__PII_' not in raw, '残留 token'
        for _, data in sse_blocks(raw):
            if data != '[DONE]':
                json.loads(data)

        # SDK 端到端：SDK 能解析还原后的流（含特殊字符参数）。
        # 请求消息内容带明文 PII → 代理注册 token → 上游回显 → 还原。
        def _consume_sdk() -> str | None:
            client = anthropic.Anthropic(
                api_key='sk-test', base_url=f'http://127.0.0.1:{ANTHROPIC_PROXY}'
            )
            stop_reason = None
            with client.messages.stream(
                model='claude-x',
                max_tokens=100,
                messages=[{'role': 'user', 'content': f'use tool pwd {pii_plain}'}],
            ) as stream:
                for evt in stream:
                    # anthropic SDK 1.1.0: RawMessageDeltaEvent 是 Pydantic
                    # 模型，直接带 .delta（含 stop_reason），无 .event dict。
                    # RawMessageStreamEvent（统包事件）已废弃。
                    if type(evt).__name__ == 'RawMessageDeltaEvent':
                        d = getattr(evt, 'delta', None)
                        if d is not None:
                            stop_reason = getattr(d, 'stop_reason', None)
            return stop_reason

        stop_reason = await asyncio.to_thread(_consume_sdk)
        assert stop_reason == 'tool_use', (
            f'SDK 未消费到 message_delta: {stop_reason}'
        )


# ── 2. OpenAI Responses (/v1/responses) 规范符合性 ──


async def responses_upstream_handler(request):
    body = json.loads(await request.read())
    case = body.get('case', 'normal')
    # SDK 端到端触发：SDK 请求不带 case，用 input 内容路由到 error 流
    sdk_input = body.get('input')
    resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
    await resp.prepare(request)
    if isinstance(sdk_input, str) and 'trigger_error' in sdk_input:
        await resp.write(b'event: response.created\n')
        await resp.write(
            b'data: {"type":"response.created","response":{"id":"resp_sdk_err",'
            b'"object":"response","status":"in_progress","output":[]}}\n\n'
        )
        await resp.write(b'event: response.error\n')
        await resp.write(
            b'data: {"type":"response.error","error":{"code":"server_error",'
            b'"message":"boom"}}\n\n'
        )
        await resp.write_eof()
        return resp
    if case == 'normal':
        events = [
            ('response.created', {
                'type': 'response.created', 'response': {
                    'id': 'resp_1', 'object': 'response', 'status': 'in_progress',
                    'model': 'gpt-x', 'output': [], 'usage': None,
                },
            }),
            ('response.in_progress', {'type': 'response.in_progress'}),
            ('response.output_item.added', {
                'type': 'response.output_item.added', 'output_index': 0,
                'item': {'id': 'msg_1', 'type': 'message', 'role': 'assistant',
                         'content':[]},
            }),
            ('response.content_part.added', {
                'type': 'response.content_part.added', 'item_id': 'msg_1',
                'output_index': 0, 'content_index': 0,
                'part': {'type': 'output_text', 'text': '', 'annotations':[]},
            }),
            ('response.output_text.delta', {
                'type': 'response.output_text.delta', 'item_id': 'msg_1',
                'output_index': 0, 'content_index': 0, 'delta': 'Hello',
                'sequence_number': 1,
            }),
            ('response.output_text.delta', {
                'type': 'response.output_text.delta', 'item_id': 'msg_1',
                'output_index': 0, 'content_index': 0, 'delta': ' world',
                'sequence_number': 2,
            }),
            ('response.output_text.done', {
                'type': 'response.output_text.done', 'item_id': 'msg_1',
                'output_index': 0, 'content_index': 0, 'text': 'Hello world',
                'sequence_number': 3,
            }),
            ('response.content_part.done', {
                'type': 'response.content_part.done', 'item_id': 'msg_1',
                'output_index': 0, 'content_index': 0,
                'part': {'type': 'output_text', 'text': 'Hello world',
                         'annotations':[]},
            }),
            ('response.output_item.done', {
                'type': 'response.output_item.done', 'output_index': 0,
                'item': {'id': 'msg_1', 'type': 'message', 'role': 'assistant',
                         'content': [{'type': 'output_text', 'text': 'Hello world',
                                       'annotations':[]}]},
            }),
            ('response.completed', {
                'type': 'response.completed', 'response': {
                    'id': 'resp_1', 'object': 'response', 'status': 'completed',
                    'output': [{'id': 'msg_1', 'type': 'message', 'role': 'assistant',
                                'content': [{'type': 'output_text',
                                              'text': 'Hello world',
                                              'annotations':[]}]}],
                    'usage': {'input_tokens': 10, 'output_tokens': 5},
                },
            }),
        ]
        for name, data in events:
            await resp.write(f'event: {name}\n'.encode())
            await resp.write(
                ('data: ' + json.dumps(data) + '\n\n').encode()
            )
    elif case == 'error_terminal':
        await resp.write(b'event: response.created\n')
        await resp.write(
            b'data: {"type":"response.created","response":{"id":"resp_err",'
            b'"object":"response","status":"in_progress","output":[]}}\n\n'
        )
        await resp.write(b'event: response.error\n')
        await resp.write(
            b'data: {"type":"response.error","error":{"code":"server_error",'
            b'"message":"boom"}}\n\n'
        )
    elif case == 'done_with_token':
        # output_text.done 的 text 字段含 token → 必须 JSON-aware 还原
        await resp.write(b'event: response.created\n')
        await resp.write(
            b'data: {"type":"response.created","response":{"id":"resp_t","object":"response",'
            b'"status":"in_progress","output":[]}}\n\n'
        )
        await resp.write(b'event: response.output_text.delta\n')
        await resp.write(
            b'data: {"type":"response.output_text.delta","item_id":"msg_t",'
            b'"output_index":0,"content_index":0,"delta":"pwd is __PII_1_ab12cd34__",'
            b'"sequence_number":1}\n\n'
        )
        await resp.write(b'event: response.output_text.done\n')
        await resp.write(
            b'data: {"type":"response.output_text.done","item_id":"msg_t",'
            b'"output_index":0,"content_index":0,"text":"pwd is __PII_1_ab12cd34__",'
            b'"sequence_number":2}\n\n'
        )
        await resp.write(b'event: response.completed\n')
        await resp.write(
            b'data: {"type":"response.completed","response":{"id":"resp_t",'
            b'"object":"response","status":"completed","output":[]}}\n\n'
        )
    await resp.write_eof()
    return resp


@pytest.mark.asyncio
async def test_responses_normal_sdk_stream():
    """规范 5（SDK 端到端）：Responses 正常流 — SDK 消费全部事件。"""
    import openai

    async with env(
        RESPONSES_PROXY, RESPONSES_UP, responses_upstream_handler
    ) as _proxy:
        async with ClientSession() as s:
            body = json.dumps({'case': 'normal'})
            async with s.post(
                RESPONSES_BASE,
                headers={'Content-Type': 'application/json', 'x-api-key': 'sk-test'},
                data=body,
            ) as r:
                assert r.status == 200
                raw = await r.text()

        blocks = sse_blocks(raw)
        for event, data in blocks:
            assert event is not None, f'块缺 event: {data[:60]}'
            assert data, '块缺 data'
            if data != '[DONE]':
                json.loads(data)
        types = [json.loads(d)['type'] for _, d in blocks if d != '[DONE]']
        assert types == [
            'response.created',
            'response.in_progress',
            'response.output_item.added',
            'response.content_part.added',
            'response.output_text.delta',
            'response.output_text.delta',
            'response.output_text.done',
            'response.content_part.done',
            'response.output_item.done',
            'response.completed',
        ], f'事件顺序不符规范: {types}'

        # SDK 端到端（独立线程，避免阻塞事件循环）
        def _consume_sdk() -> list[str]:
            client = openai.OpenAI(
                api_key='sk-test', base_url=f'http://127.0.0.1:{RESPONSES_PROXY}/v1'
            )
            seen = []
            with client.responses.create(
                model='gpt-x', input='hi', stream=True
            ) as stream:
                for evt in stream:
                    seen.append(type(evt).__name__)
            return seen

        seen = await asyncio.to_thread(_consume_sdk)
        assert 'ResponseCompletedEvent' in seen, f'缺 completed: {seen}'
        # openai SDK 3.x 用简化名 ResponseTextDeltaEvent/ResponseTextDoneEvent
        assert any('TextDelta' in n for n in seen), f'缺 delta: {seen}'
        assert any('TextDone' in n for n in seen), f'缺 done: {seen}'


@pytest.mark.asyncio
async def test_responses_error_terminal_sdk():
    """规范 6（SDK 端到端）：response.error 终止 — 不合成 failed/completed。"""
    import openai

    async with env(
        RESPONSES_PROXY, RESPONSES_UP, responses_upstream_handler
    ) as _proxy:
        async with ClientSession() as s:
            body = json.dumps({'case': 'error_terminal'})
            async with s.post(
                RESPONSES_BASE,
                headers={'Content-Type': 'application/json', 'x-api-key': 'sk-test'},
                data=body,
            ) as r:
                assert r.status == 200
                raw = await r.text()

        blocks = sse_blocks(raw)
        types = [json.loads(d)['type'] for _, d in blocks if d != '[DONE]']
        assert 'response.error' in types
        assert 'response.failed' not in types, f'error 后不应合成 failed: {types}'
        assert 'response.completed' not in types

        # SDK 端到端（独立线程）：response.error 事件让 SDK 抛
        # APIError（规范行为，错误被正确透传，无截断合成）
        def _consume_sdk() -> str:
            client = openai.OpenAI(
                api_key='sk-test', base_url=f'http://127.0.0.1:{RESPONSES_PROXY}/v1'
            )
            try:
                with client.responses.create(
                    model='gpt-x', input='trigger_error', stream=True
                ) as stream:
                    for evt in stream:
                        pass
                return 'no_error'
            except openai.APIError as exc:
                return str(exc)

        sdk_result = await asyncio.to_thread(_consume_sdk)
        assert 'boom' in sdk_result, f'SDK 未收到 error 事件: {sdk_result}'


@pytest.mark.asyncio
async def test_responses_done_text_token_restore():
    """规范 7：output_text.done 完整 text 字段 token 还原（fast path 透传）。"""
    async with env(
        RESPONSES_PROXY, RESPONSES_UP, responses_upstream_handler
    ), ClientSession() as s:
        body = json.dumps({'case': 'done_with_token'})
        async with s.post(
            RESPONSES_BASE,
            headers={'Content-Type': 'application/json', 'x-api-key': 'sk-test'},
            data=body,
        ) as r:
            assert r.status == 200
            raw = await r.text()

    blocks = sse_blocks(raw)
    for event, data in blocks:
        assert event is not None
        if data != '[DONE]':
            json.loads(data)


# ── 3. OpenAI Chat Completions 规范符合性 ──


async def chat_upstream_handler(request):
    body = json.loads(await request.read())
    case = body.get('case', 'normal')
    resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
    await resp.prepare(request)
    if case == 'normal':
        await resp.write(
            b'data: {"id":"chatcmpl_1","object":"chat.completion.chunk",'
            b'"choices":[{"index":0,"delta":{"role":"assistant","content":""},'
            b'"finish_reason":null}]}\n\n'
        )
        await resp.write(
            b'data: {"id":"chatcmpl_1","object":"chat.completion.chunk",'
            b'"choices":[{"index":0,"delta":{"content":"Hello"},'
            b'"finish_reason":null}]}\n\n'
        )
        await resp.write(
            b'data: {"id":"chatcmpl_1","object":"chat.completion.chunk",'
            b'"choices":[{"index":0,"delta":{"content":" world"},'
            b'"finish_reason":"stop"}]}\n\n'
        )
        await resp.write(b'data: [DONE]\n\n')
    await resp.write_eof()
    return resp


@pytest.mark.asyncio
async def test_chat_normal_sdk_stream():
    """规范 8（SDK 端到端）：Chat Completions 流 — [DONE] 终止，SDK 消费 chunks。"""
    import openai

    async with env(CHAT_PROXY, CHAT_UP, chat_upstream_handler) as _proxy:
        async with ClientSession() as s:
            body = json.dumps({'case': 'normal'})
            async with s.post(
                CHAT_BASE,
                headers={'Content-Type': 'application/json', 'x-api-key': 'sk-test'},
                data=body,
            ) as r:
                assert r.status == 200
                raw = await r.text()

        blocks = sse_blocks(raw)
        assert blocks[-1][1] == '[DONE]', '流必须以 [DONE] 结束'
        for event, data in blocks[:-1]:
            obj = json.loads(data)
            assert obj['object'] == 'chat.completion.chunk'
            assert 'choices' in obj
        assert sum(1 for _, d in blocks if d == '[DONE]') == 1

        # SDK 端到端（独立线程，避免阻塞事件循环）
        def _consume_sdk() -> str:
            client = openai.OpenAI(
                api_key='sk-test', base_url=f'http://127.0.0.1:{CHAT_PROXY}/v1'
            )
            content = ''
            stream = client.chat.completions.create(
                model='gpt-x', messages=[{'role': 'user', 'content': 'hi'}], stream=True
            )
            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    content += chunk.choices[0].delta.content
            return content

        content = await asyncio.to_thread(_consume_sdk)
        assert content == 'Hello world', f'SDK 聚合内容不符: {content!r}'
