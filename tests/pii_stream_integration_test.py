"""pii_stream_integration_test.py — 8.7 真实 handler 集成测试（F-07）。

驱动真实 `_handle_openai_sse` 主循环 / `_handle_anthropic_event` /
`_handle_responses_event`（经真实 aiohttp 代理），断言真实输出字节：

- OpenAI chat 流式：请求期 PII token 在正文中还原为明文
- Anthropic 流式：text_delta 跨分片 token 同行还原
- Responses 流式：output_text.delta 行缓冲还原
- 截断合成：上游无终止直接断流 → 合成终止事件（不空体）

与 sse_stream_loop_test.py 同模式（真实 aiohttp，先清 mock）。
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
from aiohttp import ClientSession, web

sys.path.insert(0, '.')

from _llm import LlmMixin
from _pii import PiiMixin
from _token import TokenMixin

UPSTREAM_PORT = 9972
PROXY_PORT = 9971
CHAT_BASE = f'http://127.0.0.1:{PROXY_PORT}/v1/chat/completions'
ANTH_BASE = f'http://127.0.0.1:{PROXY_PORT}/v1/messages'
RESP_BASE = f'http://127.0.0.1:{PROXY_PORT}/v1/responses'
HEADERS = {'Content-Type': 'application/json', 'x-api-key': 'sk-test'}


async def make_upstream():
    """mock 上游：按 case 返回 PII 流式场景。

    请求经代理脱敏后到达上游：body 内含 `__PII_<seq>_<rand8>__` token。
    上游从 body 提取 token 并在响应中回显，代理应还原为明文。
    """

    def _extract_pii_token(body: dict) -> str:
        # 从脱敏后的请求 body 里找 __PII_*__ token
        raw = json.dumps(body, ensure_ascii=False)
        import re

        m = re.search(r'__PII_\d+_[0-9a-f]{8}__', raw)
        return m.group(0) if m else '__PII_1_ab12cd34__'

    async def handler(request):
        body = json.loads(await request.read())
        case = body.get('case', 'chat_restore')
        tok = _extract_pii_token(body)
        resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
        await resp.prepare(request)
        if case == 'chat_restore':
            # OpenAI：请求期注册 token 在正文中回显 → 代理应还原为明文
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
        elif case == 'anthropic_cross_delta':
            # Anthropic：token 跨 text_delta 分片切断，同行还原
            await resp.write(b'event: content_block_delta\n')
            await resp.write(
                (
                    'data: {"type":"content_block_delta","index":0,'
                    '"delta":{"type":"text_delta","text":"号码 ' + tok[:10] + '"}}\n\n'
                ).encode()
            )
            await resp.write(b'event: content_block_delta\n')
            await resp.write(
                (
                    'data: {"type":"content_block_delta","index":0,'
                    '"delta":{"type":"text_delta","text":"' + tok[10:] + ' 结束"}}\n\n'
                ).encode()
            )
            await resp.write(b'event: message_stop\n')
            await resp.write(b'data: {"type":"message_stop"}\n\n')
        elif case == 'responses_stream':
            # Responses：output_text.delta 行缓冲还原
            await resp.write(
                (
                    'data: {"type":"response.output_text.delta",'
                    '"delta":"号码 ' + tok + '"}\n\n'
                ).encode()
            )
            await resp.write(b'data: {"type":"response.completed"}\n\n')
        elif case == 'sentinel_chat':
            # 9.13 (F-13): sentinel fixture 回放——choices n=2 第二路、
            # tool_calls arguments、finish_reason、[DONE] 全场景。
            # fixture 内硬编码 __PII_1_ab12cd34__ 替换为代理实际注册 token
            # （_extract_pii_token 从脱敏请求 body 提取），否则还原不命中。
            import json as _json
            import pathlib

            _fixture = (
                pathlib.Path(__file__).parent / 'fixtures' / 'sentinel_chat.jsonl'
            )
            for _ln in _fixture.read_text(encoding='utf-8').splitlines():
                _entry = _json.loads(_ln)
                if _entry.get('kind') == 'sse':
                    await resp.write(
                        _entry['line'].replace('__PII_1_ab12cd34__', tok).encode()
                    )
            await resp.write_eof()
            return resp
        elif case == 'truncated_no_terminal':
            # 截断：上游无终止直接断流（0 终止事件）
            await resp.write(
                (
                    'data: {"choices":[{"index":0,"delta":{"content":"半截内容"}}]}\n\n'
                ).encode()
            )
        elif case == 'refusal_line':
            # refusal 行缓冲（响应侧新检测 PII → token 保留不泄漏明文）
            await resp.write(
                (
                    'data: {"choices":[{"index":0,"delta":{"refusal":"拒绝 13800138000"}}]}\n\n'
                ).encode()
            )
            await resp.write(b'data: [DONE]\n\n')
        elif case == 'cr_only_eof':
            # 9.4 (F-04): CR-only 行（无 LF）在流末正确 dispatch——
            # 末行以 \r 结尾且带 finish_reason=stop（终止事件），EOF 时
            # 该行立即 dispatch，不残留、不丢内容、不误判截断
            await resp.write(
                (
                    'data: {"choices":[{"index":0,"delta":{"content":"第一行"}}]}\n\n'
                ).encode()
            )
            await resp.write(
                (
                    'data: {"choices":[{"index":0,"delta":{"content":"CR尾行'
                    + tok
                    + '"}, "finish_reason":"stop"}]}\r'
                ).encode()
            )
            await resp.write_eof()
            return resp
        elif case == 'cr_only_done':
            # 10.5.1 (F-01/R-03): CR-only 的 `data: [DONE]` 流末——单独
            # 透传并置位，不合成截断、不双发 [DONE]
            await resp.write(
                (
                    'data: {"choices":[{"index":0,"delta":{"content":"正常内容'
                    + tok
                    + '"}}]}\n\n'
                ).encode()
            )
            await resp.write(b'data: [DONE]\r')
            await resp.write_eof()
            return resp
        await resp.write_eof()
        return resp

    app = web.Application()
    app.router.add_route('*', '/{tail:.*}', handler)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, '127.0.0.1', UPSTREAM_PORT).start()
    return runner


async def make_proxy():
    class Proxy(TokenMixin, PiiMixin, LlmMixin):
        pass

    proxy = Proxy()
    proxy._lock = asyncio.Lock()
    proxy.token_to_pwd = {}
    proxy._token_seq = 0
    proxy.pwd_to_token = {}
    proxy.proxies = {PROXY_PORT: f'http://127.0.0.1:{UPSTREAM_PORT}'}
    proxy._runners = []
    # 启用 PII 脱敏（请求侧脱敏 + 响应侧还原/检测）
    proxy._init_pii()
    proxy.pii_enabled = True
    proxy.pii_response_side = True
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
async def test_integration_chat_stream_real_handler():
    """8.7：真实 handler — OpenAI chat 流式正文 token 还原为明文。"""
    async with env(), ClientSession() as s:
        # 请求 body 含明文 PII → 代理注册 token → 上游回显 token → 代理还原
        body = json.dumps(
            {
                'case': 'chat_restore',
                'messages': [{'role': 'user', 'content': '我的号码是 13800138000'}],
            }
        )
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
        # 真实主循环：请求期注册 token → 正文还原为明文
        # （中文可能被 ensure_ascii 转义为 \uXXXX，检查明文手机号即可）
        assert '13800138000' in raw
        assert '__PII_' not in raw
        # 9.13 (F-11): 正常流不合成截断——[DONE] 恰 1 个、无 TRUNCATED_MESSAGE
        assert 'TRUNCATED_MESSAGE' not in raw and '被截断' not in raw
        assert raw.count('data: [DONE]') == 1, f'[DONE] 数量异常: {raw!r}'


@pytest.mark.asyncio
async def test_integration_anthropic_real_handler():
    """8.7：真实 handler — Anthropic text_delta 跨分片 token 同行还原。"""
    async with env(), ClientSession() as s:
        body = json.dumps(
            {
                'case': 'anthropic_cross_delta',
                'messages': [{'role': 'user', 'content': '我的号码是 13800138000'}],
            }
        )
        async with s.post(ANTH_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
        # 跨分片切断的 token 经 line_buf 合并后还原
        assert '__PII_' not in raw
        assert '13800138000' in raw
        assert 'message_stop' in raw
        # 9.13 (F-11): 正常流不合成截断
        assert 'TRUNCATED_MESSAGE' not in raw and '被截断' not in raw


@pytest.mark.asyncio
async def test_integration_responses_real_handler():
    """8.7：真实 handler — Responses output_text.delta 行缓冲还原。"""
    async with env(), ClientSession() as s:
        body = json.dumps(
            {
                'case': 'responses_stream',
                'input': [{'role': 'user', 'content': '我的号码是 13800138000'}],
            }
        )
        async with s.post(RESP_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
        assert '__PII_' not in raw
        assert '13800138000' in raw
        assert 'response.completed' in raw
        # 9.13 (F-11): 正常流不合成截断
        assert 'TRUNCATED_MESSAGE' not in raw and '被截断' not in raw


@pytest.mark.asyncio
async def test_integration_truncated_synthetic_terminal(caplog):
    """8.7：真实 handler — 上游无终止断流 → 合成终止事件（不空体）。

    10.11.3 (F-TEST-02): 补正向断言——caplog 含截断 warning、合成事件
    类型正确（chat 协议 finish_reason:stop + [DONE] 恰 1 个）。
    """
    async with env(), ClientSession() as s:
        body = json.dumps({'case': 'truncated_no_terminal'})
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
        # 不空体：至少有一个 data 事件 + 合成的终止
        assert raw.strip()
        # 中文被 ensure_ascii 转义为 \\uXXXX，断言 unicode 转义形态
        assert '\\u534a\\u622a\\u5185\\u5bb9' in raw or '半截内容' in raw
        # 10.11.3: 正向合成断言——chat 协议合成 finish_reason:stop 事件
        # + [DONE] 恰 1 个（去重后）
        assert 'finish_reason' in raw
        assert raw.count('data: [DONE]') == 1, f'[DONE] 数量异常: {raw!r}'
        # caplog 含截断 warning（合成路径触发过告警——「流截断」或
        # 「未收到终止事件」两个 warning 之一）
        assert any(
            '截断' in r.message or 'truncated' in r.message or '终止' in r.message
            for r in caplog.records
        ), f'截断 warning 未记录: {[r.message for r in caplog.records]}'


@pytest.mark.asyncio
async def test_integration_refusal_line_buffer():
    """8.7：真实 handler — refusal 行缓冲不泄漏 PII。"""
    async with env(), ClientSession() as s:
        body = json.dumps({'case': 'refusal_line'})
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
        # 响应侧新检测 PII → 注册为 token（不还原为明文，不泄漏原文）
        assert '13800138000' not in raw
        assert '拒绝' in raw
        assert 'data: [DONE]' in raw


@pytest.mark.asyncio
async def test_fast_chain_whatwg_bom_and_comment():
    """8.8（F-09）：快链 BOM 剥离 + `:` 注释透传 + CR-only EOF。

    快链（active_t2p 为空但有 PII 检测）复用慢链 WHATWG 帧状态机：
    BOM 单次剥离、`: keepalive` 注释透传不解析、CR-only 行 EOF 正常 dispatch。
    """

    async def _make_stream_handler():
        async def handler(request):
            resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
            await resp.prepare(request)
            # BOM + 注释 + data 行 + CR-only 行
            await resp.write(b'\xef\xbb\xbf: keepalive\n\n')
            await resp.write(
                (
                    'data: {"choices":[{"index":0,"delta":{"content":"第一行"}}]}\n\n'
                ).encode()
            )
            await resp.write(
                (
                    'data: {"choices":[{"index":0,"delta":{"content":"第二行"}}]}\r'
                ).encode()
            )
            await resp.write_eof()
            return resp

        app = web.Application()
        app.router.add_route('*', '/{tail:.*}', handler)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, '127.0.0.1', UPSTREAM_PORT).start()
        return runner

    up_runner = await _make_stream_handler()
    try:
        proxy = await make_proxy()
        try:
            async with ClientSession() as s:
                body = json.dumps(
                    {'case': 'x', 'messages': [{'role': 'user', 'content': 'hi'}]}
                )
                async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
                    assert r.status == 200
                    raw = await r.text()
            # BOM 已剥离（无 EF BB BF 残留）、注释透传、两 data 行均出现
            assert '\xef\xbb\xbf' not in raw
            assert ': keepalive' in raw
            assert '第一行' in raw
            assert '第二行' in raw
        finally:
            for r in proxy._runners:
                await r.cleanup()
            if proxy._shared_session:
                await proxy._shared_session.close()
    finally:
        await up_runner.cleanup()


@pytest.mark.asyncio
async def test_sentinel_chat_fixture_choices_n2_and_tool_calls():
    """9.13 (F-13): sentinel_chat.jsonl 真实 handler 回放——choices n=2 第二路
    不丢、tool_calls arguments 还原、正常流不合成截断（[DONE] 恰 1 个）。

    该 fixture 含：n=2 第二路 __PII token 回显（9.3 全量遍历）、
    tool_calls arguments 内嵌 token（还原）、finish_reason=tool_calls。
    请求 body 必须包含 13812345678 使代理注册 token，且请求带 tools 定义。
    """
    async with env(), ClientSession() as s:
        body = json.dumps(
            {
                'case': 'sentinel_chat',
                'messages': [{'role': 'user', 'content': '查询 13812345678 的订单'}],
                'tools': [
                    {
                        'type': 'function',
                        'function': {
                            'name': 'query_order',
                            'parameters': {
                                'type': 'object',
                                'properties': {'phone': {'type': 'string'}},
                            },
                        },
                    }
                ],
            }
        )
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
        # 10.11.2 (F-TEST-01): 第二路 content 用独立明文「独立第二路」
        # （与 tool_calls 内嵌 token 解耦）——断言它出现即锁定第二路
        # content 不被 9.3 聚合/审计 continue 丢弃（原 fixture 第二路与
        # tool_calls 同 token，tool_calls 路径也能满足断言，回退 9.3 仍绿）
        assert '独立第二路' in raw, f'第二路 content 丢失: {raw!r}'
        # 9.3: 第一路 content 正常
        assert '第一路' in raw
        # 9.3: 工具调用 arguments 内嵌 token 还原为明文
        assert '13812345678' in raw, f'tool_calls token 未还原: {raw!r}'
        # 工具调用存在
        assert 'query_order' in raw
        # 正常流不合成截断：无 TRUNCATED_MESSAGE，[DONE] 恰 1 个
        assert 'TRUNCATED_MESSAGE' not in raw and '被截断' not in raw
        assert raw.count('data: [DONE]') == 1, f'[DONE] 数量异常: {raw!r}'


@pytest.mark.asyncio
async def test_integration_cr_only_eof_dispatch():
    """9.13 (F-12 改造): CR-only 行（无 LF）流末真实 handler dispatch——
    替代 residual_hardening 自模拟：上游末行以 \r 结尾断流，代理应
    立即分发该行（还原 token），不残留、不误判截断、[DONE] 恰 1 个。
    """
    async with env(), ClientSession() as s:
        body = json.dumps(
            {
                'case': 'cr_only_eof',
                'messages': [{'role': 'user', 'content': '我的号码是 13800138000'}],
            }
        )
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
        # CR 尾行内容已分发：第一行+CR 行合并后内容存在
        assert '第一行' in raw or '\\u7b2c\\u4e00\\u884c' in raw
        # CR 尾行 token 还原为明文
        assert '13800138000' in raw, f'CR 尾行 token 未还原: {raw!r}'
        # 无合成截断（[DONE] 恰 1 个）
        assert 'TRUNCATED_MESSAGE' not in raw and '被截断' not in raw
        assert raw.count('data: [DONE]') == 1, f'[DONE] 数量异常: {raw!r}'


@pytest.mark.asyncio
async def test_fast_chain_line_buf_cross_data():
    """9.5 (F-05)：快链跨 data 行切断 PII 片段（user@exa + mple.com）合并后统一处理。

    快链（active_t2p 为空但有 PII 检测）line_buf 行缓冲：跨 data: 事件切断的
    邮箱片段不透漏，合并后整体还原。
    """

    async def _make_stream_handler():
        async def handler(request):
            resp = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
            await resp.prepare(request)
            # 两 data 行各含半截邮箱（跨事件切断）
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"content":"user@exa"}}]}\n\n'
            )
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"content":"mple.com"}}]}\n\n'
            )
            await resp.write(
                b'data: {"choices":[{"index":0,"delta":{"content":" OK"}}]}\n\n'
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

    up_runner = await _make_stream_handler()
    try:
        proxy = await make_proxy()
        try:
            async with ClientSession() as s:
                body = json.dumps(
                    {'case': 'x', 'messages': [{'role': 'user', 'content': 'hi'}]}
                )
                async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
                    assert r.status == 200
                    raw = await r.text()
            # 片段不透漏：半截邮箱不孤立出现（完整邮箱或掩码形态允许）
            # 检查：user@exa 后不紧跟行结束/JSON 边界（即不是孤立片段）
            import re as _re

            assert not _re.search(r'user@exa(?!mple)', raw), f'孤立片段泄漏: {raw!r}'
            # 合并后完整输出（完整邮箱或 PII 掩码，非半截）
            assert 'user@example.com' in raw or 'user@exa' not in raw
            # 无合成截断（[DONE] 恰 1 个）
            assert raw.count('data: [DONE]') == 1
        finally:
            for r in proxy._runners:
                await r.cleanup()
            if proxy._shared_session:
                await proxy._shared_session.close()
    finally:
        await up_runner.cleanup()


@pytest.mark.asyncio
async def test_integration_cr_only_done():
    """10.5.1 (F-01/R-03)：CR-only 的 `data: [DONE]`（无 LF）流末 EOF——
    单独透传、置位终止，不合成截断、不双发 [DONE]。"""

    async with env(), ClientSession() as s:
        body = json.dumps(
            {
                'case': 'cr_only_done',
                'messages': [{'role': 'user', 'content': '我的号码是 13800138000'}],
            }
        )
        async with s.post(CHAT_BASE, headers=HEADERS, data=body) as r:
            assert r.status == 200
            raw = await r.text()
        # 内容行已分发 + token 还原
        assert '正常内容' in raw
        assert '13800138000' in raw, f'CR-only [DONE] 流 token 未还原: {raw!r}'
        # 无合成截断（[DONE] 恰 1 个，来自 CR-only 透传）
        assert 'TRUNCATED_MESSAGE' not in raw and '被截断' not in raw
        assert raw.count('data: [DONE]') == 1, f'[DONE] 数量异常: {raw!r}'
