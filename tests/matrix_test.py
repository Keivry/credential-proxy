"""test_matrix.py — MatrixMixin 消息发送异常保护单元测试。

覆盖: _ask 的 room_send 抛异常（Matrix 断连/不可达）时返回 None 而非
传播异常——调用者的 `if msg_id is None:` 清理分支（unlock_event 等）
得以接管，避免解锁状态残留导致的永久 408 死锁。

与 test_llm.py（mock aiohttp）同模式：模块级 mock aiohttp + nio。
"""

import asyncio
import sys
import types
from unittest.mock import AsyncMock, MagicMock

import pytest

# ── Mock aiohttp ──
aw = types.ModuleType('aiohttp.web')
aw.Response = MagicMock()
aw.Application = MagicMock()
aw.AppRunner = MagicMock()
aw.TCPSite = MagicMock()
aw.StreamResponse = MagicMock()
aw.json_response = MagicMock(return_value=MagicMock())
aiohttp = types.ModuleType('aiohttp')
aiohttp.web = aw
aiohttp.ClientSession = MagicMock()
aiohttp.ClientTimeout = MagicMock()
ce = types.ModuleType('aiohttp.client_exceptions')
ce.ClientConnectionError = type('ClientConnectionError', (Exception,), {})
ce.ServerDisconnectedError = type('ServerDisconnectedError', (Exception,), {})
ce.ClientConnectionResetError = type('ClientConnectionResetError', (Exception,), {})
aiohttp.client_exceptions = ce
sys.modules['aiohttp'] = aiohttp
sys.modules['aiohttp.web'] = aw
sys.modules['aiohttp.client_exceptions'] = ce

# ── Mock nio ──
nio = types.ModuleType('nio')
nio.AsyncClient = MagicMock()
nio.RoomMessageText = MagicMock()
nio.ReactionEvent = MagicMock()
sys.modules['nio'] = nio

# llm_test.py 模块级 mock 会污染 sys.modules['_matrix']（按字母序先导入）；
# 全量 pytest 时须先清除，确保加载真实 _matrix / _sse。
sys.modules.pop('_matrix', None)
sys.modules.pop('_sse', None)

from _matrix import MatrixMixin
from _sse import REACTIONS


class TestMatrixAsk(MatrixMixin):
    """最小对象：仅提供 _ask/_say 依赖的 self 属性。"""

    __test__ = False

    def __init__(self):
        self._lock = asyncio.Lock()
        self.client = MagicMock()
        self.room_id = '!test:example.org'
        self._start_ts = 0
        self.master_password = None
        self.unlock_event = None
        self._unlock_msg_id = None
        self._unlock_in_progress = False
        self._unlock_generation = 0
        self.pending_requests = {}
        self.approval_msgs = {}
        self._registration_msgs = {}
        self._registration_pending = {}
        self._hash_change_msgs = {}
        self._hash_change_pending = {}
        self.pwd_to_token = {}
        self.token_to_pwd = {}
        self._base_dir = '/tmp'


@pytest.mark.asyncio
async def test_ask_room_send_exception_returns_none():
    """Matrix 断连时 room_send 抛异常 → _ask 返回 None 而不传播异常。"""
    p = TestMatrixAsk()
    p.client.room_send = AsyncMock(
        side_effect=ConnectionError('Matrix homeserver 不可达'),
    )
    result = await p._ask('🔑 凭据请求: test')
    assert result is None


@pytest.mark.asyncio
async def test_ask_success_returns_event_id():
    """正常路径：room_send 成功 → 返回 event_id 并预加 reaction。"""
    p = TestMatrixAsk()
    p.client.room_send = AsyncMock(
        side_effect=lambda *a, **kw: {'event_id': 'evt_123'},
    )
    result = await p._ask('审批消息')
    assert result == 'evt_123'
    # 消息 1 次 + reaction len(REACTIONS) 次
    assert p.client.room_send.await_count == 1 + len(REACTIONS)


@pytest.mark.asyncio
async def test_ask_reaction_failure_still_returns_event_id():
    """reaction 发送失败（部分成功）→ 仍返回 event_id（消息可用）。"""
    p = TestMatrixAsk()
    calls = 0

    async def flaky_room_send(*a, **kw):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {'event_id': 'evt_456'}
        raise ConnectionError('reaction 发送失败')

    p.client.room_send = AsyncMock(side_effect=flaky_room_send)
    result = await p._ask('审批消息')
    assert result == 'evt_456'
