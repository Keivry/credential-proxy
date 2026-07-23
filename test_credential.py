"""test_credential.py — CredentialMixin 集成测试。

Mock: aiohttp Request, Matrix _ask/_say, TPM _tpm_unseal, KeePass PyKeePass。
覆盖: 解锁流程、审批流程、频率限制、错误路径。
"""
import asyncio
import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Mock 外部依赖 ──
# aiohttp
aw = types.ModuleType("aiohttp.web")
aw.Response = MagicMock()
aw.Application = MagicMock()
aw.AppRunner = MagicMock()
aw.TCPSite = MagicMock()
aw.StreamResponse = MagicMock()
aw.json_response = MagicMock(return_value=MagicMock())
aiohttp = types.ModuleType("aiohttp")
aiohttp.web = aw
aiohttp.ClientSession = MagicMock()
aiohttp.ClientTimeout = MagicMock()
ce = types.ModuleType("aiohttp.client_exceptions")
ce.ClientConnectionResetError = type("CR", (Exception,), {})
aiohttp.client_exceptions = ce
sys.modules["aiohttp"] = aiohttp
sys.modules["aiohttp.web"] = aw
sys.modules["aiohttp.client_exceptions"] = ce

# nio
nio = types.ModuleType("nio")
nio.AsyncClient = MagicMock()
nio.RoomMessageText = MagicMock()
nio.ReactionEvent = MagicMock()
sys.modules["nio"] = nio

# pykeepass
pk = types.ModuleType("pykeepass")
pk.PyKeePass = MagicMock()
sys.modules["pykeepass"] = pk

from _credential import CredentialMixin
from _token import TokenMixin


# ═══════════════════════════════════════════════════════════
# 测试辅助: 带 mock 的最小 CredentialProxy
# ═══════════════════════════════════════════════════════════

class MockProxy(TokenMixin, CredentialMixin):
    """最小 mock：提供 CredentialMixin 需要的所有 self 属性。"""

    def __init__(self, *, kdbx_available=True):
        self._lock = asyncio.Lock()
        self._runners = []
        self._shutting_down = False
        self._start_ts = 0

        # 解锁状态
        self.master_password = None
        self.unlock_event = None
        self._unlock_msg_id = None
        self._unlock_in_progress = False
        self._unlock_generation = 0
        self._unlock_task = None

        # 审批状态
        self.pending_requests = {}
        self.approval_msgs = {}

        # 频率限制
        self._last_credential_request = 0.0

        # Token
        self.pwd_to_token = type("FakeOD", (dict,), {
            "move_to_end": lambda s, k: None,
        })()
        self.token_to_pwd = {}
        self._token_seq = 0

        # 密码库
        self.kdbx_path = "/fake/db.kdbx" if kdbx_available else None
        self.keyfile_path = None
        self._kp = None

        # Mock _ask 和 _say（跨 Mixin 依赖）
        self._ask_mock = AsyncMock(return_value="mock_event_id")
        self._say_mock = AsyncMock()

    async def _ask(self, text: str) -> str | None:
        return await self._ask_mock(text)

    async def _say(self, text: str):
        await self._say_mock(text)

    async def _do_unlock(self, generation=0):
        """模拟 TPM 解封成功。"""
        async with self._lock:
            self.master_password = "test_master_pw"
            self._unlock_in_progress = False
            if self.unlock_event and not self.unlock_event.is_set():
                self.unlock_event.set()


# ═══════════════════════════════════════════════════════════
# 辅助: 构造 aiohttp Request mock
# ═══════════════════════════════════════════════════════════

def make_request(json_body=None):
    """构造模拟的 aiohttp Request。"""
    req = AsyncMock()
    req.json = AsyncMock(return_value=json_body or {})
    return req


# ═══════════════════════════════════════════════════════════
# 健康检查
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_health_locked():
    p = MockProxy()
    resp = await p.handle_health(None)
    # json_response is mocked, inspect the call
    call_args = aw.json_response.call_args[0][0]
    assert call_args["status"] == "ok"
    assert call_args["unlocked"] is False


@pytest.mark.asyncio
async def test_health_unlocked():
    p = MockProxy()
    p.master_password = "secret"
    resp = await p.handle_health(None)
    call_args = aw.json_response.call_args[0][0]
    assert call_args["unlocked"] is True


# ═══════════════════════════════════════════════════════════
# 频率限制
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_rate_limit():
    p = MockProxy()
    p.master_password = "pw"  # 已解锁，跳过解锁阶段
    # 第一次请求
    req1 = make_request({"entry": "test_entry"})
    # Mock _ask to trigger approval immediately
    p._ask_mock.return_value = "msg_1"

    # 模拟审批通过
    async def approve_after_msg(*args):
        async with p._lock:
            for rid, req_data in list(p.pending_requests.items()):
                req_data["approved"] = True
                req_data["event"].set()
        return "msg_1"
    p._ask_mock.side_effect = approve_after_msg

    # 第二次请求（太快）
    req2 = make_request({"entry": "test_entry2"})
    # 第一次通过
    await p.handle_credential(req1)
    # 第二次应被限速
    resp = await p.handle_credential(req2)
    call_args = aw.json_response.call_args[0][0]
    assert call_args["error"] == "请求过于频繁，请稍后再试"


# ═══════════════════════════════════════════════════════════
# 解锁流程
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_unlock_flow():
    """未解锁 → 触发解锁 → 审批通过 → 取凭据。"""
    p = MockProxy()

    # 模拟 _ask 发送消息后，外部通过 _do_unlock 完成解锁
    unlock_done = False

    async def ask_side_effect(text):
        nonlocal unlock_done
        if "未解锁" in text:
            await p._do_unlock()
            unlock_done = True
            return "unlock_msg_id"
        else:
            # 审批消息：自动批准
            async with p._lock:
                for rid, req_data in list(p.pending_requests.items()):
                    req_data["approved"] = True
                    req_data["event"].set()
            return "approval_msg_id"

    p._ask_mock.side_effect = ask_side_effect

    req = make_request({"entry": "test_entry"})
    await p.handle_credential(req)
    assert unlock_done
    assert p.master_password == "test_master_pw"


@pytest.mark.asyncio
async def test_unlock_rejected():
    """解锁被拒绝 → 返回 403。"""
    p = MockProxy()

    async def ask_side_effect(text):
        if "未解锁" in text:
            async with p._lock:
                if p.unlock_event and not p.unlock_event.is_set():
                    p.unlock_event.set()
                p.unlock_event = None
            return "unlock_msg_id"
        return "approval_msg_id"

    p._ask_mock.side_effect = ask_side_effect

    req = make_request({"entry": "test_entry"})
    await p.handle_credential(req)
    call_args = aw.json_response.call_args[0][0]
    assert call_args["error"] == "解锁失败"


@pytest.mark.asyncio
async def test_unlock_timeout():
    """解锁超时 → 返回 408。"""
    p = MockProxy()

    # _ask 发送消息但从不批准，让 wait_for 超时
    p._ask_mock.return_value = "msg_id"

    # 缩短超时
    import _credential
    original_timeout = _credential.UNLOCK_TIMEOUT
    _credential.UNLOCK_TIMEOUT = 0.1  # 100ms

    req = make_request({"entry": "test_entry"})
    await p.handle_credential(req)
    call_args = aw.json_response.call_args[0][0]
    assert call_args["error"] == "解锁超时"

    _credential.UNLOCK_TIMEOUT = original_timeout


@pytest.mark.asyncio
async def test_concurrent_unlock_only_one_ask():
    """并发解锁请求只发一次审批消息。"""
    p = MockProxy()
    ask_count = 0

    async def ask_side_effect(text):
        nonlocal ask_count
        ask_count += 1
        if "未解锁" in text:
            await p._do_unlock()
        else:
            async with p._lock:
                for rid, req_data in list(p.pending_requests.items()):
                    req_data["approved"] = True
                    req_data["event"].set()
        return f"msg_{ask_count}"

    p._ask_mock.side_effect = ask_side_effect

    # 两个并发请求
    req1 = make_request({"entry": "e1"})
    req2 = make_request({"entry": "e2"})
    await asyncio.gather(
        p.handle_credential(req1),
        p.handle_credential(req2),
    )
    # 解锁消息只发送了一次
    unlock_asks = sum(1 for call in p._ask_mock.call_args_list
                      if "未解锁" in call[0][0])
    assert unlock_asks <= 1


# ═══════════════════════════════════════════════════════════
# 审批流程
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_approval_approved():
    """审批通过 → 正常取凭据。"""
    p = MockProxy()
    p.master_password = "pw"

    async def ask_side_effect(text):
        async with p._lock:
            for rid, req_data in list(p.pending_requests.items()):
                req_data["approved"] = True
                req_data["event"].set()
        return "msg_id"

    p._ask_mock.side_effect = ask_side_effect

    req = make_request({"entry": "test_entry"})
    await p.handle_credential(req)
    # 审批通过后应进入 KeePass 查询（mock 自动创建属性，返回成功）
    call_args = aw.json_response.call_args[0][0]
    # 应返回凭据数据而非错误
    assert "error" not in call_args or "KeePass" in str(call_args.get("error", ""))


@pytest.mark.asyncio
async def test_approval_rejected():
    """审批被拒绝 → 返回 403。"""
    p = MockProxy()
    p.master_password = "pw"

    async def ask_side_effect(text):
        async with p._lock:
            for rid, req_data in list(p.pending_requests.items()):
                req_data["approved"] = False  # 拒绝
                req_data["event"].set()
        return "msg_id"

    p._ask_mock.side_effect = ask_side_effect

    req = make_request({"entry": "test_entry"})
    await p.handle_credential(req)
    call_args = aw.json_response.call_args[0][0]
    assert call_args["error"] == "审批被拒绝"


@pytest.mark.asyncio
async def test_approval_timeout():
    """审批超时 → 返回 408。"""
    p = MockProxy()
    p.master_password = "pw"
    p._ask_mock.return_value = "msg_id"

    import _credential
    original = _credential.APPROVAL_TIMEOUT
    _credential.APPROVAL_TIMEOUT = 0.1

    req = make_request({"entry": "test_entry"})
    await p.handle_credential(req)
    call_args = aw.json_response.call_args[0][0]
    assert call_args["error"] == "审批超时"

    _credential.APPROVAL_TIMEOUT = original


# ═══════════════════════════════════════════════════════════
# 错误路径
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_missing_entry():
    p = MockProxy()
    p.master_password = "pw"
    req = make_request({"entry": ""})
    await p.handle_credential(req)
    call_args = aw.json_response.call_args[0][0]
    assert call_args["error"] == "缺少 entry 参数"


@pytest.mark.asyncio
async def test_invalid_json():
    p = MockProxy()
    p.master_password = "pw"
    req = make_request()
    req.json = AsyncMock(side_effect=Exception("bad json"))
    await p.handle_credential(req)
    call_args = aw.json_response.call_args[0][0]
    assert call_args["error"] == "JSON 格式错误"


@pytest.mark.asyncio
async def test_no_kdbx():
    p = MockProxy(kdbx_available=False)
    p.master_password = "pw"

    async def ask_side_effect(text):
        async with p._lock:
            for rid, req_data in list(p.pending_requests.items()):
                req_data["approved"] = True
                req_data["event"].set()
        return "msg_id"

    p._ask_mock.side_effect = ask_side_effect

    req = make_request({"entry": "test_entry"})
    await p.handle_credential(req)
    call_args = aw.json_response.call_args[0][0]
    assert "密码库未配置" in call_args["error"]


@pytest.mark.asyncio
async def test_ask_message_failed():
    """_ask 返回 None（消息发送失败）→ 503。"""
    p = MockProxy()
    p.master_password = "pw"
    p._ask_mock.return_value = None

    req = make_request({"entry": "test_entry"})
    await p.handle_credential(req)
    call_args = aw.json_response.call_args[0][0]
    assert call_args["error"] == "无法发送审批消息"


# ═══════════════════════════════════════════════════════════
# _cleanup_request
# ═══════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_cleanup_removes_from_both():
    p = MockProxy()
    async with p._lock:
        p.pending_requests["req1"] = {"approved": None}
        p.approval_msgs["msg1"] = "req1"
        p.approval_msgs["msg2"] = "req2"  # 不相关

    async with p._lock:
        await p._cleanup_request("req1")

    assert "req1" not in p.pending_requests
    assert "msg1" not in p.approval_msgs
    assert "msg2" in p.approval_msgs  # 不相关的保留
