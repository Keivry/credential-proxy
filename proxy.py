#!/usr/bin/env python3
"""Credential Proxy — Matrix 审批 + TPM + KeePassXC + LLM 脱敏代理。

架构: CredentialProxy 继承 5 个 Mixin，按职责分文件:
  _token.py      — TokenMixin      凭据脱敏/还原
  _tpm.py        — TpmMixin        TPM 硬件解封
  _matrix.py     — MatrixMixin     Matrix Bot 交互
  _credential.py — CredentialMixin 凭据 HTTP API
  _llm.py        — LlmMixin        LLM 反向代理

入口: python proxy.py <homeserver> <room_id>
LLM 代理通过环境变量配置: LLM_8878=https://api.opencode.ai
MATRIX_ACCESS_TOKEN 环境变量提供 Matrix Bot 的 access token
"""
import asyncio
import logging
import os
import sys
import time
from collections import OrderedDict

from _token import TokenMixin
from _tpm import TpmMixin
from _matrix import MatrixMixin
from _credential import CredentialMixin, _CREDENTIAL_API_PORT as CREDENTIAL_API_PORT
from _llm import LlmMixin

logger = logging.getLogger("credential-proxy")

# ── 目录常量 ──
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", BASE_DIR)
TPM_DIR = os.environ.get("TPM_DIR", os.path.join(DATA_DIR, "tpm"))
DB_DIR = os.environ.get("DB_DIR", os.path.join(DATA_DIR, "db"))


# ── 环境变量解析 ──
def _parse_proxy_env() -> dict[int, str]:
    """从 LLM_<PORT>=<URL> 环境变量读取上游配置。"""
    proxies: dict[int, str] = {}
    for k, v in os.environ.items():
        if not k.startswith("LLM_"):
            continue
        try:
            port = int(k[4:])
        except ValueError:
            continue
        proxies[port] = v.strip().rstrip("/")
        if not proxies[port]:
            del proxies[port]
    return proxies


# ════════════════════════════════════════════════════════════════════════
# 主类：继承全部 Mixin
# ════════════════════════════════════════════════════════════════════════

class CredentialProxy(
    TokenMixin,
    TpmMixin,
    MatrixMixin,
    CredentialMixin,
    LlmMixin,
):
    """凭据代理：TPM 解锁 → Matrix 审批 → KeePass 查询 → LLM 脱敏代理。"""

    def __init__(self, homeserver: str, room_id: str, access_token: str):
        # ── Matrix ──
        self.homeserver = homeserver
        self.room_id = room_id
        self.access_token = access_token
        self.client = None   # nio.AsyncClient，start_bot() 创建

        # ── 状态 ──
        self.master_password = None
        self._kp = None                     # KeePass 缓存
        self._kp_semaphore = asyncio.Semaphore(1)  # 序列化 KeePass 访问
        self._lock = asyncio.Lock()         # 全局互斥锁
        self._shutting_down = False
        self._start_ts = int(time.time() * 1000)
        self._base_dir = DATA_DIR

        # ── 解锁状态 ──
        self.unlock_event = None            # asyncio.Event
        self._unlock_msg_id = None
        self._unlock_in_progress = False
        self._unlock_generation = 0
        self._unlock_task = None

        # ── 审批状态 ──
        self.pending_requests: dict = {}
        self.approval_msgs: dict = {}
        self._runners: list = []            # aiohttp AppRunner 列表

        # ── 凭据频率限制 ──
        self._last_credential_request = 0.0

        # ── Token 映射 (TokenMixin 使用) ──
        self.pwd_to_token = OrderedDict()
        self.token_to_pwd: dict = {}
        self._token_seq = 0

        # ── 密码库 ──
        self.kdbx_path = None
        self.keyfile_path = None
        if os.path.isdir(DB_DIR):
            kdbx_files: list[str] = []
            for f in sorted(os.listdir(DB_DIR)):
                if f.endswith(".kdbx"):
                    kdbx_files.append(f)
                    self.kdbx_path = os.path.join(DB_DIR, f)
                elif f.endswith(".key"):
                    self.keyfile_path = os.path.join(DB_DIR, f)
            if len(kdbx_files) > 1:
                logger.warning(
                    "DB_DIR 中发现 %d 个 .kdbx 文件，使用字母序最后一个: %s",
                    len(kdbx_files), kdbx_files[-1],
                )
        if self.kdbx_path:
            logger.info("密码库: %s", self.kdbx_path)
        else:
            logger.warning("未找到 .kdbx 文件，凭据获取将不可用")

        # ── TPM (TpmMixin 使用) ──
        self.tpm_primary = os.path.join(TPM_DIR, "primary.ctx")
        self.tpm_seal_pub = os.path.join(TPM_DIR, "seal.pub")
        self.tpm_seal_priv = os.path.join(TPM_DIR, "seal.priv")
        logger.info("TPM primary: %s", self.tpm_primary)

        # ── LLM 代理配置 (LlmMixin 使用) ──
        self.proxies = _parse_proxy_env()
        self._shared_session = None  # 在 start_llm_proxies() 创建
        for port, url in sorted(self.proxies.items()):
            logger.info("LLM 代理 → 0.0.0.0:%d → %s", port, url)

    # ── 主循环 ──

    async def run(self):
        tasks = [
            self.start_credential_api(CREDENTIAL_API_PORT),
            self.start_llm_proxies(),
            self.start_bot(),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.error("服务启动失败: %s", r)


# ════════════════════════════════════════════════════════════════════════
# 入口
# ════════════════════════════════════════════════════════════════════════

def main():
    import signal as _signal

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    # homeserver / room_id: 环境变量优先，CLI 参数作为后备
    homeserver = os.environ.get("HOMESERVER", "")
    room_id = os.environ.get("ROOM_ID", "")
    if len(sys.argv) >= 3:
        homeserver = homeserver or sys.argv[1]
        room_id = room_id or sys.argv[2]
    if not homeserver or not room_id:
        print(
            "错误: 请设置 HOMESERVER + ROOM_ID 环境变量，或传命令行参数",
            file=sys.stderr,
        )
        print("\\n环境变量：", file=sys.stderr)
        print("  HOMESERVER            Matrix homeserver URL", file=sys.stderr)
        print("  ROOM_ID               Matrix 房间 ID", file=sys.stderr)
        print("  MATRIX_ACCESS_TOKEN   Matrix Bot 的 access token", file=sys.stderr)
        print("  CREDENTIAL_PORT       凭据 API 端口 (默认 8877)", file=sys.stderr)
        print("  DATA_DIR              数据目录 (默认: 脚本所在目录 或 /data in Docker)", file=sys.stderr)
        print("  LLM_8878=https://api.opencode.ai", file=sys.stderr)
        print("  LLM_8879=https://api.deepseek.com", file=sys.stderr)
        sys.exit(1)

    # access_token 从环境变量读取（避免 ps aux 泄露）
    access_token = os.environ.get("MATRIX_ACCESS_TOKEN", "")
    if not access_token:
        print("错误: 请设置 MATRIX_ACCESS_TOKEN 环境变量", file=sys.stderr)
        sys.exit(1)

    proxy = CredentialProxy(homeserver, room_id, access_token)

    async def shutdown(sig):
        if proxy._shutting_down:
            return
        proxy._shutting_down = True
        logger.info("收到信号 %s，正在优雅关闭…", sig.name)
        if proxy.client is not None:
            await proxy._say("🔌 Proxy 正在关闭…")
        async with proxy._lock:
            proxy.master_password = None
            proxy._kp = None
            if proxy.unlock_event and not proxy.unlock_event.is_set():
                proxy.unlock_event.set()
            for r in proxy.pending_requests.values():
                if not r["event"].is_set():
                    r["event"].set()
        for runner in proxy._runners:
            await runner.cleanup()
        proxy._runners.clear()
        # 关闭共享 ClientSession
        if proxy._shared_session:
            await proxy._shared_session.close()
        tasks = [
            t for t in asyncio.all_tasks()
            if t is not asyncio.current_task()
        ]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for s in (_signal.SIGTERM, _signal.SIGINT):
        loop.add_signal_handler(
            s, lambda s=s: asyncio.create_task(shutdown(s)),
        )
    try:
        loop.run_until_complete(proxy.run())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        loop.close()
        logger.info("Proxy 已关闭")


if __name__ == "__main__":
    main()
