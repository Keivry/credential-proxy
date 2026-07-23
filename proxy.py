#!/usr/bin/env python3
"""Credential Proxy — Matrix 审批 + TPM + KeePassXC + LLM 脱敏代理。

架构: CredentialProxy 继承 5 个 Mixin，按职责分文件:
  _token.py      — TokenMixin      凭据脱敏/还原
  _tpm.py        — TpmMixin        TPM 硬件解封
  _matrix.py     — MatrixMixin     Matrix Bot 交互
  _credential.py — CredentialMixin 凭据 HTTP API
  _llm.py        — LlmMixin        LLM 反向代理

入口: python proxy.py <homeserver> <room_id> <access_token>
LLM 代理通过环境变量配置: LLM_8878=https://api.opencode.ai/v1
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
from _credential import CredentialMixin, CREDENTIAL_API_PORT
from _llm import LlmMixin

logger = logging.getLogger("credential-proxy")

# ── 目录常量 ──
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TPM_DIR = os.path.join(BASE_DIR, "tpm")
DB_DIR = os.path.join(BASE_DIR, "db")


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
        self._lock = asyncio.Lock()         # 全局互斥锁
        self._shutting_down = False
        self._start_ts = int(time.time() * 1000)
        self._base_dir = BASE_DIR

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
                    f"DB_DIR 中发现 {len(kdbx_files)} 个 .kdbx 文件，"
                    f"使用字母序最后一个: {kdbx_files[-1]}"
                )
        if self.kdbx_path:
            logger.info(f"密码库: {self.kdbx_path}")
        else:
            logger.warning("未找到 .kdbx 文件，凭据获取将不可用")

        # ── TPM (TpmMixin 使用) ──
        self.tpm_primary = os.path.join(TPM_DIR, "primary.ctx")
        self.tpm_seal_pub = os.path.join(TPM_DIR, "seal.pub")
        self.tpm_seal_priv = os.path.join(TPM_DIR, "seal.priv")
        logger.info(f"TPM primary: {self.tpm_primary}")

        # ── LLM 代理配置 (LlmMixin 使用) ──
        self.proxies = _parse_proxy_env()
        self._shared_session = None  # 在 start_llm_proxies() 创建
        for port, url in sorted(self.proxies.items()):
            logger.info(f"LLM 代理 → 0.0.0.0:{port} → {url}")

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
                logger.error(f"服务启动失败: {r}")


# ════════════════════════════════════════════════════════════════════════
# 入口
# ════════════════════════════════════════════════════════════════════════

def main():
    import signal as _signal

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    if len(sys.argv) < 4:
        print(
            f"用法: {sys.argv[0]} <homeserver> <room_id> <access_token>",
            file=sys.stderr,
        )
        print("\nLLM 代理通过环境变量配置：", file=sys.stderr)
        print("  LLM_8878=https://api.opencode.ai/v1", file=sys.stderr)
        print("  LLM_8879=https://api.deepseek.com/v1", file=sys.stderr)
        sys.exit(1)

    proxy = CredentialProxy(sys.argv[1], sys.argv[2], sys.argv[3])

    async def shutdown(sig):
        if proxy._shutting_down:
            return
        proxy._shutting_down = True
        logger.info(f"收到信号 {sig.name}，正在优雅关闭…")
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
