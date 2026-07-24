#!/usr/bin/env python3
"""凭据代理（轻量版）— LLM 脱敏代理 + Credential API，免 Matrix/TPM。

用法:
  LLM_8878=http://10.200.8.2:8878/v1 \\
  LLM_8879=https://api.deepseek.com/v1 \\
  CREDENTIAL_API_PORT=9876 \\
  python3 credential-proxy-only.py

环境变量:
  LLM_<PORT>=<UPSTREAM_URL>   — 端口→上游映射（必须）
  CREDENTIAL_API_PORT         — Credential API 端口（默认 9876）
  CREDENTIAL_MASTER_PASSWORD  — 可选，设置后跳过 TPM 解封
  CREDENTIAL_PROXY_DEBUG_DIR  — 可选，调试数据保存目录
"""

import asyncio
import logging
import os
import sys
from collections import OrderedDict

from _credential import CredentialMixin
from _llm import LlmMixin
from _token import TokenMixin

logger = logging.getLogger('credential-proxy')


def _parse_proxy_env() -> dict[int, str]:
    """从 LLM_<PORT>=<URL> 环境变量读取上游配置。"""
    proxies: dict[int, str] = {}
    for k, v in os.environ.items():
        if not k.startswith('LLM_'):
            continue
        try:
            port = int(k[4:])
        except ValueError:
            continue
        proxies[port] = v.strip().rstrip('/')
        if not proxies[port]:
            del proxies[port]
    return proxies


class CredentialProxyOnly(TokenMixin, CredentialMixin, LlmMixin):
    """轻量版凭据代理：含 Credential API + LLM 代理，无需 Matrix/TPM/KeePass。

    Credential API 的审批请求自动批准（适用于本地/开发环境）。
    """

    def __init__(self):
        self._lock = asyncio.Lock()
        self.pwd_to_token = OrderedDict()
        self.token_to_pwd: dict = {}
        self._token_seq = 0

        # ── LLM 代理 ──
        self.proxies = _parse_proxy_env()
        self._shared_session = None
        self._runners: list = []

        # ── Credential API 状态 ──
        self.master_password = os.environ.get('CREDENTIAL_MASTER_PASSWORD', 'dev-mode')
        self.kdbx_path: str | None = None
        self.keyfile_path: str | None = None
        self._kp = None
        self._kp_semaphore = asyncio.Semaphore(1)
        self.pending_requests: dict = {}
        self.approval_msgs: dict = {}
        self.unlock_event = None
        self._unlock_msg_id = None
        self._unlock_in_progress = False
        self._unlock_generation = 0
        self._last_credential_request = 0.0
        self._start_ts = 0
        self._base_dir = os.path.dirname(os.path.abspath(__file__))
        self._shutting_down = False

        cred_port = int(os.environ.get('CREDENTIAL_API_PORT', '9876'))
        logger.info('Credential API → 0.0.0.0:%d', cred_port)
        self._cred_port = cred_port

        for port, url in sorted(self.proxies.items()):
            logger.info('LLM 代理 → 0.0.0.0:%d → %s', port, url)

    async def _ask(self, text: str) -> str | None:
        """免 Matrix 审批：自动批准 pending_requests 中的所有请求。"""
        async with self._lock:
            for req_id, req in self.pending_requests.items():
                if req.get('approved') is None:
                    req['approved'] = True
                    req['event'].set()
        logger.info('Credential API 自动批准: %s', text.split('\n')[0])
        return 'auto-approved'

    async def run(self):
        tasks = []
        if self._cred_port:
            tasks.append(self.start_credential_api(self._cred_port))
        if self.proxies:
            tasks.append(self.start_llm_proxies())
        if not tasks:
            logger.error('未设置任何服务（需要 LLM_<PORT> 或 CREDENTIAL_API_PORT）')
            sys.exit(1)
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            pass
        finally:
            for runner in self._runners:
                await runner.cleanup()
            if self._shared_session:
                await self._shared_session.close()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    proxy = CredentialProxyOnly()
    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        logger.info('收到中断信号，退出')


if __name__ == '__main__':
    main()
