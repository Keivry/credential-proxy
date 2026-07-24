#!/usr/bin/env python3
"""轻量版 LLM Proxy — 无 Matrix/TPM/KeePass，仅 LLM 脱敏代理。

用法:
  LLM_8878=http://10.200.8.2:8878/v1 \\
  LLM_8879=https://api.deepseek.com/v1 \\
  OPENCODE_GO_API_KEY=sk-xxx \\
  DEEPSEEK_API_KEY=sk-xxx \\
  python3 llm-proxy-only.py

环境变量:
  LLM_<PORT>=<UPSTREAM_URL>  — 端口→上游映射（必须）
  CREDENTIAL_PROXY_DEBUG_DIR — 可选，调试数据保存目录
"""

import asyncio
import logging
import os
import sys
from collections import OrderedDict

from _llm import LlmMixin
from _token import TokenMixin

logger = logging.getLogger('llm-proxy')


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


class LlmOnlyProxy(TokenMixin, LlmMixin):
    """轻量版 LLM 代理，不含凭据管理/审批功能。"""

    def __init__(self):
        self._lock = asyncio.Lock()
        self.pwd_to_token = OrderedDict()
        self.token_to_pwd: dict = {}
        self._token_seq = 0
        self.proxies = _parse_proxy_env()
        self._shared_session = None
        self._runners: list = []

        for port, url in sorted(self.proxies.items()):
            logger.info('LLM 代理 → 0.0.0.0:%d → %s', port, url)

    async def run(self):
        if not self.proxies:
            logger.error('未设置 LLM_<PORT>=<URL> 环境变量，退出')
            sys.exit(1)
        await self.start_llm_proxies()
        logger.info('LLM 代理已启动，按 Ctrl+C 停止')
        # 保持运行
        try:
            await asyncio.Event().wait()
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
    proxy = LlmOnlyProxy()
    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        logger.info('收到中断信号，退出')


if __name__ == '__main__':
    main()
