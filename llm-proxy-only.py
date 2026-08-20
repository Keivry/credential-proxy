#!/usr/bin/env python3
"""轻量版 LLM Proxy — 无 Matrix/TPM/KeePass，仅 LLM 脱敏代理。

用法:
  LLM_8878=http://127.0.0.1:8878 \\
  LLM_8879=https://api.deepseek.com \\
  OPENCODE_GO_API_KEY=sk-xxx \\
  DEEPSEEK_API_KEY=sk-xxx \\
  python3 llm-proxy-only.py

环境变量:
  LLM_<PORT>=<UPSTREAM_URL>  — 端口→上游映射（必须，URL 不带 /v1）
  CREDENTIAL_PROXY_DEBUG_DIR — 可选，调试数据保存目录
"""

import asyncio
import logging
import sys
from collections import OrderedDict

from _llm import LlmMixin, parse_llm_proxy_env
from _pii import PiiMixin
from _token import TokenMixin

logger = logging.getLogger('llm-proxy')


class LlmOnlyProxy(TokenMixin, PiiMixin, LlmMixin):
    """轻量版 LLM 代理，不含凭据管理/审批功能。"""

    def __init__(self):
        self._lock = asyncio.Lock()
        self.pwd_to_token = OrderedDict()
        self.token_to_pwd: dict = {}
        self._token_seq = 0
        self.proxies = parse_llm_proxy_env()
        self._shared_session = None
        self._runners: list = []

        # ── PII 配置（Batch 8.1）──
        from _pii import parse_pii_env_config

        pii_cfg = parse_pii_env_config()
        self.pii_enabled = pii_cfg['enabled']
        self.pii_response_side = pii_cfg['response_side']
        self.pii_hold_max = pii_cfg['hold_max']
        self._init_pii()
        if pii_cfg['errors']:
            for e in pii_cfg['errors']:
                logger.error('PII 配置错误: %s', e)
            raise SystemExit(f'PII 配置错误: {pii_cfg["errors"][0]}')
        if self.pii_enabled:
            logger.info(
                'PII 脱敏启用: response_side=%s hold_max=%d',
                self.pii_response_side,
                self.pii_hold_max,
            )

        # ── 审计配置（Batch 8.1/8.2）──
        # 轻量入口无 MatrixMixin → approve 模式不支持，降级 block 并明确告警
        from _audit import parse_audit_env_config

        audit_cfg = parse_audit_env_config(require_whitelist=False)
        if audit_cfg['errors']:
            for e in audit_cfg['errors']:
                logger.error('审计配置错误: %s', e)
            raise SystemExit(f'审计配置错误: {audit_cfg["errors"][0]}')
        if audit_cfg['mode'] == 'approve':
            logger.warning(
                '轻量入口不支持 AUDIT_MODE=approve（无 Matrix 审批），降级为 block 模式'
            )
            audit_cfg['mode'] = 'block'
        self.audit_enabled_flag = audit_cfg['mode'] in ('block', 'approve')
        self.audit_mode = audit_cfg['mode'] if self.audit_enabled_flag else 'block'
        self.audit_timeout = audit_cfg['timeout']
        self.audit_hold_max_bytes = audit_cfg['hold_max']
        self.approval_whitelist = audit_cfg['whitelist']
        self._audit_approval_pending = {}
        self._audit_approval_msgs = {}
        self._audit_pending_seq = 0
        self._audit_log_ring = []
        self._audit_log_fail_count = 0
        if self.audit_enabled_flag:
            logger.info(
                '审计已启用: mode=%s timeout=%ds hold_max=%dB',
                self.audit_mode,
                self.audit_timeout,
                self.audit_hold_max_bytes,
            )

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
