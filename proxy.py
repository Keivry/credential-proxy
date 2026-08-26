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
import ctypes
import logging
import os
import sys
import time
from collections import OrderedDict

from _credential import _CREDENTIAL_API_PORT as CREDENTIAL_API_PORT
from _credential import CredentialMixin
from _llm import LlmMixin, parse_llm_proxy_env
from _matrix import MatrixMixin
from _pii import PiiMixin
from _registry import RegistryMixin
from _token import TokenMixin
from _tpm import TpmMixin

logger = logging.getLogger('credential-proxy')

# ── 目录常量 ──
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get('DATA_DIR', BASE_DIR)
TPM_DIR = os.environ.get('TPM_DIR', os.path.join(DATA_DIR, 'tpm'))
DB_DIR = os.environ.get('DB_DIR', os.path.join(DATA_DIR, 'db'))


# ════════════════════════════════════════════════════════════════════════
# 主类：继承全部 Mixin
# ════════════════════════════════════════════════════════════════════════


class CredentialProxy(
    TokenMixin,
    TpmMixin,
    MatrixMixin,
    RegistryMixin,
    CredentialMixin,
    PiiMixin,
    LlmMixin,
):
    """凭据代理：TPM 解锁 → Matrix 审批 → KeePass 查询 → LLM 脱敏代理。"""

    @staticmethod
    def _lock_memory():
        """尝试 mlockall 锁定进程内存，防止 master_password 被 swap 到磁盘。
        需要 CAP_IPC_LOCK（容器中需添加该 capability）。
        失败时仅记 warning，不阻止启动。
        """
        try:
            # Linux: libc.so.6 总是存在
            libc = ctypes.CDLL('libc.so.6', use_errno=True)
            MCL_CURRENT = 1
            MCL_FUTURE = 2
            if libc.mlockall(MCL_CURRENT | MCL_FUTURE) == 0:
                logger.info('mlockall OK — 进程内存已锁定，防止 swap')
            else:
                err = ctypes.get_errno()
                if err == 1:  # EPERM
                    logger.warning(
                        'mlockall 失败 (errno=1 EPERM)。'
                        '容器中需添加 CAP_IPC_LOCK 或 --cap-add=ipc_lock',
                    )
                elif err == 12:  # ENOMEM
                    logger.warning(
                        'mlockall 失败 (errno=12 ENOMEM)。'
                        '容器中需添加 ulimits memlock=-1:-1',
                    )
                else:
                    logger.warning(
                        'mlockall 失败 (errno=%d)，密码可能被 swap 到磁盘',
                        err,
                    )
        except OSError:
            logger.warning('mlockall 不可用，密码可能被 swap 到磁盘')

    def __init__(self, homeserver: str, room_id: str, access_token: str):
        # ── mlockall: 进程启动时锁定内存，防 master_password swap ──
        self._lock_memory()

        # ── Matrix ──
        self.homeserver = homeserver
        self.room_id = room_id
        self.access_token = access_token
        self.client = None  # nio.AsyncClient，start_bot() 创建

        # ── 状态 ──
        self.master_password = None
        self._kp = None  # KeePass 缓存
        self._kp_semaphore = asyncio.Semaphore(1)  # 序列化 KeePass 访问
        self._lock = asyncio.Lock()  # 全局互斥锁
        self._shutting_down = False
        self._start_ts = int(time.time() * 1000)
        self._base_dir = DATA_DIR

        # ── 解锁状态 ──
        self.unlock_event = None  # asyncio.Event
        self._unlock_msg_id = None
        self._unlock_in_progress = False
        self._unlock_generation = 0

        # ── 审批状态 ──
        self.pending_requests: dict = {}
        self.approval_msgs: dict = {}
        self._runners: list = []  # aiohttp AppRunner 列表

        # ── 注册表 (RegistryMixin 使用) ──
        self._registrations_by_name: dict = {}
        self._registration_pending: dict = {}
        self._registration_msgs: dict = {}
        # Caller 注册表
        self._caller_registry: dict = {}
        self._caller_registry_by_path: dict = {}
        # 哈希变更审批
        self._hash_change_pending: dict = {}
        self._hash_change_msgs: dict = {}
        self._auto_rate_limits: dict = {}
        self._auto_unlock_event = None

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
            key_files: dict[str, str] = {}
            for f in sorted(os.listdir(DB_DIR)):
                if f.endswith('.kdbx'):
                    kdbx_files.append(f)
                elif f.endswith('.key'):
                    base = f[:-4]  # strip .key
                    key_files[base] = os.path.join(DB_DIR, f)
            if kdbx_files:
                # 取字母序最后一个 .kdbx
                chosen_kdbx = kdbx_files[-1]
                self.kdbx_path = os.path.join(DB_DIR, chosen_kdbx)
                # 尝试用同名 .key，fallback 到字母序最后一个 .key
                base_name = chosen_kdbx[:-5]  # strip .kdbx
                self.keyfile_path = (
                    key_files.get(
                        base_name,
                        # 无匹配时取最后一个 .key（向后兼容）
                        os.path.join(
                            DB_DIR,
                            next(
                                (
                                    f
                                    for f in sorted(os.listdir(DB_DIR))
                                    if f.endswith('.key')
                                ),
                                '',
                            ),
                        )
                        if any(f.endswith('.key') for f in os.listdir(DB_DIR))
                        else None,
                    )
                    if key_files
                    else None
                )
            if len(kdbx_files) > 1:
                logger.warning(
                    'DB_DIR 中发现 %d 个 .kdbx 文件，使用: %s（同名 .key 优先）',
                    len(kdbx_files),
                    kdbx_files[-1],
                )
        if self.kdbx_path:
            logger.info('密码库: %s', self.kdbx_path)
        else:
            logger.warning('未找到 .kdbx 文件，凭据获取将不可用')

        # ── TPM (TpmMixin 使用) ──
        # primary key 现场派生（tpm2_createprimary），无需持久化 primary.ctx
        self.tpm_seal_pub = os.path.join(TPM_DIR, 'seal.pub')
        self.tpm_seal_priv = os.path.join(TPM_DIR, 'seal.priv')
        logger.info('TPM seal: %s / %s', self.tpm_seal_pub, self.tpm_seal_priv)

        # ── Caller 注册表 (RegistryMixin 使用) ──
        self._caller_registry_path = os.path.join(DATA_DIR, 'caller_registry.json')
        self._load_caller_registry(self._caller_registry_path)

        # ── LLM 代理配置 (LlmMixin 使用) ──
        self.proxies = parse_llm_proxy_env()
        self._shared_session = None  # 在 start_llm_proxies() 创建
        for port, url in sorted(self.proxies.items()):
            logger.info('LLM 代理 → 0.0.0.0:%d → %s', port, url)

        # ── PII + 审计配置（Batch 8.1：启动时校验 env）──
        from _audit import parse_audit_env_config
        from _pii import parse_pii_env_config

        pii_cfg = parse_pii_env_config()
        if pii_cfg['errors']:
            for e in pii_cfg['errors']:
                logger.error('PII 配置错误: %s', e)
            raise SystemExit(f'PII 配置错误: {pii_cfg["errors"][0]}')
        # 先 _init_pii（会无条件重置 pii_enabled=False），再应用配置
        self._init_pii()
        self.pii_enabled = pii_cfg['enabled']
        self.pii_response_side = pii_cfg['response_side']
        self.pii_hold_max = pii_cfg['hold_max']
        self.pii_fuzzy_restore = pii_cfg.get('fuzzy_restore', False)
        self.pii_detection_hardening = pii_cfg.get('detection_hardening', False)

        audit_cfg = parse_audit_env_config(require_whitelist=True)
        self._audit_startup_errors = audit_cfg['errors']
        if audit_cfg['errors']:
            for e in audit_cfg['errors']:
                logger.error('审计配置错误: %s', e)
            raise SystemExit(f'审计配置错误: {audit_cfg["errors"][0]}')
        # 统一走 _ensure_audit_init lazy 初始化（policy + 审批状态 + 日志）
        # 不手动设 audit 属性，避免遗漏字段（如 policy）导致 AttributeError
        self._ensure_audit_init()
        if self.audit_enabled_flag:
            logger.info(
                '审计已启用: mode=%s timeout=%ds hold_max=%dB',
                self.audit_mode,
                self.audit_timeout,
                self.audit_hold_max_bytes,
            )

    # ── 主循环 ──

    async def run(self):
        # 审批孤儿清扫需运行循环（显式生命周期，见 _audit.py v0.9.2 修复）
        if (
            getattr(self, 'audit_enabled_flag', False)
            and getattr(self, 'audit_mode', '') == 'approve'
        ):
            self._start_approval_sweeper()
        tasks = [
            self.start_credential_api(CREDENTIAL_API_PORT),
            self.start_llm_proxies(),
            self.start_bot(),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.error('服务启动失败: %s', r)


# ════════════════════════════════════════════════════════════════════════
# 入口
# ════════════════════════════════════════════════════════════════════════


def main():
    import signal as _signal

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s %(message)s',
    )
    # homeserver / room_id: 环境变量优先，CLI 参数作为后备
    homeserver = os.environ.get('HOMESERVER', '')
    room_id = os.environ.get('ROOM_ID', '')
    if len(sys.argv) >= 3:
        homeserver = homeserver or sys.argv[1]
        room_id = room_id or sys.argv[2]
    if not homeserver or not room_id:
        print(
            '错误: 请设置 HOMESERVER + ROOM_ID 环境变量，或传命令行参数',
            file=sys.stderr,
        )
        print('环境变量：', file=sys.stderr)
        print('  HOMESERVER            Matrix homeserver URL', file=sys.stderr)
        print('  ROOM_ID               Matrix 房间 ID', file=sys.stderr)
        print('  MATRIX_ACCESS_TOKEN   Matrix Bot 的 access token', file=sys.stderr)
        print('  CREDENTIAL_PORT       凭据 API 端口 (默认 8877)', file=sys.stderr)
        print(
            '  DATA_DIR              数据目录 (默认: 脚本所在目录 或 /data in Docker)',
            file=sys.stderr,
        )
        print('  LLM_8878=https://api.opencode.ai', file=sys.stderr)
        print('  LLM_8879=https://api.deepseek.com', file=sys.stderr)
        sys.exit(1)

    # access_token 从环境变量读取（避免 ps aux 泄露）
    access_token = os.environ.get('MATRIX_ACCESS_TOKEN', '')
    if not access_token:
        print('错误: 请设置 MATRIX_ACCESS_TOKEN 环境变量', file=sys.stderr)
        sys.exit(1)

    proxy = CredentialProxy(homeserver, room_id, access_token)

    async def shutdown(sig):
        if proxy._shutting_down:
            return
        proxy._shutting_down = True
        logger.info('收到信号 %s，正在优雅关闭…', sig.name)
        if proxy.client is not None:
            await proxy._say('🔌 Proxy 正在关闭…')
        async with proxy._lock:
            proxy.master_password = None
            proxy._kp = None
            if proxy.unlock_event and not proxy.unlock_event.is_set():
                proxy.unlock_event.set()
            for r in proxy.pending_requests.values():
                if not r['event'].is_set():
                    r['event'].set()
        for runner in proxy._runners:
            await runner.cleanup()
        proxy._runners.clear()
        # 关闭共享 ClientSession
        if proxy._shared_session:
            await proxy._shared_session.close()
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for s in (_signal.SIGTERM, _signal.SIGINT):
        loop.add_signal_handler(
            s,
            lambda s=s: asyncio.create_task(shutdown(s)),
        )
    try:
        loop.run_until_complete(proxy.run())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        loop.close()
        logger.info('Proxy 已关闭')


if __name__ == '__main__':
    main()
