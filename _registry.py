"""RegistryMixin — Token/Caller 注册表管理 + 认证降级链。"""

import asyncio
import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger('credential-proxy')

AUTO_RATE_INTERVAL = 1.0  # 自动放行最小间隔（秒）
GRACE_PERIOD_SECONDS = 3600  # 哈希变更宽限期（1 小时）


# ════════════════════════════════════════════════════════════════
# Data classes
# ════════════════════════════════════════════════════════════════


@dataclass
class RegisteredCaller:
    """注册的调用者（脚本文件），通过文件哈希绑定。"""

    reg_id: str
    name: str
    script_path: str
    script_hash: str  # "sha256:abc123..."
    description: str = ''
    script_hash_old: str = ''  # 上一版哈希（宽限期使用）
    hash_change_at: float = 0.0  # 最近哈希变更的 UTC 时间戳
    hash_change_notified: bool = False
    entries: dict[str, list[str]] = field(default_factory=dict)
    allow_mode: str = 'manual'
    can_auto_unlock: bool = False
    created_at: str = ''
    enabled: bool = True

    @property
    def in_grace_period(self) -> bool:
        """宽限期内旧哈希仍有效（新哈希需审批后才能使用）。"""
        if not self.hash_change_at:
            return False
        return (time.time() - self.hash_change_at) < GRACE_PERIOD_SECONDS


# ════════════════════════════════════════════════════════════════
# RegistryMixin
# ════════════════════════════════════════════════════════════════


class RegistryMixin:
    """Mixin: Token / Caller 注册表管理 + 认证降级链。

    注意：此类属性由 CredentialProxy.__init__ (proxy.py) 初始化，
    不在此处设置 __init__，因为 CredentialProxy.__init__ 不调用
    super().__init__()，且已手动初始化所有需要的属性。
    如需新增属性，请同时在 proxy.py CredentialProxy.__init__ 中添加。
    """

    # ── 通用名称检查 ──

    def _name_exists(self, name: str) -> bool:
        """检查名称是否已注册（含 Token 和 Caller，含 pending）。"""
        if name in self._registrations_by_name:
            return True
        for p in self._registration_pending.values():
            if p.get('name') == name:
                return True
        return False

    def _lookup_by_name(self, name: str):
        """按名称查询 Caller 注册。"""
        rid = self._registrations_by_name.get(name)
        if rid and rid in self._caller_registry:
            return self._caller_registry[rid]
        return None

    # ═══════════════════════════════════════════════════════════
    # Caller 注册
    # ═══════════════════════════════════════════════════════════

    def _generate_reg_id(self) -> str:
        return 'reg_' + secrets.token_hex(8)

    async def _register_caller(
        self,
        name: str,
        script_path: str,
        script_hash: str,
        description: str = '',
        entries: dict[str, list[str]] | None = None,
        allow_mode: str = 'manual',
        can_auto_unlock: bool = False,
    ) -> str:
        """注册新 Caller（待批准状态 -> enabled=False）。
        返回 reg_id 用于后续激活。"""
        reg_id = self._generate_reg_id()
        now = datetime.now(UTC).isoformat()
        reg = RegisteredCaller(
            reg_id=reg_id,
            name=name,
            description=description,
            script_path=script_path,
            script_hash=script_hash,
            entries=entries or {},
            allow_mode=allow_mode,
            can_auto_unlock=can_auto_unlock,
            created_at=now,
            enabled=False,
        )
        async with self._lock:
            self._caller_registry[reg_id] = reg
            self._caller_registry_by_path[script_path] = reg_id
            self._registrations_by_name[name] = reg_id
        return reg_id

    async def _activate_caller(self, reg_id: str):
        async with self._lock:
            reg = self._caller_registry.get(reg_id)
            if reg:
                reg.enabled = True
                await self._save_token_registry()

    async def _revoke_caller(self, reg_id: str) -> bool:
        async with self._lock:
            reg = self._caller_registry.pop(reg_id, None)
            if reg:
                self._registrations_by_name.pop(reg.name, None)
                self._caller_registry_by_path.pop(reg.script_path, None)
                await self._save_token_registry()
                return True
            return False

    def _find_caller_by_hash(
        self,
        script_hash: str,
        script_path: str,
    ) -> RegisteredCaller | None:
        """匹配 (script_hash, script_path)。两者都匹配才算。"""
        for reg in self._caller_registry.values():
            if not reg.enabled:
                continue
            if reg.script_hash == script_hash and reg.script_path == script_path:
                return reg
            # 宽限期内：旧哈希也匹配
            if (
                reg.in_grace_period
                and reg.script_hash_old == script_hash
                and reg.script_path == script_path
            ):
                return reg
        return None

    def _find_caller_by_path(self, script_path: str) -> RegisteredCaller | None:
        """按脚本路径查找 Caller 注册（用于哈希变更检测）。"""
        rid = self._caller_registry_by_path.get(script_path)
        if rid:
            return self._caller_registry.get(rid)
        return None

    def _check_entry_allowed_caller(
        self,
        reg: RegisteredCaller,
        entry_name: str,
        field: str | None,
    ) -> bool:
        """检查 Caller 注册是否有权访问指定条目和字段。"""
        if not reg.enabled:
            return False
        if entry_name not in reg.entries:
            return False
        allowed_fields = reg.entries[entry_name]
        if not allowed_fields:
            return True
        return bool(field is None or field in allowed_fields)

    # ═══════════════════════════════════════════════════════════
    # 统一认证降级链
    # ═══════════════════════════════════════════════════════════

    async def _check_auto_approve(
        self,
        entry_name: str,
        field: str | None,
        auth: dict,
    ):
        """检查是否可自动放行。

        优先级: Caller 哈希 > Token

        Returns:
            (approve, reg, reason):
                approve=True  → 自动放行（reg 是匹配的注册记录）
                approve=False → 明确拒绝（条目不在白名单）
                approve=None  → 无匹配，继续 Matrix 审批
        """
        async with self._lock:
            # ── Caller 哈希校验 ──
            caller_hash = auth.get('caller_hash', '')
            caller_path = auth.get('caller_path', '')
            if caller_hash:
                reg = self._find_caller_by_hash(caller_hash, caller_path)
                if reg:
                    if not self._check_entry_allowed_caller(reg, entry_name, field):
                        return (
                            False,
                            reg,
                            (f"Caller '{reg.name}' 无权访问 {entry_name}"),
                        )
                    return True, reg, ''
                # 哈希不匹配但路径匹配？→ 哈希变更
                path_reg = self._find_caller_by_path(caller_path)
                if path_reg and path_reg.enabled:
                    # 返回特殊状态让调用者处理哈希变更
                    return None, path_reg, 'hash_mismatch'

            return None, None, ''

    # ── 自动放行频率限制 ──

    async def _check_auto_rate_limit(self, reg_name: str) -> bool:
        """检查自动放行频率限制。

        通过 async with self._lock 保证原子性（在 _handle_auto_approve 中调用时不持有外层锁）。"""
        async with self._lock:
            now = time.monotonic()
            last = self._auto_rate_limits.get(reg_name, 0.0)
            if now - last < AUTO_RATE_INTERVAL:
                return False
            self._auto_rate_limits[reg_name] = now
            return True

    # ═══════════════════════════════════════════════════════════
    # 哈希变更
    # ═══════════════════════════════════════════════════════════

    async def _notify_hash_change(
        self,
        reg: RegisteredCaller,
        new_hash: str,
    ) -> str | None:
        """发送哈希变更通知到 Matrix，返回 msg_id。

        不阻塞——hash change 通知是异步的，正在运行的请求通过 fallback 完成。
        """
        msg_text = (
            f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
            f'⚠️ {reg.name} 哈希已变更\n'
            f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
            f'\n'
            f'  文件: {reg.script_path}\n'
            f'  宽限期至: 变更后 1 小时\n'
            f'\n'
            f'  🔓 保持自动放行  |  ✅ 降级为普通授权  |  ❎ 拒绝\n'
            f'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'
        )
        msg_id = await self._ask(
            msg_text,
            reactions=(
                '🔓',
                '✅',
                '❎',
            ),
        )
        if msg_id is None:
            return None

        # 注册 pending 哈希变更
        async with self._lock:
            self._hash_change_pending[reg.reg_id] = {
                'reg_id': reg.reg_id,
                'new_hash': new_hash,
                'event': asyncio.Event(),
                'result': None,
            }
            self._hash_change_msgs[msg_id] = reg.reg_id
        return msg_id

    async def _resolve_hash_change(
        self,
        reg_id: str,
        new_hash: str,
        reaction: str,
    ):
        """处理哈希变更的用户选择。"""
        async with self._lock:
            reg = self._caller_registry.get(reg_id)
            if not reg:
                return
            if reaction == '🔓':
                # 保持自动放行，更新哈希
                reg.script_hash_old = reg.script_hash
                reg.script_hash = new_hash
                reg.hash_change_at = 0.0
                reg.hash_change_notified = False
            elif reaction == '✅':
                # 降级为普通授权（更新哈希但改为 manual）
                reg.script_hash_old = reg.script_hash
                reg.script_hash = new_hash
                reg.hash_change_at = 0.0
                reg.hash_change_notified = False
                reg.allow_mode = 'manual'
            else:
                # ❎ 拒绝 → 禁用注册
                reg.enabled = False
            await self._save_token_registry()
            self._hash_change_pending.pop(reg_id, None)

    # ═══════════════════════════════════════════════════════════
    # 持久化
    # ═══════════════════════════════════════════════════════════

    def _load_token_registry(self, path: str):
        """从文件加载注册表（Token + Caller），含完整性校验。

        仅在 __init__ 中单线程调用（构造函数阶段未启动协程），
        因此不获取 self._lock。后续写入始终在锁内进行。"""
        self._token_registry_path = path
        try:
            with open(path) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.info('注册表不存在或损坏（%s），使用空注册表', path)
            return

        # 完整性校验（向后兼容：旧文件无 integrity 字段时跳过）
        stored_integrity = data.pop('integrity', None)
        if stored_integrity is not None:
            computed = self._compute_registry_integrity(data)
            if stored_integrity != computed:
                logger.warning(
                    '注册表完整性校验失败（%s），可能被篡改，使用空注册表',
                    path,
                )
                return

        for c in data.get('callers', []):
            reg = RegisteredCaller(
                reg_id=c.get('reg_id', ''),
                name=c.get('name', ''),
                script_path=c.get('script_path', ''),
                script_hash=c.get('script_hash', ''),
                script_hash_old=c.get('script_hash_old', ''),
                hash_change_at=c.get('hash_change_at', 0.0),
                hash_change_notified=c.get('hash_change_notified', False),
                entries=c.get('allowed_entries', {}),
                allow_mode=c.get('allow_mode', 'manual'),
                can_auto_unlock=c.get('can_auto_unlock', False),
                created_at=c.get('created_at', ''),
                enabled=c.get('enabled', True),
            )
            if reg.reg_id:
                self._caller_registry[reg.reg_id] = reg
                self._caller_registry_by_path[reg.script_path] = reg.reg_id
                self._registrations_by_name[reg.name] = reg.reg_id

        logger.info(
            '已加载 %d 个 Caller 注册（%s）',
            len(self._caller_registry),
            path,
        )

    async def _save_token_registry(self):
        """原子写 token_registry.json。
        调用者必须已持有 self._lock。"""
        callers = []
        for c in self._caller_registry.values():
            callers.append(
                {
                    'reg_id': c.reg_id,
                    'name': c.name,
                    'script_path': c.script_path,
                    'script_hash': c.script_hash,
                    'script_hash_old': c.script_hash_old,
                    'hash_change_at': c.hash_change_at,
                    'hash_change_notified': c.hash_change_notified,
                    'allowed_entries': c.entries,
                    'allow_mode': c.allow_mode,
                    'can_auto_unlock': c.can_auto_unlock,
                    'created_at': c.created_at,
                    'enabled': c.enabled,
                }
            )
        data = {
            'version': 3,
            'updated_at': datetime.now(UTC).isoformat(),
            'callers': callers,
        }
        data['integrity'] = self._compute_registry_integrity(data)
        tmp_path = self._token_registry_path + '.tmp'
        with open(tmp_path, 'w') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            # fsync 在线程池执行，不阻塞事件循环
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, os.fsync, f.fileno())
        os.chmod(tmp_path, 0o600)
        os.rename(tmp_path, self._token_registry_path)

    @staticmethod
    def _compute_registry_integrity(data: dict) -> str:
        """计算注册表数据的 SHA256 完整性哈希。
        data 不应包含 integrity 字段（加载时已 pop，保存时也先构建再添加）。
        """
        raw = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    # ═══════════════════════════════════════════════════════════
    # 注册消息构建
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def _build_registration_msg(reg_data: dict) -> str:
        """构建注册审批消息文本。"""
        lines = []
        lines.append('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
        if reg_data.get('allow_mode') == 'auto':
            lines.append('📝 注册请求 — 自动放行 ⚠️')
        else:
            lines.append('📝 注册请求 — 普通授权')
        lines.append('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
        lines.append('')
        lines.append(f'  程序: {reg_data.get("name", "?")}')
        lines.append(f'  用途: {reg_data.get("description", "无描述")}')
        if reg_data.get('script_path'):
            lines.append(f'  脚本: {reg_data["script_path"]}')
        lines.append('  访问:')
        for entry, fields in reg_data.get('entries', {}).items():
            fields_str = ', '.join(fields) if fields else '全部属性'
            lines.append(f'    · {entry} → {fields_str}')
        lines.append('')
        if reg_data.get('allow_mode') == 'auto':
            lines.append('  ⚠️ 自动放行 = 该程序无需每次审批即可获取上述凭据')
            lines.append('      请确认该程序是你信任的、不会泄漏凭据的脚本')
        lines.append('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
        lines.append('')
        if reg_data.get('allow_mode') == 'auto':
            lines.append('  🔓 自动放行  |  ✅ 普通授权  |  ❎ 拒绝')
        else:
            lines.append('  ✅ 批准  |  ❎ 拒绝')
        return '\n'.join(lines)
