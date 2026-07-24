"""RegistryMixin — Token 注册表管理。"""

import asyncio
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger('credential-proxy')

AUTO_RATE_INTERVAL = 1.0  # 自动放行最小间隔（秒）


@dataclass
class RegisteredToken:
    """注册的 Token，映射到一组允许的 KeePass 条目。"""
    token_id: str
    name: str
    description: str = ""
    # entries 格式：{"条目名": ["字段1", "字段2"]}，空列表 = 全部字段
    entries: dict[str, list[str]] = field(default_factory=dict)
    allow_mode: str = "manual"     # "auto" = 自动放行, "manual" = 每次审批
    can_auto_unlock: bool = False   # 自动放行时是否允许自动 TPM 解锁
    created_at: str = ""
    enabled: bool = True            # 是否生效


class RegistryMixin:
    """Mixin: Token 注册表管理。"""

    def __init__(self):
        self._token_registry: dict[str, RegisteredToken] = {}
        self._token_registry_path = ""
        # name → token_id 索引（用于唯一性检查）
        self._registrations_by_name: dict[str, str] = {}

        # ── 注册审批待处理 ──
        self._registration_pending: dict[str, dict] = {}
        # event_id → reg_id（用于 on_reaction 查找）
        self._registration_msgs: dict[str, str] = {}

        # ── 自动放行频率限制 ──
        self._auto_rate_limits: dict[str, float] = {}

    # ── Token 生成 ──

    def _generate_token(self) -> str:
        """生成 32 字节随机 Token（64 字符 hex）。"""
        return secrets.token_hex(32)

    # ── 注册（仅注册到 pending，等待 Matrix 审批后激活）──

    def _name_exists(self, name: str) -> bool:
        """检查名称是否已注册（含 pending）。"""
        if name in self._registrations_by_name:
            return True
        for p in self._registration_pending.values():
            if p.get("name") == name:
                return True
        return False

    async def _register_token(
        self,
        name: str,
        description: str = "",
        entries: dict[str, list[str]] | None = None,
        allow_mode: str = "manual",
        can_auto_unlock: bool = False,
    ) -> str:
        """注册新 Token（待批准状态 -> enabled=False）。
        返回 token_id 用于后续激活。
        """
        token_id = self._generate_token()
        now = datetime.utcnow().isoformat() + "Z"
        reg = RegisteredToken(
            token_id=token_id,
            name=name,
            description=description,
            entries=entries or {},
            allow_mode=allow_mode,
            can_auto_unlock=can_auto_unlock,
            created_at=now,
            enabled=False,  # 未激活
        )
        async with self._lock:
            self._token_registry[token_id] = reg
            self._registrations_by_name[name] = token_id
        return token_id

    async def _activate_token(self, token_id: str):
        """激活 Token（审批通过后调用）。"""
        async with self._lock:
            reg = self._token_registry.get(token_id)
            if reg:
                reg.enabled = True
                await self._save_token_registry()

    # ── 吊销 ──

    async def _revoke_token(self, token_id: str) -> bool:
        """吊销 Token。返回是否找到并移除。"""
        async with self._lock:
            reg = self._token_registry.pop(token_id, None)
            if reg:
                self._registrations_by_name.pop(reg.name, None)
                await self._save_token_registry()
                return True
            return False

    # ── 查询 ──

    def _lookup_token(self, token_id: str) -> RegisteredToken | None:
        """按 token_id 查询。"""
        return self._token_registry.get(token_id)

    def _lookup_by_name(self, name: str) -> RegisteredToken | None:
        """按名称查询。"""
        tid = self._registrations_by_name.get(name)
        if tid:
            return self._token_registry.get(tid)
        return None

    def _check_entry_allowed(
        self, reg: RegisteredToken, entry_name: str,
        field: str | None,
    ) -> bool:
        """检查注册是否有权访问指定条目和字段。"""
        if not reg.enabled:
            return False
        if entry_name not in reg.entries:
            return False
        allowed_fields = reg.entries[entry_name]
        if not allowed_fields:
            return True  # 空列表 = 全部字段
        if field is None or field in allowed_fields:
            return True
        return False

    # ── 认证降级链 ──

    def _check_auto_approve(
        self, entry_name: str, field: str | None, auth: dict,
    ) -> tuple[bool | None, RegisteredToken | None, str]:
        """检查是否可自动放行。

        Returns:
            (approve, reg, reason):
                approve=True  → 自动放行
                approve=False → 明确拒绝（条目不在白名单）
                approve=None  → 无匹配，继续 Matrix 审批
        """
        token = auth.get("token", "")
        if not token:
            return None, None, ""  # 无认证 -> 走 Matrix 审批

        reg = self._lookup_token(token)
        if not reg:
            return None, None, ""  # 无效 Token -> 走 Matrix 审批

        if not reg.enabled:
            return None, None, ""

        if not self._check_entry_allowed(reg, entry_name, field):
            return False, reg, f"Token '{reg.name}' 无权访问 {entry_name}"

        return True, reg, ""

    # ── 自动放行频率限制 ──

    def _check_auto_rate_limit(self, reg_name: str) -> bool:
        """检查自动放行的频率限制。
        返回 True = 允许，False = 被限速。"""
        now = time.monotonic()
        last = self._auto_rate_limits.get(reg_name, 0.0)
        if now - last < AUTO_RATE_INTERVAL:
            return False
        self._auto_rate_limits[reg_name] = now
        return True

    # ── 持久化 ──

    def _load_token_registry(self, path: str):
        """从文件加载 Token 注册表。"""
        self._token_registry_path = path
        try:
            with open(path) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.info("Token 注册表不存在或损坏（%s），使用空注册表", path)
            return

        for t in data.get("tokens", []):
            reg = RegisteredToken(
                token_id=t.get("token_id", ""),
                name=t.get("name", ""),
                description=t.get("description", ""),
                entries=t.get("allowed_entries", {}),
                allow_mode=t.get("allow_mode", "manual"),
                can_auto_unlock=t.get("can_auto_unlock", False),
                created_at=t.get("created_at", ""),
                enabled=t.get("enabled", True),
            )
            if reg.token_id:
                self._token_registry[reg.token_id] = reg
                self._registrations_by_name[reg.name] = reg.token_id

        logger.info(
            "已加载 %d 个 Token 注册（%s）",
            len(self._token_registry),
            path,
        )

    async def _save_token_registry(self):
        """原子写 token_registry.json。
        调用者必须已持有 self._lock。"""
        tokens = []
        for t in self._token_registry.values():
            tokens.append({
                "token_id": t.token_id,
                "name": t.name,
                "description": t.description,
                "allowed_entries": t.entries,
                "allow_mode": t.allow_mode,
                "can_auto_unlock": t.can_auto_unlock,
                "created_at": t.created_at,
                "enabled": t.enabled,
            })
        data = {
            "version": 1,
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "tokens": tokens,
        }
        tmp_path = self._token_registry_path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.rename(tmp_path, self._token_registry_path)

    # ── 注册消息构建 ──

    @staticmethod
    def _build_registration_msg(reg_data: dict) -> str:
        """构建注册审批消息文本。
        reg_data 包含 name, description, entries, allow_mode。"""
        lines = []
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        if reg_data.get("allow_mode") == "auto":
            lines.append("📝 注册请求 — 自动放行 ⚠️")
        else:
            lines.append("📝 注册请求 — 普通授权")
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append("")
        lines.append(f"  程序: {reg_data.get('name', '?')}")
        lines.append(f"  用途: {reg_data.get('description', '无描述')}")
        lines.append("  访问:")
        for entry, fields in reg_data.get("entries", {}).items():
            fields_str = ", ".join(fields) if fields else "全部属性"
            lines.append(f"    · {entry} → {fields_str}")
        lines.append("")
        if reg_data.get("allow_mode") == "auto":
            lines.append("  ⚠️ 自动放行 = 该程序无需每次审批即可获取上述凭据")
            lines.append("      请确认该程序是你信任的、不会泄漏凭据的脚本")
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append("")
        if reg_data.get("allow_mode") == "auto":
            lines.append("  🔓 自动放行  |  ✅ 普通授权  |  ❎ 拒绝")
        else:
            lines.append("  ✅ 批准  |  ❎ 拒绝")
        return "\n".join(lines)
