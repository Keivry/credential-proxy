"""CredentialMixin — HTTP API：凭据查询（/credential）+ 健康检查（/health）。"""

import asyncio
import json
import logging
import os
import time
import uuid

from aiohttp import web

from _matrix import REACTION_APPROVE, REACTION_AUTO_UNLOCK, REACTION_REJECT

try:
    from pykeepass import PyKeePass
except ImportError:
    PyKeePass = None

logger = logging.getLogger('credential-proxy')

# ── Constants ──
_CREDENTIAL_PORT_RAW = os.environ.get('CREDENTIAL_PORT', '8877')
try:
    _CREDENTIAL_API_PORT = int(_CREDENTIAL_PORT_RAW)
except (ValueError, TypeError):
    _CREDENTIAL_API_PORT = 8877
UNLOCK_TIMEOUT = 300  # 解锁等待超时 (s)
APPROVAL_TIMEOUT = 300  # 审批等待超时 (s)
RATE_LIMIT_INTERVAL = 2.0  # 凭据请求最小间隔 (s)


class CredentialMixin:
    """Mixin: 凭据 HTTP API 及 KeePass 查询。"""

    # ── 自动放行默认实现 (RegistryMixin 在生产代码中覆盖) ──

    def _check_auto_approve(
        self, entry_name: str, field: str | None, auth: dict,
    ) -> tuple[bool | None, object | None, str]:
        """默认实现：不执行自动放行。RegistryMixin 覆盖此方法。"""
        return None, None, ""

    def _check_auto_rate_limit(self, reg_name: str) -> bool:
        """默认实现：不限速。RegistryMixin 覆盖此方法。"""
        return True

    async def _handle_auto_approve(
        self, entry_name: str, field: str | None,
        use_token: bool, reg,
    ) -> web.Response:
        """自动放行路径：频率检查 → 解锁 → 查询返回。"""
        if not self._check_auto_rate_limit(getattr(reg, 'name', '')):
            return web.json_response(
                {'error': '请求过于频繁'},
                status=429,
            )
        if self.master_password is None:
            can_auto = getattr(reg, 'can_auto_unlock', False)
            if can_auto:
                try:
                    await self._auto_unlock()
                except Exception:
                    logger.exception(
                        'AUTO_APPROVE_UNLOCK_FAIL: reg=%s entry=%s',
                        getattr(reg, 'name', '?'), entry_name,
                    )
                    await self._say(
                        f"⚠️ 自动解封失败: {getattr(reg, 'name', '?')} → {entry_name}",
                    )
                    return web.json_response({'error': '自动解封失败'}, status=500)
            else:
                return web.json_response(
                    {'error': 'Proxy 未解锁，请先手动解锁'},
                    status=403,
                )
        logger.info(
            'AUTO_APPROVE: reg=%s entry=%s field=%s',
            getattr(reg, 'name', '?'), entry_name, field or '*',
        )
        return await self._query_and_return(entry_name, field, use_token, reg)

    # ── API startup ──

    async def start_credential_api(self, port: int = _CREDENTIAL_API_PORT):
        app = web.Application()
        app.router.add_post('/credential', self.handle_credential)
        app.router.add_get('/health', self.handle_health)
        app.router.add_post('/register', self.handle_register)
        app.router.add_post('/register-caller', self.handle_register_caller)
        app.router.add_post('/revoke', self.handle_revoke)
        app.router.add_post('/revoke/emergency', self.handle_revoke_emergency)
        app.router.add_post('/approve-hash-change', self.handle_approve_hash_change)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, '0.0.0.0', port).start()
        self._runners.append(runner)
        logger.info('Credential API → 0.0.0.0:%d', port)

    # ── Health ──

    async def handle_health(self, _request) -> web.Response:
        """健康检查端点（无锁 — 只读属性快照）。"""
        return web.json_response(
            {
                'status': 'ok',
                'unlocked': self.master_password is not None,
                'pending': len(self.pending_requests),
                'llm_secrets': len(self.pwd_to_token),
            }
        )

    # ── Credential ──

    async def handle_credential(self, request) -> web.Response:
        # ── JSON 解析与参数提取（无锁，尽早执行）──
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({'error': 'JSON 格式错误'}, status=400)

        entry_name = data.get('entry', '').strip()
        field = data.get('field', '').strip()
        use_token = data.get('token', True)  # 默认 tokenized，传 false 获取原始值
        auth = data.get('auth', {})
        if not entry_name:
            return web.json_response({'error': '缺少 entry 参数'}, status=400)

        # ── 自动放行检查 ──
        approve, reg, reason = self._check_auto_approve(
            entry_name, field, auth,
        )
        if approve is True:
            return await self._handle_auto_approve(
                entry_name, field, use_token, reg,
            )
        elif approve is False:
            # 明确拒绝（条目不在白名单）
            return web.json_response({'error': reason}, status=403)
        elif reason == "hash_mismatch" and reg is not None:
            # Caller 哈希已变更 → 异步通知用户，本次请求用 Token/Matrix 兜底
            new_hash = auth.get("caller_hash", "")
            if new_hash:
                # 去重后发送通知（通知在锁外进行，避免嵌套锁死锁）
                reg_id = getattr(reg, 'reg_id', '')
                should_notify = False
                async with self._lock:
                    caller_reg = self._caller_registry.get(reg_id)
                    if caller_reg and not caller_reg.hash_change_notified:
                        caller_reg.hash_change_notified = True
                        should_notify = True
                if should_notify:
                    await self._notify_hash_change(caller_reg, new_hash)
            # Token 兜底
            token = auth.get("token", "")
            if token:
                token_reg = self._lookup_token(token)
                if token_reg and token_reg.enabled and self._check_entry_allowed(
                    token_reg, entry_name, field,
                ):
                    return await self._handle_auto_approve(
                        entry_name, field, use_token, token_reg,
                    )
            # 无 Token 兜底 → 走 Matrix 审批

        # ── 未匹配自动放行 → 现有解锁 + Matrix 审批流程 ──

        # 频率限制 + 解锁状态检查（合并为一次锁）
        async with self._lock:
            now = time.monotonic()
            if now - self._last_credential_request < RATE_LIMIT_INTERVAL:
                return web.json_response(
                    {'error': '请求过于频繁，请稍后再试'},
                    status=429,
                )
            self._last_credential_request = now

            # 解锁阶段（与频率限制共享同一次锁）
            need_ask = False
            if not self.master_password:
                if not self.unlock_event:
                    # 首次触发解锁：创建 Event 并请求审批
                    self.unlock_event = asyncio.Event()
                    need_ask = True
                elif self._unlock_in_progress:
                    # 解锁已在进行中：不重复发审批消息，只等待
                    need_ask = False
                unlock_evt = self.unlock_event
            else:
                unlock_evt = None
                need_ask = False

        if need_ask:
            msg_id = await self._ask(
                '🔓 Proxy 未解锁\n点 ✅ 解锁（TPM 自动解封）\n点 ❎ 拒绝',
            )
            if msg_id is None:
                logger.error('解锁消息发送失败，Matrix 可能不可用')
                async with self._lock:
                    if self.unlock_event and not self.unlock_event.is_set():
                        self.unlock_event.set()
                    self.unlock_event = None
                    self._unlock_msg_id = None
                return web.json_response(
                    {'error': '无法发送解锁消息'},
                    status=503,
                )
            async with self._lock:
                self._unlock_msg_id = msg_id

        if unlock_evt is not None:
            try:
                await asyncio.wait_for(unlock_evt.wait(), timeout=UNLOCK_TIMEOUT)
            except TimeoutError:
                async with self._lock:
                    if self.unlock_event and not self.unlock_event.is_set():
                        self.unlock_event.set()
                    self.unlock_event = None
                    self._unlock_msg_id = None
                return web.json_response({'error': '解锁超时'}, status=408)

        # ── 审批阶段 ──
        async with self._lock:
            mp = self.master_password
            if not mp:
                return web.json_response({'error': '解锁失败'}, status=403)
            req_id = uuid.uuid4().hex[:8]
            evt = asyncio.Event()
            self.pending_requests[req_id] = {
                'entry': entry_name,
                'field': field,
                'use_token': use_token,
                'approved': None,
                'event': evt,
            }

        # 构建审批提示：展示条目 + 属性 + 是否原始值
        desc = entry_name
        if field:
            desc += f' - {field}'
        if use_token:
            desc += ' (脱敏)'
        else:
            desc += ' (原始值)'
        msg_id = await self._ask(
            f'🔑 凭据请求: {desc}\n点 ✅ 批准 或 ❎ 拒绝',
        )
        if msg_id is None:
            async with self._lock:
                self._cleanup_request(req_id)
            return web.json_response(
                {'error': '无法发送审批消息'},
                status=503,
            )
        async with self._lock:
            self.approval_msgs[msg_id] = req_id

        try:
            await asyncio.wait_for(evt.wait(), timeout=APPROVAL_TIMEOUT)
        except TimeoutError:
            async with self._lock:
                req = self.pending_requests.get(req_id)
                if req and req.get('approved') is True:
                    # 刚好在超时前被批准 — 继续正常流程
                    pass
                else:
                    self._cleanup_request(req_id)
                    return web.json_response({'error': '审批超时'}, status=408)

        async with self._lock:
            req = self.pending_requests.get(req_id)
            approved = req.get('approved') if req else None
            self._cleanup_request(req_id)
            if approved is not True:
                return web.json_response({'error': '审批被拒绝'}, status=403)

        # ── 取凭据（通过共享查询方法）──
        return await self._query_and_return(entry_name, field, use_token)

    # ── Token 注册 ──

    async def handle_register(self, request) -> web.Response:
        """POST /register — 注册新 Token（需 Matrix 审批）。"""
        # 频率限制
        peer = request.remote or 'unknown'
        if not self._check_register_rate_limit(peer):
            return web.json_response(
                {'error': '注册请求过于频繁，请稍后再试'},
                status=429,
            )

        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({'error': 'JSON 格式错误'}, status=400)

        name = data.get('name', '').strip()
        if not name:
            return web.json_response({'error': '缺少 name 参数'}, status=400)

        async with self._lock:
            if self._name_exists(name):
                return web.json_response(
                    {'error': f"名称 '{name}' 已存在"},
                    status=409,
                )

        description = data.get('description', '').strip()
        entries = data.get('entries', {})
        if not entries:
            return web.json_response({'error': '缺少 entries 参数'}, status=400)

        allow_mode = data.get('allow_mode', 'manual')
        if allow_mode not in ('auto', 'manual'):
            return web.json_response(
                {'error': "allow_mode 必须为 'auto' 或 'manual'"},
                status=400,
            )
        can_auto_unlock = data.get('can_auto_unlock', False)

        # 注册 Token（待批准状态）
        reg_data = {
            'name': name,
            'description': description,
            'entries': entries,
            'allow_mode': allow_mode,
            'can_auto_unlock': can_auto_unlock,
        }
        token_id = await self._register_token(
            name=name,
            description=description,
            entries=entries,
            allow_mode=allow_mode,
            can_auto_unlock=can_auto_unlock,
        )

        # 发 Matrix 审批消息
        msg_text = self._build_registration_msg(reg_data)
        reactions = (
            (REACTION_AUTO_UNLOCK, REACTION_APPROVE, REACTION_REJECT)
            if allow_mode == 'auto'
            else None  # 默认 (✅, ❎)
        )
        msg_id = await self._ask(msg_text, reactions=reactions)
        if msg_id is None:
            await self._revoke_token(token_id)
            return web.json_response(
                {'error': '无法发送审批消息'},
                status=503,
            )

        pending = {
            'token_id': token_id,
            'name': name,
            'approved': None,
            'event': asyncio.Event(),
        }
        async with self._lock:
            self._registration_pending[token_id] = pending
            self._registration_msgs[msg_id] = token_id

        # 等待用户审批（300s 超时）
        try:
            await asyncio.wait_for(pending['event'].wait(), timeout=300)
        except TimeoutError:
            async with self._lock:
                self._registration_pending.pop(token_id, None)
                self._registration_msgs.pop(msg_id, None)
            await self._revoke_token(token_id)
            return web.json_response({'error': '审批超时'}, status=408)

        # 清理 pending 状态
        async with self._lock:
            self._registration_pending.pop(token_id, None)
            self._registration_msgs.pop(msg_id, None)

        reaction = pending.get('approved')
        if reaction == REACTION_REJECT:
            await self._revoke_token(token_id)
            return web.json_response({'error': '注册被拒绝'}, status=403)

        # 激活 Token
        await self._activate_token(token_id)
        reg = self._lookup_token(token_id)

        if reaction == REACTION_AUTO_UNLOCK:
            # 用户选择了自动放行：更新 allow_mode + can_auto_unlock
            async with self._lock:
                if reg:
                    reg.allow_mode = 'auto'
                    reg.can_auto_unlock = True
                    await self._save_token_registry()

        return web.json_response({
            'token': reg.token_id if reg else token_id,
            'name': name,
            'allow_mode': reg.allow_mode if reg else allow_mode,
            'can_auto_unlock': reg.can_auto_unlock if reg else False,
            'status': 'activated',
        })

    # ── Token 吊销 ──

    async def handle_revoke(self, request) -> web.Response:
        """POST /revoke — 吊销 Token（需 Matrix 审批）。"""
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({'error': 'JSON 格式错误'}, status=400)

        name = data.get('name', '').strip()
        if not name:
            return web.json_response({'error': '缺少 name 参数'}, status=400)

        async with self._lock:
            reg = self._lookup_by_name(name)
            if not reg:
                return web.json_response(
                    {'error': f"未找到注册 '{name}'"},
                    status=404,
                )

        # 发 Matrix 审批
        msg_id = await self._ask(
            f'❓ 吊销 {name} 的全部自动放行权限？\n点 ✅ 确认吊销 或 ❎ 取消',
        )
        if msg_id is None:
            return web.json_response(
                {'error': '无法发送审批消息'},
                status=503,
            )

        # 复用 pending_requests 机制
        async with self._lock:
            req_id = uuid.uuid4().hex[:8]
            revoke_evt_inner = asyncio.Event()
            self.pending_requests[req_id] = {
                'entry': f'revoke:{name}',
                'field': None,
                'use_token': True,
                'approved': None,
                'event': revoke_evt_inner,
            }
            self.approval_msgs[msg_id] = req_id

        try:
            await asyncio.wait_for(revoke_evt_inner.wait(), timeout=300)
        except TimeoutError:
            async with self._lock:
                self._cleanup_request(req_id)
            return web.json_response({'error': '吊销审批超时'}, status=408)

        async with self._lock:
            req = self.pending_requests.get(req_id)
            approved = req.get('approved') if req else None
            self._cleanup_request(req_id)

        if not approved:
            return web.json_response({'error': '吊销被取消'}, status=403)

        async with self._lock:
            reg = self._lookup_by_name(name)
            if not reg:
                return web.json_response(
                    {'error': f"注册 '{name}' 不存在"},
                    status=404,
                )
            await self._revoke_token(reg.token_id)

        return web.json_response({'status': 'revoked', 'name': name})

    async def handle_revoke_emergency(self, request) -> web.Response:
        """POST /revoke/emergency — 紧急吊销（无需 Matrix 审批）。

        从 CREDENTIAL_ADMIN_TOKEN 环境变量或 DATA_DIR/admin_token 文件读取
        admin token 进行认证。同一内网 IP 也可执行紧急吊销。
        """
        # Admin token 检查
        admin_token = os.environ.get('CREDENTIAL_ADMIN_TOKEN', '')
        if not admin_token:
            try:
                admin_token_path = os.path.join(
                    os.environ.get('DATA_DIR', '.'),
                    'admin_token',
                )
                with open(admin_token_path) as f:
                    admin_token = f.read().strip()
            except (FileNotFoundError, OSError):
                pass

        # 提取认证信息
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({'error': 'JSON 格式错误'}, status=400)

        req_token = data.get('admin_token', '')
        peer = request.remote or ''

        # 紧急吊销要求：admin token 匹配 或 同网段 IP
        is_internal = peer.startswith(('10.', '172.', '192.168.'))
        if not req_token or (req_token != admin_token and not is_internal):
            logger.warning(
                'EMERGENCY_REVOKE_REJECTED: peer=%s', peer,
            )
            return web.json_response(
                {'error': '未授权：需要 admin token 或内网 IP'},
                status=403,
            )

        name = data.get('name', '').strip()
        if not name:
            return web.json_response({'error': '缺少 name 参数'}, status=400)

        async with self._lock:
            reg = self._lookup_by_name(name)
            if not reg:
                return web.json_response(
                    {'error': f"未找到注册 '{name}'"},
                    status=404,
                )
            token_id = reg.token_id
            await self._revoke_token(token_id)

        logger.info(
            'EMERGENCY_REVOKE: name=%s peer=%s', name, peer,
        )
        await self._say(
            f"⚠️ 紧急吊销: {name}\n发起 IP: {peer}",
        )

        return web.json_response({'status': 'revoked', 'name': name})

    # ── Register rate limiting ──

    _register_rate_limits: dict[str, list[float]] = {}
    REGISTER_MAX_PER_MINUTE = 5

    def _check_register_rate_limit(self, ip: str) -> bool:
        """/register 频率限制：每个来源 IP 最多 5 次/分钟。"""
        now = time.monotonic()
        timestamps = self._register_rate_limits.get(ip, [])
        timestamps = [t for t in timestamps if now - t < 60]
        if len(timestamps) >= self.REGISTER_MAX_PER_MINUTE:
            return False
        timestamps.append(now)
        self._register_rate_limits[ip] = timestamps
        return True

    # ── Caller 注册 ──

    async def handle_register_caller(self, request) -> web.Response:
        """POST /register-caller — 注册新 Caller（需 Matrix 审批）。"""
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({'error': 'JSON 格式错误'}, status=400)

        name = data.get('name', '').strip()
        if not name:
            return web.json_response({'error': '缺少 name 参数'}, status=400)

        async with self._lock:
            if self._name_exists(name):
                return web.json_response(
                    {'error': f"名称 '{name}' 已存在"},
                    status=409,
                )

        script_path = data.get('script_path', '').strip()
        script_hash = data.get('script_hash', '').strip()
        if not script_path or not script_hash:
            return web.json_response(
                {'error': '缺少 script_path 或 script_hash'},
                status=400,
            )

        description = data.get('description', '').strip()
        entries = data.get('entries', {})
        allow_mode = data.get('allow_mode', 'manual')
        can_auto_unlock = data.get('can_auto_unlock', False)

        reg_data = {
            'name': name,
            'description': description,
            'script_path': script_path,
            'entries': entries,
            'allow_mode': allow_mode,
        }
        reg_id = await self._register_caller(
            name=name, script_path=script_path, script_hash=script_hash,
            description=description, entries=entries,
            allow_mode=allow_mode, can_auto_unlock=can_auto_unlock,
        )

        msg_text = self._build_registration_msg(reg_data)
        reactions = (
            ("🔓", "✅", "❎") if allow_mode == 'auto' else None
        )
        msg_id = await self._ask(msg_text, reactions=reactions)
        if msg_id is None:
            await self._revoke_caller(reg_id)
            return web.json_response({'error': '无法发送审批消息'}, status=503)

        pending = {
            'reg_id': reg_id,
            'name': name,
            'approved': None,
            'event': asyncio.Event(),
        }
        async with self._lock:
            self._registration_pending[reg_id] = pending
            self._registration_msgs[msg_id] = reg_id

        try:
            await asyncio.wait_for(pending['event'].wait(), timeout=300)
        except TimeoutError:
            async with self._lock:
                self._registration_pending.pop(reg_id, None)
                self._registration_msgs.pop(msg_id, None)
            await self._revoke_caller(reg_id)
            return web.json_response({'error': '审批超时'}, status=408)

        async with self._lock:
            self._registration_pending.pop(reg_id, None)
            self._registration_msgs.pop(msg_id, None)

        reaction = pending.get('approved')
        if reaction == "❎":
            await self._revoke_caller(reg_id)
            return web.json_response({'error': '注册被拒绝'}, status=403)

        await self._activate_caller(reg_id)
        if reaction == "🔓":
            async with self._lock:
                reg = self._caller_registry.get(reg_id)
                if reg:
                    reg.allow_mode = 'auto'
                    reg.can_auto_unlock = True
                    await self._save_token_registry()

        return web.json_response({
            'reg_id': reg_id,
            'name': name,
            'status': 'activated',
        })

    # ── 哈希变更审批 ──

    async def handle_approve_hash_change(self, request) -> web.Response:
        """POST /approve-hash-change — 处理用户对哈希变更的选择。

        Body: {"reg_id": "...", "reaction": "🔓" | "✅" | "❎"}
        这个端点通常由 Matrix reaction handler 代为触发，但也接受直接 API 调用。
        """
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({'error': 'JSON 格式错误'}, status=400)

        reg_id = data.get('reg_id', '').strip()
        reaction = data.get('reaction', '').strip()
        new_hash = data.get('new_hash', '').strip()

        if not reg_id or not reaction or not new_hash:
            return web.json_response(
                {'error': '缺少 reg_id/reaction/new_hash'},
                status=400,
            )
        if reaction not in ("🔓", "✅", "❎"):
            return web.json_response(
                {'error': 'reaction 必须为 🔓/✅/❎'},
                status=400,
            )

        async with self._lock:
            reg = self._caller_registry.get(reg_id)
            if not reg:
                return web.json_response(
                    {'error': f"未找到 Caller 注册 '{reg_id}'"},
                    status=404,
                )

        await self._resolve_hash_change(reg_id, new_hash, reaction)

        action = {"🔓": "保持自动放行", "✅": "降级为普通授权", "❎": "拒绝"}[reaction]
        return web.json_response({
            'status': 'resolved',
            'name': reg.name if reg else '',
            'action': action,
        })

    # ── Auto-unlock (for auto-approve path) ──

    async def _auto_unlock(self):
        """自动 TPM 解封（用于自动放行场景，不经过 Matrix 审批）。
        使用 _unlock_generation 计数器防止 stale task 干扰。"""
        unlock_done = asyncio.Event()
        evt = None

        async with self._lock:
            if self._unlock_in_progress:
                evt = self._auto_unlock_event
            else:
                self._unlock_in_progress = True
                self._unlock_generation += 1
                gen = self._unlock_generation
                self._auto_unlock_event = unlock_done

        if evt is not None:
            await evt.wait()
            return

        try:
            loop = asyncio.get_running_loop()
            pw = await loop.run_in_executor(None, self._tpm_unseal)
            if not pw:
                raise RuntimeError("TPM 解封返回空密码")
            async with self._lock:
                if self._unlock_generation != gen:
                    return  # 过时的 task，已被新实例替代
                self.master_password = pw
                self._kp = None
                if self.unlock_event and not self.unlock_event.is_set():
                    self.unlock_event.set()
                self._unlock_in_progress = False
                self._auto_unlock_event = None
                unlock_done.set()
        except Exception:
            async with self._lock:
                self._unlock_in_progress = False
                self._auto_unlock_event = None
                if self.unlock_event and not self.unlock_event.is_set():
                    self.unlock_event.set()
                self.unlock_event = None
                self._unlock_msg_id = None
                unlock_done.set()
            logger.exception("自动 TPM 解封失败")
            raise

    # ── Shared KeePass query (used by both auto-approve and Matrix-approve paths) ──

    async def _query_and_return(
        self,
        entry_name: str,
        field: str | None,
        use_token: bool,
        reg: object | None = None,
    ) -> web.Response:
        """查询 KeePass 并返回凭据。自动放行和 Matrix 审批路径共用。

        Args:
            entry_name: KeePass 条目名
            field: 要获取的字段（None=完整条目）
            use_token: 是否返回脱敏值
            reg: 触发的注册记录（用于审计日志）
        """
        if self.kdbx_path is None:
            return web.json_response(
                {'error': '密码库未配置（db/ 目录下无 .kdbx 文件）'},
                status=503,
            )
        try:
            if PyKeePass is None:
                return web.json_response(
                    {'error': 'pykeepass 未安装'},
                    status=503,
                )
            loop = asyncio.get_running_loop()
            async with self._kp_semaphore:
                async with self._lock:
                    kp = self._kp
                if kp is None:
                    kp = await loop.run_in_executor(
                        None,
                        lambda: PyKeePass(
                            self.kdbx_path,
                            password=self.master_password,
                            keyfile=self.keyfile_path,
                        ),
                    )
                    async with self._lock:
                        if self._kp is None:
                            self._kp = kp
                        else:
                            kp = self._kp
                entry = await loop.run_in_executor(
                    None,
                    lambda: kp.find_entries(title=entry_name, first=True),
                )
            if not entry:
                return web.json_response(
                    {'error': f'未找到 {entry_name}'},
                    status=404,
                )

            if field:
                if field in ('password', 'username', 'title', 'url'):
                    val = getattr(entry, field, '') or ''
                    if field == 'password':
                        value = await self._maybe_register(val, use_token)
                    else:
                        value = val
                elif hasattr(entry, 'is_custom_property_protected'):
                    val = entry.get_custom_property(field)
                    if val is None:
                        value = None
                    elif entry.is_custom_property_protected(field):
                        value = await self._maybe_register(val, use_token)
                    else:
                        value = val
                else:
                    val = entry.get_custom_property(field) if hasattr(entry, 'get_custom_property') else None
                    value = await self._maybe_register(val, use_token) if val else None

                if value is None:
                    return web.json_response(
                        {'error': f'无属性 {field}'},
                        status=404,
                    )
                return web.json_response({'value': value})

            props = {}
            if hasattr(entry, 'is_custom_property_protected'):
                for k in entry.custom_properties or {}:
                    v = entry.get_custom_property(k)
                    if v:
                        if entry.is_custom_property_protected(k):
                            props[k] = await self._maybe_register(v, use_token)
                        else:
                            props[k] = v
            elif hasattr(entry, 'get_custom_property'):
                for k in entry.custom_properties or {}:
                    v = entry.get_custom_property(k)
                    if v:
                        props[k] = await self._maybe_register(v, use_token)
            result = {
                'title': entry.title or '',
                'username': entry.username or '',
                'password': await self._maybe_register(
                    entry.password or '', use_token,
                ),
                'url': entry.url or '',
            }
            if props:
                result['custom_properties'] = props
            return web.json_response(result)
        except Exception:
            logger.exception('KeePass 查询失败')
            # 自动放行路径中查询失败，发 Matrix 通知
            if reg:
                await self._say(
                    f"⚠️ 自动放行查询失败: {getattr(reg, 'name', '?')} → "
                    f"{entry_name}（请检查 KeePass）",
                )
            return web.json_response({'error': 'KeePass 内部错误'}, status=500)


    # ── Helpers ──

    def _cleanup_request(self, req_id: str):
        """安全清理审批请求及其关联的 approval 消息映射。
        调用者必须持有 self._lock。"""
        self.pending_requests.pop(req_id, None)
        for eid, rid in list(self.approval_msgs.items()):
            if rid == req_id:
                self.approval_msgs.pop(eid, None)
