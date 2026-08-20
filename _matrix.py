"""MatrixMixin — Matrix Bot：同步、消息处理、反应审批。"""

import asyncio
import logging
import os

from nio import AsyncClient, ReactionEvent, RoomMessageText

from _sse import (
    ALL_REACTIONS,
    REACTION_APPROVE,
    REACTION_AUTO_UNLOCK,
    REACTION_REJECT,
    REACTIONS,
)

logger = logging.getLogger('credential-proxy')

# ── Constants ──
SYNC_TIMEOUT = 30000  # Matrix sync timeout (ms)
MAX_RETRY_DELAY = 60  # 重试退避上限 (s)
CMD_LOCK = 'lock proxy'
CMD_STATUS = 'status'
CMD_FORGET = 'forget secrets'


class MatrixMixin:
    # ── Bot lifecycle ──

    async def start_bot(self):
        self.client = AsyncClient(self.homeserver)
        self.client.access_token = self.access_token
        try:
            whoami = await self.client.whoami()
        except Exception:
            logger.exception('Matrix whoami 失败，bot 不可用')
            return
        self.client.user_id = whoami.user_id
        logger.info('Bot: %s', self.client.user_id)
        self.client.add_event_callback(self.on_text, RoomMessageText)
        self.client.add_event_callback(self.on_reaction, ReactionEvent)

        def _read_token(path: str) -> str | None:
            try:
                with open(path) as f:
                    return f.read().strip()
            except FileNotFoundError:
                return None

        def _write_token(path: str, content: str) -> None:
            with open(path, 'w') as f:
                f.write(content)

        sync_token_file = os.path.join(self._base_dir, 'sync_token')
        since = None
        try:
            since = await asyncio.to_thread(_read_token, sync_token_file)
            if since:
                logger.info('从 sync token 恢复')
        except Exception:
            logger.exception('读取 sync_token 失败')

        retry_delay = 1
        while not self._shutting_down:
            try:
                resp = await self.client.sync(
                    timeout=SYNC_TIMEOUT,
                    since=since,
                    full_state=False,
                )
                retry_delay = 1
                await self.client.run_response_callbacks([resp])
                if hasattr(resp, 'next_batch') and resp.next_batch:
                    since = resp.next_batch
                    try:
                        await asyncio.to_thread(
                            _write_token,
                            sync_token_file,
                            since,
                        )
                    except Exception:
                        logger.debug('保存 sync_token 失败', exc_info=True)
            except Exception:
                logger.exception('Matrix sync 失败，%ds 后重试', retry_delay)
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY)

    # ── Text commands ──

    async def on_text(self, room, event):
        if room.room_id != self.room_id:
            return
        body = event.body.strip()
        if body == CMD_LOCK:
            async with self._lock:
                self.master_password = None
                if self.unlock_event and not self.unlock_event.is_set():
                    self.unlock_event.set()
                self.unlock_event = None
                self._unlock_msg_id = None
                self._unlock_in_progress = False
                self._kp = None
                for r in self.pending_requests.values():
                    r['approved'] = False
                    r['event'].set()
                self.pending_requests.clear()
                self.approval_msgs.clear()
            await self._say('🔒 Proxy 已锁定')
        elif body == CMD_STATUS:
            async with self._lock:
                s = '✅ 已解锁' if self.master_password else '🔒 未解锁'
                n_pending = len(self.pending_requests)
                n_secrets = len(self.pwd_to_token)
            await self._say(
                f'Proxy: {s} | 待审批: {n_pending} | LLM secrets: {n_secrets}',
            )
        elif body == CMD_FORGET:
            async with self._lock:
                n = len(self.pwd_to_token)
                self.pwd_to_token.clear()
                self.token_to_pwd.clear()
            await self._say(f'🧹 已清除 {n} 个 LLM 密码映射')

    # ── Reaction handling ──

    async def on_reaction(self, room, event):
        if room.room_id != self.room_id:
            return
        ts = getattr(event, 'server_timestamp', 0) or 0
        if ts > 0 and ts < self._start_ts:
            return
        sender = event.source.get('sender', '')
        if sender == self.client.user_id:
            return
        relates_to = event.source.get('content', {}).get('m.relates_to', {})
        orig = relates_to.get('event_id', '')
        key = relates_to.get('key', '')
        if not orig or key not in ALL_REACTIONS:
            return

        say_text = None
        async with self._lock:
            # ── 1. 解锁分支 ──
            if (
                self.unlock_event
                and self.master_password is None
                and orig == self._unlock_msg_id
            ):
                if key == REACTION_APPROVE:
                    if not self._unlock_in_progress:
                        self._unlock_in_progress = True
                        self._unlock_generation += 1
                        gen = self._unlock_generation
                        task = asyncio.create_task(self._do_unlock(gen))
                        task.add_done_callback(
                            lambda t, _logger=logger: (
                                _logger.error('解锁任务异常', exc_info=t.exception())
                                if t.exception()
                                else None
                            ),
                        )
                        say_text = '⏳ TPM 解封中…'
                else:
                    if not self.unlock_event.is_set():
                        self.unlock_event.set()
                    self.unlock_event = None
                    self._unlock_msg_id = None
                    say_text = '❌ 解锁被拒绝'

            # ── 2. 注册审批分支 ──
            elif reg_id := self._registration_msgs.get(orig):
                reg_pending = self._registration_pending.get(reg_id)
                if reg_pending and reg_pending.get('approved') is None:
                    reg_pending['approved'] = key  # 存储实际 reaction（🔓/✅/❎）
                    reg_pending['event'].set()
                    name = reg_pending.get('name', '?')
                    action = {
                        REACTION_AUTO_UNLOCK: '自动放行',
                        REACTION_APPROVE: '普通授权',
                        REACTION_REJECT: '拒绝',
                    }.get(key, key)
                    say_text = f'{key} 注册审批: {name} → {action}'

            # ── 3. 哈希变更审批分支 ──
            elif hc_id := self._hash_change_msgs.get(orig):
                pending = self._hash_change_pending.get(hc_id)
                if pending and pending.get('result') is None:
                    pending['result'] = key
                    pending['event'].set()
                    # 后台 resolve（不阻塞 on_reaction）
                    hc_task = asyncio.create_task(
                        self._resolve_hash_change(
                            pending['reg_id'],
                            pending['new_hash'],
                            key,
                        ),
                    )
                    hc_task.add_done_callback(
                        lambda t, _logger=logger: (
                            _logger.error(
                                '哈希变更处理异常',
                                exc_info=t.exception(),
                            )
                            if t.exception()
                            else None
                        ),
                    )
                    reg_obj = (
                        self._caller_registry.get(hc_id)
                        if hasattr(self, '_caller_registry')
                        else None
                    )
                    name = reg_obj.name if reg_obj else ''
                    action = {
                        '🔓': '保持自动放行',
                        '✅': '降级为普通授权',
                        '❎': '拒绝',
                    }.get(key, key)
                    say_text = f'{key} 哈希变更: {name or hc_id} → {action}'

            # ── 4. 凭据审批分支 ──
            elif (
                not (req_id := self.approval_msgs.get(orig))
                or not (req := self.pending_requests.get(req_id))
                or req['approved'] is not None
            ):
                pass
            elif (
                (req_id := self.approval_msgs.get(orig))
                and (req := self.pending_requests.get(req_id))
                and req['approved'] is None
            ):
                ok = key == REACTION_APPROVE
                req['approved'] = ok
                req['event'].set()
                extra = ''
                if req.get('field'):
                    extra += f' - {req["field"]}'
                if not req.get('use_token', True):
                    extra += ' (原始值)'
                say_text = f'{key} 已{"批准" if ok else "拒绝"}: {req["entry"]}{extra}'

            # ── 5. 审计审批分支（design D4 白名单 + event id 精确匹配 + 幂等）──
            elif a_id := self._audit_approval_msgs.get(orig):
                # (a) 发送者 ∈ 审批人白名单
                if self.approval_whitelist and sender not in self.approval_whitelist:
                    logger.warning('审计审批被忽略: 发送者 %s 不在白名单', sender)
                else:
                    ap = self._audit_approval_pending.get(a_id)
                    # (c) 幂等：只接受首次判定（approved 已定则忽略）
                    if ap and ap.get('approved') is None:
                        ok = key == REACTION_APPROVE
                        ap['approved'] = ok
                        ap['event'].set()
                        say_text = f'{key} 审计审批: {ap.get("name", "?")} → {"批准" if ok else "拒绝"}'
        if say_text:
            await self._say(say_text)

    # ── Messaging ──

    async def _say(self, text: str):
        """发送纯文本通知。client 未就绪时静默跳过。"""
        if self.client is None:
            return
        try:
            await self.client.room_send(
                self.room_id,
                'm.room.message',
                {'msgtype': 'm.notice', 'body': text},
            )
        except Exception:
            logger.debug('_say 发送失败', exc_info=True)

    async def _ask(
        self,
        text: str,
        reactions: tuple[str, ...] | None = None,
    ) -> str | None:
        """发送审批消息并预加 reaction，返回 event_id。

        默认使用 REACTIONS (✅/❎)。
        reactions 参数允许自定义 reaction 列表（如 ('🔓', '✅', '❎')）。
        """
        if reactions is None:
            reactions = REACTIONS
        # Matrix 断连/不可达时 room_send 会抛异常；此处捕获并返回 None，
        # 让调用者的 `if msg_id is None:` 清理分支接管（unlock_event 等状态不残留）。
        try:
            resp = await self.client.room_send(
                self.room_id,
                'm.room.message',
                {'msgtype': 'm.text', 'body': text},
            )
        except Exception:
            logger.exception('_ask 发送审批消息失败')
            return None
        eid = getattr(resp, 'event_id', None) or (
            resp.get('event_id') if isinstance(resp, dict) else None
        )
        if eid:
            count = 0
            for k in reactions:
                try:
                    await self.client.room_send(
                        self.room_id,
                        'm.reaction',
                        {
                            'm.relates_to': {
                                'event_id': eid,
                                'key': k,
                                'rel_type': 'm.annotation',
                            },
                        },
                    )
                    count += 1
                except Exception:
                    logger.debug('_ask 添加 reaction 失败', exc_info=True)
            if count < len(reactions):
                logger.warning(
                    '_ask 仅 %d/%d 个 reaction 成功，消息仍然可用',
                    count,
                    len(reactions),
                )
        return eid
