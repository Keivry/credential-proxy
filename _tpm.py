"""TpmMixin — TPM 硬件解封 KeePass 主密码。"""

import asyncio
import logging
import os
import subprocess
import tempfile

logger = logging.getLogger('credential-proxy')


class TpmMixin:
    """Mixin: TPM2 密封/解封操作。"""

    # ── Unseal ──

    def _tpm_unseal(self) -> str:
        """现场派生 primary key + tpm2_load + tpm2_unseal，返回主密码明文。

        primary key 由 TPM storage seed 确定性派生：同一 TPM 上相同模板参数
        (owner hierarchy + rsa2048 + sha256) 每次 createprimary 都得到相同
        key，因此 seal.pub/seal.priv 跨重启永久有效。

        ⚠️ 不要持久化 primary.ctx：它是 transient object 的 context 快照，
        TPM 重启后旧快照会因 integrity check failed (0x1DF) 失效（2026-07-31
        实测）。每次解封前现场 createprimary 即可，开销几十 ms。
        """
        primary_ctx = None
        seal_ctx = None
        try:
            # 1. 现场派生 primary key（参数必须与初始密封时完全一致）
            with tempfile.NamedTemporaryFile(suffix='.ctx', delete=False) as f:
                primary_ctx = f.name
            r0 = subprocess.run(
                [
                    'tpm2_createprimary',
                    '-C',
                    'o',  # owner hierarchy —— 与初始密封命令一致
                    '-G',
                    'rsa2048',
                    '-g',
                    'sha256',
                    '-c',
                    primary_ctx,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if r0.returncode != 0:
                raise RuntimeError(
                    f'tpm2_createprimary 失败: {r0.stderr.strip()}',
                )

            # 2. 加载 sealed blob（seal.pub/seal.priv 永久有效）
            with tempfile.NamedTemporaryFile(suffix='.ctx', delete=False) as f:
                seal_ctx = f.name
            r = subprocess.run(
                [
                    'tpm2_load',
                    '-C',
                    primary_ctx,
                    '-u',
                    self.tpm_seal_pub,
                    '-r',
                    self.tpm_seal_priv,
                    '-c',
                    seal_ctx,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if r.returncode != 0:
                raise RuntimeError(f'tpm2_load 失败: {r.stderr.strip()}')

            # 3. 解封
            r2 = subprocess.run(
                ['tpm2_unseal', '-c', seal_ctx],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if r2.returncode != 0:
                raise RuntimeError(f'tpm2_unseal 失败: {r2.stderr.strip()}')
            # 格式校验：清理输出，拒绝空/过短/含控制字符的结果
            pw = r2.stdout.rstrip('\n\r')
            if not pw:
                raise RuntimeError('TPM 解封返回空密码')
            if len(pw) < 4:
                raise RuntimeError(
                    f'TPM 解封返回的密码过短 ({len(pw)} 字符)',
                )
            # 检查是否有多余的 stderr 输出（TPM 工具可能在 stdout 外输出调试信息）
            if r2.stderr and r2.stderr.strip():
                logger.warning(
                    'tpm2_unseal stderr 非空（可能包含警告）: %s',
                    r2.stderr.strip(),
                )
            return pw
        finally:
            for path in (primary_ctx, seal_ctx):
                if path:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass

    # ── Unlock flow ──

    async def _do_unlock(self, generation: int = 0):
        """后台任务：TPM 解封 → 设置 master_password。"""
        try:
            loop = asyncio.get_running_loop()
            pw = await loop.run_in_executor(
                None,
                self._tpm_unseal,
            )
            if not pw:
                raise RuntimeError('TPM 解封返回空密码')
            async with self._lock:
                if self._unlock_generation != generation:
                    self._unlock_in_progress = False
                    return  # 过时的 unlock task
                self.master_password = pw
                self._kp = None  # 密码变更，清 KeePass 缓存
                self._unlock_in_progress = False
                self._unlock_msg_id = None
                if self.unlock_event and not self.unlock_event.is_set():
                    self.unlock_event.set()
            await self._say('✅ TPM 解锁成功！主密码已加载到内存')
        except Exception:
            logger.exception('TPM 解封失败')
            async with self._lock:
                self._unlock_in_progress = False
                if self.unlock_event and not self.unlock_event.is_set():
                    self.unlock_event.set()
                self.unlock_event = None
                self._unlock_msg_id = None
            await self._say('❌ TPM 解锁失败，详见服务端日志')
