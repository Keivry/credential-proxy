"""TpmMixin — TPM 硬件解封 KeePass 主密码。"""
import asyncio
import logging
import os
import subprocess
import tempfile

logger = logging.getLogger("credential-proxy")


class TpmMixin:
    """Mixin: TPM2 密封/解封操作。"""

    # ── Unseal ──

    def _tpm_unseal(self) -> str:
        """调用 tpm2_load + tpm2_unseal，返回主密码明文。"""
        with tempfile.NamedTemporaryFile(suffix=".ctx", delete=False) as f:
            seal_ctx = f.name
        try:
            r = subprocess.run(
                ["tpm2_load", "-C", self.tpm_primary, "-u", self.tpm_seal_pub,
                 "-r", self.tpm_seal_priv, "-c", seal_ctx],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode != 0:
                raise RuntimeError(f"tpm2_load 失败: {r.stderr.strip()}")
            r2 = subprocess.run(
                ["tpm2_unseal", "-c", seal_ctx],
                capture_output=True, text=True, timeout=30,
            )
            if r2.returncode != 0:
                raise RuntimeError(f"tpm2_unseal 失败: {r2.stderr.strip()}")
            return r2.stdout.rstrip("\n\r")
        finally:
            try:
                os.unlink(seal_ctx)
            except OSError:
                pass

    # ── Unlock flow ──

    async def _do_unlock(self, generation: int = 0):
        """后台任务：TPM 解封 → 设置 master_password。"""
        try:
            loop = asyncio.get_running_loop()
            pw = await loop.run_in_executor(
                None, self._tpm_unseal,
            )
            if not pw:
                raise RuntimeError("TPM 解封返回空密码")
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
            await self._say("✅ TPM 解锁成功！主密码已加载到内存")
        except Exception:
            logger.exception("TPM 解封失败")
            async with self._lock:
                self._unlock_in_progress = False
                if self.unlock_event and not self.unlock_event.is_set():
                    self.unlock_event.set()
                self.unlock_event = None
            await self._say("❌ TPM 解锁失败，详见服务端日志")
