"""TokenMixin — 凭据脱敏：注册、替换、还原。

每个密码映射为一个 __VG_CRED_NNNNNN__ token。
使用 OrderedDict + re.sub 单次替换，按长度降序防子串碰撞。
"""
import logging
import re as _re
from collections import OrderedDict

logger = logging.getLogger("credential-proxy")

TOKEN_PREFIX = "__VG_CRED_"
TOKEN_SUFFIX = "__"
MAX_TOKEN_ENTRIES = 5000
SECRET_MIN_LENGTH = 4
# 用 6 位数字防止 seq 溢出破坏 regex（seq 理论上可超过 9999）
TOKEN_RE = _re.compile(rb'__VG_CRED_\d{4,6}__')
TOKEN_STR_RE = _re.compile(r'__VG_CRED_\d{4,6}__')


def _make_token(n: int) -> str:
    return f"{TOKEN_PREFIX}{n:06d}{TOKEN_SUFFIX}"


class TokenMixin:
    """Mixin: credential tokenization for LLM proxy redaction."""

    # ── Registration ──

    async def _register_secret(self, value: str) -> str:
        """注册密码值，返回对应的 token。已存在则复用。"""
        if not value or len(value) < SECRET_MIN_LENGTH:
            return value
        async with self._lock:
            if value in self.pwd_to_token:
                self.pwd_to_token.move_to_end(value)
                return self.pwd_to_token[value]
            if TOKEN_STR_RE.fullmatch(value):
                logger.warning(f"密码值匹配 token 格式，拒绝注册: {value[:20]}...")
                raise ValueError("密码值不能匹配内部 token 格式")
            self._token_seq += 1
            token = _make_token(self._token_seq)
            if len(self.pwd_to_token) >= MAX_TOKEN_ENTRIES:
                oldest = next(iter(self.pwd_to_token))
                old_token = self.pwd_to_token.pop(oldest)
                self.token_to_pwd.pop(old_token, None)
            self.pwd_to_token[value] = token
            self.token_to_pwd[token] = value
            return token

    async def _maybe_register(self, value: str, use_token: bool = True) -> str:
        """条件注册：use_token=True 时注册，否则返回原值。"""
        return await self._register_secret(value) if use_token else value

    # ── Redact / Restore ──

    def _redact(self, text: str, pwd_to_token: dict | None = None) -> str:
        """用 token 替换文本中的密码。按长度降序，re.sub 单次替换。"""
        mapping = pwd_to_token if pwd_to_token is not None else self.pwd_to_token
        if not mapping:
            return text
        # 按长度降序、转义正则特殊字符、构建替换模式
        items = sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True)
        pattern = _re.compile("|".join(_re.escape(pwd) for pwd, _ in items))
        repl = {pwd: token for pwd, token in items}
        return pattern.sub(lambda m: repl[m.group(0)], text)

    def _restore(self, text: str, token_to_pwd: dict | None = None) -> str:
        """将 token 还原为原始密码。"""
        mapping = token_to_pwd if token_to_pwd is not None else self.token_to_pwd
        if not mapping:
            return text
        for token, pwd in mapping.items():
            text = text.replace(token, pwd)
        return text
