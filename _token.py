"""TokenMixin — 凭据脱敏：注册、替换、还原。

每个密码映射为一个 __VG_CRED_NNNNNN__ token。
使用 re.sub 单次替换，按长度降序防子串碰撞。

PII 请求级映射（RequestScopedTokens）与本文件同处：请求级 PII token
（__PII_<seq>_<rand8>__）与全局凭据映射完全隔离，不进入 pwd_to_token。

"""

import logging
import re as _re
import secrets

logger = logging.getLogger('credential-proxy')

TOKEN_PREFIX = '__VG_CRED_'
TOKEN_SUFFIX = '__'
MAX_TOKEN_ENTRIES = 5000
SECRET_MIN_LENGTH = 4
# 用无界匹配防止 seq 溢出破坏 regex
TOKEN_RE = _re.compile(rb'__VG_CRED_\d{4,}__')
TOKEN_STR_RE = _re.compile(r'__VG_CRED_\d{4,}__')

# ── PII 请求级 token 常量（独立于凭据版，不 import 凭据正则）──
PII_TOKEN_PREFIX = '__PII_'
# PII token 完整形态: __PII_<seq>_<rand8>__（rand8 = 8 位十六进制随机段）
PII_TOKEN_RE = _re.compile(rb'__PII_\d+_[0-9a-f]{8}__')
PII_TOKEN_STR_RE = _re.compile(r'__PII_\d+_[0-9a-f]{8}__')
# 宽松形态（restore 扫描用）：捕获格式不符/越界 token 以记审计事件
PII_TOKEN_LOOSE_RE = _re.compile(r'__PII_\d+_[^_\s]{1,16}__')
# 行尾完整 PII token 形态（流末清理模型幻觉的完整未知 token）
FULL_PII_TOKEN_RE = _re.compile(r'__PII_\d+_[0-9a-f]{8}__$')
# 行尾残缺 PII token 前缀（分片边界清理）——仿照 _PARTIAL_TOKEN_RE 语义，
# 但独立常量，不得 import/共用凭据正则（design D2 硬性）
_PII_PARTIAL_TOKEN_RE = _re.compile(r'__PI(?:I(?:_(?:\d+_)?[0-9a-fA-F]*)?)?_*$')


def _make_pii_token(seq: int, rand8: str) -> str:
    """构造 __PII_<seq>_<rand8>__ token。"""
    return f'{PII_TOKEN_PREFIX}{seq}_{rand8}__'


class RequestScopedTokens:
    """请求级 PII token 映射容器（与全局凭据映射完全隔离）。

    - 独立 pii_p2t / pii_t2p（请求期注册，可还原）
    - 响应期新注册值存 resp_p2t / resp_t2p：形态匹配但不还原（design D2）
    - token 格式 __PII_<seq>_<rand8>__，rand8 用 CSPRNG（secrets.token_hex(4)）
    - 同值去重复用 token
    - restore 仅还原请求期注册 token；格式不符/未注册 token 原样保留并
      记审计事件（同请求同类事件聚合限流：只记一次 + 计数）
    - PII 路径禁止触达全局凭据映射（代码级隔离，不调用 TokenMixin._restore）
    """

    def __init__(self, audit_cb=None):
        self.pii_p2t: dict[str, str] = {}  # 明文 -> token（请求期）
        self.pii_t2p: dict[str, str] = {}  # token -> 明文（请求期，可还原）
        self.resp_p2t: dict[str, str] = {}  # 明文 -> token（响应期）
        self.resp_t2p: dict[str, str] = {}  # token -> 明文（响应期，不可还原）
        self._seq = 0
        self._audit_cb = audit_cb
        self._malformed_counts: dict[str, int] = {}

    def register(self, value: str, response_side: bool = False) -> str:
        """注册 PII 值，返回 token。同值去重复用。响应期值注册到 resp 映射。"""
        if not value:
            return value
        # 值注册校验：拒绝 token 形态值及包含 token 形态子串的值
        # （对齐 _register_secret 的 TOKEN_STR_RE.fullmatch/前缀校验并扩展为「包含子串即拒」）
        if (
            PII_TOKEN_STR_RE.fullmatch(value)
            or PII_TOKEN_PREFIX in value
            or TOKEN_STR_RE.fullmatch(value)
            or TOKEN_PREFIX in value
        ):
            raise ValueError('PII 值不能匹配内部 token 格式或以 token 前缀开头')
        table_p2t = self.resp_p2t if response_side else self.pii_p2t
        table_t2p = self.resp_t2p if response_side else self.pii_t2p
        if value in table_p2t:
            return table_p2t[value]
        self._seq += 1
        token = _make_pii_token(self._seq, secrets.token_hex(4))
        table_p2t[value] = token
        table_t2p[token] = value
        return token

    def restore(self, text: str) -> str:
        """还原请求期注册 token；响应期/未注册/格式不符原样保留 + 审计。

        仅查 pii_t2p（请求期映射），绝不触达全局凭据映射。
        """
        if not text:
            return text
        # 无映射时仍审计格式不符 token（防恶意批量注入无还原路径刷日志，
        # 但限流保证只记一次）
        if not self.pii_t2p and self._audit_cb is not None:
            for m in PII_TOKEN_LOOSE_RE.finditer(text):
                tok = m.group(0)
                if tok not in self.resp_t2p:
                    self._audit_malformed(tok)
            return text

        def _repl(m: _re.Match) -> str:
            tok = m.group(0)
            if tok in self.pii_t2p:
                return self.pii_t2p[tok]
            if tok in self.resp_t2p:
                # 响应期注册 token：形态匹配但原样保留（不还原为明文）
                return tok
            self._audit_malformed(tok)
            return tok

        # 先还原完整形态（pii_t2p / resp_t2p 命中），再对未命中项审计。
        # PII_TOKEN_STR_RE 只覆盖合法形态；格式不符用宽松正则补扫。
        restored = PII_TOKEN_STR_RE.sub(_repl, text)
        if self._audit_cb is not None:
            for m in PII_TOKEN_LOOSE_RE.finditer(restored):
                tok = m.group(0)
                if tok not in self.pii_t2p and tok not in self.resp_t2p:
                    self._audit_malformed(tok)
        return restored

    def _audit_malformed(self, tok: str) -> None:
        """格式不符/未注册 PII token 审计（聚合限流：同类只记一次 + 计数）。

        ⚠️ category 必须保持固定枚举集（malformed/unregistered）——
        它会被 `_pii_audit_cb` 直接写入审计日志的 rule/summary 字段
        （零明文承诺基于此）。禁止扩展为携带 token 形态/前缀细分的
        动态值（如 `malformed:__PII_` 前缀类），否则明文特征落盘。
        """
        if self._audit_cb is None:
            return
        cat = 'malformed'
        if _re.match(r'__PII_\d+_[0-9a-fA-F]{8}__$', tok):
            cat = 'unregistered'
        count = self._malformed_counts.get(cat, 0)
        self._malformed_counts[cat] = count + 1
        if count == 0:
            self._audit_cb(
                'pii_restore_malformed',
                {'category': cat, 'token': tok},
            )

    def clear(self) -> None:
        """请求结束清理全部映射与计数。"""
        self.pii_p2t.clear()
        self.pii_t2p.clear()
        self.resp_p2t.clear()
        self.resp_t2p.clear()
        self._malformed_counts.clear()


def _make_token(n: int) -> str:
    return f'{TOKEN_PREFIX}{n:06d}{TOKEN_SUFFIX}'


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
            if TOKEN_STR_RE.fullmatch(value) or value.startswith(TOKEN_PREFIX):
                logger.warning(
                    '密码值匹配内部 token 格式或前缀，拒绝注册（值已截断不记录）'
                )
                raise ValueError('密码值不能匹配内部 token 格式或以 token 前缀开头')
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
        """注册密码值（use_token=True）或透传原始值（use_token=False）。

        use_token=True（默认）：注册到 token 映射，返回 __VG_CRED_NNNNNN__。
        use_token=False：直接返回原始值，不注册。
        """
        return await self._register_secret(value) if use_token else value

    # ── Redact / Restore ──

    def _redact(self, text: str, pwd_to_token: dict | None = None) -> str:
        """用 token 替换文本中的密码。按长度降序，re.sub 单次替换。
        显式 mapping 时不缓存（每次构建），全集时使用版本缓存。
        """
        mapping = pwd_to_token if pwd_to_token is not None else self.pwd_to_token
        if not mapping:
            return text
        # 显式 mapping：每次构建（快照场景，不缓存，防子集污染全集缓存）
        if pwd_to_token is not None:
            items = sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True)
            pat = _re.compile('|'.join(_re.escape(pwd) for pwd, _ in items))
            repl = {pwd: token for pwd, token in mapping.items()}
            return pat.sub(lambda m: repl.get(m.group(0), m.group(0)), text)
        # 全集：使用版本缓存（pattern + repl dict 同时缓存）
        if getattr(self, '_redact_cache_ver', -1) != self._token_seq:
            items = sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True)
            self._redact_cache_pat = _re.compile(
                '|'.join(_re.escape(pwd) for pwd, _ in items),
            )
            self._redact_cache_repl = dict(mapping)
            self._redact_cache_ver = self._token_seq
        return self._redact_cache_pat.sub(
            self._redact_cache_repl_func,
            text,
        )

    def _redact_cache_repl_func(self, m):
        return self._redact_cache_repl.get(m.group(0), m.group(0))

    def _restore(self, text: str, token_to_pwd: dict | None = None) -> str:
        """将 token 还原为原始密码。

        使用 re.sub 单次替换 + 缓存编译的正则。
        显式 mapping 时不缓存（每次构建），全集时使用版本缓存。
        """
        mapping = token_to_pwd if token_to_pwd is not None else self.token_to_pwd
        if not mapping:
            return text
        # 显式 mapping：每次构建（active_t2p 通常 <10 项，开销可忽略）
        if token_to_pwd is not None:
            items = sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True)
            pat = _re.compile('|'.join(_re.escape(tok) for tok, _ in items))
            return pat.sub(lambda m: mapping.get(m.group(0), m.group(0)), text)
        # 全集：使用版本缓存
        if getattr(self, '_restore_cache_ver', -1) != self._token_seq:
            items = sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True)
            self._restore_cache_pat = _re.compile(
                '|'.join(_re.escape(tok) for tok, _ in items),
            )
            self._restore_cache_repl = dict(mapping)
            self._restore_cache_ver = self._token_seq
        return self._restore_cache_pat.sub(
            self._restore_cache_repl_func,
            text,
        )

    def _restore_cache_repl_func(self, m):
        return self._restore_cache_repl.get(m.group(0), m.group(0))
