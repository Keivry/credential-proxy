"""TokenMixin — 凭据脱敏：注册、替换、还原。

每个密码映射为一个 __VG_CRED_NNNNNN__ token。
使用 re.sub 单次替换，按长度降序防子串碰撞。

PII 全局持久映射（GlobalPiiTokens）与本文件同处：进程级全局 LRU PII token
（__PII_<seq>_<rand8>__）与全局凭据映射完全隔离，不进入 pwd_to_token。
RequestScopedTokens 保留为兼容别名（指向 GlobalPiiTokens）。

"""

import asyncio
import json as _json
import logging
import re as _re
import secrets
from collections import OrderedDict

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


PII_MAX_ENTRIES = (
    1000  # 单表上限（pii/resp 各 1000，总量≤2000，真 LRU），与凭据 5000 区分
)


def _cred_json_walk(obj, redact_func, _depth: int = 0):
    """递归遍历 JSON 结构，仅对字符串节点调用 redact_func。

    若叶字符串本身为 JSON 文本（lstrip BOM 后 strip 再判 { / [ 且可解析为
    dict/list），则对内层同走 walk→redact/restore→dumps，失败回退 plain。
    """
    if _depth > 5:
        return redact_func(obj) if isinstance(obj, str) else obj
    if isinstance(obj, str):
        # 嵌套 JSON 字符串递归（tool_calls.arguments 等）
        inner_stripped = obj.lstrip('\ufeff').strip()
        if inner_stripped.startswith(('{', '[')):
            try:
                inner = _json.loads(inner_stripped)
                if isinstance(inner, (dict, list)):
                    walked = _cred_json_walk(inner, redact_func, _depth + 1)
                    return _json.dumps(
                        walked, ensure_ascii=False, separators=(',', ':')
                    )
            except Exception:  # noqa: S110 - "{not json" 叶回退 plain
                pass
        return redact_func(obj)
    if isinstance(obj, dict):
        return {k: _cred_json_walk(v, redact_func, _depth) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_cred_json_walk(x, redact_func, _depth) for x in obj]
    return obj


def _make_pii_token(seq: int, rand8: str) -> str:
    """构造 __PII_<seq>_<rand8>__ token。"""
    return f'{PII_TOKEN_PREFIX}{seq}_{rand8}__'


class GlobalPiiTokens:
    """进程级全局持久 PII token 映射容器（与全局凭据映射完全隔离）。

    - 进程单例，常驻 `pii_p2t/pii_t2p/resp_*`，命中复用同一 token
    - 真 LRU：`OrderedDict` + `move_to_end` + 超限 `popitem(last=False)`
    - `register` 为 `async def`，`asyncio.Lock` 保护并发注册
    - token 格式 __PII_<seq>_<rand8>__，rand8 用 CSPRNG（secrets.token_hex(4)）
    - 同值去重复用 token
    - restore 仅还原请求期注册 token；格式不符/未注册 token 原样保留并
      记审计事件（同请求同类事件聚合限流：只记一次 + 计数）
    - PII 路径禁止触达全局凭据映射（代码级隔离，不调用 TokenMixin._restore）
    """

    def __init__(self, audit_cb=None):
        self.pii_p2t: OrderedDict[str, str] = OrderedDict()  # 明文 -> token（请求期）
        self.pii_t2p: OrderedDict[str, str] = (
            OrderedDict()
        )  # token -> 明文（请求期，可还原）
        self.resp_p2t: OrderedDict[str, str] = OrderedDict()  # 明文 -> token（响应期）
        self.resp_t2p: OrderedDict[str, str] = (
            OrderedDict()
        )  # token -> 明文（响应期，不可还原）
        self._seq = 0
        self._audit_cb = audit_cb
        self._malformed_counts: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def register(self, value: str, response_side: bool = False) -> str:
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
        async with self._lock:
            table_p2t = self.resp_p2t if response_side else self.pii_p2t
            table_t2p = self.resp_t2p if response_side else self.pii_t2p
            if value in table_p2t:
                table_p2t.move_to_end(value)
                tok = table_p2t[value]
                # 同步 move 对侧
                if tok in table_t2p:
                    table_t2p.move_to_end(tok)
                return tok
            self._seq += 1
            token = _make_pii_token(self._seq, secrets.token_hex(4))
            table_p2t[value] = token
            table_t2p[token] = value
            # LRU 淘汰：仅对当前表（pii/resp 各限 1000，总量≤2000）
            while len(table_p2t) > PII_MAX_ENTRIES:
                _oldest_val, oldest_tok = table_p2t.popitem(last=False)
                table_t2p.pop(oldest_tok, None)
            return token

    def restore(self, text: str) -> str:
        """还原请求期注册 token；响应期/未注册/格式不符原样保留 + 审计。

        仅查 pii_t2p（请求期映射），绝不触达全局凭据映射。
        真 LRU：命中后 move_to_end 提升为最新（与 register 语义一致）。
        并发安全：asyncio 单线程中同步读不 yield，但 register 持 _lock 时
        可能并发读；用快照 + try/move_to_end 避免 OrderedDict mutated 异常。
        """
        if not text:
            return text
        # 无映射时仍审计格式不符 token（防恶意批量注入无还原路径刷日志，
        # 但限流保证只记一次）
        # 快照避免并发 mutated
        try:
            pii_t2p_snapshot = dict(self.pii_t2p)
            resp_t2p_snapshot = dict(self.resp_t2p)
        except RuntimeError:
            pii_t2p_snapshot = dict(list(self.pii_t2p.items()))
            resp_t2p_snapshot = dict(list(self.resp_t2p.items()))
        if not pii_t2p_snapshot and not resp_t2p_snapshot:
            if self._audit_cb is not None:
                for m in PII_TOKEN_LOOSE_RE.finditer(text):
                    tok = m.group(0)
                    self._audit_malformed(tok)
            return text

        def _repl(m: _re.Match) -> str:
            tok = m.group(0)
            if tok in pii_t2p_snapshot:
                plain = pii_t2p_snapshot[tok]
                # 真 LRU：提升热值（try 保护并发 register 期间的 mutated）
                try:
                    if tok in self.pii_t2p:
                        self.pii_t2p.move_to_end(tok)
                    if plain in self.pii_p2t:
                        self.pii_p2t.move_to_end(plain)
                except (KeyError, RuntimeError):
                    pass
                return plain
            if tok in resp_t2p_snapshot:
                # 响应期注册 token：形态匹配但原样保留（不还原为明文）
                # 同样提升 LRU — 双表同步（resp_p2t 以 resp_t2p 查 plain 再提升）
                try:
                    if tok in self.resp_t2p:
                        self.resp_t2p.move_to_end(tok)
                    # 同步提升 resp_p2t：通过快照查 plain
                    plain_resp = resp_t2p_snapshot.get(tok)
                    if plain_resp is not None and plain_resp in self.resp_p2t:
                        self.resp_p2t.move_to_end(plain_resp)
                except (KeyError, RuntimeError):
                    pass
                return tok
            self._audit_malformed(tok)
            return tok

        # 先还原完整形态（pii_t2p / resp_t2p 命中），再对未命中项审计。
        # PII_TOKEN_STR_RE 只覆盖合法形态；格式不符用宽松正则补扫。
        restored = PII_TOKEN_STR_RE.sub(_repl, text)
        if self._audit_cb is not None:
            # 用快照二次审计，避免并发期漏判
            try:
                cur_pii = set(self.pii_t2p)
                cur_resp = set(self.resp_t2p)
            except RuntimeError:
                cur_pii = set(self.pii_t2p)
                cur_resp = set(self.resp_t2p)
            for m in PII_TOKEN_LOOSE_RE.finditer(restored):
                tok = m.group(0)
                if tok not in cur_pii and tok not in cur_resp:
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
        """请求结束清理全部映射与计数。

        注意：全局持久化后此方法不再在每请求清理中调用（_pii_cleanup 不再 clear），
        仅保留供测试/手动重置使用。
        """
        self.pii_p2t.clear()
        self.pii_t2p.clear()
        self.resp_p2t.clear()
        self.resp_t2p.clear()
        self._malformed_counts.clear()


# 兼容别名：旧 RequestScopedTokens → 新 GlobalPiiTokens（已全局持久化，旧名保留仅供测试/外部兼容）
RequestScopedTokens = GlobalPiiTokens


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

    def _redact_json_aware(self, text: str, pwd_to_token: dict | None = None) -> str:
        """JSON 感知的凭据脱敏：仅对字符串节点做替换，避免破坏 \\u 转义。

        - 若 text 是合法 JSON（object/array），则 loads 后递归 walk 字符串值，逐个
          调用 _redact，再 dumps(ensure_ascii=False) 回写；\n        - 非 JSON 或解析/序列化失败时回退到纯文本 _redact。\n"""
        _mapping = (
            pwd_to_token
            if pwd_to_token is not None
            else getattr(self, 'pwd_to_token', None)
        )
        if not _mapping:
            return text
        if len(text) > 1_048_576:
            return self._redact(text, pwd_to_token)
        stripped = text.lstrip('\ufeff').lstrip()
        if not (stripped.startswith(('{', '['))):
            return self._redact(text, pwd_to_token)
        try:
            obj = _json.loads(text.lstrip('\ufeff'))
        except Exception:
            return self._redact(text, pwd_to_token)
        # 为字符串节点构造单次编译的 redact 函数（显式 mapping 场景）
        if pwd_to_token is not None:
            items = sorted(_mapping.items(), key=lambda x: len(x[0]), reverse=True)
            pat = _re.compile('|'.join(_re.escape(pwd) for pwd, _ in items))
            repl = {pwd: token for pwd, token in _mapping.items()}

            def _redact_str(s: str) -> str:
                return pat.sub(lambda m: repl.get(m.group(0), m.group(0)), s)

        else:

            def _redact_str(s: str) -> str:
                return self._redact(s, None)

        try:
            redacted = _cred_json_walk(obj, _redact_str)
            return _json.dumps(redacted, ensure_ascii=False, separators=(',', ':'))
        except Exception:
            logger.debug('_redact_json_aware 回退到纯文本路径', exc_info=True)
            return self._redact(text, pwd_to_token)

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

    def _restore_json_aware(self, text: str, token_to_pwd: dict | None = None) -> str:
        """JSON 感知的凭据还原：仅对字符串节点做替换，避免破坏 \\u 转义。

        - 若 text 是合法 JSON（object/array），则 loads 后递归 walk 字符串值，逐个
          调用 _restore，再 dumps(ensure_ascii=False) 回写；
        - 非 JSON 或解析/序列化失败时回退到纯文本 _restore。
        """
        mapping = (
            token_to_pwd
            if token_to_pwd is not None
            else getattr(self, 'token_to_pwd', None)
        )
        if not mapping:
            return text
        if len(text) > 1_048_576:
            return self._restore(text, token_to_pwd)
        stripped = text.lstrip('\ufeff').lstrip()
        if not (stripped.startswith(('{', '['))):
            return self._restore(text, token_to_pwd)
        try:
            obj = _json.loads(text.lstrip('\ufeff'))
        except Exception:
            return self._restore(text, token_to_pwd)
        if token_to_pwd is not None:
            items = sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True)
            pat = _re.compile('|'.join(_re.escape(tok) for tok, _ in items))

            def _restore_str(s: str) -> str:
                return pat.sub(lambda m: mapping.get(m.group(0), m.group(0)), s)

        else:

            def _restore_str(s: str) -> str:
                return self._restore(s, None)

        try:
            restored = _cred_json_walk(obj, _restore_str)
            return _json.dumps(restored, ensure_ascii=False, separators=(',', ':'))
        except Exception:
            logger.debug('_restore_json_aware 回退到纯文本路径', exc_info=True)
            return self._restore(text, token_to_pwd)
