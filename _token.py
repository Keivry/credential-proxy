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
import os as _os
import re as _re
import secrets
from collections import OrderedDict

# ── utils/json_walk 共享导入（design D1，存在则复用）──
try:
    from utils.json_walk import _jdumps as _shared_jdumps  # type: ignore
    from utils.json_walk import _jloads as _shared_jloads  # type: ignore
    from utils.json_walk import _strip_bom as _shared_strip_bom  # type: ignore
    from utils.json_walk import json_walk as _shared_json_walk  # type: ignore
    from utils.json_walk import (
        json_walk_async as _shared_json_walk_async,  # type: ignore
    )
except ImportError:
    _shared_strip_bom = None  # type: ignore
    _shared_json_walk = None  # type: ignore
    _shared_json_walk_async = None  # type: ignore
    _shared_jloads = None  # type: ignore
    _shared_jdumps = None  # type: ignore

logger = logging.getLogger('credential-proxy')

# ── orjson 加速封装（有则用，无则回退 stdlib；行为保持 ensure_ascii=False, separators=(',',':') 语义等价）──
try:
    import orjson as _orjson  # type: ignore

    _USE_ORJSON = True
except ImportError:  # pragma: no cover - 回退路径
    _orjson = None  # type: ignore
    _USE_ORJSON = False


def _strip_bom(s: str) -> str:
    if _shared_strip_bom is not None:  # type: ignore[truthy-function]
        return _shared_strip_bom(s)  # type: ignore
    return s.lstrip('﻿')


def _jloads(s: str):
    if _shared_jloads is not None:  # type: ignore[truthy-function]
        return _shared_jloads(s)  # type: ignore
    if _USE_ORJSON:
        return _orjson.loads(s)  # type: ignore
    return _json.loads(s)


def _jdumps(obj) -> str:
    if _shared_jdumps is not None:  # type: ignore[truthy-function]
        return _shared_jdumps(obj)  # type: ignore
    if _USE_ORJSON:
        return _orjson.dumps(obj).decode()  # type: ignore
    return _json.dumps(obj, ensure_ascii=False, separators=(',', ':'))


def _validate_json_roundtrip(original: str, output: str, label: str) -> str:
    """json-aware 后置校验：若原文本是合法 JSON，输出必须仍是合法 JSON。

    失败时打 warning（带前后预览，便于 debug）并回退到原始文本，
    保证下游不收到 JSONDecodeError。预览截断 4000 字符，避免超大体撑爆日志。
    """
    stripped = _strip_bom(original).lstrip()
    if not (stripped.startswith('{') or stripped.startswith('[')):
        return output
    try:
        _json.loads(_strip_bom(original))
    except Exception:
        return output
    try:
        _json.loads(_strip_bom(output))
        return output
    except Exception as exc:
        logger.warning(
            '%s json-aware broke JSON, fallback to original: error=%s '
            'input_len=%d output_len=%d input_preview=%r output_preview=%r',
            label,
            exc,
            len(original),
            len(output),
            original[:4000],
            output[:4000],
        )
        return original


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
# 模糊还原分支（PII_FUZZY_RESTORE=1 时大小写不敏感）
PII_TOKEN_STR_RE_FUZZY = _re.compile(r'__PII_\d+_[0-9a-f]{8}__', _re.IGNORECASE)
# 宽松形态大小写不敏感（fuzzy 分支审计用）
PII_TOKEN_LOOSE_RE_FUZZY = _re.compile(r'__PII_\d+_[^_\s]{1,16}__', _re.IGNORECASE)


def _is_pii_fuzzy_restore_enabled() -> bool:
    return _os.environ.get('PII_FUZZY_RESTORE', '0') == '1'


# 宽松形态（restore 扫描用）：捕获格式不符/越界 token 以记审计事件
PII_TOKEN_LOOSE_RE = _re.compile(r'__PII_\d+_[^_\s]{1,16}__')
# 行尾完整 PII token 形态（流末清理模型幻觉的完整未知 token）
FULL_PII_TOKEN_RE = _re.compile(r'__PII_\d+_[0-9a-f]{8}__$')
# 行尾残缺 PII token 前缀（分片边界清理）——仿照 _PARTIAL_TOKEN_RE 语义，
# 但独立常量，不得 import/共用凭据正则（design D2 硬性）。
# 8.2 修复：在 `__PI` 后负向前瞻 (?!I_\d+_[0-9a-f]{8}__) 排除完整形态
# `__PII_<seq>_<rand8>__`，使完整 token 不被误剥（响应期新 token 保留语义）。
# 8.9 修复（F-10）：结尾 `(?:$|(?=\s|[^\w]))` 覆盖行中残缺形态——
# 残缺前缀后跟空白/标点/汉字等非单词字符时同样剥离；后跟 `_`/hex（可能是
# 不完整 token 待续）保留。
# 注意：前瞻必须置于 `__PI` 之后（而非 hex 段之后），否则 `[0-9a-fA-F]*`
# 回溯可绕过前瞻重新匹配完整形态。
_PII_PARTIAL_TOKEN_RE = _re.compile(
    r'__PI(?!I_\d+_[0-9a-f]{8}__)(?:I(?:_(?:\d+_)?[0-9a-fA-F]*)?)?(?:_*$|(?=\s|[^\w]))'
)


PII_MAX_ENTRIES = (
    1000  # 单表上限（pii/resp 各 1000，总量≤2000，真 LRU），与凭据 5000 区分
)


def _cred_json_walk(obj, redact_func, path: str = '$', _depth: int = 0):
    """递归遍历 JSON 结构，仅对字符串节点调用 redact_func，叶子级最小回退。

    若叶字符串本身为 JSON 文本（lstrip BOM 后 strip 再判 { / [ 且可解析为
    dict/list），则对内层同走 walk→redact/restore→dumps，失败回退 plain。
    叶子级：仅当 redact 后值变化时做 _jdumps 校验，失败仅回退该叶子。
    """
    if _shared_json_walk is not None:  # type: ignore[truthy-function]
        return _shared_json_walk(
            obj, redact_func, depth_limit=5, path=path, _depth=_depth
        )  # type: ignore
    if _depth > 5:
        if isinstance(obj, str):
            try:
                new_s = redact_func(obj)
            except Exception:
                return obj
            if new_s != obj:
                try:
                    _jdumps(new_s)
                except Exception as exc:
                    logger.warning(
                        'cred json leaf broke, fallback leaf: path=%s error=%s '
                        'leaf_preview=%r new_preview=%r',
                        path,
                        exc,
                        obj[:500],
                        new_s[:500],
                    )
                    return obj
            return new_s
        return obj
    if isinstance(obj, str):
        # 嵌套 JSON 字符串递归（tool_calls.arguments 等）
        inner_stripped = _strip_bom(obj).strip()
        if inner_stripped.startswith(('{', '[')):
            try:
                inner = _jloads(inner_stripped)
                if isinstance(inner, (dict, list)):
                    walked = _cred_json_walk(
                        inner, redact_func, f'{path}→$.inner', _depth + 1
                    )
                    return _jdumps(walked)
            except Exception:
                pass
        try:
            new_s = redact_func(obj)
        except Exception:
            return obj
        if new_s != obj:
            try:
                _jdumps(new_s)
            except Exception as exc:
                logger.warning(
                    'cred json leaf broke, fallback leaf: path=%s error=%s '
                    'leaf_preview=%r new_preview=%r',
                    path,
                    exc,
                    obj[:500],
                    new_s[:500],
                )
                return obj
        return new_s
    if isinstance(obj, dict):
        return {
            k: _cred_json_walk(v, redact_func, f'{path}.{k}', _depth)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [
            _cred_json_walk(x, redact_func, f'{path}[{i}]', _depth)
            for i, x in enumerate(obj)
        ]
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
        # 可观测性采集器引用（llm-observability-dashboard）
        self._collector = None

    def set_collector(self, collector) -> None:
        """注入 MetricsCollector（计数钩子）。"""
        self._collector = collector

    def _next_available_index(self, used: set[int] | None = None) -> int:
        """空洞跳过：收集 pii_t2p+resp_t2p 已用 seq set，取最小空缺。"""
        if used is None:
            used = set()
            _seq_pat = _re.compile(r'__PII_(\d+)_')
            for _tok in list(self.pii_t2p.keys()) + list(self.resp_t2p.keys()):
                _m = _seq_pat.search(_tok)
                if _m:
                    try:
                        used.add(int(_m.group(1)))
                    except ValueError:
                        continue
        nxt = 1
        while nxt in used:
            nxt += 1
        return nxt

    def next_available_index(self) -> int:
        """对外兼容别名（同 _next_available_index）。"""
        return self._next_available_index()

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
        async with (
            self._lock
        ):  # 7.7: 原子覆盖 used 快照与 token 写入全程（含 resp_p2t 不还原语义）
            evicted = 0  # Y-12：锁外上报，先初始化防 UnboundLocalError
            table_p2t = self.resp_p2t if response_side else self.pii_p2t
            table_t2p = self.resp_t2p if response_side else self.pii_t2p
            if value in table_p2t:
                table_p2t.move_to_end(value)
                tok = table_p2t[value]
                # 同步 move 对侧
                if tok in table_t2p:
                    table_t2p.move_to_end(tok)
                # pii_cache_hit 计数（仅请求侧合法值；响应侧 resp_p2t 不参与）
                # per-request 累计（事件详情数据源；incr_event 按正确上游合并）
                try:
                    from _metrics import accumulate_pii_cache

                    accumulate_pii_cache(hit=1, miss=0)
                except Exception:
                    pass
                return tok
            # gap-aware: 收集 pii_t2p+resp_t2p 已用 seq set + batch_tracker 再 while递增
            used: set[int] = set()
            _seq_pat = _re.compile(r'__PII_(\d+)_')
            for _tok in list(self.pii_t2p.keys()) + list(self.resp_t2p.keys()):
                _m = _seq_pat.search(_tok)
                if _m:
                    try:
                        used.add(int(_m.group(1)))
                    except ValueError:
                        continue
            nxt = self._next_available_index(used)
            self._seq = max(self._seq, nxt)
            token = _make_pii_token(nxt, secrets.token_hex(4))
            table_p2t[value] = token
            table_t2p[token] = value
            # LRU 淘汰：仅对当前表（pii/resp 各限 1000，总量≤2000）
            evicted = 0
            while len(table_p2t) > PII_MAX_ENTRIES:
                _oldest_val, oldest_tok = table_p2t.popitem(last=False)
                table_t2p.pop(oldest_tok, None)
                evicted += 1
            # pii_cache_miss 计数（仅请求侧合法值；响应侧不参与）
            # per-request 累计（事件详情数据源；incr_event 按正确上游合并）
            try:
                from _metrics import accumulate_pii_cache

                accumulate_pii_cache(hit=0, miss=1)
            except Exception:
                pass
            # Y-12：incr_sync_lru 移到锁外（同步写 metrics，锁内做 IO 会阻塞 register 并发）
            # 记录 evicted 数量，锁块结束后统一上报
        if evicted and self._collector is not None:
            # 批量淘汰 pii_lru_evictions += n（两表各自触发均累加）
            self._collector.incr_sync_lru(cred=0, pii=evicted)
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
        # PII_FUZZY_RESTORE 分支：精确 vs IGNORECASE
        if _is_pii_fuzzy_restore_enabled():
            # fuzzy: 大小写不敏感匹配，命中记审计
            pii_lower = {k.lower(): (k, v) for k, v in pii_t2p_snapshot.items()}
            resp_lower = {k.lower(): (k, v) for k, v in resp_t2p_snapshot.items()}

            def _repl_fuzzy(m: _re.Match) -> str:
                tok = m.group(0)
                low = tok.lower()
                if low in pii_lower:
                    orig, plain = pii_lower[low]
                    try:
                        if orig in self.pii_t2p:
                            self.pii_t2p.move_to_end(orig)
                        if plain in self.pii_p2t:
                            self.pii_p2t.move_to_end(plain)
                    except (KeyError, RuntimeError):
                        pass
                    if tok != orig and self._audit_cb is not None:
                        # 模糊命中审计（大小写漂移）
                        try:
                            cat = 'fuzzy'
                            cnt = self._malformed_counts.get(cat, 0)
                            self._malformed_counts[cat] = cnt + 1
                            if cnt == 0:
                                self._audit_cb(
                                    'pii_restore_malformed',
                                    {'category': cat, 'token': tok},
                                )
                        except Exception:
                            pass
                    return plain
                if low in resp_lower:
                    orig, plain_resp = resp_lower[low]
                    try:
                        if orig in self.resp_t2p:
                            self.resp_t2p.move_to_end(orig)
                        if plain_resp in self.resp_p2t:
                            self.resp_p2t.move_to_end(plain_resp)
                    except (KeyError, RuntimeError):
                        pass
                    return tok
                self._audit_malformed(tok)
                return tok

            restored = PII_TOKEN_STR_RE_FUZZY.sub(_repl_fuzzy, text)
        else:
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
                # cred_hit 计数（按请求 out!=in 计 1）
                self._metrics_cred_hit()
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
                # cred_lru_evictions +1
                self._metrics_cred_lru(1)
            self.pwd_to_token[value] = token
            self.token_to_pwd[token] = value
            # cred_miss 计数（新建）
            self._metrics_cred_miss()
            return token

    def _metrics_cred_hit(self) -> None:
        """cred_hit 计数钩子（同步，无事件循环也安全）。"""
        collector = getattr(self, '_metrics_collector', None)
        if collector is not None:
            collector.incr_sync_cred(hit=1, miss=0)
        # per-request 累计（事件详情数据源）
        try:
            from _metrics import accumulate_cred

            accumulate_cred(hit=1, miss=0)
        except Exception:
            pass

    def _metrics_cred_miss(self) -> None:
        collector = getattr(self, '_metrics_collector', None)
        if collector is not None:
            collector.incr_sync_cred(hit=0, miss=1)
        # per-request 累计（事件详情数据源）
        try:
            from _metrics import accumulate_cred

            accumulate_cred(hit=0, miss=1)
        except Exception:
            pass

    def _metrics_cred_lru(self, n: int = 1) -> None:
        collector = getattr(self, '_metrics_collector', None)
        if collector is not None:
            collector.incr_sync_lru(cred=n, pii=0)

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
          调用 _redact，再 dumps 回写（orjson 优先）；
        - 非 JSON 或解析/序列化失败时回退到纯文本 _redact；
        - 大 JSON 不再按 len 回退 plain，全走 json-aware（C 方案）。
        """
        _mapping = (
            pwd_to_token
            if pwd_to_token is not None
            else getattr(self, 'pwd_to_token', None)
        )
        if not _mapping:
            return text
        stripped = _strip_bom(text).lstrip()
        if not (stripped.startswith(('{', '['))):
            return self._redact(text, pwd_to_token)
        try:
            obj = _jloads(_strip_bom(text))
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
            redacted = _cred_json_walk(obj, _redact_str, path='$')
            out = _jdumps(redacted)
            return _validate_json_roundtrip(text, out, 'cred_redact_json_aware')
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
        # 显式 mapping：请求级两级缓存（9.7 F-07）——同一 active_t2p dict
        # 贯穿整个流（内容几乎不变），仅首行重编 pat，后续行直接复用。
        # 键 = (id(mapping), len(mapping), items 指纹)，mapping 内容变化即失效重编。
        if token_to_pwd is not None:
            _cache = getattr(self, '_restore_active_cache', None)
            _key = (id(mapping), len(mapping), tuple(sorted(mapping.items())))
            if _cache is None or _cache[0] != _key:
                items = sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True)
                pat = _re.compile('|'.join(_re.escape(tok) for tok, _ in items))
                repl = dict(mapping)
                _cache = (_key, pat, repl)
                self._restore_active_cache = _cache
            _pat, _repl = _cache[1], _cache[2]
            return _pat.sub(lambda m: _repl.get(m.group(0), m.group(0)), text)
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
          调用 _restore，再 dumps 回写（orjson 优先）；
        - 非 JSON 或解析/序列化失败时回退到纯文本 _restore；
        - 大 JSON 不再回退 plain，全走 json-aware。
        """
        mapping = (
            token_to_pwd
            if token_to_pwd is not None
            else getattr(self, 'token_to_pwd', None)
        )
        if not mapping:
            return text
        stripped = _strip_bom(text).lstrip()
        if not (stripped.startswith(('{', '['))):
            return self._restore(text, token_to_pwd)
        try:
            obj = _jloads(_strip_bom(text))
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
            restored = _cred_json_walk(obj, _restore_str, path='$')
            out = _jdumps(restored)
            return _validate_json_roundtrip(text, out, 'cred_restore_json_aware')
        except Exception:
            logger.debug('_restore_json_aware 回退到纯文本路径', exc_info=True)
            return self._restore(text, token_to_pwd)
