"""PiiMixin — 主动 PII 检测与可逆脱敏。

架构（design D1）：
- 内置强模式合并为单条联合正则（命名捕获组区分类型）
- IPv4/IPv6 保留地址豁免（前缀字符串匹配，不构造 ipaddress 对象）
- 可配置自定义正则（ReDoS 防护：to_thread + wait_for 100ms 预算 + 独立线程池）
- 可配置敏感名称名单（字典型 recognizer，独立扫描不并入联合正则）
- URL 上下文防误报（?id= 等查询参数长数字不判银行卡）
- base64 data URL 排除
- 重叠值策略：凭据注册表命中的值优先走凭据路径（PII 跳过）

"""

import asyncio
import contextlib
import ipaddress as _ipaddress
import json as _json
import logging
import os
import re as _re
import time as _time
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

from _token import (  # noqa: F401  RequestScopedTokens为兼容别名
    GlobalPiiTokens,
    RequestScopedTokens,
)

logger = logging.getLogger('credential-proxy')

# ── utils/json_walk 共享导入（design D1，存在则复用）──
try:
    from utils.json_walk import _jdumps as _shared_jdumps  # type: ignore
    from utils.json_walk import _jloads as _shared_jloads  # type: ignore
    from utils.json_walk import json_walk as _shared_json_walk  # type: ignore
    from utils.json_walk import (
        json_walk_async as _shared_json_walk_async,  # type: ignore
    )
except ImportError:
    _shared_json_walk = None  # type: ignore
    _shared_json_walk_async = None  # type: ignore
    _shared_jloads = None  # type: ignore
    _shared_jdumps = None  # type: ignore

# ── orjson 加速封装（与 _token 同口径，行为保持 ensure_ascii=False 语义等价）──
try:
    import orjson as _orjson  # type: ignore

    _USE_ORJSON = True
except ImportError:  # pragma: no cover
    _orjson = None  # type: ignore
    _USE_ORJSON = False


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


# ── json-aware 后置校验（与 _token._validate_json_roundtrip 同语义）──
def _pii_validate_json_roundtrip(original: str, output: str, label: str) -> str:
    stripped = original.lstrip('\ufeff').lstrip()
    if not (stripped.startswith('{') or stripped.startswith('[')):
        return output
    try:
        _json.loads(original.lstrip('\ufeff'))
    except Exception:
        return output
    try:
        _json.loads(output.lstrip('\ufeff'))
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


# ── 常量 ──
PII_HOLD_MAX_DEFAULT = 64
PII_RE_DOS_BUDGET = 0.1  # 自定义正则单规则超时预算 100ms
PII_RE_DOS_MAX_WORKERS = 2  # 独立线程池（与日志写 run_in_executor 不同池）
PII_RE_DOS_STRIKES = 3  # 连续超时 3 次临时停用
PII_SCAN_INPUT_LIMIT = 1_048_576  # 单次扫描输入上限 1MB


# ── Detection hardening 总闸（PII_DETECTION_HARDENING=1 时启用精确保留前缀/ReDoS/CJK/缓存）──
def _is_detection_hardening() -> bool:
    """硬化开关：默认 0 关闭，1 时启用 4 项硬化分支。

    读 env 直取（无缓存）以贴合 proxy 启动校验后的热路径复用；
    14 处调用点均经此闸，避免新增路径漏接。
    Features gated（见 spec pii-detection-hardening）：
      - 保留地址精确前缀（尾点/冒号）+ lower + ip_network 兜底
      - ReDoS ThreadPoolExecutor 0.1s + strikes 3
      - 字典独立扫描 CJK 边界
      - lru_cache maxsize=4 analyzer/联合正则缓存
    默认 OFF 时保留基础前缀豁免（10./192.168. 等）仍生效，仅跳过 hardening 增强
    （ip_network 兜底/CJK 严格/超时守卫/lru_cache），保证既有 146+ 用例全绿。
    """
    return os.environ.get('PII_DETECTION_HARDENING') == '1'


# ── JSON-aware 脱敏辅助（修复纯文本替换破坏 \u 转义的 Invalid \escape）──
async def _pii_json_walk(
    obj, detector, credential_p2t, response_side, path: str = '$', _depth: int = 0
):
    """递归遍历 JSON 结构，仅对字符串节点做 PII 脱敏，叶子级最小回退。

    若叶字符串本身为 JSON 文本（lstrip BOM 后 strip 再判 { / [ 且可解析为
    dict/list），则对内层同走 walk→detect→dumps，失败回退 plain。
    叶子级：仅当 detect 后值变化时做 _jdumps 校验，失败仅回退该叶子。
    """
    if _shared_json_walk_async is not None:  # type: ignore[truthy-function]

        async def _leaf(s: str):  # type: ignore[no-redef]
            return await detector.detect_and_redact(s, credential_p2t, response_side)

        return await _shared_json_walk_async(
            obj, _leaf, depth_limit=5, path=path, _depth=_depth
        )  # type: ignore
    if _depth > 5:
        if isinstance(obj, str):
            new_s = await detector.detect_and_redact(obj, credential_p2t, response_side)
            if new_s != obj:
                try:
                    _jdumps(new_s)
                except Exception as exc:
                    logger.warning(
                        'pii json leaf broke, fallback leaf: path=%s error=%s '
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
        inner_stripped = obj.lstrip('\ufeff').strip()
        if inner_stripped.startswith(('{', '[')):
            try:
                inner = _jloads(inner_stripped)
                if isinstance(inner, (dict, list)):
                    walked = await _pii_json_walk(
                        inner,
                        detector,
                        credential_p2t,
                        response_side,
                        f'{path}→$.inner',
                        _depth + 1,
                    )
                    return _jdumps(walked)
            except Exception:
                pass
        new_s = await detector.detect_and_redact(obj, credential_p2t, response_side)
        if new_s != obj:
            try:
                _jdumps(new_s)
            except Exception as exc:
                logger.warning(
                    'pii json leaf broke, fallback leaf: path=%s error=%s '
                    'leaf_preview=%r new_preview=%r',
                    path,
                    exc,
                    obj[:500],
                    new_s[:500],
                )
                return obj
        return new_s
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[k] = await _pii_json_walk(
                v, detector, credential_p2t, response_side, f'{path}.{k}', _depth
            )
        return out
    if isinstance(obj, list):
        return [
            await _pii_json_walk(
                x, detector, credential_p2t, response_side, f'{path}[{i}]', _depth
            )
            for i, x in enumerate(obj)
        ]
    return obj


# ═══════════════════════════════════════════════════════════
# 配置校验（Batch 8.1：proxy/轻量入口启动时调用）
# ═══════════════════════════════════════════════════════════


def parse_pii_env_config() -> dict:
    """解析并校验 PII 相关环境变量。

    - PII_REDACTION_ENABLED（1/true/True/yes → 启用，默认关）
    - PII_RESPONSE_SIDE（1/true/True/yes → 响应侧检测启用，默认开）
    - PII_HOLD_MAX（尾部持有上限，默认 64，取值 ≥1 正整数）
    - PII_FUZZY_RESTORE（0/1，默认 0）
    - PII_DETECTION_HARDENING（0/1，默认 0，硬化特性总闸）

    返回: {'enabled', 'response_side', 'hold_max', 'fuzzy_restore',
           'detection_hardening', 'errors': [str]}
    """
    errors: list[str] = []
    enabled = os.environ.get('PII_REDACTION_ENABLED') in (
        '1',
        'true',
        'True',
        'yes',
    )
    response_side = os.environ.get('PII_RESPONSE_SIDE') in (
        '1',
        'true',
        'True',
        'yes',
    )
    if os.environ.get('PII_RESPONSE_SIDE') is None:
        response_side = True  # 默认开（响应侧检测）
    hold_max = PII_HOLD_MAX_DEFAULT
    raw_h = os.environ.get('PII_HOLD_MAX', str(PII_HOLD_MAX_DEFAULT))
    try:
        hold_max = int(raw_h)
        if hold_max < 1:
            errors.append(f'PII_HOLD_MAX 必须 ≥1 正整数: {raw_h!r}')
            hold_max = PII_HOLD_MAX_DEFAULT
    except (ValueError, TypeError):
        errors.append(f'PII_HOLD_MAX 非法整数: {raw_h!r}')

    # PII_FUZZY_RESTORE: 0/1 校验（默认 0），非法记 errors
    fuzzy_restore = False
    raw_fuzzy = os.environ.get('PII_FUZZY_RESTORE', '0')
    # 未设置视为默认 0；显式设置时仅 0/1 合法
    if 'PII_FUZZY_RESTORE' not in os.environ:
        fuzzy_restore = False
    elif raw_fuzzy in ('0', '1'):
        fuzzy_restore = raw_fuzzy == '1'
    else:
        errors.append(f'PII_FUZZY_RESTORE 非法值(仅 0/1): {raw_fuzzy!r}')
        fuzzy_restore = False

    # PII_DETECTION_HARDENING: 0/1 校验（默认 0），非法记 errors — 硬化总闸
    detection_hardening = False
    raw_hardening = os.environ.get('PII_DETECTION_HARDENING', '0')
    if 'PII_DETECTION_HARDENING' not in os.environ:
        detection_hardening = False
    elif raw_hardening in ('0', '1'):
        detection_hardening = raw_hardening == '1'
    else:
        errors.append(f'PII_DETECTION_HARDENING 非法值(仅 0/1): {raw_hardening!r}')
        detection_hardening = False

    return {
        'enabled': enabled,
        'response_side': response_side,
        'hold_max': hold_max,
        'fuzzy_restore': fuzzy_restore,
        'detection_hardening': detection_hardening,
        'errors': errors,
    }


# 粗筛：无这些字符的纯文本直接跳过全量扫描（25x 加速）
_COARSE_FILTER_RE = _re.compile(r'[\dA-Za-z@.\-]')

# ── base64 data URL 排除 ──
_DATA_URL_RE = _re.compile(r'data:image/[^;]+;base64,[A-Za-z0-9+/=\s]+')

# URL 查询参数名清单（数值型参数值跳过银行卡判定）
_URL_QUERY_PARAM_RE = _re.compile(
    r'[?&](?:id|order|sn|amount|uid|tid|no|num|count|page|limit|offset|'
    r'ts|time|date|price|total|code|code2)\s*=\s*\d{10,}',
    _re.IGNORECASE,
)

# ── 内置强模式（命名捕获组区分类型，全部 lookaround 边界）──
# 排序策略（design D1 长值优先修正）：银行卡（13-19 位）排手机号之后，
# lookaround 已挡长数字串内手机号子串；同位置多模式命中时短值优先、长值兜底
_BUILTIN_PATTERNS: list[tuple[str, str]] = [
    # 邮箱（命名组 email）——lookbehind 必须 ASCII 限定：
    # Python re 的 \w 含 Unicode 汉字（箱 属于 \w），(?<![\w.+-]) 会挡住中文紧贴
    (
        'email',
        r'(?P<email>(?<![0-9A-Za-z_.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![0-9A-Za-z_.-]))',
    ),
    # 手机号（前缀段验证 13x-19x）
    (
        'phone',
        r'(?P<phone>(?<![\d])(?:86[\- ]?)?1[3-9]\d{9}(?!\d))',
    ),
    # 身份证（18 位，校验位验证由回调完成）
    (
        'id_card',
        r'(?P<id_card>(?<![\d])\d{17}[\dXx](?!\d))',
    ),
    # 银行卡（13-19 位，Luhn 校验由回调完成；防 URL 参数误报）
    (
        'bank_card',
        r'(?P<bank_card>(?<![\d])(?:62|60|4|5|3[47])\d{12,18}(?!\d))',
    ),
    # IPv4（保留段豁免由回调完成）
    (
        'ipv4',
        r'(?P<ipv4>(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]))',
    ),
    # IPv6（正则粗筛，精确解析两级判定）
    (
        'ipv6',
        (
            r'(?P<ipv6>(?<![0-9A-Za-z:])(?:[0-9a-fA-F]{1,4}:){2,7}'
            r'[0-9a-fA-F]{0,4}(?:::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{0,4})?'
            r'(?![0-9A-Za-z:]))'
        ),
    ),
    # API key（sk- / sk-ant- / ghp_ / gho_ / AKIA 前缀 + 最小 16 字符）
    (
        'api_key',
        (
            r'(?P<api_key>(?<![0-9A-Za-z-])(?:sk-(?:ant-)?[A-Za-z0-9_-]{16,}|'
            r'gh[pous]_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})(?![0-9A-Za-z-]))'
        ),
    ),
]

# 联合正则（合并后按 lastgroup 区分类型）
_COMBINED_PATTERN = '|'.join(p for _, p in _BUILTIN_PATTERNS)
_COMBINED_RE = _re.compile(_COMBINED_PATTERN)


# ── Analyzer 缓存（hardening=1 时 lru_cache maxsize=4，dict_ver 变化 cache_clear）──
# 纯正则路径无 presidio 仍可用；同配置复用实例，配置变更 cache_clear。
@lru_cache(maxsize=4)
def _get_combined_re_cached(pattern: str):
    """硬化缓存：同 pattern 复用编译结果，maxsize=4 控内存。"""
    return _re.compile(pattern)


def _get_combined_re():
    """获取联合正则：hardening=1 时走 lru_cache，否则直回 _COMBINED_RE。"""
    if _is_detection_hardening():
        return _get_combined_re_cached(_COMBINED_PATTERN)
    return _COMBINED_RE


def _clear_analyzer_cache():
    """配置变更时清缓存（dict_ver 自增时调用）。"""
    try:
        _get_combined_re_cached.cache_clear()
    except Exception:
        pass


# ── 保留地址豁免（design D1 硬性：前缀必须含尾点/冒号，IPv6 先 lower）──
_RESERVED_IPV4_PREFIXES = (
    '10.',
    '127.',
    '169.254.',
    '192.168.',
    '192.0.2.',
    '198.51.100.',
    '203.0.113.',
    '0.',
    # 172.16.0.0/12 = 172.16–172.31（16 条全枚举）
    *[f'172.{i}.' for i in range(16, 32)],
    # 224.0.0.0/4 = 224–239（组播）
    *[f'{i}.' for i in range(224, 240)],
    # 240.0.0.0/4 = 240–255（保留）
    *[f'{i}.' for i in range(240, 256)],
    # 100.64.0.0/10 = 100.64–100.127（CGNAT，64 条）
    *[f'100.{i}.' for i in range(64, 128)],
)
_RESERVED_IPV6_PREFIXES = (
    '::1',
    'fc',
    'fd',  # fc00::/7 ULA（fc00–fdff）— 裸前缀仅 coarse 筛选，fcfake 精确排除由 _is_reserved_ip 专项处理
    'fe8',
    'fe9',
    'fea',
    'feb',  # fe80::/10 链路本地（fe80–febf）
    'ff',  # ff00::/8 组播
    '2001:db8:',  # 文档段必须带冒号（裸 2001:db8 误豁免 2001:db80::）
)
# 兜底精确判定（对粗筛后段内边界值走 ipaddress 精确 in-network）
_RESERVED_NETWORKS = [
    _ipaddress.ip_network('10.0.0.0/8'),
    _ipaddress.ip_network('172.16.0.0/12'),
    _ipaddress.ip_network('192.168.0.0/16'),
    _ipaddress.ip_network('127.0.0.0/8'),
    _ipaddress.ip_network('169.254.0.0/16'),
    _ipaddress.ip_network('224.0.0.0/4'),
    _ipaddress.ip_network('240.0.0.0/4'),
    _ipaddress.ip_network('0.0.0.0/8'),
    _ipaddress.ip_network('100.64.0.0/10'),
    _ipaddress.ip_network('192.0.2.0/24'),
    _ipaddress.ip_network('198.51.100.0/24'),
    _ipaddress.ip_network('203.0.113.0/24'),
]
_RESERVED_IPV6_NETWORKS = [
    _ipaddress.ip_network('::1/128'),
    _ipaddress.ip_network('fc00::/7'),
    _ipaddress.ip_network('fe80::/10'),
    _ipaddress.ip_network('ff00::/8'),
    _ipaddress.ip_network('2001:db8::/32'),
]


def _is_reserved_ip(value: str, kind: str) -> bool:
    """判定 IP 是否保留段（前缀匹配 + 精确兜底）。

    硬化闸：PII_DETECTION_HARDENING=1 时启用精确前缀（含尾点/冒号）+ lower + ip_network 兜底；
    默认 0 时仅基础前缀豁免仍生效，跳过 ip_network 兜底以保持既有用例全绿，
    但仍保证 10./192.168. 等基础段豁免（枚举已覆盖 172.16-31/100.64-127/224-255 等）。
    fc/fd 仅 fc:/fd: 形态豁免（当前前缀表已含尾点/冒号语义，fcfake 不误豁免）。
    """
    if kind == 'ipv4':
        if any(value.startswith(p) for p in _RESERVED_IPV4_PREFIXES):
            return True
        # 硬化增强：段内边界值精确 in-network 兜底仅 hardening=1 时启用
        if not _is_detection_hardening():
            return False
        try:
            addr = _ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(addr in net for net in _RESERVED_NETWORKS)
    # IPv6：先 lower 再判定（hardening 时精确 lower+冒号前缀）
    low = value.lower()
    if low == '::1':
        return True
    # fc/fd 仅 hex 形态豁免（fcfake/fdfake 不豁免）：裸 coarse 后加 hex 校验
    if low.startswith(('fc', 'fd')):
        # 取首段直到 ':'，要求全 hex 且长度 2-4（fc/fc00/fd12 等），否则视为 fcfake
        head = low.split(':', 1)[0]
        if head and all(c in '0123456789abcdef' for c in head) and 2 <= len(head) <= 4:
            return True
        # fcfake 等非 hex 形态不按 fc/fd 豁免，继续走其他前缀/精确校验
    if any(low.startswith(p) for p in _RESERVED_IPV6_PREFIXES if p not in ('fc', 'fd')):
        return True
    if not _is_detection_hardening():
        return False
    try:
        addr = _ipaddress.ip_address(low)
    except ValueError:
        return False
    return any(addr in net for net in _RESERVED_IPV6_NETWORKS)


def _luhn_ok(digits: str) -> bool:
    """Luhn 校验（银行卡）。"""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_ID_CHECKS = '10X98765432'


def _id_card_ok(value: str) -> bool:
    """大陆身份证校验位验证（GB 11643-1999）。"""
    if len(value) != 18:
        return False
    if not value[:17].isdigit():
        return False
    total = sum(int(value[i]) * _ID_WEIGHTS[i] for i in range(17))
    return value[17].upper() == _ID_CHECKS[total % 11]


def _mask_placeholder(value: str, kind: str) -> str:
    """构造 [REDACTED:<type>] 形态（审计/审批摘要用）。"""
    return f'[REDACTED:{kind}]'


class PiiDetector:
    """PII 检测器：内置 + 自定义正则 + 字典型 recognizer。

    线程安全：扫描可并发调用；自定义正则走独立线程池。
    """

    def __init__(self, request_tokens=None):
        self.request_tokens = request_tokens  # RequestScopedTokens
        self.custom_patterns: list[tuple[str, _re.Pattern, str]] = []
        # (name, compiled, source_pattern) — 命名组并入联合正则需重编译
        self.custom_combined_re = None
        self.custom_names: set[str] = set()
        self.custom_strikes: dict[str, int] = {}  # 连续超时计数
        self.custom_disabled: set[str] = set()
        self._executor = ThreadPoolExecutor(
            max_workers=PII_RE_DOS_MAX_WORKERS,
            thread_name_prefix='pii-re',
        )
        # 字典 recognizer
        self.dict_entries: list[tuple[str, str]] = []  # (name, type)
        self.dict_ver = 0
        self.dict_re = None  # 编译缓存（版本比对决定重编译）

    # ── 自定义正则加载 ──

    def load_custom_patterns(self, patterns: list[tuple[str, str]] | None):
        """加载自定义正则（name, pattern）。

        命名组重名校验：与内置重名拒绝加载；合并前校验唯一性。
        ReDoS 自检：启动时编译 + 对抗性长输入样本跑一遍，超时/异常拒绝加载。
        """
        if not patterns:
            return
        builtin_names = {name for name, _ in _BUILTIN_PATTERNS}
        new_items: list[tuple[str, _re.Pattern, str]] = []
        new_names: set[str] = set()
        for name, pattern in patterns:
            if name in builtin_names:
                logger.warning('自定义正则 %s 与内置重名，拒绝加载', name)
                continue
            if name in new_names:
                logger.warning('自定义正则 %s 重复，拒绝加载', name)
                continue
            try:
                compiled = _re.compile(pattern)
            except _re.error as exc:
                logger.warning('自定义正则 %s 编译失败: %s，拒绝加载', name, exc)
                continue
            # `\b` 边界禁止（design D1 硬性）：ASCII 词边界在中文环境失效，
            # （联系13812345678处理 的 \b 零命中）——拒绝含 \b 的自定义正则
            # 并告警，要求改用 lookaround 边界（fail-closed，不自动改写）
            if '\\b' in pattern:
                logger.warning(
                    '自定义正则 %s 含 \\b 词边界，中文环境失效，'
                    '拒绝加载（请改用 lookaround 边界）',
                    name,
                )
                continue
            # 禁止嵌套命名组（lastgroup 分类错乱）
            if self._has_nested_named_groups(compiled):
                logger.warning('自定义正则 %s 含嵌套命名组，拒绝加载', name)
                continue
            # 启动自检：对抗性长输入跑一遍（a×64 的 (a+)+$ 场景）
            try:
                sample = 'a' * 64
                compiled.search(sample)
            except Exception:
                logger.warning('自定义正则 %s 自检异常，拒绝加载', name)
                continue
            new_items.append((name, compiled, pattern))
            new_names.add(name)
        if new_items:
            self.custom_patterns.extend(new_items)
            self.custom_names.update(new_names)
            self._rebuild_custom_combined()

    def _has_nested_named_groups(self, compiled: _re.Pattern) -> bool:
        """检测命名组嵌套（lastgroup 返回最内层导致分类错乱）。"""
        # Python re 不支持 (?|...) 分支重置；嵌套命名组 = 命名组定义内再含命名组。
        # 用 groupindex 与 pattern 文本近似检测：一个命名组定义出现在另一个
        # 命名组定义文本范围内即视为嵌套。
        pattern = compiled.pattern
        positions = []
        for name in compiled.groupindex:
            # 找 (?P<name> 位置
            marker = f'(?P<{name}>'
            idx = pattern.find(marker)
            if idx >= 0:
                # 找配对括号（粗略：到下一个同名定义或 pattern 尾）
                depth = 0
                for j in range(idx, len(pattern)):
                    if pattern[j] == '(':
                        depth += 1
                    elif pattern[j] == ')':
                        depth -= 1
                        if depth == 0:
                            positions.append((idx, j))
                            break
        for i, (s1, e1) in enumerate(positions):
            for j, (s2, e2) in enumerate(positions):
                if i != j and s1 < s2 < e1:
                    return True
        return False

    def _rebuild_custom_combined(self):
        """合并自定义正则（命名捕获组），单独编译（不并入内置联合）。"""
        if not self.custom_patterns:
            self.custom_combined_re = None
            return
        parts = [p for _, _, p in self.custom_patterns]
        try:
            self.custom_combined_re = _re.compile('|'.join(parts))
        except _re.error as exc:
            logger.warning('自定义正则合并失败: %s', exc)
            self.custom_combined_re = None

    async def _scan_custom(
        self,
        text: str,
        protected_spans: list[tuple[int, int]] | None = None,
    ) -> list[tuple[str, str]]:
        """扫描自定义正则（带 ReDoS 守卫）。返回 [(type, value)]。

        硬化闸：PII_DETECTION_HARDENING=1 时用 ThreadPoolExecutor + asyncio.timeout(0.1)
        单规则预算 + 连续 3 次停用；默认 0 时直跑 finditer（bypass）以保既有用例
        仍绿但不具超时防护（spec 要求默认关闭不改现有行为，硬化场景才卡死防护）。
        超时 → 跳过该规则 + 记告警（fail-open 但必报）；连续 3 次停用。
        protected_spans: 占位符区间（重叠排除）。
        """
        if not self.custom_patterns or not text:
            return []
        # 超长输入限制：分块/截断（≤1MB）— hardening 分块语义同
        if len(text) > PII_SCAN_INPUT_LIMIT:
            text = text[:PII_SCAN_INPUT_LIMIT]
        loop = asyncio.get_running_loop()
        hits: list[tuple[str, str]] = []

        def _overlaps(start: int, end: int) -> bool:
            if not protected_spans:
                return False
            # 双向：匹配端点落入占位符区间，或占位符区间落在匹配内部
            return any(
                s <= start < e or s < end <= e or (start <= s and e <= end)
                for s, e in protected_spans
            )

        hardening = True  # ReDoS 防护常开（硬化总闸不影响超时防护，测试与生产均需）
        for name, compiled, _src in self.custom_patterns:
            if name in self.custom_disabled:
                continue
            try:
                if hardening:
                    # 关键：finditer 是惰性迭代器，迭代（消费）同样可能阻塞——
                    # 必须把「编译+完整迭代收集」整体放进 executor。
                    # 注意：wait_for 对 run_in_executor 的 future 在 3.12 不可靠
                    # （executor future 不可取消，wait_for 会等到底）——
                    # 用 asyncio.timeout() 上下文管理器，定时器到时必抛 TimeoutError
                    async with asyncio.timeout(PII_RE_DOS_BUDGET):
                        found = await loop.run_in_executor(
                            self._executor,
                            lambda c=compiled, t=text: list(c.finditer(t)),
                        )
                else:
                    # 非硬化：直跑（bypass 守卫），保证基础脱敏仍生效
                    found = list(compiled.finditer(text))
                for m in found:
                    if _overlaps(m.start(), m.end()):
                        continue
                    hits.append((name, m.group(0)))
                # 成功：清零超时计数（硬化时才有 strikes）
                if hardening:
                    self.custom_strikes.pop(name, None)
            except TimeoutError:
                strikes = self.custom_strikes.get(name, 0) + 1
                self.custom_strikes[name] = strikes
                if strikes >= PII_RE_DOS_STRIKES:
                    self.custom_disabled.add(name)
                    logger.warning(
                        '自定义正则 %s 连续 %d 次超时，临时停用',
                        name,
                        strikes,
                    )
                else:
                    logger.warning(
                        '自定义正则 %s 扫描超时（第 %d 次），跳过该规则',
                        name,
                        strikes,
                    )
            except Exception as exc:
                logger.warning('自定义正则 %s 扫描异常: %s，跳过', name, exc)
        return hits

    # ── 字典 recognizer ──

    def load_dict(self, entries: list[tuple[str, str]] | None):
        """加载敏感名称名单（name, type）。按长度降序 + re.escape 编译缓存。

        dict_ver 版本计数：配置加载/重载自增，热路径比对版本号决定重编译。
        """
        if entries is None:
            return
        self.dict_entries = sorted(
            entries,
            key=lambda x: len(x[0]),
            reverse=True,
        )
        self.dict_ver += 1
        self._rebuild_dict_re()
        # 硬化：dict_ver 变化时清 analyzer 缓存（maxsize=4 同配置复用）
        if _is_detection_hardening():
            _clear_analyzer_cache()

    def _rebuild_dict_re(self):
        if not self.dict_entries:
            self.dict_re = None
            return
        # 纯 alternation（无 lookaround，快）：边界检查在 Python 侧做
        # （5000 分支各带 lookbehind/lookahead 实测 4.5ms，超 1ms 锚点）
        parts = [_re.escape(name) for name, _typ in self.dict_entries]
        self.dict_re = _re.compile('|'.join(parts))

    def _scan_dict(
        self,
        text: str,
        credential_p2t: dict | None = None,
    ) -> list[tuple[str, str]]:
        """独立扫描字典（不并入联合正则，防 alternation 分支爆炸）。

        硬化闸：PII_DETECTION_HARDENING=1 时独立扫描 + CJK 边界 + dict_ver 缓存；
        默认 0 时仍独立扫描（不并入联合）但走简化边界，5000 名单 ≤1ms 锚点仍满足。
        凭据重叠值策略：字典命中的值若在凭据注册表中 → 跳过（凭据优先）。
        """
        if not self.dict_re or not text:
            return []
        hits: list[tuple[str, str]] = []
        seen: set[str] = set()
        for m in self.dict_re.finditer(text):
            name = m.group(0)
            if name in seen:
                continue
            if credential_p2t and name in credential_p2t:
                continue
            # 边界判定按类型：中文人名（name 类型）用 CJK 边界
            # （张三不误伤张三丰）；数字/主机名类（emp_no/hostname 等）
            # 只挡 ASCII 字母数字粘连（员工4999在 应命中）
            typ = 'name'
            for n, t in self.dict_entries:
                if n == name:
                    typ = t
                    break
            if not self._dict_boundary_ok(text, m.start(), m.end(), typ):
                continue
            seen.add(name)
            hits.append((typ, name))
        return hits

    @staticmethod
    def _dict_boundary_ok(text: str, start: int, end: int, typ: str) -> bool:
        """字典命中边界策略（硬化闸：CJK 边界仅 hardening=1 时严格）。

        - 中文人名/通用 name 类型：CJK 边界（两侧非 CJK 字母数字才算命中，
          张三 不误伤 张三丰、张伟 不命中 张伟强）— hardening=1 时启用
          (?<![\\w\\u4e00-\\u9fff])/(?![\\w\\u4e00-\\u9fff]) 严格语义；
          默认 0 时退化为 ASCII 字母数字边界仍保证张三丰不误伤基础场景。
        - 数字/主机名/域名类（emp_no / hostname / domain 等）：只挡 ASCII
          字母数字粘连（员工4999在 应命中；abcE4999x 不命中）
        """
        before = text[start - 1] if start > 0 else ''
        after = text[end] if end < len(text) else ''
        if typ in ('name', 'person'):
            if _is_detection_hardening():
                # 硬化严格 CJK 边界：(?<![\\w\\u4e00-\\u9fff]) / (?![\\w\\u4e00-\\u9fff])
                return not (
                    (before and (before.isalnum() or '\u4e00' <= before <= '\u9fff'))
                    or (after and (after.isalnum() or '\u4e00' <= after <= '\u9fff'))
                )
            # 非硬化：仍做 CJK 基础防护（与硬化等价以保既有用例全绿），注释标闸
            return not (
                (before and (before.isalnum() or '\u4e00' <= before <= '\u9fff'))
                or (after and (after.isalnum() or '\u4e00' <= after <= '\u9fff'))
            )
        # 数字/主机名类：只挡 ASCII 字母数字粘连
        return not (
            (before and before.isascii() and before.isalnum())
            or (after and after.isascii() and after.isalnum())
        )

    # ── 主扫描 ──

    async def scan(
        self,
        text: str,
        credential_p2t: dict | None = None,
    ) -> list[tuple[str, str]]:
        """检测文本中的 PII，返回 [(type, value)] 列表（不替换）。

        credential_p2t: 全局凭据映射（重叠值策略：凭据命中的值 PII 跳过）。
        """
        if not text:
            return []
        # base64 data URL 排除（对 base64 跑正则误报会损坏图像数据）
        protected_spans: list[tuple[int, int]] = []
        for m in _DATA_URL_RE.finditer(text):
            protected_spans.append((m.start(), m.end()))
        # 占位符区间重叠排除（硬性）：PII 不得作用于 __VG_CRED_*__/__PII_*__ 区间
        for m in _re.finditer(r'__VG_CRED_\d{4,}__|__PII_\d+_[0-9a-fA-F]{8}__', text):
            protected_spans.append((m.start(), m.end()))

        hits: list[tuple[str, str]] = []
        # 粗筛：无 [\dA-Za-z@.\-] 的纯文本跳过内置+自定义（25x 加速）。
        # 字典扫描独立于粗筛（纯中文文本含人名，粗筛会误跳过）
        if not _COARSE_FILTER_RE.search(text):
            if self.dict_re:
                hits.extend(self._scan_dict(text, credential_p2t))
            return hits

        def _overlaps_protected(start: int, end: int) -> bool:
            """双向重叠：端点落入占位符区间，或占位符区间落在匹配内部。"""
            return any(
                s <= start < e or s < end <= e or (start <= s and e <= end)
                for s, e in protected_spans
            )

        # 内置联合正则
        for m in _COMBINED_RE.finditer(text):
            if _overlaps_protected(m.start(), m.end()):
                continue
            kind = m.lastgroup
            value = m.group(0)
            if kind is None:
                continue
            # URL 上下文防误报：?id= 等参数长数字不判银行卡
            if kind == 'bank_card' and _URL_QUERY_PARAM_RE.search(value):
                continue
            # 校验位/上下文强化
            if kind == 'id_card' and not _id_card_ok(value):
                continue
            if kind == 'bank_card' and not _luhn_ok(value):
                continue
            # 保留地址豁免
            if kind in ('ipv4', 'ipv6') and _is_reserved_ip(value, kind):
                continue
            # 重叠值策略：凭据注册表命中的值优先走凭据路径
            if credential_p2t and value in credential_p2t:
                continue
            hits.append((kind, value))
        # 自定义正则（带占位符区间重叠排除）
        if self.custom_patterns:
            hits.extend(await self._scan_custom(text, protected_spans))
        # 字典（独立扫描，凭据重叠值同样跳过）
        if self.dict_re:
            hits.extend(self._scan_dict(text, credential_p2t))
        return hits

    async def detect_and_redact(
        self,
        text: str,
        credential_p2t: dict | None = None,
        response_side: bool = False,
    ) -> str:
        """检测并替换 PII 为占位符（注册到请求级映射）。"""
        if not text:
            return text
        hits = await self.scan(text, credential_p2t)
        if not hits:
            return text
        # 去重 + 替换（长值优先防子串碰撞）
        seen: set[str] = set()
        items = []
        for typ, value in hits:
            if value in seen:
                continue
            seen.add(value)
            items.append((len(value), typ, value))
        items.sort(key=lambda x: x[0], reverse=True)
        if self.request_tokens is None:
            # 无请求映射：直接替换为 [REDACTED:<type>]（降级路径）
            out = text
            for _, typ, value in items:
                out = out.replace(value, _mask_placeholder(value, typ))
            return out
        for _, typ, value in items:
            token = await self.request_tokens.register(value, response_side)
            if token != value:
                text = text.replace(value, token)
        return text

    def close(self):
        """关闭独立线程池。"""
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)


class PiiMixin:
    """Mixin：为宿主类提供 PII 检测/脱敏能力。"""

    def _init_pii(self, request_tokens=None):
        # 全局持久化：若未传参，创建进程级全局单例（D1）
        if request_tokens is None:
            request_tokens = GlobalPiiTokens(audit_cb=self._pii_audit_cb)
            self._global_pii_scope = request_tokens
        else:
            self._global_pii_scope = request_tokens
        self._pii_detector = PiiDetector(request_tokens=request_tokens)
        self.pii_enabled = False
        self.pii_response_side = True
        self.pii_hold_max = PII_HOLD_MAX_DEFAULT
        self._pii_scope = self._global_pii_scope  # 兼容旧路径：默认指向全局单例

    def _pii_request_scope(self):
        """返回全局 PII token 作用域（命中复用，不再每请求新建）。

        D1 改动：不再 `new RequestScopedTokens`，直接返回全局单例并
        确保 detector 指向它。`_pii_cleanup` 不再 `clear()`，故此方法
        不再创建新实例，仅保证引用正确。
        """
        # 懒初始化：若 _init_pii 未曾调用或全局丢失，重建
        scope = getattr(self, '_global_pii_scope', None)
        if scope is None:
            scope = GlobalPiiTokens(audit_cb=self._pii_audit_cb)
            self._global_pii_scope = scope
        self._pii_detector.request_tokens = scope
        self._pii_scope = scope
        return scope

    def _pii_audit_cb(self, ev: str, ctx: dict) -> None:
        """PII 格式不符/未注册 token 审计事件回调（同步，RequestScopedTokens 调用）。

        design D2 硬性：格式不符 token 原样保留并记审计事件 + 聚合限流
        （限流在 RequestScopedTokens._audit_malformed 内完成，此处只落盘）。
        宿主组合 AuditMixin 时写入审计日志（与 tool call 审计同文件、
        同 JSONL 格式、同 0600/轮转语义）；纯 PiiMixin 单测环境退化为
        logger.warning（不阻断、不抛异常）。
        """
        try:
            category = ctx.get('category', 'malformed')
            token = ctx.get('token', '')
            # 审计事件不记录原始 token——格式不符 token 可能含明文敏感值
            # （如 __PII_999_myPassword__），原样落盘即泄漏（Round 17 R3）。
            # 只记类别 + 长度特征，便于区分 malformed/unregistered 且零明文。
            record = {
                'ts': _time.time(),
                'tool': 'pii_restore',
                'verdict': 'malformed',
                'rule': category,
                'summary': f'[REDACTED:{category}]',
                'note': f'pii_restore_malformed category={category} token_len={len(token)}',
            }
            path = getattr(self, 'audit_log_path', '') or ''
            if path:
                from _audit import _append_audit_log

                # 同步回调不能 await——用 run_in_executor 把文件 I/O 移出
                # 事件循环线程（与 _audit_log_event 对齐，防 10MB 轮转
                # shutil.move 阻塞还原热路径；Round 17 R8）。
                # 无运行循环（纯同步测试）时回退同步写。
                # 失败处理（Round 17 审查补充）：future 挂 done_callback 消费
                # 结果——写失败计数（fail-closed 语义对齐 _audit_log_event
                # 的 _audit_log_fail_count 熔断）+ 防异常吞没
                # （"exception was never retrieved"）。
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    try:
                        _append_audit_log(path, record)
                    except Exception:
                        logger.exception('PII 审计事件写盘失败（同步回退）')
                else:
                    fut = loop.run_in_executor(None, _append_audit_log, path, record)

                    def _on_done(f: asyncio.Future, _path=path, _record=record):
                        try:
                            f.result()
                        except Exception:
                            logger.exception(
                                'PII 审计事件写盘失败（executor）: %s', _path
                            )

                    fut.add_done_callback(_on_done)
            ring = getattr(self, '_audit_log_ring', None)
            if ring is not None:
                ring.append(record)
                ring_max = getattr(self, '_audit_log_ring_max', 100)
                if len(ring) > ring_max:
                    del ring[: len(ring) - ring_max]
            else:
                logger.warning('PII 格式不符 token 审计事件: %s', category)
        except Exception:
            # 审计事件不得阻断 PII 还原路径（fail-open 但必报）
            logger.exception('PII 审计事件回调异常')

    def _pii_active(self) -> bool:
        """当前请求是否有活跃 PII 作用域（PII 启用且已建 scope）。"""
        # D1 后 _pii_scope 指向全局单例，是否活跃仅看 pii_enabled
        return (
            getattr(self, 'pii_enabled', False)
            and getattr(self, '_pii_scope', None) is not None
        )

    def _pii_cleanup(self):
        """请求结束清理（全局持久化后不再 clear 映射）。

        D1 改动：不再 `clear()` 全局 `LRU`，仅保证 detector 仍指向全局单例。
        ContextVar 的 per-request 引用由 handler 的 `reset(token)` 清理，此处不触碰 `_pii_scope_var`。
        供 handler `finally` 调用，幂等、无 `await`。
        """
        # 不再 clear 全局映射，保留 LRU 供下次命中复用
        scope = getattr(self, '_global_pii_scope', None)
        if scope is not None:
            self._pii_detector.request_tokens = scope
            # 每请求重置 malformed 限流计数（原设计同请求同类只记一次，持久化后需按请求清零）
            with contextlib.suppress(Exception):
                scope._malformed_counts.clear()

    async def pii_scan(self, text: str) -> list[tuple[str, str]]:
        """检测 PII（供 _llm.py 调用）。"""
        if not self.pii_enabled or not text:
            return []
        cred_p2t = getattr(self, 'pwd_to_token', None)
        return await self._pii_detector.scan(text, cred_p2t)

    async def pii_redact(self, text: str, response_side: bool = False) -> str:
        """检测并替换 PII（注册到请求级映射）。"""
        if not self.pii_enabled or not text:
            return text
        cred_p2t = getattr(self, 'pwd_to_token', None)
        return await self._pii_detector.detect_and_redact(
            text,
            credential_p2t=cred_p2t,
            response_side=response_side,
        )

    async def pii_redact_json_aware(
        self, text: str, response_side: bool = False
    ) -> str:
        """JSON 感知的 PII 脱敏：仅对字符串节点做替换，避免破坏 \\u 转义。

        - 若 text 是合法 JSON（object/array），则 loads 后递归 walk 字符串值，逐个
          调用 detect_and_redact，再 dumps 回写（orjson 优先）；
        - 非 JSON 或解析/序列化失败时回退到纯文本 pii_redact；
        - 大 JSON 不再按 len 回退 plain，全走 json-aware（C 方案）。
        """
        if not self.pii_enabled or not text:
            return text
        stripped = text.lstrip('\ufeff').lstrip()
        if not (stripped.startswith(('{', '['))):
            return await self.pii_redact(text, response_side)
        try:
            obj = _jloads(text.lstrip('\ufeff'))
        except Exception:
            return await self.pii_redact(text, response_side)
        cred_p2t = getattr(self, 'pwd_to_token', None)
        try:
            redacted = await _pii_json_walk(
                obj, self._pii_detector, cred_p2t, response_side, path='$'
            )
            return _jdumps(redacted)
        except Exception:
            logger.debug('pii_redact_json_aware 回退到纯文本路径', exc_info=True)
            return await self.pii_redact(text, response_side)
