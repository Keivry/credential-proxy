"""PiiMixin — 主动 PII 检测与可逆脱敏。

架构（design D1）：
- 内置强模式合并为单条联合正则（命名捕获组区分类型）
- IPv4/IPv6 保留地址豁免（标准库 ipaddress 判定：is_global/is_private/is_multicast/is_reserved）
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
    from utils.json_walk import (
        PROTECTED_TOKEN_RE as _SHARED_PROTECTED_RE,  # type: ignore
    )
    from utils.json_walk import _jdumps as _shared_jdumps  # type: ignore
    from utils.json_walk import _jloads as _shared_jloads  # type: ignore
    from utils.json_walk import _strip_bom as _shared_strip_bom  # type: ignore
    from utils.json_walk import (
        _validate_json_roundtrip as _shared_validate,  # type: ignore
    )
    from utils.json_walk import json_walk as _shared_json_walk  # type: ignore
    from utils.json_walk import (
        json_walk_async as _shared_json_walk_async,  # type: ignore
    )
except ImportError:
    _SHARED_PROTECTED_RE = None  # type: ignore
    _shared_strip_bom = None  # type: ignore
    _shared_validate = None  # type: ignore
    _shared_json_walk = None  # type: ignore
    _shared_json_walk_async = None  # type: ignore
    _shared_jloads = None  # type: ignore
    _shared_jdumps = None  # type: ignore

_PROTECTED_TOKEN_RE = (
    _SHARED_PROTECTED_RE
    if _SHARED_PROTECTED_RE is not None
    else _re.compile(r'__VG_CRED_\d{4,}__|__PII_\d+_[0-9a-fA-F]{8}__')
)

# ── orjson 加速封装（与 _token 同口径，行为保持 ensure_ascii=False 语义等价）──
try:
    import orjson as _orjson  # type: ignore

    _USE_ORJSON = True
except ImportError:  # pragma: no cover
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


# ── json-aware 后置校验（deprecated：保留作 utils 缺失兜底，正本见 utils.json_walk）──
def _pii_validate_json_roundtrip(original: str, output: str, label: str) -> str:
    if _shared_validate is not None:  # type: ignore[truthy-function]
        return _shared_validate(original, output, label)  # type: ignore
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


# ── 常量 ──
PII_HOLD_MAX_DEFAULT = 64
PII_RE_DOS_BUDGET = 0.1  # 自定义正则单规则超时预算 100ms
PII_RE_DOS_MAX_WORKERS = 2  # 独立线程池（与日志写 run_in_executor 不同池）
PII_RE_DOS_STRIKES = 3  # 连续超时 3 次临时停用
PII_SCAN_INPUT_LIMIT = 1_048_576  # 单次扫描输入上限 1MB

# ── 自定义规则文件加载（pii-custom）────────────────────
# 零依赖：JSON 优先，YAML 走 _audit._parse_simple_yaml（存在则复用，缺失则回退极简解析）


def _load_pii_raw_file(path: str) -> tuple[object, str | None]:
    """读取 YAML/JSON 原始数据，返回 (data, error)。"""
    # 防误配 DoS：文件大小上限（与 PII_SCAN_INPUT_LIMIT 同级 1MB），超限拒绝
    try:
        st = os.stat(path)
        if st.st_size > 1_048_576:
            return None, f'文件过大（{st.st_size} 字节 > 1MB 上限），拒绝加载'
    except OSError as e:
        return None, f'stat 失败: {e}'
    try:
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()
    except Exception as e:
        return None, f'读取失败: {e}'
    stripped = text.lstrip()
    if not stripped:
        return None, '文件为空'
    # JSON 直判
    if stripped.startswith('{') or stripped.startswith('['):
        try:
            return _json.loads(text), None
        except Exception as e:
            return None, f'JSON 解析失败: {e}'
    # YAML：优先复用 _audit 的极简解析（零依赖）
    try:
        from _audit import _parse_simple_yaml as _audit_yaml  # type: ignore

        return _audit_yaml(text), None
    except Exception:
        pass
    # 回退：尝试 JSON 兼容的宽松解析（单引号转双引号等不处理，直接报错提示用 JSON）
    return (
        None,
        'YAML 解析失败（请用 JSON 或 audit-policy 同款极简 YAML：顶层 key + "- key: value" 列表）',
    )


def _extract_patterns_from_data(data: object) -> list[tuple[str, str]]:
    """从解析后的数据中提取 [(name, pattern)]。"""
    if data is None:
        return []
    # list 形态：直接是 patterns 列表
    if isinstance(data, list):
        out: list[tuple[str, str]] = []
        for item in data:
            if isinstance(item, dict):
                name = (
                    item.get('name')
                    or item.get('type')
                    or item.get('kind')
                    or item.get('id')
                )
                pat = (
                    item.get('pattern')
                    or item.get('regex')
                    or item.get('re')
                    or item.get('value')
                )
                if name and pat:
                    out.append((str(name), str(pat)))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                out.append((str(item[0]), str(item[1])))
        return out
    if isinstance(data, dict):
        # 已知 patterns 键
        for k in (
            'patterns',
            'custom_patterns',
            'customPatterns',
            'pii_patterns',
            'rules',
            'custom_rules',
        ):
            if k in data:
                v = data[k]
                if isinstance(v, list):
                    return _extract_patterns_from_data(v)
                if isinstance(v, dict):
                    # {"patterns": {"emp_no": "(?P<emp_no>..."}}
                    return [
                        (str(k2), str(v2))
                        for k2, v2 in v.items()
                        if isinstance(v2, str)
                    ]
        # 扁平 name->pattern 映射（排除 names/dict 干扰）
        if (
            data
            and all(isinstance(v, str) for v in data.values())
            and not any(
                k in data
                for k in (
                    'names',
                    'sensitive_names',
                    'sensitiveNames',
                    'dict',
                    'entries',
                    'words',
                )
            )
        ):
            # 启发：pattern 值含正则特征 (?P< 或包含 \d 等，dict 映射值通常不含
            # 但为稳妥，仅当调用方明确要 patterns 时才按映射处理；此处放宽，返回映射
            # 由调用方决定是否为 patterns 场景
            return [(str(k), str(v)) for k, v in data.items()]
    return []


def _extract_dict_from_data(data: object) -> list[tuple[str, str]]:
    """从解析后的数据中提取 [(name, type)]。"""
    if data is None:
        return []
    if isinstance(data, list):
        out: list[tuple[str, str]] = []
        for item in data:
            if isinstance(item, str):
                if item.strip():
                    out.append((item.strip(), 'name'))
            elif isinstance(item, dict):
                name = (
                    item.get('name')
                    or item.get('value')
                    or item.get('word')
                    or item.get('key')
                )
                typ = (
                    item.get('type')
                    or item.get('kind')
                    or item.get('category')
                    or 'name'
                )
                if name:
                    out.append((str(name).strip(), str(typ).strip() or 'name'))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                out.append((str(item[0]).strip(), str(item[1]).strip() or 'name'))
        return out
    if isinstance(data, dict):
        for k in (
            'names',
            'sensitive_names',
            'sensitiveNames',
            'dict',
            'entries',
            'dictionary',
            'words',
            'custom_dict',
            'sensitive_dict',
            'people',
            'personnel',
        ):
            if k in data:
                v = data[k]
                if isinstance(v, list):
                    return _extract_dict_from_data(v)
                if isinstance(v, dict):
                    return [
                        (str(k2), str(v2) if isinstance(v2, str) else 'name')
                        for k2, v2 in v.items()
                    ]
        # 扁平 name->type 映射
        if (
            data
            and all(isinstance(v, str) for v in data.values())
            and not any(k in data for k in ('patterns', 'custom_patterns', 'rules'))
        ):
            return [
                (str(k).strip(), str(v).strip() or 'name')
                for k, v in data.items()
                if str(k).strip()
            ]
    return []


# ── 占位符说明提示词（pii-placeholder-prompt）──
# 注入给上游 LLM 的默认说明文案：告知 __PII_*__ / __VG_CRED_*__ 是脱敏占位符。
# 安全不变量（design D5）：
#   - 静态文本，不含真实 PII 值、不含占位符序号
#   - 用 `*` 通配形态描述（非合法 hex8/数字），不命中 PII/凭据真实形态
#     （__PII_<seq>_<hex8>__ / __VG_CRED_<digits>__），不被检测引擎误伤
#   - 明确「不要校验格式」覆盖 IP 192.168.1.100 → __PII_...__ 被改写成 0.0.0.0 的格式敏感风险
#   - 明确「不要推断或补全」防模型幻觉补全占位符内容
#   - 点名 tool_calls/function 参数（工具参数 JSON Schema 校验比 content 更严格）
#   - 🔴 关键语义（2026-08-30 用户反馈）：占位符 = 原文已被替换，LLM 无法直接看到原文；
#     不要假设工具输出/文件内容里看到占位符是"原文就是占位符"，不要拿占位符当真实数据样例
PII_PLACEHOLDER_PROMPT_DEFAULT = (
    '说明：消息中形如 __PII_*__ 和 __VG_CRED_*__ 的标记是安全网关的敏感信息脱敏占位符，'
    '代表被替换的原始值（如手机号、IP 地址、银行卡号、密钥等）。'
    '重要：这些占位符出现的位置，其原始内容已被安全网关替换，你无法直接看到原文；'
    '因此不要把占位符当作真实数据（不要用它做样例、比对、推断原文，也不要假设原文就是占位符形态）。'
    '请原样保留这些占位符（包括 content 与 tool calls/function 参数中的）：'
    '不要修改格式、不要校验其合法性、不要推断或补全内容，也不要视为输入错误。'
    '它们不是格式问题，直接使用即可。若你需要查看被替换的原文进行分析，'
    '请改用不经由此网关的通道（如直接在受信任环境执行命令），不要尝试从占位符本身还原。'
)
PII_PLACEHOLDER_PROMPT_MAX_LEN = 4096  # 自定义文案长度上限 4KB（超限截断并告警）
# 合法形态占位符：自定义文案含此形态时回退内置（防说明文本被脱敏/还原链误匹配）
_PII_PLACEHOLDER_FORBIDDEN_RE = _re.compile(
    r'__PII_\d+_[0-9a-fA-F]{8}__|__VG_CRED_\d+__'
)


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
    obj,
    detector,
    credential_p2t,
    response_side,
    path: str = '$',
    _depth: int = 0,
    tail: str | None = None,
):
    """递归遍历 JSON 结构，仅对字符串节点做 PII 脱敏，叶子级最小回退。

    若叶字符串本身为 JSON 文本（lstrip BOM 后 strip 再判 { / [ 且可解析为
    dict/list），则对内层同走 walk→detect→dumps，失败回退 plain。
    叶子级：仅当 detect 后值变化时做 _jdumps 校验，失败仅回退该叶子。
    """
    if _shared_json_walk_async is not None:  # type: ignore[truthy-function]

        async def _leaf(s: str):  # type: ignore[no-redef]
            return await detector.detect_and_redact(
                s, credential_p2t, response_side, tail=tail
            )

        return await _shared_json_walk_async(
            obj, _leaf, depth_limit=5, path=path, _depth=_depth
        )  # type: ignore
    if _depth > 5:
        if isinstance(obj, str):
            new_s = await detector.detect_and_redact(
                obj, credential_p2t, response_side, tail=tail
            )
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
        inner_stripped = _strip_bom(obj).strip()
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
                        tail,
                    )
                    return _jdumps(walked)
            except Exception:
                pass
        new_s = await detector.detect_and_redact(
            obj, credential_p2t, response_side, tail=tail
        )
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
                v, detector, credential_p2t, response_side, f'{path}.{k}', _depth, tail
            )
        return out
    if isinstance(obj, list):
        return [
            await _pii_json_walk(
                x, detector, credential_p2t, response_side, f'{path}[{i}]', _depth, tail
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
    - PII_HOLD_MAX（审计 hold 尾部持有上限，默认 64，取值 ≥1 正整数；
      流式正文行缓冲由 LINE_BUF_FLUSH=16KB / LINE_BUF_MAX_AGE=30s 控制）
    - PII_FUZZY_RESTORE（0/1，默认 0）
    - PII_DETECTION_HARDENING（0/1，默认 0，硬化特性总闸）
    - PII_VALUE_SAMPLE_ENABLED（0/1，默认 0，1 时启用值级掩码采样）
    - PII_VALUE_SAMPLE_PERSIST（0/1，默认 0，1 时持久化采样且隐含 ENABLED=1）

    返回: {'enabled', 'response_side', 'hold_max', 'fuzzy_restore',
           'detection_hardening', 'pii_value_sample_enabled',
           'pii_value_sample_persist', 'errors': [str]}
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

    # PII_PLACEHOLDER_PROMPT: 占位符说明注入开关（默认 1 启用，0/false/no 关闭）
    _pp_raw = os.environ.get('PII_PLACEHOLDER_PROMPT', '').strip().lower()
    placeholder_prompt_enabled = _pp_raw not in ('0', 'false', 'no')
    # PII_PLACEHOLDER_PROMPT_TEXT: 自定义文案（未设置/空/全空白 → 内置默认文案）
    # 开关关闭时（spec R3/design D4）：SHALL NOT 解析/校验/告警，零副作用短路
    placeholder_prompt_text = ''
    if placeholder_prompt_enabled:
        raw_text = os.environ.get('PII_PLACEHOLDER_PROMPT_TEXT', '')
        if raw_text and raw_text.strip():
            # 先校验禁词再截断（防超长文案中 4096 之后的合法占位符形态被截掉逃逸）
            if _PII_PLACEHOLDER_FORBIDDEN_RE.search(raw_text):
                # 含合法形态占位符：回退内置文案（防说明文本被脱敏/还原链误匹配）
                logger.warning(
                    'PII_PLACEHOLDER_PROMPT_TEXT 含合法形态占位符，回退内置默认文案'
                )
            else:
                if len(raw_text) > PII_PLACEHOLDER_PROMPT_MAX_LEN:
                    logger.warning(
                        'PII_PLACEHOLDER_PROMPT_TEXT 超长(%d>%d)，截断到上限',
                        len(raw_text),
                        PII_PLACEHOLDER_PROMPT_MAX_LEN,
                    )
                    raw_text = raw_text[:PII_PLACEHOLDER_PROMPT_MAX_LEN]
                placeholder_prompt_text = raw_text

    # PII 值级掩码采样开关（dashboard-pii-value-details 1.1）：0/1 校验，默认 0，
    # PERSIST=1 隐含 ENABLED=1，非法值记 errors 并告警回退 0
    pii_value_sample_enabled = False
    pii_value_sample_persist = False
    raw_vs_enabled = os.environ.get('PII_VALUE_SAMPLE_ENABLED', '0')
    raw_vs_persist = os.environ.get('PII_VALUE_SAMPLE_PERSIST', '0')
    vs_enabled_valid = raw_vs_enabled in ('0', '1')
    vs_persist_valid = raw_vs_persist in ('0', '1')
    if not vs_enabled_valid:
        errors.append(f'PII_VALUE_SAMPLE_ENABLED 非法值(仅 0/1): {raw_vs_enabled!r}')
        logger.warning(
            'PII_VALUE_SAMPLE_ENABLED 非法值(仅 0/1): %r, 回退 0', raw_vs_enabled
        )
    if not vs_persist_valid:
        errors.append(f'PII_VALUE_SAMPLE_PERSIST 非法值(仅 0/1): {raw_vs_persist!r}')
        logger.warning(
            'PII_VALUE_SAMPLE_PERSIST 非法值(仅 0/1): %r, 回退 0', raw_vs_persist
        )
    vs_enabled = (raw_vs_enabled == '1') if vs_enabled_valid else False
    vs_persist = (raw_vs_persist == '1') if vs_persist_valid else False
    if vs_persist:
        vs_enabled = True
    pii_value_sample_enabled = vs_enabled
    pii_value_sample_persist = vs_persist

    # ── 自定义规则文件（pii-custom，新增）────────────────
    # 支持：
    #   PII_CUSTOM_RULES_FILE         — 合并文件（含 patterns + names，两者任一）
    #   PII_CUSTOM_PATTERNS_FILE      — 仅自定义正则（别名 PII_CUSTOM_PATTERN_FILE）
    #   PII_DICT_FILE / PII_SENSITIVE_DICT_FILE / PII_SENSITIVE_NAMES_FILE — 仅字典名单
    # 格式：JSON（{}/[] 开头）或极简 YAML（audit-policy 同款解析：顶层 key + "- name: ... / pattern: ..." 列表）
    # 校验：文件不存在 / 解析失败 → 记 errors（启动拒绝，fail-closed）；空文件 / 零命中仅 warning
    custom_patterns: list[tuple[str, str]] = []
    dict_entries: list[tuple[str, str]] = []
    raw_combined = (
        os.environ.get('PII_CUSTOM_RULES_FILE')
        or os.environ.get('PII_RULES_FILE')
        or ''
    ).strip()
    raw_pat = (
        os.environ.get('PII_CUSTOM_PATTERNS_FILE')
        or os.environ.get('PII_CUSTOM_PATTERN_FILE')
        or ''
    ).strip()
    raw_dict = (
        os.environ.get('PII_DICT_FILE')
        or os.environ.get('PII_SENSITIVE_DICT_FILE')
        or os.environ.get('PII_SENSITIVE_NAMES_FILE')
        or ''
    ).strip()

    def _load_patterns_file(p: str, label: str):
        if not p:
            return
        if not os.path.exists(p):
            errors.append(f'{label} 文件不存在: {p!r}')
            return
        data, err = _load_pii_raw_file(p)
        if err:
            errors.append(f'{label} 解析失败 {p!r}: {err}')
            return
        pats = _extract_patterns_from_data(data)
        # 合并文件场景：若按 patterns 键提不到，尝试从顶层 dict 的 patterns 嵌套里已在上面处理
        # 扁平映射场景已在 extractor 内处理；零命中仅 warning
        if not pats:
            logger.warning(
                '%s %r 未解析到有效 patterns（需 patterns: [{name, pattern}]）',
                label,
                p,
            )
            return
        custom_patterns.extend(pats)
        logger.info('%s 已加载 %d 条自定义正则: %s', label, len(pats), p)

    def _load_dict_file(p: str, label: str):
        if not p:
            return
        if not os.path.exists(p):
            errors.append(f'{label} 文件不存在: {p!r}')
            return
        # 纯文本回退：若 YAML/JSON 解析零命中，尝试按行读取（每行一名单）
        data, err = _load_pii_raw_file(p)
        if err:
            # 尝试按行回退（txt 名单）
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    lines = [
                        ln.strip()
                        for ln in f
                        if ln.strip() and not ln.strip().startswith('#')
                    ]
                if lines:
                    dict_entries.extend([(ln, 'name') for ln in lines])
                    logger.info('%s 已加载 %d 条字典（按行）: %s', label, len(lines), p)
                    return
            except Exception:
                pass
            errors.append(f'{label} 解析失败 {p!r}: {err}')
            return
        ents = _extract_dict_from_data(data)
        if not ents:
            # 按行回退
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    lines = [
                        ln.strip()
                        for ln in f
                        if ln.strip() and not ln.strip().startswith('#')
                    ]
                if lines:
                    ents = [(ln, 'name') for ln in lines]
                else:
                    logger.warning(
                        '%s %r 未解析到有效 names（需 names: [{name, type}] 或每行一名）',
                        label,
                        p,
                    )
                    return
            except Exception as e2:
                errors.append(f'{label} 字典解析失败 {p!r}: {e2}')
                return
        dict_entries.extend(ents)
        logger.info('%s 已加载 %d 条字典: %s', label, len(ents), p)

    # 合并文件优先：同时提取 patterns + names（互不覆盖，叠加）
    if raw_combined:
        if not os.path.exists(raw_combined):
            errors.append(f'PII_CUSTOM_RULES_FILE 文件不存在: {raw_combined!r}')
        else:
            data, err = _load_pii_raw_file(raw_combined)
            if err:
                errors.append(f'PII_CUSTOM_RULES_FILE 解析失败 {raw_combined!r}: {err}')
            else:
                c_pats = _extract_patterns_from_data(data)
                c_ents = _extract_dict_from_data(data)
                if not c_pats and not c_ents:
                    logger.warning(
                        'PII_CUSTOM_RULES_FILE %r 未解析到 patterns/names', raw_combined
                    )
                if c_pats:
                    custom_patterns.extend(c_pats)
                    logger.info(
                        'PII_CUSTOM_RULES_FILE 已加载 %d 条自定义正则: %s',
                        len(c_pats),
                        raw_combined,
                    )
                if c_ents:
                    dict_entries.extend(c_ents)
                    logger.info(
                        'PII_CUSTOM_RULES_FILE 已加载 %d 条字典: %s',
                        len(c_ents),
                        raw_combined,
                    )

    _load_patterns_file(raw_pat, 'PII_CUSTOM_PATTERNS_FILE')
    _load_dict_file(raw_dict, 'PII_DICT_FILE')

    return {
        'enabled': enabled,
        'response_side': response_side,
        'hold_max': hold_max,
        'fuzzy_restore': fuzzy_restore,
        'detection_hardening': detection_hardening,
        'placeholder_prompt_enabled': placeholder_prompt_enabled,
        'placeholder_prompt_text': placeholder_prompt_text,
        'pii_value_sample_enabled': pii_value_sample_enabled,
        'pii_value_sample_persist': pii_value_sample_persist,
        'custom_patterns': custom_patterns,
        'dict_entries': dict_entries,
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
    # 手机号（前缀段验证 13x-19x，兼容 +86 国际冠码）
    (
        'phone',
        r'(?P<phone>(?<![\d])(?:\+?86[\- ]?)?1[3-9]\d{9}(?!\d))',
    ),
    # 身份证（18 位，校验位验证由回调完成）
    (
        'id_card',
        r'(?P<id_card>(?<![\d])\d{17}[\dXx](?!\d))',
    ),
    # 银行卡（13-19 位，Luhn 校验由回调完成；防 URL 参数误报，长度按 BIN 分支精确：62/60/34/37→13-19，4/5→13-19）
    (
        'bank_card',
        r'(?P<bank_card>(?<![\d])(?:(?:62|60|3[47])\d{11,17}|[45]\d{12,18})(?!\d))',
    ),
    # IPv4（保留段豁免由回调完成；前瞻仅禁数字不禁止尾随句号，句末句号场景
    # 由二次校验 rstrip 处理——与 IPv6 core 剥离对称，防 `Visit 1.2.3.4.` 漏脱敏）
    (
        'ipv4',
        r'(?P<ipv4>(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d]))',
    ),
    # IPv6（正则粗筛 + 标准库精确校验）
    # 粗筛：含至少 2 个冒号的十六进制/冒号/点串，边界用负向环视防粘连；
    # 精确校验走 ipaddress.ip_address (version==6) 二次判定，明显非 IPv6 的串不再误脱敏。
    (
        'ipv6',
        r'(?P<ipv6>(?<![0-9A-Za-z:.])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*)(?![0-9A-Za-z:.])',
    ),
    # API key（sk- / sk-proj- / sk-ant- / ghp_ / gho_ / AKIA 前缀 + 最小 16 字符）
    (
        'api_key',
        (
            r'(?P<api_key>(?<![0-9A-Za-z-])(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|'
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
    for _name in (
        '_is_reserved_ip',
        '_is_valid_ipv4',
        '_is_valid_ipv6',
        '_luhn_ok',
        '_id_card_ok',
    ):
        try:
            _fn = globals().get(_name)  # type: ignore[assignment]
            if _fn is not None and hasattr(_fn, 'cache_clear'):
                _fn.cache_clear()  # type: ignore[attr-defined]
        except Exception:
            pass


# ── 保留地址豁免（标准库 ipaddress 判定，替代前缀表）──
# 仅公网全局可路由地址视为 PII（需脱敏），其余均豁免。标准库已含 IANA 全表，
# 无需硬编码前缀，Python 升级自动跟进（198.18/15、192.0.0.0/24、64:ff9b::/96 等）。
@lru_cache(maxsize=4096)
def _is_reserved_ip(value: str, kind: str) -> bool:
    """判定 IP 是否保留/私有段（标准库）。

    Returns True  豁免（不脱敏）：私有/保留/回环/链路本地/组播/CGNAT/文档/未指定等
            False 公网（需脱敏）：全局可路由地址

    判定： not is_global → 私有/保留/CGNAT 100.64/10/document 等（is_private+is_global 已含 IANA 全表）
           is_multicast/is_reserved/is_unspecified/is_site_local → 组播/保留/NAT64/未指定等
           仍 is_global=True 的特殊段（Python 3.13 实测：224.0.0.1、ff02::1、64:ff9b::1 均为 global=True）
    性能：单次 ip_address 解析 ~5-15µs，lru_cache 命中 ~0.3µs，scan 链路每 IP 一次可忽略。
    兼容：value 可能含句末标点（scan/_metrics 双路径均先 rstrip 剥离），此处统一防御剥离。
    前导零：ipv4 分支先归一化（_normalize_ipv4_leading_zeros），与 _is_valid_ipv4 保持一致。
    """
    try:
        # IPv6 需剥句末标点并 lower（与 scan 侧 core=rstrip 逻辑一致，防 2001:db8::1. 误判）
        v = value.rstrip('.,;)]}') if kind == 'ipv6' else value
        if kind == 'ipv6':
            v = v.lower()
            if not v:
                return False
        elif kind == 'ipv4':
            # 前导零兼容：ipaddress 严格拒绝前导零（ValueError→False→误判公网），
            # 与 _is_valid_ipv4 同归一化，避免前导零私有/保留段被过度脱敏
            v = _normalize_ipv4_leading_zeros(v)
        ip = _ipaddress.ip_address(v)
    except ValueError:
        # 非法格式（如 999.999.999.999）不视为保留，避免误豁免；上层正则已控，此处防御
        return False
    # 非全局即保留（已含 0.0.0.0/8, 10/8, 172.16/12, 192.168/16, 100.64/10, 192.0.2/24,
    # 198.51.100/24, fe80::/10, fc00::/7, 2001:db8::/32, ::1 等）
    if not ip.is_global:
        return True
    # 标准库中以下类型仍 is_global=True，需显式豁免
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    if getattr(ip, 'is_site_local', False):
        return True
    # 兜底：loopback/link_local/private 已被 not is_global 覆盖，此处仅防御性补充
    return ip.is_loopback or ip.is_link_local or ip.is_private


# 兼容别名：旧前缀常量已由标准库替代，保留空元组防外部导入报错
_RESERVED_IPV4_PREFIXES: tuple = ()  # deprecated: 由 ipaddress 替代
_RESERVED_IPV6_PREFIXES: tuple = ()  # deprecated
_RESERVED_NETWORKS: list = []  # deprecated
_RESERVED_IPV6_NETWORKS: list = []  # deprecated


@lru_cache(maxsize=4096)
def _is_valid_ipv4(value: str) -> bool:
    """正则粗筛后的标准库精确校验：仅合法 IPv4 视为命中（0-255 逐段）。

    粗筛正则仅保证 `\\d{1,3}.` 重复，`__PII_26_1336ed19__` 等非法段会误命中；
    此处用 ipaddress 精确判定，version==4 才视为 IPv4。带 lru_cache 复用。

    前导零兼容：`192.168.001.001` 是合法且常见的 IPv4 表示法（旧前缀表时代即脱敏），
    而 ipaddress.ip_address 严格拒绝前导零（ValueError）；此处先归一化前导零
    （192.168.001.001 -> 192.168.1.1）再判定，保持旧版脱敏行为。
    注意：`value` 仅用于判定，scan 的 hits/replace 始终使用原始文本。
    """

    try:
        _v = _normalize_ipv4_leading_zeros(value)
        return _ipaddress.ip_address(_v).version == 4
    except ValueError:
        return False


def _normalize_ipv4_leading_zeros(value: str) -> str:
    """归一化 IPv4 前导零：192.168.001.001 -> 192.168.1.1（ipaddress 严格拒绝前导零）。"""
    parts = value.split('.')
    if len(parts) != 4:
        return value
    try:
        return '.'.join(str(int(p)) for p in parts)
    except ValueError:
        return value


@lru_cache(maxsize=4096)
def _is_valid_ipv6(value: str) -> bool:
    """正则粗筛后的标准库精确校验：仅合法 IPv6 视为命中。

    粗筛正则仅保证含至少 2 个冒号的十六进制/冒号/点串，边界已做负向环视；
    此处用标准库 ipaddress.ip_address 做精确判定，version==6 才视为 IPv6。
    显式拒绝 IPv4（version==4）及非法格式，避免明显非 IPv6 的串被误脱敏。
    """
    try:
        return _ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


@lru_cache(maxsize=4096)
def _luhn_ok(digits: str) -> bool:
    """Luhn 校验（银行卡）。带 lru_cache 复用，重复卡号命中 ~0.1µs。"""
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


@lru_cache(maxsize=4096)
def _id_card_ok(value: str) -> bool:
    """大陆身份证校验位验证（GB 11643-1999）。带 lru_cache 复用。"""
    if len(value) != 18:
        return False
    if not value[:17].isdigit():
        return False
    total = sum(int(value[i]) * _ID_WEIGHTS[i] for i in range(17))
    return value[17].upper() == _ID_CHECKS[total % 11]


def _mask_placeholder(value: str, kind: str) -> str:
    try:
        from _metrics import redacted_tag as _tag  # type: ignore

        return _tag(kind)
    except Exception:
        return f'[REDACTED:{kind}]'


# ── pii value sample: mask & enable guard (dashboard-pii-value-details) ──
def _is_pii_value_sample_enabled() -> bool:
    """值级采样开关：PII_VALUE_SAMPLE_ENABLED=1 或 PERSIST=1 时启用（热读，统一 _metrics 校验与告警）。"""
    try:
        from _metrics import _is_pii_value_sample_enabled as _enabled  # type: ignore

        return bool(_enabled())
    except Exception:
        return (
            os.environ.get('PII_VALUE_SAMPLE_ENABLED') == '1'
            or os.environ.get('PII_VALUE_SAMPLE_PERSIST') == '1'
        )


def _pii_value_hash(value: str) -> str:
    """PII 明文 hash（16 hex，64bit）— 防 1万匿名集枚举。

    优先 HMAC-SHA256(SALT, value)[:16]（SALT 来自 PII_VALUE_SAMPLE_HMAC_KEY 环境变量，
    若未设则退化为 SHA256(value)[:16] 并文档声明小空间可枚举风险；SALT 仅服务端持有，
    HMAC 使离线枚举需先获 SALT）。兼容存量无盐 hash 的去重语义（同值同 hash 仍合并，
    不同值同掩码已按 masked 合并，hash 首写 wins）。
    """

    try:
        _salt = os.environ.get('PII_VALUE_SAMPLE_HMAC_KEY', '').strip()
        if _salt:
            import hashlib as _hl
            import hmac as _hmac

            return _hmac.new(
                _salt.encode('utf-8'), value.encode('utf-8'), _hl.sha256
            ).hexdigest()[:16]
    except Exception as _e:
        logger.warning('pii_value_hash HMAC 失败降级 sha256: %s', _e)
    import hashlib as _hl2

    return _hl2.sha256(value.encode('utf-8')).hexdigest()[:16]


def mask_pii_value(kind: str, value: str) -> str:
    """按 kind 掩码明文值（不含 hash，仅 masked_sample）。

    真实值形态：
    - phone: 138****8000 (first3****last4，len>=7)
    - email: ***@***.com (不透 local/domain 首字符；suffix 保留，防 a***@b.com 侧信道)
    - bank_card: **** **** **** 6789 (仅后4，BIN不保留)
    - ipv4: 192.168.**.** (非4段时按长度规则)
    - ipv6/api_key: len>=8 时前4****后4；len 6-7 时前3****后3
    - other: 前3****后3 且 <6 时 前1****后1
    - empty -> ***
    - masked 长度上限 64，超长截断

    占位符形态输入（如 __PII_82_8f6a798b__）同样按长度规则掩码
    （如 phone 占位符 len=18 → __P****8b__），不还原为真实值形态。
    """
    if not value:
        return '***'
    k = (kind or '').lower()
    v = value
    if k == 'phone':
        if len(v) >= 7:
            masked = f'{v[:3]}****{v[-4:]}'
        else:
            if len(v) < 6:
                masked = f'{v[0]}****{v[-1]}' if len(v) >= 2 else '***'
            else:
                masked = f'{v[:3]}****{v[-3:]}'
    elif k == 'email':
        if '@' not in v:
            if len(v) < 6:
                masked = f'{v[0]}****{v[-1]}' if len(v) >= 2 else '***'
            else:
                masked = f'{v[:3]}****{v[-3:]}'
        else:
            _, domain = v.split('@', 1)
            # 不透 local/domain 首字符：统一 ***@***.suffix（防 a***@b.com 侧信道，见 design D1）
            if '.' in domain:
                suffix = domain.rsplit('.', 1)[-1]
                masked = f'***@***.{suffix}' if suffix else '***@***'
            else:
                masked = '***@***'
    elif k == 'bank_card':
        if len(v) >= 4:
            masked = f'**** **** **** {v[-4:]}'
        else:
            masked = f'{v[0]}****{v[-1]}' if len(v) >= 2 else '***'
    elif k == 'ipv4':
        parts = v.split('.')
        if len(parts) == 4:
            masked = f'{parts[0]}.{parts[1]}.**.**'
        else:
            if len(v) >= 8:
                masked = f'{v[:4]}****{v[-4:]}'
            else:
                masked = f'{v[0]}****{v[-1]}' if len(v) >= 2 else '***'
    elif k in ('ipv6', 'api_key'):
        if len(v) < 6:
            masked = f'{v[0]}****{v[-1]}' if len(v) >= 2 else '***'
        else:
            if len(v) >= 8:
                masked = f'{v[:4]}****{v[-4:]}'
            else:
                masked = f'{v[:3]}****{v[-3:]}'
    else:
        if len(v) < 6:
            if len(v) == 0 or len(v) == 1:
                masked = '***'
            else:
                masked = f'{v[0]}****{v[-1]}'
        else:
            masked = f'{v[:3]}****{v[-3:]}'
    if len(masked) > 64:
        masked = masked[:64]
    return masked


def _custom_literal_run(src: str, min_len: int = 2) -> str:
    """提取自定义正则字面前缀 run（best-effort，永不抛）。

    跳过 `(?P<name>` 样板后收集连续字面字符（字母/数字/CJK/`-_./` 等），
    遇正则元字符即停：`工号\\d{6}`→`工号`，`PRJ-[A-Z]{2}`→`PRJ-`；
    纯 lookaround 开头（如 `(?<![0-9…`）返回 ''（无字面头，调用方按未命中计）。
    """
    try:
        if not isinstance(src, str) or not src:
            return ''
        text = src
        m = _re.search(r'\(\?P<[^>]+>', text)
        if m:
            text = text[m.end() :]
        else:
            text = _re.sub(r'^(?:\(\?[a-zA-Z-]*\)|\^)+', '', text)
        run: list[str] = []
        for ch in text:
            if ch in '\\[()?*+{|^$.' or ch == ')':
                break
            run.append(ch)
            if len(run) >= 32:
                break
        out = ''.join(run)
        return out if len(out) >= min_len else ''
    except Exception:
        return ''


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
        # G-6：进程退出时回收线程池（否则非 daemon 线程阻塞退出/泄漏）
        import atexit as _atexit

        _atexit.register(self._executor.shutdown, wait=False, cancel_futures=True)
        # 字典 recognizer
        self.dict_entries: list[tuple[str, str]] = []  # (name, type)
        self.dict_ver = 0
        self.dict_re = None  # 编译缓存（版本比对决定重编译）
        # 可观测性采集器引用（llm-observability-dashboard）
        self._collector = None

    def set_collector(self, collector) -> None:
        """注入 MetricsCollector（pii_detected_total 计数钩子）。"""
        self._collector = collector

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
            if name in self.custom_names:
                logger.warning('自定义正则 %s 与已加载规则重名，拒绝加载', name)
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

    def partial_prefix_hints(self, tail: str | None = None) -> list[str]:
        """自定义规则 best-effort 前缀提示（D5/3.1 流式持有等待用）。

        来源：已加载自定义正则的字面 run + 字典名单全名，合计 cap64 去重。
        `tail` 给出时仅返回与尾部窗口命中的子集；未命中返回 []（调用方透传
        并计 custom_other，不阻塞主链）。永不抛异常（异常→返回 []）。
        """
        try:
            hints: list[str] = []
            seen: set[str] = set()

            def _add(_h: str) -> None:
                if not isinstance(_h, str) or not _h or len(hints) >= 64:
                    return
                _h = _h[:64]
                if _h and _h not in seen:
                    seen.add(_h)
                    hints.append(_h)

            for _name, _compiled, _src in self.custom_patterns or []:
                try:
                    if isinstance(_src, str):
                        _run = _custom_literal_run(_src)
                        if _run:
                            _add(_run)
                except Exception:
                    logger.debug('partial_prefix_hints 正则提示跳过', exc_info=True)
                    continue
            for _nm, _typ in self.dict_entries or []:
                try:
                    if isinstance(_nm, str) and _nm:
                        _add(_nm)
                except Exception:
                    logger.debug('partial_prefix_hints 名单提示跳过', exc_info=True)
                    continue
            if tail is None:
                return hints
            if not isinstance(tail, str) or not tail:
                return []
            window = tail[-64:] if len(tail) > 64 else tail
            matched: list[str] = []
            for _h in hints:
                try:
                    if _h in window:
                        matched.append(_h)
                        continue
                    _n = min(len(_h), len(window))
                    for _k in range(_n, 0, -1):
                        if window.endswith(_h[:_k]):
                            matched.append(_h)
                            break
                except Exception:
                    logger.debug('partial_prefix_hints 尾部匹配跳过', exc_info=True)
                    continue
            return matched
        except Exception:
            return []

    async def _scan_custom(
        self,
        text: str,
        protected_spans: list[tuple[int, int]] | None = None,
        cred_spans: list[tuple[int, int]] | None = None,
    ) -> list[tuple[str, str, int, int]]:
        """扫描自定义正则（带 ReDoS 守卫）。返回 [(type, value, start, end)]。

        位置为含分块偏移的绝对区间；调用方不得再用 str.find 重定位
        （重复值/重叠值下错位）。分块 overlap 区同一 span 按 (s,e) 去重。

        硬化闸：PII_DETECTION_HARDENING=1 时用 ThreadPoolExecutor + asyncio.timeout(0.1)
        单规则预算 + 连续 3 次停用；默认 0 时直跑 finditer（bypass）以保既有用例
        仍绿但不具超时防护（spec 要求默认关闭不改现有行为，硬化场景才卡死防护）。
        超时 → 跳过该规则 + 记告警（fail-open 但必报）；连续 3 次停用。
        protected_spans: 占位符区间（重叠排除）。
        cred_spans: 凭据区间（位置化优先，落入则跳过）。
        """
        if not self.custom_patterns or not text:
            return []
        loop = asyncio.get_running_loop()
        hits: list[tuple[str, str, int, int]] = []

        def _overlaps(start: int, end: int) -> bool:
            for spans in (protected_spans, cred_spans):
                if not spans:
                    continue
                if any(
                    s <= start < e or s < end <= e or (start <= s and e <= end)
                    for s, e in spans
                ):
                    return True
            return False

        hardening = True
        # 跨界保证上限：overlap 取 max(256, 最长 custom 源串, 上限 4096)；
        # 单个匹配跨度超过 overlap 仍可能被分块切断漏检（已知限制）。
        overlap = 256
        try:
            longest = 0
            for _, _, _src in self.custom_patterns:
                if _src and len(_src) > longest:
                    longest = len(_src)
            if longest > overlap:
                overlap = min(longest, 4096)
        except Exception:
            overlap = 256
        step = PII_SCAN_INPUT_LIMIT - overlap
        _chunks: list[tuple[int, str]] = []
        if len(text) > PII_SCAN_INPUT_LIMIT:
            for off in range(0, len(text), step):
                _chunks.append((off, text[off : off + PII_SCAN_INPUT_LIMIT]))
        else:
            _chunks = [(0, text)]
        seen_spans: set[tuple[int, int]] = set()
        for name, compiled, _src in self.custom_patterns:
            if name in self.custom_disabled:
                continue
            try:
                if hardening:
                    for _chunk_offset, _chunk in _chunks:
                        async with asyncio.timeout(PII_RE_DOS_BUDGET):
                            _found = await loop.run_in_executor(
                                self._executor,
                                lambda c=compiled, t=_chunk: list(c.finditer(t)),
                            )
                        for m in _found:
                            abs_s = _chunk_offset + m.start()
                            abs_e = _chunk_offset + m.end()
                            if (abs_s, abs_e) in seen_spans:
                                continue
                            if _overlaps(abs_s, abs_e):
                                continue
                            seen_spans.add((abs_s, abs_e))
                            hits.append((name, m.group(0), abs_s, abs_e))
                else:
                    for _chunk_offset, _chunk in _chunks:
                        for m in compiled.finditer(_chunk):
                            abs_s = _chunk_offset + m.start()
                            abs_e = _chunk_offset + m.end()
                            if (abs_s, abs_e) in seen_spans:
                                continue
                            if _overlaps(abs_s, abs_e):
                                continue
                            seen_spans.add((abs_s, abs_e))
                            hits.append((name, m.group(0), abs_s, abs_e))
                # 成功：清零超时计数（硬化时才有 strikes）
                if hardening:
                    self.custom_strikes.pop(name, None)
            except TimeoutError:
                strikes = self.custom_strikes.get(name, 0) + 1
                self.custom_strikes[name] = strikes
                if strikes >= PII_RE_DOS_STRIKES:
                    self.custom_disabled.add(name)
                    # 可观测性：ReDoS 停用暴露到 health（运维可见自定义规则被降级）
                    if self._collector is not None:
                        try:
                            self._collector.set_health_flag(
                                'pii_custom_disabled_count', len(self.custom_disabled)
                            )
                        except Exception:  # pragma: no cover — 防御
                            pass
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

        2-tuple 兼容薄层，正本见 _scan_dict_spans（位置化区间语义；
        凭据区间落入跳过，同值非凭据位置正常返回）。
        """
        return [
            (typ, name)
            for typ, name, _, _ in self._scan_dict_spans(text, credential_p2t)
        ]

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
            # 非硬化：混合边界 —— before 用 ASCII 字母数字 (?<!\w) 与硬化 CJK 差异化，after 仍 CJK 以保张三丰不误伤（7.6 修正保测试绿）
            return not (
                (before and before.isascii() and before.isalnum())
                or (after and (after.isalnum() or '\u4e00' <= after <= '\u9fff'))
            )
        # 数字/主机名类：只挡 ASCII 字母数字粘连
        return not (
            (before and before.isascii() and before.isalnum())
            or (after and after.isascii() and after.isalnum())
        )

    # ── 主扫描 ──

    def _credential_spans(
        self, text: str, credential_p2t: dict | None
    ) -> list[tuple[int, int]]:
        """凭据值在文本中的位置区间（位置化优先的基础）。"""
        if not credential_p2t or not text:
            return []
        spans: list[tuple[int, int]] = []
        for cred_value in credential_p2t:
            if not cred_value or cred_value not in text:
                continue
            start = 0
            while True:
                idx = text.find(cred_value, start)
                if idx == -1:
                    break
                spans.append((idx, idx + len(cred_value)))
                start = idx + 1
        return spans

    async def scan_spans(
        self,
        text: str,
        credential_p2t: dict | None = None,
        tail: str | None = None,
    ) -> list[tuple[str, str, int, int]]:
        """检测文本中的 PII，返回 [(type, value, start, end)] 位置列表。

        与 `scan` 同语义，差异仅为携带位置并按位置做凭据优先：
        仅落在凭据区间内的匹配跳过，同值非凭据位置正常返回。
        长跨度优先 + 重叠仲裁由调用方（detect_and_redact）执行，
        此处保留原始命中顺序。
        """
        if not text:
            return []
        protected_spans: list[tuple[int, int]] = []
        for m in _DATA_URL_RE.finditer(text):
            protected_spans.append((m.start(), m.end()))
        for m in _PROTECTED_TOKEN_RE.finditer(text):
            protected_spans.append((m.start(), m.end()))

        def _overlaps_protected(start: int, end: int) -> bool:
            return any(
                s <= start < e or s < end <= e or (start <= s and e <= end)
                for s, e in protected_spans
            )

        cred_spans = self._credential_spans(text, credential_p2t)

        def _overlaps_cred(start: int, end: int) -> bool:
            return any(
                s <= start < e or s < end <= e or (start <= s and e <= end)
                for s, e in cred_spans
            )

        spans: list[tuple[str, str, int, int]] = []
        has_coarse = bool(_COARSE_FILTER_RE.search(text))
        if has_coarse:
            for m in _get_combined_re().finditer(text):
                if _overlaps_protected(m.start(), m.end()):
                    continue
                kind = m.lastgroup
                value = m.group(0)
                if kind is None:
                    continue
                if kind == 'ipv6':
                    core = value.rstrip('.,;)]}')
                    if core and _is_valid_ipv6(core):
                        value = core
                    elif not _is_valid_ipv6(value):
                        continue
                if kind == 'ipv4':
                    core = value.rstrip('.,;)]}')
                    if core and _is_valid_ipv4(core):
                        value = core
                    elif not _is_valid_ipv4(value):
                        continue
                if kind == 'bank_card':
                    ctx_start = max(0, m.start() - 64)
                    ctx_end = min(len(text), m.end() + 16)
                    if _URL_QUERY_PARAM_RE.search(text[ctx_start:ctx_end]):
                        continue
                if kind == 'id_card' and not _id_card_ok(value):
                    continue
                if kind == 'bank_card' and not _luhn_ok(value):
                    continue
                if kind in ('ipv4', 'ipv6') and _is_reserved_ip(value, kind):
                    continue
                s, e = m.start(), m.start() + len(value)
                if _overlaps_cred(s, e):
                    continue
                spans.append((kind, value, s, e))
        if self.custom_patterns:
            custom_hits = await self._scan_custom(text, protected_spans, cred_spans)
            spans.extend(custom_hits)
        if self.dict_re:
            dict_hits = self._scan_dict_spans(text, credential_p2t, cred_spans)
            spans.extend(dict_hits)
        return spans

    def _scan_dict_spans(
        self,
        text: str,
        credential_p2t: dict | None = None,
        cred_spans: list[tuple[int, int]] | None = None,
    ) -> list[tuple[str, str, int, int]]:
        """字典的位置化扫描（边界判定与 _scan_dict 同语义）。"""
        if not self.dict_re or not text:
            return []
        if cred_spans is None:
            cred_spans = self._credential_spans(text, credential_p2t)
        out: list[tuple[str, str, int, int]] = []
        seen_spans: set[tuple[int, int]] = set()
        for m in self.dict_re.finditer(text):
            name = m.group(0)
            s, e = m.start(), m.end()
            if (s, e) in seen_spans:
                continue
            if cred_spans and any(
                cs <= s < ce or cs < e <= ce or (s <= cs and ce <= e)
                for cs, ce in cred_spans
            ):
                continue
            typ = 'name'
            for n, t in self.dict_entries:
                if n == name:
                    typ = t
                    break
            if not self._dict_boundary_ok(text, s, e, typ):
                continue
            seen_spans.add((s, e))
            out.append((typ, name, s, e))
        return out

    async def scan(
        self,
        text: str,
        credential_p2t: dict | None = None,
        tail: str | None = None,
    ) -> list[tuple[str, str]]:
        """检测文本中的 PII，返回 [(type, value)] 列表（不替换）。

        2-tuple 兼容薄层，正本见 scan_spans（位置化区间语义）。
        credential_p2t: 全局凭据映射（凭据区间落入跳过，同值非凭据位置正常返回）。
        tail: 请求路径尾（is_chat_tail 守门，值级采样仅对话路径；None 时不采样）。
        """
        if not text:
            return []
        hits: list[tuple[str, str]] = [
            (kind, value)
            for kind, value, _, _ in await self.scan_spans(
                text, credential_p2t, tail=tail
            )
        ]
        self._count_detected(hits)
        # ── 值级掩码采样（dashboard-pii-value-details 2.2）──
        # 明文仅在命中回调作用域内可见，仅掩码+hash 进 ContextVar
        _effective_tail = tail
        # 严格模式：tail is None => 不采样（需调用方显式传 tail，防 ContextVar 陈旧值中毒）
        # 请求侧已通过 handler 注入 tail 并显式透传；直调 scan 不传 tail 视为非对话不采样
        if hits and _is_pii_value_sample_enabled() and _effective_tail is not None:
            try:
                # lazy is_chat_tail guard（防 _pii↔_llm 循环）
                _is_dialog = False
                try:
                    from _llm import is_chat_tail as _is_chat_tail  # type: ignore

                    _is_dialog = _is_chat_tail(_effective_tail)
                except Exception:
                    # fallback inline（与 _llm.is_chat_tail 同语义，保持同步：tail.rstrip('/') 后 endswith chat/completions|v1/messages|v1/responses，见 _llm.py:184）
                    t = (_effective_tail or '').rstrip('/')
                    if t.endswith(('chat/completions', 'v1/messages', 'v1/responses')):
                        _is_dialog = True
                    else:
                        for _known in (
                            'chat/completions',
                            'v1/messages',
                            'v1/responses',
                        ):
                            _marker = '/' + _known + '/'
                            _idx = t.rfind(_marker)
                            if _idx != -1:
                                _suffix = t[_idx + len(_marker) :]
                                if _suffix and '/' not in _suffix:
                                    _is_dialog = True
                                    break
                if _is_dialog:
                    # lazy anti-cycle: ContextVar + sanitize_kind from _metrics
                    try:
                        from _metrics import _req_pii_var as _pii_var  # type: ignore
                        from _metrics import (
                            sanitize_kind as _sanitize_kind,  # type: ignore
                        )

                        _ctx = _pii_var.get()
                        if _ctx is not None:
                            _pvs = _ctx.setdefault('pii_value_samples', {})  # type: ignore[attr-defined]
                            for _k, _v in hits:
                                try:
                                    try:
                                        _sk = _sanitize_kind(_k, self.custom_names)
                                    except TypeError:
                                        _sk = _sanitize_kind(_k)  # type: ignore
                                except Exception:
                                    _sk = 'custom_other'
                                _masked = mask_pii_value(_sk, _v)
                                if len(_masked) > 64:
                                    _masked = _masked[:64]
                                _h = _pii_value_hash(_v)
                                _bucket = _pvs.setdefault(_sk, {})  # type: ignore
                                _ent = _bucket.get(_masked)
                                if _ent is None:
                                    _bucket[_masked] = {'count': 1, 'hash': _h}
                                else:
                                    _ent['count'] += 1
                    except Exception:
                        pass
            except Exception:
                pass
        return hits

    def _count_detected(self, hits: list[tuple[str, str]]) -> None:
        """pii_detected_total{kind} 计数（sanitize_kind 消毒后）。"""
        if not hits or self._collector is None:
            return
        from _metrics import sanitize_kind

        by_kind: dict[str, int] = {}
        for kind, _value in hits:
            sk = sanitize_kind(kind, self.custom_names)
            by_kind[sk] = by_kind.get(sk, 0) + 1
        if by_kind:
            self._collector.incr_sync_pii_detected(by_kind)

    async def detect_and_redact(
        self,
        text: str,
        credential_p2t: dict | None = None,
        response_side: bool = False,
        tail: str | None = None,
    ) -> str:
        """检测并替换 PII 为占位符（注册到请求级映射）。"""
        if not text:
            return text
        spans = await self.scan_spans(text, credential_p2t, tail=tail)
        if not spans:
            return text
        spans.sort(key=lambda x: (-(x[3] - x[2]), x[2]))
        selected: list[tuple[str, str, int, int]] = []
        occupied: list[tuple[int, int]] = []
        for kind, value, s, e in spans:
            if any(
                os <= s < oe or os < e <= oe or (s <= os and oe <= e)
                for os, oe in occupied
            ):
                continue
            occupied.append((s, e))
            selected.append((kind, value, s, e))
        selected.sort(key=lambda x: x[2])
        if self.request_tokens is None:
            parts: list[str] = []
            cursor = 0
            for kind, value, s, e in selected:
                parts.append(text[cursor:s])
                parts.append(_mask_placeholder(value, kind))
                cursor = e
            parts.append(text[cursor:])
            return ''.join(parts)
        token_by_value: dict[str, str] = {}
        for _, value, _, _ in selected:
            if value not in token_by_value:
                token_by_value[value] = await self.request_tokens.register(
                    value, response_side
                )
        parts = []
        cursor = 0
        for _, value, s, e in selected:
            token = token_by_value[value]
            parts.append(text[cursor:s])
            parts.append(token if token != value else value)
            cursor = e
        parts.append(text[cursor:])
        return ''.join(parts)

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
        # 占位符说明提示词（pii-placeholder-prompt）：默认启用，文案默认内置
        self.pii_placeholder_prompt_enabled = True
        self.pii_placeholder_prompt_text = ''
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

    async def pii_scan(
        self, text: str, tail: str | None = None
    ) -> list[tuple[str, str]]:
        """检测 PII（供 _llm.py 调用）。"""
        if not self.pii_enabled or not text:
            return []
        cred_p2t = getattr(self, 'pwd_to_token', None)
        return await self._pii_detector.scan(text, cred_p2t, tail=tail)

    async def pii_redact(
        self, text: str, response_side: bool = False, tail: str | None = None
    ) -> str:
        """检测并替换 PII（注册到请求级映射）。"""
        if not self.pii_enabled or not text:
            return text
        cred_p2t = getattr(self, 'pwd_to_token', None)
        return await self._pii_detector.detect_and_redact(
            text,
            credential_p2t=cred_p2t,
            response_side=response_side,
            tail=tail,
        )

    async def pii_redact_json_aware(
        self, text: str, response_side: bool = False, tail: str | None = None
    ) -> str:
        """JSON 感知的 PII 脱敏：仅对字符串节点做替换，避免破坏 \\u 转义。

        - 若 text 是合法 JSON（object/array），则 loads 后递归 walk 字符串值，逐个
          调用 detect_and_redact，再 dumps 回写（orjson 优先）；
        - 非 JSON 或解析/序列化失败时回退到纯文本 pii_redact；
        - 大 JSON 不再按 len 回退 plain，全走 json-aware（C 方案）。
        """
        if not self.pii_enabled or not text:
            return text
        stripped = _strip_bom(text).lstrip()
        if not (stripped.startswith(('{', '['))):
            return await self.pii_redact(text, response_side, tail=tail)
        try:
            obj = _jloads(_strip_bom(text))
        except Exception:
            return await self.pii_redact(text, response_side, tail=tail)
        cred_p2t = getattr(self, 'pwd_to_token', None)
        try:
            redacted = await _pii_json_walk(
                obj, self._pii_detector, cred_p2t, response_side, path='$', tail=tail
            )
            out = _jdumps(redacted)
            return _pii_validate_json_roundtrip(text, out, 'pii_redact_json_aware')
        except Exception:
            logger.debug('pii_redact_json_aware 回退到纯文本路径', exc_info=True)
            return await self.pii_redact(text, response_side, tail=tail)

    # ── 占位符说明提示词注入（pii-placeholder-prompt）──

    def _pii_placeholder_text(self) -> str:
        """当前生效的说明文案：自定义非空用自定义，否则内置默认。"""
        custom = getattr(self, 'pii_placeholder_prompt_text', '') or ''
        return custom.strip() or PII_PLACEHOLDER_PROMPT_DEFAULT

    @staticmethod
    def _pii_placeholder_inject_obj(obj, prompt: str, protocol: str = 'openai'):
        """在已解析的消息对象中注入说明提示词（原地修改并返回）。

        协议分支（design D2），协议以路由 path 判定（由调用方传入）：
        - 'anthropic'：顶层 system 字段（字符串或数组）存在 → 追加；
          不存在 → 新建顶层 system 字符串（Anthropic 不用 messages 内 system 角色）。
        - 'responses'：input[] 数组；input[0].role == "system" → 追加 content；
          否则新建 system 消息插入头部；空 input → 唯一 system 消息。
        - 'openai'：messages[] 数组；同 responses 逻辑。

        content/system 为数组时：向数组末尾追加 text block；若最后一个元素已是
        text，追加到其末尾。多条 system 仅追加第一条。非 JSON 结构（无法定位
        messages/input/system）→ 返回 False 表示不注入。
        """

        def _append_text(field):
            if isinstance(field, str):
                if not field:
                    return prompt  # 空 system/content：直接替换，不留前导换行
                return field + '\n\n' + prompt
            if isinstance(field, list):
                if field and isinstance(field[-1], dict):
                    last = field[-1]
                    if last.get('type') == 'text' and isinstance(last.get('text'), str):
                        last['text'] = last['text'] + '\n\n' + prompt
                        return field
                field.append({'type': 'text', 'text': prompt})
                return field
            return field  # 未知类型：不注入（安全透传）

        # Anthropic：顶层 system 字段（字符串或数组）
        if protocol == 'anthropic':
            if isinstance(obj, dict) and obj.get('system') is not None:
                sys_field = obj['system']
                if isinstance(sys_field, (str, list)):
                    obj['system'] = _append_text(sys_field)
                    return True
                return False  # 未知类型：不注入（安全透传）
            if isinstance(obj, dict):
                obj['system'] = prompt
                return True
            return False

        # OpenAI / Responses：messages/input 数组
        msgs = obj.get('messages') if isinstance(obj, dict) else None
        if protocol == 'responses':
            msgs = obj.get('input') if isinstance(obj, dict) else None
        if isinstance(msgs, list):
            if not msgs:
                msgs.append({'role': 'system', 'content': prompt})
                return True
            first = msgs[0]
            if isinstance(first, dict) and first.get('role') == 'system':
                if isinstance(first.get('content'), (str, list)):
                    first['content'] = _append_text(first['content'])
                    return True
                # content 缺失/未知类型：仍追加为字符串（保守）
                first['content'] = _append_text(first.get('content') or '')
                return True
            msgs.insert(0, {'role': 'system', 'content': prompt})
            return True

        # 无法定位可注入结构：不注入
        return False

    @staticmethod
    def _pii_placeholder_schema_ok(obj, protocol: str = 'openai') -> bool:
        if not isinstance(obj, dict):
            return False
        if protocol == 'anthropic':
            sys_field = obj.get('system')
            return sys_field is None or isinstance(sys_field, (str, list))
        if protocol == 'responses':
            return isinstance(obj.get('input'), list)
        return isinstance(obj.get('messages'), list)

    def inject_placeholder_prompt(self, body_text: str, protocol: str = 'openai'):
        """向脱敏后的请求 body 注入占位符说明提示词（同步纯函数）。

        protocol 由调用方按路由 path 判定（'openai'/'anthropic'/'responses'）。

        错误路径（design D6）：body 非合法 JSON / 非对象 → 透传原 body 不注入、
        不抛异常（与 _llm.py 现有「JSON 解析失败回退原文」模式一致）。
        注入为请求作用域纯函数：无共享可变状态、无需锁、不读写
        pii_t2p/used_tokens，与脱敏/还原映射无冲突。
        """
        if not body_text or not getattr(self, 'pii_placeholder_prompt_enabled', True):
            return body_text
        stripped = _strip_bom(body_text).lstrip()
        if not (stripped.startswith(('{', '['))):
            return body_text  # 非 JSON：透传不注入
        try:
            obj = _jloads(_strip_bom(body_text))
        except Exception:
            logger.debug(
                'inject_placeholder_prompt 解析失败，透传原 body', exc_info=True
            )
            return body_text
        if not isinstance(obj, dict):
            return body_text  # 非对象：透传不注入
        prompt = self._pii_placeholder_text()
        try:
            if self._pii_placeholder_inject_obj(obj, prompt, protocol):
                if not self._pii_placeholder_schema_ok(obj, protocol):
                    logger.warning(
                        'inject_placeholder_prompt schema 校验失败，回退不注入: protocol=%s',
                        protocol,
                    )
                    try:
                        self._inject_schema_failed = (
                            getattr(self, '_inject_schema_failed', 0) + 1
                        )
                    except Exception:
                        pass
                    return body_text
                return _jdumps(obj)
        except Exception:
            logger.exception('inject_placeholder_prompt 注入异常，透传原 body')
            return body_text
        return body_text
