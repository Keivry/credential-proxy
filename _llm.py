"""LlmMixin — LLM API 反向代理：脱敏请求 → 上游 → 还原响应。"""

import asyncio
import contextlib
import contextvars
import json
import logging
import os
import re as _re
import time as _time
import uuid as _uuid

from aiohttp import ClientSession, ClientTimeout, web
from aiohttp.client_exceptions import ClientConnectionError, ServerDisconnectedError

from _audit import BLOCK_MESSAGE, AuditMixin, redact_summary
from _sse import SSE_CLIENT_GONE, filter_hop_headers
from _token import (
    _PII_PARTIAL_TOKEN_RE,
    FULL_PII_TOKEN_RE,
    PII_TOKEN_LOOSE_RE,
    PII_TOKEN_RE,
    PII_TOKEN_STR_RE,
    TOKEN_RE,
    TOKEN_STR_RE,
)

logger = logging.getLogger('credential-proxy')

TRUNCATED_MESSAGE = '上游流式响应被截断（未收到终止事件），请重试。'

# ── utils/json_walk 共享导入（design D1，存在则复用）──
try:
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

    _SHARED_WALK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _shared_json_walk = None  # type: ignore
    _shared_json_walk_async = None  # type: ignore
    _shared_jloads = None  # type: ignore
    _shared_jdumps = None  # type: ignore
    _shared_strip_bom = None  # type: ignore
    _shared_validate = None  # type: ignore
    _SHARED_WALK_AVAILABLE = False

# ── orjson 加速封装（与 _token/_pii 同口径）──
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
    return json.loads(s)


def _jdumps(obj) -> str:
    if _shared_jdumps is not None:  # type: ignore[truthy-function]
        return _shared_jdumps(obj)  # type: ignore
    if _USE_ORJSON:
        return _orjson.dumps(obj).decode()  # type: ignore
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':'))


# ── json-aware 后置校验（与 _token._validate_json_roundtrip 同语义）──
def _llm_validate_json_roundtrip(original: str, output: str, label: str) -> str:
    stripped = original.lstrip('\ufeff').lstrip()
    if not (stripped.startswith('{') or stripped.startswith('[')):
        return output
    try:
        json.loads(original.lstrip('\ufeff'))
    except Exception:
        return output
    try:
        json.loads(output.lstrip('\ufeff'))
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


# ── Per-request ContextVars for concurrency isolation (D2) ──
_pii_scope_var = contextvars.ContextVar('_pii_scope_var', default=None)
_audit_hold_active_var = contextvars.ContextVar('_audit_hold_active_var', default=False)
_audit_hold_buf_var = contextvars.ContextVar('_audit_hold_buf_var', default=None)
_audit_hold_bytes_var = contextvars.ContextVar('_audit_hold_bytes_var', default=0)
_last_anthropic_tool_name_var = contextvars.ContextVar(
    '_last_anthropic_tool_name_var', default=None
)
_last_responses_tool_name_var = contextvars.ContextVar(
    '_last_responses_tool_name_var', default=None
)
_audit_created_ids_var = contextvars.ContextVar('_audit_created_ids_var', default=None)


def _strip_partials(text: str) -> str:
    """流末/安全输出前清理残缺 token 前缀（凭据 + PII 两套）。

    design D2 硬性：PII 残缺形态（`__PII_…` 前缀在分片边界被切断）必须与
    凭据残缺同规则清理，否则 `__PII_1_ab` 等残缺会随 safe 输出泄漏给客户端。
    统一入口替换散落的 `_PARTIAL_TOKEN_RE.sub`，避免新增路径漏接 PII 版。
    """
    out = _PARTIAL_TOKEN_RE.sub('', text)
    return _PII_PARTIAL_TOKEN_RE.sub('', out)


# ── Constants ──
UPSTREAM_TOTAL_TIMEOUT = 600  # 上游总超时 (s)
UPSTREAM_CONNECT_TIMEOUT = 30  # 上游连接超时 (s)
MAX_UPSTREAM_RETRIES = 3  # 上游连接重试次数（含首次）
UPSTREAM_RETRY_BACKOFF = 0.5  # 上游连接重试退避基数 (s)，指数增长
SSE_CHUNK_SIZE = 4096  # SSE 分片大小
SSE_MAX_BUF = 1_048_576  # SSE 缓冲区上限 (1MB)
LINE_BUF_FLUSH = 16384  # 单逻辑行超长强制阈值 (16KB)
LINE_BUF_MAX_AGE = 30  # 持有超长阈值 (30s)
KEEPALIVE_INTERVAL = 10  # 保活间隔 (10s, `: keepalive\\n\\n` comment)
# 流末清理：匹配 token 前缀/残缺形态（含完整但未还原的幻觉 token）。
# 真实 token 会被 _restore 先行还原为明文，不会落此正则。
# 8.9 修复（F-10）：结尾 `(?:$|(?=\s|[^\w]))` 覆盖行中残缺形态。
_PARTIAL_TOKEN_RE = _re.compile(
    r'__VG_C(?:R(?:E(?:D(?:_?\d*)?)?)?)?(?:_*$|(?=\s|[^\w]))'
)
# 完整 token 形态（行尾）：__VG_CRED_NNNNNN__
_FULL_TOKEN_RE = _re.compile(r'__VG_CRED_\d+__$')
# ── 6.5/3.1 超长强制候选感知：检测行尾是否可能为 PII 前缀 ──
# D5/3.1 扩展为内置全类型前缀族（email/phone/id_card/bank_card/ipv4/ipv6/api_key）
# + __VG_CRED__/__PII__ 保留前缀全覆盖。注意（Non-Goals）：只扩展持有等待，
# 不改变检测命中语义（检测正则本身不动）。
# ipv4 尾点修复：旧正则 `(?:\.\d{1,3}){0,2}$` 要求段尾为数字，`192.168.` 等
# 尾点形态恒不命中；现允许尾点并覆盖 4 段切断（`192.168.1.2`+`5`）。
_HAS_PARTIAL_IPV4_RE = _re.compile(r'\b\d{1,3}(?:\.\d{1,3}){0,3}\.?$')
# 纯数字尾（phone/id_card/bank_card 被切断的数字前缀：`138`/`110105`/`622588` 等；
# 要求 ≥2 位——单数字尾（`step1`/`v2`）多为普通词内编号，持有只会切碎文本，
# 且无触发时驻留缓冲仍可随后续分片重组，不丢安全）。
_HAS_PARTIAL_DIGITS_RE = _re.compile(r'(?<![\d])\d{2,19}$')
# 邮箱：`user@` + 切断的域片段（`user@exa`+`mple.com` 的前段必须持有等待）
_HAS_PARTIAL_EMAIL_RE = _re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]*$')
# IPv6：旧正则仅覆盖 fe80::；现覆盖任意含冒号十六进制切断（含 `::` 压缩尾片）。
# 前瞻排除纯 `key:` 误持（冒号前须为十六进制字符或冒号）。
_HAS_PARTIAL_IPV6_RE = _re.compile(
    r'(?<![0-9A-Za-z:.])(?:[0-9a-fA-F]{0,4}::?[0-9a-fA-F:.]*|(?:[0-9a-fA-F]{1,4}:)+[0-9a-fA-F:.]*)$',
    _re.IGNORECASE,
)
# api_key 裸前缀（sk-/ghp_/AKIA 被切断的头部）。词边界用负向 lookbehind
# （`ask`/`task` 尾 `sk` 前为字母，不持留；`sk-` 尾 `-` 非词字符故不用 \b）。
_HAS_PARTIAL_APIKEY_RE = _re.compile(
    r'(?<![0-9A-Za-z-])(?:sk(?:-(?:p(?:r(?:o(?:j(?:-)?)?)?)?|a(?:n(?:t(?:-)?)?)?)?)?[A-Za-z0-9_-]{0,16}|gh[pous]?(?:_[A-Za-z0-9]{0,16})?|AK(?:IA?[0-9A-Z]{0,16})?)$'
)
_VG_CRED_PREFIX = '__VG_CRED_'
_PII_PREFIX = '__PII_'


def _has_partial_pii_candidate(
    text: str, extra_prefixes: list[str] | None = None
) -> bool:
    """检测文本尾部是否存在 PII 前缀候选（6.5 超长强制感知，3.1 扩展全类型）。

    - 内置前缀族：ipv4（含尾点）/ 纯数字（phone/id_card/bank_card）/
      邮箱（含域片段）/ ipv6（全形态）/ api_key（裸前缀，词边界防误持）
    - 保留前缀：`__VG_CRED__`/`__PII__` 完整与切断形态（`__V`/`__VG_CRED_000` 等）
    - 自定义：`extra_prefixes`（`PiiDetector.partial_prefix_hints` best-effort
      提示）非空命中即持有；调用方已预过滤，未过滤的原始列表同样兼容判定
    仅检查尾部 64 字符窗口（调用方传入已截断），命中即视为候选。
    只扩展持有等待，不改变检测命中语义。
    """
    if not text or not isinstance(text, str):
        return False
    tail = text[-64:] if len(text) > 64 else text
    _m4 = _HAS_PARTIAL_IPV4_RE.search(tail)
    if _m4 and len(_m4.group(0)) >= 2:
        return True
    if _HAS_PARTIAL_DIGITS_RE.search(tail):
        return True
    if _HAS_PARTIAL_EMAIL_RE.search(tail):
        return True
    if _HAS_PARTIAL_IPV6_RE.search(tail):
        return True
    if _HAS_PARTIAL_APIKEY_RE.search(tail):
        return True
    if '__' in tail or tail.endswith('_'):
        last = tail.rfind('__')
        suffix = tail[last:] if last != -1 else tail[tail.rfind('_') :]
        if suffix in ('_', '__'):
            return True
        if _VG_CRED_PREFIX.startswith(suffix) or _PII_PREFIX.startswith(suffix):
            return True
        if suffix.startswith(_VG_CRED_PREFIX) or suffix.startswith(_PII_PREFIX):
            return True
    if extra_prefixes:
        for _h in extra_prefixes:
            if not _h or not isinstance(_h, str):
                continue
            _h = _h[:64]
            if not _h:
                continue
            if _h in tail:
                return True
            _n = min(len(_h), len(tail))
            for _k in range(_n, 0, -1):
                if tail.endswith(_h[:_k]):
                    return True
    return False


# Debug 开关：设置环境变量 CREDENTIAL_PROXY_DEBUG_DIR 开启
_DEBUG_DIR = os.environ.get('CREDENTIAL_PROXY_DEBUG_DIR', '')


def is_chat_tail(tail: str) -> bool:
    """判定对话类 LLM 接口尾（chat/completions | v1/messages | v1/responses）。

    对 `tail.rstrip('/')` 后段级判定，避免 `/v1/responses/` 漏判。
    容忍一层自定义后缀（`.../chat/completions/custom` 等中转自定义路径仍计对话）——
    Y-11 修复：纯 endswith 会漏这类非标准但确为对话的端点。
    单一共享函数（19 处内联收敛），供埋点与协议分派共用。
    """
    t = tail.rstrip('/')
    if t.endswith(('chat/completions', 'v1/messages', 'v1/responses')):
        return True
    # 一层自定义后缀容忍：父路径以已知对话端点结尾 + 仅一层子路径
    # （如 /v1/chat/completions/custom → 合法；/v1/chat/completions/a/b → 两层，不判）
    for known in ('chat/completions', 'v1/messages', 'v1/responses'):
        marker = '/' + known + '/'
        idx = t.rfind(marker)
        if idx != -1:
            suffix = t[idx + len(marker) :]
            if suffix and '/' not in suffix:
                return True
    return False


def _capture_usage_ctx(payload: str, metrics_ctx: dict, protocol: str) -> None:
    """从 SSE data payload 捕获 usage → 归一 tokens（按 model 分桶）。

    - OpenAI Chat 末块 usage / Responses response.completed.response.usage /
      Anthropic message_start+message_delta 聚合
    - 仅当 payload 可解析且含 usage 字段；无则保持现状不估算
    """
    if not payload or not payload.strip() or payload.strip() == '[DONE]':
        return
    # 快路径排除：99% chunk 无 usage/cached_tokens，避免全量 JSON 解析
    if '"usage"' not in payload and '"cached_tokens"' not in payload:
        return
    try:
        obj = _jloads(payload.strip())
    except Exception:
        return
    if not isinstance(obj, dict):
        return
    usage = None
    if 'usage' in obj and isinstance(obj.get('usage'), dict):
        usage = obj['usage']
    else:
        # Responses: response.completed.response.usage
        # 实测 muse-spark（opencode zen/go /v1/responses）为单层
        # {"type":"response.completed","response":{"id":...,"usage":{...}}}
        # 兼容双层 {"response":{"response":{"usage":...}}} 历史形态
        resp_inner = obj.get('response')
        if isinstance(resp_inner, dict):
            if isinstance(resp_inner.get('usage'), dict):
                usage = resp_inner['usage']
            else:
                inner2 = resp_inner.get('response')
                if isinstance(inner2, dict) and isinstance(inner2.get('usage'), dict):
                    usage = inner2['usage']
        # Anthropic message_delta.usage
        delta_inner = obj.get('delta')
        if isinstance(delta_inner, dict) and isinstance(delta_inner.get('usage'), dict):
            usage = delta_inner['usage']
        # Anthropic message_start.message.usage
        msg_inner = obj.get('message')
        if isinstance(msg_inner, dict) and isinstance(msg_inner.get('usage'), dict):
            usage = msg_inner['usage']
    if not isinstance(usage, dict):
        return
    try:
        from _metrics import normalize_usage

        norm = normalize_usage(usage, protocol)
        model = metrics_ctx.get('model', 'unknown_model')
        tokens = metrics_ctx.setdefault('tokens', {})
        cur = tokens.setdefault(model, {})
        for k in (
            'prompt',
            'completion',
            'total',
            'input',
            'output',
            'cached_read',
            'cached_write',
        ):
            v = norm.get(k)
            if isinstance(v, int):
                cur[k] = cur.get(k, 0) + v
        if norm.get('unknown'):
            # 幂等：unknown 表示“该请求无法归一”，按请求计 1 次而非按 chunk 累加
            # （Anthropic message_start + message_delta 两段式会重复计数）
            cur['unknown'] = max(cur.get('unknown', 0), 1)
    except Exception:
        logger.debug('usage 归一失败（fail-open）', exc_info=True)


def parse_llm_proxy_env() -> dict[int, str]:
    """从 LLM_<PORT>=<URL> 环境变量读取上游配置。"""
    proxies: dict[int, str] = {}
    for k, v in os.environ.items():
        if not k.startswith('LLM_'):
            continue
        try:
            port = int(k[4:])
        except ValueError:
            continue
        proxies[port] = v.strip().rstrip('/')
        if not proxies[port]:
            del proxies[port]
    return proxies


def _extract_conv_id(data: dict) -> str | None:
    """从 SSE data JSON 中提取 conversation ID。

    兼容 OpenAI 格式 (data.id) 和 Anthropic 格式 (data.message.id)。
    新增 Responses API 兼容：response.created/in_progress/completed 等
    事件的 id 藏在 data.response.id（顶层无 id）。
    """
    if 'id' in data and isinstance(data['id'], str) and data['id']:
        return data['id']
    if isinstance(data.get('message'), dict):
        mid = data['message'].get('id')
        if isinstance(mid, str) and mid:
            return mid
    # OpenAI Responses API: {"type":"response.created","response":{"id":"resp_..."},...}
    if isinstance(data.get('response'), dict):
        rid = data['response'].get('id')
        if isinstance(rid, str) and rid:
            return rid
    return None


def _save_request_body(conv_id: str, body: bytes) -> None:
    """保存脱敏后的请求 body 到 debug 目录，以 conversation ID 命名。

    保存的是 redact 后的 out_body（不含明文凭据）。
    仅在 LLM 对话 endpoint 且 CREDENTIAL_PROXY_DEBUG_DIR 设置时调用。
    单次写入 request.json，不追加，不保存上游响应。
    """
    if not _DEBUG_DIR or not body:
        return
    path = os.path.join(_DEBUG_DIR, conv_id, 'request.json')
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(body)
    except OSError as exc:
        logger.debug('保存调试请求失败: %s', exc)


async def _save_response_line(resp_log_path: str, payload: str) -> None:
    """追加一行原始 payload 到 response.jsonl。

    通过 run_in_executor 异步写入，不阻塞 SSE 流式转发。
    """
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _append_jsonl_line, resp_log_path, payload)


def _append_jsonl_line(path: str, line: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a', encoding='utf-8') as f:
        f.write(line + '\n')


# === DEBUG 调试增强：原版/脱敏请求、原版/恢复回复四份落盘 ===
def _debug_dir_for_req(req_id: str) -> str:
    return os.path.join(_DEBUG_DIR, f'req_{req_id}')


def _save_debug_bytes(req_id: str, filename: str, data: bytes) -> None:
    if not _DEBUG_DIR or data is None:
        return
    path = os.path.join(_debug_dir_for_req(req_id), filename)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(data)
    except OSError as exc:
        logger.debug('保存调试文件失败 %s: %s', filename, exc)


def _save_debug_text(req_id: str, filename: str, text: str) -> None:
    if not _DEBUG_DIR or text is None:
        return
    path = os.path.join(_debug_dir_for_req(req_id), filename)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
    except OSError as exc:
        logger.debug('保存调试文件失败 %s: %s', filename, exc)


def _save_debug_json(req_id: str, filename: str, obj) -> None:
    if not _DEBUG_DIR:
        return
    try:
        # 调试文件快照：indent=2 可读格式；非SSE转发故不走_jdumps紧凑口径
        txt = json.dumps(obj, ensure_ascii=False, indent=2)  # _jdumps-whitelist
    except Exception:
        txt = str(obj)
    _save_debug_text(req_id, filename, txt)


async def _debug_append_line(req_id: str, filename: str, line: str) -> None:
    if not _DEBUG_DIR:
        return
    path = os.path.join(_debug_dir_for_req(req_id), filename)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _append_jsonl_line, path, line)


def _debug_link_conv_id(req_id: str, conv_id: str, out_body: bytes) -> None:
    if not _DEBUG_DIR or not conv_id:
        return
    try:
        req_dir = _debug_dir_for_req(req_id)
        conv_dir = os.path.join(_DEBUG_DIR, conv_id)
        os.makedirs(conv_dir, exist_ok=True)
        with open(os.path.join(req_dir, 'conv_id.txt'), 'w', encoding='utf-8') as f:
            f.write(conv_id)
        with open(os.path.join(conv_dir, 'req_id.txt'), 'w', encoding='utf-8') as f:
            f.write(req_id)
        if out_body:
            with open(os.path.join(conv_dir, 'request.json'), 'wb') as f:
                f.write(out_body)
    except OSError as exc:
        logger.debug('保存conv_id映射失败: %s', exc)


def _chat_choice_index(choice, pos: int) -> int:
    """取 chat chunk 单路索引：`choices[i].index` 为 int 则用之，否则回退位置序号。"""
    try:
        idx = choice.get('index') if isinstance(choice, dict) else None
    except AttributeError:
        return pos
    return idx if isinstance(idx, int) else pos


def _parsed_choice_indexes(parsed) -> set:
    try:
        _cs = parsed.get('choices') if isinstance(parsed, dict) else None
    except AttributeError:
        return set()
    if not isinstance(_cs, list):
        return set()
    return {
        _chat_choice_index(_c, _p) for _p, _c in enumerate(_cs) if isinstance(_c, dict)
    }


def _single_mapped_index(src: set, cur: dict, parsed=None):
    try:
        _all = set(src) | {i for i, v in cur.items() if v}
    except AttributeError:
        return None
    if len(_all) != 1:
        return None
    _idx = next(iter(_all))
    if parsed is not None and _idx not in _parsed_choice_indexes(parsed):
        return None
    return _idx


def _rebuild_chat_chunk(
    parsed,
    content_by_index: dict | None = None,
    reasoning_by_index: dict | None = None,
    finish_by_index: dict | None = None,
    tool_calls_by_index: dict | None = None,
) -> str:
    """D1 结构保留重建：deepcopy 原解析对象，按 `choices[i].index` 逐路替换 delta 字段。

    - 仅替换映射命中的路；未命中路原样保留（禁止把同一 content 广播到所有路）。
    - `id/created/model/system_fingerprint/usage` 等协议字段原位保留（只改文本叶）。
    - `finish_reason` 默认保留原值，仅 `finish_by_index` 命中的路覆盖。
    - `parsed` 非 dict（数组/标量）→ 整包透传，不抛 AttributeError。
    - 序列化统一走 `_jdumps`。
    """
    import copy

    if not isinstance(parsed, dict):
        try:
            return _jdumps(parsed)
        except Exception:
            return str(parsed)
    try:
        out = copy.deepcopy(parsed)
    except Exception:
        try:
            return _jdumps(parsed)
        except Exception:
            return str(parsed)
    try:
        choices = out.get('choices')
        if not isinstance(choices, list):
            return _jdumps(out)
        pos_map: dict[int, dict] = {}
        for _pos, _ch in enumerate(choices):
            if not isinstance(_ch, dict):
                continue
            pos_map[_chat_choice_index(_ch, _pos)] = _ch
        if not pos_map:
            return _jdumps(out)
        for _idx, _ch in pos_map.items():
            _delta = _ch.get('delta')
            if content_by_index and _idx in content_by_index:
                _v = content_by_index[_idx]
                if isinstance(_v, str):
                    if not isinstance(_delta, dict):
                        _delta = {}
                        _ch['delta'] = _delta
                    _delta['content'] = _v
            if reasoning_by_index and _idx in reasoning_by_index:
                _v = reasoning_by_index[_idx]
                if isinstance(_v, str):
                    if not isinstance(_delta, dict):
                        _delta = {}
                        _ch['delta'] = _delta
                    if 'reasoning' in _delta and 'reasoning_content' not in _delta:
                        _delta['reasoning'] = _v
                    else:
                        _delta['reasoning_content'] = _v
            if tool_calls_by_index and _idx in tool_calls_by_index:
                _v = tool_calls_by_index[_idx]
                if not isinstance(_delta, dict):
                    _delta = {}
                    _ch['delta'] = _delta
                _delta['tool_calls'] = _v
            if finish_by_index and _idx in finish_by_index:
                _v = finish_by_index[_idx]
                if _v is not None:
                    _ch['finish_reason'] = _v
        return _jdumps(out)
    except Exception:
        try:
            return _jdumps(parsed)
        except Exception:
            return str(parsed)


def _mk_sse_event(
    content: str = '',
    finish_reason: str | None = None,
    reasoning_content: str = '',
    parsed=None,
    *,
    content_by_index: dict | None = None,
    reasoning_by_index: dict | None = None,
    finish_by_index: dict | None = None,
) -> str:
    """Build OpenAI-compatible SSE data event JSON.

    Supports both content and reasoning_content delta fields.
    Content is always included when non-empty — OpenAI allows
    content + finish_reason in the same delta event.

    D1 结构保留：`parsed` 为上游原解析对象时走 deepcopy 逐路重建
    （`id/created/model/system_fingerprint/usage` 原位保留）；
    `parsed` 非 dict 时整包透传；`parsed=None` 时保持原最小事件合成。
    """
    if parsed is not None and not isinstance(parsed, dict):
        try:
            return f'data: {_jdumps(parsed)}\n\n'
        except Exception:
            return f'data: {parsed}\n\n'
    if isinstance(parsed, dict):
        _cbi = dict(content_by_index) if content_by_index else {}
        _rbi = dict(reasoning_by_index) if reasoning_by_index else {}
        _fbi = dict(finish_by_index) if finish_by_index else {}
        try:
            _choices = parsed.get('choices')
        except AttributeError:
            _choices = None
        if isinstance(_choices, list) and _choices:
            _idxs = [_chat_choice_index(_ch, _pos) for _pos, _ch in enumerate(_choices)]
            if content and not _cbi:
                if len(_idxs) == 1:
                    _cbi[_idxs[0]] = content
                else:
                    for _pos, _ch in enumerate(_choices):
                        if not isinstance(_ch, dict):
                            continue
                        _d = _ch.get('delta')
                        if isinstance(_d, dict) and isinstance(_d.get('content'), str):
                            _cbi[_chat_choice_index(_ch, _pos)] = content
                            break
            if reasoning_content and not _rbi:
                if len(_idxs) == 1:
                    _rbi[_idxs[0]] = reasoning_content
                else:
                    for _pos, _ch in enumerate(_choices):
                        if not isinstance(_ch, dict):
                            continue
                        _d = _ch.get('delta')
                        if isinstance(_d, dict) and (
                            isinstance(_d.get('reasoning_content'), str)
                            or isinstance(_d.get('reasoning'), str)
                        ):
                            _rbi[_chat_choice_index(_ch, _pos)] = reasoning_content
                            break
            if finish_reason is not None and not _fbi:
                for _pos, _ch in enumerate(_choices):
                    if not isinstance(_ch, dict):
                        continue
                    if _ch.get('finish_reason') is None:
                        _fbi[_chat_choice_index(_ch, _pos)] = finish_reason
        return f'data: {_rebuild_chat_chunk(parsed, _cbi or None, _rbi or None, _fbi or None)}\n\n'
    delta = {}
    if content:
        delta['content'] = content
    if reasoning_content:
        delta['reasoning_content'] = reasoning_content
    # 10.11.4 (F-QUAL-01): 统一走 _jdumps（ensure_ascii=False +
    # separators=(',',':')），与共享 json_walk 口径一致（原裸
    # dumps 空格分隔与 _jdumps 输出形态不一致）
    event = _jdumps(
        {
            'choices': [{'index': 0, 'delta': delta, 'finish_reason': finish_reason}],
            'object': 'chat.completion.chunk',
        }
    )
    return f'data: {event}\n\n'


def _fast_rebuild_chunk(parsed, content, reasoning=None) -> str:
    """10.14 (API-SPEC): 快链重建 chat.completion.chunk JSON。

    D1 结构保留：deepcopy 原 chunk，按 `choices[i].index` 逐路替换
    `delta.content`（`content` 为 `dict[int, str]` 时）；`id/object/model/
    choices` 结构与 `finish_reason/usage` 原位保留；`parsed` 非 dict 时
    整包透传不抛 AttributeError。

    3.1 (D5)：`reasoning` 为 `dict[int, str]` 时同等按路替换
    `delta.reasoning_content`（与 content 共用重建入口，不另设阈值）。

    `content` 为 str 时为兼容形态：仅替换原含 str content 的路
    （内部调用方一律用 dict 形态，禁止跨路广播）。
    """

    def _as_map(text) -> dict | None:
        try:
            _choices = parsed.get('choices')
        except AttributeError:
            return None
        if not isinstance(_choices, list) or not _choices:
            return None
        _m: dict[int, str] = {}
        for _pos, _ch in enumerate(_choices):
            if not isinstance(_ch, dict):
                continue
            _d = _ch.get('delta')
            if isinstance(_d, dict) and isinstance(_d.get('content'), str):
                _m[_chat_choice_index(_ch, _pos)] = text
        return _m or None

    try:
        if not isinstance(parsed, dict):
            try:
                return _jdumps(parsed)
            except Exception:
                return str(parsed)
        if isinstance(content, dict):
            _rmap = None
            if isinstance(reasoning, dict):
                _rmap = {
                    k: v for k, v in reasoning.items() if isinstance(v, str)
                } or None
            return _rebuild_chat_chunk(
                parsed,
                {k: v for k, v in content.items() if isinstance(v, str)} or None,
                _rmap,
            )
        if isinstance(content, str):
            return _rebuild_chat_chunk(parsed, _as_map(content))
        try:
            return _jdumps(parsed)
        except Exception:
            return str(parsed)
    except Exception:
        # 解析失败：原样返回（保持 JSON 结构，避免破坏流）
        try:
            return _jdumps(parsed)
        except Exception:
            return str(parsed)


def _responses_event(parsed: dict) -> tuple[str, str | None] | None:
    """识别 OpenAI Responses API SSE 事件（/v1/responses）。

    返回 (kind, delta_text)：
      kind ∈ {'output_text', 'reasoning_text', 'function_call_arguments', 'item_done', 'other'}
      - delta 事件: delta_text 为文本片段
      - 'item_done'（response.output_item.done / output_text.done / ...）: delta_text=None，
        表示 item 结束，需清理跨 item 残留
      - 'other'（response.created / completed 等）: delta_text=None
    非 Responses 事件（chat/completions SSE 等）返回 None。
    """
    evt_type = parsed.get('type') if isinstance(parsed, dict) else None
    if not isinstance(evt_type, str) or not evt_type.startswith('response.'):
        # 10.13 (F-12): ping 事件也识别为 'other' ——
        # 上游 responses 流中 `event: ping\ndata: {"type":"ping"}`
        # 若不识别，data 行走普通透传（不拼暂存 event 行），
        # event 行被流末单独透传 → 拆块 → 下游 sdk JSONDecodeError。
        if evt_type == 'ping':
            return 'other', None
        return None
    kind_map = {
        'response.output_text.delta': 'output_text',
        'response.reasoning_text.delta': 'reasoning_text',
        'response.function_call_arguments.delta': 'function_call_arguments',
        'response.refusal.delta': 'output_text',
        'response.reasoning_summary_text.delta': 'reasoning_text',
        'response.reasoning_summary.delta': 'reasoning_text',
        'response.audio.transcript.delta': 'output_text',
        'response.code_interpreter_call_code.delta': 'function_call_arguments',
        'response.shell_call_command.delta': 'function_call_arguments',
        'response.mcp_call_arguments.delta': 'function_call_arguments',
        'response.custom_tool_call_input.delta': 'function_call_arguments',
    }
    kind = kind_map.get(evt_type, 'other')
    if evt_type.endswith('.done'):
        # 各类型 done 事件：item 结束，arg_buf 中未完成的 token 前缀
        # 不可能再有后续分片，必须清理，否则下一个 item 的
        # function_call_arguments.delta 可能跨 item 拼接伪还原
        kind = 'item_done'
    delta_text = parsed.get('delta') if kind not in ('other', 'item_done') else None
    # audio.delta is audio bytes (not text), ignore -> treat as other
    if evt_type == 'response.audio.delta':
        return 'other', None
    if kind not in ('other', 'item_done') and not isinstance(delta_text, str):
        # delta 字段缺失/非字符串 → 当作普通事件透传
        return 'other', None
    return kind, delta_text


def _mk_responses_sse_event(parsed: dict, delta_text: str) -> str:
    """保持 Responses 事件结构，仅替换 delta 字段（已还原文本）。"""
    try:
        if not isinstance(parsed, dict):
            return 'data: ' + _jdumps(parsed) + '\n\n'
        out = dict(parsed)
        out['delta'] = delta_text
        return 'data: ' + _jdumps(out) + '\n\n'
    except Exception:
        return 'data: ' + _jdumps(parsed) + '\n\n'


def _mk_responses_flush_event(event_type: str, delta_text: str) -> str:
    """构造一个 Responses delta 事件（流末/非 delta 事件前 flush 残留用）。"""
    out = {'type': event_type, 'delta': delta_text}
    return 'data: ' + _jdumps(out) + '\n\n'


# Anthropic delta 类型 → (字段, 输出时使用的 delta.type)
_ANTHROPIC_DELTA_FIELDS = {
    'text': ('text', 'text_delta'),
    'thinking': ('thinking', 'thinking_delta'),
    'function_args': ('partial_json', 'input_json_delta'),
}
# 字段名 → delta.type（_mk_anthropic_flush_event 用）
_ANTHROPIC_FIELD_DELTA_TYPE = {
    field: dtype for _kind, (field, dtype) in _ANTHROPIC_DELTA_FIELDS.items()
}


def _anthropic_event(parsed: dict) -> tuple[str, str | None] | None:
    """识别 Anthropic Messages API SSE 事件（/v1/messages）。

    返回 (kind, delta_text)：
      kind ∈ {'text', 'thinking', 'function_args', 'block_stop', 'block_start', 'other'}
      - 'text': content_block_delta 的 text_delta → delta.text
      - 'thinking': content_block_delta 的 thinking_delta → delta.thinking
      - 'function_args': content_block_delta 的 input_json_delta → delta.partial_json
      - 'block_stop': content_block_stop（块结束，需清理跨块残留）→ delta_text=None
      - 'block_start': content_block_start（tool_use 块开始，携带工具名）→
        delta_text = tool name（非 tool_use 块为 None）
      - 'other': 其他 content_block_delta 类型（server_tool_use 等）→ delta_text=None
    非 Anthropic 事件（chat/completions、responses SSE 等）返回 None。
    注：message_start / message_delta / message_stop 等
    不含文本 delta 的事件返回 None，走整行透传（原样保留，无需还原）。
    """
    evt_type = parsed.get('type') if isinstance(parsed, dict) else None
    if evt_type == 'content_block_stop':
        # 块结束：arg_buf 中未完成的 token 前缀不可能再有后续分片，
        # 必须清理，否则下一个 input_json_delta 可能跨块拼接伪还原
        return 'block_stop', None
    if evt_type == 'content_block_start':
        # tool_use 块开始：捕获工具名供 block_stop 审计用。
        # 无 tool name（text 块等）→ 返回 None（不拦截，走透传）
        cb = parsed.get('content_block')
        if isinstance(cb, dict) and cb.get('type') == 'tool_use':
            name = cb.get('name')
            if isinstance(name, str) and name:
                return 'block_start', name
        return None
    if evt_type != 'content_block_delta':
        return None
    delta = parsed.get('delta')
    if not isinstance(delta, dict):
        return 'other', None
    dtype = delta.get('type')
    if dtype == 'text_delta' and isinstance(delta.get('text'), str):
        return 'text', delta['text']
    if dtype == 'thinking_delta' and isinstance(delta.get('thinking'), str):
        return 'thinking', delta['thinking']
    if dtype == 'input_json_delta' and isinstance(delta.get('partial_json'), str):
        return 'function_args', delta['partial_json']
    return 'other', None


def _mk_anthropic_delta_event(parsed: dict, text: str, field: str) -> str:
    """保持 Anthropic 事件结构，仅替换 delta 文本字段（已还原文本）。

    field ∈ {'text', 'thinking', 'partial_json'} 对应三种 delta 类型。
    """
    out = dict(parsed)
    try:
        out['delta'] = dict(parsed['delta'])
    except (KeyError, TypeError, AttributeError):
        out['delta'] = {}
    out['delta'][field] = text
    return 'data: ' + _jdumps(out) + '\n\n'


def _mk_anthropic_flush_event(parsed: dict, text: str, field: str) -> str:
    """构造 Anthropic content_block_delta 事件（中游/流末 flush 残留用）。"""
    delta_type = _ANTHROPIC_FIELD_DELTA_TYPE[field]
    try:
        _idx = parsed.get('index', 0) if isinstance(parsed, dict) else 0
    except AttributeError:
        _idx = 0
    out = {
        'type': 'content_block_delta',
        'index': _idx,
        'delta': {'type': delta_type, field: text},
    }
    return 'data: ' + _jdumps(out) + '\n\n'


def _strip_token_forms(content: str) -> str:
    """剥离凭据 + PII token 形态（safe 输出前清理残留 token 字符串）。

    - 凭据 token（TOKEN_STR_RE）完整形态剥离——凭据无响应期注册场景，
      幻觉/未知句柄必须清理
    - PII token（PII_TOKEN_STR_RE）完整形态**保留**——响应期注册的 token
      在还原时被保留（resp_t2p 形态匹配不还原），safe 输出前必须保留
      （8.2 修复：vault-stable-mapping spec「响应期新 token 不被还原、
      原样保留」；幻觉完整 token 由 _split_safe_hold 的 FULL_PII_TOKEN_RE
      先行 hold 分离，不会到达此函数泄漏）
    - 残缺形态（流分片边界切断的 __VG_/__PII_ 前缀）由 _strip_partials
      兜底——任何 safe 输出出口都经此函数，统一获得残缺清理
      （Round 17 R4：mid-stream safe flush / 流末残余字节全覆盖）
    """
    out = TOKEN_STR_RE.sub('', content)
    return _strip_partials(out)


def _strip_token_forms_json_aware(content: str) -> str:
    """JSON 感知的残留 token 清理：仅对字符串节点做剥离，避免破坏 \\u 转义。

    - 若 content 是合法 JSON（object/array），则 loads 后经共享 json_walk
      递归处理字符串值，逐个调用 _strip_token_forms，再 dumps 回写；
    - 非 JSON 或解析失败回退到纯文本 _strip_token_forms；
    - 9.9 (F-09): 第四处内联 _walk 收敛为共享 json_walk 薄包装（消除与
      utils/json_walk 的语义漂移：dict/list 深度语义/RecursionError 兜底/
      叶子级校验统一由共享实现负责）。
    """
    stripped = content.lstrip('\ufeff').lstrip()
    if not (stripped.startswith(('{', '['))):
        return _strip_token_forms(content)
    try:
        obj = _jloads(content.lstrip('\ufeff'))
    except Exception:
        return _strip_token_forms(content)

    try:
        if _shared_json_walk is not None:
            cleaned = _shared_json_walk(obj, _strip_token_forms, depth_limit=5)
            out = (
                _shared_jdumps(cleaned)
                if _shared_jdumps is not None
                else _jdumps(cleaned)
            )
            if _shared_validate is not None:
                return _shared_validate(content, out, 'strip_token_forms_json_aware')
            return out
        # 共享 walk 不可用：回退 plain（与旧行为一致）
        return _strip_token_forms(content)
    except Exception:
        logger.debug('_strip_token_forms_json_aware 回退', exc_info=True)
        return _strip_token_forms(content)


# 3.1 (D5) PII 尾 run 提取（与 _has_partial_pii_candidate 同口径，供
# _split_safe_hold 持有跨片切断的半截 PII；只扩展持有等待，不改检测语义）
_PII_TAIL_EMAIL_RE = _re.compile(r'([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]*)$')
_PII_TAIL_IPV4_RE = _re.compile(r'(\b\d{1,3}(?:\.\d{1,3}){0,3}\.?)$')
_PII_TAIL_IPV6_RE = _re.compile(
    r'((?<![0-9A-Za-z:.])(?:[0-9a-fA-F]{0,4}::?[0-9a-fA-F:.]*|(?:[0-9a-fA-F]{1,4}:)+[0-9a-fA-F:.]*))$',
    _re.IGNORECASE,
)
_PII_TAIL_APIKEY_RE = _re.compile(
    r'((?<![0-9A-Za-z-])(?:sk(?:-(?:p(?:r(?:o(?:j(?:-)?)?)?)?|a(?:n(?:t(?:-)?)?)?)?)?[A-Za-z0-9_-]{0,16}|gh[pous]?(?:_[A-Za-z0-9]{0,16})?|AK(?:IA?[0-9A-Z]{0,16})?))$'
)
_PII_TAIL_DIGITS_RE = _re.compile(r'(?<![\d])(\d{2,19})$')


# 3.1 完整形态判定（与 _pii.py 检测形状同口径，供持有逻辑释放用）：
# 完整形状还原时检测侧已有机会处理（命中→token 持有/还原；豁免/漏检→
# 与基线一致放行），只有不完整 run 才需持有等待后续分片。
_TAIL_COMPLETE_PHONE_RE = _re.compile(r'^(?:\+?86[\- ]?)?1[3-9]\d{9}$')
_TAIL_COMPLETE_EMAIL_RE = _re.compile(
    r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
)
_TAIL_COMPLETE_ID_RE = _re.compile(r'^\d{17}[\dXx]$')
_TAIL_COMPLETE_BANK_RE = _re.compile(r'^(?:(?:62|60|3[47])\d{11,17}|[45]\d{12,18})$')
_TAIL_COMPLETE_IPV4_RE = _re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}\.?$')
_TAIL_COMPLETE_APIKEY_RE = _re.compile(
    r'^(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|gh[pous]_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})$'
)


def _pii_tail_hold_run(content: str) -> str:
    """返回内容尾部应持有的 PII 前缀 run（无/完整形态则 ''，永不抛）。

    顺序：邮箱（含域片段）→ipv4（含尾点）→ipv6（全形态）→api_key
    （裸前缀，词边界）→纯数字（phone/id_card/bank_card 前缀）。
    完整形状直接放行（检测侧已处理；放行=基线行为，不回归）；
    仅不完整 run 持有等待后续分片。仅作用于 256 字符尾窗口。
    """
    try:
        if not content or not isinstance(content, str):
            return ''
        win = content[-256:] if len(content) > 256 else content
        m = _PII_TAIL_EMAIL_RE.search(win)
        if m:
            run = m.group(1)
            return '' if _TAIL_COMPLETE_EMAIL_RE.match(run) else run
        m = _PII_TAIL_IPV4_RE.search(win)
        if m:
            run = m.group(1)
            if len(run) >= 2:
                return '' if _TAIL_COMPLETE_IPV4_RE.match(run) else run
        m = _PII_TAIL_IPV6_RE.search(win)
        if m:
            run = m.group(1)
            try:
                import ipaddress as _ipmod

                _ipmod.IPv6Address(run)
                return ''
            except Exception:
                return run
        m = _PII_TAIL_APIKEY_RE.search(win)
        if m:
            run = m.group(1)
            return '' if _TAIL_COMPLETE_APIKEY_RE.match(run) else run
        m = _PII_TAIL_DIGITS_RE.search(win)
        if m:
            run = m.group(1)
            if (
                _TAIL_COMPLETE_PHONE_RE.match(run)
                or _TAIL_COMPLETE_ID_RE.match(run)
                or _TAIL_COMPLETE_BANK_RE.match(run)
            ):
                return ''
            return run
    except Exception:
        pass
    return ''


def _custom_tail_hold_run(content: str, extra_prefixes) -> str:
    """返回内容尾部应持有的自定义前缀 run（无则 ''，永不抛）。

    best-effort：字面 run 完整出现在尾窗口 → 自其最后一次出现处持有；
    尾部切在 run 中部 → 持有该部分 run。命中区域约束在 64 字符尾窗口内。
    """
    try:
        if not content or not extra_prefixes:
            return ''
        win = content[-64:] if len(content) > 64 else content
        base = len(content) - len(win)
        for _h in extra_prefixes:
            if not _h or not isinstance(_h, str):
                continue
            _h = _h[:64]
            if not _h:
                continue
            if _h in win:
                _idx = content.rfind(_h, base)
                if _idx >= base:
                    return content[_idx:]
            else:
                _n = min(len(_h), len(win))
                for _k in range(_n, 0, -1):
                    if win.endswith(_h[:_k]):
                        return content[len(content) - _k :]
    except Exception:
        pass
    return ''


def _split_safe_hold(
    content: str,
    active_t2p: dict,
    pii_scope=None,
    extra_prefixes=None,
    hold_pii_tail: bool = False,
) -> tuple[str, str]:
    """将累积文本分割为 (safe, hold)。

    - safe: 可安全输出（剥离行中完整 token 形态——未还原的必是幻觉/未知句柄；
      active 内的真实 token 已被 _restore 还原为明文）
    - hold: 保留到下个分片（以 __ 开头且匹配 active token 前缀）
    - pii_scope（可选）：提供 PII token 前缀集合，使 __PII_*__ 形态同样
      参与完整形态检测 / hold 判定（防 PII token 跨分片截断泄漏）
    - extra_prefixes（可选，3.1）：自定义 best-effort 前缀提示，未被检测的
      自定义值半截同样持有等待后续分片（不阻塞主链，流末放行）
    - hold_pii_tail（3.1，默认 False 即基线行为）：还原后文本尾为内置 PII
      前缀（邮箱/数字/ipv4/ipv6/api_key 半截）时持有该尾 run，防跨 data:
      切断的半截 PII 被当 safe 提前发出。调用方仅在还原无改动
      （`restored == buf`，尾部非还原产物）时置 True——还原产物（凭据/
      请求 PII 明文）形状恰似半截 PII 时不得再持有，否则流末重扫会将其
      误注册为响应期 PII（明文还原语义破坏）
    """
    if not content:
        return '', ''
    # 完整 token 形态但不在 active_t2p（LLM 幻觉/未知句柄）→ 整体 hold，
    # 防止 rfind('__') 把完整 token 拆成两段、后续分片重组泄漏 token 字符串
    m = _FULL_TOKEN_RE.search(content)
    if m:
        token_str = m.group(0)
        if token_str not in active_t2p:
            return _strip_token_forms(content[: m.start()]), token_str
    # PII 完整 token 形态（未还原的必是幻觉/未知句柄）→ 整体 hold
    if pii_scope is not None:
        m_pii = FULL_PII_TOKEN_RE.search(content)
        if m_pii:
            token_str = m_pii.group(0)
            return (
                _strip_token_forms(content[: m_pii.start()]),
                token_str,
            )
    last_us = content.rfind('__')
    if last_us >= 0:
        suffix = content[last_us:]
        maybe_prefix = any(t.startswith(suffix) for t in active_t2p)
        if pii_scope is not None:
            # PII token 前缀参与 hold 判定
            pii_tokens = set(pii_scope.pii_t2p) | set(pii_scope.resp_t2p)
            maybe_prefix = maybe_prefix or any(t.startswith(suffix) for t in pii_tokens)
        if maybe_prefix:
            return _strip_token_forms(content[:last_us]), suffix
    if hold_pii_tail:
        _ch = _custom_tail_hold_run(content, extra_prefixes)
        if _ch:
            return _strip_token_forms(content[: len(content) - len(_ch)]), _ch
        _ph = _pii_tail_hold_run(content)
        if _ph:
            return _strip_token_forms(content[: len(content) - len(_ph)]), _ph
    return _strip_token_forms(content), ''


def _sanitize_json(text: str) -> str:
    """Replace unescaped control chars within JSON string values."""
    result = []
    in_string = False
    escape = False
    for ch in text:
        if escape:
            result.append(ch)
            escape = False
            continue
        if ch == '\\':
            result.append(ch)
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            result.append(ch)
            continue
        if in_string and (ord(ch) < 0x20 or ch == '\x7f'):
            # Unescaped control char inside string → replace with escaped \\n
            result.append('\\n')
            continue
        result.append(ch)
    return ''.join(result)


def _accumulate_tool_calls(
    buf: dict[int, dict[str, str]],
    tool_calls,
) -> None:
    """累积 OpenAI chat/completions delta.tool_calls 分片（按 index 分组）。

    - tool_calls: delta.tool_calls 值（list 或 None）；None 跳过
    - 每项含 index / function.name / function.arguments 字段（缺失项跳过）
    - name 通常首个分片出现；arguments 为字符串增量分片（跨分片拼接）
    - null 值防御：function 为 None 或字段为 None 时跳过（不抛异常）
    """
    if not tool_calls or not isinstance(tool_calls, list):
        return
    for tc in tool_calls:
        if not isinstance(tc, dict):
            continue
        idx = tc.get('index')
        if idx is None or not isinstance(idx, int):
            continue
        fn = tc.get('function')
        if not isinstance(fn, dict):
            continue  # function 缺失/None → 不创建 entry（null 值防御）
        entry = buf.setdefault(idx, {'name': '', 'arguments': ''})
        _tc_id = tc.get('id')
        if isinstance(_tc_id, str) and _tc_id and not entry.get('id'):
            entry['id'] = _tc_id
        name = fn.get('name')
        if isinstance(name, str) and name:
            entry['name'] += name
        args = fn.get('arguments')
        if isinstance(args, str) and args:
            entry['arguments'] += args


def _extract_tool_calls_non_stream(
    parsed: dict,
    tail: str,
) -> list[tuple[str, str]]:
    """从非流式整包响应提取 tool calls（三协议）。

    返回 [(tool_name, args_json)]：
      - OpenAI chat/completions: choices[0].message.tool_calls[]
      - Anthropic Messages: content[].tool_use（name + input JSON 序列化）
      - Responses: output[] 中 type == 'function_call'（name + arguments）
    提取失败/结构异常返回 []（不抛异常，走透传）。
    """
    if not isinstance(parsed, dict):
        return []
    tail_norm = tail.rstrip('/')
    calls: list[tuple[str, str]] = []

    # OpenAI chat/completions
    if tail_norm.endswith('chat/completions'):
        choices = parsed.get('choices') or []
        for ch in choices:
            if not isinstance(ch, dict):
                continue
            msg = ch.get('message') or {}
            tcs = msg.get('tool_calls') or []
            for tc in tcs:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get('function') or {}
                name = fn.get('name')
                args = fn.get('arguments')
                if isinstance(name, str) and name:
                    calls.append((name, args if isinstance(args, str) else ''))
        return calls

    # Anthropic Messages
    if tail_norm.endswith('v1/messages'):
        content = parsed.get('content') or []
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get('type') != 'tool_use':
                continue
            name = block.get('name')
            inp = block.get('input')
            if isinstance(name, str) and name:
                # 非流式审计参数提取：审计语义冻结，不动序列化口径
                args = ''
                if inp is not None:
                    args = json.dumps(inp, ensure_ascii=False)  # _jdumps-whitelist
                calls.append((name, args))
        return calls

    # Responses
    if tail_norm.endswith('v1/responses'):
        output = parsed.get('output') or []
        for item in output:
            if not isinstance(item, dict):
                continue
            if item.get('type') != 'function_call':
                continue
            name = item.get('name')
            args = item.get('arguments')
            if isinstance(name, str) and name:
                calls.append((name, args if isinstance(args, str) else ''))
        return calls

    return []


# 规范化分隔符集合（design D2 skip 判定）：[-. ] 连字符、点、空格
_SEP_NORMALIZE_RE = _re.compile(r'[-. ]')


def re_sub_seps(value: str) -> str:
    """去除分隔符（[-. ]）后返回，用于还原产物规范化等价比较。"""
    return _SEP_NORMALIZE_RE.sub('', value)


class LlmMixin(AuditMixin):
    """Mixin: LLM 反向代理，脱敏/还原 + 输出审计。"""

    # ── ContextVar-backed per-request state (D2) ──
    @property
    def _pii_scope(self):
        return _pii_scope_var.get()

    @_pii_scope.setter
    def _pii_scope(self, value):
        _pii_scope_var.set(value)

    @property
    def _audit_hold_active(self):
        return _audit_hold_active_var.get()

    @_audit_hold_active.setter
    def _audit_hold_active(self, value):
        _audit_hold_active_var.set(value)

    @property
    def _audit_hold_buf(self):
        v = _audit_hold_buf_var.get()
        if v is None:
            v = []  # type: ignore[assignment]
            _audit_hold_buf_var.set(v)  # type: ignore[arg-type]
        return v

    @_audit_hold_buf.setter
    def _audit_hold_buf(self, value):
        _audit_hold_buf_var.set(value)

    @property
    def _audit_hold_bytes(self):
        return _audit_hold_bytes_var.get()

    @_audit_hold_bytes.setter
    def _audit_hold_bytes(self, value):
        _audit_hold_bytes_var.set(value)

    @property
    def _last_anthropic_tool_name(self):
        return _last_anthropic_tool_name_var.get()

    @_last_anthropic_tool_name.setter
    def _last_anthropic_tool_name(self, value):
        _last_anthropic_tool_name_var.set(value)

    @property
    def _last_responses_tool_name(self):
        return _last_responses_tool_name_var.get()

    @_last_responses_tool_name.setter
    def _last_responses_tool_name(self, value):
        _last_responses_tool_name_var.set(value)

    # ── PII 响应侧处理（还原 → 响应侧检测 → 转发）──

    def _pii_restore(
        self,
        text: str,
        active_t2p: dict,
        pii_scope,
    ) -> tuple[str, list]:
        """还原文本（凭据 + 请求级 PII），返回 (还原后文本, 还原产物区间)。

        PII 还原路径：请求级映射优先；响应期 token 形态匹配也原样保留。
        还原产物区间（restored_spans）供响应侧检测跳过——模型回显请求期
        占位符还原出的明文不得二次掩码（design D2 硬性）。
        """
        # 凭据还原（现有逻辑）
        restored = self._restore(text, active_t2p)
        # PII 请求级还原（仅还原请求期注册 token）
        restored_spans: list = []
        if pii_scope is not None:
            scope = pii_scope
            # 10.4.1 (F-SEC-02): re.sub 的 m.start() 是原串坐标，替换后
            # 文本长度变化（token 18 vs plain 11），多 token 时后续 span 若
            # 沿用原串坐标会在最终文本中错位（还原区被二次掩码/边界误放行）。
            # 用累计偏移差把原串坐标映射到最终文本坐标。
            _offset_delta = 0  # 已替换前缀的总长度变化（新 - 旧）

            def _repl_pii(m):
                nonlocal _offset_delta
                tok = m.group(0)
                if tok in scope.pii_t2p:
                    start = m.start()
                    plain = scope.pii_t2p[tok]
                    # 真 LRU：命中提升热值
                    try:
                        scope.pii_t2p.move_to_end(tok)
                        scope.pii_p2t.move_to_end(plain)
                    except (KeyError, RuntimeError):
                        pass
                    # 记录还原产物区间（原 token 位置 → 明文），坐标校正到
                    # 最终文本（替换后）
                    _final_start = start + _offset_delta
                    restored_spans.append(
                        (_final_start, _final_start + len(plain), plain),
                    )
                    _offset_delta += len(plain) - len(tok)
                    return plain
                if tok in scope.resp_t2p:
                    try:
                        scope.resp_t2p.move_to_end(tok)
                        # 同步提升 resp_p2t（通过 tok 查 plain）
                        plain_resp = scope.resp_t2p.get(tok)
                        if plain_resp is not None and plain_resp in scope.resp_p2t:
                            scope.resp_p2t.move_to_end(plain_resp)
                    except (KeyError, RuntimeError):
                        pass
                    return tok  # 响应期 token 原样保留
                # 未注册/格式不符：记审计（与 GlobalPiiTokens.restore 对齐）
                with contextlib.suppress(Exception):
                    scope._audit_malformed(tok)
                return tok

            restored = PII_TOKEN_STR_RE.sub(_repl_pii, restored)
            # 宽松形态二次审计（幻觉 token）：未命中 pii/resp 的 loose tok
            if getattr(scope, '_audit_cb', None) is not None:
                try:
                    cur_pii = set(scope.pii_t2p)
                    cur_resp = set(scope.resp_t2p)
                except RuntimeError:
                    cur_pii = set(list(scope.pii_t2p))  # noqa: C414
                    cur_resp = set(list(scope.resp_t2p))  # noqa: C414
                for m in PII_TOKEN_LOOSE_RE.finditer(restored):
                    tok = m.group(0)
                    if tok not in cur_pii and tok not in cur_resp:
                        with contextlib.suppress(Exception):
                            scope._audit_malformed(tok)
        return restored, restored_spans

    async def _pii_response_scan(
        self,
        text: str,
        restored_spans: list,
        pii_scope,
    ) -> str:
        """响应侧 PII 检测：仅跳过还原产物区间，新检测值注册实时映射。

        模型独立输出（非还原产物）的同值明文仍掩码为新占位符——
        不得因值与请求期已注册值等价而放行（design D2 硬性）。
        """
        if not getattr(self, 'pii_enabled', False) or not text:
            return text
        if not getattr(self, 'pii_response_side', True):
            return text
        if pii_scope is None:
            return text
        # 9.7 (F-07): 请求级 scan 小缓存——同一 (text, restored_spans)
        # 组合不重复跑检测（流内重复文本行/重复占位符场景）。spans 含
        # 位置元组，指纹即全量；容量 1（流内几乎每行 text 不同，大容量
        # 只会无界增长，单槽足够覆盖「重复行」热点）。
        # 10.2.1 (F-04): key 必须含 pii_scope 指纹（id + 注册版本），
        # 否则并发请求同 text 命中他 scope 的缓存，register 副作用被跳过
        # （跨会话 PII token 串扰/漏掩）。
        _scope_fp = (
            id(pii_scope),
            getattr(pii_scope, '_seq', 0) if pii_scope is not None else 0,
        )
        _cache = getattr(self, '_pii_response_scan_cache', None)
        if (
            _cache is not None
            and _cache[0] == _scope_fp
            and _cache[1] == text
            and _cache[2] == restored_spans
        ):
            return _cache[3]
        _result = await self._pii_response_scan_uncached(
            text, restored_spans, pii_scope
        )
        self._pii_response_scan_cache = (_scope_fp, text, restored_spans, _result)
        return _result

    async def _pii_response_scan_uncached(
        self,
        text: str,
        restored_spans: list,
        pii_scope,
    ) -> str:
        """响应侧检测未缓存实现（9.7 拆分）：原 _pii_response_scan 主体。"""
        if not getattr(self, 'pii_enabled', False) or not text:
            return text
        if not getattr(self, 'pii_response_side', True):
            return text
        if pii_scope is None:
            return text
        # 检测（跳过还原产物区间）—— 响应侧同走 is_chat_tail 守门，需透传 tail
        _tail_for_sample = None
        try:
            from _metrics import _req_pii_var as _rpv2  # type: ignore

            _ctx2 = _rpv2.get()
            if isinstance(_ctx2, dict):
                _tail_for_sample = _ctx2.get('tail')
        except Exception:
            pass
        hits = await self._pii_detector.scan(
            text,
            credential_p2t=getattr(self, 'pwd_to_token', None),
            tail=_tail_for_sample,
        )
        if not hits:
            return text
        # 过滤：命中值若完全落在还原产物区间内 → 跳过（9.8 F-08: 位置区间
        # 重叠比较而非值级等价 —— 模型独立输出的同值明文（不同位置）仍掩码，
        # 与 docstring「模型独立输出仍掩码」一致）
        # 10.3.1 (F-05/F-SEC-01): 按出现位置逐段判定，仅跳过落在 span 内的
        # 出现；同值多处（一还原一独立）时独立处必须仍掩码——value 级去重
        # 粒度会让「任一重叠即整值跳过」漏掩独立输出。
        filtered: list[tuple[str, str]] = []
        _restored_spans = sorted(restored_spans)  # 按 start 排序便于二分
        for typ, value in hits:
            # 找 value 在 text 中的全部出现位置，与还原产物区间比对
            is_restored_all = True
            _search_from = 0
            while True:
                _pos = text.find(value, _search_from)
                if _pos < 0:
                    break
                _overlaps = False
                for _s, _e, _plain in _restored_spans:
                    # 区间重叠：命中起点落在还原产物 span 内（或其内包含 span）
                    if _pos < _e and _pos + len(value) > _s:
                        _overlaps = True
                        break
                if not _overlaps:
                    is_restored_all = False
                    break
                _search_from = _pos + 1
            if not is_restored_all:
                filtered.append((typ, value))
        if not filtered:
            return text
        # 新检测值注册实时请求级映射（响应期）并替换
        # 10.3.1: 位置感知替换——仅替换不在 span 内的出现，span 内的
        # 还原产物保留明文（避免二次掩码）
        seen: set[str] = set()
        items = []
        for typ, value in filtered:
            if value in seen:
                continue
            seen.add(value)
            items.append((len(value), typ, value))
        items.sort(key=lambda x: x[0], reverse=True)
        # 构建替换区间：对每个 value 找出不在 span 内的出现
        _repl_ranges: list[tuple[int, int, str, str]] = []
        for _, typ, value in items:
            token = await pii_scope.register(value, response_side=True)
            if token == value:
                continue
            _search_from = 0
            while True:
                _pos = text.find(value, _search_from)
                if _pos < 0:
                    break
                _in_span = any(
                    _pos < _e and _pos + len(value) > _s
                    for _s, _e, _plain in _restored_spans
                )
                if not _in_span:
                    _repl_ranges.append((_pos, _pos + len(value), value, token))
                _search_from = _pos + 1
        if not _repl_ranges:
            return text
        # 按位置倒序替换，避免偏移漂移
        _repl_ranges.sort(key=lambda x: x[0], reverse=True)
        for _start, _end, _val, _tok in _repl_ranges:
            text = text[:_start] + _tok + text[_end:]
        return text

    def _pii_active(self) -> bool:
        """当前请求是否有活跃 PII 作用域（PII 启用且已建 scope）。"""
        return bool(getattr(self, 'pii_enabled', False)) and bool(
            getattr(self, '_pii_scope', None)
        )

    def _pii_scope_or_none(self):
        """返回当前请求 PII scope（无则 None）。"""
        return getattr(self, '_pii_scope', None)

    def _pii_detector_or_none(self):
        """返回 PII 检测器（自定义前缀提示/计数用；兼容 scope 直挂同名方法的单测替身）。

        优先 `self._pii_detector`，回退自带同名方法的 `_pii_scope`；
        均无则 None（永不抛）。
        """
        try:
            det = getattr(self, '_pii_detector', None)
            if det is not None and callable(getattr(det, 'partial_prefix_hints', None)):
                return det
            scope = self._pii_scope_or_none()
            if scope is not None and callable(
                getattr(scope, 'partial_prefix_hints', None)
            ):
                return scope
        except Exception:
            pass
        return None

    def _extra_prefixes(self, tail: str) -> list[str] | None:
        """3.1 自定义 best-effort 前缀提示（永不抛；无 detector/无命中→None）。"""
        try:
            det = self._pii_detector_or_none()
            fn = getattr(det, 'partial_prefix_hints', None) if det is not None else None
            if callable(fn):
                res = fn(tail)
                if isinstance(res, list) and res:
                    return [h for h in res if isinstance(h, str) and h][:64]
        except Exception:
            pass
        return None

    def _count_custom_other_miss(self) -> None:
        """3.1 自定义候选未命中计数：经 `_count_detected` 走 `sanitize_kind` 归一口径。

        仅在自定义规则已加载且超长透传时调用（主链不阻塞，只计数）。
        永不抛异常（异常→跳过计数，不阻塞主链）。
        """
        try:
            det = self._pii_detector_or_none()
            if det is None:
                return
            if not (
                getattr(det, 'custom_patterns', None)
                or getattr(det, 'dict_entries', None)
            ):
                return
            fn = getattr(det, '_count_detected', None)
            if callable(fn):
                fn([('custom_other', '__candidate_miss__')])
        except Exception:
            pass

    # ── 输出审计钩子（Batch 5：AuditMixin 策略引擎 + 阻断处置）──

    async def _audit_openai_tool_calls(
        self,
        tool_calls_buf: dict[int, dict[str, str]],
        active_t2p: dict,
    ) -> list[str]:
        """审计 OpenAI chat/completions 累积的 tool calls（finish_reason 触发）。

        审计读取**掩码前原始 args**（design D3 审计对抗性）——即累积的
        arguments 原文，不含 PII 占位符（PII 掩码在 flush 阶段）。

        返回：需要注入的拒绝消息 SSE 行列表（deny verdict 时生成，
        由调用方在 tool_calls 事件前 flush；allow 返回空列表）。
        """
        injections: list[str] = []
        if not tool_calls_buf or not self.audit_enabled():
            return injections
        for idx in sorted(tool_calls_buf):
            entry = tool_calls_buf[idx]
            name = entry.get('name', '')
            args = entry.get('arguments', '')
            if not name:
                continue
            verdict = await self.audit_tool_call(name, args)
            if verdict == 'deny':
                if self.audit_mode == 'approve':
                    # 审批模式：发起 Matrix 审批；approved → 放行（不注入拒绝）
                    result = await self._request_audit_approval(name, args)
                    if result == 'approved':
                        # 审批通过：补记审计日志（verdict=allow, note=approved）
                        await self._audit_log_event('allow', name, args, '', '审批通过')
                        continue
                    # rejected/expired/failed → 注入拒绝
                    await self._audit_log_event('deny', name, args, '', f'审批{result}')
                injections.append(self._build_block_event())
        return injections

    async def _request_audit_approval(self, name: str, args_json: str) -> str:
        """审批模式：发起 Matrix ✅/❎ 审批，返回 'approved'/'rejected'/'expired'/'failed'。

        design D4：
        - 审批消息含工具名 + 先脱敏后截断的参数摘要（redact_summary）+ 超时提示
        - 超时默认拒绝（AUDIT_TIMEOUT）
        - _ask 返回 None（发送失败）→ 'failed'（调用方按 rejected 处置 + 清理）
        """
        summary = redact_summary(args_json)
        timeout = getattr(self, 'audit_timeout', 90)
        _mc = getattr(self, '_metrics_collector', None)

        def _count_approval(result: str) -> None:
            """audit_approval_result 分布（内存计数，重启归零）。"""
            if _mc is not None:
                _mc.incr_sync_audit_approval(result)

        if not hasattr(self, '_ask'):
            logger.error('审批模式需要 MatrixMixin（_ask 不可用）')
            return 'failed'
        # seq 递增加锁（若存在 _lock 则用，否则直接递增，兼容测试桩）
        _lock = getattr(self, '_lock', None)
        if _lock is not None and hasattr(_lock, '__aenter__'):
            async with _lock:
                req_id = f'audit-{getattr(self, "_audit_pending_seq", 0)}'
                self._audit_pending_seq = getattr(self, '_audit_pending_seq', 0) + 1
        else:
            req_id = f'audit-{getattr(self, "_audit_pending_seq", 0)}'
            self._audit_pending_seq = getattr(self, '_audit_pending_seq', 0) + 1
        _created = _audit_created_ids_var.get()
        if isinstance(_created, list):
            _created.append(req_id)
        evt = asyncio.Event()
        entry = {
            'name': name,
            'args': args_json,
            'approved': None,
            'event': evt,
        }
        self._audit_approval_pending[req_id] = entry
        # 10.7.1 (F-07): 审批挂起期即使无任何 SSE 输出也要保活——
        # tool_calls 审批窗口（缓冲区空、_tracked_write 不触发）若无
        # keepalive 任务，hermes inactivity 120s 会判定断流。这里直接
        # 启动独立保活协程（读 _audit_approval_pending，空即退出）。
        _ka_resp = getattr(self, '_audit_keepalive_resp', None)
        if _ka_resp is not None and not getattr(self, '_audit_keepalive_task', None):

            async def _audit_ka():
                try:
                    while getattr(self, '_audit_approval_pending', None):
                        await asyncio.sleep(KEEPALIVE_INTERVAL)
                        if not getattr(self, '_audit_approval_pending', None):
                            break
                        try:
                            await _ka_resp.write(b': keepalive\n\n')
                            await _ka_resp.drain()
                        except Exception:
                            break
                except asyncio.CancelledError:
                    pass

            self._audit_keepalive_task = asyncio.create_task(_audit_ka())
        try:
            msg_id = await self._ask(
                f'⚠️ 工具调用待审批: {name}\n参数摘要: {summary}\n'
                f'点 ✅ 批准 或 ❎ 拒绝（{timeout}s 超时默认拒绝）',
            )
        except Exception as exc:
            # 8.3 修复（F-03）：_ask 抛异常（非返回 None）时统一清理，
            # 防孤儿 pending 条目与 created_ids 残留（跨请求错误关联）
            logger.error(
                '审计审批发送异常: %s req_id=%s → failed: %s',
                name,
                req_id,
                exc,
            )
            self._audit_approval_pending.pop(req_id, None)
            _created = _audit_created_ids_var.get()
            if isinstance(_created, list) and req_id in _created:
                _created.remove(req_id)
            _count_approval('failed')
            return 'failed'
        logger.info(
            '审计审批已发送: %s req_id=%s msg_id=%s timeout=%ds 摘要=%.80s',
            name,
            req_id,
            str(msg_id)[:12] if msg_id else 'None',
            timeout,
            summary,
        )
        if msg_id is None:
            # 发送失败 → 立即按 rejected 处置 + 清理 pending
            logger.error('审计审批发送失败: %s req_id=%s → failed', name, req_id)
            self._audit_approval_pending.pop(req_id, None)
            _created = _audit_created_ids_var.get()
            if isinstance(_created, list) and req_id in _created:
                _created.remove(req_id)
            _count_approval('failed')
            return 'failed'
        self._audit_approval_msgs[msg_id] = req_id
        logger.info('审计审批等待中: %s req_id=%s msg_id=%s', name, req_id, msg_id)
        try:
            await asyncio.wait_for(evt.wait(), timeout=timeout)
        except TimeoutError:
            logger.warning(
                '审计审批超时: %s req_id=%s %ds → expired', name, req_id, timeout
            )
            self._audit_approval_pending.pop(req_id, None)
            self._audit_approval_msgs.pop(msg_id, None)
            _created = _audit_created_ids_var.get()
            if isinstance(_created, list) and req_id in _created:
                _created.remove(req_id)
            _count_approval('expired')
            return 'expired'
        except Exception:
            # 8.3：等待期间异常（event 被异常置位等）同样清理
            logger.exception('审计审批等待异常: %s req_id=%s', name, req_id)
            self._audit_approval_pending.pop(req_id, None)
            self._audit_approval_msgs.pop(msg_id, None)
            _created = _audit_created_ids_var.get()
            if isinstance(_created, list) and req_id in _created:
                _created.remove(req_id)
            _count_approval('failed')
            return 'failed'
        # reaction 已到达
        ap = self._audit_approval_pending.pop(req_id, None)
        self._audit_approval_msgs.pop(msg_id, None)
        _created = _audit_created_ids_var.get()
        if isinstance(_created, list) and req_id in _created:
            _created.remove(req_id)
        if ap and ap.get('approved') is True:
            logger.info('审计审批结果: %s req_id=%s → approved', name, req_id)
            _count_approval('approved')
            return 'approved'
        logger.warning('审计审批结果: %s req_id=%s → rejected', name, req_id)
        _count_approval('rejected')
        return 'rejected'

    def _build_block_event(self) -> str:
        """构造 OpenAI chat/completions 阻断拒绝消息 SSE 行。

        design D4：无 tool_calls 的 assistant content，finish_reason: stop——
        客户端按普通助手回复处理，不会尝试执行工具。
        """
        payload = {
            'choices': [
                {
                    'index': 0,
                    'delta': {'role': 'assistant', 'content': BLOCK_MESSAGE},
                    'finish_reason': 'stop',
                }
            ]
        }
        return f'data: {_jdumps(payload)}\n\n'

    def _build_block_event_anthropic(self) -> str:
        """构造 Anthropic 阻断拒绝消息 SSE 行（content_block + message_delta）。"""
        lines = []
        lines.append(
            'data: '
            + _jdumps(
                {
                    'type': 'content_block_delta',
                    'index': 0,
                    'delta': {'type': 'text_delta', 'text': BLOCK_MESSAGE},
                },
            )
            + '\n\n'
        )
        lines.append(
            'data: '
            + _jdumps(
                {
                    'type': 'message_delta',
                    'delta': {'stop_reason': 'end_turn'},
                    'usage': {'output_tokens': 1},
                },
            )
            + '\n\n'
        )
        return ''.join(lines)

    def _build_block_event_responses(self) -> str:
        """构造 Responses 阻断拒绝消息 SSE 行（output_text.delta + completed）。"""
        lines = []
        lines.append(
            'data: '
            + _jdumps(
                {
                    'type': 'response.output_text.delta',
                    'item_id': 'blocked',
                    'output_index': 0,
                    'content_index': 0,
                    'delta': BLOCK_MESSAGE,
                },
            )
            + '\n\n'
        )
        lines.append(
            'data: '
            + _jdumps(
                {
                    'type': 'response.completed',
                    'response': {
                        'id': 'blocked',
                        'status': 'completed',
                        'output': [
                            {
                                'type': 'message',
                                'role': 'assistant',
                                'content': [
                                    {'type': 'output_text', 'text': BLOCK_MESSAGE}
                                ],
                            }
                        ],
                    },
                },
            )
            + '\n\n'
        )
        return ''.join(lines)

    def _build_truncated_event_responses(self) -> str:
        """构造 Responses 截断合成终止事件（failed 避免下游空体）。"""
        lines = []
        lines.append(
            'data: '
            + _jdumps(
                {
                    'type': 'response.output_text.delta',
                    'item_id': 'truncated',
                    'output_index': 0,
                    'content_index': 0,
                    'delta': TRUNCATED_MESSAGE,
                },
            )
            + '\n\n'
        )
        lines.append(
            'data: '
            + _jdumps(
                {
                    'type': 'response.failed',
                    'response': {
                        'id': 'truncated',
                        'status': 'failed',
                        'error': {
                            'message': 'stream truncated: missing terminal event',
                            'type': 'server_error',
                        },
                    },
                },
            )
            + '\n\n'
        )
        return ''.join(lines)

    async def _pii_response_process(
        self,
        text: str,
        active_t2p: dict,
    ) -> str:
        """统一响应侧文本处理：还原（凭据+请求级 PII）→ 响应侧检测 → 输出。

        - PII 未启用/无 scope：等价原 _restore 行为
        - PII 启用：先还原请求级 PII token（占位符→明文，还原产物区间
          标记），再对还原后文本做响应侧 PII 检测（跳过还原产物区间，
          新检测值注册响应期映射并替换为占位符）
        """
        scope = self._pii_scope_or_none()
        if scope is None:
            return self._restore(text, active_t2p)
        restored, restored_spans = self._pii_restore(text, active_t2p, scope)
        return await self._pii_response_scan(restored, restored_spans, scope)

    async def _pii_response_process_json_aware(
        self,
        text: str,
        active_t2p: dict,
        parsed_obj=None,
    ) -> str:
        """JSON 感知的响应侧处理：仅对字符串节点做还原+检测，避免破坏 \\u 转义。

        - 若 text 是合法 JSON（object/array），则 loads 后递归 walk 字符串值，
          逐个调用 _pii_restore + _pii_response_scan，再 dumps 回写（orjson 优先）；
        - 非 JSON 或解析失败回退到纯文本 _pii_response_process；
        - 叶字符串若本身为 JSON 文本（BOM 剥离后为 { / [ 且可解析为 dict/list），
          则对内层同 walk 后 dumps，失败回退 plain；
        - 叶子级：仅当还原后值变化时校验，失败仅回退该叶子（C+A 方案）。
        - C 方案：不再按 len 回退 plain。
        - 8.10 优化（F-11）：`parsed_obj` 传入调用方已解析的对象（主循环
          `json.loads(payload)` 的结果），跳过首层二次 loads。
        """
        stripped = text.lstrip('\ufeff').lstrip()
        if not (stripped.startswith(('{', '['))):
            return await self._pii_response_process(text, active_t2p)
        if parsed_obj is None:
            try:
                obj = _jloads(text.lstrip('\ufeff'))
            except Exception:
                return await self._pii_response_process(text, active_t2p)
        else:
            obj = parsed_obj
        scope = self._pii_scope_or_none()
        # ── D1 thin wrapper: 优先复用共享 walk（utils/json_walk）──
        if _shared_json_walk_async is not None and isinstance(obj, (dict, list)):  # type: ignore[truthy-function]

            async def _shared_leaf(s: str) -> str:  # type: ignore[no-redef]
                if scope is None:
                    return self._restore(s, active_t2p)
                restored, spans = self._pii_restore(s, active_t2p, scope)
                return await self._pii_response_scan(restored, spans, scope)

            try:
                walked = await _shared_json_walk_async(obj, _shared_leaf, depth_limit=5)  # type: ignore
                # 9.6 (F-06): 外层出口统一 _shared_validate 校验（tasks 6.1
                # 声称三处统一但 _llm 响应侧漏接；original 合法 output 非法
                # 时回退原串，与 _token/_pii 包装一致）
                # _validate_json_roundtrip 返回 str（失败回退 original，成功返回 output）
                _out = _jdumps(walked)
                if _shared_validate is not None:
                    return _shared_validate(text, _out, 'llm_response_json_aware')
                return _out
            except Exception:
                pass

        async def _walk(node, path: str = '$', _depth: int = 0):
            if _depth > 5:
                if isinstance(node, str):
                    if scope is None:
                        new_s = self._restore(node, active_t2p)
                    else:
                        restored, spans = self._pii_restore(node, active_t2p, scope)
                        new_s = await self._pii_response_scan(restored, spans, scope)
                    if new_s != node:
                        try:
                            _jdumps(new_s)
                        except Exception as exc:
                            logger.warning(
                                'llm response leaf broke, fallback leaf: path=%s error=%s leaf_preview=%r new_preview=%r',
                                path,
                                exc,
                                node[:500],
                                new_s[:500],
                            )
                            return node
                    return new_s
                return node
            if isinstance(node, str):
                # 嵌套 JSON 字符串递归（tool_calls.arguments 等）
                inner_stripped = node.lstrip('\ufeff').strip()
                if inner_stripped.startswith(('{', '[')):
                    try:
                        inner = _jloads(inner_stripped)
                        if isinstance(inner, (dict, list)):
                            walked = await _walk(inner, f'{path}→$.inner', _depth + 1)
                            return _jdumps(walked)
                    except Exception:
                        pass
                if scope is None:
                    # 无 PII：仅凭据还原
                    new_s = self._restore(node, active_t2p)
                else:
                    restored, spans = self._pii_restore(node, active_t2p, scope)
                    new_s = await self._pii_response_scan(restored, spans, scope)
                if new_s != node:
                    try:
                        _jdumps(new_s)
                    except Exception as exc:
                        logger.warning(
                            'llm response leaf broke, fallback leaf: path=%s error=%s leaf_preview=%r new_preview=%r',
                            path,
                            exc,
                            node[:500],
                            new_s[:500],
                        )
                        return node
                return new_s
            if isinstance(node, dict):
                out = {}
                for k, v in node.items():
                    out[k] = await _walk(v, f'{path}.{k}', _depth)
                return out
            if isinstance(node, list):
                return [
                    await _walk(x, f'{path}[{i}]', _depth) for i, x in enumerate(node)
                ]
            return node

        try:
            new_obj = await _walk(obj, path='$')
            # 9.6 (F-06): fallback 路径同样外层校验
            _out2 = _jdumps(new_obj)
            if _shared_validate is not None:
                return _shared_validate(text, _out2, 'llm_response_json_aware')
            return _out2
        except Exception:
            logger.debug('_pii_response_process_json_aware 回退', exc_info=True)
            return await self._pii_response_process(text, active_t2p)

    async def _pii_process_sse_line(
        self, line: str, active_t2p: dict, parsed_obj=None
    ) -> str:
        """SSE 行的 JSON-aware 处理：剥离 data: 前缀后对 payload 做 JSON-aware。

        - 对 data: {JSON} 形态：payload = split(":",1)[1].lstrip(" \t") 后，
          对 payload.lstrip('\ufeff').strip() 判空 / "[DONE]" 早退，
          非 { / [ 开头回退 plain，否则 payload 走
          _pii_response_process_json_aware（含嵌套与 BOM）。
        - fast path（active_t2p==0 且无 PII/审计）由调用方守门，本 helper
          不再二次守门；对非 data: 前缀行直接回退 plain。
        - 8.10 优化（F-11）：`parsed_obj` 传调用方已 `json.loads` 的结果，
          跳过二次 loads（慢链主循环复用）。
        - 1.2 (D2 逐行独立)：多行块每 `data:` 行独立 `loads` 解析，
          `parsed_obj` 仅在块内恰好一行 `data:` 行时复用（调用方已解析
          该行 payload），多 `data:` 行时一律独立解析不再跨行复用；
          还原失败单行回退 plain 不影响整块其余行。
        - `event:/id:/retry:` 行与 `:` 注释行原样保留（不走 plain 还原，
          防事件名被 `_strip_partials` 改写）；单行非 `data:` 前缀亦原样
          返回；`[DONE]`/空行早退按单行语义（返回原行）。
        """
        # 多行 SSE 块（event:/id: 前缀 + data: 行）逐行处理
        if '\n' in line:
            parts = line.split('\n')
            # 块内 data 行计数：仅单 data 行时可复用调用方 parsed_obj，
            # 多 data 行一律独立解析（防跨行复用错配）。
            _data_count = sum(1 for _p in parts if _p.strip().startswith('data:'))
            _reuse_obj = parsed_obj if _data_count == 1 else None
            out_parts = []
            for part in parts:
                stripped = part.strip()
                if not stripped:
                    continue
                if stripped.startswith('data:'):
                    # data 行走 JSON-aware（单行失败回退 plain，不影响其余行）
                    try:
                        payload = stripped.split(':', 1)[1].lstrip(' \t')
                    except Exception:
                        payload = stripped
                    stripped_payload = payload.lstrip('\ufeff').strip()
                    if stripped_payload in ('', '[DONE]'):
                        out_parts.append(part)
                    elif not stripped_payload.startswith(('{', '[')):
                        out_parts.append(
                            await self._pii_response_process(stripped, active_t2p)
                        )
                    else:
                        try:
                            payload_aware = await self._pii_response_process_json_aware(
                                payload, active_t2p, parsed_obj=_reuse_obj
                            )
                            out_parts.append('data: ' + payload_aware)
                        except Exception:
                            logger.debug(
                                '_pii_process_sse_line 多行块 data 回退',
                                exc_info=True,
                            )
                            out_parts.append(
                                await self._pii_response_process(stripped, active_t2p)
                            )
                else:
                    # event:/id:/retry:/注释等非 data 行原样保留（不进还原）
                    out_parts.append(part)
            return '\n'.join(out_parts)
        if not line.lstrip().startswith('data:'):
            # 单行非 data: 前缀（event:/id:/retry:/注释/空行）原样返回
            return line
        # 统一剥离前缀（含 data:[DONE] 无空格与 data:  多空格）
        try:
            payload = line.split(':', 1)[1].lstrip(' \t')
        except Exception:
            return await self._pii_response_process(line, active_t2p)
        stripped_payload = payload.lstrip('\ufeff').strip()
        if stripped_payload in ('', '[DONE]'):
            return line
        if not stripped_payload.startswith(('{', '[')):
            return await self._pii_response_process(line, active_t2p)
        try:
            payload_aware = await self._pii_response_process_json_aware(
                payload, active_t2p, parsed_obj=parsed_obj
            )
            return 'data: ' + payload_aware
        except Exception:
            logger.debug('_pii_process_sse_line 回退', exc_info=True)
            return await self._pii_response_process(line, active_t2p)

    # ── Anthropic Messages API SSE 事件处理 ──

    async def _flush_anthropic_buf(
        self,
        write,
        parsed: dict,
        field: str,
        buf: str,
        active_t2p: dict,
        keep_pending: bool = True,
    ) -> str:
        """flush 单个 Anthropic 缓冲：还原 → safe/pending 分割 → 输出 safe。

        - keep_pending=True（中游）：返回保留的 pending（不完整 token 前缀，
          等待后续分片）；safe 中无法 hold 的残缺 token 形态被 _PARTIAL_TOKEN_RE 清理
        - keep_pending=False（流末）：不保留 pending，所有 partial 形态清理后
          输出残余（如有）
        - PII 启用（self._pii_active）：执行「还原 → 响应侧检测 → 转发」
          顺序（design D2），_split_safe_hold 携带 pii_scope
        """
        pii_scope = self._pii_scope_or_none()
        if not buf:
            return ''
        # JSON-aware: 覆盖 partial_json 等 stringified JSON 场景（p@ss"quote/\u 等特殊字符），
        # 增量片段为不完整 JSON 时 json.loads 失败自动回退 plain，行为等价
        restored = await self._pii_response_process_json_aware(buf, active_t2p)
        if not keep_pending:
            restored = _strip_partials(restored)
            if not restored:
                return ''
            try:
                await write(
                    _mk_anthropic_flush_event(parsed, restored, field).encode('utf-8')
                )
            except SSE_CLIENT_GONE:
                logger.debug('SSE 残余写入失败')
            return ''
        safe, pending = _split_safe_hold(restored, active_t2p, pii_scope)
        if safe:
            safe = _strip_partials(safe)
        if safe:
            try:
                await write(
                    _mk_anthropic_flush_event(parsed, safe, field).encode('utf-8')
                )
            except SSE_CLIENT_GONE:
                logger.debug('SSE 残余写入失败')
        return pending

    async def _resolve_anthropic_hold(
        self,
        write,
        active_t2p: dict,
        line: str,
        content_buf: str,
        reasoning_buf: str,
        arg_buf: str,
    ) -> None:
        """挂起结束（block_stop 到达）：完整审计 + 审批处置。

        design D4 终态表：
        - 预检误判（完整审计 allow）→ 恢复续传：缓冲行 + block_stop 原样放行
        - deny + approve 模式 → Matrix 审批；approved → 放行；其余 → 拒绝
        - deny + block 模式 → 注入拒绝 + 终止事件，缓冲丢弃
        """
        name = self._last_anthropic_tool_name or ''
        args = arg_buf
        verdict = await self.audit_tool_call(name, args)
        if verdict == 'allow':
            # 预检误判：完整审计通过 → 恢复续传（缓冲行 + block_stop 放行）
            await self._release_hold(write, active_t2p, extra_line=line)
        else:
            result = 'rejected'
            if self.audit_mode == 'approve':
                result = await self._request_audit_approval(name, args)
            if result == 'approved':
                await self._release_hold(write, active_t2p, extra_line=line)
            else:
                await self._reject_anthropic_hold(write, active_t2p)
        # 清理挂起状态
        self._audit_hold_active = False
        self._audit_hold_buf = []
        self._audit_hold_bytes = 0
        self._last_anthropic_tool_name = None

    async def _release_hold(
        self, write, active_t2p: dict, extra_line: str | None = None
    ) -> None:
        """放行挂起缓冲（approved / 预检误判）。

        design D4：已 flush 部分不可撤回、不得重复拼接；缓冲行按原序放行，
        均经 _pii_response_process（响应侧 PII 掩码在 flush 阶段）。
        """
        buf = getattr(self, '_audit_hold_buf', [])
        for line in buf:
            try:
                await write(
                    (
                        await self._pii_process_sse_line(line, active_t2p) + '\n\n'
                    ).encode('utf-8')
                )
            except SSE_CLIENT_GONE:
                logger.debug('SSE 挂起放行写入失败')
                break
        if extra_line:
            try:
                await write(
                    (
                        await self._pii_process_sse_line(extra_line, active_t2p)
                        + '\n\n'
                    ).encode('utf-8')
                )
            except SSE_CLIENT_GONE:
                logger.debug('SSE 挂起终止写入失败')

    async def _reject_anthropic_hold(self, write, active_t2p: dict) -> None:
        """拒绝挂起（rejected/expired/failed/超限）：注入拒绝 + 终止事件，缓冲丢弃。

        design D4：挂起期间缓冲的 content 一律丢弃（拒绝后不再放行）。
        """
        # 丢弃缓冲（含未 flush 的参数残余）+ 解除挂起（后续事件正常转发）
        self._audit_hold_buf = []
        self._audit_hold_bytes = 0
        self._audit_hold_active = False
        self._last_anthropic_tool_name = None
        try:
            await write(self._build_block_event_anthropic().encode('utf-8'))
        except SSE_CLIENT_GONE:
            logger.debug('SSE 挂起拒绝注入失败')

    async def _handle_anthropic_event(
        self,
        write,
        parsed: dict,
        line: str,
        active_t2p: dict,
        content_buf: str,
        reasoning_buf: str,
        arg_buf: str,
    ) -> tuple[str, str, str]:
        """处理单个 Anthropic Messages API 事件，返回更新后的 (content_buf, reasoning_buf, arg_buf)。

        - content_block_delta 文本事件（text_delta / thinking_delta / input_json_delta）：
          累积 → _restore → safe/pending 分割 → 保持 Anthropic 格式输出已还原片段
        - 其他 content_block_delta（server_tool_use 等）：flush 各缓冲 safe 部分
          （pending 保留等待后续分片，未完成的 token 前缀由流末清理），再原样透传
        """
        event = _anthropic_event(parsed)
        if event is None:  # pragma: no cover — 调用方已保证是 Anthropic 事件
            await write(
                (await self._pii_process_sse_line(line, active_t2p) + '\n\n').encode(
                    'utf-8'
                )
            )
            return content_buf, reasoning_buf, arg_buf
        kind, delta_text = event

        # ── 审计挂起状态（design D4：verdict 前暂停 flush）──
        # 预检命中后：所有事件行缓冲（不 write），block_stop 到达时统一处置
        if getattr(self, '_audit_hold_active', False):
            if kind == 'block_stop':
                # 挂起结束：完整审计 + 审批处置
                await self._resolve_anthropic_hold(
                    write,
                    active_t2p,
                    line,
                    content_buf,
                    reasoning_buf,
                    arg_buf,
                )
                return content_buf, reasoning_buf, ''
            # 挂起期间参数 delta 仍须累积（block_stop 审计读完整参数）
            if kind == 'function_args' and delta_text is not None:
                arg_buf += delta_text
            # 缓冲超限 → fail-closed（design D4：超限按 rejected 处置）
            if (
                len(line.encode('utf-8')) + getattr(self, '_audit_hold_bytes', 0)
                > self.audit_hold_max_bytes
            ):
                await self._reject_anthropic_hold(write, active_t2p)
                return content_buf, reasoning_buf, arg_buf
            self._audit_hold_buf.append(line)
            self._audit_hold_bytes = getattr(self, '_audit_hold_bytes', 0) + len(
                line.encode('utf-8')
            )
            return content_buf, reasoning_buf, arg_buf

        if kind == 'block_stop':
            # 工具调用块结束：arg_buf 中未完成的 token 前缀不可能再有
            # 后续分片（token 不会跨两个 tool_use block），清空防伪还原
            # （content/reasoning 保留 pending，由流末统一清理）
            # 审计触发点：读取掩码前原始完整参数（design D3 审计对抗性）
            # 6.6 攒整段刷新：单次 json_aware walk
            # F-12 合并：arg_buf 即原始参数累积器（与旧 _audit_arg_accum 同源），
            # 审计必须发生在 json_aware 还原/清空之前
            if arg_buf and self.audit_enabled():
                name = self._last_anthropic_tool_name or ''
                verdict = await self.audit_tool_call(name, arg_buf)
                if verdict == 'deny':
                    if self.audit_mode == 'approve':
                        # 审批模式：发起 Matrix 审批；approved → 放行（不注入拒绝）
                        result = await self._request_audit_approval(name, arg_buf)
                        if result == 'approved':
                            verdict = 'allow'
                    if verdict == 'deny':
                        # 阻断：注入拒绝消息 + block_stop 终止事件（design D4 防 dangling）
                        await write(self._build_block_event_anthropic().encode('utf-8'))
                        # 2.1 攒整段：deny 丢弃残缺参数，清空后跳过下方单次 flush
                        arg_buf = ''
                        self._last_anthropic_tool_name = None
            if arg_buf:
                try:
                    restored_arg = await self._pii_response_process_json_aware(
                        arg_buf, active_t2p
                    )
                    restored_arg = _strip_partials(restored_arg)
                    if restored_arg:
                        # 10.14 (API-SPEC): 用 _mk_anthropic_flush_event 构造
                        # content_block_delta 事件（原 _mk_anthropic_delta_event
                        # 访问 parsed['delta']——block_stop 事件无 delta 字段，
                        # KeyError 被吞 → delta 事件静默丢失，规范破坏）。
                        # pending 中对应 event 行由主循环 block_stop 分支清理。
                        await write(
                            _mk_anthropic_flush_event(
                                parsed, restored_arg, 'partial_json'
                            ).encode('utf-8')
                        )
                except Exception:
                    pass
                arg_buf = ''
            self._last_anthropic_tool_name = None
            await write(
                (await self._pii_process_sse_line(line, active_t2p) + '\n\n').encode(
                    'utf-8'
                )
            )
            return content_buf, reasoning_buf, ''

        if kind == 'block_start':
            # tool_use 块开始：记录工具名（block_stop 审计用）
            if delta_text:
                self._last_anthropic_tool_name = delta_text
            await write(
                (await self._pii_process_sse_line(line, active_t2p) + '\n\n').encode(
                    'utf-8'
                )
            )
            return content_buf, reasoning_buf, arg_buf

        if kind in ('text', 'thinking', 'function_args'):
            if delta_text is None:  # pragma: no cover — 识别器保证 delta 事件携带 str
                return content_buf, reasoning_buf, arg_buf
            # 6.3/6.6: 文本 delta 统一 CRLF 归一，工具参数攒整段不即时 json_aware
            if kind == 'function_args':
                # 6.6 攒整段：仅累积，不每 delta 即 json_aware/切片（防跨行泄漏）
                arg_buf += delta_text
                # 2.1 超限 fail-closed：复用 SSE_MAX_BUF=1MB，丢弃累积参数 + 拒绝处置
                if len(arg_buf) > SSE_MAX_BUF:
                    logger.warning(
                        'Anthropic 参数累积超限(%d>1MB)，丢弃并拒绝', len(arg_buf)
                    )
                    arg_buf = ''
                    self._last_anthropic_tool_name = None
                    try:
                        await write(self._build_block_event_anthropic().encode('utf-8'))
                    except SSE_CLIENT_GONE:
                        logger.debug('SSE 超限拒绝注入失败')
                    return content_buf, reasoning_buf, ''
                if (
                    self.audit_enabled()
                    and not getattr(self, '_audit_hold_active', False)
                    and self.audit_precheck(
                        self._last_anthropic_tool_name or '',
                        arg_buf,
                    )
                ):
                    self._audit_hold_active = True
                    self._audit_hold_buf = []
                    self._audit_hold_bytes = 0
                    self._audit_hold_buf.append(line)
                    self._audit_hold_bytes = len(line.encode('utf-8'))
                    return content_buf, reasoning_buf, arg_buf
                # 持有不发，仅在 block_stop 时单次 json_aware
                return content_buf, reasoning_buf, arg_buf
            # text/thinking 走 line_buf 行缓冲（6.3），而非 _split_safe_hold 每 delta 切片
            field = _ANTHROPIC_DELTA_FIELDS[kind][0]
            norm = delta_text.replace('\r\n', '\n').replace('\r', '\n')
            if kind == 'text':
                content_buf += norm
                buf = content_buf
            else:
                reasoning_buf += norm
                buf = reasoning_buf
            # 行缓冲：有 \n 立即刷，无则持有（除非超长）
            out_lines = []
            while '\n' in buf:
                line_seg, buf = buf.split('\n', 1)
                line_seg += '\n'
                restored = await self._pii_response_process(line_seg, active_t2p)
                safe = _strip_partials(restored)
                if safe:
                    out_lines.append(safe)
            # 超长强制（6.5/3.1）——即使无 \n 也按候选感知切片
            _extra_31 = self._extra_prefixes(buf[-64:])
            _cand_31 = _has_partial_pii_candidate(buf[-64:], _extra_31)
            if buf and (len(buf) > LINE_BUF_FLUSH or _cand_31):
                # 简化：超长时接 _split_safe_hold 才不残留 token 前缀
                restored = await self._pii_response_process(buf, active_t2p)
                # 3.1：仅还原无改动时启用 PII/自定义尾持有（还原产物不得再持有）
                _same_31 = restored == buf
                safe, pending = _split_safe_hold(
                    restored,
                    active_t2p,
                    self._pii_scope_or_none(),
                    extra_prefixes=_extra_31 if _same_31 else None,
                    hold_pii_tail=_same_31,
                )
                if safe:
                    safe = _strip_partials(safe)
                    out_lines.append(safe)
                    if not _cand_31:
                        self._count_custom_other_miss()
                buf = pending
            if out_lines:
                combined = ''.join(out_lines)
                await write(
                    _mk_anthropic_delta_event(parsed, combined, field).encode('utf-8')
                )
            if kind == 'text':
                content_buf = buf
            else:
                reasoning_buf = buf
            return content_buf, reasoning_buf, arg_buf

        # 其他 content_block_delta：flush 正文缓冲 safe 部分（pending 保留）→ 原样透传
        # 2.1 攒整段：arg_buf 中途零写出，仅 block_stop 单次 flush，此处不刷参数
        content_buf = await self._flush_anthropic_buf(
            write, parsed, 'text', content_buf, active_t2p
        )
        reasoning_buf = await self._flush_anthropic_buf(
            write, parsed, 'thinking', reasoning_buf, active_t2p
        )
        await write(
            (await self._pii_process_sse_line(line, active_t2p) + '\n\n').encode(
                'utf-8'
            )
        )
        return content_buf, reasoning_buf, arg_buf

    # ── Responses API SSE 事件处理 ──

    async def _flush_responses_buf(
        self,
        write,
        event_type: str,
        buf: str,
        active_t2p: dict,
        keep_pending: bool = True,
    ) -> str:
        """flush 单个 Responses 缓冲：还原 → safe/pending 分割 → 输出 safe。

        - keep_pending=True（中游）：返回保留的 pending（不完整 token 前缀，
          等待后续分片）；safe 中无法 hold 的残缺 token 形态被 _PARTIAL_TOKEN_RE 清理
        - keep_pending=False（流末）：不保留 pending，所有 partial 形态清理后
          输出残余（如有）
        - PII 启用（self._pii_active）：执行「还原 → 响应侧检测 → 转发」
          顺序（design D2），_split_safe_hold 携带 pii_scope
        """
        pii_scope = self._pii_scope_or_none()
        if not buf:
            return ''
        # JSON-aware: 覆盖 function_call_arguments 等 stringified JSON（p@ss"quote/\u 等），不完整片段自动回退 plain
        restored = await self._pii_response_process_json_aware(buf, active_t2p)
        if not keep_pending:
            restored = _strip_partials(restored)
            if not restored:
                return ''
            try:
                await write(
                    _mk_responses_flush_event(event_type, restored).encode('utf-8')
                )
            except SSE_CLIENT_GONE:
                logger.debug('SSE 残余写入失败')
            return ''
        safe, pending = _split_safe_hold(restored, active_t2p, pii_scope)
        if safe:
            safe = _strip_partials(safe)
        if safe:
            try:
                await write(_mk_responses_flush_event(event_type, safe).encode('utf-8'))
            except SSE_CLIENT_GONE:
                logger.debug('SSE 残余写入失败')
        return pending

    async def _resolve_responses_hold(
        self,
        write,
        active_t2p: dict,
        line: str,
        content_buf: str,
        reasoning_buf: str,
        arg_buf: str,
    ) -> None:
        """挂起结束（item_done 到达）：完整审计 + 审批处置（同 Anthropic）。"""
        name = self._last_responses_tool_name or ''
        args = arg_buf
        verdict = await self.audit_tool_call(name, args)
        if verdict == 'allow':
            await self._release_hold(write, active_t2p, extra_line=line)
        else:
            result = 'rejected'
            if self.audit_mode == 'approve':
                result = await self._request_audit_approval(name, args)
            if result == 'approved':
                await self._release_hold(write, active_t2p, extra_line=line)
            else:
                await self._reject_responses_hold(write, active_t2p)
        # 清理挂起状态
        self._audit_hold_active = False
        self._audit_hold_buf = []
        self._audit_hold_bytes = 0
        self._last_responses_tool_name = None

    async def _reject_responses_hold(self, write, active_t2p: dict) -> None:
        """拒绝挂起（rejected/expired/failed/超限）：注入拒绝 + 终止事件，缓冲丢弃。"""
        self._audit_hold_buf = []
        self._audit_hold_bytes = 0
        self._audit_hold_active = False
        self._last_responses_tool_name = None
        try:
            await write(self._build_block_event_responses().encode('utf-8'))
        except SSE_CLIENT_GONE:
            logger.debug('SSE 挂起拒绝注入失败')

    async def _handle_responses_event(
        self,
        write,
        parsed: dict,
        line: str,
        active_t2p: dict,
        content_buf: str,
        reasoning_buf: str,
        arg_buf: str,
    ) -> tuple[str, str, str]:
        """处理单个 Responses API SSE 事件，返回更新后的 (content_buf, reasoning_buf, arg_buf)。

        - output_text / reasoning_text / function_call_arguments 的 delta 事件：
          累积 → _restore → safe/pending 分割 → 保持原格式输出已还原片段
        - 其他 response.* 事件：先 flush 各缓冲的 safe 部分（pending 保留等待
          后续分片，未完成的 token 前缀由流末清理），再原样透传事件行
        """
        kind, delta_text = _responses_event(parsed)
        if kind is None:  # pragma: no cover — 调用方已保证是 Responses 事件
            await write(
                (await self._pii_process_sse_line(line, active_t2p) + '\n\n').encode(
                    'utf-8'
                )
            )
            return content_buf, reasoning_buf, arg_buf

        # ── 审计挂起状态（design D4：verdict 前暂停 flush）──
        if getattr(self, '_audit_hold_active', False):
            if kind == 'item_done':
                # 挂起结束：完整审计 + 审批处置
                await self._resolve_responses_hold(
                    write,
                    active_t2p,
                    line,
                    content_buf,
                    reasoning_buf,
                    arg_buf,
                )
                return content_buf, reasoning_buf, ''
            # 挂起期间参数 delta 仍须累积（item_done 审计读完整参数）
            if kind == 'function_call_arguments' and delta_text is not None:
                arg_buf += delta_text
            # 缓冲超限 → fail-closed
            if (
                len(line.encode('utf-8')) + getattr(self, '_audit_hold_bytes', 0)
                > self.audit_hold_max_bytes
            ):
                await self._reject_responses_hold(write, active_t2p)
                return content_buf, reasoning_buf, arg_buf
            self._audit_hold_buf.append(line)
            self._audit_hold_bytes = getattr(self, '_audit_hold_bytes', 0) + len(
                line.encode('utf-8')
            )
            return content_buf, reasoning_buf, arg_buf

        if kind == 'item_done':
            # item 结束：arg_buf 中未完成的 token 前缀不可能再有后续分片
            # （function call 参数不会跨 item 续写），清空防跨 item 伪还原
            # （content/reasoning 保留 pending，由流末统一清理）
            # 审计触发点：读取掩码前原始完整参数（design D3 审计对抗性）
            # F-12 合并：arg_buf 即原始参数累积器（与旧 _audit_arg_accum 同源），
            # 审计必须发生在 json_aware 还原/清空之前
            if arg_buf and self.audit_enabled():
                name = self._last_responses_tool_name or ''
                verdict = await self.audit_tool_call(name, arg_buf)
                if verdict == 'deny':
                    if self.audit_mode == 'approve':
                        # 审批模式：发起 Matrix 审批；approved → 放行（不注入拒绝）
                        result = await self._request_audit_approval(name, arg_buf)
                        if result == 'approved':
                            verdict = 'allow'
                    if verdict == 'deny':
                        # 阻断：注入拒绝消息 + item_done 终止事件（design D4 防 dangling）
                        await write(self._build_block_event_responses().encode('utf-8'))
                        arg_buf = ''
                        self._last_responses_tool_name = None
            # 6.6 攒整段刷新
            if arg_buf:
                try:
                    restored_arg = await self._pii_response_process_json_aware(
                        arg_buf, active_t2p
                    )
                    restored_arg = _strip_partials(restored_arg)
                    if restored_arg:
                        await write(
                            _mk_responses_sse_event(parsed, restored_arg).encode(
                                'utf-8'
                            )
                        )
                except Exception:
                    pass
                arg_buf = ''
            self._last_responses_tool_name = None
            await write(
                (await self._pii_process_sse_line(line, active_t2p) + '\n\n').encode(
                    'utf-8'
                )
            )
            return content_buf, reasoning_buf, ''

        if kind in ('output_text', 'reasoning_text', 'function_call_arguments'):
            if delta_text is None:  # pragma: no cover — 识别器保证 delta 事件携带 str
                return content_buf, reasoning_buf, arg_buf
            if kind == 'function_call_arguments':
                # 6.6 攒整段：仅累积，不每 delta 即 json_aware
                arg_buf += delta_text
                if len(arg_buf) > SSE_MAX_BUF:
                    logger.warning(
                        'Responses 参数累积超限(%d>1MB)，丢弃并拒绝', len(arg_buf)
                    )
                    arg_buf = ''
                    self._last_responses_tool_name = None
                    try:
                        await write(self._build_block_event_responses().encode('utf-8'))
                    except SSE_CLIENT_GONE:
                        logger.debug('SSE 超限拒绝注入失败')
                    return content_buf, reasoning_buf, ''
                if (
                    self.audit_enabled()
                    and not getattr(self, '_audit_hold_active', False)
                    and self.audit_precheck(
                        self._last_responses_tool_name or '',
                        arg_buf,
                    )
                ):
                    self._audit_hold_active = True
                    self._audit_hold_buf = []
                    self._audit_hold_bytes = 0
                    self._audit_hold_buf.append(line)
                    self._audit_hold_bytes = len(line.encode('utf-8'))
                    return content_buf, reasoning_buf, arg_buf
                return content_buf, reasoning_buf, arg_buf
            # output_text / reasoning_text 走 line_buf 行缓冲（6.3）
            norm = delta_text.replace('\r\n', '\n').replace('\r', '\n')
            if kind == 'output_text':
                content_buf += norm
                buf = content_buf
            else:
                reasoning_buf += norm
                buf = reasoning_buf
            out_lines = []
            while '\n' in buf:
                line_seg, buf = buf.split('\n', 1)
                line_seg += '\n'
                restored = await self._pii_response_process(line_seg, active_t2p)
                safe = _strip_partials(restored)
                if safe:
                    out_lines.append(safe)
            _extra_31 = self._extra_prefixes(buf[-64:])
            _cand_31 = _has_partial_pii_candidate(buf[-64:], _extra_31)
            if buf and (len(buf) > LINE_BUF_FLUSH or _cand_31):
                restored = await self._pii_response_process(buf, active_t2p)
                _same_31 = restored == buf
                safe, pending = _split_safe_hold(
                    restored,
                    active_t2p,
                    self._pii_scope_or_none(),
                    extra_prefixes=_extra_31 if _same_31 else None,
                    hold_pii_tail=_same_31,
                )
                if safe:
                    safe = _strip_partials(safe)
                    out_lines.append(safe)
                    if not _cand_31:
                        self._count_custom_other_miss()
                buf = pending
            if out_lines:
                combined = ''.join(out_lines)
                await write(_mk_responses_sse_event(parsed, combined).encode('utf-8'))
            if kind == 'output_text':
                content_buf = buf
            else:
                reasoning_buf = buf
            return content_buf, reasoning_buf, arg_buf

        # 其他 response.* 事件：flush 正文缓冲 safe 部分（pending 保留）→ 原样透传
        content_buf = await self._flush_responses_buf(
            write, 'response.output_text.delta', content_buf, active_t2p
        )
        reasoning_buf = await self._flush_responses_buf(
            write, 'response.reasoning_text.delta', reasoning_buf, active_t2p
        )
        # 捕获 function call 工具名（response.function_call 事件，item_done 审计用）
        if isinstance(parsed, dict):
            item = parsed.get('item')
            if isinstance(item, dict) and item.get('type') == 'function_call':
                name = item.get('name')
                if isinstance(name, str) and name:
                    self._last_responses_tool_name = name
        await write(
            (await self._pii_process_sse_line(line, active_t2p) + '\n\n').encode(
                'utf-8'
            )
        )
        return content_buf, reasoning_buf, arg_buf

    # ── Startup ──

    async def start_llm_proxies(self):
        if not self.proxies:
            logger.info('LLM 代理已禁用（未设置 LLM_* 环境变量）')
            return
        # 共享 ClientSession：所有端口共用一个连接池
        self._shared_session = ClientSession(
            timeout=ClientTimeout(
                total=UPSTREAM_TOTAL_TIMEOUT,
                connect=UPSTREAM_CONNECT_TIMEOUT,
            ),
        )
        for port, upstream in sorted(self.proxies.items()):
            await self._start_one_proxy(port, upstream)

    async def _start_one_proxy(self, port: int, upstream: str):
        session = self._shared_session  # 共享会话

        async def handler(request):
            req_id = (
                request.headers.get('x-request-id', '')
                or str(_uuid.uuid4()).replace('-', '')[:16]
            )
            # 请求级 ContextVar 隔离（D2）：捕获 Token 以便 finally reset
            # _pii_scope 全局持久化：set(get()) 仅捕获 Token 供 reset，值保持全局单例（D1）
            _cv_pii_scope_tok = _pii_scope_var.set(_pii_scope_var.get())
            # per-request PII/cred 计数 ctx（_metrics.py 定义，事件详情 hit/miss 数据源）— Token 隔离防跨请求泄露
            from _metrics import _req_pii_ctx, _req_pii_var

            _cv_req_pii_tok = _req_pii_var.set(_req_pii_var.get())
            _req_pii_ctx()  # 初始化当前请求计数（若 None 则新建 dict，已在 Token 隔离上下文内）
            _cv_audit_hold_active_tok = _audit_hold_active_var.set(False)
            _cv_audit_hold_buf_tok = _audit_hold_buf_var.set([])  # type: ignore[arg-type]
            _cv_audit_hold_bytes_tok = _audit_hold_bytes_var.set(0)
            _cv_last_anthropic_tok = _last_anthropic_tool_name_var.set(None)
            _cv_last_responses_tok = _last_responses_tool_name_var.set(None)
            _cv_audit_created_ids_tok = _audit_created_ids_var.set([])
            tail = request.match_info['tail']
            is_dialog_tail = is_chat_tail(tail)
            try:
                _ctx_tail = _req_pii_ctx()
                _ctx_tail['tail'] = tail
            except Exception:
                pass
            target_url = f'{upstream.rstrip("/")}/{tail}'
            if request.query_string:
                target_url += '?' + request.query_string
            body = await request.read()
            body_text = body.decode('utf-8', errors='replace') if body else ''
            # 可观测性埋点上下文（llm-observability-dashboard 1.3）
            _metrics_ctx: dict = {
                't0': _time.time(),
                'port': str(port),
                'upstream': str(port),  # 主键仅 port
                'status': None,
                'latency_ms': None,
                'bytes_in': len(body) if body else 0,
                'bytes_out': 0,
                'empty_guarded': False,
                'invalid_json_guarded': False,
                'client_gone': False,
                'exception': False,
                'sse_events': 0,
                'truncated': 0,
                'json_aware_success': 0,
                'json_leaf_fallback': 0,
                'json_full_fallback': 0,
                'placeholder_injected': False,
                'pii_hits': 0,
                'pii_miss': 0,
                'cred_hits': 0,
                'cred_miss': 0,
                'tokens': {},
                'audit_by_verdict': {},
                'audit_by_rule': {},
                'pii_by_type': {},
                'pii_found': False,
                'request_id': req_id,
                'tail': tail,
                'verdict': '',
                'raw_summary': '',
                'model': 'unknown_model',
            }

            # 仅对 LLM 对话 endpoint 保存调试原始请求 JSON（非对话如 /v1/models 不保存）
            _debug_save_eligible = bool(_DEBUG_DIR) and (is_chat_tail(tail))
            _debug_saved = False  # 标记是否已在 SSE 响应中保存过
            # === DEBUG: 原版请求 + meta 立即落盘（早于脱敏，便于对比） ===
            if _debug_save_eligible:
                try:
                    _save_debug_bytes(req_id, 'request_original.json', body)
                    _save_debug_json(
                        req_id,
                        'request_meta.json',
                        {
                            'req_id': req_id,
                            'tail': tail,
                            'target_url': target_url,
                            'method': request.method,
                            'timestamp': __import__('datetime')
                            .datetime.now(__import__('datetime').timezone.utc)
                            .isoformat(),
                            'headers': {
                                k: v
                                for k, v in request.headers.items()
                                if k.lower()
                                not in ('authorization', 'x-api-key', 'cookie')
                            },
                            'query_string': request.query_string,
                            'body_len': len(body) if body else 0,
                            'eligible': True,
                        },
                    )
                except Exception as exc:
                    logger.debug('保存原版请求失败: %s', exc)

            # 拍快照防 "forget secrets" 竞态（需持锁，防快照不一致）
            async with self._lock:
                snapshot_p2t = dict(self.pwd_to_token)
                snapshot_t2p = dict(self.token_to_pwd)

            if body_text:
                # PII 请求侧脱敏（在凭据 redact 前，PII_REDACTION_ENABLED 时）：
                # 检测 PII → 注册请求级映射 → 替换为 __PII_*__ 占位符
                # JSON-aware：仅对字符串节点替换，避免纯文本替换破坏 \u 转义（Invalid \escape）
                # 7.4: 非对话尾（v1/models 等）透传不 walk
                if is_dialog_tail and getattr(self, 'pii_enabled', False):
                    self._pii_request_scope()
                    if hasattr(self, 'pii_redact_json_aware'):
                        body_text = await self.pii_redact_json_aware(
                            body_text, tail=tail
                        )
                    else:
                        body_text = await self.pii_redact(body_text, tail=tail)
                if is_dialog_tail and hasattr(self, '_redact_json_aware'):
                    out_body = self._redact_json_aware(body_text, snapshot_p2t).encode(
                        'utf-8'
                    )
                elif is_dialog_tail and hasattr(self, '_redact'):
                    out_body = self._redact(body_text, snapshot_p2t).encode('utf-8')
                else:
                    # 非对话尾：透传原文，不走 walk/脱敏
                    out_body = body_text.encode('utf-8') if body_text else body
                # 事件摘要：请求体（已脱敏 out_body）存入，供最近事件展示与 ?kind= 过滤
                # （redact_summary 在 incr_event 内二次脱敏 + 截断 120 字符）
                _metrics_ctx['raw_summary'] = (
                    out_body.decode('utf-8', errors='replace') if out_body else ''
                )
                # 快速路径：无 token 时不扫描（门控扩展：PII token 同样触发还原路径）
                pii_scope = self._pii_scope_or_none()
                has_cred = snapshot_t2p and b'__VG_CRED_' in out_body
                has_pii = bool(pii_scope) and b'__PII_' in out_body
                if has_pii:
                    _metrics_ctx['pii_found'] = True
                # ── 请求脱敏后置校验：仅 has_cred/has_pii 时触发，失败先叶子重建仍失败才全量回退 ──
                if has_cred or has_pii:
                    try:
                        _orig_stripped = (
                            body.decode('utf-8', errors='replace')
                            .lstrip('\ufeff')
                            .lstrip()
                        )
                        if _orig_stripped.startswith(('{', '[')):
                            try:
                                _jloads(
                                    body.decode('utf-8', errors='replace').lstrip(
                                        '\ufeff'
                                    )
                                )
                                _jloads(
                                    out_body.decode('utf-8', errors='replace').lstrip(
                                        '\ufeff'
                                    )
                                )
                            except Exception as _je:
                                logger.warning(
                                    'request redact broke JSON, fallback to original: error=%s '
                                    'input_len=%d output_len=%d input_preview=%r output_preview=%r',
                                    _je,
                                    len(body),
                                    len(out_body),
                                    body[:4000],
                                    out_body[:4000],
                                )
                                out_body = body
                    except Exception:
                        pass
                if has_cred or has_pii:
                    # 收集本次请求实际使用的 token，仅还原这些（防 LLM 幻觉泄露）。
                    # used_tokens 仅收集实际注册产出的 token：凭据注册表命中
                    # （快照中已存在）+ PII 请求级映射——不收集任意 TOKEN_RE
                    # 形态匹配（关闭「prompt 字面量 __VG_CRED_*__ → 回显 → 还原」放大路径）
                    used_tokens = set()
                    for m in TOKEN_RE.finditer(out_body):
                        used_tokens.add(m.group().decode())
                    if pii_scope:
                        for m in PII_TOKEN_RE.finditer(out_body):
                            used_tokens.add(m.group().decode())
                    active_t2p = {
                        t: p for t, p in snapshot_t2p.items() if t in used_tokens
                    }
                else:
                    active_t2p = {}
            else:
                out_body = body
                active_t2p = {}
                pii_scope = None

            # ── 可观测性：model 提取 + stream_options.include_usage 注入 ──
            # （仅 OpenAI Chat/Responses 且 is_stream==true；Anthropic 严禁注入）
            # 非流式/Anthropic 不做全量 loads/dumps，仅轻量正则提取 model
            _req_model = 'unknown_model'
            try:
                _body_str = out_body.decode('utf-8', errors='replace')
                # 轻量流式探测：`"stream":true` 出现在 body 中（仅 true 触发注入）
                _is_stream = _re.search(rb'"stream"\s*:\s*true', out_body) is not None
                _tail_n = tail.rstrip('/')
                _is_chat = (
                    _tail_n.endswith('chat/completions')
                    or _tail_n.endswith('v1/messages')
                    or _tail_n.endswith('v1/responses')
                )
                _is_injectable = _is_stream and (
                    _tail_n.endswith('chat/completions')
                    or _tail_n.endswith('v1/responses')
                )
                # 仅对话类请求解析（model 用于 tokens 分桶）；其他（embeddings 等）不解析
                if _is_chat:
                    _req_obj = _jloads(_body_str)
                    if isinstance(_req_obj, dict):
                        _m = _req_obj.get('model')
                        if isinstance(_m, str) and _m:
                            # model label 消毒：截断过长 + 去控制字符（防脏标签入 tokens dict/大盘）
                            _req_model = (
                                _re.sub(r'[\x00-\x1f\x7f]', '', _m)[:128].strip()
                                or 'unknown_model'
                            )
                        if _is_injectable:
                            _so = _req_obj.setdefault('stream_options', {})
                            if isinstance(_so, dict):
                                _so.setdefault('include_usage', True)
                            out_body = _jdumps(_req_obj).encode('utf-8')
            except Exception:
                pass
            _metrics_ctx['model'] = _req_model

            # ── 占位符说明提示词注入（pii-placeholder-prompt）──
            # 触发条件（D1/D3/D4，三者同时满足才注入）：
            #   (a) is_dialog_tail 且 pii_enabled（脱敏路径）
            #   (b) pii_placeholder_prompt_enabled（开关）
            #   (c) 脱敏后 body 含 __PII_ 或 __VG_CRED_ 占位符（OR 语义，任一命中）
            # 零脱敏零注入：无占位符时不注入，不污染 prompt、不消耗 token。
            # 注入在 pii_redact_json_aware 之后、转发上游之前；禁止注入后二次
            # PII 扫描（design D6，防说明文本自身被脱敏）。
            if (
                is_dialog_tail
                and getattr(self, 'pii_enabled', False)
                and getattr(self, 'pii_placeholder_prompt_enabled', True)
                and (b'__PII_' in out_body or b'__VG_CRED_' in out_body)
            ):
                try:
                    # 协议以路由 path 判定（design D2 协议判定 path 为主）
                    if tail.rstrip('/').endswith('v1/messages'):
                        _pp_protocol = 'anthropic'
                    elif tail.rstrip('/').endswith('v1/responses'):
                        _pp_protocol = 'responses'
                    else:
                        _pp_protocol = 'openai'
                    _pp_before = out_body
                    out_body = self.inject_placeholder_prompt(
                        out_body.decode('utf-8', errors='replace'),
                        protocol=_pp_protocol,
                    ).encode('utf-8')
                    if out_body != _pp_before:
                        # placeholder_prompt_injected_total（注入发生与否）
                        _metrics = getattr(self, '_metrics_collector', None)
                        if _metrics is not None:
                            _metrics.incr_sync_placeholder_injected()
                except Exception:
                    logger.exception('注入占位符说明提示词失败，透传原 body')

            # === DEBUG: 脱敏后请求落盘（与原版对比） ===
            if _debug_save_eligible:
                try:
                    _save_debug_bytes(req_id, 'request_redacted.json', out_body)
                    _save_debug_bytes(req_id, 'request.json', out_body)
                except Exception as exc:
                    logger.debug('保存脱敏请求失败: %s', exc)

            # 透传 Hermes headers（过滤逐跳头）
            headers = filter_hop_headers(dict(request.headers))

            try:
                # 上游连接重试：仅对「拿到响应头之前」的瞬时连接异常重试。
                # ServerDisconnectedError（上游主动断开）/ ClientConnectionError（连接层）/
                # TimeoutError（connect 超时）均为瞬时故障，LLM chat 请求重试幂等安全。
                # 一旦拿到 upstream_resp（进入 SSE 转发/读 body），绝不再重试。
                upstream_resp = None
                for attempt in range(MAX_UPSTREAM_RETRIES):
                    try:
                        upstream_resp = await session.request(
                            request.method,
                            target_url,
                            headers=headers,
                            data=out_body,
                        )
                        break
                    except (
                        ServerDisconnectedError,
                        ClientConnectionError,
                        TimeoutError,
                    ) as e:
                        if attempt == MAX_UPSTREAM_RETRIES - 1:
                            raise
                        delay = UPSTREAM_RETRY_BACKOFF * (2**attempt)
                        logger.warning(
                            'LLM 上游连接异常(%s)，%.1fs 后重试 %d/%d: %s %s',
                            type(e).__name__,
                            delay,
                            attempt + 2,
                            MAX_UPSTREAM_RETRIES,
                            request.method,
                            target_url,
                        )
                        await asyncio.sleep(delay)

                # 循环内要么 break 要么 raise，到达此处必非 None
                assert upstream_resp is not None
                # async with 确保上游响应在 SSE 客户端断连时正确释放连接
                async with upstream_resp:
                    content_type = upstream_resp.content_type or ''

                    # Log non-2xx upstream responses, only for chat completion endpoints
                    # 覆盖三种 LLM 对话协议：chat/completions、v1/messages、v1/responses
                    # 0.9.2 漏了 v1/responses，导致 Responses API 的上游错误被沉默
                    if upstream_resp.status >= 400 and (is_chat_tail(tail)):
                        logger.warning(
                            'LLM 上游返回 %d: %s %s',
                            upstream_resp.status,
                            request.method,
                            target_url,
                        )

                    if content_type.startswith('text/event-stream'):
                        # ── SSE 流式 ──
                        resp = web.StreamResponse(
                            status=upstream_resp.status,
                            headers=filter_hop_headers(
                                dict(upstream_resp.headers),
                            ),
                        )
                        await resp.prepare(request)
                        # 10.7.1 (F-07): 供审批 keepalive 协程使用（见
                        # _request_audit_approval）；流结束后清理
                        self._audit_keepalive_resp = resp
                        self._audit_keepalive_task = None
                        if is_chat_tail(tail):
                            logger.info(
                                'LLM 流式开始: %s %s tail=%s ct=%s status=%d',
                                request.method,
                                target_url,
                                tail,
                                content_type,
                                upstream_resp.status,
                            )

                        if is_dialog_tail and (
                            active_t2p or self._pii_active() or self.audit_enabled()
                        ):
                            # ── JSON-aware 流式 token 还原（广义 Plan C） ──
                            content_buf = ''  # 累积 delta.content 片段（每事件经 safe/pending 分割重置为小字符串，摊还 O(1)）
                            reasoning_buf = ''  # 累积 delta.reasoning_content 片段
                            # D1 发射映射：joint 缓冲文本的来源路索引（精确单路时
                            # 按 index 重建，含多路时回退原最小事件；见
                            # _single_mapped_index）
                            content_buf_src: set[int] = set()
                            reasoning_buf_src: set[int] = set()
                            # D1 流末合成重建用：最近一次 chat chunk 解析对象
                            slow_last_chat_parsed = None
                            arg_buf = ''  # 累积 responses function_call_arguments / anthropic partial_json 片段
                            is_responses_stream = False  # 本流是否 Responses API SSE
                            is_anthropic_stream = (
                                False  # 本流是否 Anthropic Messages API SSE
                            )
                            byte_buf = bytearray()
                            resp_log_path = None
                            sse_event_count = 0  # 空流检测：统计 data 事件数
                            bytes_written = (
                                0  # D3：实际写入字节数守门（仅成功 write 计数）
                            )
                            seen_terminal = False  # 是否已收到终止事件（responses: completed/failed/incomplete, chat: [DONE]）
                            _done_sent = False  # chat 协议 [DONE] 是否已发出（防双发）
                            seen_global_terminal = False  # 全局终止，仅全局置位；item_done/block_stop 仅清 arg_buf
                            # ── 6.2 WHATWG / 6.3 line_buf / 6.5 keepalive 新增变量 ──
                            data_buffer: list[
                                str
                            ] = []  # 同事件多 data: 行聚合（WHATWG）
                            # 10.13 (F-12): slow 链 event:/id: 行暂存 ——
                            # 不得立即透传（会把 SSE 块拆成 event 独块 + data 独块，
                            # openai sdk 按块解析 → 无 data 的块 JSONDecodeError）。
                            # 暂存后拼入 data 行同一块写出。
                            slow_event_pending: list[str] = []
                            pending_cr = False  # 上 chunk 末孤立 \r 跨块粘合
                            bom_seen = False  # 流首 BOM 单次剥离
                            line_buf_ts = _time.monotonic()  # 6.3/6.5 行缓冲时间戳
                            reasoning_buf_ts = _time.monotonic()
                            keepalive_task: asyncio.Task | None = None

                            def _reset_keepalive():
                                nonlocal keepalive_task, line_buf_ts, reasoning_buf_ts
                                if keepalive_task is not None:
                                    try:
                                        keepalive_task.cancel()
                                    except Exception:
                                        pass
                                    keepalive_task = None
                                if (
                                    content_buf
                                    or reasoning_buf
                                    or arg_buf
                                    or data_buffer
                                    # 10.7.1 (F-07): 审计审批挂起期（最长 90s
                                    # Matrix 人工审批）即使缓冲区为空也必须
                                    # 有 keepalive 任务——否则 tool_calls 审批
                                    # 窗口（content_buf 空）无 keepalive，
                                    # hermes inactivity 120s 判定断流
                                    or getattr(
                                        self,
                                        '_audit_approval_pending',
                                        {},
                                    )
                                ):
                                    line_buf_ts = _time.monotonic()
                                    reasoning_buf_ts = _time.monotonic()

                                    async def _ka():
                                        while True:
                                            try:
                                                await asyncio.sleep(KEEPALIVE_INTERVAL)
                                                # 9.12 (F-12): 审计审批挂起（最长 90s
                                                # 等待 Matrix 人工审批）期间必须持续保活，
                                                # 否则 hermes inactivity 120s 超时断流
                                                _ap_pending = bool(
                                                    getattr(
                                                        self,
                                                        '_audit_approval_pending',
                                                        {},
                                                    )
                                                )
                                                if (
                                                    content_buf
                                                    or reasoning_buf
                                                    or arg_buf
                                                    or data_buffer
                                                    or _ap_pending
                                                ):
                                                    try:
                                                        await resp.write(
                                                            b': keepalive\n\n'
                                                        )
                                                        await resp.drain()
                                                    except Exception:
                                                        break
                                                else:
                                                    break
                                            except asyncio.CancelledError:
                                                break

                                    keepalive_task = asyncio.create_task(_ka())

                            async def _tracked_write(data: bytes):
                                nonlocal bytes_written
                                await resp.write(data)
                                bytes_written += len(data)
                                try:
                                    _reset_keepalive()
                                except Exception:
                                    pass
                                if _debug_save_eligible:
                                    try:
                                        txt = data.decode('utf-8', errors='replace')
                                        for _line in txt.splitlines():
                                            if _line.strip() == '':
                                                continue
                                            await _debug_append_line(
                                                req_id, 'response_restored.jsonl', _line
                                            )
                                    except Exception as exc:
                                        logger.debug('保存下游恢复日志失败: %s', exc)

                            # OpenAI chat/completions tool_calls 分片累积：
                            # index → {'name': str, 'arguments': str}
                            tool_calls_buf: dict[int, dict[str, str]] = {}
                            tool_calls_audited = (
                                False  # 防止重复审计（finish_reason + 流末双触发）
                            )
                            tool_calls_blocked = (
                                False  # 审计 deny：抑制后续 tool_calls 事件流出
                            )
                            audit_block_injected = False
                            # 审计启用时缓冲 tool_calls SSE 行（design D4：未出 verdict 不流出）
                            tool_calls_pending_events: list[str] = []

                            # 1.3 (D3) 缓冲事件单次还原 helper：
                            # 三处放行点（[DONE]兜底/finish触发/流末）统一经此单次
                            # `_pii_process_sse_line` 还原；还原后 `json.loads`
                            # 校验，失败走 `_strip_partials` 清理不回退原串
                            # （防未还原占位符泄漏）；返回不带帧尾的 SSE 行，
                            # 校验后无内容返回 None（调用方跳过写出）。
                            async def _release_pending_once(
                                ev: str, _t2p: dict
                            ) -> str | None:
                                restored = await self._pii_process_sse_line(ev, _t2p)
                                try:
                                    _lines = (
                                        restored.split('\n')
                                        if '\n' in restored
                                        else [restored]
                                    )
                                    for _ln in _lines:
                                        _s = _ln.strip()
                                        if not _s or not _s.startswith('data:'):
                                            continue
                                        _pl = _s.split(':', 1)[1].lstrip(' \t').strip()
                                        if (
                                            not _pl
                                            or _pl == '[DONE]'
                                            or not _pl.startswith(('{', '['))
                                        ):
                                            continue
                                        json.loads(_pl)
                                except Exception as exc:
                                    logger.warning(
                                        '缓冲 tool_calls 事件还原后校验失败走残缺清理: error=%s ev_preview=%r restored_preview=%r',
                                        exc,
                                        ev[:200],
                                        restored[:200],
                                    )
                                    restored = _strip_partials(restored)
                                    if not restored.strip():
                                        return None
                                return restored

                            async def _single_flush_openai_tool_calls(
                                _parsed_tpl,
                            ) -> None:
                                _tool_by_idx: dict[int, list] = {}
                                for _idx in sorted(tool_calls_buf):
                                    _entry = tool_calls_buf[_idx]
                                    _args = _entry.get('arguments', '')
                                    if not _args:
                                        continue
                                    try:
                                        _restored = (
                                            await self._pii_response_process_json_aware(
                                                _args, active_t2p
                                            )
                                        )
                                    except Exception as exc:
                                        logger.debug(
                                            '工具参数 json-aware 还原失败，回退 plain: %s',
                                            exc,
                                        )
                                        try:
                                            _restored = (
                                                await self._pii_response_process(
                                                    _args, active_t2p
                                                )
                                            )
                                        except Exception as exc2:
                                            logger.debug(
                                                '工具参数 plain 还原失败，跳过该路: %s',
                                                exc2,
                                            )
                                            continue
                                    _restored = _strip_partials(_restored)
                                    if not _restored:
                                        try:
                                            _restored = _strip_partials(
                                                await self._pii_response_process(
                                                    _args, active_t2p
                                                )
                                            )
                                        except Exception as exc3:
                                            logger.debug(
                                                '工具参数 plain 回退失败，跳过该路: %s',
                                                exc3,
                                            )
                                            continue
                                        if not _restored:
                                            continue
                                    _tool_entry = {
                                        'index': _idx,
                                        'type': 'function',
                                        'function': {
                                            'name': _entry.get('name', ''),
                                            'arguments': _restored,
                                        },
                                    }
                                    if _entry.get('id'):
                                        _tool_entry['id'] = _entry['id']
                                    _tool_by_idx[_idx] = [_tool_entry]
                                if not _tool_by_idx:
                                    return
                                try:
                                    if not isinstance(
                                        _parsed_tpl, dict
                                    ) or not isinstance(
                                        _parsed_tpl.get('choices'), list
                                    ):
                                        _min = {
                                            'object': 'chat.completion.chunk',
                                            'choices': [],
                                        }
                                        for _idx in sorted(_tool_by_idx):
                                            _min['choices'].append(
                                                {
                                                    'index': _idx,
                                                    'delta': {
                                                        'role': 'assistant',
                                                        'tool_calls': _tool_by_idx[
                                                            _idx
                                                        ],
                                                    },
                                                    'finish_reason': None,
                                                }
                                            )
                                        _payload = _jdumps(_min)
                                    else:
                                        _payload = _rebuild_chat_chunk(
                                            _parsed_tpl,
                                            None,
                                            None,
                                            None,
                                            _tool_by_idx,
                                        )
                                except Exception:
                                    return
                                try:
                                    await _tracked_write(
                                        ('data: ' + _payload + '\n\n').encode('utf-8')
                                    )
                                except SSE_CLIENT_GONE:
                                    pass

                            # 9.10 (F-11): 三协议同阈值 30s 强制 ——
                            # anthropic/responses 的 line_buf 持有时间戳
                            # （chat 分支已有 line_buf_ts，三协议需一致）
                            _proto_text_ts = _time.monotonic()

                            async def _flush(
                                c: str = '',
                                rc: str = '',
                                fr: str | None = None,
                                parsed=None,
                                content_by_index: dict | None = None,
                                reasoning_by_index: dict | None = None,
                                finish_by_index: dict | None = None,
                            ):
                                """flush 内容作为 SSE 事件并清空缓冲区。

                                10.14 (API-SPEC): 协议感知 —— 在 anthropic /
                                responses 流中，非 content 事件（message_delta
                                等）落 chat 分支时不能把残留缓冲用 chat 格式
                                刷出（协议污染，SDK JSONDecodeError / 事件
                                语义错误）。anthropic → content_block_delta
                                text/thinking，responses → 对应 delta 事件，
                                chat → 原 _mk_sse_event。
                                """
                                nonlocal content_buf, reasoning_buf
                                if c or rc or fr:
                                    if is_anthropic_stream:
                                        # 残留按 anthropic delta 类型输出
                                        _dummy = {
                                            'type': 'content_block_delta',
                                            'index': 0,
                                        }
                                        if c:
                                            c = await self._pii_response_process(
                                                c, active_t2p
                                            )
                                            c = _strip_partials(c)
                                            if c:
                                                await _tracked_write(
                                                    _mk_anthropic_flush_event(
                                                        _dummy, c, 'text'
                                                    ).encode('utf-8')
                                                )
                                        if rc:
                                            rc = await self._pii_response_process(
                                                rc, active_t2p
                                            )
                                            rc = _strip_partials(rc)
                                            if rc:
                                                await _tracked_write(
                                                    _mk_anthropic_flush_event(
                                                        _dummy, rc, 'thinking'
                                                    ).encode('utf-8')
                                                )
                                    elif is_responses_stream:
                                        _dummy = {
                                            'type': 'response.output_text.delta',
                                            'index': 0,
                                        }
                                        if c:
                                            c = await self._pii_response_process(
                                                c, active_t2p
                                            )
                                            c = _strip_partials(c)
                                            if c:
                                                await _tracked_write(
                                                    _mk_responses_flush_event(
                                                        'response.output_text.delta',
                                                        c,
                                                    ).encode('utf-8')
                                                )
                                        if rc:
                                            rc = await self._pii_response_process(
                                                rc, active_t2p
                                            )
                                            rc = _strip_partials(rc)
                                            if rc:
                                                await _tracked_write(
                                                    _mk_responses_flush_event(
                                                        'response.reasoning_text.delta',
                                                        rc,
                                                    ).encode('utf-8')
                                                )
                                    else:
                                        if c:
                                            c = await self._pii_response_process(
                                                c, active_t2p
                                            )
                                            c = _strip_partials(c)
                                        if rc:
                                            rc = await self._pii_response_process(
                                                rc, active_t2p
                                            )
                                            rc = _strip_partials(rc)
                                        await _tracked_write(
                                            _mk_sse_event(
                                                content=c,
                                                finish_reason=(
                                                    fr
                                                    if not isinstance(parsed, dict)
                                                    else None
                                                ),
                                                reasoning_content=rc,
                                                parsed=parsed,
                                                content_by_index=content_by_index,
                                                reasoning_by_index=reasoning_by_index,
                                                finish_by_index=finish_by_index,
                                            ).encode(),
                                        )
                                content_buf = ''
                                reasoning_buf = ''
                                content_buf_src.clear()
                                reasoning_buf_src.clear()

                            try:
                                async for chunk in upstream_resp.content.iter_chunked(
                                    SSE_CHUNK_SIZE,
                                ):
                                    byte_buf.extend(chunk)
                                    # ── 6.2 BOM 单次剥离 ──
                                    if not bom_seen:
                                        if len(byte_buf) >= 3:
                                            if byte_buf[:3] == b'\xef\xbb\xbf':
                                                del byte_buf[:3]
                                            bom_seen = True
                                        else:
                                            if byte_buf.startswith(
                                                b'\xef'
                                            ) or byte_buf.startswith(b'\xef\xbb'):
                                                continue
                                            else:
                                                bom_seen = True
                                    if pending_cr:
                                        if byte_buf.startswith(b'\n'):
                                            del byte_buf[0]
                                        pending_cr = False
                                    pos = 0
                                    while True:
                                        idx_n = byte_buf.find(b'\n', pos)
                                        idx_r = byte_buf.find(b'\r', pos)
                                        if idx_n == -1 and idx_r == -1:
                                            break
                                        if idx_r != -1 and (
                                            idx_n == -1 or idx_r < idx_n
                                        ):
                                            if (
                                                idx_r + 1 < len(byte_buf)
                                                and byte_buf[idx_r + 1] == 10
                                            ):
                                                line_bytes = byte_buf[pos:idx_r]
                                                pos = idx_r + 2
                                            else:
                                                if idx_r == len(byte_buf) - 1:
                                                    pending_cr = True
                                                    break
                                                else:
                                                    line_bytes = byte_buf[pos:idx_r]
                                                    pos = idx_r + 1
                                        else:
                                            line_bytes = byte_buf[pos:idx_n]
                                            pos = idx_n + 1
                                        line = line_bytes.decode(
                                            'utf-8', errors='replace'
                                        )
                                        if line == '':
                                            if data_buffer:
                                                payload = '\n'.join(data_buffer)
                                                data_buffer.clear()
                                                line = 'data: ' + payload
                                                # 空 data 行不计为有效事件，避免下游 JSONDecodeError (char 0)
                                                if not payload.strip():
                                                    continue

                                                sse_event_count += 1
                                                # 可观测性：捕获 usage（slow 链）
                                                _capture_usage_ctx(
                                                    payload,
                                                    _metrics_ctx,
                                                    'anthropic'
                                                    if is_anthropic_stream
                                                    else (
                                                        'responses'
                                                        if is_responses_stream
                                                        else 'openai'
                                                    ),
                                                )
                                                if _debug_save_eligible:
                                                    try:
                                                        await _debug_append_line(
                                                            req_id,
                                                            'response_original.jsonl',
                                                            payload,
                                                        )
                                                    except Exception as exc:
                                                        logger.debug(
                                                            '保存上游原版日志失败: %s',
                                                            exc,
                                                        )

                                                # [DONE] 标记：先 flush 累积内容
                                                if payload.strip() == '[DONE]':
                                                    # 流末兜底审计（finish_reason 未触发时）
                                                    if (
                                                        tool_calls_buf
                                                        and not tool_calls_audited
                                                    ):
                                                        tool_calls_audited = True
                                                        injections = await self._audit_openai_tool_calls(
                                                            tool_calls_buf,
                                                            active_t2p,
                                                        )
                                                        if injections:
                                                            # deny：丢弃缓冲 + 注入拒绝
                                                            tool_calls_blocked = True
                                                            tool_calls_pending_events.clear()
                                                            tool_calls_buf.clear()
                                                            for ev in injections:
                                                                await _tracked_write(
                                                                    ev.encode('utf-8')
                                                                )
                                                        else:
                                                            await _single_flush_openai_tool_calls(
                                                                slow_last_chat_parsed
                                                            )
                                                            tool_calls_pending_events.clear()
                                                            tool_calls_buf.clear()
                                                    if is_responses_stream:
                                                        # 兼容网关可能在 responses 流中发 [DONE]：
                                                        # 用 responses 格式 flush，避免 chat 格式污染
                                                        content_buf = await self._flush_responses_buf(
                                                            _tracked_write,
                                                            'response.output_text.delta',
                                                            content_buf,
                                                            active_t2p,
                                                        )
                                                        reasoning_buf = await self._flush_responses_buf(
                                                            _tracked_write,
                                                            'response.reasoning_text.delta',
                                                            reasoning_buf,
                                                            active_t2p,
                                                        )
                                                        arg_buf = await self._flush_responses_buf(
                                                            _tracked_write,
                                                            'response.function_call_arguments.delta',
                                                            arg_buf,
                                                            active_t2p,
                                                        )
                                                        content_buf_src.clear()
                                                        reasoning_buf_src.clear()
                                                    elif is_anthropic_stream:
                                                        # 兼容网关可能在 anthropic 流中发 [DONE]：
                                                        # 用 anthropic 格式 flush，避免 chat 格式污染
                                                        _dummy = {
                                                            'type': 'content_block_delta',
                                                            'index': 0,
                                                        }
                                                        content_buf = await self._flush_anthropic_buf(
                                                            _tracked_write,
                                                            _dummy,
                                                            'text',
                                                            content_buf,
                                                            active_t2p,
                                                        )
                                                        reasoning_buf = await self._flush_anthropic_buf(
                                                            _tracked_write,
                                                            _dummy,
                                                            'thinking',
                                                            reasoning_buf,
                                                            active_t2p,
                                                        )
                                                        arg_buf = await self._flush_anthropic_buf(
                                                            _tracked_write,
                                                            _dummy,
                                                            'partial_json',
                                                            arg_buf,
                                                            active_t2p,
                                                        )
                                                        content_buf_src.clear()
                                                        reasoning_buf_src.clear()
                                                    else:
                                                        await _flush(
                                                            c=content_buf,
                                                            rc=reasoning_buf,
                                                        )
                                                    seen_terminal = True
                                                    seen_global_terminal = True
                                                    _done_sent = True
                                                    await _tracked_write(
                                                        b'data: [DONE]\n\n',
                                                    )
                                                    continue

                                                # 解析 JSON，提取 delta content
                                                try:
                                                    parsed = json.loads(payload)
                                                    # 非 dict payload（JSON 数组/标量）→
                                                    # 原样透传，避免下游 .get 抛 AttributeError
                                                    if not isinstance(parsed, dict):
                                                        await _tracked_write(
                                                            (
                                                                await self._pii_process_sse_line(
                                                                    line,
                                                                    active_t2p,
                                                                    parsed_obj=parsed,
                                                                )
                                                                + '\n\n'
                                                            ).encode('utf-8'),
                                                        )
                                                        continue

                                                    # 保存原始 SSE payload 到 response.jsonl
                                                    if resp_log_path:
                                                        await _save_response_line(
                                                            resp_log_path,
                                                            payload,
                                                        )
                                                    # DEBUG: 已在上游原版落盘，此处补充 conv_id 映射（若首次）
                                                    if (
                                                        _debug_save_eligible
                                                        and not _debug_saved
                                                    ):
                                                        try:
                                                            _tmp_parsed = json.loads(
                                                                payload
                                                            )
                                                            _tmp_cid = _extract_conv_id(
                                                                _tmp_parsed
                                                            )
                                                            if _tmp_cid:
                                                                _debug_link_conv_id(
                                                                    req_id,
                                                                    _tmp_cid,
                                                                    out_body,
                                                                )
                                                        except Exception:
                                                            logger.debug(
                                                                '解析临时 payload 失败',
                                                                exc_info=True,
                                                            )

                                                    # 首次成功解析 SSE data 时提取 conversation ID 保存原始请求
                                                    if (
                                                        _debug_save_eligible
                                                        and not _debug_saved
                                                    ):
                                                        conv_id = _extract_conv_id(
                                                            parsed
                                                        )
                                                        if conv_id:
                                                            _save_request_body(
                                                                conv_id, out_body
                                                            )
                                                            _debug_link_conv_id(
                                                                req_id,
                                                                conv_id,
                                                                out_body,
                                                            )
                                                            _debug_saved = True
                                                            resp_log_path = (
                                                                os.path.join(
                                                                    _DEBUG_DIR,
                                                                    conv_id,
                                                                    'response.jsonl',
                                                                )
                                                            )
                                                            await _save_response_line(
                                                                resp_log_path,
                                                                payload,
                                                            )

                                                    # ── Responses API 事件（/v1/responses SSE）──
                                                    if (
                                                        _responses_event(parsed)
                                                        is not None
                                                    ):
                                                        is_responses_stream = True
                                                        if parsed.get('type') in (
                                                            'response.completed',
                                                            'response.failed',
                                                            'response.incomplete',
                                                            # 10.14 (API-SPEC): response.error
                                                            # 是正常终止事件（错误后流结束）。
                                                            # 不置位会误判截断合成注入假事件。
                                                            'response.error',
                                                        ):
                                                            seen_terminal = True
                                                            seen_global_terminal = True
                                                        # 10.13 (F-12): 把暂存的 event:/id:
                                                        # 行拼入 data 行同一块写出（SSE 规范：
                                                        # event + data 属于同一块，空行分隔）。
                                                        # 避免 event 独块 + data 独块被下游
                                                        # openai sdk 按块解析时报 JSONDecodeError。
                                                        # 10.14.1 (API-SPEC FIX): 多条 event
                                                        # 行累积（跨批/非标准上游）时按 FIFO
                                                        # 弹第一条配对——join 全部会让 SDK
                                                        # 取最后 event 名配首个 data 载荷
                                                        # （错配）；FIFO 保真且不吞数据。
                                                        if slow_event_pending:
                                                            line = (
                                                                slow_event_pending.pop(
                                                                    0
                                                                )
                                                                + '\n'
                                                                + line
                                                            )
                                                        (
                                                            content_buf,
                                                            reasoning_buf,
                                                            arg_buf,
                                                        ) = await self._handle_responses_event(
                                                            _tracked_write,
                                                            parsed,
                                                            line,
                                                            active_t2p,
                                                            content_buf,
                                                            reasoning_buf,
                                                            arg_buf,
                                                        )
                                                        # D1: 协议处理器重绑缓冲后 chat 侧来源集合失效，
                                                        # 保守清空（后继 chat 发射回退原最小事件，不误映射）
                                                        content_buf_src.clear()
                                                        reasoning_buf_src.clear()
                                                        _proto_text_ts = (
                                                            _time.monotonic()
                                                        )
                                                        continue

                                                    # ── 9.10 (F-11): 三协议同阈值 ——
                                                    # anthropic/responses 持有超 30s 强制 flush
                                                    # （chat 分支 line_buf_ts 已有此语义）
                                                    # 10.8.2 (F-08): 仅非 chat 协议检查——
                                                    # chat 流 _proto_text_ts 不更新（保持初始
                                                    # 值），若也检查会在超 30s 后每个 chunk
                                                    # 触发多余 flush（碎片化）
                                                    if (
                                                        (
                                                            is_anthropic_stream
                                                            or is_responses_stream
                                                        )
                                                        and (
                                                            content_buf or reasoning_buf
                                                        )
                                                        and (
                                                            _time.monotonic()
                                                            - _proto_text_ts
                                                            > LINE_BUF_MAX_AGE
                                                        )
                                                    ):
                                                        await _flush(
                                                            c=content_buf,
                                                            rc=reasoning_buf,
                                                        )
                                                        _proto_text_ts = (
                                                            _time.monotonic()
                                                        )

                                                    # ── Anthropic Messages API 事件（/v1/messages SSE）──
                                                    if (
                                                        _anthropic_event(parsed)
                                                        is not None
                                                    ):
                                                        is_anthropic_stream = True
                                                        (
                                                            content_buf,
                                                            reasoning_buf,
                                                            arg_buf,
                                                        ) = await self._handle_anthropic_event(
                                                            _tracked_write,
                                                            parsed,
                                                            line,
                                                            active_t2p,
                                                            content_buf,
                                                            reasoning_buf,
                                                            arg_buf,
                                                        )
                                                        content_buf_src.clear()
                                                        reasoning_buf_src.clear()
                                                        # 10.14 (API-SPEC): block_stop 时
                                                        # arg_buf 被 flush 为合成 delta 事件
                                                        # （_mk_anthropic_flush_event），
                                                        # 被持有的 input_json_delta 原始
                                                        # event 行已多余——从 pending 清除
                                                        # 对应 content_block_delta 行，
                                                        # 避免流末残留透传成裸 event 块。
                                                        if (
                                                            parsed.get('type')
                                                            == 'content_block_stop'
                                                        ):
                                                            slow_event_pending = [
                                                                _ln
                                                                for _ln in slow_event_pending
                                                                if 'event: content_block_delta'
                                                                not in _ln
                                                            ]
                                                        _proto_text_ts = (
                                                            _time.monotonic()
                                                        )
                                                        continue

                                                    if (
                                                        parsed.get('type')
                                                        == 'message_stop'
                                                    ):
                                                        seen_terminal = True

                                                        seen_global_terminal = True
                                                    if parsed.get('type') == 'error':
                                                        # 10.14 (API-SPEC): Anthropic 流
                                                        # `event: error` 是正常终止事件
                                                        # （错误后流结束，不再发 message_stop）。
                                                        # 不置位会误判截断合成注入假事件。
                                                        seen_terminal = True
                                                        seen_global_terminal = True
                                                    choices = parsed.get('choices', [])
                                                    # 9.3 (F-03): choices 全量遍历（spec
                                                    # streaming-residual-hardening 多 choices
                                                    # 场景）—— 原 choices[0] 只取首路，
                                                    # n=2 第二路 content/tool_calls/finish_reason
                                                    # 全部丢失（PII 旁路泄漏）
                                                    _seen_any_finish = False
                                                    _any_tool_calls_finish = False
                                                    # 2.2 (D4): 结构化阻断判定标志——choices 循环内
                                                    # 计算，与审计开关无关（`delta.tool_calls is not None`
                                                    # 结构化判定 + `finish_reason == 'tool_calls'` 兜底，
                                                    # 替代 `'tool_calls' in line` 子串匹配）。
                                                    _line_has_tool_calls = False
                                                    # 9.3 (F-03): 聚合所有 choices 的
                                                    # content/reasoning（原版循环外完整处理
                                                    # 块继续使用聚合后的单一 delta 语义）
                                                    _agg_content = ''
                                                    _agg_reasoning = None
                                                    _agg_delta = None  # 10.1.1 (R-04): None 哨兵保留首个 delta
                                                    # D1 逐路采集：当前事件各路原始片段/终止原因
                                                    _idx_content: dict[int, str] = {}
                                                    _idx_reasoning: dict[int, str] = {}
                                                    _idx_finish: dict[int, str] = {}
                                                    if isinstance(parsed, dict):
                                                        slow_last_chat_parsed = parsed
                                                    # 审计启用时 tool_calls 行整体进 pending
                                                    # 不输出（原 continue 语义，见下）
                                                    _tool_calls_audit_pending = False
                                                    for _pos, _ch in enumerate(
                                                        choices
                                                        if isinstance(choices, list)
                                                        else []
                                                    ):
                                                        _ch_idx = _chat_choice_index(
                                                            _ch, _pos
                                                        )
                                                        _delta = (
                                                            _ch.get('delta', {})
                                                            if isinstance(_ch, dict)
                                                            else {}
                                                        )
                                                        if not isinstance(_delta, dict):
                                                            _delta = {}
                                                        _fr = (
                                                            _ch.get('finish_reason')
                                                            if isinstance(_ch, dict)
                                                            else None
                                                        )
                                                        if _fr is not None:
                                                            _seen_any_finish = True
                                                            if _fr == 'tool_calls':
                                                                _any_tool_calls_finish = True
                                                        # ── OpenAI tool_calls 分片累积（全量）──
                                                        # 2.2 结构化标志：审计开关无关，先置位再累积
                                                        # （畸形分片由 _accumulate 内跳过，不崩）。
                                                        if (
                                                            _delta.get('tool_calls')
                                                            is not None
                                                        ):
                                                            _line_has_tool_calls = True
                                                            _accumulate_tool_calls(
                                                                tool_calls_buf,
                                                                _delta['tool_calls'],
                                                            )
                                                            _over_args = sum(
                                                                len(
                                                                    _e.get(
                                                                        'arguments',
                                                                        '',
                                                                    )
                                                                )
                                                                for _e in tool_calls_buf.values()
                                                            )
                                                            if _over_args > SSE_MAX_BUF:
                                                                logger.warning(
                                                                    'OpenAI 参数累积超限，丢弃并拒绝'
                                                                )
                                                                tool_calls_buf.clear()
                                                                tool_calls_pending_events.clear()
                                                                tool_calls_blocked = (
                                                                    True
                                                                )
                                                                tool_calls_audited = (
                                                                    True
                                                                )
                                                                for _ev in [
                                                                    self._build_block_event()
                                                                ]:
                                                                    await (
                                                                        _tracked_write(
                                                                            _ev.encode(
                                                                                'utf-8'
                                                                            )
                                                                        )
                                                                    )
                                                                audit_block_injected = (
                                                                    True
                                                                )
                                                            else:
                                                                if (
                                                                    self.audit_enabled()
                                                                    and not tool_calls_blocked
                                                                ):
                                                                    tool_calls_pending_events.append(
                                                                        line
                                                                    )
                                                                _tool_calls_audit_pending = True
                                                        # 聚合 content（拼接多路，循环外统一 line_buf 处理）
                                                        _ch_content = _delta.get(
                                                            'content'
                                                        )
                                                        if _ch_content is not None:
                                                            _agg_content += _ch_content
                                                        if (
                                                            isinstance(_ch_content, str)
                                                            and _ch_content
                                                        ):
                                                            _idx_content[_ch_idx] = (
                                                                _idx_content.get(
                                                                    _ch_idx, ''
                                                                )
                                                                + _ch_content
                                                            )
                                                        _ch_ref = _delta.get('refusal')
                                                        if (
                                                            isinstance(_ch_ref, str)
                                                            and _ch_ref
                                                        ):
                                                            _agg_content += _ch_ref
                                                            _idx_content[_ch_idx] = (
                                                                _idx_content.get(
                                                                    _ch_idx, ''
                                                                )
                                                                + _ch_ref
                                                            )
                                                            _delta.pop('refusal', None)
                                                        _ch_rc = _delta.get(
                                                            'reasoning_content'
                                                        )
                                                        if _ch_rc is None:
                                                            _ch_rc = _delta.get(
                                                                'reasoning'
                                                            )
                                                        if (
                                                            isinstance(_ch_rc, str)
                                                            and _ch_rc
                                                        ):
                                                            if not isinstance(
                                                                _agg_reasoning, str
                                                            ):
                                                                _agg_reasoning = ''
                                                            _agg_reasoning += _ch_rc
                                                        elif (
                                                            _ch_rc is not None
                                                            and _agg_reasoning is None
                                                        ):
                                                            _agg_reasoning = _ch_rc
                                                        if (
                                                            isinstance(_ch_rc, str)
                                                            and _ch_rc
                                                        ):
                                                            _idx_reasoning[_ch_idx] = (
                                                                _idx_reasoning.get(
                                                                    _ch_idx, ''
                                                                )
                                                                + _ch_rc
                                                            )
                                                        if _fr is not None:
                                                            _idx_finish[_ch_idx] = _fr
                                                        # 10.1.1 (R-04): 保留首个非空 delta（content-only
                                                        # 单 choice 流也应拿到原语义的 delta）
                                                        if (
                                                            _agg_delta is None
                                                            and _delta
                                                        ):
                                                            _agg_delta = _delta
                                                    # 10.6.1 (F-03/R-05): 本行含 tool_calls——
                                                    # 不再整行 continue（会连带丢弃同 event 其他 choice 的
                                                    # content/reasoning）。仅当行纯 tool_calls（无 content/
                                                    # reasoning）时跳过；有 content 的行正常处理，
                                                    # tool_calls 部分仍攒整段，verdict 后单次 flush/丢弃。
                                                    if (
                                                        _tool_calls_audit_pending
                                                        and not _agg_content
                                                        and _agg_reasoning is None
                                                    ):
                                                        continue
                                                    # 注：有 content 的行走 content 分支（只发 content），
                                                    # tool_calls 已进 pending_events，verdict 后统一放行——
                                                    # 无需额外抑制透传
                                                    if _seen_any_finish:
                                                        seen_terminal = True

                                                        seen_global_terminal = True
                                                    # 供下方原逻辑使用（多路聚合为单路语义）
                                                    delta = _agg_delta or {}
                                                    finish_reason = (
                                                        next(
                                                            (
                                                                _ch.get('finish_reason')
                                                                for _ch in choices
                                                                if isinstance(_ch, dict)
                                                                and _ch.get(
                                                                    'finish_reason'
                                                                )
                                                                is not None
                                                            ),
                                                            None,
                                                        )
                                                        if choices
                                                        else None
                                                    )
                                                    content = _agg_content
                                                    rc_val = _agg_reasoning
                                                    # ── finish_reason == tool_calls：审计触发点 ──
                                                    if (
                                                        _any_tool_calls_finish
                                                        and tool_calls_buf
                                                        and not tool_calls_audited
                                                    ):
                                                        tool_calls_audited = True
                                                        injections = await self._audit_openai_tool_calls(
                                                            tool_calls_buf,
                                                            active_t2p,
                                                        )
                                                        if injections:
                                                            # deny：丢弃缓冲的 tool_calls 事件 + 注入拒绝
                                                            tool_calls_blocked = True
                                                            tool_calls_pending_events.clear()
                                                            tool_calls_buf.clear()
                                                            for ev in injections:
                                                                await _tracked_write(
                                                                    ev.encode('utf-8')
                                                                )
                                                            audit_block_injected = True
                                                        else:
                                                            await _single_flush_openai_tool_calls(
                                                                parsed
                                                            )
                                                            tool_calls_pending_events.clear()
                                                            tool_calls_buf.clear()

                                                    # deny：finish_reason: tool_calls 行不透传
                                                    # （客户端不应看到 tool_calls 语义——拒绝后
                                                    # 只有拒绝消息 + finish_reason: stop）
                                                    # 只跳过当前终止行，不得永久跳过后续行
                                                    # （阻断后模型可能继续发 content 说明）
                                                    # 2.2 结构化阻断：按路归属的 finish 判定替代聚合
                                                    # 比较；含文本行不抑制；多路竞态各路保留。
                                                    if (
                                                        tool_calls_blocked
                                                        and _any_tool_calls_finish
                                                        and not _agg_content
                                                        and _agg_reasoning is None
                                                    ):
                                                        _non_tc_finish = {
                                                            _i: _fr2
                                                            for _i, _fr2 in _idx_finish.items()
                                                            if _fr2 != 'tool_calls'
                                                        }
                                                        if _non_tc_finish and len(
                                                            _non_tc_finish
                                                        ) < len(_idx_finish):
                                                            await _tracked_write(
                                                                _mk_sse_event(
                                                                    parsed=parsed,
                                                                    finish_by_index=_non_tc_finish,
                                                                ).encode()
                                                            )
                                                        continue

                                                    # D1 多路直接逐路还原：当前事件含多路非空文本
                                                    # 且无历史持有时，各路独立还原后单次重建发射
                                                    # （禁止拼合广播；有残缺悬挂时回退 joint 路径，
                                                    # 跨事件持有对齐属 3.x 范围）
                                                    _multi_c = [
                                                        i
                                                        for i, v in _idx_content.items()
                                                        if v
                                                    ]
                                                    _multi_r = [
                                                        i
                                                        for i, v in _idx_reasoning.items()
                                                        if v
                                                    ]
                                                    if (
                                                        (
                                                            len(_multi_c) > 1
                                                            or len(_multi_r) > 1
                                                        )
                                                        and not content_buf
                                                        and not reasoning_buf
                                                    ):
                                                        _cbi_d: dict[int, str] = {}
                                                        _rbi_d: dict[int, str] = {}
                                                        _has_pend = False
                                                        for _di in _multi_c:
                                                            _rr = await self._pii_response_process(
                                                                _idx_content[_di],
                                                                active_t2p,
                                                            )
                                                            _ss, _pp = _split_safe_hold(
                                                                _rr,
                                                                active_t2p,
                                                                self._pii_scope_or_none(),
                                                            )
                                                            _ss = _strip_partials(_ss)
                                                            if _ss:
                                                                _cbi_d[_di] = _ss
                                                            if _pp:
                                                                _has_pend = True
                                                        for _di in _multi_r:
                                                            _rr = await self._pii_response_process(
                                                                _idx_reasoning[_di],
                                                                active_t2p,
                                                            )
                                                            _ss, _pp = _split_safe_hold(
                                                                _rr,
                                                                active_t2p,
                                                                self._pii_scope_or_none(),
                                                            )
                                                            _ss = _strip_partials(_ss)
                                                            if _ss:
                                                                _rbi_d[_di] = _ss
                                                            if _pp:
                                                                _has_pend = True
                                                        if not _has_pend and (
                                                            _cbi_d or _rbi_d
                                                        ):
                                                            await _tracked_write(
                                                                _mk_sse_event(
                                                                    parsed=parsed,
                                                                    content_by_index=(
                                                                        _cbi_d or None
                                                                    ),
                                                                    reasoning_by_index=(
                                                                        _rbi_d or None
                                                                    ),
                                                                    finish_by_index=(
                                                                        _idx_finish
                                                                        or None
                                                                    ),
                                                                ).encode(),
                                                            )
                                                            continue

                                                    # ── Reasoning content（独立处理，不受 content 影响）──
                                                    # 9.3: rc_val 已在 choices 循环中聚合（_agg_reasoning）
                                                    if rc_val is not None:
                                                        norm = rc_val.replace(
                                                            '\r\n', '\n'
                                                        ).replace('\r', '\n')
                                                        reasoning_buf += norm
                                                        reasoning_buf_src.update(
                                                            _multi_r
                                                        )
                                                        reasoning_buf_ts = (
                                                            _time.monotonic()
                                                        )
                                                        out_rc = []
                                                        while '\n' in reasoning_buf:
                                                            line_seg, reasoning_buf = (
                                                                reasoning_buf.split(
                                                                    '\n', 1
                                                                )
                                                            )
                                                            line_seg += '\n'
                                                            restored = await self._pii_response_process(
                                                                line_seg, active_t2p
                                                            )
                                                            safe = _strip_partials(
                                                                restored
                                                            )
                                                            if safe:
                                                                out_rc.append(safe)
                                                        _reason_extra_31 = (
                                                            self._extra_prefixes(
                                                                reasoning_buf[-64:]
                                                            )
                                                        )
                                                        _reason_cand_31 = (
                                                            _has_partial_pii_candidate(
                                                                reasoning_buf[-64:],
                                                                _reason_extra_31,
                                                            )
                                                        )
                                                        if reasoning_buf and (
                                                            len(reasoning_buf)
                                                            > LINE_BUF_FLUSH
                                                            or _time.monotonic()
                                                            - reasoning_buf_ts
                                                            > LINE_BUF_MAX_AGE
                                                            or _reason_cand_31
                                                        ):
                                                            restored = await self._pii_response_process(
                                                                reasoning_buf,
                                                                active_t2p,
                                                            )
                                                            _same_reason_31 = (
                                                                restored
                                                                == reasoning_buf
                                                            )
                                                            safe, pending = (
                                                                _split_safe_hold(
                                                                    restored,
                                                                    active_t2p,
                                                                    self._pii_scope_or_none(),
                                                                    extra_prefixes=_reason_extra_31
                                                                    if _same_reason_31
                                                                    else None,
                                                                    hold_pii_tail=_same_reason_31,
                                                                )
                                                            )
                                                            if safe:
                                                                safe = _strip_partials(
                                                                    safe
                                                                )
                                                                out_rc.append(safe)
                                                                if not _reason_cand_31:
                                                                    self._count_custom_other_miss()
                                                            reasoning_buf = pending
                                                            reasoning_buf_ts = (
                                                                _time.monotonic()
                                                            )
                                                        if out_rc:
                                                            _rtxt = ''.join(out_rc)
                                                            _ridx = (
                                                                _single_mapped_index(
                                                                    reasoning_buf_src,
                                                                    _idx_reasoning,
                                                                    parsed,
                                                                )
                                                            )
                                                            if _ridx is None:
                                                                _rev = _mk_sse_event(
                                                                    reasoning_content=_rtxt
                                                                )
                                                            else:
                                                                _rev = _mk_sse_event(
                                                                    parsed=parsed,
                                                                    reasoning_by_index={
                                                                        _ridx: _rtxt
                                                                    },
                                                                )
                                                            await _tracked_write(
                                                                _rev.encode()
                                                            )
                                                        if (
                                                            finish_reason
                                                            and not content
                                                        ):
                                                            if reasoning_buf:
                                                                reasoning_buf = await self._pii_response_process(
                                                                    reasoning_buf,
                                                                    active_t2p,
                                                                )
                                                                reasoning_buf = (
                                                                    _strip_partials(
                                                                        reasoning_buf
                                                                    )
                                                                )
                                                                _ridx2 = _single_mapped_index(
                                                                    reasoning_buf_src,
                                                                    _idx_reasoning,
                                                                    parsed,
                                                                )
                                                                if _ridx2 is None:
                                                                    _rev2 = _mk_sse_event(
                                                                        reasoning_content=reasoning_buf,
                                                                        finish_reason=finish_reason,
                                                                    )
                                                                else:
                                                                    _rev2 = _mk_sse_event(
                                                                        parsed=parsed,
                                                                        reasoning_by_index={
                                                                            _ridx2: reasoning_buf
                                                                        },
                                                                        finish_by_index=(
                                                                            _idx_finish
                                                                            or None
                                                                        ),
                                                                    )
                                                                await _tracked_write(
                                                                    _rev2.encode()
                                                                )
                                                                reasoning_buf = ''
                                                                reasoning_buf_src.clear()
                                                            else:
                                                                await _tracked_write(
                                                                    _mk_sse_event(
                                                                        parsed=parsed,
                                                                        finish_by_index=(
                                                                            _idx_finish
                                                                            or None
                                                                        ),
                                                                    ).encode()
                                                                )
                                                            reasoning_buf_ts = (
                                                                _time.monotonic()
                                                            )

                                                    # ── Content / 非 content 事件 ──
                                                    # 9.3: content 已在循环中聚合（_agg_content）
                                                    if content:
                                                        norm = content.replace(
                                                            '\r\n', '\n'
                                                        ).replace('\r', '\n')
                                                        content_buf += norm
                                                        content_buf_src.update(_multi_c)
                                                        line_buf_ts = _time.monotonic()
                                                        out_c = []
                                                        while '\n' in content_buf:
                                                            line_seg, content_buf = (
                                                                content_buf.split(
                                                                    '\n', 1
                                                                )
                                                            )
                                                            line_seg += '\n'
                                                            restored = await self._pii_response_process(
                                                                line_seg, active_t2p
                                                            )
                                                            safe = _strip_partials(
                                                                restored
                                                            )
                                                            if safe:
                                                                out_c.append(safe)
                                                        _content_extra_31 = (
                                                            self._extra_prefixes(
                                                                content_buf[-64:]
                                                            )
                                                        )
                                                        _content_cand_31 = (
                                                            _has_partial_pii_candidate(
                                                                content_buf[-64:],
                                                                _content_extra_31,
                                                            )
                                                        )
                                                        if content_buf and (
                                                            len(content_buf)
                                                            > LINE_BUF_FLUSH
                                                            or _time.monotonic()
                                                            - line_buf_ts
                                                            > LINE_BUF_MAX_AGE
                                                            or _content_cand_31
                                                        ):
                                                            restored = await self._pii_response_process(
                                                                content_buf, active_t2p
                                                            )
                                                            _same_content_31 = (
                                                                restored == content_buf
                                                            )
                                                            safe, pending = (
                                                                _split_safe_hold(
                                                                    restored,
                                                                    active_t2p,
                                                                    self._pii_scope_or_none(),
                                                                    extra_prefixes=_content_extra_31
                                                                    if _same_content_31
                                                                    else None,
                                                                    hold_pii_tail=_same_content_31,
                                                                )
                                                            )
                                                            if safe:
                                                                safe = _strip_partials(
                                                                    safe
                                                                )
                                                                out_c.append(safe)
                                                                if not _content_cand_31:
                                                                    self._count_custom_other_miss()
                                                            content_buf = pending
                                                            line_buf_ts = (
                                                                _time.monotonic()
                                                            )
                                                        if out_c:
                                                            _ctxt = ''.join(out_c)
                                                            _cidx = (
                                                                _single_mapped_index(
                                                                    content_buf_src,
                                                                    _idx_content,
                                                                    parsed,
                                                                )
                                                            )
                                                            if _cidx is None:
                                                                _cev = _mk_sse_event(
                                                                    _ctxt
                                                                )
                                                            else:
                                                                _cev = _mk_sse_event(
                                                                    parsed=parsed,
                                                                    content_by_index={
                                                                        _cidx: _ctxt
                                                                    },
                                                                )
                                                            await _tracked_write(
                                                                _cev.encode()
                                                            )
                                                        if finish_reason:
                                                            if content_buf:
                                                                content_buf = await self._pii_response_process(
                                                                    content_buf,
                                                                    active_t2p,
                                                                )
                                                                content_buf = (
                                                                    _strip_partials(
                                                                        content_buf
                                                                    )
                                                                )
                                                                _cidx2 = _single_mapped_index(
                                                                    content_buf_src,
                                                                    _idx_content,
                                                                    parsed,
                                                                )
                                                                if _cidx2 is None:
                                                                    _cev2 = _mk_sse_event(
                                                                        content_buf,
                                                                        finish_reason,
                                                                    )
                                                                else:
                                                                    _cev2 = _mk_sse_event(
                                                                        parsed=parsed,
                                                                        content_by_index={
                                                                            _cidx2: content_buf
                                                                        },
                                                                        finish_by_index=(
                                                                            _idx_finish
                                                                            or None
                                                                        ),
                                                                    )
                                                                await _tracked_write(
                                                                    _cev2.encode()
                                                                )
                                                                content_buf = ''
                                                                content_buf_src.clear()
                                                                line_buf_ts = (
                                                                    _time.monotonic()
                                                                )
                                                            else:
                                                                await _tracked_write(
                                                                    _mk_sse_event(
                                                                        parsed=parsed,
                                                                        finish_by_index=(
                                                                            _idx_finish
                                                                            or None
                                                                        ),
                                                                    ).encode()
                                                                )
                                                    elif (
                                                        'reasoning_content' not in line
                                                        and content == ''
                                                    ):
                                                        # 真正的非 content 事件
                                                        await _flush(
                                                            c=content_buf,
                                                            rc=reasoning_buf,
                                                        )
                                                        # 10.14 (API-SPEC): 透传前把
                                                        # 暂存的 event:/id: 行拼入同一块
                                                        # （SSE 规范：event+data 同块，
                                                        # 空行分隔）。anthropic 的
                                                        # message_start/message_delta
                                                        # 等非 delta 事件在这里透传，
                                                        # 不拼装会把块拆成 event 独块 +
                                                        # data 独块 → SDK JSONDecodeError
                                                        # （responses 分支已有同逻辑）。
                                                        # 注意：此处 join 全部（SSE 覆盖
                                                        # 语义——anthropic 分支的
                                                        # content_block_delta 等事件在
                                                        # _handle_anthropic_event 内部
                                                        # 输出 data 行不消费 pending，
                                                        # pending 里的 event 行是留给
                                                        # 下一个透传 data 行的；FIFO
                                                        # 弹旧行会错配）。
                                                        if slow_event_pending:
                                                            line = (
                                                                '\n'.join(
                                                                    slow_event_pending
                                                                )
                                                                + '\n'
                                                                + line
                                                            )
                                                            slow_event_pending.clear()
                                                        # 审计阻断：抑制 tool_calls 事件流出
                                                        # （design D4：拒绝后 tool call 不发给客户端）
                                                        # 2.2 结构化阻断：delta.tool_calls 结构化判定 +
                                                        # finish_reason 兜底；子串/role 启发式已移除；
                                                        # 未识别形态整行透传不抑制。
                                                        if tool_calls_blocked and (
                                                            _line_has_tool_calls
                                                            or _any_tool_calls_finish
                                                        ):
                                                            continue
                                                        await _tracked_write(
                                                            (
                                                                await self._pii_process_sse_line(
                                                                    line,
                                                                    active_t2p,
                                                                    parsed_obj=parsed,
                                                                )
                                                                + '\n\n'
                                                            ).encode('utf-8'),
                                                        )

                                                except json.JSONDecodeError:
                                                    # 尝试从 byte_buf 读取续行重建 JSON
                                                    # （处理 \n 在 JSON content 内截断的情况）
                                                    accumulated = payload
                                                    reconstructed = False
                                                    parsed = None  # 续行重建成功时赋值
                                                    sanitized = ''
                                                    for _ in range(20):
                                                        nl = byte_buf.find(b'\n', pos)
                                                        if nl < 0:
                                                            break
                                                        next_line = (
                                                            bytes(byte_buf[pos:nl])
                                                            .decode(
                                                                'utf-8',
                                                                errors='replace',
                                                            )
                                                            .rstrip('\r')
                                                        )
                                                        # 只有不以 data:/event:/id: 开头的行才是续行
                                                        if (
                                                            not next_line.strip()
                                                            or next_line.startswith(
                                                                (
                                                                    'data:',
                                                                    'event:',
                                                                    'id:',
                                                                )
                                                            )
                                                        ):
                                                            break
                                                        accumulated += '\n' + next_line
                                                        pos = nl + 1
                                                        try:
                                                            sanitized = _sanitize_json(
                                                                accumulated,
                                                            )
                                                            parsed = json.loads(
                                                                sanitized
                                                            )
                                                            reconstructed = True
                                                            if resp_log_path:
                                                                await (
                                                                    _save_response_line(
                                                                        resp_log_path,
                                                                        sanitized,
                                                                    )
                                                                )
                                                            break
                                                        except json.JSONDecodeError:
                                                            continue
                                                    if reconstructed:
                                                        if parsed is None:
                                                            continue  # pragma: no cover
                                                        # 非 dict payload（数组/标量）→ 原样透传
                                                        # （与主循环 isinstance 防御对称）
                                                        if not isinstance(parsed, dict):
                                                            await _tracked_write(
                                                                (
                                                                    await self._pii_process_sse_line(
                                                                        'data: '
                                                                        + sanitized,
                                                                        active_t2p,
                                                                    )
                                                                    + '\n\n'
                                                                ).encode('utf-8'),
                                                            )
                                                            continue
                                                        # ── Responses API 事件（续行重建路径）──
                                                        if (
                                                            _responses_event(parsed)
                                                            is not None
                                                        ):
                                                            is_responses_stream = True
                                                            if parsed.get('type') in (
                                                                'response.completed',
                                                                'response.failed',
                                                                'response.incomplete',
                                                                'response.error',
                                                            ):
                                                                seen_terminal = True
                                                                seen_global_terminal = (
                                                                    True
                                                                )
                                                            (
                                                                content_buf,
                                                                reasoning_buf,
                                                                arg_buf,
                                                            ) = await self._handle_responses_event(
                                                                _tracked_write,
                                                                parsed,
                                                                (
                                                                    (
                                                                        slow_event_pending.pop(
                                                                            0
                                                                        )
                                                                        + '\n'
                                                                    )
                                                                    if slow_event_pending
                                                                    else ''
                                                                )
                                                                + 'data: '
                                                                + sanitized,
                                                                active_t2p,
                                                                content_buf,
                                                                reasoning_buf,
                                                                arg_buf,
                                                            )
                                                            content_buf_src.clear()
                                                            reasoning_buf_src.clear()
                                                            continue
                                                        # ── Anthropic Messages API 事件（续行重建路径）──
                                                        if (
                                                            _anthropic_event(parsed)
                                                            is not None
                                                        ):
                                                            is_anthropic_stream = True
                                                            if (
                                                                parsed.get('type')
                                                                == 'message_stop'
                                                            ):
                                                                seen_terminal = True
                                                                seen_global_terminal = (
                                                                    True
                                                                )
                                                            (
                                                                content_buf,
                                                                reasoning_buf,
                                                                arg_buf,
                                                            ) = await self._handle_anthropic_event(
                                                                _tracked_write,
                                                                parsed,
                                                                'data: ' + sanitized,
                                                                active_t2p,
                                                                content_buf,
                                                                reasoning_buf,
                                                                arg_buf,
                                                            )
                                                            content_buf_src.clear()
                                                            reasoning_buf_src.clear()
                                                            continue
                                                        if (
                                                            parsed.get('type')
                                                            == 'message_stop'
                                                        ):
                                                            seen_terminal = True
                                                            seen_global_terminal = True
                                                        if (
                                                            parsed.get('type')
                                                            == 'error'
                                                        ):
                                                            # 10.14 (API-SPEC): 同主循环——
                                                            # Anthropic error 事件也是正常终止
                                                            seen_terminal = True
                                                            seen_global_terminal = True
                                                        choices = parsed.get(
                                                            'choices',
                                                            [],
                                                        )
                                                        # 9.3 (F-03): 续行重建同样全量遍历
                                                        # choices（原 choices[0] 只取首路）
                                                        _agg_c = ''
                                                        _agg_rc = None
                                                        _agg_fr = None
                                                        _agg_delta = None  # 10.1.1 (R-01): 续行路径补 delta 聚合
                                                        _idx_content = {}
                                                        _idx_reasoning = {}
                                                        _idx_finish = {}
                                                        for _cpos, _ch in enumerate(
                                                            choices
                                                            if isinstance(choices, list)
                                                            else []
                                                        ):
                                                            _cidx = _chat_choice_index(
                                                                _ch, _cpos
                                                            )
                                                            _d = (
                                                                _ch.get('delta', {})
                                                                if isinstance(_ch, dict)
                                                                else {}
                                                            )
                                                            if not isinstance(_d, dict):
                                                                _d = {}
                                                            if (
                                                                _agg_delta is None
                                                                and _d
                                                            ):
                                                                _agg_delta = _d
                                                            _c = _d.get('content')
                                                            if _c is not None:
                                                                _agg_c += _c
                                                            if (
                                                                isinstance(_c, str)
                                                                and _c
                                                            ):
                                                                _idx_content[_cidx] = (
                                                                    _idx_content.get(
                                                                        _cidx, ''
                                                                    )
                                                                    + _c
                                                                )
                                                            _cref = _d.get('refusal')
                                                            if (
                                                                isinstance(_cref, str)
                                                                and _cref
                                                            ):
                                                                _agg_c += _cref
                                                                _idx_content[_cidx] = (
                                                                    _idx_content.get(
                                                                        _cidx, ''
                                                                    )
                                                                    + _cref
                                                                )
                                                                _d.pop('refusal', None)
                                                            _rc = _d.get(
                                                                'reasoning_content'
                                                            )
                                                            if _rc is None:
                                                                _rc = _d.get(
                                                                    'reasoning'
                                                                )
                                                            if (
                                                                isinstance(_rc, str)
                                                                and _rc
                                                            ):
                                                                if not isinstance(
                                                                    _agg_rc, str
                                                                ):
                                                                    _agg_rc = ''
                                                                _agg_rc += _rc
                                                            elif (
                                                                _rc is not None
                                                                and _agg_rc is None
                                                            ):
                                                                _agg_rc = _rc
                                                            if (
                                                                isinstance(_rc, str)
                                                                and _rc
                                                            ):
                                                                _idx_reasoning[
                                                                    _cidx
                                                                ] = (
                                                                    _idx_reasoning.get(
                                                                        _cidx, ''
                                                                    )
                                                                    + _rc
                                                                )
                                                            _fr = (
                                                                _ch.get('finish_reason')
                                                                if isinstance(_ch, dict)
                                                                else None
                                                            )
                                                            if (
                                                                _fr is not None
                                                                and _agg_fr is None
                                                            ):
                                                                _agg_fr = _fr
                                                            if _fr is not None:
                                                                _idx_finish[_cidx] = _fr
                                                        content = _agg_c
                                                        rc_val = _agg_rc
                                                        finish_reason = _agg_fr
                                                        # 10.1.1 (R-01): 续行路径曾缺 delta 赋值
                                                        # （3303 elif 引用 NameError/陈旧值）
                                                        delta = _agg_delta or {}
                                                        if finish_reason is not None:
                                                            seen_terminal = True

                                                            seen_global_terminal = True
                                                        # reasoning_content 独立处理
                                                        if rc_val is not None:
                                                            rc_combined = (
                                                                reasoning_buf + rc_val
                                                            )
                                                            _rridx = (
                                                                _single_mapped_index(
                                                                    reasoning_buf_src,
                                                                    _idx_reasoning,
                                                                    parsed,
                                                                )
                                                            )
                                                            reasoning_buf = ''
                                                            reasoning_buf_src.clear()
                                                            rc_restored = await self._pii_response_process(
                                                                rc_combined, active_t2p
                                                            )
                                                            rc_restored = (
                                                                _strip_partials(
                                                                    rc_restored
                                                                )
                                                            )
                                                            if _rridx is None:
                                                                _rrev = _mk_sse_event(
                                                                    reasoning_content=rc_restored,
                                                                    finish_reason=(
                                                                        finish_reason
                                                                        if not content
                                                                        else None
                                                                    ),
                                                                )
                                                            else:
                                                                _rrev = _mk_sse_event(
                                                                    parsed=parsed,
                                                                    reasoning_by_index={
                                                                        _rridx: rc_restored
                                                                    },
                                                                    finish_by_index=(
                                                                        _idx_finish
                                                                        or None
                                                                        if not content
                                                                        else None
                                                                    ),
                                                                )
                                                            await _tracked_write(
                                                                _rrev.encode(),
                                                            )

                                                        # content / 非 content
                                                        if content:
                                                            combined = (
                                                                content_buf + content
                                                            )
                                                            _ccidx = (
                                                                _single_mapped_index(
                                                                    content_buf_src,
                                                                    _idx_content,
                                                                    parsed,
                                                                )
                                                            )
                                                            content_buf = ''
                                                            content_buf_src.clear()
                                                            restored = await self._pii_response_process(
                                                                combined, active_t2p
                                                            )
                                                            restored = _strip_partials(
                                                                restored
                                                            )
                                                            if _ccidx is None:
                                                                _cev3 = _mk_sse_event(
                                                                    content=restored,
                                                                    finish_reason=finish_reason,
                                                                )
                                                            else:
                                                                _cev3 = _mk_sse_event(
                                                                    parsed=parsed,
                                                                    content_by_index={
                                                                        _ccidx: restored
                                                                    },
                                                                    finish_by_index=(
                                                                        _idx_finish
                                                                        or None
                                                                    ),
                                                                )
                                                            await _tracked_write(
                                                                _cev3.encode(),
                                                            )
                                                        elif (
                                                            'reasoning_content'
                                                            not in delta
                                                        ):
                                                            # 非 content 事件
                                                            await _flush(
                                                                c=content_buf,
                                                                rc=reasoning_buf,
                                                            )
                                                            await _tracked_write(
                                                                (
                                                                    await self._pii_process_sse_line(
                                                                        'data: '
                                                                        + sanitized,
                                                                        active_t2p,
                                                                    )
                                                                    + '\n\n'
                                                                ).encode('utf-8'),
                                                            )
                                                    else:
                                                        # pos 已越过续行，不回退（续行已在 byte_buf 中被消费）
                                                        # 8.4 修复（F-04）：多 data 行无空行分隔时聚合 payload
                                                        # 解析失败且续行重建失败 → 逐行独立脱敏后转发，
                                                        # 不转发未脱敏原始行（防明文泄漏）
                                                        logger.warning(
                                                            'SSE JSON 解析失败，'
                                                            '续行重建失败，逐行脱敏转发: %s...',
                                                            payload[:80],
                                                        )
                                                        for _sub in payload.split('\n'):
                                                            if not _sub.strip():
                                                                continue
                                                            await _tracked_write(
                                                                (
                                                                    await self._pii_process_sse_line(
                                                                        'data: ' + _sub,
                                                                        active_t2p,
                                                                    )
                                                                    + '\n\n'
                                                                ).encode('utf-8'),
                                                            )
                                                except (
                                                    KeyError,
                                                    IndexError,
                                                    TypeError,
                                                ):
                                                    logger.warning(
                                                        'SSE 数据结构异常: %s...',
                                                        payload[:80],
                                                    )
                                                    await _tracked_write(
                                                        (
                                                            await self._pii_process_sse_line(
                                                                line, active_t2p
                                                            )
                                                            + '\n\n'
                                                        ).encode('utf-8'),
                                                    )
                                            continue
                                        if line.startswith(':'):
                                            await _tracked_write(
                                                (line + '\n').encode('utf-8')
                                            )
                                            continue
                                        if ':' in line:
                                            field, value = line.split(':', 1)
                                            value = value.removeprefix(' ')
                                            if field == 'data':
                                                data_buffer.append(value)
                                                continue
                                            elif field == 'event' or field == 'id':
                                                # 10.13 (F-12): 暂存不立即透传 ——
                                                # 立即透传会把 SSE 块拆成 event 独块 +
                                                # data 独块，openai sdk 按块解析 →
                                                # JSONDecodeError。暂存后拼入 data 行
                                                # 同一块写出（见 _handle_responses_event
                                                # 调用点前的拼装）。
                                                slow_event_pending.append(
                                                    await self._pii_process_sse_line(
                                                        line, active_t2p
                                                    )
                                                )
                                                continue
                                            elif field == 'retry':
                                                if value.isdigit() and value.isascii():
                                                    await _tracked_write(
                                                        (line + '\n').encode('utf-8')
                                                    )
                                                continue
                                            else:
                                                await _tracked_write(
                                                    (
                                                        await self._pii_process_sse_line(
                                                            line, active_t2p
                                                        )
                                                        + '\n\n'
                                                    ).encode('utf-8')
                                                )
                                                continue
                                        else:
                                            field = line
                                            value = ''
                                            if field == 'data':
                                                data_buffer.append(value)
                                                continue
                                            elif field in ('event', 'id'):
                                                # 10.13 (F-12): 暂存不立即透传
                                                # （同上方 event/id 分支）
                                                slow_event_pending.append(
                                                    await self._pii_process_sse_line(
                                                        line, active_t2p
                                                    )
                                                )
                                                continue
                                            elif field == 'retry':
                                                continue
                                            else:
                                                await _tracked_write(
                                                    (
                                                        await self._pii_process_sse_line(
                                                            line, active_t2p
                                                        )
                                                        + '\n\n'
                                                    ).encode('utf-8')
                                                )
                                                continue
                                    # Trim processed portion (F-01: 移出 while 循环体，
                                    # 原 3284-3301 在 c4750dc §7 重构时被误缩进进 while True
                                    # 体内，体内 5 分支全 continue/break 无一 fallthrough →
                                    # del 永不执行，byte_buf 单调增长致正常流误判截断+重复 DONE)
                                    if pos > 0:
                                        del byte_buf[:pos]
                                    if len(byte_buf) > SSE_MAX_BUF:
                                        logger.warning(
                                            'SSE 缓冲区超过 1MB 上限，保留最后一个部分行'
                                        )
                                        last_nl = byte_buf.rfind(b'\n')
                                        if last_nl >= 0:
                                            byte_buf = bytearray(
                                                byte_buf[last_nl + 1 :]
                                            )
                                        if len(byte_buf) > SSE_MAX_BUF:
                                            byte_buf = bytearray()
                                        # 7.5: 截断后清空 data_buffer 避免残留与后续事件叠加
                                        try:
                                            data_buffer.clear()
                                        except Exception:
                                            pass

                            except SSE_CLIENT_GONE as e:
                                logger.debug('SSE 客户端断连: %s', e)

                            # 流结束：未审计 tool call 兜底（design D4 硬性）
                            # EOF/[DONE] 前上游正常结束但无终止事件（不完整
                            # tool call）→ 一律 fail-closed 丢弃 + 注入拒绝；
                            # 连接中断（无 [DONE]）同理——已累积未审计的
                            # tool call 不得静默 flush
                            if (
                                tool_calls_buf
                                and not tool_calls_audited
                                and self.audit_enabled()
                            ):
                                tool_calls_audited = True
                                _inj = await self._audit_openai_tool_calls(
                                    tool_calls_buf,
                                    active_t2p,
                                )
                                if _inj:
                                    tool_calls_blocked = True
                                    tool_calls_pending_events.clear()
                                    tool_calls_buf.clear()
                                    _eof_injected_ok = False
                                    for _ev in _inj:
                                        try:
                                            await _tracked_write(_ev.encode('utf-8'))
                                            _eof_injected_ok = True
                                        except SSE_CLIENT_GONE:
                                            break
                                    if _eof_injected_ok:
                                        audit_block_injected = True
                                else:
                                    try:
                                        await _single_flush_openai_tool_calls(
                                            slow_last_chat_parsed
                                        )
                                    except SSE_CLIENT_GONE:
                                        pass
                                    tool_calls_pending_events.clear()
                                    tool_calls_buf.clear()

                            # 流末：Anthropic/Responses 未完成 tool call 兜底
                            # （design D4 硬性：正常结束但无 block_stop/item_done
                            # 终止事件 → 不完整参数不得 flush，fail-closed 丢弃）
                            # F-12 合并：arg_buf 即原始参数累积器（主循环闭包持有，
                            # 流末仍保留未消费参数；旧 _audit_arg_accum 已删除）
                            if (
                                arg_buf
                                and self.audit_enabled()
                                and (is_anthropic_stream or is_responses_stream)
                            ):
                                _name = (
                                    self._last_anthropic_tool_name
                                    if is_anthropic_stream
                                    else self._last_responses_tool_name
                                ) or ''
                                _args = arg_buf
                                _verdict = await self.audit_tool_call(_name, _args)
                                if _verdict == 'deny' and self.audit_mode == 'approve':
                                    _result = await self._request_audit_approval(
                                        _name, _args
                                    )
                                    if _result != 'approved':
                                        _verdict = 'deny'
                                if _verdict == 'deny':
                                    # 不完整 tool call：丢弃 arg_buf + 注入拒绝
                                    arg_buf = ''
                                    if is_anthropic_stream:
                                        _block = self._build_block_event_anthropic()
                                    else:
                                        _block = self._build_block_event_responses()
                                    try:
                                        await _tracked_write(_block.encode('utf-8'))
                                        audit_block_injected = True
                                    except SSE_CLIENT_GONE:
                                        pass
                                self._last_anthropic_tool_name = None
                                self._last_responses_tool_name = None

                            # ── 8.5 修复（F-05）：流末 pending_cr 视为行终止符 ──
                            # CR-only 行（无 LF）在流末残留 \r：pending_cr=True 且
                            # byte_buf 以 \r 结尾 → 立即 dispatch 该行，
                            # 不残留 \r 触发截断误报、不丢该行数据
                            if pending_cr and byte_buf and byte_buf.endswith(b'\r'):
                                _cr_text = bytes(byte_buf[:-1]).decode(
                                    'utf-8', errors='replace'
                                )
                                byte_buf.clear()
                                pending_cr = False
                                # 10.14.1 (API-SPEC FIX): EOF 残留可能是
                                # 多行（CR-only 分批到达时主循环 pending_cr
                                # break，byte_buf 残留整个未处理批次，如
                                # `event: a\ndata: {...}\nevent: b\ndata: {...}`）。
                                # 必须按 \n 切分成行逐行处理——整段当单行会：
                                # ① event 行与 data 行全拼一块（协议污染，
                                #    SDK 取最后一个 event 名配第一个 data）；
                                # ② 顺序颠倒/坏块。
                                for _cr_line in _cr_text.split('\n'):
                                    if not _cr_line.strip():
                                        continue
                                    if _cr_line.startswith(':'):
                                        await _tracked_write(
                                            (_cr_line + '\n').encode('utf-8')
                                        )
                                    elif _cr_line.startswith('data:'):
                                        _pl = _cr_line[5:].removeprefix(' ')
                                        # 10.14.1 (API-SPEC FIX): CR-only 多行流
                                        # 中 [DONE] 不得立即透传——同一 EOF 批次的
                                        # 前面 content 行仍在 data_buffer 未 dispatch，
                                        # 立即透传会颠倒顺序（SDK 收到 [DONE] 即
                                        # 结束流，后续 content 全丢）。改为入
                                        # data_buffer 保持行序统一 dispatch。
                                        # 同时 [DONE] 行与 content 行同批
                                        # dispatch（行序保持），见下方 9.4。
                                        if _pl.strip():
                                            data_buffer.append(_pl)
                                        # 9.4 (F-04): CR-only 行流末立即 dispatch，
                                        # 不能等流末统一处理 —— 下方截断检测会把
                                        # data_buffer 残留当截断 clear 丢弃（原注释
                                        # 「交由下方统一处理」落空，快链 3922 有 dispatch
                                        # 慢链没有 → 双链不对称）
                                        if data_buffer:
                                            _cr_payload = '\n'.join(data_buffer)
                                            data_buffer.clear()
                                            if _cr_payload.strip():
                                                sse_event_count += 1
                                                if _cr_payload.strip() == '[DONE]':
                                                    seen_global_terminal = True
                                                # 9.4 补 (F-04): CR-only 行若含
                                                # finish_reason（chat）或终止事件类型
                                                # （responses/anthropic），同样置位全局
                                                # 终止——否则流末误判截断合成（CR 行
                                                # 绕过主循环 JSON 解析，finish_reason
                                                # 不会被 _seen_any_finish 捕获）
                                                else:
                                                    # 10.8.1 (F-08): join 后一次
                                                    # json.loads 对多 data 行（WHATWG
                                                    # 同事件多行 `{a}\n{b}`）必失败 →
                                                    # 逐个条目分别解析判断终止，任一
                                                    # 含 finish_reason/终止类型即置位
                                                    # （data_buffer 已 clear，用
                                                    # _cr_payload 按行切回条目）
                                                    _cr_term_found = False
                                                    for _cr_entry in _cr_payload.split(
                                                        '\n'
                                                    ):
                                                        _cr_entry_plain = (
                                                            _cr_entry.strip()
                                                        )
                                                        if not _cr_entry_plain:
                                                            continue
                                                        # 10.14.1 (API-SPEC FIX):
                                                        # CR-only 多行流中 [DONE] 行
                                                        # 与 content 行同批 dispatch
                                                        # （行序保持），逐条判断时
                                                        # [DONE] 同样置位全局终止
                                                        if _cr_entry_plain == '[DONE]':
                                                            _cr_term_found = True
                                                            break
                                                        try:
                                                            _cr_parsed = json.loads(
                                                                _cr_entry_plain
                                                            )
                                                        except Exception:  # noqa: S112 - 非 JSON 条目跳过是设计
                                                            # 单个 data 条目非 JSON 跳过，
                                                            # 其余条目继续判断终止
                                                            continue
                                                        _cr_choices = (
                                                            _cr_parsed.get(
                                                                'choices', []
                                                            )
                                                            if isinstance(
                                                                _cr_parsed, dict
                                                            )
                                                            else []
                                                        )
                                                        _cr_fr = any(
                                                            (
                                                                _c.get('finish_reason')
                                                                is not None
                                                            )
                                                            for _c in _cr_choices
                                                            if isinstance(_c, dict)
                                                        )
                                                        _cr_term = (
                                                            _cr_parsed.get('type')
                                                            in (
                                                                'response.completed',
                                                                'response.failed',
                                                                'response.incomplete',
                                                                # 10.14 (API-SPEC):
                                                                # error 事件也是正常终止
                                                                'response.error',
                                                                'message_stop',
                                                                'error',
                                                            )
                                                            if isinstance(
                                                                _cr_parsed, dict
                                                            )
                                                            else False
                                                        )
                                                        if _cr_fr or _cr_term:
                                                            _cr_term_found = True
                                                            break
                                                    if _cr_term_found:
                                                        seen_global_terminal = True
                                                # _pii_process_sse_line 接收完整 SSE 行
                                                # （含 data: 前缀），返回完整行。
                                                # 10.14.1 (API-SPEC FIX): CR-only 多行
                                                # 流逐条 dispatch（每行独立 data: 前缀 +
                                                # 独立空行块），保持行序 content 在前、
                                                # [DONE] 在后；不能整体 join 后单次传
                                                # —— [DONE] 行会丢 data: 前缀混入
                                                # content 块（SDK JSONDecodeError）。
                                                for _cr_line_out in _cr_payload.split(
                                                    '\n'
                                                ):
                                                    if not _cr_line_out.strip():
                                                        continue
                                                    # 10.14.1 (API-SPEC FIX):
                                                    # 透传 [DONE] 行时置位
                                                    # _done_sent，防止流末
                                                    # 9.4 补发逻辑双发
                                                    if _cr_line_out.strip() == '[DONE]':
                                                        _done_sent = True
                                                    # 10.14.1 (API-SPEC FIX):
                                                    # data 行 dispatch 前把暂存的
                                                    # event:/id: 行拼入同块（SSE
                                                    # 规范：event+data 同块，空行
                                                    # 分隔）——否则 event 独块 +
                                                    # data 独块被 SDK 按块解析报
                                                    # JSONDecodeError。多条 event
                                                    # 累积时按 FIFO 弹第一条配对。
                                                    _cr_block = ''
                                                    if slow_event_pending:
                                                        _cr_block = (
                                                            slow_event_pending.pop(0)
                                                            + '\n'
                                                        )
                                                    # 事件识别置位（responses /
                                                    # anthropic 终止事件）：CR-only
                                                    # 路径绕过主循环 JSON 解析，
                                                    # 此处补协议判定，防止流末
                                                    # 误按 chat 协议补 [DONE]
                                                    try:
                                                        _cr_parsed2 = json.loads(
                                                            _cr_line_out
                                                        )
                                                        if isinstance(
                                                            _cr_parsed2, dict
                                                        ):
                                                            _cr_t2 = _cr_parsed2.get(
                                                                'type'
                                                            )
                                                            if (
                                                                _cr_t2
                                                                and _cr_t2.startswith(
                                                                    'response.'
                                                                )
                                                            ):
                                                                is_responses_stream = (
                                                                    True
                                                                )
                                                            if _cr_t2 in (
                                                                'response.completed',
                                                                'response.failed',
                                                                'response.incomplete',
                                                                'response.error',
                                                                'message_stop',
                                                                'error',
                                                            ):
                                                                seen_global_terminal = (
                                                                    True
                                                                )
                                                            if _cr_t2 in (
                                                                'message_start',
                                                                'content_block_start',
                                                                'content_block_delta',
                                                                'content_block_stop',
                                                                'message_delta',
                                                                'message_stop',
                                                                'error',
                                                                'ping',
                                                            ):
                                                                is_anthropic_stream = (
                                                                    True
                                                                )
                                                    except Exception:
                                                        pass
                                                    _cr_out = await self._pii_process_sse_line(
                                                        _cr_block
                                                        + 'data: '
                                                        + _cr_line_out,
                                                        active_t2p,
                                                    )
                                                    await _tracked_write(
                                                        (_cr_out + '\n\n').encode(
                                                            'utf-8'
                                                        )
                                                    )
                                    else:
                                        # 10.14.1 (API-SPEC FIX): event:/id: 行
                                        # 暂存 slow_event_pending（不立即透传——
                                        # 立即透传会把 SSE 块拆成 event 独块 +
                                        # data 独块，SDK JSONDecodeError；且
                                        # 绕过主循环事件识别导致
                                        # is_responses_stream 不置位，流末按
                                        # chat 协议误补 [DONE]）。data 行
                                        # dispatch 时拼入同块（下方逐条
                                        # dispatch 前拼装）。
                                        if _cr_line.startswith(('event:', 'id:')):
                                            slow_event_pending.append(
                                                await self._pii_process_sse_line(
                                                    _cr_line, active_t2p
                                                )
                                            )
                                        elif _cr_line.startswith(':'):
                                            await _tracked_write(
                                                (_cr_line + '\n').encode('utf-8')
                                            )
                                        else:
                                            await _tracked_write(
                                                (
                                                    await self._pii_process_sse_line(
                                                        _cr_line, active_t2p
                                                    )
                                                    + '\n\n'
                                                ).encode('utf-8')
                                            )

                            # 流结束：flush 残留（含 partial token 前缀清理）
                            if is_responses_stream:
                                # ── Responses 流：残留按对应 delta 事件类型输出 ──
                                await self._flush_responses_buf(
                                    _tracked_write,
                                    'response.output_text.delta',
                                    content_buf,
                                    active_t2p,
                                    keep_pending=False,
                                )
                                await self._flush_responses_buf(
                                    _tracked_write,
                                    'response.reasoning_text.delta',
                                    reasoning_buf,
                                    active_t2p,
                                    keep_pending=False,
                                )
                                await self._flush_responses_buf(
                                    _tracked_write,
                                    'response.function_call_arguments.delta',
                                    arg_buf,
                                    active_t2p,
                                    keep_pending=False,
                                )
                            elif is_anthropic_stream:
                                # ── Anthropic 流：残留按对应 delta 类型输出 ──
                                _dummy = {'type': 'content_block_delta', 'index': 0}
                                await self._flush_anthropic_buf(
                                    _tracked_write,
                                    _dummy,
                                    'text',
                                    content_buf,
                                    active_t2p,
                                    keep_pending=False,
                                )
                                await self._flush_anthropic_buf(
                                    _tracked_write,
                                    _dummy,
                                    'thinking',
                                    reasoning_buf,
                                    active_t2p,
                                    keep_pending=False,
                                )
                                await self._flush_anthropic_buf(
                                    _tracked_write,
                                    _dummy,
                                    'partial_json',
                                    arg_buf,
                                    active_t2p,
                                    keep_pending=False,
                                )
                            elif content_buf or reasoning_buf:
                                if content_buf:
                                    content_buf = await self._pii_response_process(
                                        content_buf, active_t2p
                                    )
                                    content_buf = _strip_partials(content_buf)
                                if reasoning_buf:
                                    reasoning_buf = await self._pii_response_process(
                                        reasoning_buf, active_t2p
                                    )
                                    reasoning_buf = _strip_partials(reasoning_buf)
                                if content_buf or reasoning_buf:
                                    # D1 流末残余改走结构保留重建（单路可映射时；
                                    # 多路/无映射回退原最小事件，不丢文本）
                                    _eec = _single_mapped_index(
                                        content_buf_src,
                                        {},
                                        slow_last_chat_parsed,
                                    )
                                    _eer = _single_mapped_index(
                                        reasoning_buf_src,
                                        {},
                                        slow_last_chat_parsed,
                                    )
                                    if (
                                        isinstance(slow_last_chat_parsed, dict)
                                        and (_eec is not None or _eer is not None)
                                        and (not content_buf or _eec is not None)
                                        and (not reasoning_buf or _eer is not None)
                                    ):
                                        _eev = _mk_sse_event(
                                            parsed=slow_last_chat_parsed,
                                            content_by_index=(
                                                {_eec: content_buf}
                                                if _eec is not None
                                                else None
                                            ),
                                            reasoning_by_index=(
                                                {_eer: reasoning_buf}
                                                if _eer is not None
                                                else None
                                            ),
                                        )
                                    else:
                                        _eev = _mk_sse_event(
                                            content=content_buf,
                                            reasoning_content=reasoning_buf,
                                        )
                                    try:
                                        await _tracked_write(_eev.encode())
                                    except SSE_CLIENT_GONE:
                                        logger.debug('SSE 残余写入失败')
                            # 10.13 (F-12): 流末 slow_event_pending 残留透传 ——
                            # data 行始终没来（异常流）时，不能把 event 行闷掉；
                            # 透传保留原始信息，客户端自行容错。
                            # 10.14.1 (API-SPEC FIX): 逐条透传独立块
                            # （多条 event 残留时 join 全拼成单块，
                            # SDK 取最后 event 名无 data 反而更乱）。
                            if slow_event_pending:
                                for _pend in slow_event_pending:
                                    await _tracked_write(
                                        (_pend + '\n\n').encode('utf-8'),
                                    )
                                slow_event_pending.clear()
                            # ── 截断检测：byte_buf/data_buffer 残留或未收到终止事件则告警并合成 ──
                            _truncated = False
                            # 9.2 (F-02): 截断判定收紧 —— 仅 byte_buf（未消费的部分行）
                            # 或 data_buffer（待 dispatch 事件）残留才判截断；
                            # content_buf/reasoning_buf/arg_buf 是逻辑行/参数缓冲，
                            # 流末 flush 已处理（3500-3514），残留不代表截断（原条件
                            # 过敏感，9.1 修复前 byte_buf 恒残留致正常流误报）
                            # 11.2 (TSS-01): 已 complete（seen_global_terminal=true）时
                            # byte_buf/data_buffer 残留（尾部 ping/重复对象）不判截断——
                            # 终止语义已完整传达，残留无内容价值，静默丢弃（stream_meta
                            # 记 truncated_mode=silent_discard）
                            if (byte_buf or data_buffer) and not seen_global_terminal:
                                _truncated = True
                                # 10.11.1 (F-SEC-03): preview 必须脱敏——
                                # byte_buf/data_buffer 残留可能含明文手机号/
                                # 邮箱/工具参数，直写日志形成 PII 泄漏路径。
                                # 剥离 PII 候选形态（__PII_/__VG_ 前缀、残缺
                                # 片段）+ 限制长度，保留排障信息
                                if byte_buf:
                                    _preview_raw = byte_buf[:200].decode(
                                        'utf-8', errors='replace'
                                    )
                                    # 10.11.1: 双重脱敏——先剥离 token 残缺
                                    # 形态，再过 redact_summary（手机号/邮箱等
                                    # 明文 PII → ***）
                                    _preview = _strip_partials(_preview_raw)
                                    _preview = redact_summary(_preview)
                                    if not _preview:
                                        _preview = (
                                            f'len={len(byte_buf)} '
                                            f'hex_head={bytes(byte_buf[:16]).hex()}'
                                        )
                                else:
                                    _preview = redact_summary(
                                        'data_buffer=' + str(data_buffer[:2])
                                        if data_buffer
                                        else ''
                                    )
                                logger.warning(
                                    'LLM 流截断: bytes_buf_len=%d data_buffer=%d content_buf=%d reasoning_buf=%d arg_buf=%d sse_events=%d bytes_written=%d req_id=%s tail=%s preview=%r',
                                    len(byte_buf),
                                    len(data_buffer),
                                    len(content_buf),
                                    len(reasoning_buf),
                                    len(arg_buf),
                                    sse_event_count,
                                    bytes_written,
                                    req_id,
                                    tail,
                                    _preview,
                                )
                                # 丢弃破损残余，不直接转发避免下游 JSONDecodeError
                                # 清空 data_buffer 避免重复合成
                                data_buffer.clear()
                            if (
                                not seen_global_terminal
                                and bytes_written > 0
                                and sse_event_count > 0
                            ):
                                if not _truncated:
                                    logger.warning(
                                        'LLM 流未收到终止事件: sse_events=%d bytes_written=%d req_id=%s tail=%s is_responses=%s is_anthropic=%s',
                                        sse_event_count,
                                        bytes_written,
                                        req_id,
                                        tail,
                                        is_responses_stream,
                                        is_anthropic_stream,
                                    )
                                _truncated = True
                            # 6.5 keepalive 清理
                            if keepalive_task is not None:
                                try:
                                    keepalive_task.cancel()
                                except Exception:
                                    pass
                                keepalive_task = None
                            if _truncated:
                                # 11.2 (TSS-02): 未 complete 截断不再伪造成功终止——
                                # chat/anthropic 路径不合成 finish_reason:stop/message_stop/
                                # [DONE]（下游 Hermes 靠 finish_reason is None 走 stub 保护或
                                # EmptyStreamError 重试）；仅 responses 路径保留合成
                                # response.failed（协议原生失败语义，下游报错重试）
                                try:
                                    if is_responses_stream:
                                        _fb = self._build_truncated_event_responses()
                                        await _tracked_write(_fb.encode('utf-8'))
                                        seen_terminal = True
                                        seen_global_terminal = True
                                    elif not is_anthropic_stream:
                                        # chat 协议：不合成成功终止，流以最后一个已透传
                                        # chunk 结束（open-ended）；tool_calls 残缺参数丢弃
                                        # （TSS-03 在下方统一处理）
                                        pass
                                    else:
                                        # anthropic 协议：不合成 message_stop，open-ended
                                        pass
                                except SSE_CLIENT_GONE:
                                    logger.debug('SSE 截断合成写入失败，客户端已断连')
                                except Exception:
                                    logger.exception('SSE 截断合成异常')
                                # 11.2 (TSS-03): 未 complete 截断且 tool_calls 残留——
                                # 丢弃未透传的残缺分片（不 flush 到下游），让下游识别
                                # 工具调用不完整而拒绝执行（Hermes mid-tool-call drop）
                                if (
                                    not is_responses_stream
                                    and not seen_global_terminal
                                    and tool_calls_pending_events
                                ):
                                    # 11.2 (TSS-03) F-01 修复：先取 len 再 clear，
                                    # 否则日志恒记 0 事件
                                    _tss_dropped = len(tool_calls_pending_events)
                                    tool_calls_pending_events.clear()
                                    tool_calls_blocked = True
                                    logger.warning(
                                        'LLM 截断丢弃残缺 tool_calls 分片: %d 事件 req_id=%s tail=%s',
                                        _tss_dropped,
                                        req_id,
                                        tail,
                                    )
                            # 9.4 补 (F-04): chat 协议 CR-only 流末已置位
                            # seen_global_terminal（finish_reason 终止）但上游
                            # 未发 [DONE] → 补发恰 1 个（OpenAI 流必须 [DONE] 收尾；
                            # _truncated 分支只在 seen_global_terminal=False 时
                            # 补发，此处覆盖 seen_global_terminal=True 场景）
                            elif (
                                not is_responses_stream
                                and not is_anthropic_stream
                                and seen_global_terminal
                                and _done_sent is False
                            ):
                                await _tracked_write(b'data: [DONE]\n\n')
                                _done_sent = True
                            # D3: 流末 hold 悬挂兜底：若 audit_hold 仍 active，强制拒绝再走守门
                            if getattr(self, '_audit_hold_active', False):
                                try:
                                    if is_anthropic_stream:
                                        await self._reject_anthropic_hold(
                                            _tracked_write, active_t2p
                                        )
                                    elif is_responses_stream:
                                        await self._reject_responses_hold(
                                            _tracked_write, active_t2p
                                        )
                                    else:
                                        # chat 场景：悬挂 hold 视为审计拦截，补发拒绝消息
                                        if tool_calls_pending_events:
                                            tool_calls_pending_events.clear()
                                            tool_calls_blocked = True
                                        if not audit_block_injected:
                                            _fb = self._build_block_event()
                                            await _tracked_write(_fb.encode('utf-8'))
                                            audit_block_injected = True
                                except Exception:
                                    logger.exception('流末 hold 兜底拒绝失败')
                            if bytes_written == 0 and upstream_resp.status == 200:
                                if audit_block_injected or tool_calls_blocked:
                                    # 审计拦截：上游 0 events 属预期，不计为空流错误；若前序注入失败则补发
                                    if not audit_block_injected:
                                        try:
                                            if is_responses_stream:
                                                _fb = (
                                                    self._build_block_event_responses()
                                                )
                                            elif is_anthropic_stream:
                                                _fb = (
                                                    self._build_block_event_anthropic()
                                                )
                                            else:
                                                _fb = self._build_block_event()
                                            await _tracked_write(_fb.encode('utf-8'))
                                            audit_block_injected = True
                                        except SSE_CLIENT_GONE:
                                            logger.debug(
                                                '审计拦截补发写入失败，客户端已断连'
                                            )
                                    logger.info(
                                        '审计拦截已注入拒绝消息(上游0 data events, %d bytes): %s %s',
                                        len(byte_buf),
                                        request.method,
                                        target_url,
                                    )
                                else:
                                    # 上游真空流（非审计）：注入最小拒绝消息避免 hermes JSONDecodeError 空体
                                    try:
                                        if is_responses_stream:
                                            _fb = self._build_block_event_responses()
                                        elif is_anthropic_stream:
                                            _fb = self._build_block_event_anthropic()
                                        else:
                                            _fb = self._build_block_event()
                                        await _tracked_write(_fb.encode('utf-8'))
                                        logger.error(
                                            'LLM 上游返回空流(0 data events, %d bytes)已兜底注入拒绝消息: %s %s',
                                            len(byte_buf),
                                            request.method,
                                            target_url,
                                        )
                                    except SSE_CLIENT_GONE:
                                        logger.error(
                                            'LLM 上游返回空流(0 data events, %d bytes): %s %s '
                                            '(client may see EmptyStreamError)',
                                            len(byte_buf),
                                            request.method,
                                            target_url,
                                        )
                            try:
                                await resp.write_eof()
                            except SSE_CLIENT_GONE:
                                logger.debug(
                                    'SSE write_eof 失败，客户端已断连',
                                )
                            # 埋点上下文更新（slow 链）
                            _metrics_ctx['status'] = upstream_resp.status
                            _metrics_ctx['latency_ms'] = (
                                _time.time() - _metrics_ctx['t0']
                            ) * 1000
                            _metrics_ctx['bytes_out'] = bytes_written
                            _metrics_ctx['sse_events'] = sse_event_count
                            _metrics_ctx['truncated'] = 1 if _truncated else 0
                            if is_chat_tail(tail):
                                logger.info(
                                    'LLM 流式结束(slow): %s %s status=%d sse_events=%d bytes_written=%d tail=%s',
                                    request.method,
                                    target_url,
                                    upstream_resp.status,
                                    sse_event_count,
                                    bytes_written,
                                    tail,
                                )
                            # 10.7.1 (F-07): 流结束清理审批 keepalive
                            # 资源（响应对象 + 任务），防跨请求残留
                            self._audit_keepalive_resp = None
                            _akt = self._audit_keepalive_task
                            self._audit_keepalive_task = None
                            if _akt is not None:
                                try:
                                    _akt.cancel()
                                except Exception:
                                    pass
                            if _debug_save_eligible:
                                try:
                                    _save_debug_json(
                                        req_id,
                                        'stream_meta.json',
                                        {
                                            'mode': 'slow',
                                            'status': upstream_resp.status,
                                            'sse_events': sse_event_count,
                                            'bytes_written': bytes_written,
                                            'tail': tail,
                                            'target_url': target_url,
                                            'is_responses': is_responses_stream,
                                            'is_anthropic': is_anthropic_stream,
                                            'audit_block_injected': audit_block_injected,
                                            'tool_calls_blocked': tool_calls_blocked,
                                            'bytes_buf_len': len(byte_buf),
                                            'seen_terminal': seen_terminal,
                                            'truncated': _truncated,
                                            # 11.2 (TSS-04) F-03 修复：正常完成流（_truncated=False）
                                            # 记 none，与「已 complete 残留静默丢弃」区分——
                                            # 否则监控无法区分无截断 vs silent_discard
                                            # silent_discard（已 complete 残留静默丢弃）/
                                            # open_ended（未 complete 不伪造终止）/
                                            # synthesized_failed（responses 合成 failed）
                                            'truncated_mode': (
                                                'synthesized_failed'
                                                if _truncated and is_responses_stream
                                                else 'open_ended'
                                                if _truncated
                                                else 'none'
                                            ),
                                            # 11.2 (TSS-03): 残缺 tool_calls 是否被丢弃
                                            'tool_calls_dropped': (
                                                tool_calls_blocked
                                                and _truncated
                                                and not seen_global_terminal
                                            ),
                                        },
                                    )
                                except Exception as exc:
                                    logger.debug('保存流式meta失败: %s', exc)
                        else:
                            # ── Fast path: active_t2p 为空，逐行 text-level 还原 ──
                            byte_buf = bytearray()
                            resp_log_path = None
                            fast_sse_event_count = 0
                            fast_bytes_written = 0  # D3 fast路径同样按字节守门
                            fast_seen_terminal = (
                                False  # 是否已收到终止事件（fast 路径）
                            )
                            fast_seen_global_terminal = False  # 全局终止（fast）
                            # ── 8.8 修复（F-09）：快链复用 WHATWG 帧状态机 ──
                            fast_pending_cr = False  # 上 chunk 末孤立 \r 跨块粘合
                            fast_bom_seen = False  # 流首 BOM 单次剥离
                            fast_data_buffer: list[str] = []  # 同事件多 data: 行聚合
                            # 10.13 (F-12): fast 链 event:/id: 行暂存 ——
                            # 不得立即透传（会把 SSE 块拆成 event 独块 + data 独块，
                            # openai sdk 按块解析 → 无 data 的块 JSONDecodeError）。
                            # 暂存后随 _fast_emit_data 的 data 行同块写出。
                            fast_event_pending: list[str] = []
                            # 9.5 (F-05): 快链 line_buf 行缓冲 —— 跨 data: 事件
                            # 切断的 PII 片段（user@exa + mple.com）合并后统一处理，
                            # 不透漏片段（tasks 8.8 声称的公共行缓冲在快链真实生效）
                            fast_line_buf: str = ''
                            fast_line_buf_ts = _time.monotonic()
                            # 3.1 (D5): 快链 reasoning 独立缓冲实例，与 content 共用
                            # 同一 16KB/30s 阈值语义（不另设阈值）；refusal 并入 content
                            fast_reasoning_buf: str = ''
                            fast_reasoning_buf_ts = _time.monotonic()
                            # D1 流末合成重建用：最近一次 chat chunk 解析对象
                            fast_last_chat_parsed = None

                            async def _tracked_write(data: bytes):
                                nonlocal fast_bytes_written
                                await resp.write(data)
                                fast_bytes_written += len(data)
                                if _debug_save_eligible:
                                    try:
                                        txt = data.decode('utf-8', errors='replace')
                                        for _line in txt.splitlines():
                                            if _line.strip() == '':
                                                continue
                                            await _debug_append_line(
                                                req_id, 'response_restored.jsonl', _line
                                            )
                                    except Exception as exc:
                                        logger.debug(
                                            '保存下游恢复日志失败(fast): %s', exc
                                        )

                            # ── 8.8 _fast_emit_data：聚合后统一 emit（含 json-aware 还原）──
                            async def _fast_emit_data(_payload: str):
                                nonlocal fast_seen_terminal, fast_seen_global_terminal
                                nonlocal fast_line_buf, fast_line_buf_ts
                                nonlocal fast_reasoning_buf, fast_reasoning_buf_ts
                                nonlocal fast_last_chat_parsed
                                nonlocal resp_log_path, _debug_saved
                                # 终止判定（结构化解析，7.3 语义）
                                try:
                                    _fast_parsed = (
                                        json.loads(_payload.strip())
                                        if _payload.strip().startswith(('{', '['))
                                        else {}
                                    )
                                    _ft = (
                                        _fast_parsed.get('type')
                                        if isinstance(_fast_parsed, dict)
                                        else None
                                    )
                                    if _ft in (
                                        'response.completed',
                                        'response.failed',
                                        'response.incomplete',
                                        # 10.14 (API-SPEC): error 事件也是正常终止
                                        'response.error',
                                        'message_stop',
                                        'error',
                                    ):
                                        fast_seen_terminal = True
                                        fast_seen_global_terminal = True
                                    else:
                                        for _c in (
                                            _fast_parsed.get('choices', [])
                                            if isinstance(_fast_parsed, dict)
                                            else []
                                        ) or []:
                                            if (
                                                isinstance(_c, dict)
                                                and _c.get('finish_reason') is not None
                                            ):
                                                fast_seen_terminal = True
                                                fast_seen_global_terminal = True
                                                break
                                except Exception:
                                    pass
                                if _debug_save_eligible:
                                    try:
                                        await _debug_append_line(
                                            req_id,
                                            'response_original.jsonl',
                                            _payload,
                                        )
                                    except Exception as exc:
                                        logger.debug(
                                            '保存上游原版日志失败(fast): %s', exc
                                        )
                                if resp_log_path:
                                    await _save_response_line(resp_log_path, _payload)
                                # 首次 data 事件提取 conversation ID 保存原始请求
                                if _debug_save_eligible and not _debug_saved:
                                    try:
                                        _parsed = json.loads(_payload)
                                        _cid = _extract_conv_id(_parsed)
                                        if _cid:
                                            _save_request_body(_cid, out_body)
                                            _debug_link_conv_id(req_id, _cid, out_body)
                                            _debug_saved = True
                                            resp_log_path = os.path.join(
                                                _DEBUG_DIR,
                                                _cid,
                                                'response.jsonl',
                                            )
                                            await _save_response_line(
                                                resp_log_path,
                                                _payload,
                                            )
                                    except json.JSONDecodeError:
                                        pass
                                # JSON-aware: data 载荷为 JSON 时走 loads→walk→dumps
                                # 7.4: 非对话尾透传不 walk
                                # 9.5 (F-05): 快链 content 走 line_buf 行缓冲 ——
                                # 跨 data: 事件切断的 PII 片段（user@exa + mple.com）
                                # 合并后统一处理，不透漏片段
                                if not is_dialog_tail:
                                    _restored_payload = _payload
                                else:
                                    # 提取 content/reasoning/refusal 文本累积行缓冲
                                    # （仅 chat/completions choices delta；其他载荷走
                                    # 完整 JSON-aware）。refusal 并入 content（与慢链
                                    # 同语义：pop 后合并，逐路累积）；reasoning 独立
                                    # 累积，与 content 共用同一 16KB/30s 阈值语义。
                                    _fast_text = ''
                                    _fast_reason = ''
                                    _fp_idx_text: dict[int, str] = {}
                                    _fp_idx_reason: dict[int, str] = {}
                                    _fp = None
                                    try:
                                        _fp = json.loads(_payload)
                                        if isinstance(_fp, dict):
                                            for _fpos, _ch in enumerate(
                                                _fp.get('choices', []) or []
                                            ):
                                                _d = (
                                                    _ch.get('delta', {})
                                                    if isinstance(_ch, dict)
                                                    else {}
                                                )
                                                if not isinstance(_d, dict):
                                                    continue
                                                _fidx = _chat_choice_index(_ch, _fpos)
                                                _ct = _d.get('content')
                                                _cref = _d.get('refusal')
                                                if isinstance(_cref, str) and _cref:
                                                    _d.pop('refusal', None)
                                                    _ct = (
                                                        (_ct or '') + _cref
                                                        if isinstance(_ct, str)
                                                        else _cref
                                                    )
                                                if isinstance(_ct, str) and _ct:
                                                    _fp_idx_text[_fidx] = (
                                                        _fp_idx_text.get(_fidx, '')
                                                        + _ct
                                                    )
                                                    _fast_text += _ct
                                                _rc = _d.get('reasoning_content')
                                                if _rc is None:
                                                    _rc = _d.get('reasoning')
                                                if isinstance(_rc, str) and _rc:
                                                    _fp_idx_reason[_fidx] = (
                                                        _fp_idx_reason.get(_fidx, '')
                                                        + _rc
                                                    )
                                                    _fast_reason += _rc
                                    except Exception:
                                        _fast_text = ''
                                        _fast_reason = ''
                                        _fp_idx_text = {}
                                        _fp_idx_reason = {}
                                    if isinstance(_fp, dict) and _fp.get('choices'):
                                        fast_last_chat_parsed = _fp
                                    if _fast_text or _fast_reason:
                                        # D1 逐路还原：多路 chunk 各路文本独立还原，
                                        # 禁止拼合后广播同一文本（n=2 串扰）。
                                        async def _restore_idx_text(
                                            _t: str,
                                        ) -> str:
                                            _r = await self._pii_response_process(
                                                _t, active_t2p
                                            )
                                            return _strip_partials(_r)

                                        # 3.1 (D5): TTFB 直通仅限无 PII 检测态
                                        # （`not _pii_active()`）：无还原/检测能力时持有
                                        # 毫无意义，只损 TTFB 并破坏 TSS-01 终端结构；
                                        # PII 检测态短分片一律行缓冲持有（消快慢旁路）。
                                        # 凭据 token 前缀尾仍被候选排除在直通外。
                                        _bypass_extra_t = (
                                            self._extra_prefixes(_fast_text[-64:])
                                            if _fast_text
                                            else None
                                        )
                                        _bypass_extra_r = (
                                            self._extra_prefixes(_fast_reason[-64:])
                                            if _fast_reason
                                            else None
                                        )
                                        if (
                                            not self._pii_active()
                                            and not fast_line_buf
                                            and not fast_reasoning_buf
                                            and len(_fast_text) + len(_fast_reason) < 64
                                            and not _has_partial_pii_candidate(
                                                _fast_text[-64:] if _fast_text else '',
                                                _bypass_extra_t,
                                            )
                                            and not _has_partial_pii_candidate(
                                                _fast_reason[-64:]
                                                if _fast_reason
                                                else '',
                                                _bypass_extra_r,
                                            )
                                        ):
                                            _safe_by_idx = {}
                                            for _fi, _ft in _fp_idx_text.items():
                                                _s = await _restore_idx_text(_ft)
                                                if _s:
                                                    _safe_by_idx[_fi] = _s
                                            _safe_reason_by_idx = {}
                                            for _fi, _ft in _fp_idx_reason.items():
                                                _s = await _restore_idx_text(_ft)
                                                if _s:
                                                    _safe_reason_by_idx[_fi] = _s
                                            if _safe_by_idx or _safe_reason_by_idx:
                                                _restored_payload = _fast_rebuild_chunk(
                                                    _fp,
                                                    _safe_by_idx,
                                                    _safe_reason_by_idx or None,
                                                )
                                            else:
                                                return
                                        elif len(_fp_idx_text) > 1 or (
                                            not _fast_text and len(_fp_idx_reason) > 1
                                        ):
                                            _safe_by_idx: dict[int, str] = {}
                                            for _fi, _ft in _fp_idx_text.items():
                                                _s = await _restore_idx_text(_ft)
                                                if _s:
                                                    _safe_by_idx[_fi] = _s
                                            _safe_reason_by_idx: dict[int, str] = {}
                                            for _fi, _ft in _fp_idx_reason.items():
                                                _s = await _restore_idx_text(_ft)
                                                if _s:
                                                    _safe_reason_by_idx[_fi] = _s
                                            if _safe_by_idx or _safe_reason_by_idx:
                                                # 10.14 (API-SPEC): 保留 chunk JSON 结构，
                                                # 按 choices[i].index 逐路替换 delta.content
                                                # （原实现把整个 payload 换成裸文本，
                                                # 破坏 chat.completion.chunk 结构，下游
                                                # SDK JSONDecodeError）
                                                _restored_payload = _fast_rebuild_chunk(
                                                    _fp,
                                                    _safe_by_idx,
                                                    _safe_reason_by_idx or None,
                                                )
                                            else:
                                                return
                                        else:
                                            fast_line_buf += _fast_text
                                            fast_line_buf_ts = _time.monotonic()
                                            # 有 \n 按行 flush，无则持有（除非超长）
                                            _out_c = []
                                            while '\n' in fast_line_buf:
                                                _seg, fast_line_buf = (
                                                    fast_line_buf.split('\n', 1)
                                                )
                                                _seg += '\n'
                                                _rest = (
                                                    await self._pii_response_process(
                                                        _seg, active_t2p
                                                    )
                                                )
                                                _safe = _strip_partials(_rest)
                                                if _safe:
                                                    _out_c.append(_safe)
                                            _fast_extra_31 = self._extra_prefixes(
                                                fast_line_buf[-64:]
                                            )
                                            _fast_cand_31 = _has_partial_pii_candidate(
                                                fast_line_buf[-64:], _fast_extra_31
                                            )
                                            if fast_line_buf and (
                                                len(fast_line_buf) > LINE_BUF_FLUSH
                                                or _time.monotonic() - fast_line_buf_ts
                                                > LINE_BUF_MAX_AGE
                                                or _fast_cand_31
                                            ):
                                                _rest = (
                                                    await self._pii_response_process(
                                                        fast_line_buf, active_t2p
                                                    )
                                                )
                                                _same_fast_31 = _rest == fast_line_buf
                                                _safe, _pend = _split_safe_hold(
                                                    _rest,
                                                    active_t2p,
                                                    self._pii_scope_or_none(),
                                                    extra_prefixes=_fast_extra_31
                                                    if _same_fast_31
                                                    else None,
                                                    hold_pii_tail=_same_fast_31,
                                                )
                                                if _safe:
                                                    _safe = _strip_partials(_safe)
                                                    _out_c.append(_safe)
                                                    if not _fast_cand_31:
                                                        self._count_custom_other_miss()
                                                fast_line_buf = _pend
                                                fast_line_buf_ts = _time.monotonic()
                                            _emit_content_map = None
                                            if _out_c:
                                                # 10.14 (API-SPEC): 同上——保留 chunk JSON
                                                # 结构，按 index 逐路替换 delta.content
                                                _single_idx = next(
                                                    iter(_fp_idx_text), 0
                                                )
                                                _emit_content_map = {
                                                    _single_idx: ''.join(_out_c)
                                                }
                                            # 3.1 (D5): reasoning 独立缓冲实例，与 content
                                            # 共用同一 16KB/30s 阈值语义（不另设阈值）
                                            _emit_reason_map = None
                                            if _fast_reason:
                                                fast_reasoning_buf += _fast_reason
                                                fast_reasoning_buf_ts = (
                                                    _time.monotonic()
                                                )
                                                _out_r = []
                                                while '\n' in fast_reasoning_buf:
                                                    _seg, fast_reasoning_buf = (
                                                        fast_reasoning_buf.split(
                                                            '\n', 1
                                                        )
                                                    )
                                                    _seg += '\n'
                                                    _rest = await self._pii_response_process(
                                                        _seg, active_t2p
                                                    )
                                                    _safe = _strip_partials(_rest)
                                                    if _safe:
                                                        _out_r.append(_safe)
                                                _reason_extra_2 = self._extra_prefixes(
                                                    fast_reasoning_buf[-64:]
                                                )
                                                _reason_cand_2 = (
                                                    _has_partial_pii_candidate(
                                                        fast_reasoning_buf[-64:],
                                                        _reason_extra_2,
                                                    )
                                                )
                                                if fast_reasoning_buf and (
                                                    len(fast_reasoning_buf)
                                                    > LINE_BUF_FLUSH
                                                    or _time.monotonic()
                                                    - fast_reasoning_buf_ts
                                                    > LINE_BUF_MAX_AGE
                                                    or _reason_cand_2
                                                ):
                                                    _rest = await self._pii_response_process(
                                                        fast_reasoning_buf,
                                                        active_t2p,
                                                    )
                                                    _same_reason_2 = (
                                                        _rest == fast_reasoning_buf
                                                    )
                                                    _safe, _pend = _split_safe_hold(
                                                        _rest,
                                                        active_t2p,
                                                        self._pii_scope_or_none(),
                                                        extra_prefixes=_reason_extra_2
                                                        if _same_reason_2
                                                        else None,
                                                        hold_pii_tail=_same_reason_2,
                                                    )
                                                    if _safe:
                                                        _safe = _strip_partials(_safe)
                                                        _out_r.append(_safe)
                                                        if not _reason_cand_2:
                                                            self._count_custom_other_miss()
                                                    fast_reasoning_buf = _pend
                                                    fast_reasoning_buf_ts = (
                                                        _time.monotonic()
                                                    )
                                                if _out_r:
                                                    _single_ridx = next(
                                                        iter(_fp_idx_reason), 0
                                                    )
                                                    _emit_reason_map = {
                                                        _single_ridx: ''.join(_out_r)
                                                    }
                                            if _emit_content_map or _emit_reason_map:
                                                _restored_payload = _fast_rebuild_chunk(
                                                    _fp,
                                                    _emit_content_map or {},
                                                    _emit_reason_map,
                                                )
                                            else:
                                                # 无完整行可发：跳过本次 emit（行内持有）
                                                return
                                    else:
                                        if hasattr(
                                            self, '_pii_response_process_json_aware'
                                        ):
                                            _restored_payload = await self._pii_response_process_json_aware(
                                                _payload, active_t2p
                                            )
                                        else:
                                            _restored_payload = (
                                                await self._pii_response_process(
                                                    _payload, active_t2p
                                                )
                                            )
                                # 10.13 (F-12): event:/id: 暂存行与 data 行同块写出
                                # （保持 SSE 块结构：event: xxx\ndata: {...}\n\n）
                                # 10.14.1 (API-SPEC FIX): 多条 event 累积
                                # （跨批/非标准上游）时按 FIFO 弹第一条配对
                                # ——join 全部会让 SDK 取最后 event 名配
                                # 首个 data 载荷（错配）。
                                _fast_block = (
                                    fast_event_pending.pop(0) + '\n'
                                    if fast_event_pending
                                    else ''
                                )
                                await _tracked_write(
                                    (
                                        _fast_block
                                        + 'data: '
                                        + _restored_payload
                                        + '\n\n'
                                    ).encode('utf-8'),
                                )

                            try:
                                async for chunk in upstream_resp.content.iter_chunked(
                                    SSE_CHUNK_SIZE,
                                ):
                                    byte_buf.extend(chunk)
                                    # ── 8.8 BOM 单次剥离（同慢链 6.2）──
                                    if not fast_bom_seen:
                                        if len(byte_buf) >= 3:
                                            if byte_buf[:3] == b'\xef\xbb\xbf':
                                                del byte_buf[:3]
                                            fast_bom_seen = True
                                        else:
                                            if byte_buf.startswith(
                                                b'\xef'
                                            ) or byte_buf.startswith(b'\xef\xbb'):
                                                continue
                                            else:
                                                fast_bom_seen = True
                                    # ── 8.8 pending_cr 粘合（同慢链）──
                                    if fast_pending_cr:
                                        if byte_buf.startswith(b'\n'):
                                            del byte_buf[0]
                                        fast_pending_cr = False
                                    # 先处理完整行，再检查缓冲区（防截断丢数据）
                                    # 3.2 (D5): fast 与 slow 同款 WHATWG 切行
                                    # （CRLF/LF/CR 统一分行；块末孤立 \r 置
                                    # fast_pending_cr 持有跨块粘合，下 chunk
                                    # 首字节 \n 则吞之即 CRLF，否则单 \r 成行）
                                    pos = 0
                                    while True:
                                        idx_n = byte_buf.find(b'\n', pos)
                                        idx_r = byte_buf.find(b'\r', pos)
                                        if idx_n == -1 and idx_r == -1:
                                            break
                                        if idx_r != -1 and (
                                            idx_n == -1 or idx_r < idx_n
                                        ):
                                            if (
                                                idx_r + 1 < len(byte_buf)
                                                and byte_buf[idx_r + 1] == 10
                                            ):
                                                line_bytes = byte_buf[pos:idx_r]
                                                pos = idx_r + 2
                                            else:
                                                if idx_r == len(byte_buf) - 1:
                                                    fast_pending_cr = True
                                                    break
                                                else:
                                                    line_bytes = byte_buf[pos:idx_r]
                                                    pos = idx_r + 1
                                        else:
                                            line_bytes = byte_buf[pos:idx_n]
                                            pos = idx_n + 1
                                        line = line_bytes.decode(
                                            'utf-8',
                                            errors='replace',
                                        )
                                        if line == '':
                                            # 空行：dispatch 聚合的 data_buffer
                                            if fast_data_buffer:
                                                _fast_payload = '\n'.join(
                                                    fast_data_buffer
                                                )
                                                fast_data_buffer.clear()
                                                # 空 data 行不计为有效事件
                                                if not _fast_payload.strip():
                                                    continue
                                                fast_sse_event_count += 1
                                                # 可观测性：捕获 usage（fast 链）
                                                _capture_usage_ctx(
                                                    _fast_payload,
                                                    _metrics_ctx,
                                                    'anthropic'
                                                    if tail.rstrip('/').endswith(
                                                        'v1/messages'
                                                    )
                                                    else (
                                                        'responses'
                                                        if tail.rstrip('/').endswith(
                                                            'v1/responses'
                                                        )
                                                        else 'openai'
                                                    ),
                                                )
                                                if _fast_payload.strip() == '[DONE]':
                                                    fast_seen_terminal = True
                                                    fast_seen_global_terminal = True
                                                await _fast_emit_data(_fast_payload)
                                            continue
                                        if line.startswith(':'):
                                            await _tracked_write(
                                                (line + '\n').encode('utf-8')
                                            )
                                            continue
                                        if ':' in line:
                                            field, value = line.split(':', 1)
                                            value = value.removeprefix(' ')
                                            if field == 'data':
                                                if not value.strip():
                                                    continue
                                                fast_data_buffer.append(value)
                                                continue
                                            elif field == 'event' or field == 'id':
                                                restored_line = (
                                                    await self._pii_process_sse_line(
                                                        line, active_t2p
                                                    )
                                                )
                                                fast_event_pending.append(restored_line)
                                                continue
                                            elif field == 'retry':
                                                if value.isdigit() and value.isascii():
                                                    await _tracked_write(
                                                        (line + '\n').encode('utf-8')
                                                    )
                                                continue
                                            else:
                                                await _tracked_write(
                                                    (
                                                        await self._pii_process_sse_line(
                                                            line, active_t2p
                                                        )
                                                        + '\n\n'
                                                    ).encode('utf-8')
                                                )
                                                continue
                                        else:
                                            field = line
                                            if field == 'data':
                                                fast_data_buffer.append('')
                                                continue
                                            elif field in ('event', 'id'):
                                                restored_line = (
                                                    await self._pii_process_sse_line(
                                                        line, active_t2p
                                                    )
                                                )
                                                fast_event_pending.append(restored_line)
                                                continue
                                            elif field == 'retry':
                                                continue
                                            else:
                                                await _tracked_write(
                                                    (
                                                        await self._pii_process_sse_line(
                                                            line, active_t2p
                                                        )
                                                        + '\n\n'
                                                    ).encode('utf-8')
                                                )
                                                continue
                                    # pos==0 意味着本轮无完整行：不得 del，
                                    # byte_buf 单调增长属预期（等后续 chunk
                                    # 补齐成行），由下方 SSE_MAX_BUF 截断接管，
                                    # 不得误判为截断合成。
                                    if pos > 0:
                                        del byte_buf[:pos]
                                    if len(byte_buf) > SSE_MAX_BUF:
                                        logger.warning(
                                            'SSE 缓冲区超过 1MB 上限，'
                                            '保留最后一个部分行',
                                        )
                                        last_nl = byte_buf.rfind(b'\n')
                                        last_cr = byte_buf.rfind(b'\r')
                                        last_safe = max(last_nl, last_cr)
                                        if last_safe >= 0:
                                            byte_buf = bytearray(
                                                byte_buf[last_safe + 1 :],
                                            )
                                        if len(byte_buf) > SSE_MAX_BUF:
                                            byte_buf = bytearray()
                                        try:
                                            fast_data_buffer.clear()
                                        except Exception:
                                            pass
                            except SSE_CLIENT_GONE as e:
                                logger.debug('SSE 客户端断连: %s', e)
                            # ── 8.8 EOF 残留处理（同慢链 8.5）──
                            # CR-only 行流末：byte_buf 以 \r 结尾 → 视为行终止符
                            # 10.14.1 (API-SPEC FIX): 整个流全 CR-only（每行 \r
                            # 结尾）时 byte_buf 里有多行——不能只取末尾一段，
                            # 必须按 \r 切分逐行 dispatch（保持行序，中间行
                            # 不得丢失）。每行独立 data: 前缀 + 独立空行块，
                            # [DONE] 在 content 之后按序透传。
                            if byte_buf.endswith(b'\r'):
                                _cr_text = bytes(byte_buf).decode(
                                    'utf-8', errors='replace'
                                )
                                byte_buf.clear()
                                fast_pending_cr = False
                                for _cr_raw in _cr_text.split('\r'):
                                    _cr_line = _cr_raw.strip('\r')
                                    if not _cr_line:
                                        continue
                                    if _cr_line.startswith('data:'):
                                        _pl = _cr_line[5:].removeprefix(' ')
                                        # 10.14.1 (API-SPEC FIX): CR-only 多行
                                        # 流保持行序 dispatch——content 行立即
                                        # 走 _fast_emit_data（还原+透传），
                                        # [DONE] 行最后透传（不得提前，否则
                                        # SDK 收到 [DONE] 即结束流，后续
                                        # content 全丢）。
                                        if _pl.strip() == '[DONE]':
                                            fast_seen_terminal = True
                                            fast_seen_global_terminal = True
                                            await _tracked_write(b'data: [DONE]\n\n')
                                        elif _pl.strip():
                                            fast_sse_event_count += 1
                                            # 可观测性：捕获 usage（fast CR 链）
                                            _capture_usage_ctx(
                                                _pl,
                                                _metrics_ctx,
                                                'anthropic'
                                                if tail.rstrip('/').endswith(
                                                    'v1/messages'
                                                )
                                                else (
                                                    'responses'
                                                    if tail.rstrip('/').endswith(
                                                        'v1/responses'
                                                    )
                                                    else 'openai'
                                                ),
                                            )
                                            await _fast_emit_data(_pl)
                                    else:
                                        # 10.14.1 (API-SPEC FIX): 非 data 行
                                        # （event:/id:）暂存 fast_event_pending，
                                        # data 行 dispatch 前拼入同块（FIFO
                                        # 弹第一条配对）——立即透传会把 SSE
                                        # 块拆成 event 独块 + data 独块，
                                        # SDK JSONDecodeError（与主循环
                                        # 4821-4826 一致）。
                                        if _cr_line.startswith(('event:', 'id:')):
                                            fast_event_pending.append(
                                                await self._pii_process_sse_line(
                                                    _cr_line, active_t2p
                                                )
                                            )
                                        elif _cr_line.startswith(':'):
                                            await _tracked_write(
                                                (_cr_line + '\n').encode('utf-8')
                                            )
                                        else:
                                            await _tracked_write(
                                                (
                                                    await self._pii_process_sse_line(
                                                        _cr_line, active_t2p
                                                    )
                                                    + '\n\n'
                                                ).encode('utf-8')
                                            )
                            # data_buffer 残留 → dispatch
                            if fast_data_buffer:
                                _fast_payload = '\n'.join(fast_data_buffer)
                                fast_data_buffer.clear()
                                if _fast_payload.strip():
                                    fast_sse_event_count += 1
                                    if _fast_payload.strip() == '[DONE]':
                                        fast_seen_terminal = True
                                        fast_seen_global_terminal = True
                                    await _fast_emit_data(_fast_payload)
                            # 10.13 (F-12): 流末 event_pending 残留透传 ——
                            # data 行始终没来（异常流）时，不能把 event 行闷掉；
                            # 透传保留原始信息，客户端自行容错。
                            # 10.14.1 (API-SPEC FIX): 逐条透传独立块。
                            if fast_event_pending:
                                for _pend in fast_event_pending:
                                    await _tracked_write(
                                        (_pend + '\n\n').encode('utf-8'),
                                    )
                                fast_event_pending.clear()
                            # 9.5 (F-05): 快链 line_buf 流末 flush（持有行不丢）
                            if fast_line_buf:
                                _rest = await self._pii_response_process(
                                    fast_line_buf, active_t2p
                                )
                                _safe = _strip_partials(_rest)
                                if _safe:
                                    fast_sse_event_count += 1
                                    # D1: 流末合成改走结构保留重建（原对象
                                    # deepcopy + 逐路替换，全链 _jdumps）
                                    if isinstance(fast_last_chat_parsed, dict):
                                        _tail_cbi: dict[int, str] | None = {}
                                        try:
                                            _tail_choices = (
                                                fast_last_chat_parsed.get('choices')
                                                or []
                                            )
                                        except AttributeError:
                                            _tail_choices = []
                                        for _tpos, _tch in enumerate(_tail_choices):
                                            if not isinstance(_tch, dict):
                                                continue
                                            _td = _tch.get('delta')
                                            if isinstance(_td, dict) and isinstance(
                                                _td.get('content'), str
                                            ):
                                                _tail_cbi[
                                                    _chat_choice_index(_tch, _tpos)
                                                ] = _safe
                                                break
                                        _tail_ev = _mk_sse_event(
                                            parsed=fast_last_chat_parsed,
                                            content_by_index=_tail_cbi or None,
                                        )
                                    else:
                                        _tail_ev = _mk_sse_event(content=_safe)
                                    await _tracked_write(_tail_ev.encode('utf-8'))
                                fast_line_buf = ''
                            # 3.1 (D5): 快链 reasoning 流末 flush（持有不丢，与 content 同口径重建）
                            if fast_reasoning_buf:
                                _rest = await self._pii_response_process(
                                    fast_reasoning_buf, active_t2p
                                )
                                _safe = _strip_partials(_rest)
                                if _safe:
                                    fast_sse_event_count += 1
                                    if isinstance(fast_last_chat_parsed, dict):
                                        _tail_rbi: dict[int, str] | None = {}
                                        try:
                                            _tail_choices = (
                                                fast_last_chat_parsed.get('choices')
                                                or []
                                            )
                                        except AttributeError:
                                            _tail_choices = []
                                        for _tpos, _tch in enumerate(_tail_choices):
                                            if not isinstance(_tch, dict):
                                                continue
                                            _td = _tch.get('delta')
                                            if isinstance(_td, dict) and (
                                                isinstance(
                                                    _td.get('reasoning_content'), str
                                                )
                                                or isinstance(_td.get('reasoning'), str)
                                            ):
                                                _tail_rbi[
                                                    _chat_choice_index(_tch, _tpos)
                                                ] = _safe
                                                break
                                        _tail_ev = _mk_sse_event(
                                            parsed=fast_last_chat_parsed,
                                            reasoning_by_index=_tail_rbi or None,
                                        )
                                    else:
                                        _tail_ev = _mk_sse_event(
                                            reasoning_content=_safe
                                        )
                                    await _tracked_write(_tail_ev.encode('utf-8'))
                                fast_reasoning_buf = ''
                            # ── fast 截断检测 ──
                            _fast_truncated = False
                            # 11.2 (TSS-01): 已 complete（fast_seen_global_terminal=true）
                            # 时 byte_buf 残留不判截断——终止语义已完整，静默丢弃
                            if byte_buf and not fast_seen_global_terminal:
                                _fast_truncated = True
                                # 11.2 (TSS-01) F-13 修复：fast 预览与 slow 同款脱敏——
                                # 先剥离 PII/凭据 token 残缺形态，再过 redact_summary
                                # （手机号/邮箱等明文 → ***），空结果用 hex 兜底
                                _preview_raw = byte_buf[:200].decode(
                                    'utf-8', errors='replace'
                                )
                                _preview = _strip_partials(_preview_raw)
                                _preview = redact_summary(_preview)
                                if not _preview:
                                    _preview = (
                                        f'len={len(byte_buf)} '
                                        f'hex_head={bytes(byte_buf[:16]).hex()}'
                                    )
                                logger.warning(
                                    'LLM 流截断(fast): bytes_buf_len=%d sse_events=%d bytes_written=%d req_id=%s tail=%s preview=%r',
                                    len(byte_buf),
                                    fast_sse_event_count,
                                    fast_bytes_written,
                                    req_id,
                                    tail,
                                    _preview,
                                )
                            if (
                                not fast_seen_global_terminal
                                and fast_bytes_written > 0
                                and fast_sse_event_count > 0
                            ):
                                if not _fast_truncated:
                                    logger.warning(
                                        'LLM 流未收到终止事件(fast): sse_events=%d bytes_written=%d req_id=%s tail=%s',
                                        fast_sse_event_count,
                                        fast_bytes_written,
                                        req_id,
                                        tail,
                                    )
                                _fast_truncated = True
                            if _fast_truncated:
                                # 11.2 (TSS-02): fast 路径与 slow 一致——未 complete 截断
                                # 不再伪造成功终止：chat/anthropic open-ended，responses 保留 failed
                                try:
                                    _tail_norm = tail.rstrip('/')
                                    if _tail_norm.endswith('v1/responses'):
                                        _fb = self._build_truncated_event_responses()
                                        await _tracked_write(_fb.encode('utf-8'))
                                        fast_seen_terminal = True
                                        fast_seen_global_terminal = True
                                    elif _tail_norm.endswith('v1/messages'):
                                        # anthropic：不合成 message_stop，open-ended
                                        pass
                                    else:
                                        # chat：不合成 finish_reason:stop/[DONE]，open-ended
                                        pass
                                except SSE_CLIENT_GONE:
                                    logger.debug(
                                        'SSE 截断合成写入失败(fast)，客户端已断连'
                                    )
                                except Exception:
                                    logger.exception('SSE 截断合成异常(fast)')
                            if fast_bytes_written == 0 and upstream_resp.status == 200:
                                # fast path 无审计：上游真空流，注入最小拒绝消息避免空体
                                try:
                                    _tail_norm = tail.rstrip('/')
                                    if _tail_norm.endswith('v1/responses'):
                                        _fb = self._build_block_event_responses()
                                    elif _tail_norm.endswith('v1/messages'):
                                        _fb = self._build_block_event_anthropic()
                                    else:
                                        _fb = self._build_block_event()
                                    await _tracked_write(_fb.encode('utf-8'))
                                    logger.error(
                                        'LLM 上游返回空流(0 data events, %d bytes)已兜底注入拒绝消息: %s %s',
                                        len(byte_buf),
                                        request.method,
                                        target_url,
                                    )
                                except SSE_CLIENT_GONE:
                                    logger.error(
                                        'LLM 上游返回空流(0 data events, %d bytes): %s %s '
                                        '(client may see EmptyStreamError)',
                                        len(byte_buf),
                                        request.method,
                                        target_url,
                                    )
                            try:
                                await resp.write_eof()
                            except SSE_CLIENT_GONE:
                                logger.debug(
                                    'SSE write_eof 失败，客户端已断连',
                                )
                            # 埋点上下文更新（fast 链）
                            _metrics_ctx['status'] = upstream_resp.status
                            _metrics_ctx['latency_ms'] = (
                                _time.time() - _metrics_ctx['t0']
                            ) * 1000
                            _metrics_ctx['bytes_out'] = fast_bytes_written
                            _metrics_ctx['sse_events'] = fast_sse_event_count
                            _metrics_ctx['truncated'] = 1 if _fast_truncated else 0
                            if is_chat_tail(tail):
                                logger.info(
                                    'LLM 流式结束(fast): %s %s status=%d sse_events=%d bytes_written=%d tail=%s',
                                    request.method,
                                    target_url,
                                    upstream_resp.status,
                                    fast_sse_event_count,
                                    fast_bytes_written,
                                    tail,
                                )
                            if _debug_save_eligible:
                                try:
                                    _save_debug_json(
                                        req_id,
                                        'stream_meta.json',
                                        {
                                            'mode': 'fast',
                                            'status': upstream_resp.status,
                                            'sse_events': fast_sse_event_count,
                                            'bytes_written': fast_bytes_written,
                                            'tail': tail,
                                            'target_url': target_url,
                                            'bytes_buf_len': len(byte_buf),
                                            'seen_terminal': fast_seen_terminal,
                                            'truncated': _fast_truncated,
                                            # 11.2 (TSS-04) F-03 修复：正常完成流记 none
                                            # （与 slow 同构，区分无截断 vs silent_discard）
                                            # silent_discard / open_ended / synthesized_failed
                                            'truncated_mode': (
                                                'synthesized_failed'
                                                if _fast_truncated
                                                and tail.rstrip('/').endswith(
                                                    'v1/responses'
                                                )
                                                else 'open_ended'
                                                if _fast_truncated
                                                else 'none'
                                            ),
                                        },
                                    )
                                except Exception as exc:
                                    logger.debug('保存流式meta失败(fast): %s', exc)
                        return resp
                    else:
                        # ── 非流式 ──
                        resp_body = await upstream_resp.read()
                        # === DEBUG: 非流式原版回复落盘 ===
                        if _debug_save_eligible:
                            try:
                                _save_debug_bytes(
                                    req_id, 'response_original.json', resp_body
                                )
                                _save_debug_json(
                                    req_id,
                                    'response_original_meta.json',
                                    {
                                        'status': upstream_resp.status,
                                        'headers': dict(upstream_resp.headers),
                                        'len': len(resp_body),
                                        'content_type': upstream_resp.headers.get(
                                            'Content-Type', ''
                                        ),
                                    },
                                )
                            except Exception as exc:
                                logger.debug('保存非流式原版回复失败: %s', exc)

                        if (
                            not resp_body
                            and upstream_resp.status == 200
                            and (is_chat_tail(tail))
                        ):
                            logger.error(
                                'LLM 上游返回空响应体(%d bytes): %s %s '
                                '(client may see EmptyStreamError)',
                                len(resp_body),
                                request.method,
                                target_url,
                            )

                        if _debug_save_eligible:
                            try:
                                resp_json = json.loads(resp_body)
                                conv_id = resp_json.get('id')
                                if conv_id:
                                    _save_request_body(conv_id, out_body)
                                    _debug_link_conv_id(req_id, conv_id, out_body)
                                    _debug_saved = True
                                    # 非流式 response 写为完整 response.json
                                    resp_path = os.path.join(
                                        _DEBUG_DIR,
                                        conv_id,
                                        'response.json',
                                    )
                                    await _save_response_line(
                                        resp_path,
                                        resp_body.decode('utf-8', errors='replace'),
                                    )
                            except json.JSONDecodeError:
                                pass

                        resp_text = resp_body.decode(
                            'utf-8',
                            errors='replace',
                        )
                        # 空体/非JSON 转 502：上游 200 却返回空体或非JSON时，原逻辑会透传 200 坏体
                        # 导致 Hermes OpenAI SDK 执行 response.json() → JSONDecodeError
                        # 重试 5 次仍 empty；改为 502 显式错误，便于观测与 failover
                        # 仅对话接口转 502，非对话（如 /v1/models）空体按原样透传
                        _is_empty = not resp_text.strip()
                        _is_invalid_json = False
                        if not _is_empty:
                            try:
                                _resp_parsed = json.loads(resp_text)
                                # 可观测性：非流式 usage 提取（按 model 分桶）
                                if isinstance(_resp_parsed, dict) and isinstance(
                                    _resp_parsed.get('usage'), dict
                                ):
                                    _resp_usage = _resp_parsed['usage']
                                    _resp_model = _req_model
                                    if isinstance(_resp_parsed.get('model'), str):
                                        _resp_model = _resp_parsed['model']
                                    _metrics_ctx['model'] = _resp_model
                                    # 可观测性内部取数，非SSE转发
                                    _ujson = json.dumps(  # _jdumps-whitelist
                                        {'usage': _resp_usage}
                                    )
                                    _capture_usage_ctx(
                                        _ujson,
                                        _metrics_ctx,
                                        'anthropic'
                                        if tail.rstrip('/').endswith('v1/messages')
                                        else (
                                            'responses'
                                            if tail.rstrip('/').endswith('v1/responses')
                                            else 'openai'
                                        ),
                                    )
                            except json.JSONDecodeError:
                                _is_invalid_json = True
                        # DEBUG: 0.9.8 后仍出现 JSONDecodeError 的诊断日志（临时）
                        if is_chat_tail(tail):
                            logger.info(
                                'LLM 非流式响应诊断: %s %s status=%d empty=%s invalid=%s len=%d tail=%s ct=%s',
                                request.method,
                                target_url,
                                upstream_resp.status,
                                _is_empty,
                                _is_invalid_json,
                                len(resp_text),
                                tail,
                                upstream_resp.headers.get('Content-Type', ''),
                            )
                        if (
                            (_is_empty or _is_invalid_json)
                            and upstream_resp.status == 200
                            and is_chat_tail(tail)
                        ):
                            logger.error(
                                'LLM 上游空体/非JSON转 502: %s %s status=%d empty=%s invalid_json=%s len=%d '
                                '(client would see JSONDecodeError)',
                                request.method,
                                target_url,
                                upstream_resp.status,
                                _is_empty,
                                _is_invalid_json,
                                len(resp_text),
                            )
                            # 埋点上下文更新（空体/非JSON 502）
                            _metrics_ctx['status'] = 502
                            _metrics_ctx['latency_ms'] = (
                                _time.time() - _metrics_ctx['t0']
                            ) * 1000
                            _metrics_ctx['bytes_out'] = 0
                            _metrics_ctx['empty_guarded'] = bool(
                                _is_empty and upstream_resp.status == 200
                            )
                            _metrics_ctx['invalid_json_guarded'] = bool(
                                _is_invalid_json and upstream_resp.status == 200
                            )
                            return web.Response(
                                body=json.dumps(  # _jdumps-whitelist: 非流式502错误体（非SSE转发）
                                    {
                                        'error': {
                                            'message': 'upstream empty response',
                                            'type': 'empty_response',
                                        }
                                    },
                                    ensure_ascii=False,
                                ).encode('utf-8'),
                                status=502,
                                headers={'Content-Type': 'application/json'},
                            )
                        # 非流式整包审计（design D4：不因缺 SSE 完成事件跳过）
                        blocked = False
                        if self.audit_enabled() and resp_text:
                            try:
                                _resp_json = json.loads(resp_text)
                                _calls = _extract_tool_calls_non_stream(
                                    _resp_json,
                                    tail,
                                )
                                for _name, _args in _calls:
                                    _verdict = await self.audit_tool_call(_name, _args)
                                    if _verdict == 'deny':
                                        blocked = True
                            except json.JSONDecodeError:
                                pass
                        if blocked:
                            # 阻断：用拒绝消息替换整个响应体（design D4）
                            _tail_norm = tail.rstrip('/')
                            if _tail_norm.endswith('chat/completions'):
                                _block_body = json.dumps(  # _jdumps-whitelist: 非流式阻断合成占位构造
                                    {
                                        'choices': [
                                            {
                                                'index': 0,
                                                'message': {
                                                    'role': 'assistant',
                                                    'content': BLOCK_MESSAGE,
                                                },
                                                'finish_reason': 'stop',
                                            }
                                        ]
                                    },
                                    ensure_ascii=False,
                                )
                            elif _tail_norm.endswith(('messages', 'v1/messages')):
                                _block_body = json.dumps(  # _jdumps-whitelist: 非流式阻断合成占位构造
                                    {
                                        'id': 'blocked',
                                        'type': 'message',
                                        'role': 'assistant',
                                        'content': [
                                            {
                                                'type': 'text',
                                                'text': BLOCK_MESSAGE,
                                            }
                                        ],
                                        'stop_reason': 'end_turn',
                                        'usage': {
                                            'input_tokens': 0,
                                            'output_tokens': 1,
                                        },
                                    },
                                    ensure_ascii=False,
                                )
                            else:  # Responses API
                                _block_body = json.dumps(  # _jdumps-whitelist: 非流式阻断合成占位构造
                                    {
                                        'id': 'blocked',
                                        'status': 'completed',
                                        'output': [
                                            {
                                                'type': 'message',
                                                'role': 'assistant',
                                                'content': [
                                                    {
                                                        'type': 'output_text',
                                                        'text': BLOCK_MESSAGE,
                                                    }
                                                ],
                                            }
                                        ],
                                    },
                                    ensure_ascii=False,
                                )
                            return web.Response(
                                body=_block_body.encode('utf-8'),
                                status=200,
                                headers=filter_hop_headers(
                                    dict(upstream_resp.headers),
                                ),
                            )
                        # JSON-aware：仅对字符串节点做还原/检测，避免纯文本替换破坏 \\u 转义（Invalid \\escape）
                        # 7.4: 非对话尾透传不 walk
                        if not is_dialog_tail:
                            out_text = resp_text
                        elif hasattr(self, '_pii_response_process_json_aware'):
                            out_text = await self._pii_response_process_json_aware(
                                resp_text, active_t2p
                            )
                        else:
                            out_text = await self._pii_response_process(
                                resp_text, active_t2p
                            )
                        # 非流式整包：还原后统一清理残缺/完整幻觉 token 形态
                        # （Round 17 R4：非流式出口缺 _strip_partials；
                        #  审查补充：与流式 _split_safe_hold 语义对齐，
                        #  用 _strip_token_forms 一并剥离完整幻觉 token）
                        # JSON-aware 清理：仅对字符串节点剥离，避免破坏 \\u
                        try:
                            out_text = _strip_token_forms_json_aware(out_text)
                        except NameError:
                            out_text = _strip_token_forms(out_text)
                        # ── 响应还原后置校验：仅 active_t2p 非空时触发，失败先叶子重建仍失败才全量回退 ──
                        if active_t2p:
                            try:
                                _rs = resp_text.lstrip('\ufeff').lstrip()
                                if _rs.startswith(('{', '[')):
                                    try:
                                        _jloads(resp_text.lstrip('\ufeff'))
                                        _jloads(out_text.lstrip('\ufeff'))
                                    except Exception as _je:
                                        logger.warning(
                                            'response restore broke JSON, fallback to original: error=%s '
                                            'input_len=%d output_len=%d input_preview=%r output_preview=%r',
                                            _je,
                                            len(resp_text),
                                            len(out_text),
                                            resp_text[:4000],
                                            out_text[:4000],
                                        )
                                        out_text = resp_text
                            except Exception:
                                pass
                        if is_chat_tail(tail):
                            logger.info(
                                'LLM 剥离后诊断: %s %s status=%d empty_after_strip=%s out_len=%d tail=%s',
                                request.method,
                                target_url,
                                upstream_resp.status,
                                not out_text.strip(),
                                len(out_text),
                                tail,
                            )
                        # === DEBUG: 非流式恢复后回复落盘 ===
                        if _debug_save_eligible:
                            try:
                                _save_debug_text(
                                    req_id, 'response_restored.json', out_text
                                )
                                _save_debug_text(
                                    req_id, 'response_original_decoded.json', resp_text
                                )
                            except Exception as exc:
                                logger.debug('保存非流式恢复回复失败: %s', exc)
                        if (
                            not out_text.strip()
                            and upstream_resp.status == 200
                            and is_chat_tail(tail)
                        ):
                            logger.error(
                                '非流式剥离后空体转 502: %s %s status=%d out_len=%d',
                                request.method,
                                target_url,
                                upstream_resp.status,
                                len(out_text),
                            )
                            # 埋点上下文更新（剥离后空体 502）
                            _metrics_ctx['status'] = 502
                            _metrics_ctx['latency_ms'] = (
                                _time.time() - _metrics_ctx['t0']
                            ) * 1000
                            _metrics_ctx['bytes_out'] = 0
                            _metrics_ctx['empty_guarded'] = True
                            return web.Response(
                                body=json.dumps(  # _jdumps-whitelist: 非流式502错误体（非SSE转发）
                                    {'error': {'message': 'empty after strip'}},
                                    ensure_ascii=False,
                                ).encode('utf-8'),
                                status=502,
                                headers={'Content-Type': 'application/json'},
                            )
                        # 埋点上下文更新（非流式）
                        _metrics_ctx['status'] = upstream_resp.status
                        _metrics_ctx['latency_ms'] = (
                            _time.time() - _metrics_ctx['t0']
                        ) * 1000
                        _metrics_ctx['bytes_out'] = len(out_text.encode('utf-8'))
                        _metrics_ctx['empty_guarded'] = bool(
                            _is_empty and upstream_resp.status == 200
                        )
                        _metrics_ctx['invalid_json_guarded'] = bool(
                            _is_invalid_json and upstream_resp.status == 200
                        )
                        return web.Response(
                            body=out_text.encode('utf-8'),
                            status=upstream_resp.status,
                            headers=filter_hop_headers(
                                dict(upstream_resp.headers),
                            ),
                        )
            except Exception:
                if _debug_save_eligible and not _debug_saved:
                    _save_request_body(f'failed-{req_id}', out_body)
                    _save_debug_json(
                        req_id,
                        'exception.json',
                        {
                            'error': 'upstream_failed',
                            'target_url': target_url,
                            'tail': tail,
                            'method': request.method,
                        },
                    )
                logger.exception(
                    'LLM 上游请求失败: %s %s',
                    request.method,
                    target_url,
                )
                raise
            finally:
                # 可观测性埋点（请求完成统一入口，slow/fast/非流式/异常均达此）
                try:
                    _mc = getattr(self, '_metrics_collector', None)
                    if _mc is not None:
                        # 非对话请求彻底不进统计（design D4）：不调 incr_event、
                        # 不进 recent_events、不进聚合（v0.9.34 及之前归 other 的口径废弃）
                        # 注意：不能 return（finally 内 return 会跳过下方 PII/审计清理），
                        # 用 flag 跳过埋点体
                        if not is_chat_tail(tail):
                            _metrics_ctx['_skip_metrics'] = True
                        if not _metrics_ctx.get('_skip_metrics'):
                            _status = _metrics_ctx.get('status')
                            _lat = _metrics_ctx.get('latency_ms')
                            if _status is None:
                                # 异常/未达响应分支：按异常计
                                _metrics_ctx['exception'] = True
                                _status = 500
                                _lat = (_time.time() - _metrics_ctx['t0']) * 1000
                            _upstream = _metrics_ctx.get('upstream', str(port))
                            await _mc.incr_event(
                                upstream=_upstream,
                                status=_status,
                                latency_ms=_lat,
                                bytes_in=_metrics_ctx.get('bytes_in', 0),
                                bytes_out=_metrics_ctx.get('bytes_out', 0),
                                empty_guarded=_metrics_ctx.get('empty_guarded', False),
                                invalid_json_guarded=_metrics_ctx.get(
                                    'invalid_json_guarded', False
                                ),
                                client_gone=_metrics_ctx.get('client_gone', False),
                                exception=_metrics_ctx.get('exception', False),
                                sse_events=_metrics_ctx.get('sse_events', 0),
                                truncated=_metrics_ctx.get('truncated', 0),
                                json_aware_success=_metrics_ctx.get(
                                    'json_aware_success', 0
                                ),
                                json_leaf_fallback=_metrics_ctx.get(
                                    'json_leaf_fallback', 0
                                ),
                                json_full_fallback=_metrics_ctx.get(
                                    'json_full_fallback', 0
                                ),
                                placeholder_prompt_injected=_metrics_ctx.get(
                                    'placeholder_injected', False
                                ),
                                pii_hits=_metrics_ctx.get('pii_hits', 0),
                                pii_miss=_metrics_ctx.get('pii_miss', 0),
                                pii_found=_metrics_ctx.get('pii_found', False),
                                cred_hits=_metrics_ctx.get('cred_hits', 0),
                                cred_miss=_metrics_ctx.get('cred_miss', 0),
                                model=_metrics_ctx.get('model', 'unknown_model'),
                                tokens=_metrics_ctx.get('tokens') or None,
                                audit_by_verdict=_metrics_ctx.get('audit_by_verdict')
                                or None,
                                audit_by_rule=_metrics_ctx.get('audit_by_rule') or None,
                                pii_by_type=_metrics_ctx.get('pii_by_type') or None,
                                request_id=req_id,
                                tail=tail,
                                verdict=_metrics_ctx.get('verdict', ''),
                                raw_summary=_metrics_ctx.get('raw_summary', ''),
                            )
                            _metrics_ctx['_skip_metrics'] = False
                except Exception:
                    logger.debug('metrics 埋点失败', exc_info=True)
                # 请求级 PII 映射清理（无论成功/异常/客户端断连）
                if getattr(self, 'pii_enabled', False):
                    self._pii_cleanup()
                # 请求级审计状态清理（design D4 6.4：审批/挂起与流生命周期绑定）
                # 未决审批 → 取消（置 rejected 语义）；挂起缓冲 → 丢弃
                if getattr(self, 'audit_enabled_flag', False):
                    _created_ids = _audit_created_ids_var.get()
                    if isinstance(_created_ids, list) and _created_ids:
                        for _req_id in list(_created_ids):
                            _ap = self._audit_approval_pending.get(_req_id)
                            if _ap is not None and _ap.get('approved') is None:
                                _ap['approved'] = False
                                _ap['event'].set()
                            self._audit_approval_pending.pop(_req_id, None)
                        # 清理对应的 msg_id 映射
                        for _msg_id, _rid in list(self._audit_approval_msgs.items()):
                            if _rid in _created_ids:
                                self._audit_approval_msgs.pop(_msg_id, None)
                    else:
                        # 兜底：无跟踪列表时仅处理仍为 pending 的条目，避免误删活请求
                        for _req_id, _ap in list(
                            getattr(self, '_audit_approval_pending', {}).items()
                        ):
                            if (
                                _ap.get('approved') is None
                                and _ap.get('event') is not None
                            ):
                                # 仅当该 pending 的 event 已在当前 handler 创建的上下文才处理
                                # 保守策略：不全局 clear，逐条判断
                                pass
                        # 不全局 clear，仅由上面的 _created_ids 分支清理
                # D2 reset：按 token 恢复，避免跨请求/子任务泄露（失败显式清理防污染）
                try:
                    _pii_scope_var.reset(_cv_pii_scope_tok)
                except (LookupError, ValueError):
                    with contextlib.suppress(Exception):
                        _pii_scope_var.set(None)
                try:
                    from _metrics import _req_pii_var as _rpv

                    try:
                        _rpv.reset(_cv_req_pii_tok)
                    except (LookupError, ValueError):
                        with contextlib.suppress(Exception):
                            from _metrics import reset_req_pii_ctx

                            reset_req_pii_ctx()
                        with contextlib.suppress(Exception):
                            _rpv.set(None)  # type: ignore
                except Exception:
                    with contextlib.suppress(Exception):
                        from _metrics import reset_req_pii_ctx

                        reset_req_pii_ctx()
                    with contextlib.suppress(Exception):
                        from _metrics import _req_pii_var as _rpv3  # type: ignore

                        _rpv3.set(None)  # type: ignore
                with contextlib.suppress(LookupError, ValueError):
                    _audit_hold_active_var.reset(_cv_audit_hold_active_tok)
                with contextlib.suppress(LookupError, ValueError):
                    _audit_hold_buf_var.reset(_cv_audit_hold_buf_tok)
                with contextlib.suppress(LookupError, ValueError):
                    _audit_hold_bytes_var.reset(_cv_audit_hold_bytes_tok)
                with contextlib.suppress(LookupError, ValueError):
                    _last_anthropic_tool_name_var.reset(_cv_last_anthropic_tok)
                with contextlib.suppress(LookupError, ValueError):
                    _last_responses_tool_name_var.reset(_cv_last_responses_tok)
                with contextlib.suppress(LookupError, ValueError):
                    _audit_created_ids_var.reset(_cv_audit_created_ids_tok)

        app = web.Application()
        # 可观测性：先注册 /_admin/* 长路由（防通配 * 吞路由）
        _mc = getattr(self, '_metrics_collector', None)
        if _mc is not None:
            try:
                from _admin import init_observability

                init_observability(app, _mc)
            except Exception:
                logger.exception('初始化 /_admin 路由失败')
        app.router.add_route('*', '/{tail:.*}', handler)
        # 注意：不在此处注册 session.close() — _shared_session 由 shutdown() 统一关闭
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, '0.0.0.0', port).start()
        self._runners.append(runner)
        logger.info('LLM 代理 → 0.0.0.0:%d → %s', port, upstream)
