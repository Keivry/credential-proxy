"""嵌入式可观测性采集器（llm-observability-dashboard change）。

MetricsCollector:
- 单锁批递增（asyncio.Lock，锁内禁 await）: 每请求一次 `async with self._lock`
  护住全部计数器 + recent_events.append。
- 有界 queue.Queue(maxsize=5)（线程安全）+ ThreadPoolExecutor(metrics-writer)
  单写者串行覆盖式 UPSERT（INSERT ... ON CONFLICT DO UPDATE SET col=excluded.col）。
- 固定 12 桶 LATENCY_BUCKETS 二分命中，p95 用独立 p95-worker executor 不与写盘排队。
- WAL + busy_timeout=5000 + synchronous=NORMAL + user_version=1，文件 0600。
- ENOSPC 磁盘满降级内存-only（health.sqlite_ok=false）。
"""

from __future__ import annotations

import asyncio
import bisect
import contextvars
import json
import logging
import os
import queue
import re as _re
import sqlite3
import threading
import time
import urllib.parse
from collections import OrderedDict, deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

logger = logging.getLogger('credential-proxy.metrics')

# ── 常量 ──
LATENCY_BUCKETS: list[float] = [
    10,
    25,
    50,
    100,
    200,
    400,
    800,
    1500,
    3000,
    5000,
    10000,
    float('inf'),
]
"""固定 12 桶（ms）。最差桶中位误差约30.4% @[800,1500)（等比约33%）。"""

BUILTIN_KINDS = {
    'phone',
    'id_card',
    'email',
    'bank_card',
    'ipv4',
    'ipv6',
    'api_key',
}
"""内置 PII kind 白名单。"""

RING_MAXLEN = 10000
FLUSH_INTERVAL_S = 300  # 5min
# 有界队列上限：单 upstream 满 30d+168h 时 _snapshot 产出 198 条快照，
# 128 会固定丢最老 70 条；512 覆盖单 U 198 + 多 U 积压余量
# （flush 后立即 _drain_async 消费，队列主要缓冲单次 flush 积压）
QUEUE_MAXSIZE = 512
DAILY_RETENTION_DAYS = 30
HOURLY_RETENTION_HOURS = 24 * 7
DB_FILE = 'metrics.sqlite'

# SQLite 权限（0600）——含 -wal/-shm
MODE_0600 = 0o600


def metrics_bucket(latency_ms: float) -> float:
    """二分命中首个 >= latency_ms 的桶上界。Inf 桶为 float('inf')。"""
    return LATENCY_BUCKETS[bisect.bisect_left(LATENCY_BUCKETS, latency_ms)]


def sanitize_kind(raw_kind: str, custom_names: set[str] | None = None) -> str:
    """集中 kind 消毒：长度/形态/白名单 → custom_other。

    三处落盘前必经（scan 计数、register 计数、metrics.sqlite UPSERT json.dumps 前）。
    """
    if not isinstance(raw_kind, str) or not raw_kind:
        return 'custom_other'
    if len(raw_kind) > 32:
        return 'custom_other'
    if '__' in raw_kind:
        return 'custom_other'
    if '\x00' in raw_kind:
        return 'custom_other'
    norm = raw_kind.lower()
    if norm in BUILTIN_KINDS:
        return norm
    if custom_names and norm in {c.lower() for c in custom_names}:
        return norm
    return 'custom_other'


def normalize_usage(obj: dict | None, protocol: str) -> dict[str, int | None]:
    """归一三协议 usage → 8 字段 {prompt, completion, total, input, output,
    cached_read, cached_write, unknown}。

    protocol: 'openai' | 'anthropic' | 'responses' | 其他。
    total 语义: total = total_tokens or total or (input+output)；两值均缺 → unknown。
    """
    empty = {
        'prompt': None,
        'completion': None,
        'total': None,
        'input': None,
        'output': None,
        'cached_read': 0,
        'cached_write': 0,
        'unknown': True,
    }
    if not isinstance(obj, dict):
        return empty
    prompt = obj.get('prompt_tokens')
    completion = obj.get('completion_tokens')
    input_t = obj.get('input_tokens')
    output = obj.get('output_tokens')
    total = obj.get('total_tokens')
    if total is None:
        total = obj.get('total')
    if total is None:
        in_ok = isinstance(input_t, int) and input_t >= 0
        out_ok = isinstance(output, int) and output >= 0
        if in_ok and out_ok:
            total = input_t + output  # type: ignore[operator]
        elif in_ok:
            total = input_t
        elif out_ok:
            total = output
    # 缓存维度
    cached_read = 0
    cached_write = 0
    if protocol == 'anthropic':
        cached_read = obj.get('cache_read_input_tokens', 0) or 0
        cached_write = obj.get('cache_creation_input_tokens', 0) or 0
    elif protocol == 'responses':
        details = obj.get('input_tokens_details') or {}
        cached_read = details.get('cached_tokens', 0) or 0
    else:  # openai chat
        details = obj.get('prompt_tokens_details') or {}
        cached_read = details.get('cached_tokens', 0) or 0
    unknown = not (
        (isinstance(prompt, int) and isinstance(completion, int))
        or (isinstance(input_t, int) and isinstance(output, int))
    )
    return {
        'prompt': prompt if isinstance(prompt, int) else None,
        'completion': completion if isinstance(completion, int) else None,
        'total': total if isinstance(total, int) else None,
        'input': input_t if isinstance(input_t, int) else None,
        'output': output if isinstance(output, int) else None,
        'cached_read': cached_read,
        'cached_write': cached_write,
        'unknown': unknown,
    }


def _utc_now() -> float:
    return time.time()


def _day_key(ts: float) -> str:
    return time.strftime('%Y-%m-%d', time.gmtime(ts))


def _hour_key(ts: float) -> str:
    return time.strftime('%Y-%m-%dT%H:00:00Z', time.gmtime(ts))


def _chmod_0600(path: str) -> None:
    """批量 chmod 0600：文件与 -wal/-shm（防 WAL 延迟创建遗漏）。"""
    try:
        for suffix in ('', '-wal', '-shm'):
            p = path + suffix
            if os.path.exists(p):
                os.chmod(p, MODE_0600)
    except OSError:
        logger.debug('chmod 0600 失败: %s', path, exc_info=True)


# ── 脱敏摘要（不含明文契约）──

_PII_TOKEN_RE = _re.compile(r'__PII_\d+_[0-9a-fA-F]{8}__|__VG_CRED_\d{4,}__')
_CRED_TOKEN_RE = _re.compile(r'__VG_CRED_\d{4,}__')
# 常见密钥形态：sk-*（OpenAI 含 sk-proj-/sk-ant-）、xox*（Slack）、ghp_/gho_/github_pat_（GitHub）、
# AKIA*（AWS）、Bearer JWT（eyJ...）。raw_summary 来自已脱敏请求体，此处兜底防遗漏形态明文入库。
_API_KEY_RE = _re.compile(
    r'(?i)\b(sk-[A-Za-z0-9_\-]{16,}|xox[baprs]-[A-Za-z0-9\-]{10,}|'
    r'ghp_[A-Za-z0-9_]{30,}|gho_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{20,}|'
    r'AKIA[0-9A-Z]{16}|Bearer\s+eyJ[A-Za-z0-9_\-\.]{20,}|'
    r'sk-[A-Za-z0-9_\-]{20,})\b'
)
_EMAIL_RE = _re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b')
# 手机号明文（与 _pii.py 同款模式：前缀段验证 13x-19x，防误伤长数字串）
# 覆盖连续 11 位 + 带分隔符形态（138-0013-8000 / 138 0013 8000 / +86 138 0013 8000）
_PHONE_RE = _re.compile(
    r'(?<!\d)(?:(?:86|\+86)[- ]?)?(?:1[3-9]\d{9}|'
    r'1[3-9]\d[- ]?\d{4}[- ]?\d{4})(?!\d)'
)


def redact_summary(raw: str, limit: int = 120) -> str:
    """先脱敏后截断的单一路径摘要（不含明文 PII）。

    - 替换内部 token 形态为 [REDACTED:token]
    - 替换 sk-/xox 密钥形态与 email 为 [REDACTED:key]/[REDACTED:email]
    - 截断边界半字符保护：绝不切断多字节字符（Python str 按码点切片天然安全）
    """
    if not raw:
        return ''
    out = _PII_TOKEN_RE.sub('[REDACTED:token]', raw)
    # _CRED_TOKEN_RE 已被 _PII_TOKEN_RE 覆盖（__VG_CRED_\d{4,}__ 是后者的子集），
    # 删除冗余 sub 避免死分支（保留正则定义供诊断/测试引用）
    out = _API_KEY_RE.sub('[REDACTED:key]', out)
    out = _EMAIL_RE.sub('[REDACTED:email]', out)
    out = _PHONE_RE.sub('[REDACTED:phone]', out)
    if len(out) <= limit:
        return out
    # 截断边界半字符保护：Python 按码点切片天然不产生半字符，直接截断
    # 但超长摘要可能包含代理对（emoji），用 errors='ignore' 保证合法 UTF-8
    cut = (
        out[: limit - 1]
        .encode('utf-8', errors='ignore')
        .decode('utf-8', errors='ignore')
    )
    return cut + '…'


class _DailyAgg:
    """daily_agg 15 基础列 + 5 扩展列（与 design D1/spec 2.3 一致）。"""

    __slots__ = (
        'audit_by_rule',
        'audit_by_verdict',
        'cred_hits',
        'cred_lru_evictions',
        'cred_miss',
        'json_aware_success',
        'json_full_fallback',
        'json_leaf_fallback',
        'latency_buckets',
        'pii_by_type',
        'pii_hits',
        'pii_lru_evictions',
        'pii_miss',
        'pii_requests',
        'placeholder_prompt_injected',
        'requests',
        'requests_by_status',
        'tokens',
        'truncated_total',
    )

    def __init__(self) -> None:
        self.pii_by_type: dict[str, int] = {}
        self.pii_hits = 0
        self.pii_miss = 0
        self.pii_requests = 0
        self.cred_hits = 0
        self.cred_miss = 0
        self.cred_lru_evictions = 0
        self.pii_lru_evictions = 0
        self.requests = 0
        self.requests_by_status: dict[str, int] = {}
        self.tokens: dict[str, dict[str, Any]] = {}
        self.audit_by_verdict: dict[str, int] = {}
        self.audit_by_rule: dict[str, int] = {}
        self.latency_buckets: dict[str, int] = {}
        self.placeholder_prompt_injected = 0
        self.truncated_total = 0
        self.json_aware_success = 0
        self.json_leaf_fallback = 0
        self.json_full_fallback = 0

    def to_dict(self) -> dict[str, Any]:
        """序列化为 dict（快照用）。"""
        return {
            'pii_by_type': self.pii_by_type,
            'pii_hits': self.pii_hits,
            'pii_miss': self.pii_miss,
            'pii_requests': self.pii_requests,
            'cred_hits': self.cred_hits,
            'cred_miss': self.cred_miss,
            'cred_lru_evictions': self.cred_lru_evictions,
            'pii_lru_evictions': self.pii_lru_evictions,
            'requests': self.requests,
            'requests_by_status': self.requests_by_status,
            'tokens': self.tokens,
            'audit_by_verdict': self.audit_by_verdict,
            'audit_by_rule': self.audit_by_rule,
            'latency_buckets': self.latency_buckets,
            'placeholder_prompt_injected': self.placeholder_prompt_injected,
            'truncated_total': self.truncated_total,
            'json_aware_success': self.json_aware_success,
            'json_leaf_fallback': self.json_leaf_fallback,
            'json_full_fallback': self.json_full_fallback,
        }


class _HourlyAgg:
    """hourly_agg 9 列轻量子集（pii_hits/miss、cred、audit 仅日表保留）。"""

    __slots__ = (
        'cred_lru_evictions',
        'latency_buckets',
        'pii_by_type',
        'pii_hits',
        'pii_lru_evictions',
        'pii_miss',
        'pii_requests',
        'requests',
        'requests_by_status',
        'tokens',
    )

    def __init__(self) -> None:
        self.requests = 0
        self.requests_by_status: dict[str, int] = {}
        self.tokens: dict[str, dict[str, Any]] = {}
        self.latency_buckets: dict[str, int] = {}
        self.pii_by_type: dict[str, int] = {}
        self.pii_hits = 0
        self.pii_miss = 0
        self.pii_requests = 0
        self.pii_lru_evictions = 0
        self.cred_lru_evictions = 0

    def to_dict(self) -> dict[str, Any]:
        """序列化为 dict（快照用）。"""
        return {
            'requests': self.requests,
            'requests_by_status': self.requests_by_status,
            'tokens': self.tokens,
            'latency_buckets': self.latency_buckets,
            'pii_by_type': self.pii_by_type,
            'pii_hits': self.pii_hits,
            'pii_miss': self.pii_miss,
            'pii_requests': self.pii_requests,
            'pii_lru_evictions': self.pii_lru_evictions,
            'cred_lru_evictions': self.cred_lru_evictions,
        }


def _deep_copy_snapshot(agg: _DailyAgg) -> _DailyAgg:
    """深拷贝快照（防线程撕裂；拷贝段 100~400µs 每 5min 可接受）。"""
    copy = _DailyAgg()
    copy.pii_by_type = dict(agg.pii_by_type)
    copy.pii_hits = agg.pii_hits
    copy.pii_miss = agg.pii_miss
    copy.pii_requests = agg.pii_requests
    copy.cred_hits = agg.cred_hits
    copy.cred_miss = agg.cred_miss
    copy.cred_lru_evictions = agg.cred_lru_evictions
    copy.pii_lru_evictions = agg.pii_lru_evictions
    copy.requests = agg.requests
    copy.requests_by_status = dict(agg.requests_by_status)
    copy.tokens = json.loads(json.dumps(agg.tokens)) if agg.tokens else {}
    copy.audit_by_verdict = dict(agg.audit_by_verdict)
    copy.audit_by_rule = dict(agg.audit_by_rule)
    copy.latency_buckets = dict(agg.latency_buckets)
    copy.placeholder_prompt_injected = agg.placeholder_prompt_injected
    copy.truncated_total = agg.truncated_total
    copy.json_aware_success = agg.json_aware_success
    copy.json_leaf_fallback = agg.json_leaf_fallback
    copy.json_full_fallback = agg.json_full_fallback
    return copy


def _copy_hourly(agg: _HourlyAgg) -> _HourlyAgg:
    copy = _HourlyAgg()
    copy.requests = agg.requests
    copy.requests_by_status = dict(agg.requests_by_status)
    copy.tokens = json.loads(json.dumps(agg.tokens)) if agg.tokens else {}
    copy.latency_buckets = dict(agg.latency_buckets)
    copy.pii_by_type = dict(agg.pii_by_type)
    copy.pii_hits = agg.pii_hits
    copy.pii_miss = agg.pii_miss
    copy.pii_requests = agg.pii_requests
    copy.pii_lru_evictions = agg.pii_lru_evictions
    copy.cred_lru_evictions = agg.cred_lru_evictions
    return copy


class MetricsCollector:
    """进程级单例采集器。

    用法:
        collector = MetricsCollector(DATA_DIR)
        await collector.incr_event(upstream='8878', status='200', ...)
        await collector.close()
    """

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.db_path = os.path.join(data_dir, DB_FILE)
        self._lock = asyncio.Lock()
        # 进程级聚合计数（请求级 + LRU 级）
        self.counters: dict[str, Any] = {}
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=RING_MAXLEN)
        self._daily: dict[tuple[str, str], _DailyAgg] = (
            OrderedDict()
        )  # (date, upstream) -> agg
        self._hourly: dict[tuple[str, str], _HourlyAgg] = (
            OrderedDict()
        )  # (hour, upstream) -> agg
        self._p95_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix='p95-worker'
        )
        self._writer_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix='metrics-writer'
        )
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=QUEUE_MAXSIZE)
        self._flush_task: asyncio.Task | None = None
        self._closed = False
        self._sqlite_ok = True
        self._sqlite_error: str | None = None
        self._dropped_snapshots = 0
        self._first_dropped_ts: float | None = None
        self._last_dropped_ts: float | None = None
        self._last_flush_ts = _utc_now()
        self._conn: sqlite3.Connection | None = None
        self._connect_db()

    # ── DB ──

    def _connect_db(self) -> None:
        try:
            old_umask = os.umask(0o077)
            try:
                # makedirs 也须在 umask 窗口内：裸机首启 DATA_DIR 应 700 而非 755
                os.makedirs(self.data_dir, exist_ok=True)
                conn = sqlite3.connect(
                    self.db_path, timeout=5.0, check_same_thread=False
                )
            finally:
                os.umask(old_umask)
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA busy_timeout=5000')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA wal_autocheckpoint=1000')
            conn.execute('PRAGMA user_version=1')
            self._create_tables(conn)
            conn.commit()
            self._conn = conn
            _chmod_0600(self.db_path)
            self._sqlite_ok = True
        except (OSError, sqlite3.Error) as e:
            self._sqlite_ok = False
            self._sqlite_error = str(e)[:200]
            logger.error('metrics.sqlite 初始化失败，降级内存-only: %s', e)

    def _create_tables(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS daily_agg (
                date TEXT NOT NULL,
                upstream TEXT NOT NULL,
                pii_by_type JSON,
                pii_hits INT,
                pii_miss INT,
                pii_requests INT,
                cred_hits INT,
                cred_miss INT,
                cred_lru_evictions INT,
                pii_lru_evictions INT,
                requests INT,
                requests_by_status JSON,
                tokens JSON,
                audit_by_verdict JSON,
                audit_by_rule JSON,
                latency_buckets JSON,
                placeholder_prompt_injected INT,
                truncated_total INT,
                json_aware_success INT,
                json_leaf_fallback INT,
                json_full_fallback INT,
                PRIMARY KEY(date, upstream)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hourly_agg (
                hour TEXT NOT NULL,
                upstream TEXT NOT NULL,
                requests INT,
                requests_by_status JSON,
                tokens JSON,
                latency_buckets JSON,
                pii_by_type JSON,
                pii_hits INT,
                pii_miss INT,
                pii_requests INT,
                pii_lru_evictions INT,
                cred_lru_evictions INT,
                PRIMARY KEY(hour, upstream)
            )
            """
        )
        # 轻量迁移：旧库（无 pii_hits/pii_miss/pii_requests 列）升级补列
        # CREATE TABLE IF NOT EXISTS 不会给已存在的表加列，需显式 ALTER
        for table, col in (
            ('daily_agg', 'pii_requests'),
            ('hourly_agg', 'pii_hits'),
            ('hourly_agg', 'pii_miss'),
            ('hourly_agg', 'pii_requests'),
        ):
            cols = {r[1] for r in conn.execute(f'PRAGMA table_info({table})')}
            if col not in cols:
                conn.execute(f'ALTER TABLE {table} ADD COLUMN {col} INT')

    def _write_flush(self, snapshot: dict[str, Any]) -> None:
        """单写者覆盖式 UPSERT（线程中运行）。"""
        if not self._sqlite_ok or self._conn is None:
            return
        try:
            day = snapshot.get('date', '')
            hour = snapshot.get('hour', '')
            upstream = snapshot.get('upstream', 'other')
            conn = self._conn
            if day:
                conn.execute(
                    """
                    INSERT INTO daily_agg (
                        date, upstream, pii_by_type, pii_hits, pii_miss, pii_requests,
                        cred_hits, cred_miss, cred_lru_evictions,
                        pii_lru_evictions, requests, requests_by_status,
                        tokens, audit_by_verdict, audit_by_rule,
                        latency_buckets, placeholder_prompt_injected,
                        truncated_total, json_aware_success,
                        json_leaf_fallback, json_full_fallback
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(date, upstream) DO UPDATE SET
                        pii_by_type=excluded.pii_by_type,
                        pii_hits=excluded.pii_hits,
                        pii_miss=excluded.pii_miss,
                        pii_requests=excluded.pii_requests,
                        cred_hits=excluded.cred_hits,
                        cred_miss=excluded.cred_miss,
                        cred_lru_evictions=excluded.cred_lru_evictions,
                        pii_lru_evictions=excluded.pii_lru_evictions,
                        requests=excluded.requests,
                        requests_by_status=excluded.requests_by_status,
                        tokens=excluded.tokens,
                        audit_by_verdict=excluded.audit_by_verdict,
                        audit_by_rule=excluded.audit_by_rule,
                        latency_buckets=excluded.latency_buckets,
                        placeholder_prompt_injected=excluded.placeholder_prompt_injected,
                        truncated_total=excluded.truncated_total,
                        json_aware_success=excluded.json_aware_success,
                        json_leaf_fallback=excluded.json_leaf_fallback,
                        json_full_fallback=excluded.json_full_fallback
                    """,
                    (
                        day,
                        upstream,
                        json.dumps(snapshot.get('pii_by_type', {}), ensure_ascii=False),
                        snapshot.get('pii_hits', 0),
                        snapshot.get('pii_miss', 0),
                        snapshot.get('pii_requests', 0),
                        snapshot.get('cred_hits', 0),
                        snapshot.get('cred_miss', 0),
                        snapshot.get('cred_lru_evictions', 0),
                        snapshot.get('pii_lru_evictions', 0),
                        snapshot.get('requests', 0),
                        json.dumps(
                            snapshot.get('requests_by_status', {}), ensure_ascii=False
                        ),
                        json.dumps(snapshot.get('tokens', {}), ensure_ascii=False),
                        json.dumps(
                            snapshot.get('audit_by_verdict', {}), ensure_ascii=False
                        ),
                        json.dumps(
                            snapshot.get('audit_by_rule', {}), ensure_ascii=False
                        ),
                        json.dumps(
                            snapshot.get('latency_buckets', {}), ensure_ascii=False
                        ),
                        snapshot.get('placeholder_prompt_injected', 0),
                        snapshot.get('truncated_total', 0),
                        snapshot.get('json_aware_success', 0),
                        snapshot.get('json_leaf_fallback', 0),
                        snapshot.get('json_full_fallback', 0),
                    ),
                )
            if hour:
                conn.execute(
                    """
                    INSERT INTO hourly_agg (
                        hour, upstream, requests, requests_by_status,
                        tokens, latency_buckets, pii_by_type,
                        pii_hits, pii_miss, pii_requests,
                        pii_lru_evictions, cred_lru_evictions
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(hour, upstream) DO UPDATE SET
                        requests=excluded.requests,
                        requests_by_status=excluded.requests_by_status,
                        tokens=excluded.tokens,
                        latency_buckets=excluded.latency_buckets,
                        pii_by_type=excluded.pii_by_type,
                        pii_hits=excluded.pii_hits,
                        pii_miss=excluded.pii_miss,
                        pii_requests=excluded.pii_requests,
                        pii_lru_evictions=excluded.pii_lru_evictions,
                        cred_lru_evictions=excluded.cred_lru_evictions
                    """,
                    (
                        hour,
                        upstream,
                        snapshot.get('requests', 0),
                        json.dumps(
                            snapshot.get('requests_by_status', {}), ensure_ascii=False
                        ),
                        json.dumps(snapshot.get('tokens', {}), ensure_ascii=False),
                        json.dumps(
                            snapshot.get('latency_buckets', {}), ensure_ascii=False
                        ),
                        json.dumps(snapshot.get('pii_by_type', {}), ensure_ascii=False),
                        snapshot.get('pii_hits', 0),
                        snapshot.get('pii_miss', 0),
                        snapshot.get('pii_requests', 0),
                        snapshot.get('pii_lru_evictions', 0),
                        snapshot.get('cred_lru_evictions', 0),
                    ),
                )
            self._trim_old(conn)
            conn.commit()
            _chmod_0600(self.db_path)
        except (OSError, sqlite3.Error) as e:
            self._handle_write_error(e)

    def _handle_write_error(self, e: Exception) -> None:
        if isinstance(e, OSError) and getattr(e, 'errno', None) == 28:
            self._sqlite_ok = False
            self._sqlite_error = str(e)[:200]
            logger.error('metrics.sqlite ENOSPC，降级内存-only: %s', e)
        elif isinstance(e, sqlite3.OperationalError) and (
            'disk I/O error' in str(e) or 'database or disk is full' in str(e)
        ):
            self._sqlite_ok = False
            self._sqlite_error = str(e)[:200]
            logger.error('metrics.sqlite 磁盘错误，降级内存-only: %s', e)
        else:
            logger.warning('metrics.sqlite 写入失败: %s', e)

    def _trim_old(self, conn: sqlite3.Connection) -> None:
        """30天/7天滚动删除（Python 计算 cutoff，UTC 统一）。"""
        now = _utc_now()
        cutoff_date = time.strftime(
            '%Y-%m-%d',
            time.gmtime(now - DAILY_RETENTION_DAYS * 86400),
        )
        cutoff_hour = time.strftime(
            '%Y-%m-%dT%H:00:00Z',
            time.gmtime(now - HOURLY_RETENTION_HOURS * 3600),
        )
        conn.execute('DELETE FROM daily_agg WHERE date < ?', (cutoff_date,))
        conn.execute('DELETE FROM hourly_agg WHERE hour < ?', (cutoff_hour,))

    # ── 快照 ──

    def _snapshot(self, now: float) -> list[dict[str, Any]]:
        """深拷贝当前累计 → 按 (date,upstream)/(hour,upstream) 键拆快照。"""
        out: list[dict[str, Any]] = []
        for (date, up), agg in list(self._daily.items()):
            s = {'date': date, 'upstream': up, **_deep_copy_snapshot(agg).to_dict()}
            out.append(s)
        for (hour, up), hagg in list(self._hourly.items()):
            s = {'hour': hour, 'upstream': up, **_copy_hourly(hagg).to_dict()}
            out.append(s)
        self._trim_memory(now)
        return out

    def _trim_memory(self, now: float) -> None:
        """内存累计滚动清理：_daily 保留 30d、_hourly 保留 7d（与 DB 保留一致）。"""
        day_cutoff = time.strftime(
            '%Y-%m-%d',
            time.gmtime(now - DAILY_RETENTION_DAYS * 86400),
        )
        hour_cutoff = time.strftime(
            '%Y-%m-%dT%H:00:00Z',
            time.gmtime(now - HOURLY_RETENTION_HOURS * 3600),
        )
        for key in [k for k in self._daily if k[0] < day_cutoff]:
            del self._daily[key]
        for key in [k for k in self._hourly if k[0] < hour_cutoff]:
            del self._hourly[key]

    # ── 事件递增 ──

    async def incr_event(
        self,
        *,
        upstream: str = 'other',
        status: int = 200,
        latency_ms: float | None = None,
        bytes_in: int = 0,
        bytes_out: int = 0,
        empty_guarded: bool = False,
        invalid_json_guarded: bool = False,
        client_gone: bool = False,
        exception: bool = False,
        sse_events: int = 0,
        truncated: int = 0,
        json_aware_success: int = 0,
        json_leaf_fallback: int = 0,
        json_full_fallback: int = 0,
        placeholder_prompt_injected: bool = False,
        pii_hits: int = 0,
        pii_miss: int = 0,
        pii_found: bool = False,
        cred_hits: int = 0,
        cred_miss: int = 0,
        model: str = 'unknown_model',
        tokens: dict[str, Any] | None = None,
        audit_by_verdict: dict[str, int] | None = None,
        audit_by_rule: dict[str, int] | None = None,
        pii_by_type: dict[str, int] | None = None,
        request_id: str = '',
        tail: str = '',
        verdict: str = '',
        raw_summary: str = '',
    ) -> None:
        """请求完成时的单锁批递增（锁内禁 await）。"""
        now = _utc_now()
        day = _day_key(now)
        hour = _hour_key(now)
        # 锁外收集 delta
        d_up = 'other' if upstream == 'other' else upstream
        status_s = str(status)
        delta_pii: dict[str, int] = {}
        for k, v in (pii_by_type or {}).items():
            sk = sanitize_kind(k)
            delta_pii[sk] = delta_pii.get(sk, 0) + v
        delta_verdict: dict[str, int] = dict(audit_by_verdict or {})
        delta_rule: dict[str, int] = dict(audit_by_rule or {})
        # 防御性拷贝（内层也拷）：metrics_ctx['tokens'] 是请求局部 dict，流式增量修改
        # 会污染 recent_events/聚合已引用的同一对象；tokens 结构为 {model: {k: int}}，
        # 内层 dict 也须隔离（浅拷贝外层不足以防止内层共享引用）
        tokens_d = (
            {k: dict(v) if isinstance(v, dict) else v for k, v in tokens.items()}
            if tokens
            else {}
        )
        latency_ms_v = latency_ms if latency_ms is not None else None
        # model 白名单/截断（防属性注入/超长；非法则归 unknown_model）
        if not _re.fullmatch(r'[A-Za-z0-9._/\-]{1,64}', model or ''):
            model = 'unknown_model'
        # 锁外做脱敏（5 个正则替换，避免占用全局锁）
        summary_redacted = redact_summary(raw_summary, 120) if raw_summary else ''

        async with self._lock:
            d = self._daily.setdefault((day, d_up), _DailyAgg())
            h = self._hourly.setdefault((hour, d_up), _HourlyAgg())
            d.requests += 1
            h.requests += 1
            d.requests_by_status[status_s] = d.requests_by_status.get(status_s, 0) + 1
            h.requests_by_status[status_s] = h.requests_by_status.get(status_s, 0) + 1
            if latency_ms_v is not None:
                bucket = metrics_bucket(latency_ms_v)
                d.latency_buckets[str(bucket)] = (
                    d.latency_buckets.get(str(bucket), 0) + 1
                )
                h.latency_buckets[str(bucket)] = (
                    h.latency_buckets.get(str(bucket), 0) + 1
                )
            if empty_guarded:
                d.requests_by_status['empty_guarded'] = (
                    d.requests_by_status.get('empty_guarded', 0) + 1
                )
            if invalid_json_guarded:
                d.requests_by_status['invalid_json_guarded'] = (
                    d.requests_by_status.get('invalid_json_guarded', 0) + 1
                )
            if sse_events:
                d.requests_by_status['sse_events'] = (
                    d.requests_by_status.get('sse_events', 0) + sse_events
                )
            if truncated:
                d.truncated_total += truncated
            if json_aware_success:
                d.json_aware_success += json_aware_success
            if json_leaf_fallback:
                d.json_leaf_fallback += json_leaf_fallback
            if json_full_fallback:
                d.json_full_fallback += json_full_fallback
            if placeholder_prompt_injected:
                d.placeholder_prompt_injected += 1
            for k, v in delta_pii.items():
                d.pii_by_type[k] = d.pii_by_type.get(k, 0) + v
                h.pii_by_type[k] = h.pii_by_type.get(k, 0) + v
            d.pii_hits += pii_hits
            d.pii_miss += pii_miss
            h.pii_hits += pii_hits
            h.pii_miss += pii_miss
            if pii_found:
                d.pii_requests += 1
                h.pii_requests += 1
            d.cred_hits += cred_hits
            d.cred_miss += cred_miss
            for k, v in delta_verdict.items():
                d.audit_by_verdict[k] = d.audit_by_verdict.get(k, 0) + v
            for k, v in delta_rule.items():
                d.audit_by_rule[k] = d.audit_by_rule.get(k, 0) + v
            if tokens_d:
                self._merge_tokens(d.tokens, tokens_d)
                self._merge_tokens(h.tokens, tokens_d)
            # recent_events
            if request_id:
                # 从 ContextVar 读 per-request 真实计数（sync 钩子累计）：
                # pii_hits/pii_miss 若调用方显式传参则优先，否则取 ctx 累计
                _ctx_pii = _req_pii_var.get()
                if _ctx_pii:
                    if pii_hits == 0:
                        pii_hits = _ctx_pii.get('pii_hits', 0)
                    if pii_miss == 0:
                        pii_miss = _ctx_pii.get('pii_miss', 0)
                    if cred_hits == 0:
                        cred_hits = _ctx_pii.get('cred_hits', 0)
                    if cred_miss == 0:
                        cred_miss = _ctx_pii.get('cred_miss', 0)
                self.recent_events.append(
                    {
                        'ts': now,
                        'request_id': request_id,
                        'upstream': d_up,
                        'model': model,
                        'tail': tail,
                        'status': status_s,
                        'latency_ms': latency_ms_v,
                        'pii_hits': pii_hits,
                        'pii_miss': pii_miss,
                        'pii_found': pii_found,
                        'cred_hits': cred_hits,
                        'cred_miss': cred_miss,
                        'tokens': tokens_d,
                        'verdict': verdict,
                        'summary': summary_redacted,
                        'client_gone': client_gone,
                        'exception': exception,
                    }
                )

    @staticmethod
    def _merge_tokens(
        target: dict[str, dict[str, Any]], src: dict[str, dict[str, Any]]
    ) -> None:
        for model, u in src.items():
            if not isinstance(u, dict):
                continue
            t = target.setdefault(model, {})
            for k, v in u.items():
                if isinstance(v, (int, float)):
                    t[k] = t.get(k, 0) + v

    # ── LRU 淘汰 / gauge 递增 ──

    async def incr_lru_evictions(self, cred: int = 0, pii: int = 0) -> None:
        now = _utc_now()
        day = _day_key(now)
        hour = _hour_key(now)
        async with self._lock:
            d = self._daily.setdefault((day, 'other'), _DailyAgg())
            h = self._hourly.setdefault((hour, 'other'), _HourlyAgg())
            d.cred_lru_evictions += cred
            d.pii_lru_evictions += pii
            h.cred_lru_evictions += cred
            h.pii_lru_evictions += pii

    async def incr_placeholder_injected(self) -> None:
        now = _utc_now()
        day = _day_key(now)
        async with self._lock:
            d = self._daily.setdefault((day, 'other'), _DailyAgg())
            d.placeholder_prompt_injected += 1

    async def incr_truncated(self) -> None:
        now = _utc_now()
        day = _day_key(now)
        async with self._lock:
            d = self._daily.setdefault((day, 'other'), _DailyAgg())
            d.truncated_total += 1

    async def incr_audit_log_write_fail(self) -> None:
        """audit_log_write_fail 计数（内存 gauge，不进聚合）。"""
        async with self._lock:
            self.counters['audit_log_write_fail'] = (
                self.counters.get('audit_log_write_fail', 0) + 1
            )

    async def incr_audit_approval_result(self, result: str) -> None:
        """审批结果分布 audit_approval_result（内存计数，重启归零）。"""
        async with self._lock:
            cur = self.counters.setdefault('audit_approval_result', {})
            cur[result] = cur.get(result, 0) + 1

    async def set_audit_pending_gauge(self, pending: int, overflows: int = 0) -> None:
        """audit_pending_total / audit_hold_overflows 内存 gauge（瞬态）。"""
        async with self._lock:
            self.counters['audit_pending_total'] = pending
            if overflows:
                self.counters['audit_hold_overflows'] = overflows

    # ── flush / 定时 ──

    def _enqueue(self, snapshot: list[dict[str, Any]]) -> None:
        """有界队列入队：QueueFull 丢最老再入队并计 dropped。"""
        for s in snapshot:
            try:
                self._queue.put_nowait(s)
            except queue.Full:
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    pass
                self._dropped_snapshots += 1
                now = _utc_now()
                if self._first_dropped_ts is None:
                    self._first_dropped_ts = now
                self._last_dropped_ts = now
                logger.warning(
                    'metrics 队列满，丢弃快照: dropped=%d', self._dropped_snapshots
                )
                try:
                    self._queue.put_nowait(s)
                except queue.Full:
                    pass

    async def flush(self) -> None:
        """深拷贝当前累计 → 入队 → 单写者写盘。锁内禁 await。"""
        now = _utc_now()
        snapshot = self._snapshot(now)
        self._last_flush_ts = now
        if snapshot:
            self._enqueue(snapshot)

    def _flush_sync(self) -> None:
        """同步 flush（供 close 前调用；事件循环外）。"""
        now = _utc_now()
        snapshot = self._snapshot(now)
        self._last_flush_ts = now
        for s in snapshot:
            self._write_flush(s)

    async def _flush_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(FLUSH_INTERVAL_S)
                await self.flush()
                # 立即消费队列（单写者 executor 串行写盘）——避免有界队列只入不出的断流
                await self._drain_async()
        except asyncio.CancelledError:
            pass

    async def _drain_async(self) -> None:
        """把队列中的快照交给单写者线程写盘（背压保留：队列仍是有界的）。"""
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._writer_executor, self._drain_queue)

    def start(self) -> None:
        """启动 5min 定时 flush（需在运行事件循环内调用；无循环时惰性跳过）。"""
        if self._flush_task is None and not self._closed:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return  # 无运行循环（同步 init），惰性等首次 flush 调用
            self._flush_task = asyncio.create_task(self._flush_loop())

    # ── p95 / ring ──

    def ring_stats(
        self,
        *,
        upstream_filter: str | None = None,
        model_filter: str | None = None,
    ) -> dict[str, Any]:
        """recent_events 现场统计（含 is_precise/ring_coverage_s）。

        可选按 upstream/model 过滤（1h 窗口查询带筛选时用）。
        """
        now = _utc_now()
        evs = [
            e
            for e in self.recent_events
            if (upstream_filter is None or e.get('upstream') == upstream_filter)
            and (model_filter is None or e.get('model') == model_filter)
        ]
        if not evs:
            return {
                'ring_len': len(evs),
                'ring_coverage_s': 0.0,
                'is_precise': False,
                'p95': None,
                'p50': None,
            }
        oldest_ts = evs[0]['ts']
        coverage = now - oldest_ts
        lat = [e['latency_ms'] for e in evs if e.get('latency_ms') is not None]
        precise = coverage >= 3600 and len(lat) >= 100
        p95 = p50 = None
        if lat:
            lat_sorted = sorted(lat)
            n = len(lat_sorted)
            p95 = lat_sorted[min(int(0.95 * n), n - 1)]
            p50 = lat_sorted[min(int(0.50 * n), n - 1)]
        return {
            'ring_len': len(evs),
            'ring_coverage_s': round(coverage, 1),
            'is_precise': precise,
            'p95': p95,
            'p50': p50,
        }

    async def p95_async(self) -> dict[str, Any]:
        """p95 用独立 p95-worker executor（不与写盘排队）。"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._p95_executor, self.ring_stats)

    # ── health / 查询 ──

    def health(self) -> dict[str, Any]:
        ring = self.ring_stats()
        return {
            'pii_enabled': bool(self.counters.get('_pii_enabled', True)),
            'audit_mode': self.counters.get('_audit_mode', ''),
            'placeholder_prompt_enabled': bool(
                self.counters.get('_placeholder_prompt_enabled', True)
            ),
            'metrics_age_s': round(_utc_now() - self._last_flush_ts, 1),
            'sqlite_ok': self._sqlite_ok,
            'ring_len': ring['ring_len'],
            'ring_coverage_s': ring['ring_coverage_s'],
            'is_precise': ring['is_precise'],
            'p95': ring['p95'],
            'p50': ring['p50'],
            'dropped_snapshots': self._dropped_snapshots,
            'first_dropped_ts': self._first_dropped_ts,
            'last_dropped_ts': self._last_dropped_ts,
            'audit_pending_total': self.counters.get('audit_pending_total', 0),
            'audit_hold_overflows': self.counters.get('audit_hold_overflows', 0),
            'truncated_total': self._sum_counter('truncated_total'),
            'json_aware_success': self._sum_counter('json_aware_success'),
            'json_leaf_fallback': self._sum_counter('json_leaf_fallback'),
            'json_full_fallback': self._sum_counter('json_full_fallback'),
            'placeholder_prompt_injected': self._sum_counter(
                'placeholder_prompt_injected'
            ),
            'sqlite_error': self._sqlite_error,
        }

    def _sum_counter(self, key: str) -> int:
        total = 0
        for d in self._daily.values():
            total += getattr(d, key, 0)
        return total

    def set_health_flag(self, key: str, value: Any) -> None:
        self.counters[key] = value

    def set_pii_enabled_sync(self, enabled: bool) -> None:
        self.counters['_pii_enabled'] = bool(enabled)

    def set_audit_mode_sync(self, mode: str) -> None:
        self.counters['_audit_mode'] = mode

    def set_placeholder_prompt_enabled_sync(self, enabled: bool) -> None:
        self.counters['_placeholder_prompt_enabled'] = bool(enabled)

    # ── 窗口查询 ──

    def query_range(
        self,
        range_: str,
        *,
        model_filter: str | None = None,
        upstream_filter: str | None = None,
    ) -> dict[str, Any]:
        """?range=1h|24h|7d|30d 聚合（1h 内存 ring，其余 DB 桶 SUM）。"""
        if range_ == '1h':
            return self._query_1h(model_filter, upstream_filter)
        hours = 24 if range_ == '24h' else (24 * 7 if range_ == '7d' else 24 * 30)
        return self._query_db(hours, model_filter, upstream_filter)

    def _query_1h(
        self,
        model_filter: str | None = None,
        upstream_filter: str | None = None,
    ) -> dict[str, Any]:
        now = _utc_now()
        cutoff = now - 3600
        evs = [
            e
            for e in self.recent_events
            if e['ts'] >= cutoff
            and (upstream_filter is None or e.get('upstream') == upstream_filter)
            and (model_filter is None or e.get('model') == model_filter)
        ]
        ring = self.ring_stats(
            upstream_filter=upstream_filter, model_filter=model_filter
        )
        requests = len(evs)
        by_status: dict[str, int] = {}
        pii_by_type: dict[str, int] = {}
        tokens: dict[str, dict[str, Any]] = {}
        pii_hits = pii_miss = pii_requests = cred_hits = cred_miss = 0
        for e in evs:
            s = e['status']
            by_status[s] = by_status.get(s, 0) + 1
            # recent_events 不含 pii_by_type 明细（含类型分布需从 daily 拉近 1h）
            if e.get('pii_found'):
                pii_requests += 1
            pii_hits += e.get('pii_hits', 0)
            pii_miss += e.get('pii_miss', 0)
        # 1h 的 pii_by_type / tokens 从 daily 当日累计近似（按 1h 窗口取当日）
        day_key = _day_key(now)
        audit_by_verdict: dict[str, int] = {}
        audit_by_rule: dict[str, int] = {}
        for (_d, _up), agg in self._daily.items():
            if _d != day_key:
                continue
            if upstream_filter is not None and _up != upstream_filter:
                continue
            for k, v in agg.pii_by_type.items():
                pii_by_type[k] = pii_by_type.get(k, 0) + v
            if model_filter is not None:
                self._merge_tokens(
                    tokens,
                    {k: v for k, v in agg.tokens.items() if k == model_filter},
                )
            else:
                self._merge_tokens(tokens, agg.tokens)
            # pii_hits/pii_miss/pii_requests 均从 recent_events 精确统计（同 requests 数据源）；
            # _daily 只作为 pii_by_type/tokens 的全天近似
            cred_hits += agg.cred_hits
            cred_miss += agg.cred_miss
            for k, v in agg.audit_by_verdict.items():
                audit_by_verdict[k] = audit_by_verdict.get(k, 0) + v
            for k, v in agg.audit_by_rule.items():
                audit_by_rule[k] = audit_by_rule.get(k, 0) + v
        if model_filter:
            tokens = {k: v for k, v in tokens.items() if k == model_filter}
        return {
            'range': '1h',
            'requests': requests,
            'requests_by_status': by_status,
            'pii_by_type': pii_by_type,
            'pii_hits': pii_hits,
            'pii_miss': pii_miss,
            'pii_requests': pii_requests,
            'cred_hits': cred_hits,
            'cred_miss': cred_miss,
            'tokens': tokens,
            'latency_buckets': {},
            'audit_by_verdict': audit_by_verdict,
            'audit_by_rule': audit_by_rule,
            'latency': {
                'p50': ring['p50'],
                'p95': ring['p95'],
                'is_precise': ring['is_precise'],
            },
        }

    def _query_db(
        self,
        hours: int,
        model_filter: str | None = None,
        upstream_filter: str | None = None,
    ) -> dict[str, Any]:
        """DB 桶 SUM 单条 SELECT 拉全量后内存归并（非 N+1）。

        用独立只读连接（mode=ro），不与 writer 线程共享 self._conn，
        避免 SQLite 跨线程并发 execute 竞态（WAL 多读单写）。
        查询前先同步 flush：把内存最新累计落盘，避免 24h/7d/30d 窗口
        读到的 DB 落后于 1h（内存 recent_events）——启动初期 5min flush
        未到时 24h 不应为空。
        """
        # 查询前同步落盘最新内存（UPSERT 幂等，无重复计数）
        try:
            self._flush_sync()
        except Exception:
            pass  # flush 失败仍继续查（可能读到旧数据）
        if self._conn is None:
            return self._query_memory_fallback(hours, model_filter, upstream_filter)
        cutoff_hour = _hour_key(_utc_now() - hours * 3600)
        cutoff_date = _day_key(_utc_now() - hours * 3600)
        try:
            # DATA_DIR 可能含空格/?/#，须 URL 编码后再拼 URI
            ro_conn = sqlite3.connect(
                f'file:{urllib.parse.quote(self.db_path, safe="/")}?mode=ro',
                uri=True,
                timeout=5.0,
            )
        except sqlite3.Error:
            return self._query_memory_fallback(hours, model_filter, upstream_filter)
        try:
            return self._query_db_with(
                ro_conn,
                hours,
                model_filter,
                upstream_filter,
                cutoff_hour,
                cutoff_date,
            )
        except (sqlite3.Error, OSError):
            return self._query_memory_fallback(hours, model_filter, upstream_filter)
        finally:
            try:
                ro_conn.close()
            except sqlite3.Error:
                pass

    def _query_db_with(
        self,
        conn: sqlite3.Connection,
        hours: int,
        model_filter: str | None,
        upstream_filter: str | None,
        cutoff_hour: str,
        cutoff_date: str,
    ) -> dict[str, Any]:
        """独立连接上执行 DB 查询（供只读连接使用）。"""
        out: dict[str, Any] = {
            'range': f'{hours}h',
            'requests': 0,
            'requests_by_status': {},
            'pii_by_type': {},
            'pii_hits': 0,
            'pii_miss': 0,
            'pii_requests': 0,
            'cred_hits': 0,
            'cred_miss': 0,
            'cred_lru_evictions': 0,
            'pii_lru_evictions': 0,
            'tokens': {},
            'audit_by_verdict': {},
            'audit_by_rule': {},
            'latency_buckets': {},
            'placeholder_prompt_injected': 0,
            'truncated_total': 0,
            'json_aware_success': 0,
            'json_leaf_fallback': 0,
            'json_full_fallback': 0,
            'latency': {'p50': None, 'p95': None, 'is_precise': False},
        }
        try:
            # hourly: 24h/7d 窗口（30d 走 daily，避免双计）
            if hours < 24 * 30:
                if upstream_filter is not None:
                    rows = conn.execute(
                        'SELECT hour, upstream, requests, requests_by_status, tokens, '
                        'latency_buckets, pii_by_type, pii_hits, pii_miss, pii_requests, '
                        'pii_lru_evictions, cred_lru_evictions '
                        'FROM hourly_agg WHERE hour >= ? AND upstream = ?',
                        (cutoff_hour, upstream_filter),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        'SELECT hour, upstream, requests, requests_by_status, tokens, '
                        'latency_buckets, pii_by_type, pii_hits, pii_miss, pii_requests, '
                        'pii_lru_evictions, cred_lru_evictions '
                        'FROM hourly_agg WHERE hour >= ?',
                        (cutoff_hour,),
                    ).fetchall()
                for (
                    _h,
                    _up,
                    requests,
                    rbs,
                    tokens,
                    buckets,
                    pii_by_type,
                    pii_hits,
                    pii_miss,
                    pii_requests,
                    pii_lru,
                    cred_lru,
                ) in rows:
                    out['requests'] += requests or 0
                    self._merge_json_counter(out['requests_by_status'], rbs)
                    self._merge_tokens(
                        out['tokens'], json.loads(tokens) if tokens else {}
                    )
                    self._merge_json_counter(out['latency_buckets'], buckets)
                    self._merge_json_counter(out['pii_by_type'], pii_by_type)
                    out['pii_hits'] += pii_hits or 0
                    out['pii_miss'] += pii_miss or 0
                    out['pii_requests'] += pii_requests or 0
                    out['pii_lru_evictions'] += pii_lru or 0
                    out['cred_lru_evictions'] += cred_lru or 0
            # daily: 30d 窗口（含扩展列）
            if hours >= 24 * 30:
                if upstream_filter is not None:
                    rows_d = conn.execute(
                        'SELECT date, upstream, pii_hits, pii_miss, pii_requests, cred_hits, cred_miss, '
                        'cred_lru_evictions, pii_lru_evictions, requests, requests_by_status, '
                        'tokens, audit_by_verdict, audit_by_rule, latency_buckets, '
                        'placeholder_prompt_injected, truncated_total, json_aware_success, '
                        'json_leaf_fallback, json_full_fallback '
                        'FROM daily_agg WHERE date >= ? AND upstream = ?',
                        (cutoff_date, upstream_filter),
                    ).fetchall()
                else:
                    rows_d = conn.execute(
                        'SELECT date, upstream, pii_hits, pii_miss, pii_requests, cred_hits, cred_miss, '
                        'cred_lru_evictions, pii_lru_evictions, requests, requests_by_status, '
                        'tokens, audit_by_verdict, audit_by_rule, latency_buckets, '
                        'placeholder_prompt_injected, truncated_total, json_aware_success, '
                        'json_leaf_fallback, json_full_fallback '
                        'FROM daily_agg WHERE date >= ?',
                        (cutoff_date,),
                    ).fetchall()
                for row in rows_d:
                    (
                        _d,
                        _up,
                        pii_hits,
                        pii_miss,
                        pii_requests,
                        cred_hits,
                        cred_miss,
                        cred_lru,
                        pii_lru,
                        requests,
                        rbs,
                        tokens,
                        abv,
                        abr,
                        buckets,
                        ppi,
                        tt,
                        jas,
                        jlf,
                        jff,
                    ) = row
                    out['requests'] += requests or 0
                    out['pii_hits'] += pii_hits or 0
                    out['pii_miss'] += pii_miss or 0
                    out['pii_requests'] += pii_requests or 0
                    out['cred_hits'] += cred_hits or 0
                    out['cred_miss'] += cred_miss or 0
                    out['cred_lru_evictions'] += cred_lru or 0
                    out['pii_lru_evictions'] += pii_lru or 0
                    self._merge_json_counter(out['requests_by_status'], rbs)
                    self._merge_tokens(
                        out['tokens'], json.loads(tokens) if tokens else {}
                    )
                    self._merge_json_counter(out['audit_by_verdict'], abv)
                    self._merge_json_counter(out['audit_by_rule'], abr)
                    self._merge_json_counter(out['latency_buckets'], buckets)
                    out['placeholder_prompt_injected'] += ppi or 0
                    out['truncated_total'] += tt or 0
                    out['json_aware_success'] += jas or 0
                    out['json_leaf_fallback'] += jlf or 0
                    out['json_full_fallback'] += jff or 0
            # p95≈ 桶 SUM 逆分位
            out['latency']['p95'] = self._percentile_from_buckets(
                out['latency_buckets'], 0.95
            )
            out['latency']['p50'] = self._percentile_from_buckets(
                out['latency_buckets'], 0.50
            )
            if model_filter:
                out['tokens'] = {
                    k: v for k, v in out['tokens'].items() if k == model_filter
                }
        except (sqlite3.Error, OSError) as e:
            logger.warning('metrics 查询失败（降级内存）: %s', e)
            raise
        return out

    def _query_memory_fallback(
        self,
        hours: int,
        model_filter: str | None = None,
        upstream_filter: str | None = None,
    ) -> dict[str, Any]:
        out: dict[str, Any] = {
            'range': f'{hours}h',
            'requests': 0,
            'requests_by_status': {},
            'pii_by_type': {},
            'pii_hits': 0,
            'pii_miss': 0,
            'pii_requests': 0,
            'cred_hits': 0,
            'cred_miss': 0,
            'cred_lru_evictions': 0,
            'pii_lru_evictions': 0,
            'tokens': {},
            'audit_by_verdict': {},
            'audit_by_rule': {},
            'latency_buckets': {},
            'placeholder_prompt_injected': 0,
            'truncated_total': 0,
            'json_aware_success': 0,
            'json_leaf_fallback': 0,
            'json_full_fallback': 0,
            'latency': {'p50': None, 'p95': None, 'is_precise': False},
        }
        for (_d, _up), d in self._daily.items():
            if upstream_filter is not None and _up != upstream_filter:
                continue
            out['requests'] += d.requests
            self._merge_json_counter(out['requests_by_status'], d.requests_by_status)
            self._merge_tokens(out['tokens'], d.tokens)
            self._merge_json_counter(out['pii_by_type'], d.pii_by_type)
            self._merge_json_counter(out['audit_by_verdict'], d.audit_by_verdict)
            self._merge_json_counter(out['audit_by_rule'], d.audit_by_rule)
            self._merge_json_counter(out['latency_buckets'], d.latency_buckets)
            out['pii_hits'] += d.pii_hits
            out['pii_miss'] += d.pii_miss
            out['pii_requests'] += d.pii_requests
            out['cred_hits'] += d.cred_hits
            out['cred_miss'] += d.cred_miss
            out['cred_lru_evictions'] += d.cred_lru_evictions
            out['pii_lru_evictions'] += d.pii_lru_evictions
            out['placeholder_prompt_injected'] += d.placeholder_prompt_injected
            out['truncated_total'] += d.truncated_total
            out['json_aware_success'] += d.json_aware_success
            out['json_leaf_fallback'] += d.json_leaf_fallback
            out['json_full_fallback'] += d.json_full_fallback
        out['latency']['p95'] = self._percentile_from_buckets(
            out['latency_buckets'], 0.95
        )
        out['latency']['p50'] = self._percentile_from_buckets(
            out['latency_buckets'], 0.50
        )
        if model_filter:
            out['tokens'] = {
                k: v for k, v in out['tokens'].items() if k == model_filter
            }
        return out

    @staticmethod
    def _merge_json_counter(target: dict[str, int], src: str | dict | None) -> None:
        if not src:
            return
        try:
            data = json.loads(src) if isinstance(src, str) else src
        except (ValueError, TypeError):
            return
        if not isinstance(data, dict):
            return
        for k, v in data.items():
            if isinstance(v, (int, float)):
                target[k] = target.get(k, 0) + int(v)

    @staticmethod
    def _percentile_from_buckets(
        buckets: dict[str, int], percentile: float
    ) -> float | None:
        """桶 SUM 逆分位取首个累计 >= p*total 的桶中位。"""
        if not buckets:
            return None
        total = sum(int(v) for v in buckets.values())
        if total <= 0:
            return None
        target = percentile * total
        cum = 0
        for k, v in sorted(
            buckets.items(),
            key=lambda kv: float(kv[0]) if kv[0] != 'inf' else float('inf'),
        ):
            cum += int(v)
            if cum >= target:
                upper = float(k)
                lower = 0.0
                if upper == float('inf'):
                    return None
                # 桶中位（等比近似）
                idx = LATENCY_BUCKETS.index(upper) if upper in LATENCY_BUCKETS else 0
                lower = LATENCY_BUCKETS[idx - 1] if idx > 0 else 0.0
                return (lower + upper) / 2
        return None

    def events(
        self,
        limit: int = 50,
        kind: str | None = None,
        upstream: str | None = None,
        model: str | None = None,
    ) -> list[dict[str, Any]]:
        """recent_events 环形缓冲视图（数据源仅 recent_events）。

        recent_events 为 append 追加的环形缓冲（deque），尾部即最新事件，
        逆序扫描早停即可取最新 limit 条，无需全量拷贝+排序（SSE 每 2s 调用）。
        """
        out: list[dict[str, Any]] = []
        for e in reversed(self.recent_events):
            if upstream and e['upstream'] != upstream:
                continue
            if model and e.get('model') != model:
                continue
            if kind and kind not in e.get('summary', ''):
                continue
            out.append(e)
            if len(out) >= limit:
                break
        return out

    # ── series 时间桶序列 ──

    def series(
        self,
        range_: str,
        *,
        model_filter: str | None = None,
        upstream_filter: str | None = None,
    ) -> dict[str, Any]:
        """时间桶序列（趋势图数据源）。

        - `1h`：recent_events 分钟桶（60 点，锁内快照防撕裂），is_precise 由 ring 覆盖决定
        - `24h`/`7d`：hourly_agg 小时桶（24/168 点）
        - `30d`：daily_agg 日桶（30 点）
        - 空桶补零；支持 model/upstream 过滤（DB 路径按桶键过滤 + tokens 内 model 近似）
        返回 `{buckets: [{ts, requests, tokens_prompt, tokens_completion, cached_read, p95, pii_requests}], is_precise}`。
        """
        now = _utc_now()
        if range_ == '1h':
            return self._series_1h(now, model_filter, upstream_filter)
        if range_ == '30d':
            return self._series_db(
                hours=24 * 30,
                bucket_s=24 * 3600,
                key_fn=_day_key,
                granularity='day',
                model_filter=model_filter,
                upstream_filter=upstream_filter,
            )
        hours = 24 if range_ == '24h' else 24 * 7
        return self._series_db(
            hours=hours,
            bucket_s=3600,
            key_fn=_hour_key,
            granularity='hour',
            model_filter=model_filter,
            upstream_filter=upstream_filter,
        )

    def _series_1h(
        self,
        now: float,
        model_filter: str | None,
        upstream_filter: str | None,
    ) -> dict[str, Any]:
        """1h 分钟桶：recent_events 锁内快照后归并。"""
        cutoff = now - 3600
        # 快照（deque list() 在 CPython GIL 下原子；series 在 executor 线程，
        # 不能用 asyncio.Lock，直接拷贝即可——append 与 list() 并发安全）
        snap = list(self.recent_events)
        buckets: list[dict[str, Any]] = []
        # 60 个分钟桶：从「当前分钟对齐」往前推 59 分钟，覆盖最近 1h
        now_min = int(now // 60) * 60
        start_min = now_min - 59 * 60
        for i in range(60):
            ts = start_min + i * 60
            buckets.append(
                {
                    'ts': ts,
                    'requests': 0,
                    'tokens_prompt': 0,
                    'tokens_completion': 0,
                    'cached_read': 0,
                    'p95': None,
                    'pii_requests': 0,
                }
            )
        lat_by_min: dict[int, list[float]] = {}
        for e in snap:
            if e['ts'] < cutoff:
                continue
            if upstream_filter is not None and e.get('upstream') != upstream_filter:
                continue
            if model_filter is not None and e.get('model') != model_filter:
                continue
            idx = int((e['ts'] - start_min) // 60)
            if not (0 <= idx < 60):
                continue
            b = buckets[idx]
            b['requests'] += 1
            if e.get('pii_found'):
                b['pii_requests'] += 1
            toks = e.get('tokens') or {}
            for _m, u in toks.items():
                if model_filter is not None and _m != model_filter:
                    continue
                b['tokens_prompt'] += u.get('prompt', 0) or 0
                b['tokens_completion'] += u.get('completion', 0) or 0
                b['cached_read'] += u.get('cached_read', 0) or 0
            lat = e.get('latency_ms')
            if lat is not None:
                lat_by_min.setdefault(idx, []).append(lat)
        for idx, lats in lat_by_min.items():
            if lats:
                buckets[idx]['p95'] = sorted(lats)[
                    min(int(0.95 * len(lats)), len(lats) - 1)
                ]
        ring = self.ring_stats(
            upstream_filter=upstream_filter, model_filter=model_filter
        )
        return {'buckets': buckets, 'is_precise': ring['is_precise']}

    def _series_db(
        self,
        *,
        hours: int,
        bucket_s: int,
        key_fn,
        granularity: str,
        model_filter: str | None,
        upstream_filter: str | None,
    ) -> dict[str, Any]:
        """DB 桶序列：独立只读连接拉全量后按时间键归并（与 _query_db 同模式）。"""
        try:
            self._flush_sync()
        except Exception:
            pass
        if self._conn is None:
            return self._series_memory(
                hours, bucket_s, key_fn, granularity, model_filter, upstream_filter
            )
        cutoff = _utc_now() - hours * 3600
        cutoff_key = key_fn(cutoff)
        try:
            ro_conn = sqlite3.connect(
                f'file:{urllib.parse.quote(self.db_path, safe="/")}?mode=ro',
                uri=True,
                timeout=5.0,
            )
        except sqlite3.Error:
            return self._series_memory(
                hours, bucket_s, key_fn, granularity, model_filter, upstream_filter
            )
        try:
            # 拉窗口内全量桶（hourly 或 daily），内存归并
            if granularity == 'hour':
                if upstream_filter is not None:
                    rows = ro_conn.execute(
                        'SELECT hour, upstream, requests, tokens, latency_buckets, pii_requests '
                        'FROM hourly_agg WHERE hour >= ? AND upstream = ?',
                        (cutoff_key, upstream_filter),
                    ).fetchall()
                else:
                    rows = ro_conn.execute(
                        'SELECT hour, upstream, requests, tokens, latency_buckets, pii_requests '
                        'FROM hourly_agg WHERE hour >= ?',
                        (cutoff_key,),
                    ).fetchall()
            else:
                if upstream_filter is not None:
                    rows = ro_conn.execute(
                        'SELECT date, upstream, requests, tokens, latency_buckets, pii_requests '
                        'FROM daily_agg WHERE date >= ? AND upstream = ?',
                        (cutoff_key, upstream_filter),
                    ).fetchall()
                else:
                    rows = ro_conn.execute(
                        'SELECT date, upstream, requests, tokens, latency_buckets, pii_requests '
                        'FROM daily_agg WHERE date >= ?',
                        (cutoff_key,),
                    ).fetchall()
            # 建桶（空桶补零）
            now = _utc_now()
            n_buckets = int(hours * 3600 // bucket_s)
            bucket_ts = [
                int((now - (n_buckets - i) * bucket_s) // bucket_s) * bucket_s
                for i in range(n_buckets)
            ]
            buckets = [
                {
                    'ts': ts,
                    'requests': 0,
                    'tokens_prompt': 0,
                    'tokens_completion': 0,
                    'cached_read': 0,
                    'p95': None,
                    'pii_requests': 0,
                }
                for ts in bucket_ts
            ]
            key_to_idx = {key_fn(ts): i for i, ts in enumerate(bucket_ts)}
            for row in rows:
                k = row[0]
                idx = key_to_idx.get(k)
                if idx is None:
                    continue
                b = buckets[idx]
                b['requests'] += row[2] or 0
                toks = json.loads(row[3]) if row[3] else {}
                for _m, u in toks.items():
                    if model_filter is not None and _m != model_filter:
                        continue
                    b['tokens_prompt'] += u.get('prompt', 0) or 0
                    b['tokens_completion'] += u.get('completion', 0) or 0
                    b['cached_read'] += u.get('cached_read', 0) or 0
                b['pii_requests'] += row[5] or 0
                lb = json.loads(row[4]) if row[4] else {}
                if lb:
                    b['p95'] = self._percentile_from_buckets(lb, 0.95)
            return {'buckets': buckets, 'is_precise': False}
        except (sqlite3.Error, OSError):
            return self._series_memory(
                hours, bucket_s, key_fn, granularity, model_filter, upstream_filter
            )
        finally:
            try:
                ro_conn.close()
            except sqlite3.Error:
                pass

    def _series_memory(
        self,
        hours: int,
        bucket_s: int,
        key_fn,
        granularity: str,
        model_filter: str | None,
        upstream_filter: str | None,
    ) -> dict[str, Any]:
        """内存 fallback：从 _daily/_hourly 归并（无 DB 时）。"""
        now = _utc_now()
        cutoff = now - hours * 3600
        n_buckets = int(hours * 3600 // bucket_s)
        bucket_ts = [
            int((now - (n_buckets - i) * bucket_s) // bucket_s) * bucket_s
            for i in range(n_buckets)
        ]
        buckets = [
            {
                'ts': ts,
                'requests': 0,
                'tokens_prompt': 0,
                'tokens_completion': 0,
                'cached_read': 0,
                'p95': None,
                'pii_requests': 0,
            }
            for ts in bucket_ts
        ]
        key_to_idx = {key_fn(ts): i for i, ts in enumerate(bucket_ts)}
        agg_map = self._daily if granularity == 'day' else self._hourly
        cutoff_key = key_fn(cutoff)
        for (_k, _up), agg in agg_map.items():
            if upstream_filter is not None and _up != upstream_filter:
                continue
            if _k < cutoff_key:
                continue
            idx = key_to_idx.get(_k)
            if idx is None:
                continue
            b = buckets[idx]
            b['requests'] += agg.requests
            for _m, u in agg.tokens.items():
                if model_filter is not None and _m != model_filter:
                    continue
                b['tokens_prompt'] += u.get('prompt', 0) or 0
                b['tokens_completion'] += u.get('completion', 0) or 0
                b['cached_read'] += u.get('cached_read', 0) or 0
            b['pii_requests'] += agg.pii_requests
            if agg.latency_buckets:
                b['p95'] = self._percentile_from_buckets(agg.latency_buckets, 0.95)
        return {'buckets': buckets, 'is_precise': False}

    # ── close ──

    async def close(self) -> None:
        """优雅关闭：cancel 定时器 + 最终 flush + 等待 executor + wal_checkpoint。"""
        if self._closed:
            return
        self._closed = True
        if self._flush_task is not None:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except (asyncio.CancelledError, Exception):
                pass
        await self.flush()
        # 等待写盘 executor 排空；shutdown 也移出 event loop（writer 卡 busy_timeout/ENOSPC 时
        # 不阻塞事件循环；shutdown(wait=True) 在后台线程完成）
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._writer_executor, self._drain_queue)

        def _shutdown_writers() -> None:
            # 两个 executor 的 shutdown(wait=True) 在后台线程执行，避免阻塞 event loop
            try:
                self._writer_executor.shutdown(wait=True)
            except RuntimeError:
                pass
            try:
                self._p95_executor.shutdown(wait=True)
            except RuntimeError:
                pass

        await loop.run_in_executor(None, _shutdown_writers)
        if self._conn is not None:
            try:
                self._conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                self._conn.commit()
                _chmod_0600(self.db_path)
            except (sqlite3.Error, OSError):
                logger.warning('wal_checkpoint 失败', exc_info=True)
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None
        # executor shutdown 已在 _shutdown_writers（run_in_executor 后台）完成

    def _drain_queue(self) -> None:
        while True:
            try:
                s = self._queue.get_nowait()
            except queue.Empty:
                break
            self._write_flush(s)

    # ── 线程安全入口（供锁外同步路径调用）──

    def _sync_fail_open(self, fn: Callable[[], None]) -> None:
        """热路径埋点 fail-open：观测异常绝不阻断业务（脱敏/审计/注册）。"""
        try:
            fn()
        except Exception as e:
            logger.debug('metrics 同步埋点失败（fail-open）: %s', e)

    def incr_sync_lru(self, cred: int = 0, pii: int = 0) -> None:
        """同步 LRU 淘汰递增（无事件循环环境；直接写内存累计）。"""

        def _do() -> None:
            now = _utc_now()
            day = _day_key(now)
            hour = _hour_key(now)
            # 事件循环单线程中同步调用不会并发 → 直接改（无 await）
            d = self._daily.setdefault((day, 'other'), _DailyAgg())
            h = self._hourly.setdefault((hour, 'other'), _HourlyAgg())
            d.cred_lru_evictions += cred
            d.pii_lru_evictions += pii
            h.cred_lru_evictions += cred
            h.pii_lru_evictions += pii

        self._sync_fail_open(_do)

    def incr_sync_pii_cache(self, hit: int = 0, miss: int = 0) -> None:
        """同步 pii_cache_hit/miss 递增（register 钩子调用）。"""

        def _do() -> None:
            now = _utc_now()
            day = _day_key(now)
            hour = _hour_key(now)
            d = self._daily.setdefault((day, 'other'), _DailyAgg())
            h = self._hourly.setdefault((hour, 'other'), _HourlyAgg())
            d.pii_hits += hit
            d.pii_miss += miss
            h.pii_hits += hit
            h.pii_miss += miss

        self._sync_fail_open(_do)

    def incr_sync_pii_detected(self, by_kind: dict[str, int]) -> None:
        """同步 pii_detected_total{kind} 递增（scan 钩子调用，sanitize 后）。"""

        def _do() -> None:
            now = _utc_now()
            day = _day_key(now)
            hour = _hour_key(now)
            d = self._daily.setdefault((day, 'other'), _DailyAgg())
            h = self._hourly.setdefault((hour, 'other'), _HourlyAgg())
            for kind, n in by_kind.items():
                d.pii_by_type[kind] = d.pii_by_type.get(kind, 0) + n
                h.pii_by_type[kind] = h.pii_by_type.get(kind, 0) + n

        self._sync_fail_open(_do)

    def incr_sync_placeholder_injected(self) -> None:
        """同步 placeholder_prompt_injected_total 递增（注入发生与否）。"""

        def _do() -> None:
            now = _utc_now()
            day = _day_key(now)
            d = self._daily.setdefault((day, 'other'), _DailyAgg())
            d.placeholder_prompt_injected += 1

        self._sync_fail_open(_do)

    def incr_sync_cred(self, hit: int = 0, miss: int = 0) -> None:
        """同步 cred_hit/miss 递增（_register_secret 钩子调用）。"""

        def _do() -> None:
            now = _utc_now()
            day = _day_key(now)
            d = self._daily.setdefault((day, 'other'), _DailyAgg())
            d.cred_hits += hit
            d.cred_miss += miss

        self._sync_fail_open(_do)

    def incr_sync_audit(self, verdict: str, rule: str) -> None:
        """同步 audit_by_verdict / audit_by_rule 递增（audit_tool_call 钩子）。"""

        def _do() -> None:
            now = _utc_now()
            day = _day_key(now)
            d = self._daily.setdefault((day, 'other'), _DailyAgg())
            d.audit_by_verdict[verdict] = d.audit_by_verdict.get(verdict, 0) + 1
            if rule:
                d.audit_by_rule[rule] = d.audit_by_rule.get(rule, 0) + 1

        self._sync_fail_open(_do)

    def incr_sync_audit_log_write_fail(self) -> None:
        """同步 audit_log_write_fail 计数（内存 gauge，不进聚合）。"""

        def _do() -> None:
            self.counters['audit_log_write_fail'] = (
                self.counters.get('audit_log_write_fail', 0) + 1
            )

        self._sync_fail_open(_do)

    def incr_sync_audit_approval(self, result: str) -> None:
        """同步 audit_approval_result 分布（内存计数，重启归零）。"""

        def _do() -> None:
            cur = self.counters.setdefault('audit_approval_result', {})
            cur[result] = cur.get(result, 0) + 1

        self._sync_fail_open(_do)


_collector_singleton: MetricsCollector | None = None
_collector_lock = threading.Lock()


# ── per-request PII/cred 计数（ContextVar，事件详情 hit/miss 数据源）──
# _pii.py/_token.py 的同步钩子在请求上下文内调用，通过本 ContextVar 累计
# 当前请求的 pii_cache hit/miss 与 cred hit/miss；incr_event 时读取并写入
# recent_events，使事件详情的 hit/miss 不再是恒 0。
_req_pii_var = contextvars.ContextVar(
    '_req_pii_var', default=None
)  # dict: {'pii_hits':0,'pii_miss':0,'cred_hits':0,'cred_miss':0}


def _req_pii_ctx() -> dict[str, int]:
    """获取当前请求的 per-request 计数（无则创建并 set）。"""
    d = _req_pii_var.get()
    if d is None:
        d = {'pii_hits': 0, 'pii_miss': 0, 'cred_hits': 0, 'cred_miss': 0}
        _req_pii_var.set(d)
    return d


def accumulate_pii_cache(hit: int = 0, miss: int = 0) -> None:
    """当前请求的 pii_cache hit/miss 累计（_token.py register 钩子调用）。"""
    try:
        d = _req_pii_var.get()
        if d is not None:
            d['pii_hits'] += hit
            d['pii_miss'] += miss
    except Exception:
        pass  # fail-open：埋点绝不阻断业务


def accumulate_cred(hit: int = 0, miss: int = 0) -> None:
    """当前请求的 cred hit/miss 累计（_token.py _register_secret 钩子调用）。"""
    try:
        d = _req_pii_var.get()
        if d is not None:
            d['cred_hits'] += hit
            d['cred_miss'] += miss
    except Exception:
        pass


def reset_req_pii_ctx() -> None:
    """请求结束时清理 per-request 计数（handler finally 调用）。"""
    try:
        _req_pii_var.set(None)  # type: ignore[arg-type]
    except Exception:
        pass


def get_collector(data_dir: str | None = None) -> MetricsCollector:
    """模块级单例（DATA_DIR 单一来源 from proxy import DATA_DIR）。"""
    global _collector_singleton
    if _collector_singleton is None:
        with _collector_lock:
            if _collector_singleton is None:
                _collector_singleton = MetricsCollector(data_dir or os.getcwd())
    return _collector_singleton
