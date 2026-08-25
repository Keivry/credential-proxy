## Purpose

为 credential-proxy 提供不含明文的嵌入式可观测性采集与聚合，覆盖 PII/凭据脱敏计数与命中率、上游转发与延迟、token usage、审计处置计数与 LRU/守门状态的统一采集与日聚合落盘。

## ADDED Requirements

### Requirement: 脱敏与缓存指标采集

系统 SHALL 在 PII 检测命中、凭据注册/还原、LRU 淘汰路径采集计数：PII 按 `kind`（内置 phone/id_card/email/bank_card/ipv4/ipv6/api_key + 自定义正则名 + 字典类型）分两类计数——`pii_detected_total{kind}`（`PiiDetector.scan` 检测到即 +1）与 `pii_cache_hit/miss`（`GlobalPiiTokens.register` 命中已注册复用即 `hit`、新建即 `miss`；响应侧 `resp_p2t` 还原不参与 `pii_cache_*` 计数）及 `pii_lru_evictions`（`while len(table_p2t)>PII_MAX_ENTRIES: popitem(last=False)` 淘汰时 +1，两表 `pii_p2t/resp_p2t` 各自触发均 +1，暴露到 `/_admin/metrics` 与 `health` 含 `last_dropped_ts`），凭据按 `cred_hit/cred_miss`（`_register_secret` 新建与 `_redact` 快照命中均计 `hit`，按请求 `out!=in` 计 1 而非替换次数）与 `cred_lru_evictions`（`len(pwd_to_token)>=MAX_TOKEN_ENTRIES` 分支内 `next(iter(pwd_to_token))` 取最老并 `pop(oldest)` 时 +1，文案旧称 `popitem(last=False)` 已对齐真代码）计数；自定义正则名 SHALL 经集中 `sanitize_kind` 消毒（长度 >32、含 `__`、含 `\x00`、或经大小写归一后不在内置 7 种 + 自定义模式白名单 → 归 `custom_other`，防 label 基数爆炸，`audit_by_rule` 存 `reason` 非 `pattern`）；所有计数 SHALL 可按聚合窗口查询且不含明文 PII（仅 `kind` 与 `[REDACTED:<kind>]` 形态，摘要经 `redact_summary(raw,120)` 先脱敏后 `truncate(120)` 单一路径）。

#### Scenario: PII 命中按类型计数

- **WHEN** 同值 `phone` 连续两次请求（第一次新建、第二次复用）且另有一请求命中 `email` 新值
- **THEN** 指标中 `pii_detected_total{phone}=2, pii_cache_miss+1, pii_cache_hit+1` 且 `pii_detected_total{email}=1`，总数可对账

#### Scenario: 凭据 LRU 淘汰可观测

- **WHEN** 凭据映射 `pwd_to_token` 因达到 `MAX_TOKEN_ENTRIES` 触发 `next(iter(pwd_to_token))` 取最老并 `pop(oldest)` 淘汰（旧文案 `popitem(last=False)` 已对齐真代码）
- **THEN** 指标中 `cred_lru_evictions` 递增且总数可查询；PII 分表淘汰同理 `pii_lru_evictions` 递增

#### Scenario: 指标不含明文

- **WHEN** 查询任意指标或事件摘要
- **THEN** 返回中不含原始 PII 明文，仅含 `kind`、`count`、`[REDACTED:<kind>]` 占位预览与脱敏后摘要（`redact_summary` 单一路径验证：`120+64` 长 `sk-` 注入后 `recent_events` 仍无明文残留）

#### Scenario: 自定义正则名基数受控

- **WHEN** 通过 `PII_CUSTOM_PATTERNS` 注入超长/含 `__` 的自定义名
- **THEN** 对应计数归入 `custom_other`，`pii_by_type` 标签数不随注入膨胀

### Requirement: 上游与 Token 指标采集

系统 SHALL 按上游 `port` 主键维度采集（`tail/stream` 为事件维度不进主键；非对话如 `/v1/models` 计入 `requests_total` 但 `upstream` 分组归 `other`，共享 `is_chat_tail` 判定 `chat/completions|v1/messages|v1/responses`）：`requests_total{status}`（每条请求计 1，上游重试不计多次，计数紧贴替换/转发的同一回调内**单锁批递增且锁内禁 `await`**——先锁外收集 `delta` 再 `async with lock` 批递增同步段 <20µs）、`upstream_latency`（`1h` 的 p50/p95 由 `recent_events` 的 `latency_ms` 现场 `sorted` 精确计算并置于 `asyncio.to_thread` 独立于写盘单 worker（防排队），低流量/高 TPS（50 RPS+ 时 1h 永 `≈` 属预期）时标注 `≈` 并返回 `ring_coverage_s/is_precise`（`is_precise=(now-oldest_ts)>=3600 and len>=100`，`len==0` 时 `p95=None`），`24h/7d/30d` 的 p95 由对应 `latency_buckets`（12 桶 `LATENCY_BUCKETS=[10,25,50,100,200,400,800,1500,3000,5000,10000,Inf] ms` 桶中位最差 28% @[800,1500)）近似并标注 `≈`）、首字节时间 `ttft`、`bytes_in/out`、空体守门注入次数 `empty_guarded`（流式 `bytes_written==0 && 200` 与非流式 `not resp_text.strip() && 200` 两条路径均 +1）、token usage（归一 OpenAI/Anthropic/Responses 的 `prompt/completion/total`，有 `usage` 则记无则记 `unknown` 不估算）与客户端提前断连 `client_gone` + `exception`（统一 `try/finally` + `except (ClientConnectionError, ServerDisconnectedError, TimeoutError, SSE_CLIENT_GONE)` 钩子计 `client_gone` 与对应 `status` 含 `exception` 重试不计多次）；流式与非流式两条响应路径 SHALL 均埋点（非流式 `upstream_resp.read()` 分支也记 `requests_total/latency/bytes`，查询 `SELECT ... WHERE hour>=?` 单条拉全量后内存分组求和避免 N+1）。

#### Scenario: 上游分流可归因

- **WHEN** 同一时段内 `LLM_8878` 与 `LLM_8879` 各处理若干请求
- **THEN** 按 `upstream` 分组的 `requests_total` 与 `tokens` 能分别归因且合计等于总量

#### Scenario: 空体守门注入可计数

- **WHEN** `bytes_written == 0 && upstream.status == 200` 触发守门注入
- **THEN** 对应上游的 `empty_guarded` 计数 +1 且可在大盘中看到

#### Scenario: Token 缺失不估算

- **WHEN** 上游流式响应未携带 `usage`（未发 `stream_options.include_usage`）
- **THEN** 该请求的 tokens 记为 `unknown`，不做本地分词估算，聚合中单独列计数

#### Scenario: 非流式路径同样计数

- **WHEN** 上游返回非流式响应（`upstream_resp.read()` 分支）
- **THEN** 该请求仍计入 `requests_total{status}`、`latency`、`bytes_in/out`，聚合中可见

### Requirement: 审计处置计数

系统 SHALL 采集审计 `audit_tool_call` 的处置 `verdict`（`allow/deny/block/approve_pending/approved/rejected/expired`）计数与 `rule` 命中分布，以及 `audit_log_write_fail` 计数；`audit_pending_total` 与 `audit_hold_overflows` 为内存 gauge 瞬态计数（重启归零，`health` 标注“瞬态”）SHALL 暴露到 `GET /_admin/health`（不进 `daily_agg/hourly_agg` 冷聚合）；`/_admin/metrics` SHALL 能按窗口返回 `audit_by_verdict/audit_by_rule` 分布。

#### Scenario: 阻断可计数

- **WHEN** 某请求命中 `rm -rf` 危险模式被 `block` 处置
- **THEN** `audit_by_verdict.block +1` 且 `audit_by_rule['危险删除'] +1`

#### Scenario: 写失败可观测

- **WHEN** `audit.log` 连续写失败
- **THEN** 指标中 `audit_log_write_fail` 递增且可在 `health` 中提示

### Requirement: 聚合与窗口化查询

系统 SHALL 维护进程级内存聚合（`recent_events: deque(10000)` 每条含 `latency_ms`，单锁批递增且**锁内禁 `await`**（先锁外收集 `delta` 再 `async with lock` <20µs，用 `asyncio.Lock` 保护，`p95` 计算置 `asyncio.to_thread` 独立于写盘单 worker 并返回 `ring_coverage_s/is_precise`（`is_precise=(now-oldest_ts)>=3600 and len>=100`），`len==0` 时 `p95=None`；延迟分桶 `LATENCY_BUCKETS=[10,25,50,100,200,400,800,1500,3000,5000,10000,Inf] ms` 固定 12 桶，`metrics_bucket(latency_ms)` 命中 `+1`，聚合后桶 `SUM` 单条 `SELECT ... WHERE hour>=?` 拉全量后逆分位取首个累计 `>=0.95*total` 的桶中位作为 `p95≈`（最差 28% @[800,1500) 桶中位））与 `DATA_DIR/metrics.sqlite` WAL 双表：`daily_agg(date TEXT, upstream TEXT, pii_by_type JSON, pii_hits INT, pii_miss INT, cred_hits INT, cred_miss INT, cred_lru_evictions INT, pii_lru_evictions INT, requests INT, requests_by_status JSON, tokens JSON, audit_by_verdict JSON, audit_by_rule JSON, latency_buckets JSON, PRIMARY KEY(date, upstream))` 30天滚动（15 列完整）+ `hourly_agg(hour TEXT, upstream TEXT, requests INT, requests_by_status JSON, tokens JSON, latency_buckets JSON, pii_by_type JSON, pii_lru_evictions INT, cred_lru_evictions INT, PRIMARY KEY(hour, upstream))` 7天滑动小时聚合（8 列轻量子集，`pii_hits/miss`/`cred`/`audit` 仅日表）；每 5min 原子快照覆盖式 UPSERT（`INSERT ... ON CONFLICT DO UPDATE SET col=excluded.col` 覆盖，累计快照直接覆盖，单写者串行避免 `col+excluded.col` 的持续双计；落盘用有界 `asyncio.Queue(maxsize=5)` 单写者 `ThreadPoolExecutor(max_workers=1, thread_name_prefix="metrics-writer")` 串行，深拷贝 `snapshot={k: dict(v) if isinstance(v,dict) else v}+list(deque)` 防撕裂，`QueueFull` 时 `get_nowait` 丢最老 + `logger.warning`，`dropped_snapshots` + `last_dropped_ts` 计入 `health`）+ 优雅关闭显式 `await collector.close()`（cancel 定时器 + 最终 flush + 等待 executor + `PRAGMA wal_checkpoint(TRUNCATE)` + 重 `chmod 0600`，`proxy.py` 的 `shutdown` 在 `runner.cleanup` 前 `await collector.close()`）；`PRAGMA journal_mode=WAL` + `busy_timeout=5000` + `synchronous=NORMAL` + `wal_autocheckpoint=1000` + `PRAGMA user_version=1`，`CREATE INDEX idx_daily_agg_date, idx_hourly_agg_hour`，文件创建前 `os.umask(0o077)` 或 `open; chmod` 紧邻，文件与 `-wal`/`-shm` 均 `0600` 且 `wal_checkpoint` 后重 `chmod 0600`；所有 `date`/`hour` 统一 **UTC ISO**（`date=%Y-%m-%d`、`hour=%Y-%m-%dT%H:00:00Z`，`datetime.now(timezone.utc)` 生成），滚动清理同 TZ（Python 计算 `cutoff_date/cutoff_hour` 传入 `WHERE date < ?` / `WHERE hour < ?`，不依赖 SQLite `date('now')`）。`GET /_admin/metrics?range=1h|24h|7d|30d` SHALL 按窗口返回聚合（`1h` 走内存 ring 精确分位（含 `is_precise` + `≈` 语义，高 TPS 50 RPS+ 永 `≈` 属预期）、`24h/7d` 走 `hourly_agg`、`30d` 走 `daily_agg` 的 `latency_buckets` 单条 SQL 求和近似并标 `≈`，`requests_by_status` 同窗口 `SUM(JSON)` 归并并标 `≈`），缺失文件时自动建表且不报错（空表 `?range=30d` 返 `{requests:0, buckets:[0*12]}` 不 500，`ring_len=0` 时 `p95=None`）；`metrics.sqlite` 不存在时启动期 `PRAGMA user_version` 建表，`synchronous=NORMAL` 正常退出丢 0/`kill -9`/断电丢 ≤5min+WAL 未 checkpoint 页已在文档明示（含 12 桶误差表）。

#### Scenario: 窗口化查询

- **WHEN** 查询 `?range=1h|24h|7d|30d`
- **THEN** 分别返回对应窗口的聚合（`1h` 精确标 `1h精确`（`is_precise=true` 仅当 `now-oldest>=3600 and len>=100`，低流量 `len<100` 或高 TPS 50 RPS+ 时标 `≈`）、`24h≈`/`7d≈`/`30d≈` 均为桶中位 `≈` 最差 28%）；`1h` 的 p95 与 ring 现场 `sorted(latency_ms)` 一致且返回 `is_precise` + `ring_coverage_s`

#### Scenario: 自动建表与滚动

- **WHEN** 首次启动且 `metrics.sqlite` 不存在或超过 30/7 天数据存在
- **THEN** 自动建表（WAL+索引+`user_version=1`）且老于阈值的 `date/hour` 行被清理，查询不受影响；`metrics.sqlite` 与 `-wal`/`-shm` 权限为 `0600`

#### Scenario: 关闭时数据不丢

- **WHEN** 进程收到 SIGTERM/正常关闭（含 `llm-proxy-only` / `credential-proxy-only` 的 `SIGTERM`，`proxy.py` 在 `runner.cleanup` 前 `await collector.close()`）
- **THEN** `collector.close()` 完成最终 flush（含 `cancel 定时器 + 最终 flush + 等待 executor + wal_checkpoint(TRUNCATE) + 重 chmod 0600`）后退出，最近 5min 快照不丢失（正常退出丢 0，`kill -9` 丢 ≤5min+WAL 未 checkpoint 页）
