## MODIFIED Requirements

### Requirement: 上游与 Token 指标采集

系统 SHALL 按上游 `port` 主键维度采集（`tail/stream` 为事件维度不进主键；**仅对话端点计入统计——`is_chat_tail` 判定 `chat/completions|v1/messages|v1/responses` 三种端点，非对话请求（如 `/v1/models`、`/v1/embeddings` 等）SHALL 完全不计入 `requests_total`/`latency`/`bytes_in/out`/`tokens`/脱敏计数，也不进入 `recent_events` 事件流与 `daily_agg`/`hourly_agg` 聚合（v0.9.34 及之前计入 `requests_total` 并归 `other` 的口径废弃）**，共享 `is_chat_tail` 判定）：`requests_total{status}`（每条请求计 1，上游重试不计多次（重试次数首版不单独暴露，二期可加 `upstream_retry_total`），计数紧贴替换/转发的同一回调内**单锁批递增且锁内禁 `await`**——先锁外收集 `delta` 再 `async with lock` 批递增同步段 <20µs/拷贝段 100~400µs；口径对照：`pii_detected_total` 按次、`pii_cache_hit/miss` 按值、`cred_hit/miss` 按请求 `out!=in` 计 1，不混用）、`upstream_latency`（`1h` 的 p50/p95 由 `recent_events` 的 `latency_ms` 现场 `sorted` 精确计算并置于独立专用 `ThreadPoolExecutor(max_workers=1, thread_name_prefix="p95-worker")`（或等效隔离的 `asyncio.to_thread` 专用池）独立于 `metrics-writer` 单 worker（防排队），低流量/高 TPS（50 RPS+ 时 1h 永 `≈` 属预期）时标注 `≈` 并返回 `ring_coverage_s/is_precise`（`is_precise=(now-oldest_ts)>=3600 and len>=100`，`len==0` 时 `p95=None`），`24h/7d/30d` 的 p95 由对应 `latency_buckets`（12 桶 `LATENCY_BUCKETS=[10,25,50,100,200,400,800,1500,3000,5000,10000,Inf] ms` 桶中位最差约30.4% @[800,1500)（等比约33%））近似并标注 `≈`）、首字节时间 `ttft`、`bytes_in/out`、空体守门注入次数 `empty_guarded`（流式 `bytes_written==0 && 200` 与非流式 `not resp_text.strip() && 200` 两条路径均 +1；**v0.9.14 起非流式 `_is_invalid_json` 判定的非 JSON 响应亦转 502，该场景单列 `invalid_json_guarded` 不计入 `empty_guarded`**）、token usage（归一 OpenAI/Anthropic/Responses 的 `prompt/completion/total` **及缓存命中维度**，有 `usage` 则记无则记 `unknown` 不估算；**当前实现仅透传上游 `usage` 字段无解析逻辑，本 change 需新增提取：非流式 `upstream_resp.read()` 分支从 body JSON 提取，流式从 `stream_options.include_usage` 末块或 `usage` delta 聚合**。**缓存命中 token SHALL 归一进 `tokens JSON`**：统一字段 `{prompt, completion, total, input, output, cached_read, cached_write, unknown}`——`cached_read`（缓存命中，按折扣价计费）映射：OpenAI Chat `usage.prompt_tokens_details.cached_tokens` / Anthropic `usage.cache_read_input_tokens` / Responses `usage.input_tokens_details.cached_tokens`；`cached_write`（缓存写入）仅 Anthropic `usage.cache_creation_input_tokens` 有，OpenAI/Responses 无则 `0` 或缺省；无 usage 或字段缺失时该请求 tokens 记 `unknown` 不估算）与客户端提前断连 `client_gone` + `exception`（统一 `try/finally` + `except (ClientConnectionError, ServerDisconnectedError, TimeoutError, SSE_CLIENT_GONE)` 钩子计 `client_gone` 与对应 `status` 含 `exception` 重试不计多次）；流式与非流式两条响应路径 SHALL 均埋点（非流式 `upstream_resp.read()` 分支也记 `requests_total/latency/bytes`，查询 `SELECT ... WHERE hour>=?` 单条拉全量后内存分组求和避免 N+1）。**流式双路径均埋点**：`_llm.py` handler 内 `is_chat_tail(tail) && (active_t2p || _pii_active() || audit_enabled())` 分流 slow 链（JSON-aware 流式还原）与 fast 链（`active_t2p==0` 且无 PII/审计时整行透传，v0.9.24 起为默认热路径），`requests_total/l... [truncated]

#### Scenario: 上游分流可归因

- **WHEN** 同一时段内 `LLM_8878` 与 `LLM_8879` 各处理若干请求
- **THEN** 按 `upstream` 分组的 `requests_total` 与 `tokens` 能分别归因且合计等于总量

#### Scenario: 空体守门注入可计数

- **WHEN** `bytes_written == 0 && upstream.status == 200` 触发守门注入
- **THEN** 对应上游的 `empty_guarded` 计数 +1 且可在大盘中看到

#### Scenario: Token 缺失不估算

- **WHEN** 上游流式响应未携带 `usage`（未发 `stream_options.include_usage`）
- **THEN** 该请求的 tokens 记为 `unknown`，不做本地分词估算，聚合中单独列计数

#### Scenario: 缓存命中 token 可核算

- **WHEN** 上游返回 `usage` 且含缓存命中字段（OpenAI Chat `usage.prompt_tokens_details.cached_tokens` / Anthropic `usage.cache_read_input_tokens` / Responses `usage.input_tokens_details.cached_tokens`）
- **THEN** 该请求 `tokens JSON` 的 `cached_read` 反映缓存命中 token 数（成本核算关键：缓存命中输入 token 按折扣价计费），Anthropic 的 `cache_creation_input_tokens` 归一进 `cached_write`（写入缓存非命中，成本按写入价计费区别于命中折扣价）；无缓存命中时 `cached_read` 为 `0`；`/_admin/metrics` 与大盘可分别查询输入/输出/缓存命中 token 合计

#### Scenario: normalize_usage 归一口径

- **WHEN** `_metrics.py: normalize_usage(obj, protocol)` 收到三协议 usage（OpenAI `prompt_tokens/completion_tokens/total_tokens`、Anthropic/Responses `input_tokens/output_tokens`，含 `prompt_tokens_details.cached_tokens`/`cache_read_input_tokens`/`input_tokens_details.cached_tokens` 与 Anthropic `cache_creation_input_tokens`）
- **THEN** 输出统一 8 字段 `{prompt, completion, total, input, output, cached_read, cached_write, unknown}`；`total = obj.get("total_tokens") or obj.get("total") or (input+output)`（Anthropic/Responses 无 `total_tokens`，缺失求和，两值均缺 `unknown`）；`cached_read = (obj.get("prompt_tokens_details") or{}).get("cached_tokens", 0)`（`prompt_tokens_details: null` 时返回 `0` 不抛异常）；OpenAI/Responses 无 `cached_write` 归 `0`

#### Scenario: 流式注入协议限定

- **WHEN** 流式请求需注入 `stream_options: {"include_usage": true}`
- **THEN** 注入仅限 OpenAI Chat/Responses 且 `is_stream==true`，Anthropic `/v1/messages` 严禁注入（严格 JSON Schema 携带 `stream_options` 即 `400 invalid_request_error: extra field`）；注入用 `setdefault` 不覆盖客户端已设的 `include_usage`；非 JSON 请求体不注入原样透传

#### Scenario: tokens JSON 按 model 分桶

- **WHEN** 同一上游 `port` 内多个不同 `model`（`gpt-4o`/`gpt-4o-mini`）的请求发生
- **THEN** `tokens JSON` 内部按 model 分桶 `{"gpt-4o": {"prompt":..,"cached_read":..}, "gpt-4o-mini": {...}}`（无 model 记 `unknown_model`），主键仍 `(date, upstream)` 不新增列，`/_admin/metrics` 可按 model 归因成本

#### Scenario: 非流式路径同样计数

- **WHEN** 上游返回非流式响应（`upstream_resp.read()` 分支）
- **THEN** 该请求仍计入 `requests_total{status}`、`latency`、`bytes_in/out`，聚合中可见

#### Scenario: 流式双路径均计数

- **WHEN** 流式响应分别走 slow 链（`active_t2p>0` 或 PII/审计启用，JSON-aware 还原）与 fast 链（`active_t2p==0` 且无 PII/审计，整行透传）
- **THEN** 两条路径的请求均计入 `requests_total{status}`/`latency`/`bytes_in/out`，`sse_events` 按 SSE 事件块（`event:`/`id:`+`data:` 同块计 1）计数且合计等于两链事件块总数

#### Scenario: 合成终止事件单列

- **WHEN** 流未收到终止事件（`seen_global_terminal==false`）且 `bytes_written>0`，触发 `_build_truncated_event*`/`_fast_truncated` 注入合成终止
- **THEN** `truncated_total` 递增且不计入 `sse_events`；`empty_guarded` 仅在实际空体守门注入（`bytes_written==0 && 200`）时递增

#### Scenario: JSON-aware 三态可观测

- **WHEN** 脱敏/还原走 JSON-aware 全链路（orjson），部分叶子失败走叶子级最小回退，整体失败走全量回退
- **THEN** `json_aware_success_total`/`json_leaf_fallback_total`/`json_full_fallback_total` 分别递增且合计等于请求数；旧的 `plain str.replace` 度量口径不再使用

### Requirement: 聚合与窗口化查询

系统 SHALL 维护进程级内存聚合（`recent_events: deque(10000)` 每条含 `latency_ms`，单锁批递增且**锁内禁 `await`**（先锁外收集 `delta` 再 `async with lock` <20µs，用 `asyncio.Lock` 保护，`p95` 计算置独立专用 `ThreadPoolExecutor(max_workers=1, thread_name_prefix="p95-worker")`（或等效隔离专用池）独立于 `metrics-writer` 并返回 `ring_coverage_s/is_precise`（`is_precise=(now-oldest_ts)>=3600 and len>=100`），`len==0` 时 `p95=None`；延迟分桶 `LATENCY_BUCKETS=[10,25,50,100,200,400,800,1500,3000,5000,10000,Inf] ms` 固定 12 桶，`metrics_bucket(latency_ms)` 二分命中首个 `>=latency` 桶 `+1`，聚合后桶 `SUM` 单条 `SELECT ... WHERE hour>=?` 拉全量后逆分位取首个累计 `>=0.95*total` 的桶中位作为 `p95≈`（最差约30.4% @[800,1500)（等比约33%） 桶中位））与 `DATA_DIR/metrics.sqlite` WAL 双表（磁盘满 `ENOSPC` 降级内存-only（捕获 `OSError as e if e.errno==28` 或 `sqlite3.OperationalError` 含 `disk I/O error`/`database or disk is full`，统一置 `health.sqlite_ok=false` + `logger.error`；恢复后仅从当前累计续写，不回补） 且 `health.sqlite_ok=false`）：`daily_agg(date TEXT, upstream TEXT, pii_by_type JSON, pii_hits INT, pii_miss INT, cred_hits INT, cred_miss INT, cred_lru_evictions INT, pii_lru_evictions INT, requests INT, requests_by_status JSON, tokens JSON, audit_by_verdict JSON, audit_by_rule JSON, latency_buckets JSON, placeholder_prompt_injected INT, truncated_total INT, json_aware_success INT, json_leaf_fallback INT, json_full_fallback INT, PRIMARY KEY(date, upstream))` 30天滚动（15 基础列 + 5 扩展列，`audit_by_verdict` 值域为 `allow/deny` 两值；`placeholder_prompt_injected`/`truncated_total`/`json_*` 三态为 v0.9.16-25 新基线指标） + `hourly_agg(hour TEXT, upstream TEXT, requests INT, requests_by_status JSON, tokens JSON, latency_buckets JSON, pii_by_type JSON, pii_lru_evictions INT, cred_lru_evictions INT, PRIMARY KEY(hour, upstream))` 7天滑动小时聚合（9 列轻量子集，`pii_hits/miss`/`cred`/`audit`/`placeholder_prompt_injected`/`truncated_total`/`json_*` 仅日表保留）；每 5min 原子快照覆盖式 UPSERT（`INSERT ... ON CONFLICT DO UPDATE SET col=excluded.col` 覆盖，累计快照直接覆盖，单写者串行避免 `col+excluded.col` 的持续双计；落盘用有界 `queue.Queue(maxsize=5)`（线程安全，替代 `asyncio.Queue` 跨线程不安全，或经 `loop.call_soon_threadsafe` 入队） 单写者 `ThreadPoolExecutor(max_workers=1, thread_name_prefix="metrics-writer")` 串行，深拷贝 `snapshot={k: dict(v) if isinstance(v,dict) else v}+list(deque)` 防撕裂（拷贝 1~2MB 每 5min，锁内 100~400µs 可接受），`QueueFull` 时 `get_nowait` 丢最老再入队并计 `dropped_snapshots` + `first_dropped_ts/last_dropped_ts`（覆盖式快照丢弃不丢数（同窗口内不丢数，跨hour/date边界可能丢增量，需按窗口键落盘旧键/清零当前桶）——累计快照下一周期覆盖，`logger.warning`））+ 优雅关闭显式 `await collector.close()`（cancel 定时器 + 最终 flush + 等待 executor + `PRAGMA wal_checkpoint(TRUNCATE)` + 重 `chmod 0600`，`proxy.py` 的 `shutdown` 在 `runner.cleanup` 前 `await collector.close()`）；`PRAGMA journal_mode=WAL` + `busy_timeout=5000` + `synchronous=NORMAL` + `wal_autocheckpoint=1000` + `PRAGMA user_version=1`，`CREATE INDEX idx_daily_agg_date, idx_hourly_agg_hour`，文件创建前 `os.umask(0o077)` 紧邻或 `open; chmod 0600` 紧邻且 `finally` 恢复 `umask`，文件与 `-wal`/`-shm` 均 `0600`；滚动 `DELETE` 不做 per-flush `VACUUM`，碎片化靠月度 `VACUUM` 或 `auto_vacuum=INCREMENTAL` 二期可选 且 `wal_checkpoint` 后重 `chmod 0600`；所有 `date`/`hour` 统一 **UTC ISO**（`date=%Y-%m-%d`、`hour=%Y-%m-%dT%H:00:00Z`，`datetime.now(timezone.utc)` 生成），滚动清理同 TZ（Python 计算 `cutoff_date/cutoff_hour` 传入 `WHERE date < ?` / `WHERE hour < ?`，不依赖 SQLite `date('now')`）。`GET /_admin/metrics?range=1h|24h|7d|30d` SHALL 按窗口返回聚合（`1h` 走内存 ring 精确分位（含 `is_precise` + `≈` 语义，高 TPS 50 RPS+ 永 `≈` 属预期）、`24h/7d` 走 `hourly_agg`、`30d` 走 `daily_agg` 的 `latency_buckets` 单条 SQL 求和近似并标 `≈`，`requests_by_status` 同窗口 `SUM(JSON)` 归并并标 `≈`），缺失文件时自动建表且不报错（空表 `?range=30d` 返 `{requests:0, buckets:[0*12]}` 不 500，`ring_len=0` 时 `p95=None`）；`metrics.sqlite` 不存在时启动期 `PRAGMA user_version` 建表，`synchronous=NORMAL` 正常退出丢 0/`kill -9`/断电丢 ≤5min+WAL 未 checkpoint 页已在文档明示（含 12 桶误差表）。

#### Scenario: 窗口化查询

- **WHEN** 查询 `?range=1h|24h|7d|30d`（可选 `&model=<m>&upstream=<u>`）
- **THEN** 分别返回对应窗口的聚合；`upstream` 过滤按 `(date/hour, upstream)` 键精确归并，`model` 过滤对 1h 精确、对 24h/7d/30d 按 tokens JSON 键存在性近似（聚合无按 model 分桶列）（`1h` 精确标 `1h精确`（`is_precise=true` 仅当 `now-oldest>=3600 and len>=100`，低流量 `len<100` 或高 TPS 50 RPS+ 时标 `≈`）、`24h≈`/`7d≈`/`30d≈` 均为桶中位 `≈` 最差 约30.4%）；`1h` 的 p95 与 ring 现场 `sorted(latency_ms)` 一致且返回 `is_precise` + `ring_coverage_s`

#### Scenario: 自动建表与滚动

- **WHEN** 首次启动且 `metrics.sqlite` 不存在或超过 30/7 天数据存在
- **THEN** 自动建表（WAL+索引+`user_version=1`）且老于阈值的 `date/hour` 行被清理，查询不受影响；`metrics.sqlite` 与 `-wal`/`-shm` 权限为 `0600`

#### Scenario: 关闭时数据不丢

- **WHEN** 进程收到 SIGTERM/正常关闭（含 `llm-proxy-only` / `credential-proxy-only` 的 `SIGTERM`，`proxy.py` 在 `runner.cleanup` 前 `await collector.close()`）
- **THEN** `collector.close()` 完成最终 flush（含 `cancel 定时器 + 最终 flush + 等待 executor + wal_checkpoint(TRUNCATE) + 重 chmod 0600`）后退出，最近 5min 快照不丢失（正常退出丢 0，`kill -9` 丢 ≤5min+WAL 未 checkpoint 页）
