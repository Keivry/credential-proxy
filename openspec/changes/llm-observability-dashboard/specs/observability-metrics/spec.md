## Purpose

为 credential-proxy 提供不含明文的嵌入式可观测性采集与聚合，覆盖 PII/凭据脱敏计数与命中率、上游转发与延迟、token usage、审计处置计数与 LRU/守门状态的统一采集与日聚合落盘。

## ADDED Requirements

### Requirement: 脱敏与缓存指标采集

系统 SHALL 在 PII 检测命中、凭据注册/还原、LRU 淘汰路径采集计数：PII 按 `kind`（内置 phone/id_card/email/bank_card/ipv4/ipv6/api_key + 自定义正则名 + 字典类型）分两类计数——`pii_detected_total{kind}`（`PiiDetector.scan` 检测到即 +1）与 `pii_cache_hit/miss`（`GlobalPiiTokens.register` 命中已注册复用即 `hit`、新建即 `miss`；响应侧 `resp_p2t` 还原不参与 `pii_cache_*` 计数），凭据按 `cred_hit/cred_miss`（`_register_secret` 新建与 `_redact` 快照命中均计 `hit`，按请求 `out!=in` 计 1 而非替换次数）与 `cred_lru_evictions`（`popitem(last=False)`）计数；自定义正则名 SHALL 经 `sanitize_kind` 消毒（长度 >32、含 `__`、或不在内置 7 种 + 自定义模式白名单 → 归 `custom_other`，防 label 基数爆炸）；所有计数 SHALL 可按聚合窗口查询且不含明文 PII（仅 `kind` 与 `[REDACTED:<kind>]` 形态，摘要先脱敏后 `truncate(120)`）。

#### Scenario: PII 命中按类型计数

- **WHEN** 同值 `phone` 连续两次请求（第一次新建、第二次复用）且另有一请求命中 `email` 新值
- **THEN** 指标中 `pii_detected_total{phone}=2, pii_cache_miss+1, pii_cache_hit+1` 且 `pii_detected_total{email}=1`，总数可对账

#### Scenario: 凭据 LRU 淘汰可观测

- **WHEN** 凭据映射 `pwd_to_token` 因达到 `MAX_TOKEN_ENTRIES` 触发 `popitem(last=False)` 淘汰
- **THEN** 指标中 `cred_lru_evictions` 递增且总数可查询

#### Scenario: 指标不含明文

- **WHEN** 查询任意指标或事件摘要
- **THEN** 返回中不含原始 PII 明文，仅含 `kind`、`count`、`[REDACTED:<kind>]` 占位预览与脱敏后摘要

#### Scenario: 自定义正则名基数受控

- **WHEN** 通过 `PII_CUSTOM_PATTERNS` 注入超长/含 `__` 的自定义名
- **THEN** 对应计数归入 `custom_other`，`pii_by_type` 标签数不随注入膨胀

### Requirement: 上游与 Token 指标采集

系统 SHALL 按上游 `port/url + tail + stream/non-stream` 维度采集：`requests_total{status}`（每条请求计 1，上游重试不计多次；`/v1/models` 等非对话 tail 过滤不计入 `upstream` 分组）、`upstream_latency`（`1h` 的 p50/p95 由 `recent_events` 的 `latency_ms` 现场 `sorted` 精确计算，低流量时标注 `≈`，`24h/7d` 的 p95 由 `hourly_agg.latency_buckets` 近似并标注 `≈`）、首字节时间 `ttft`、`bytes_in/out`、空体守门注入次数 `empty_guarded`、token usage（归一 OpenAI/Anthropic/Responses 的 `prompt/completion/total`，有 `usage` 则记无则记 `unknown` 不估算）与客户端提前断连 `client_gone`；流式与非流式两条响应路径 SHALL 均埋点（非流式 `upstream_resp.read()` 分支也记 `requests_total/latency/bytes`），错误分支（SSE 客户端断开/上游异常）在 `except` 钩子计 `client_gone` 与对应 `status`。

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

系统 SHALL 采集审计 `audit_tool_call` 的处置 `verdict`（`allow/deny/block/approve_pending/approved/rejected/expired`）计数与 `rule` 命中分布，以及 `audit_log_write_fail`、`audit_pending_total`、`audit_hold_overflows` 计数；`/_admin/metrics` SHALL 能按窗口返回 verdict/规则分布。

#### Scenario: 阻断可计数

- **WHEN** 某请求命中 `rm -rf` 危险模式被 `block` 处置
- **THEN** `audit_by_verdict.block +1` 且 `audit_by_rule['rm -rf'] +1`

#### Scenario: 写失败可观测

- **WHEN** `audit.log` 连续写失败达到阈值触发熔断记内存环形
- **THEN** 指标中 `audit_log_write_fail` 递增且可在健康接口中提示

### Requirement: 聚合与窗口化查询

系统 SHALL 维护进程级内存聚合（`recent_events: deque(10000)` 每条含 `latency_ms`，用 `asyncio.Lock` 保护）与 `DATA_DIR/metrics.sqlite` WAL 双表：`daily_agg(date TEXT, upstream TEXT, pii_by_type JSON, pii_hits, pii_miss, cred_hits, cred_miss, cred_lru_evictions, requests, tokens JSON, audit_by_verdict JSON, audit_by_rule JSON, PRIMARY KEY(date, upstream))` 30天滚动 + `hourly_agg(hour TEXT, upstream TEXT, requests, tokens JSON, latency_buckets JSON, pii_by_type JSON, PRIMARY KEY(hour, upstream))` 7天滑动小时聚合；每 5min 原子快照 UPSERT（`INSERT ... ON CONFLICT DO UPDATE SET col=col+excluded.col`，计数器递增用 `asyncio.Lock`，落盘用 `asyncio.Queue` 单写者串行）+ 优雅关闭显式 `await collector.close()`（cancel 定时器 + 最终 flush + `PRAGMA wal_checkpoint(TRUNCATE)`）；`PRAGMA journal_mode=WAL` + `busy_timeout=5000` + `synchronous=NORMAL`，文件与 `-wal`/`-shm` 均 `0600`；所有 `date`/`hour` 统一 **UTC ISO**（`date=%Y-%m-%d`、`hour=%Y-%m-%dT%H:00:00Z`），滚动清理同 TZ。`GET /_admin/metrics?range=1h|24h|7d|30d` SHALL 按窗口返回聚合（`1h` 走内存 ring 精确分位、`24h/7d` 走 `hourly_agg`、`30d` 走 `daily_agg`），缺失文件时自动建表且不报错。

#### Scenario: 窗口化查询

- **WHEN** 查询 `?range=1h|24h|7d|30d`
- **THEN** 分别返回对应窗口的聚合（`1h` 精确、`24h/7d` 168点小时粒度、`30d` 30点日粒度）；`1h` 的 p95 与 ring 现场计算一致

#### Scenario: 自动建表与滚动

- **WHEN** 首次启动且 `metrics.sqlite` 不存在或超过 30/7 天数据存在
- **THEN** 自动建表（WAL+索引）且老于阈值的 `date/hour` 行被清理，查询不受影响；`metrics.sqlite` 与 `-wal`/`-shm` 权限为 `0600`

#### Scenario: 关闭时数据不丢

- **WHEN** 进程收到 SIGTERM/正常关闭
- **THEN** `collector.close()` 完成最终 flush 且 `wal_checkpoint(TRUNCATE)` 后退出，最近 5min 快照不丢失
