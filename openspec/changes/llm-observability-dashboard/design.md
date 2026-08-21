## Context

见 `proposal.md — Why`。`llm-privacy-gateway` 与 `llm-pii-cache-concurrency` 后，PII 脱敏已切为全局持久 LRU（`GlobalPiiTokens` 1000+1000）+ `ContextVar` 并发隔离，空体守门改为 `bytes_written`。但全链路仍黑盒：无处可查“某请求是否触发替换、命中哪类、哪条上游、多少 token、是否走 cache、审计是否拦截”。本 change 在不改转发语义的前提下补可观测性：**内存轻量采集（含 latency 环形用于 p50/p95）+ SQLite WAL 日/小时聚合 + 同进程 `/_admin` 单 HTML 大盘（Chart.js 内联）**。约束：Mixin 拆分、锁外网络 I/O、146 测试 + ruff 全绿、public repo 无内网信息、单实例 NASRT/Docker 为主。

## Goals / Non-Goals

**Goals:**
- 同进程内完成采集→聚合→展示闭环，首版零新增 pip 依赖、单 HTML（无构建）、首帧可见
- 指标覆盖：PII/凭据脱敏计数与命中率、上游转发与延迟、token usage、审计处置、LRU/守门状态，全部不含明文 PII
- 实时：最近事件环形缓冲（含 `latency_ms`）+ SSE 推送，窗口化查询 `?range=1h|24h|7d|30d`（`1h` 精确分位/`7d` 小时粒度/`30d` 日粒度）

**Non-Goals:**
- 不做多实例聚合/告警（Prometheus 首版不注册路由，仅预留命名 `credential_proxy_*`，二期再引入 `prometheus_client`）
- 不引入重前端框架（Next/React）与构建链
- 不改 `PII_HOLD_MAX`、LRU、上游重试等现有语义；不新增对外转发 API

## Decisions

### D1 — 单进程嵌入式采集（`_metrics.py` MetricsCollector）

**选择：** 新增 `MetricsCollector` 单例（`proxy.py` 初始化、注入到各 Mixin），**counters 用无锁递增 + 定时原子快照**（事件循环内 `dict()` 拷贝后丢 `run_in_executor` 写，避免跨线程撕裂），仅环形缓冲 `recent_events: deque(maxlen=1000)` 用 `asyncio.Lock` 保护且每条含 `latency_ms`。埋点位置（口径拆分）：`_pii.py: PiiDetector.scan` → `pii_detected_total{kind}`（检测到）与 `_token.py: GlobalPiiTokens.register` → `pii_cache_hit/miss`（命中已注册复用/新建）分离；`TokenMixin._register_secret` + `_llm.py._redact` 命中 → `cred_hit/miss`（`_redact` 快照命中亦计 `hit`）与 `cred_lru_evictions`（`popitem(last=False)` 分支）；`_llm.py: handler`（上游 `port/tail/stream`、`requests_total{status}`、`latency_ms/ttft/bytes_in/out`、`empty_guarded`、`client_gone`、token `usage` 归一）与 `_audit.py: audit_tool_call`（`audit_by_verdict`/`audit_by_rule`）及 `_append_audit_log` 失败 `audit_log_write_fail`。SQLite `DATA_DIR/metrics.sqlite` WAL 模式：`daily_agg(date, upstream, pii_by_type JSON, pii_hits, pii_miss, cred_hits, cred_miss, cred_lru_evictions, requests, tokens JSON, audit_by_verdict JSON, audit_by_rule JSON)` 日聚合（30天滚动）+ `hourly_agg(hour, upstream, requests, tokens JSON, latency_buckets JSON, pii_by_type JSON)` 7天滑动小时聚合，每 5min `UPSERT` 当天/当小时行 + 优雅关闭再 flush，`PRAGMA journal_mode=WAL`，`CREATE INDEX idx_daily_agg_date, idx_hourly_agg_hour`，文件 `0600`。`1h` 的 p50/p95 由 `recent_events` 的 `latency_ms` 现场 `sorted` 计算（精确），`24h+` 的 p95 由 `hourly_agg.latency_buckets` 近似或标注 `≈`。

**备选：** 独立 sidecar 进程 / 外置 TSDB —— 部署与 IPC 成本高，单实例场景无收益。

**理由：** 与现有 Mixin 单例、`DATA_DIR` 落盘风格一致；热路径仅 `+=1` 与 `deque.append`，`ruff` 可静态检查未污染。

### D2 — Admin API 与现有服务同端口同 aiohttp 应用

**选择：** `_admin.py: AdminMixin` 挂 `/_admin/*`（`metrics?range=1h|24h|7d|30d` / `events?limit&kind&upstream&verdict` / `events/stream SSE` / `health`），**首版不注册 `metrics/prometheus`**。鉴权仅认独立 `ADMIN_TOKEN` env（`X-Admin-Token` 头，`trust_proxy_headers=false` 不读 `X-Forwarded-For`）；`ADMIN_TOKEN` 未设时仅 `127.0.0.1` 可访且启动打 `warning`，设后任意 IP 均需 token；全部只读 `GET`（`POST/PUT/DELETE →405`），响应头 `Cache-Control: no-store` + `X-Content-Type-Options: nosniff`，SSE 同样鉴权。

**备选：** 另起端口 —— 占用端口与防火墙配置翻倍。

**理由：** 复用 `proxy.py:_runners` 生命周期与 `aiohttp` 中间件，无额外 `ClientSession`。

### D3 — 单 HTML 无构建大盘（静态内联 + 降级）

**选择：** 单文件 `admin.html`（`aiohttp` 静态路由 `/_admin/`）含内联 CSS + **内联 `Chart.js`（~200KB 零 pip 依赖，`Chart is not defined` 时降级纯 SVG 条形/折线，无外部字体/CDN）**，首帧总览 KPI（今日请求/脱敏占比/PII 命中/阻断数/p95，`p95` 标注 `1h精确/7d≈`）+ 时序趋势（`1h` 细粒度/`7d` 168点小时粒度/`30d` 30点日粒度）+ 类型/上游分布 + 最近事件表（`ts/request_id/upstream/pii_hits/cred_hits/tokens/verdict/latency`，可按 `verdict/kind/upstream` 过滤）+ `EventSource` 实时行。深色风格、等宽数字、与 `architecture-diagram` 同色板。

**备选：** React/Next 构建产物 —— 与“零依赖、单文件可审计”相悖。

**理由：** 用户偏好“简单直接、schema 精简”；单文件便于 `docker exec cat` 审计与离线可用。

### D4 — 不含明文的可观测性契约

**选择：** 所有对外 JSON/HTML 仅暴露 `kind/count/placeholder_preview([REDACTED:phone])`，不含原始 PII；`recent_events` 存 `先 _audit_live_redact 脱敏后 truncate(120)` 的摘要；自定义正则名白名单（超长/含 `__` 归 `custom_other` 防 label 基数爆炸）。

**备选：** 明文落盘便于排障 —— 与隐私目标冲突。

## Risks / Trade-offs

- [计数与真实转发不一致/口径重叠] → Mitigation: `pii_detected_total` 与 `pii_cache_hit/miss` 分离，`cred_hit` 含 `_redact` 快照命中；计数紧贴替换/转发的同一回调内递增，同请求 `try/finally` 保证落数；单测对照 `audit.log` 条数
- [SQLite 锁竞争/半写] → Mitigation: 事件循环内 `dict()` 快照拷贝后丢 `run_in_executor` 串行 `UPSERT`（WAL），读走只读快照；5min + 优雅关闭双 flush；`PRAGMA journal_mode=WAL` + 索引；30天/7天滚动
- [Admin 接口未鉴权外泄] → Mitigation: `ADMIN_TOKEN` 未设仅回环 + warning，设后任意 IP 均需 `X-Admin-Token`，不信任 `X-Forwarded-For`，`401` 不泄露数据；响应头 `Cache-Control: no-store` + `X-Content-Type-Options: nosniff`；README 显式警示
- [CDN 不可用导致图表空白] → Mitigation: `Chart.js` 内联打包，`Chart is not defined` 时自动切 SVG 降级，保证数值与表格始终可见
- [埋点遗漏/p95不可算] → Mitigation: tasks 验收 `grep -rn collector.` 覆盖 5 文件 + `grep -rn latency_ms`；`recent_events` 存 `latency_ms` 支撑 `1h` 精确分位，`hourly_agg.latency_buckets` 近似 `7d` p95
- [JSON 半写/截断先脱敏后截断] → Mitigation: `redact_summary` 先脱敏后 `truncate(120)`，`metrics.sqlite` `0600` + `user_version`

## Migration Plan

1. 合并本 change 后重建 Docker 镜像 `ghcr.io/keivry/credential-proxy`，无配置变更即可启用（`DATA_DIR/metrics.sqlite` WAL 自动建表，`0600`，`hourly_agg` 7天滑动）
2. 需外网查看时置 `ADMIN_TOKEN`（任意 IP 均需 `X-Admin-Token`）并配置反代鉴权（不依赖 `X-Forwarded-For`）
3. 回滚：直接回退镜像，`metrics.sqlite` 可保留或删除，无数据迁移

## Open Questions

- 无（Prometheus 首版不注册路由已定；时序已定 `hourly_agg 7天` + `daily_agg 30天`，`1h` 由 ring 精确分位）
