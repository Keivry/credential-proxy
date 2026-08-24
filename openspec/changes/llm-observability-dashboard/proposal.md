## Why

两轮 change（`llm-privacy-gateway` 与 `llm-pii-cache-concurrency`）已上线：PII 全局持久 LRU 解决了 cache 命中暴跌，并发用 `ContextVar` 隔离 + `bytes_written` 守门解决了空流 `JSONDecodeError`。但两者均未补可观测性：PII 是否被替换为 `__PII_*__`、各上游各自转发多少、token/缓存命中多少、上游输出多少、审计拦截多少，全部黑盒——无法验证脱敏生效、无法做成本/故障归因、无法调优 `PII_HOLD_MAX` 与 LRU。

## What Changes

- **新增嵌入式指标采集层**：在 `PiiDetector` / `GlobalPiiTokens` / `TokenMixin` / `LlmMixin` / `AuditMixin` 的关键路径植入无阻塞计数，产出请求级 `recent_events` 环形缓冲（含 `latency_ms` 用于 p50/p95，`1h` 精确分位、低流量标 `≈`、`24h/7d/30d` 均标 `≈`）+ 进程级聚合计数，落盘 `DATA_DIR/metrics.sqlite`（WAL 模式，`daily_agg` 日聚合 + `hourly_agg` 7天滑动小时聚合，每 5min 原子快照 UPSERT，30天/7天滚动，不存明文 PII；`daily_agg` 含 `latency_buckets` 支撑 `30d` 延迟近似）
- **新增轻量 Admin API**：`/_admin/*` 只读 JSON（`metrics` / `events` / `events/stream` / `health`），与现有 `aiohttp` 服务同进程同端口（每个 `LLM_887x` 代理 app 与 `8877` 凭据 API app 均在通配 `*` 前注册 `/_admin/*`，三入口 `proxy.py` / `llm-proxy-only.py` / `credential-proxy-only.py` 均注入），鉴权仅认独立 `OBSERVABILITY_ADMIN_TOKEN`（`X-Admin-Token` 头优先，`Cookie __Host-admin_token` 与 `?access_token` 仅作 `EventSource` 兼容回退且 `?access_token` 仅限 `events/stream`；`trust_proxy_headers=false` 不读 `X-Forwarded-For`；`OBSERVABILITY_ADMIN_TOKEN` 必填，未设时启动直接 `SystemExit`，与 `CREDENTIAL_ADMIN_TOKEN` / `MATRIX_ACCESS_TOKEN` / `DATA_DIR/admin_token` 文件值完全独立，启动时若与任一相等则 `SystemExit`；不复用 `MATRIX_ACCESS_TOKEN`）
- **新增单 HTML 实时大盘**：单一 `admin.html`（无构建、内联 `Chart.js` 零 pip 依赖，`Chart.js` 加载失败降级纯 SVG）把上述指标清晰美观地展示为总览卡片 + 时序趋势（`1h` 精确分位/`24h` 小时粒度/`7d` 小时粒度/`30d` 日粒度，p95 标注 `1h精确(低流量≈)/24h≈/7d≈/30d≈`）+ 类型/上游分布 + 最近事件表 + 实时 SSE 流，_dark 风格、适配 Matrix 侧轻量运维
- **可选 Prometheus 兼容**：首版不注册 `/_admin/metrics/prometheus` 路由（预留命名 `credential_proxy_*`，请求返回 `404`，二期按需引入 `prometheus_client` 再暴露）

## Capabilities

### New Capabilities

- `observability-metrics`: 嵌入式指标采集与聚合——PII/凭据脱敏计数与命中率、上游转发与延迟、token usage、审计处置计数、LRU/环形缓冲状态的统一采集、内存聚合与 SQLite 日/小时聚合，不含明文 PII
- `observability-dashboard`: 单 HTML 轻量可视化大盘——总览 KPI、时序趋势、类型/上游分布、事件 inspector、SSE 实时流、健康检查的只读 UI，适配单实例 NASRT/Docker 自部署

### Modified Capabilities

<!-- 无既有 spec 行为变更，本 change 为纯新增能力 -->

## Impact

- **新增文件**：`_metrics.py`（采集器，含 `sanitize_kind` 集中实现 + 深拷贝快照 + 单 worker 队列 + `health` gauge）、`_admin.py`（AdminMixin/API，三入口共享单例）、`admin.html`（单文件大盘）、`openspec/specs` 下 2 个新能力 spec
- **修改文件**：`proxy.py`（初始化采集器与 Admin 路由，注入多 app，显式 `await collector.close()` 接入 `shutdown` 含 `SIGTERM`）、`llm-proxy-only.py` / `credential-proxy-only.py`（同注入 AdminMux 与 `collector`，同鉴权校验）、`_pii.py`（命中计数钩子）、`_token.py`（凭据/LRU 计数）、`_llm.py`（上游/token/守门计数，含非流式分支与错误分支，`upstream` 主键仅 `port` 避免高基数）、`_audit.py`（处置计数）、`docker-compose.yml`/`docker-entrypoint.sh`（新增必填 `OBSERVABILITY_ADMIN_TOKEN`、`DATA_DIR` 卷挂载与 `metrics.sqlite{,-wal,-shm} 0600` 权限初始化，`chmod 700 /data`）、`README.md`
- **依赖**：首版零新增 pip 依赖；`Chart.js` 内联打包（~200KB）零 pip 依赖，加载失败降级为 SVG 条形图
- **兼容**：全部只读、不改转发语义；默认落地到 `DATA_DIR`（`${DATA_DIR:-./data}:/data` 卷挂载，`tpm:ro/db:ro` 子卷叠加验证），旧部署需补 `OBSERVABILITY_ADMIN_TOKEN` 后启用；SQLite WAL 模式，文件缺失自动建表，权限 `0600`（含 `-wal`/`-shm` 同 `0600`），`busy_timeout=5000`，`PRAGMA user_version=1`
