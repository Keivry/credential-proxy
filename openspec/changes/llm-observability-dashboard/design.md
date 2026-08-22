## Context

见 `proposal.md — Why`。`llm-privacy-gateway` 与 `llm-pii-cache-concurrency` 后，PII 脱敏已切为全局持久 LRU（`GlobalPiiTokens` 1000+1000）+ `ContextVar` 并发隔离，空体守门改为 `bytes_written`。但全链路仍黑盒：无处可查“某请求是否触发替换、命中哪类、哪条上游、多少 token、是否走 cache、审计是否拦截”。本 change 在不改转发语义的前提下补可观测性：**内存轻量采集（含 latency 环形用于 p50/p95）+ SQLite WAL 日/小时聚合 + 同进程 `/_admin` 单 HTML 大盘（Chart.js 内联）**。约束：Mixin 拆分、锁外网络 I/O、146 测试 + ruff 全绿、public repo 无内网信息、单实例 NASRT/Docker 为主。

## Goals / Non-Goals

**Goals:**
- 同进程内完成采集→聚合→展示闭环，首版零新增 pip 依赖、单 HTML（无构建）、首帧可见
- 指标覆盖：PII/凭据脱敏计数与命中率、上游转发与延迟、token usage、审计处置、LRU/守门状态，全部不含明文 PII
- 实时：最近事件环形缓冲（含 `latency_ms`）+ SSE 推送，窗口化查询 `?range=1h|24h|7d|30d`（`1h` 精确分位/`24h` 与 `7d` 小时粒度/`30d` 日粒度）

**Non-Goals:**
- 不做多实例聚合/告警（Prometheus 首版不注册路由，仅预留命名 `credential_proxy_*`，请求返回 `404`，二期再引入 `prometheus_client`）
- 不引入重前端框架（Next/React）与构建链
- 不改 `PII_HOLD_MAX`、LRU、上游重试等现有语义；不新增对外转发 API

## Decisions

### D1 — 单进程嵌入式采集（`_metrics.py` MetricsCollector）

**选择：** 新增 `MetricsCollector` 单例（`proxy.py` 初始化、注入到各 Mixin），**counters 用 `asyncio.Lock` 保护递增**（热路径 `LOAD-ADD-STORE` 非原子，跨 `await` 让出时 `dict() +=1` 会丢数，嵌套 `dict[rule]+=1` 更易撕裂；用锁护住整段递增），**快照与落盘用 `asyncio.Queue` 单写者串行化**（事件循环内 `dict()` 拷贝后 `put_nowait` 到队列，`run_in_executor` 单 worker 消费，逐条 `INSERT ... ON CONFLICT DO UPDATE SET col=col+excluded.col` 原子累加，避免 SQLITE_BUSY 与覆盖丢数）。仅环形缓冲 `recent_events: deque(maxlen=10000)` 用 `asyncio.Lock` 保护且每条含 `latency_ms`。**埋点位置（口径拆分）：** `_pii.py: PiiDetector.scan` → `pii_detected_total{kind}`（检测到）与 `_token.py: GlobalPiiTokens.register` → `pii_cache_hit/miss`（命中已注册复用/新建）分离；`TokenMixin._register_secret` + `_llm.py._redact` 命中 → `cred_hit/miss`（`_redact` 快照命中亦计 `hit`，按请求 `out!=in` 计 1 而非替换次数）与 `cred_lru_evictions`（`popitem(last=False)` 分支）；`_llm.py: handler`（上游 `port/tail/stream`、`requests_total{status}` 每条请求计 1（重试不计多次）、`latency_ms/ttft/bytes_in/out`、`empty_guarded`、`client_gone`、token `usage` 归一）——**流式与非流式两条响应路径均埋点**（非流式 `upstream_resp.read()` 分支也记 `requests_total/latency/bytes`），`/v1/models` 等非对话 tail 过滤不计入 `upstream` 分组；错误分支（SSE 客户端断开/上游异常）在 `except` 钩子计 `client_gone` 与对应 `status`；`_audit.py: audit_tool_call`（`audit_by_verdict`/`audit_by_rule`）及 `_append_audit_log` 失败 `audit_log_write_fail`，`audit_pending_total` 与 `audit_hold_overflows` 为必选计数（非可选）。**SQLite `DATA_DIR/metrics.sqlite` WAL 模式：** `daily_agg(date TEXT, upstream TEXT, pii_by_type JSON, pii_hits, pii_miss, cred_hits, cred_miss, cred_lru_evictions, requests, tokens JSON, audit_by_verdict JSON, audit_by_rule JSON, PRIMARY KEY(date, upstream))` 日聚合（30天滚动）+ `hourly_agg(hour TEXT, upstream TEXT, requests, tokens JSON, latency_buckets JSON, pii_by_type JSON, PRIMARY KEY(hour, upstream))` 7天滑动小时聚合，每 5min `UPSERT` 当天/当小时行 + **优雅关闭显式 `await collector.close()`**（cancel 定时器 + 最终 flush + 等待 executor 完成 + `PRAGMA wal_checkpoint(TRUNCATE)`）；`PRAGMA journal_mode=WAL` + `busy_timeout=5000` + `synchronous=NORMAL`，`CREATE INDEX idx_daily_agg_date, idx_hourly_agg_hour`，文件 `0600`（含 `-wal`/`-shm` 也 `os.chmod 0600`）；所有 `date`/`hour` 统一 **UTC ISO**（`date=%Y-%m-%d`、`hour=%Y-%m-%dT%H:00:00Z`），滚动清理同 TZ（`WHERE date < date('now','-30 days')` 依赖 UTC 会话）。`1h` 的 p50/p95 由 `recent_events` 的 `latency_ms` 现场 `sorted` 计算（精确，注意 `deque(10000)` 覆盖 1h 高流量量级；低流量下标注 `≈`），`24h+` 的 p95 由 `hourly_agg.latency_buckets` 近似或标注 `≈`。**埋点不遗漏：** `resp_p2t` 响应侧还原不参与 `pii_cache_*` 计数（仅请求侧检测计）。

**备选：** 独立 sidecar 进程 / 外置 TSDB —— 部署与 IPC 成本高，单实例场景无收益。

**理由：** 与现有 Mixin 单例、`DATA_DIR` 落盘风格一致；热路径仅 `+=1` 与 `deque.append`，锁/队列单写者保证快照一致性，`ruff` 可静态检查未污染。

### D2 — Admin API 与现有服务同端口同 aiohttp 应用（多 App 注入）

**选择：** `_admin.py: AdminMixin` 挂 `/_admin/*`（`metrics?range=1h|24h|7d|30d` / `events?limit&kind&upstream&verdict` / `events/stream SSE` / `health`），**首版不注册 `metrics/prometheus`（404）**。**多 App 注入策略：** `_llm.py:_start_one_proxy` 为每个 `LLM_887x` 端口创建 `web.Application`（`add_route('*','/{tail:.*}')` 通配），`_credential.py:start_credential_api` 另建 `8877` app，`proxy.py:_runners` 管理多个 runner——`AdminMixin` 在每个 app 创建后、注册通配 `*` **之前**调用 `add_get('/_admin/...')`（先注册长路由，避免通配吞掉 `/_admin/metrics`）；所有 runner 共享同一个 `MetricsCollector` 单例，保证聚合一致。**鉴权：** 仅认独立必填 `OBSERVABILITY_ADMIN_TOKEN` env（未设 → 启动 `SystemExit`，与 `_audit.py:parse_audit_env_config` 同模式）；启动时检查 `OBSERVABILITY_ADMIN_TOKEN == CREDENTIAL_ADMIN_TOKEN` 或 `== MATRIX_ACCESS_TOKEN` 则 `SystemExit`（三 Token 独立、互不识别；`/revoke/emergency` 等凭据 API 仍只认 `CREDENTIAL_ADMIN_TOKEN`）。**凭证三选一：** `X-Admin-Token` 头优先；`Cookie: __Host-admin_token=<token>`（`HttpOnly; Secure; SameSite=Strict`，仅经 `/_admin/` HTTPS/反代）；`?access_token=<token>` 查询参数仅作 `EventSource` 兼容回退（浏览器原生 `EventSource` 无法带自定义头）——三者任一匹配即通过，SSE 同样鉴权；`trust_proxy_headers=false` 不读 `X-Forwarded-For`/`X-Real-IP`/`Forwarded`，一律用 `request.remote` 直连地址。**回环策略：** 不做裸 `127.0.0.1` 白名单（Docker bridge 下 `request.remote=172.18.0.1` 非回环、前置反代恒为反代 IP，回环判断不可靠）；仅当 `ALLOW_LOOPBACK_NO_TOKEN=1 && 显式环境标记 env==dev` 时放行 `request.remote in ('127.0.0.1','::1')` 或 `remote.startswith('127.')`，且仅限 `GET`；生产 `OBSERVABILITY_ADMIN_TOKEN` 必填。**只读与头：** 全部只读 `GET`（`POST/PUT/DELETE/PATCH` → `405` + `Allow: GET`），响应头 `Cache-Control: no-store, no-cache, must-revalidate, private` + `Pragma: no-cache` + `X-Content-Type-Options: nosniff` + `X-Frame-Options: DENY` + `Referrer-Policy: no-referrer`；`401` body 不含任何指标数据；`metrics`/`events` JSON 使用 `sniff` 防护的 `application/json`，`admin.html` 用 `text/html; charset=utf-8`。

**备选：** 另起端口 —— 占用端口与防火墙配置翻倍。

**理由：** 复用 `proxy.py:_runners` 生命周期与 `aiohttp` 中间件，无额外 `ClientSession`；先注册长路由规避通配吞路由；多 runner 共享单例保证数据一致。

### D3 — 单 HTML 无构建大盘（静态内联 + 降级）

**选择：** 单文件 `admin.html`（`aiohttp` 静态路由 `/_admin/`）含内联 CSS + **内联 `Chart.js`（~200KB 零 pip 依赖，`Chart is not defined` 时降级纯 SVG 条形/折线，无外部字体/CDN）**，首帧总览 KPI（今日请求/脱敏占比/PII 命中/阻断数/p95，`p95` 标注 `1h精确/7d≈`）+ 时序趋势（`1h` 细粒度/`24h` 小时粒度/`7d` 168点小时粒度/`30d` 30点日粒度）+ 类型/上游分布 + 最近事件表（`ts/request_id/upstream/pii_hits/cred_hits/tokens/verdict/latency`，可按 `verdict/kind/upstream` 过滤）+ `EventSource` 实时行。深色风格、等宽数字、与 `architecture-diagram` 同色板。**CSP 注意：** 内联 `Chart.js` 与 `onclick`/`style` 在 `script-src 'self'` 严格 CSP 下会被拦，若部署环境启用严格 CSP 则图表降级为 SVG 且数值/表格仍可见（数值优先，图表可降级）；首包 ~200KB 内联 JS，鉴权失败时仍先返回 `401` 不发送 body。**鉴权初始化：** `admin.html` 首次加载先 `fetch('/_admin/metrics')`（带 `X-Admin-Token` 头或 `?access_token`）成功后将 token 写入 `__Host-admin_token` Cookie，后续 `EventSource` 走 `?access_token` 或 Cookie 完成鉴权。

**备选：** React/Next 构建产物 —— 与“零依赖、单文件可审计”相悖。

**理由：** 用户偏好“简单直接、schema 精简”；单文件便于 `docker exec cat` 审计与离线可用。

### D4 — 不含明文的可观测性契约

**选择：** 所有对外 JSON/HTML 仅暴露 `kind/count/placeholder_preview([REDACTED:phone])`，不含原始 PII；`recent_events` 存 `先 _audit_live_redact 脱敏后 truncate(120)` 的摘要（脱敏在持久化之前完成，PII 明文不落盘）；自定义正则名白名单（`sanitize_kind`：长度 >32、含 `__`、或不在内置 7 种 + 自定义模式白名单 → 归 `custom_other`，防 label 基数爆炸）；`metrics.sqlite` 落盘目录经 `docker-compose.yml` 卷挂载 `${DATA_DIR:-./data}:/data`，`docker-entrypoint.sh` 负责 `mkdir -p /data && chmod 700 /data`，DB 文件与 `-wal`/`-shm` 均 `0600`。

**备选：** 明文落盘便于排障 —— 与隐私目标冲突。

## Risks / Trade-offs

- [计数与真实转发不一致/口径重叠] → Mitigation: `pii_detected_total` 与 `pii_cache_hit/miss` 分离，`cred_hit` 含 `_redact` 快照命中（按请求计 1）；计数紧贴替换/转发的同一回调内递增，同请求 `try/finally` 保证落数；单测对照 `audit.log` 条数
- [SQLite 锁竞争/半写] → Mitigation: `asyncio.Lock` 护计数器递增 + `asyncio.Queue` 单写者串行 UPSERT（WAL + `busy_timeout=5000` + `synchronous=NORMAL`），原子 `ON CONFLICT DO UPDATE SET col=col+excluded.col`；5min + 优雅关闭双 flush（`await collector.close()` 含 `wal_checkpoint(TRUNCATE)`）；30天/7天滚动
- [Admin 接口未鉴权外泄] → Mitigation: `OBSERVABILITY_ADMIN_TOKEN` 必填（未设 `SystemExit`），不与 `CREDENTIAL_ADMIN_TOKEN`/`MATRIX_ACCESS_TOKEN` 重名（启动交叉检查），不信任 `X-Forwarded-For`，`401` 不泄露数据；响应头 `Cache-Control: no-store` + `X-Content-Type-Options: nosniff` + `X-Frame-Options: DENY`；README 显式警示
- [CDN 不可用导致图表空白] → Mitigation: `Chart.js` 内联打包，`Chart is not defined` 时自动切 SVG 降级，保证数值与表格始终可见；CSP `script-src 'self'` 场景同样降级
- [埋点遗漏/p95不可算] → Mitigation: tasks 验收 `grep -rn collector.` 覆盖 5 文件 + `grep -rn latency_ms`；`recent_events deque(10000)` 存 `latency_ms` 支撑 `1h` 精确分位（低流量标注 `≈`），`hourly_agg.latency_buckets` 近似 `7d` p95；流式与非流式两条响应路径均埋点
- [JSON 半写/截断先脱敏后截断] → Mitigation: `redact_summary` 先脱敏后 `truncate(120)`，`metrics.sqlite` `0600`（含 `-wal/-shm`）+ `user_version`

## Migration Plan

1. 合并本 change 后重建 Docker 镜像 `ghcr.io/keivry/credential-proxy`；部署时新增必填 env `OBSERVABILITY_ADMIN_TOKEN`（与 `CREDENTIAL_ADMIN_TOKEN`/`MATRIX_ACCESS_TOKEN` 不同值），`docker-compose.yml` 补 `${DATA_DIR:-./data}:/data` 卷挂载；`DATA_DIR/metrics.sqlite` WAL 自动建表，`0600`，`hourly_agg` 7天滑动
2. 需外网查看时通过反代（TLS）暴露 `/_admin/` 并配置反代鉴权（不依赖 `X-Forwarded-For`）；`EventSource` 使用 `?access_token` 或 Cookie 兼容
3. 回滚：直接回退镜像，`metrics.sqlite` 可保留或删除，无数据迁移

## Open Questions

- 无（Prometheus 首版不注册路由已定；时序已定 `hourly_agg 7天` + `daily_agg 30天`，`1h` 由 ring 精确分位（低流量 `≈`）；Token 命名已定 `OBSERVABILITY_ADMIN_TOKEN`）
