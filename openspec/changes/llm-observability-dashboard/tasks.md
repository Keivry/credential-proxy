## 1. 采集层落地

- [ ] 1.1 新增 `_metrics.py: MetricsCollector`（counters 用 `asyncio.Lock` 保护递增；事件循环内 `dict()` 快照后 `put_nowait` 到 `asyncio.Queue`，`run_in_executor` 单 worker 串行 UPSERT WAL，`INSERT ... ON CONFLICT DO UPDATE SET col=col+excluded.col` 原子累加；`recent_events deque(10000)` 每条含 `latency_ms`，用 `asyncio.Lock` 保护；表 `daily_agg(date TEXT, upstream TEXT, ..., PRIMARY KEY(date,upstream))` 30天 + `hourly_agg(hour TEXT, upstream TEXT, ..., PRIMARY KEY(hour,upstream))` 7天滑动，每 5min UPSERT + 优雅关闭显式 `await collector.close()`（cancel 定时器 + 最终 flush + `PRAGMA wal_checkpoint(TRUNCATE)`），`PRAGMA journal_mode=WAL` + `busy_timeout=5000` + `synchronous=NORMAL`，`date/hour` 统一 UTC ISO（`%Y-%m-%d` / `%Y-%m-%dT%H:00:00Z`），文件与 `-wal`/`-shm` 均 `0600`）
  - 验收：`grep -rn MetricsCollector _metrics.py proxy.py` 命中单例且 `asyncio.Lock`/`asyncio.Queue` 存在；`metrics.sqlite` 不存在时首次 `GET /_admin/metrics` 自动建表不报错；`PRAGMA journal_mode` 为 WAL，`busy_timeout=5000`；`ls -l metrics.sqlite metrics.sqlite-wal metrics.sqlite-shm` 均为 0600；关闭进程后最近 5min 快照仍可查（`wal_checkpoint(TRUNCATE)` 生效）

- [ ] 1.2 PII/凭据埋点（口径拆分）：`_pii.py:PiiDetector.scan` → `pii_detected_total{kind}`；`_token.py:GlobalPiiTokens.register` → `pii_cache_hit/miss`（命中复用/新建，响应侧 `resp_p2t` 不参与）；`TokenMixin._register_secret` + `_llm.py._redact` 快照命中 → `cred_hit/miss`（按请求 `out!=in` 计 1） + `cred_lru_evictions`（`popitem(last=False)` 淘汰分支）；`sanitize_kind` 对超长/含 `__`/非白名单名归 `custom_other`
  - 验收：同值连续两次：第一次 `detected+1 miss+1`，第二次 `detected+1 hit+1`；凭据达 `MAX_TOKEN_ENTRIES` 淘汰时 `cred_lru_evictions+1`；注入 `PII_CUSTOM_PATTERNS` 超长名后 `pii_by_type` 只出现 `custom_other`；满足 `observability-metrics — 脱敏与缓存指标采集`

- [ ] 1.3 上游/Token/守门埋点：`_llm.py` handler 记录 `upstream(port/tail/stream)`、`requests_total{status}`（每条请求计 1，重试不计多次；`/v1/models` 非对话 tail 过滤）、`latency_ms/ttft/bytes_in/out`、`empty_guarded`（`bytes_written==0` 分支）、token `usage` 归一（OpenAI/Anthropic/Responses 有则记无则 `unknown`）、`client_gone`；**流式与非流式两条响应路径均埋点**（非流式 `upstream_resp.read()` 分支也记 `requests_total/latency/bytes`），错误分支（SSE 客户端断开/上游异常）在 `except` 钩子计 `client_gone` 与对应 `status`；`recent_events` 存 `latency_ms` 支撑 p50/p95，`hourly_agg` 存 `latency_buckets`
  - 验收：`LLM_8878/8879` 各发请求后 `/_admin/metrics` 按 `upstream` 分组合计等于总量；守门注入单测 `empty_guarded+1`；非流式请求在 `requests_total`/`latency` 可见；`1h` 的 p95 与 ring 现场 `sorted(latency_ms)` 一致，`7d` 的 p95 为 `≈` 近似

- [ ] 1.4 审计埋点：`_audit.py:audit_tool_call` 的 `audit_by_verdict`/`audit_by_rule` 分布与 `_append_audit_log` 失败的 `audit_log_write_fail`，`audit_pending_total` 与 `audit_hold_overflows` 为**必选**计数
  - 验收：`block` 命中 `rm -rf` 后 `audit_by_verdict.block+1` 且 `audit_by_rule['rm -rf']+1`；写失败注入后 `audit_log_write_fail` 递增；`audit_pending_total`/`audit_hold_overflows` 有计数可查

## 2. Admin API

- [ ] 2.1 新增 `_admin.py: AdminMixin` 并在每个 aiohttp app（`_llm.py:_start_one_proxy` 的 `LLM_887x` app 与 `_credential.py:start_credential_api` 的 `8877` app）**注册通配 `*` 之前**挂 `/_admin/*`（`metrics?range=1h|24h|7d|30d`、`events?limit&kind&upstream&verdict`、`events/stream SSE`、`health`），所有 runner 共享同一 `MetricsCollector` 单例；**首版不注册 `metrics/prometheus`（404）**，统一 `Cache-Control: no-store, no-cache, must-revalidate, private` + `Pragma: no-cache` + `X-Content-Type-Options: nosniff` + `X-Frame-Options: DENY` + `Referrer-Policy: no-referrer`
  - 验收：`curl /_admin/metrics?range=1h|24h|7d|30d` 与 `/_admin/events` 返回 200 且 `range=1h` 走内存 ring 精确分位、`24h` 走 `hourly_agg`/`daily_agg` 求和；`POST/PUT/DELETE/PATCH /_admin/*` 返回 405 + `Allow: GET`；`GET /_admin/metrics/prometheus` 返回 404；遍历 `LLM_8878`、`LLM_8879`、`8877` 三端口 `/_admin/metrics` 均 200 且数值一致

- [ ] 2.2 鉴权与绑定：`OBSERVABILITY_ADMIN_TOKEN` 必填（未设启动 `SystemExit`），三选一凭证——`X-Admin-Token` 头优先、`Cookie: __Host-admin_token`（`HttpOnly; Secure; SameSite=Strict`）、`?access_token` 查询参数（`EventSource` 兼容）；`trust_proxy_headers=false` 不读 `X-Forwarded-For`/`X-Real-IP`/`Forwarded`；启动时与 `CREDENTIAL_ADMIN_TOKEN`/`MATRIX_ACCESS_TOKEN` 相等则 `SystemExit`；不做裸回环白名单（`ALLOW_LOOPBACK_NO_TOKEN=1 && env==dev` 时才放行 `127.0.0.1/::1`）；SSE 同样鉴权；`401/405` 不泄露指标
  - 验收：无 token 访问 `/_admin/metrics` 返回 401 且 body 无指标；加 `X-Admin-Token` 头后 200；用 `CREDENTIAL_ADMIN_TOKEN`/`MATRIX_ACCESS_TOKEN` 访问返回 401；`?access_token` 的 SSE 返回 200 流、无凭证 SSE 401；`ALLOW_LOOPBACK_NO_TOKEN=1` 未设时回环也 401；`observability-dashboard — 只读与鉴权` 全覆盖

- [ ] 2.3 聚合窗口与自动建表：`1h` 走内存 ring 精确 p95、`24h/7d` 走 `hourly_agg` 小时聚合（7天滑动）、`30d` 走 `daily_agg` 日聚合；启动时 `metrics.sqlite` 缺失自动建表（WAL+索引），30天/7天滚动删除（UTC 同 TZ）
  - 验收：`rm metrics.sqlite` 后重启首个请求不报错且后续 `?range=7d` 与 `?range=30d` 与预期合计一致；`hourly_agg` 超 7 天行被清理；`daily_agg` 主键含 `(date,upstream)`、`hourly_agg` 含 `(hour,upstream)`

## 3. 单 HTML 实时大盘

- [ ] 3.1 新增 `admin.html` 单文件静态（内联 CSS + **内联 Chart.js ~200KB** + `Chart is not defined` 时 SVG 降级、深色风格）挂到 `/_admin/`，首帧 5 KPI（今日请求/脱敏占比/PII 命中/阻断数/p95，p95 标注 `1h精确/7d≈`）+ 时序（`1h`/`24h`/`7d`/`30d` 四档）+ 分布（PII 按 kind、上游按 port）三区；首次加载先 `fetch('/_admin/metrics')` 换 `__Host-admin_token` Cookie，后续 `EventSource` 走 `?access_token` 或 Cookie
  - 验收：浏览器打开 `/_admin/` 首帧可见 5 卡与两条趋势线，数值与 `/_admin/metrics?range=24h` 合计差值为 0；`Chart.js` 未定义时图表降级为 SVG 数值仍全；严格 CSP（`script-src 'self'`）下数值表格仍可见

- [ ] 3.2 事件表与过滤：最近事件表（`ts/request_id/upstream/pii_hits/cred_hits/tokens/verdict/latency`，数据源仅 `recent_events`，`audit.log` 仅作 `raw-tail` 排障）支持 `1h|24h|7d|30d` 窗口与 `kind/upstream/verdict` 过滤联动，点击行弹窗看脱敏摘要（`[REDACTED:<kind>]`，先脱敏后 `truncate(120)`，无明文）
  - 验收：`?verdict=block` 过滤后表与 `/_admin/events?verdict=block` 一致；弹窗不含明文 PII（`grep` 明文值命中为 0）

- [ ] 3.3 Live 实时流：前端 `EventSource /_admin/events/stream`（带 `?access_token` 或 Cookie，浏览器原生 `EventSource` 无法带 `X-Admin-Token` 头）推新事件到表首，2 秒内可见
  - 验收：`Live` 开启下发新请求，完成 2 秒内表首出现新行；无凭证的 SSE 返回 401

## 4. 质量与交付

- [ ] 4.1 单测与回归：为两能力各补覆盖 `observability-metrics` 5 个 requirement 与 `observability-dashboard` 3 个 requirement 的场景单测（`pii_detected_total`/`pii_cache_hit/miss`、`empty_guarded`、`unknown tokens`、`hourly_agg`、`鉴权 401/405`、`CDN 降级` 等），**含 `llm-proxy-only.py` / `credential-proxy-only.py` 双入口专项**（两个轻量入口各自 `/_admin/*` 可用且鉴权生效），全量 `pytest + ruff check + format --check` 绿
  - 验收：`pytest -q` 全 pass；`ruff check . && ruff format --check .` 0 error；`grep -rn collector\. _pii.py _token.py _llm.py _audit.py _metrics.py` 覆盖全部埋点文件无遗漏（命中非注释行）；`grep -rn latency_ms` 有 p95 支撑；轻量双入口 `/_admin/*` 单测通过

- [ ] 4.2 文档与部署：更新 `README` 的 `/_admin` 章节（`OBSERVABILITY_ADMIN_TOKEN` 必填说明、与 `CREDENTIAL_ADMIN_TOKEN`/`MATRIX_ACCESS_TOKEN` 独立、`?access_token`/Cookie 兼容、数据留存 30天/7天、WAL 0600、不含明文声明）、`docker-compose.yml`/`docker-entrypoint.sh`（新增必填 env、`${DATA_DIR:-./data}:/data` 卷挂载、`mkdir -p /data && chmod 700 /data`、`metrics.sqlite` 及其 `-wal`/`-shm` 0600 初始化）、镜像验证回滚可删 `metrics.sqlite`
  - 验收：`README` 含 `/_admin` 鉴权与隐私声明；`docker compose config` 可见新增 env 与卷挂载；回滚镜像后服务正常且可删 `metrics.sqlite` 不影响启动
