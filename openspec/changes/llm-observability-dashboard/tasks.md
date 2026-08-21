## 1. 采集层落地

- [ ] 1.1 新增 `_metrics.py: MetricsCollector`（counters 无锁递增仅 ring 用 `asyncio.Lock`；事件循环内 `dict()` 快照后 `run_in_executor` 串行 UPSERT WAL；`recent_events deque(1000)` 每条含 `latency_ms`；表 `daily_agg(date,upstream,...)` 30天 + `hourly_agg(hour,upstream,...)` 7天滑动，每 5min UPSERT + 优雅关闭再 flush，`PRAGMA journal_mode=WAL`，`0600`）
  - 验收：`grep -rn MetricsCollector _metrics.py proxy.py` 命中单例；`metrics.sqlite` 不存在时首次 `GET /_admin/metrics` 自动建表不报错；`PRAGMA journal_mode` 为 WAL，`ls -l metrics.sqlite` 为 0600

- [ ] 1.2 PII/凭据埋点（口径拆分）：`_pii.py:PiiDetector.scan` → `pii_detected_total{kind}`；`_token.py:GlobalPiiTokens.register` → `pii_cache_hit/miss`（命中复用/新建）；`TokenMixin._register_secret` + `_llm.py._redact` 快照命中 → `cred_hit/miss` + `cred_lru_evictions`（`popitem(last=False)` 淘汰分支）
  - 验收：同值连续两次：第一次 `detected+1 miss+1`，第二次 `detected+1 hit+1`；凭据达 `MAX_TOKEN_ENTRIES` 淘汰时 `cred_lru_evictions+1`；满足 `observability-metrics — 脱敏与缓存指标采集`

- [ ] 1.3 上游/Token/守门埋点：`_llm.py` handler 记录 `upstream(port/tail/stream)`、`requests_total{status}`、`latency_ms/ttft/bytes_in/out`、`empty_guarded`（`bytes_written==0` 分支）、token `usage` 归一（OpenAI/Anthropic/Responses 有则记无则 `unknown`）、`client_gone`；`recent_events` 存 `latency_ms` 支撑 p50/p95，`hourly_agg` 存 `latency_buckets`
  - 验收：`LLM_8878/8879` 各发请求后 `/_admin/metrics` 按 `upstream` 分组合计等于总量；守门注入单测 `empty_guarded+1`；`1h` 的 p95 与 ring 现场 `sorted(latency_ms)` 一致，`7d` 的 p95 为 `≈` 近似

- [ ] 1.4 审计埋点：`_audit.py:audit_tool_call` 的 `audit_by_verdict`/`audit_by_rule` 分布与 `_append_audit_log` 失败的 `audit_log_write_fail`，补充 `audit_pending_total` 与 `audit_hold_overflows`（可选）
  - 验收：`block` 命中 `rm -rf` 后 `audit_by_verdict.block+1` 且 `audit_by_rule['rm -rf']+1`；写失败注入后 `audit_log_write_fail` 递增

## 2. Admin API

- [ ] 2.1 新增 `_admin.py: AdminMixin` 并在 `proxy.py` 的 `aiohttp` 应用挂 `/_admin/*`（`metrics?range=1h|24h|7d|30d`、`events?limit&kind&upstream&verdict`、`events/stream SSE`、`health`），**首版不注册 `metrics/prometheus`**，统一 `Cache-Control: no-store` + `X-Content-Type-Options: nosniff`
  - 验收：`curl /_admin/metrics?range=1h|24h|7d|30d` 与 `/_admin/events` 返回 200 且 `range=1h` 走内存 ring 精确分位、`24h` 走 `hourly_agg`/`daily_agg` 求和；`POST /_admin/*` 返回 405；`GET /_admin/metrics/prometheus` 返回 404

- [ ] 2.2 鉴权与绑定：`X-Admin-Token` 仅认 `ADMIN_TOKEN`（不复用 `MATRIX_ACCESS_TOKEN`，`trust_proxy_headers=false` 不读 `X-Forwarded-For`），`ADMIN_TOKEN` 未设时仅 `127.0.0.1` 可访且启动打 warning，设后任意 IP 均需 token；SSE 同样鉴权；`401/405` 不泄露指标
  - 验收：非回环无 token 访问 `/_admin/metrics` 返回 401 且 body 无指标；加头后 200；回环无 token 无 `ADMIN_TOKEN` 时可访但日志有 warning；`observability-dashboard — 只读与鉴权` 全覆盖

- [ ] 2.3 聚合窗口与自动建表：`1h` 走内存 ring 精确 p95、`24h/7d` 走 `hourly_agg` 小时聚合（7天滑动）、`30d` 走 `daily_agg` 日聚合；启动时 `metrics.sqlite` 缺失自动建表（WAL+索引），30天/7天滚动删除
  - 验收：`rm metrics.sqlite` 后重启首个请求不报错且后续 `?range=7d` 与 `?range=30d` 与预期合计一致；`hourly_agg` 超 7 天行被清理

## 3. 单 HTML 实时大盘

- [ ] 3.1 新增 `admin.html` 单文件静态（内联 CSS + **内联 Chart.js ~200KB** + `Chart is not defined` 时 SVG 降级、深色风格）挂到 `/_admin/`，首帧 5 KPI（今日请求/脱敏占比/PII 命中/阻断数/p95，p95 标注 `1h精确/7d≈`）+ 时序（`1h`/`7d`/ `30d` 三档）+ 分布（PII 按 kind、上游按 port）三区
  - 验收：浏览器打开 `/_admin/` 首帧可见 5 卡与两条趋势线，数值与 `/_admin/metrics?range=24h` 合计差值为 0；`Chart.js` 未定义时图表降级为 SVG 数值仍全

- [ ] 3.2 事件表与过滤：最近事件表（`ts/request_id/upstream/pii_hits/cred_hits/tokens/verdict/latency`，数据源仅 `recent_events`，`audit.log` 仅作 `raw-tail` 排障）支持 `1h|24h|7d|30d` 窗口与 `kind/upstream/verdict` 过滤联动，点击行弹窗看脱敏摘要（`[REDACTED:<kind>]`，先脱敏后 `truncate(120)`，无明文）
  - 验收：`?verdict=block` 过滤后表与 `/_admin/events?verdict=block` 一致；弹窗不含明文 PII（`grep` 明文值命中为 0）

- [ ] 3.3 Live 实时流：前端 `EventSource /_admin/events/stream`（带 `X-Admin-Token` 鉴权）推新事件到表首，2 秒内可见
  - 验收：`Live` 开启下发新请求，完成 2 秒内表首出现新行；无 token 的 SSE 返回 401

## 4. 质量与交付

- [ ] 4.1 单测与回归：为两能力各补覆盖 `observability-metrics` 4 个 requirement 与 `observability-dashboard` 3 个 requirement 的场景单测（`pii_detected_total`/`pii_cache_hit/miss`、`empty_guarded`、`unknown tokens`、`hourly_agg`、`鉴权 401/405`、`CDN 降级` 等），全量 `pytest + ruff check + format --check` 绿
  - 验收：`pytest -q` 全 pass；`ruff check . && ruff format --check .` 0 error；`grep -rn collector\. _pii.py _token.py _llm.py _audit.py` 覆盖全部埋点文件无遗漏；`grep -rn latency_ms` 有 p95 支撑

- [ ] 4.2 文档与部署：更新 `README` 的 `/_admin` 章节（`ADMIN_TOKEN` 必填说明、回环 warning、不复用 `MATRIX_ACCESS_TOKEN`、数据留存 30天/7天、WAL 0600、不含明文声明）、`docker-compose.yml`/`docker-entrypoint.sh` 的 `ADMIN_TOKEN` 注释与示例（`DATA_DIR` 卷挂载 `metrics.sqlite`）、镜像验证回滚可删 `metrics.sqlite`
  - 验收：`README` 含 `/_admin` 鉴权与隐私声明；`docker compose config` 可见新增 env 注释；回滚镜像后服务正常且可删 `metrics.sqlite` 不影响启动
