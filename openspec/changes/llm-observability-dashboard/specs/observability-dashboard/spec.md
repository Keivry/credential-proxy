## Purpose

为 credential-proxy 提供单 HTML 轻量可视化大盘，将脱敏、上游、Token、审计等核心指标清晰美观地展示并支持按窗口/维度过滤与实时查看，适配单实例 Docker 自部署的轻量运维。

## ADDED Requirements

### Requirement: 单 HTML 实时大盘展示

系统 SHALL 提供单一静态 `admin.html`（无构建、内联 CSS、内联 `Chart.js` ~200KB，`Chart is not defined` 时降级为 SVG（`try/catch` 包初始化，不泄露脚本错误，数值/表格始终可见），首访经 `fetch('/_admin/health',{credentials:'include'})` 探测无 `__Host-admin_token` Cookie（`HttpOnly`对`document.cookie`不可见）时展示居中密码输入框 `type=password autocomplete=current-password` 回车提交 `X-Admin-Token` 校验（`fetch('/_admin/health', {headers:{'X-Admin-Token':t}})`），成功由服务端 `Set-Cookie: __Host-admin_token=...; HttpOnly; Secure(由`request.scheme`判定，仅https); SameSite=Strict; Path=/; Max-Age=3600` 写入（`admin.html` 不写 `document.cookie`）并 `history.replaceState` 清可能残留的 `?access_token`，失败 401 抖动，`http` 下 `__Host-` 拒写时仅 `ENV==dev && ALLOW_LOOPBACK_NO_TOKEN==1` 回退为普通 `admin_token`（仍 `HttpOnly`; `https` 时 `Secure`/`http` 时不带 `Secure` 否则仍拒写; `SameSite=Lax`; `Path=/; Max-Age=3600` 仅去 `__Host-` 前缀）并黄条提示 TLS（`ENV==prod` 不回退仍 401））在 `/_admin/` 下访问，首帧展示：总览 KPI 卡（今日请求、脱敏请求占比、PII 命中总数、阻断数、上游 p95 延迟，p95 标注 `1h精确(低流量≈或50 RPS+ 永≈属预期)/24h≈/7d≈/30d≈` 含 `is_precise` + `≈` 语义）、时序趋势（`1h` 细粒度/`24h` 小时粒度/`7d` 小时粒度/`30d` 日粒度，请求/token/延迟，分桶 `LATENCY_BUCKETS=[10,25,50,100,200,400,800,1500,3000,5000,10000,Inf] ms` 支撑 `p95≈` 最差约30.4% @[800,1500)（等比约33%））、类型分布（PII 按 `kind`）、上游分布（按 `port`，所有 `*_887x` 端口均暴露同鉴权 `/_admin`）、最近事件表；所有数值 SHALL 精确（个位/小数一位）且与 `/_admin/metrics` 聚合一致。不主动发 `Content-Security-Policy` 头（交由反代），禁用 `onclick` 改 `addEventListener`（所有字段经`textContent`转义防XSS）。

#### Scenario: 首帧可见且数值精确

- **WHEN** 打开 `/_admin/` 大盘
- **THEN** 首帧无需滚动即可看到 5 个 KPI 卡与至少两条趋势线，数值与 `/_admin/metrics?range=24h` 返回的合计一致（精确到 1）

#### Scenario: 内联 Chart.js 失败仍可用

- **WHEN** `Chart.js` 未定义（内联加载失败或严格 CSP `script-src 'self'` 拦内联脚本）
- **THEN** 趋势与分布自动降级为纯 SVG 条形/折线，数值与表格仍完整可用（`try/catch` 包初始化，禁用 `onclick` 改 `addEventListener`（所有字段经`textContent`转义防XSS），`style`抽`class`，所有事件字段经`textContent`或转义后入DOM防XSS（`redact_summary`仅替密钥形态，HTML标签原样透传），图表同样降级，不泄露错误栈）

#### Scenario: 窗口与维度过滤

- **WHEN** 切换 `1h | 24h | 7d | 30d` 窗口或按 `kind/upstream/verdict` 过滤
- **THEN** 图表与事件表联动刷新且请求参数与 `/_admin/metrics` 与 `/_admin/events` 的查询语义一致

### Requirement: 事件 Inspector 与实时流

系统 SHALL 提供 `GET /_admin/events?limit&kind&upstream&verdict` 的环形缓冲视图（数据源仅 `recent_events`，`audit.log` 仅作 `raw-tail` 排障，不 merge；`verdict` 过滤值域为真实实现的 `allow/deny` 两值）以及 `GET /_admin/events/stream` 的 SSE 实时推送（鉴权三选一严格优先级 `X-Admin-Token` 头优先（`hmac.compare_digest`（等长摘要）时序安全比较）> `Cookie: __Host-admin_token`（`HttpOnly; Secure(由`request.scheme`判定，仅https); SameSite=Strict; Path=/; Max-Age=3600`，`ENV==dev` 回退为 `admin_token` 仍 `HttpOnly` 且 `https` 才 `Secure`/`http` 不带 `Secure`、`SameSite=Lax`）> `?access_token` 查询参数仅作 `EventSource` 兼容回退且仅限 SSE（`?access_token` 非空且 `path != /_admin/events/stream` 无条件 `401` 不评估 header/cookie），日志掩码 `access_token`，`history.replaceState` 清 URL，且 `GET /_admin/metrics` / `/_admin/events` 带 `?access_token` SHALL 返回 `401`；SSE 限 `max 5 concurrent SSE/IP` + `60s :ping` 心跳 + `5min` 服务端 `retry` 强制断开重连，超限 `429 + Retry-After` 不泄露指标；管理接口额外 `10/min/IP` 限流超限 `429 + Retry-After`（`on_disconnect` 清理计数器防泄漏））；事件 SHALL 仅含脱敏摘要（`redact_summary(raw,120)` 先脱敏后 `truncate(120)` 的 `[REDACTED:<kind>]` 单一路径，PII 明文不落 `recent_events` 与 SSE），不含明文；事件 `sse_events` 计数按 SSE 事件块（`event:`/`id:`+`data:` 同块计 1，v0.9.23-25 同块写出），合成终止事件（`truncated`）单列不计入；点击事件 SHALL 可查看 `request_id` 级摘要（命中类型、上游、tokens、verdict、延迟）。首版 SHALL 不注册 `GET /_admin/metrics/prometheus`（请求返回 404，预留 `credential_proxy_*`）。不主动发 `CSP` 头。

#### Scenario: 事件可过滤可追溯

- **WHEN** 查询 `/_admin/events?verdict=deny&limit=20`
- **THEN** 返回最近 20 条 `deny` 事件，每条含 `ts/request_id/upstream/pii_hits/cred_hits/tokens/verdict/latency` 且不含明文

#### Scenario: 实时推送

- **WHEN** 大盘开启 `Live` 且有新请求完成
- **THEN** `/_admin/events/stream` 在 2 秒内推送新事件行到前端表首

#### Scenario: SSE 兼容鉴权

- **WHEN** 浏览器原生 `EventSource` 无法携带自定义头（`X-Admin-Token`）
- **THEN** 携带 `Cookie` 的 SSE 请求返回 200 流，仅回退时带 `?access_token` 亦返回 200；无任何凭证的 SSE 返回 401 且不推送数据；`GET /_admin/metrics?access_token=x` 与 `GET /_admin/events?access_token=x` 返回 401（非 SSE 带 `?access_token` 拒）

### Requirement: 健康检查

系统 SHALL 提供 `GET /_admin/health` 返回 `{pii_enabled, audit_mode, placeholder_prompt_enabled, metrics_age_s, sqlite_ok, ring_len, ring_coverage_s, is_precise, dropped_snapshots, first_dropped_ts, last_dropped_ts, audit_pending_total, audit_hold_overflows, truncated_total, json_aware_success, json_leaf_fallback, json_full_fallback, placeholder_prompt_injected, sqlite_error}`（`sqlite_error` 为最近 ENOSPC 等错误截断，`first_dropped_ts` 辅助排障）（`pii_enabled`/`audit_mode`/`placeholder_prompt_enabled` 来自当前进程配置，`metrics_age_s` 为距上次 flush 秒数，`sqlite_ok` 为 `SELECT 1` 探活，`ring_len/coverage/is_precise` 来自 `recent_events`（`is_precise=(now-oldest_ts)>=3600 and len>=100`），`dropped_snapshots` + `last_dropped_ts` 来自 Queue 满丢计数（递增时 `logger.warning`），`audit_pending_total/hold_overflows` 为内存 gauge 瞬态（重启归零，`health` 标注"瞬态"），`truncated_total`/`json_*`/`placeholder_prompt_injected` 为 v0.9.16-25 新基线指标，），同 `/_admin/*` 鉴权（`401` 不泄露，`401` 前不触 DB），无 `OBSERVABILITY_ADMIN_TOKEN` 时同样 `SystemExit` 前置。

#### Scenario: 健康探活

- **WHEN** 携带 `X-Admin-Token` 查询 `GET /_admin/health`
- **THEN** 返回 200 且 `sqlite_ok==true`（磁盘满 `ENOSPC`（恢复后仅从当前累计续写） 时 `sqlite_ok==false` 且 `sqlite_error` 含截断错误，不抛 500）、`ring_len` 与 `recent_events` 长度一致；无凭证返回 401 且 body 仅 `{"error":"unauthorized"}`

### Requirement: 只读与鉴权

`/_admin/*` SHALL 仅支持 `GET`（鉴权优先：未鉴权直接 `401` 不触 DB 防时序侧信道（`POST` 无 token 亦 `401` 非 `405`），鉴权中间件仅作用于 `path.startswith('/_admin/')`（其余放行），鉴权通过后非法方法才 `405 + Allow: GET`；显式覆盖 `HEAD/OPTIONS/TRACE`（`aiohttp` 默认 `HEAD` 自动降级 `GET` 需 `add_route('*', ...)` 首行 `if method!='GET': 405`），（静态 `/_admin/` 壳免鉴权，本身无数据，`Cache-Control: public`佐证；`/_admin/metrics|events|events/stream|health`全量鉴权；401不发body仅指API）响应头 `Cache-Control: no-store, no-cache, must-revalidate, private` + `Pragma: no-cache` + `X-Content-Type-Options: nosniff` + `X-Frame-Options: DENY` + `Referrer-Policy: no-referrer` + `Permissions-Policy: camera=(), microphone=(), geolocation=()`；`admin.html` 静态 `/_admin/` 单独 `Cache-Control: public, max-age=3600` + `ETag` 避免每次重传 200KB），鉴权 SHALL 仅认独立必填 `OBSERVABILITY_ADMIN_TOKEN`（建议 ≥32 字符，比较用 `hmac.compare_digest`）（`X-Admin-Token` 头优先 > `Cookie __Host-admin_token`（`HttpOnly; Secure(由`request.scheme`判定，仅https); SameSite=Strict; Path=/; Max-Age=3600`，`ENV==dev` 回退为 `admin_token` 仍 `HttpOnly` 且 `https` 才 `Secure`/`http` 不带 `Secure`、`SameSite=Lax` 仅去 `__Host-`）> `?access_token` 仅 SSE 回退（`?access_token` 非空且 `path != /_admin/events/stream` 无条件 `401`），`trust_proxy_headers=false` 不读 `X-Forwarded-For`/`X-Real-IP`/`Forwarded` 且不加载 `Forwarded` 中间件），未设时启动 `SystemExit`（`logger.critical` 明示），且启动时若与 `CREDENTIAL_ADMIN_TOKEN` / `MATRIX_ACCESS_TOKEN` / `DATA_DIR/admin_token` 文件值任一相等（空值短路 `if tok and obs==tok`）则 `SystemExit`；三 Token 完全独立、互不识别；不做裸 `127.0.0.1` 白名单（Docker/反代下不可靠），仅当 `ALLOW_LOOPBACK_NO_TOKEN=1 && os.environ.get("ENV","prod")=="dev"` 时放行 `request.remote` 经 `ipaddress.ip_address` 精确判定 `127.0.0.0/8|::1|::ffff:127.0.0.1` 且仅限 `GET`，并打 `warning`；SSE 同样鉴权（`5/IP` + `60s :ping` + `5min` 强制断开超限 `429` + `10/min/IP` 限流超限 `429 + Retry-After`）且 `401` 不泄露指标数据，新 `_admin.py` SHALL 不复用 `_credential.py:568` 的 `172.` 前缀过宽逻辑，单独 `def _is_loopback(remote)` 用 `ipaddress.ip_address` 精确判定 `127.0.0.0/8|::1|::ffff:127.0.0.1`（需显式处理 `ipv4_mapped` 转换，`ipaddress` 不自动归一）。

#### Scenario: 未鉴权被拒

- **WHEN** 未带 token 访问 `/_admin/metrics`（`OBSERVABILITY_ADMIN_TOKEN` 已设）
- **THEN** 返回 `401` 且 body 仅 `{"error":"unauthorized"}` 不含任何指标数据，且服务端未触 `metrics.sqlite`

#### Scenario: Token 独立性

- **WHEN** 使用 `CREDENTIAL_ADMIN_TOKEN` 或 `MATRIX_ACCESS_TOKEN` 或 `DATA_DIR/admin_token` 文件值访问 `/_admin/*`
- **THEN** 返回 `401`（不互相识别）；启动时若 `OBSERVABILITY_ADMIN_TOKEN` 与任一相等则进程以 `SystemExit` 退出（空值不触发）

#### Scenario: 只读约束

- **WHEN** 对 `/_admin/*` 发送 `POST/PUT/DELETE/PATCH/HEAD/OPTIONS/TRACE`（含无 token 的 `POST`）
- **THEN** 无 token 时返回 `401`（鉴权优先于 `405`）不触 DB，鉴权通过后非法方法才 `405` + `Allow: GET` 且不产生副作用；`HEAD` 显式 `405` 不自动降级 `GET`
