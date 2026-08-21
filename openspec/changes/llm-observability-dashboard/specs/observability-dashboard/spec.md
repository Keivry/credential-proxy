## Purpose

为 credential-proxy 提供单 HTML 轻量可视化大盘，将脱敏、上游、Token、审计等核心指标清晰美观地展示并支持按窗口/维度过滤与实时查看，适配单实例 Docker 自部署的轻量运维。

## ADDED Requirements

### Requirement: 单 HTML 实时大盘展示

系统 SHALL 提供单一静态 `admin.html`（无构建、内联 CSS、内联 `Chart.js` ~200KB，`Chart is not defined` 时降级为 SVG）在 `/_admin/` 下访问，首帧展示：总览 KPI 卡（今日请求、脱敏请求占比、PII 命中总数、阻断数、上游 p95 延迟，p95 标注 `1h精确/7d≈`）、时序趋势（`1h` 细粒度/`7d` 小时粒度/`30d` 日粒度，请求/token/延迟）、类型分布（PII 按 `kind`）、上游分布（按 `port/url`）、最近事件表；所有数值 SHALL 精确（个位/小数一位）且与 `/_admin/metrics` 聚合一致。

#### Scenario: 首帧可见且数值精确

- **WHEN** 打开 `/_admin/` 大盘
- **THEN** 首帧无需滚动即可看到 5 个 KPI 卡与至少两条趋势线，数值与 `/_admin/metrics?range=24h` 返回的合计一致（精确到 1）

#### Scenario: CDN 失败仍可用

- **WHEN** `Chart.js` 未定义（内联加载失败）
- **THEN** 趋势与分布自动降级为纯 SVG 条形/折线，数值与表格仍完整可用

#### Scenario: 窗口与维度过滤

- **WHEN** 切换 `1h | 24h | 7d | 30d` 窗口或按 `kind/upstream/verdict` 过滤
- **THEN** 图表与事件表联动刷新且请求参数与 `/_admin/metrics` 与 `/_admin/events` 的查询语义一致

### Requirement: 事件 Inspector 与实时流

系统 SHALL 提供 `GET /_admin/events?limit&kind&upstream&verdict` 的环形缓冲视图（数据源仅 `recent_events`，`audit.log` 仅作 `raw-tail` 排障，不 merge）以及 `GET /_admin/events/stream` 的 SSE 实时推送（同 `X-Admin-Token` 鉴权）；事件 SHALL 仅含脱敏摘要（先脱敏后 `truncate(120)` 的 `[REDACTED:<kind>]`），不含明文；点击事件 SHALL 可查看 `request_id` 级摘要（命中类型、上游、tokens、verdict、延迟）。首版 SHALL 不注册 `GET /_admin/metrics/prometheus`（请求返回 404）。

#### Scenario: 事件可过滤可追溯

- **WHEN** 查询 `/_admin/events?verdict=block&limit=20`
- **THEN** 返回最近 20 条 `block` 事件，每条含 `ts/request_id/upstream/pii_hits/cred_hits/tokens/verdict/latency` 且不含明文

#### Scenario: 实时推送

- **WHEN** 大盘开启 `Live` 且有新请求完成
- **THEN** `/_admin/events/stream` 在 2 秒内推送新事件行到前端表首

### Requirement: 只读与鉴权

`/_admin/*` SHALL 仅支持 `GET`（写方法返回 `405`），响应头 `Cache-Control: no-store` + `X-Content-Type-Options: nosniff`；鉴权 SHALL 仅认独立 `ADMIN_TOKEN`（`X-Admin-Token` 头，`trust_proxy_headers=false` 不读 `X-Forwarded-For`），`ADMIN_TOKEN` 未设时仅 `127.0.0.1` 可访且启动打 warning，设后任意 IP 均需 token；SSE 同样鉴权；未鉴权访问 SHALL 返回 `401` 且不泄露指标数据。

#### Scenario: 未鉴权被拒

- **WHEN** 未带 token 从非回环地址访问 `/_admin/metrics`（`ADMIN_TOKEN` 已设）
- **THEN** 返回 `401` 且 body 不含任何指标数据；`ADMIN_TOKEN` 未设时回环可访但日志含 warning

#### Scenario: 只读约束

- **WHEN** 对 `/_admin/*` 发送 `POST/PUT/DELETE`
- **THEN** 返回 `405` 且不产生副作用
