## Purpose

为 credential-proxy 仪表盘提供按时间桶聚合的历史序列查询能力，支撑折线图等直观趋势展示，覆盖 1h 分钟级、24h/7d 逐小时、30d 逐日的粒度。

## ADDED Requirements

### Requirement: 时间桶序列查询

系统 SHALL 提供 `GET /_admin/series?range=1h|24h|7d|30d` 接口，返回按时间桶聚合的历史序列，供前端折线图渲染。序列桶粒度 SHALL 为：`1h` → 分钟级（近 60 个分钟桶，由内存 `recent_events` 现场聚合）；`24h` → 逐小时（`hourly_agg` 24 个桶）；`7d` → 逐小时（`hourly_agg` 168 个桶）；`30d` → 逐日（`daily_agg` 30 个桶）。每桶 SHALL 包含 `{ts, requests, tokens_prompt, tokens_completion, cached_read, p95, pii_requests}`（`tokens_*`/`cached_read` 来自对应聚合的 `tokens JSON` 跨 model 求和；`p95` 来自 `latency_buckets` 分位近似，1h 档可用 ring 现场精确值；`pii_requests` 为脱敏请求数）。空桶 SHALL 返回 `requests: 0` 等零值而非缺桶。`1h` 档 SHALL 优先从内存 `recent_events` 精确聚合；内存不足（`ring_coverage` 不足以覆盖 1h）时按可用窗口返回并在 `is_precise` 标注。

#### Scenario: 各范围返回正确粒度

- **WHEN** 请求 `/_admin/series?range=1h`、`?range=24h`、`?range=7d`、`?range=30d`
- **THEN** 分别返回 60 个分钟桶、24 个小时桶、168 个小时桶、30 个日桶，每桶含 `ts/requests/tokens_prompt/tokens_completion/cached_read/p95/pii_requests`，桶数正确且时间递增

#### Scenario: 空桶补零

- **WHEN** 某时间桶内无请求（如深夜无流量）
- **THEN** 该桶仍返回 `{ts, requests: 0, ...}` 而非缺桶，序列连续

#### Scenario: 1h 分钟级由 ring 精确聚合

- **WHEN** `recent_events` 覆盖近 1h（`is_precise` 为真）
- **THEN** `1h` 序列的 60 个分钟桶与 ring 内事件逐分钟归并一致，`requests` 合计等于 ring 中近 1h 事件数，`is_precise: true`

#### Scenario: 序列支持模型/上游过滤

- **WHEN** 请求 `/_admin/series?range=24h&model=<m>&upstream=<u>`
- **THEN** 序列仅包含对应模型/上游的桶数据（model 过滤对 24h/7d/30d 历史为近似——聚合无按 model 分桶列，按 tokens JSON 键存在性近似；upstream 过滤精确按 `(date/hour, upstream)` 键）

### Requirement: 序列接口鉴权与安全

`GET /_admin/series` SHALL 与 `/_admin/*` 其他端点同鉴权（`X-Admin-Token` 头优先 > `Cookie __Host-admin_token` > `?access_token` 仅 SSE 回退，非 SSE 带 `?access_token` 返回 `401`）；未鉴权返回 `401` 且 body 仅 `{"error":"unauthorized"}` 不含任何序列数据；仅支持 `GET`（非法方法 `405 + Allow: GET`）；响应头 `Cache-Control: no-store` + `X-Content-Type-Options: nosniff` + `X-Frame-Options: DENY` 等与 `/_admin/*` 一致。

#### Scenario: 未鉴权被拒

- **WHEN** 未带 token 请求 `/_admin/series?range=24h`
- **THEN** 返回 `401` 且 body 仅 `{"error":"unauthorized"}` 不含序列数据

#### Scenario: 非法方法被拒

- **WHEN** 对 `/_admin/series` 发送 `POST`
- **THEN** 返回 `405 + Allow: GET`（未鉴权时优先 `401`）
