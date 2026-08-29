## Why

credential-proxy 仪表盘（admin.html）存在 6 个 UX/统计口径问题：模型筛选下拉只有「全部模型」且过滤不生效、不能按上游筛选、事件详情是居中 modal 而非 tooltip 式浮窗、最近事件表里 verdict 筛选/列恒为空无意义、除事件外的统计区不自动刷新、历史数据只有当前窗口单点无折线图。此外统计口径把 `v1/models` 等非对话请求也计入 requests/status/latency/tokens，污染 LLM 调用统计。

## What Changes

- **模型筛选补全**：`incr_event` 增加 `model` 参数，`_llm.py` 埋点传 `_metrics_ctx['model']`；recent_events 事件存 `model` 字段；查询端 `model_filter` 从「只过滤 tokens」扩展为「过滤 requests/status/pii/latency/audit 全指标」；前端模型下拉从 metrics 返回的 tokens 键自动填充。
- **上游筛选补齐**：事件表 `ev-upstream` change 时重新请求 `events?upstream=`；`query_range` 增加 `upstream_filter` 参数（1h 内存 ring 直接筛；DB 按 `(date/hour, upstream)` 键过滤）。
- **详情 tooltip 式 popup**：事件行 **hover** 触发 → 行旁悬浮小卡片（跟随行定位，Esc/点击外部关闭），替代居中 modal（单击改 hover 触发）。
- **人性化数字显示**：KPI/Token 四卡/分布统计值以 K/M/B 缩写显示（≥1e3 显示 `1.2K`、≥1e6 `3.4M`、≥1e9 `1.2B`，1 位小数去尾零），**hover 显示完整精确值**（`title`/tooltip）；延迟 ms 与百分比不缩写；折线图数据点与 PII kind 分布 hover 显示完整数值。
- **事件表新增 Cache% 列**：最近事件表新增「输入 token 缓存命中率」列（`cached_read / input * 100%`，input 缺省回退 prompt，分母为 0 显示 `-`，1 位小数），hover 显示 `cached_read / input` 绝对值。
- **图表 hover 精确值**：折线图数据点与 PII kind 分布 hover 显示完整精确值（Chart.js `tooltip` 回调 / SVG `<title>`），不因 K/M/B 缩写丢失精度。
- **去掉 verdict 筛选/列**：删除最近事件表的 verdict 下拉与列（LLM 事件 verdict 恒为空，无意义）。**BREAKING**（移除 `_admin/events?verdict=` 筛选参数）。
- **全区域自动刷新**：SSE 现有 2s 事件推送不变，扩展为每 15s 推送一次全量 metrics 快照（`event: metrics`），前端收到更新 KPI/图表/token 四卡/上游分布；Chart.js 改为 `update()` 增量更新避免卡顿。
- **历史折线图**：新增 `/_admin/series?range=` 返回时间桶序列（1h→分钟级 60 点内存 ring；24h/7d→hourly_agg 逐小时；30d→daily_agg 逐日），字段 `{ts, requests, tokens_prompt, tokens_completion, p95, pii_requests}`；前端趋势区改多序列折线。
- **非对话请求不统计**：`_llm.py` 埋点处非对话请求（`!is_chat_tail`）**彻底不进** recent_events 与任何聚合（requests/status/latency/tokens/脱敏全不含）。**BREAKING**（requests_total 口径变化：仅计 3 种对话端点）。

## Capabilities

### New Capabilities

- `metrics-time-series`: 历史时间桶序列查询（1h 分钟级/24h/7d 逐小时/30d 逐日），供折线图与趋势展示。仪表盘可查询任意范围的按时间聚合序列。

### Modified Capabilities

- `observability-dashboard`: 模型筛选下拉自动填充并全局生效、新增上游筛选、详情 tooltip 式 popup、移除 verdict 筛选/列、全区域 SSE 15s 自动刷新、趋势区多序列折线图。
- `observability-metrics`: `incr_event` 增加 `model` 参数；`query_range` 增加 `upstream_filter`；非对话请求（非 3 种对话端点）不进入任何统计与事件流；SSE 增加 15s 全量 metrics 快照事件；新增 `series` 时间序列端点。

## Impact

- **代码**：`admin.html`（前端筛选/弹窗/Tab/刷新/折线）、`_admin.py`（series 端点、events 去 verdict、metrics 透传 upstream/model）、`_metrics.py`（incr_event model 参数、query_range upstream_filter、非对话跳过、series 聚合）、`_llm.py`（埋点传 model、非对话跳过统计）、`_sse.py`（metrics 快照事件）。
- **API**：`GET /_admin/metrics` 新增 `upstream` 查询参数（`model` 参数已存在）；新增 `GET /_admin/series?range=&model=&upstream=`；`GET /_admin/events` 移除 `verdict` 参数（可加 `model` 过滤）；SSE 流新增 `event: metrics`。
- **数据**：recent_events 事件 schema 增加 `model` 字段；hourly_agg/daily_agg 不变（历史近似按模型过滤）。
- **测试**：新增 observability 测试（model 过滤全指标、upstream 过滤、series 序列、非对话不统计、SSE metrics 快照）；ruff check + format 必须通过。
- **兼容**：requests_total 口径变化（仅对话端点）为 **BREAKING**，README/CHANGELOG 需注明。
