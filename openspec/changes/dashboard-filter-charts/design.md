## Context

See proposal.md — Why for motivation. Current state (v0.9.34): 前端 `admin.html` 是单 HTML 静态文件（内联 Chart.js + SVG 降级），`_admin.py` 提供 `/_admin/metrics|events|events/stream|health`；`_metrics.py` 的 `MetricsCollector` 维护 `recent_events` 环形缓冲（deque 10000）+ `_daily`/`_hourly` 内存聚合（主键 `(date/hour, upstream)`）+ SQLite `daily_agg`/`hourly_agg` 冷聚合（WAL，5min 快照）。现有查询端 `query_range(range_, model_filter)` 的 `model_filter` 只过滤 `tokens` 字典，其余指标（requests/status/pii/latency/audit）不过滤；`events()` 支持 `upstream`/`verdict`/`kind` 过滤；SSE 每 2s 只推新事件；前端趋势图是「当前窗口单点」不是时间序列。**关键约束**：审批事件走 `incr_sync_audit`（只进审计聚合与 `audit_log_ring`），**不进入 recent_events**；`_llm.py` 埋点处 `is_chat_tail` 判定 3 种对话端点，非对话请求 `_upstream` 归 `other` 但仍全量 `incr_event` 计数。

## Goals / Non-Goals

**Goals:**
- 模型筛选全局生效（1h 精确、24h/7d/30d 近似），下拉自动填充
- 上游筛选补齐（events + metrics + series 全支持）
- 事件详情 tooltip 式浮窗（替代居中 modal）
- 移除 verdict 筛选/列（LLM 事件恒空，无意义）
- 全区域 15s 自动刷新（SSE metrics 快照 + Chart.js `update()` 增量）
- 历史折线图（1h 分钟级 60 点 / 24h / 7d 逐小时 / 30d 逐日）
- 非对话请求（`!is_chat_tail`）彻底不进统计与事件流

**Non-Goals:**
- 不改审计埋点（审批事件仍不进 recent_events）
- 不做按 model 的历史分桶列（24h/7d/30d 模型过滤近似）
- 不做多上游对比图 / 导出 / 告警
- 不引入新前端框架（保持单 HTML 内联）

## Decisions

### D1: `incr_event` 增加 `model` 参数，recent_events 存 `model` 字段

**决定**：`_metrics.py: incr_event(..., model: str = 'unknown_model')`，`_llm.py` 埋点处传 `_metrics_ctx.get('model', 'unknown_model')`；recent_events 事件 dict 增加 `model` 键。
**理由**：模型是成本归因核心维度；事件行带 model 才能支持事件表按模型筛 + 详情展示。
**备选**：从 `tokens` 字典推导（`tokens` 键就是 model）——但 `tokens` 可能为空（无 usage），事件仍应有 model；且非对话请求已跳过，模型语义更干净。选显式参数。

### D2: `model_filter` 扩展为全局过滤（1h 精确 + 历史近似）

**决定**：`_query_1h` 在 `recent_events` 扫描时按 `e.get('model')==model_filter` 过滤（精确）；`_query_db`/`_query_db_with` 对 24h/7d/30d 按 `tokens JSON` 内 `model_filter in tokens` 的桶求和（近似——无按 model 分桶列，用 tokens 键存在性近似请求归属）。
**理由**：1h 有事件级 model 字段可精确；历史聚合无 model 列，加列需全量重算 + DB 迁移，收益低。近似口径在文档标注。
**备选**：给 hourly/daily 加 `models JSON` 列记录每 model 请求数——需迁移 + 全量重算历史，且与现有 5min 快照叠加逻辑冲突。否决。

### D3: `query_range` 增加 `upstream_filter` 参数

**决定**：`query_range(range_, model_filter=None, upstream_filter=None)`；`_query_1h` 按 `e['upstream']==upstream_filter` 过滤 ring；`_query_db`/`_query_db_with` 按 `(date/hour, upstream)==upstream_filter` 键过滤（精确，聚合主键本来就有 upstream）。
**理由**：聚合主键 `(date/hour, upstream)` 天然支持上游切片，改动小、精确。与模型过滤组合使用（AND 语义）。
**备选**：查询时按 tokens 键猜上游——不靠谱。否决。

### D4: 非对话请求彻底跳过统计

**决定**：`_llm.py` 埋点处 `if not is_chat_tail(tail): 直接 return`（不调 `incr_event`、不进 recent_events、不进聚合）；`incr_event` 不加 `is_dialog` 参数（调用方已过滤）。判定函数统一用 `is_chat_tail`（`_llm.py:184` 已有）。
**理由**：`_llm.py` 是唯一埋点入口，在源头过滤最干净；`incr_event` 保持纯统计函数不关心业务语义。requests_total 口径变化在 README/CHANGELOG 标注 BREAKING。
**备选**：`incr_event` 加 `is_dialog` 参数内部跳过——多一层参数，且 `_audit.py` 的 `incr_sync_audit` 不受影响（审批本来就不进 recent_events）。源头过滤更简单。

### D5: 事件详情 tooltip 式浮窗（hover 触发 + 点击固定）

**决定**：事件行浮窗以 **hover 触发为主**（`mouseenter` 显示、`mouseleave` 关闭，移入浮窗本体不关闭），**点击行可固定**（再点/Esc 关闭）；浮窗渲染在行右侧/下方绝对定位（`position:absolute` + 相对行坐标），内容为 `request_id` 级摘要（**`redact_summary(raw,120)` 脱敏后 JSON 格式化**，`__PII_*__`/`__VG_CRED_*__` 占位符原样保留，不还原明文）；Esc/点击外部/滚动关闭；替代现有居中 modal（`.modal` + `.modal-box`）。
**理由**：用户明确要 tooltip 式（贴近查看），居中 modal 打断视线；纯 CSS + 少量 JS，无新依赖。
**备选**：保留居中 modal 改样式——不符合用户诉求。否决。

### D6: 移除 verdict 筛选/列

**决定**：前端删除 verdict 下拉与表格列；`_admin.py` `events()` 删除 `verdict` 参数（后端同时移除，避免死参数）。LLM 事件 `verdict` 恒为空（`_metrics_ctx['verdict']` 初始化后无写入），保留无意义。
**理由**：用户确认 + 代码实证（`_llm.py` 无任何 `_metrics_ctx['verdict']` 赋值）。
**备选**：保留但隐藏——死代码。否决。

### D7: SSE 每 15s 推全量 metrics 快照（自动刷新）

**决定**：`_sse.py` 现有 2s 事件推送不变，在主循环内以 `now - last_metrics >= 15` 分支**顺序写入** `event: metrics`（**不另起 task，单 writer 避免并发写 `StreamResponse` 交织**），data 为 `query_range`（SSE 建连时绑定的 range/model/upstream）+ `series` + `health` 的合并 JSON，且快照 JSON 回显 `range` 字段；前端收到 `event: metrics` 时先校验 `data.range === state.range`（不一致则丢弃，防旧窗口覆盖新窗口——复用 `loadSeq` 思想）再更新 KPI/图表/token 四卡/上游分布（不重建事件表）。前端 `state.range/model/upstream` 任一变化时 `restartLive()` 重建 SSE（`es.close(); connect(newUrl)`）。
**理由**：SSE 常开连接复用，无 HTTP 建连开销；15s 频率对 SQLite 查询压力可忽略（数据量小）；事件仍 2s 实时。**性能关键**：前端 Chart.js 必须从 `destroy()+new` 改为 `chart.data = ...; chart.update()` 增量更新，否则 15s 一次重建会卡。
**备选**：前端 `setInterval(fetchMetrics, 15000)` 轮询——多 3-4 个 HTTP 请求/15s，且与 SSE 竞争；SSE 单连接更优雅。选 SSE。
**备选2**：`event: metrics` 只推增量 diff——复杂度高，全量 JSON 才几 KB，无必要。

### D8: 历史折线图 + `/_admin/series` 端点

**决定**：新增 `GET /_admin/series?range=&model=&upstream=` 返回 `{buckets: [{ts, requests, tokens_prompt, tokens_completion, cached_read, p95, pii_requests}], is_precise}`；前端趋势区用 Chart.js line 画 requests/tokens_prompt/tokens_completion/p95 多序列。
**实现**：
- `1h`：从 `recent_events` 按分钟桶（`ts//60`）归并（精确，is_precise 由 ring 覆盖决定）
- `24h`/`7d`：`hourly_agg` 按小时桶（tokens JSON 跨 model 求和；p95 从 latency_buckets 分位）
- `30d`：`daily_agg` 按日桶
**理由**：聚合表本来就有时间键，序列查询是纯读聚合；1h 分钟级从 ring 现算成本低（10000 条内）。
**备选**：前端从 `query_range` 单点画柱状——没有历史维度。否决。

### D9: 模型下拉自动填充

**决定**：前端 model 下拉选项从 `query_range` 返回的 `tokens` 键（`Object.keys(tokens)`）+ 事件行的 `model` 去重生成；无数据时仅「全部模型」。不做独立 `/_admin/models` 端点（避免多一次请求）。
**理由**：`tokens` 键就是已见模型全集（成本归因维度），事件行 model 补充无 usage 请求的模型；一个数据源即可。
**备选**：独立 models 端点——多一次往返 + 缓存失效逻辑。否决。

### D10: 人性化数字缩写 + hover 精确值

**决定**：前端加 `fmtNum(n)` 工具函数：`≥1e9 → 1.2B`、`≥1e6 → 3.4M`、`≥1e3 → 1.2K`（1 位小数去尾零），`<1e3` 原样；KPI 卡/token 四卡/分布表用 `fmtNum` 显示缩写，元素 `title`/tooltip 存完整精确值（`textContent` 缩写 + `title` 精确）；延迟 ms 与百分比**不缩写**（`p95` 保持 `1234ms`，脱敏占比保持 `83.4%`）；折线图数据点与 PII kind 分布 hover 显示完整精确值（Chart.js `tooltip.callbacks.label` 返回精确值，SVG 降级用 `<title>`）。**`title` 仅用于数值精确值，不用于展示 PII 原文**（脱敏占位符 `__PII_*__`/`__VG_CRED_*__` 原样保留，不还原明文）；model 名等字符串字段同样 `textContent` 赋值，`title` 属性赋值禁止拼接 HTML。
**理由**：数据精确型用户——缩写提升可读性，hover 保证查数不失真；延迟/百分比是量纲敏感的，缩写会造成误解。
**备选**：切换开关（精确/缩写）——多一个 UI 状态，hover 已满足。否决。

### D11: 事件详情 hover 触发（tooltip）— 与 D5 合并

**说明**：D5 已整合 hover 触发与点击固定，本决策并入 D5（避免双轨定义）。触发细节：行 `mouseenter` 延迟 200ms 显示浮窗（避免与 Cache%/KPI `title` 气泡冲突），`mouseleave` 延迟 150ms 关闭（移入浮窗本体则取消关闭）；`Esc`/点击外部/`scroll` 立即关闭；触屏 `@media(hover:none)` 下 hover 自动显示禁用，tap 行固定显示。

### D12: 事件表 Cache% 列（输入 token 缓存命中率）

**决定**：最近事件表新增 Cache% 列，值 = `cached_read / input * 100%`（1 位小数）；input 缺失时回退 prompt；两者均缺失或分母 0 显示 `-`；hover 显示 `cached_read / input` 绝对值。事件行已有 `tokens`（含 cached_read/cached_write），前端现场计算，无需后端新聚合。
**理由**：缓存命中按折扣价计费，是成本核算关键指标，用户明确要求；事件行数据已具备，改动最小。
**备选**：`cached_read / (cached_read + input)` — 与现有 token 分桶语义不一致，否决。

## Risks / Trade-offs

- [requests_total 口径变化（BREAKING）] → README/CHANGELOG 标注；`other` 上游不再有非对话请求，历史对比时需注意口径差异。**历史桶策略（选 A）**：仅新数据生效——`daily_agg`/`hourly_agg` 中 `(date/hour, other)` 已混入 v0.9.34 及之前的非对话请求，change 后不再写入；不做 DELETE/迁移（避免丢失 other 真实对话数据），README 注明「24h/7d/30d 窗口在滚动排出前含历史非对话，对比以 1h 精确窗口为准」；前端 24h/7d/30d 窗口的 `other` 上游显示「≈含历史非对话」标注
- [24h/7d/30d 模型过滤近似] → 标注「≈」；tokens JSON 键存在性可能漏掉无 usage 请求的模型（事件级 model 只对 1h 精确）
- [SSE 15s 全量快照带宽] → 全量 JSON 仅几 KB（60 桶 × 7 字段），15s 频率可忽略；Chart.js `update()` 增量避免重渲染卡顿
- [series 1h 从 ring 现算的 CPU] → ring ≤10000 条，分钟归并 O(n)，每 15s 一次可忽略；放 `asyncio.to_thread` 防阻塞事件循环
- [移除 verdict 参数破坏下游] → 内部仪表盘无外部消费者；README 注明
- [model 字段仅新事件有] → 旧 recent_events 无 model（重启即清空，无持久化），无兼容问题

## Migration Plan

1. 代码改动：`_metrics.py`（incr_event model + query_range upstream_filter + series 聚合 + 非对话已在源头过滤）、`_llm.py`（埋点传 model + 非对话 return）、`_admin.py`（series 端点 + events 去 verdict + metrics 透传 model/upstream）、`_sse.py`（15s metrics 快照）、`admin.html`（下拉/浮窗/折线/SSE 处理）
2. 测试：新增 observability 测试（model 过滤、upstream 过滤、series 序列、非对话不统计、SSE metrics 快照）；`pytest` + `ruff check + format --check` 必过
3. 部署：镜像构建发布（v0.9.35+），`docker compose pull + up -d`
4. 回滚：git revert 到 v0.9.34；DB schema 不变（无迁移），回滚零风险。历史桶数据不迁移不删除，仅文档标注口径变化

## Open Questions

无——所有口径问题已与用户确认（tooltip 浮窗、去 verdict、15s 刷新、1h 分钟级、非对话彻底不计入、不进事件流）。
