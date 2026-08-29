## 1. 后端指标采集与查询（_metrics.py）

- [x] 1.1 `incr_event` 增加 `model: str = 'unknown_model'` 参数，recent_events 事件 dict 增加 `model` 键（默认 `unknown_model`）；**model 白名单/截断：`^[a-zA-Z0-9._/-]{1,64}$` 校验，超长或非法字符截断为 `unknown_model`**（防属性注入/超长）
  - 验收：`incr_event(model='gpt-4o')` 后 `recent_events[0]['model']=='gpt-4o'`；不传时 `'unknown_model'`；`model='<svg onload=alert(1)>'` 被截断为 `unknown_model`
- [x] 1.2 `query_range` 增加 `upstream_filter: str|None=None` 参数，`_query_1h` 按 `e['upstream']==upstream_filter` 过滤 ring
  - 验收：`query_range('1h', upstream_filter='8878')` 只含 `upstream=='8878'` 的事件聚合；`None` 不过滤
- [x] 1.3 `_query_db`/`_query_db_with` 增加 `upstream_filter` 参数，按 `(date/hour, upstream)==upstream_filter` 键过滤
  - 验收：`query_range('24h', upstream_filter='8878')` 只含 `(hour, '8878')` 桶；`None` 全量
- [x] 1.4 `_query_1h` 的 `model_filter` 从「只过滤 tokens」扩展为「过滤 requests/status/pii/latency/audit 全指标」（ring 事件按 `e['model']==model_filter` 过滤）
  - 验收：`query_range('1h', model_filter='gpt-4o')` 的 `requests`/`requests_by_status`/`pii_*`/`audit_*` 只含 `model=='gpt-4o'` 事件；`tokens` 只含 `gpt-4o` 键
- [x] 1.5 `_query_db`/`_query_db_with` 的 `model_filter` 历史近似：按 `tokens JSON` 内 `model_filter in tokens` 的桶求和（requests/status/pii/latency 近似，tokens 精确）
  - 验收：`query_range('24h', model_filter='gpt-4o')` 的 `tokens` 只含 `gpt-4o` 键；requests 按 tokens 含该 model 的桶求和；文档标注「≈」
- [x] 1.6 新增 `series(range_, model_filter=None, upstream_filter=None)` 方法：`1h` 从 `recent_events` 按分钟桶（`ts//60`）归并（精确），`24h/7d` 从 `hourly_agg` 按小时桶，`30d` 从 `daily_agg` 按日桶；每桶 `{ts, requests, tokens_prompt, tokens_completion, cached_read, p95, pii_requests}`；空桶补零；返回 `{buckets, is_precise}`；**ring 扫描在 `_lock` 内同步快照 `list(recent_events)` 后释放锁再计算（防锁外读撕裂）**
  - 验收：`series('1h')` 返回 60 个分钟桶且 `sum(requests)==ring 近 1h 事件数`；`series('24h')` 返回 24 桶；`series('30d')` 返回 30 桶；无流量桶 `requests:0` 不缺桶

## 2. 后端 LLM 埋点（_llm.py）

- [x] 2.1 `_llm.py` 埋点处（5697 `incr_event` 调用）增加 `model=_metrics_ctx.get('model', 'unknown_model')` 参数
  - 验收：`incr_event` 收到 `model` 字段；事件行含 model
- [x] 2.2 `_llm.py` 埋点处 `if not is_chat_tail(tail): 直接 return`（非对话请求不调 `incr_event`、不进 recent_events、不进聚合）
  - 验收：`v1/models` 请求后 `recent_events` 长度不变、`requests` 不增、无聚合记录；`chat/completions` 正常计数
- [x] 2.3 确认 `_metrics_ctx['model']` 在非对话路径也正确设置（或非对话直接 return 前无需设置）；判定函数统一用 `is_chat_tail`（`_llm.py:184` 已有）
  - 验收：非对话请求不触发任何埋点副作用；对话请求 model 正确

## 3. 后端管理 API（_admin.py + _sse.py）

- [x] 3.1 `_admin.py` 新增 `GET /_admin/series?range=&model=&upstream=` 路由，调用 `Metrics.series(...)`，响应 `{buckets, is_precise}`，与 `/_admin/*` 同鉴权（401 不泄露、仅 GET、no-store 头）
  - 验收：`curl -H "X-Admin-Token: t" /_admin/series?range=24h` 返回 24 桶 JSON；无 token 401；POST 405；`?model=&upstream=` 透传生效
- [x] 3.2 `_admin.py` `events()` 删除 `verdict` 参数，新增 `model` 参数（`e.get('model')==model` 过滤，`None` 不过滤）
  - 验收：`events(limit, kind, upstream, model)` 签名无 verdict 有 model；`?verdict=` 被忽略或 400；`?model=gpt-4o` 只返回该 model 事件
- [x] 3.3 `_admin.py` `GET /_admin/metrics` 透传 `upstream` 查询参数到 `query_range(upstream_filter=...)`
  - 验收：`curl /_admin/metrics?range=24h&upstream=8878` 只含 8878 聚合
- [x] 3.4 `_admin.py` `GET /_admin/metrics` 透传 `model` 查询参数（已存在 `model_filter`，确认参数名一致）
  - 验收：`curl /_admin/metrics?range=1h&model=gpt-4o` 全局过滤生效
- [x] 3.5 `_sse.py` 增加 15s 定时器推送 `event: metrics`（data 为 `query_range(当前range) + series + health` 合并 JSON）；2s 事件推送不变
  - 验收：SSE 连接 15s 内收到 `event: metrics` 且含 `metrics`/`series`/`health` 数据；事件仍 2s 推

## 4. 前端 admin.html

- [x] 4.1 模型下拉自动填充：选项从 `query_range` 返回的 `tokens` 键 + 事件行 `model` 去重生成；`unknown_model` 映射「未知模型」；按请求量降序；超长 `text-overflow:ellipsis` + `title` 完整值；无数据仅「全部模型」且下拉 `disabled`
  - 验收：加载后下拉含 `gpt-4o`/`gpt-4o-mini` 等已见模型；`unknown_model` 显示「未知模型 (unknown)」；选模型触发 `loadAll()` 重查且**事件表同步按 `events?model=` 联动刷新**
- [x] 4.2 新增上游下拉（`ev-upstream` change 时重新请求 `events?upstream=`；metrics 查询带 `upstream` 参数）
  - 验收：选上游后事件表与 KPI/图表联动刷新；「全部上游」不过滤
- [x] 4.3 事件详情改 tooltip 式浮窗：点击行 → 行旁绝对定位浮窗（JSON 摘要），Esc/点击外部关闭；删除居中 modal
  - 验收：点击事件行显示浮窗且定位跟随行；Esc 关闭；浮窗含 model/tokens/latency
- [x] 4.4 删除 verdict 下拉与表格列
  - 验收：事件表无 verdict 列；无 verdict 筛选 UI
- [x] 4.5 SSE 收到 `event: metrics` 时更新 KPI/图表/token 四卡/上游分布（不重建事件表）；**SSE 断开时启动 `setInterval(fetchMetrics, 15000)` 轮询回退，`onopen` 时清除**
  - 验收：15s 内 KPI 数字自动变化（有新请求时）；事件表仍 2s 实时；SSE 断开 3s 后 KPI 仍通过轮询刷新
- [x] 4.6 Chart.js 从 `destroy()+new` 改为 `chart.data=...; chart.update()` 增量更新；趋势区改多序列折线（requests/tokens_prompt/tokens_completion/p95）；`tension:0.3` 平滑 + 空桶 `spanGaps:false` 虚线提示（1h→24h 粒度跳变 60→24 点过渡）；图例旁持续显示 `is_precise≈` 标注
  - 验收：图表更新不重建实例（无闪烁）；趋势区显示多序列折线；切 range 平滑过渡
- [x] 4.7 趋势区折线图接入 `/_admin/series`（1h 60 点分钟级 / 24h 24 点 / 7d 168 点 / 30d 30 点）
  - 验收：切换 range 后趋势图显示对应粒度的历史曲线；数据来自 series 端点
- [x] 4.8 SVG 降级保持：Chart.js 未定义时趋势区仍显示 SVG 折线/条形（含 series 数据）；新增 `renderTrendSVG(buckets)` 用 `svg polyline points` 归一化 requests 到视口，`buckets.forEach` 追加 `circle + <title>精确值</title>`；PII/上游分布复用 `renderBar` SVG
  - 验收：禁用 Chart.js 后趋势图仍有 SVG 折线渲染（非文本），数据点 hover 显示精确值；数值/表格完整
- [x] 4.9 新增 `fmtNum(n)` 工具函数（≥1e9 `1.2B`、≥1e6 `3.4M`、≥1e3 `1.2K`，1 位小数去尾零；<1e3 原样），KPI 卡/token 四卡/分布表用缩写显示，元素 `title` 存完整精确值；延迟 ms 与百分比不缩写；**全部渲染走 `textContent`/`createTextNode`/`title` 属性赋值，禁止 `innerHTML`/`outerHTML`/`insertAdjacentHTML`**（model 名、request_id 等字符串字段同样转义）；**unknown>20% 黄条保留且与 fmtNum 共存不冲突**
  - 验收：`fmtNum(1234567)` 返回 `1.2M`；`fmtNum(999)` 返回 `999`；`fmtNum(999999)` 返回 `1M`（非 `1000K`）、`fmtNum(1000)` 返回 `1K`、`fmtNum(1500)` 返回 `1.5K`、`fmtNum(1499)` 返回 `1.5K`（四舍五入）、`fmtNum(999500)` 返回 `1M`（进位）；KPI 卡显示缩写且 hover 显示精确值；p95/占比不缩写；`grep innerHTML admin.html` 0 命中；unknown>20% 黄条正常显示
- [x] 4.10 事件详情浮窗改 hover 触发：`mouseenter` 延迟 200ms 显示、`mouseleave` 延迟 150ms 关闭（移入浮窗本体不关闭；点击可固定），浮窗跟随行定位；`Esc`/点击外部/`scroll` 立即关闭；触屏 `@media(hover:none)` 禁用 hover 自动显示，tap 行固定
  - 验收：鼠标悬停事件行 200ms 后显示浮窗，移出关闭；浮窗含 model/tokens/latency；Esc 关闭；触屏 tap 显示
- [x] 4.11 折线图数据点与 PII kind 分布 hover 显示完整精确值（Chart.js `tooltip.callbacks.label` 精确值 + SVG `<title>` 降级）
  - 验收：悬停折线图数据点显示该桶完整数值（如 `1,234,567`）；悬停 PII kind 显示完整计数与占比
- [x] 4.12 事件表新增 Cache% 列（输入 token 缓存命中率）：`cached_read/input*100%`，1 位小数；input 缺省回退 prompt；分母 0 或 usage 缺失显示 `-`；hover 显示 `cached_read / input` 绝对值
  - 验收：有 usage 事件行显示命中率（如 `83.4%`），hover 显示 `12345 / 14800`；无 usage 行显示 `-`

## 5. 测试与验证

- [x] 5.1 新增 `tests/observability_series_test.py`：series 各范围粒度、空桶补零、1h 分钟级精确、model/upstream 过滤、`is_precise` 翻转（ring 未覆盖 1h 时 `false` 且桶数为可用窗口）、跨日/跨小时空桶补零
  - 验收：pytest 通过；`sum(requests)==ring 事件数` 断言成立；空桶 `requests:0` 不缺桶；`is_precise` 翻转断言成立
- [x] 5.2 新增 `tests/observability_model_filter_test.py`：model 过滤全指标（1h 精确）、历史近似（24h tokens 键存在性）
  - 验收：pytest 通过；1h 过滤后 requests/requests_by_status/pii_*/audit_* 只含该 model 事件；`unknown_model` 事件过滤；24h tokens 只含指定 model 键（反向用例）
- [x] 5.3 新增 `tests/observability_upstream_filter_test.py`：upstream 过滤（1h ring + 24h DB）
  - 验收：pytest 通过；过滤后聚合只含指定 upstream；metrics+events+series 三端一致
- [x] 5.4 新增 `tests/observability_non_dialog_test.py`：非对话请求（`v1/models`/`v1/embeddings`/`health` 等非 3 端点全量）不进 recent_events/聚合/事件流；`is_chat_tail` 的 `rstrip('/')` 边界（`/v1/responses/`）
  - 验收：pytest 通过；非对话请求后指标不变；`/v1/responses/` 判定为对话
- [x] 5.5 新增 `tests/observability_sse_metrics_test.py`：SSE 15s `event: metrics` 快照（单 writer 无并发写、range 绑定回显、切 range 后丢弃旧窗口快照、断开重连、限流 5/IP/429）
  - 验收：pytest 通过；15s 内收到 metrics 快照且含 metrics/series/health；`event: metrics` 与 `event: event` 不交织；切 range 后 15s 内不收到旧窗口快照覆盖
- [x] 5.6 全量回归：`pytest`（现有 132+ 新增）+ `ruff check` + `ruff format --check` 全过；**同步更新 `tests/observability_admin_test.py:263` 的 `model_filter kwonly` 断言兼容新增 `upstream_filter` kwonly 参数**
  - 验收：pytest 全绿；ruff check + format --check 无错误

## 6. 文档与发布

^- [x] 6.1 README 更新：requests_total 口径变化（仅对话端点，BREAKING）、series 端点、SSE 15s 快照、verdict 移除
  - 验收：README 含口径变化说明与 series 端点文档
^- [x] 6.2 CHANGELOG 更新：v0.9.35（或下一版本）记录 6 大修复
  - 验收：CHANGELOG 有对应条目
^- [x] 6.3 版本 bump（pyproject.toml + docker-compose image tag + uv.lock + README changelog）+ commit + tag + push 触发 CI
  - 验收：git tag v0.9.35 推送后 GitHub Actions 构建成功
