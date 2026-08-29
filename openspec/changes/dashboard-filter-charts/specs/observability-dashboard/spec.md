## MODIFIED Requirements

### Requirement: 单 HTML 实时大盘展示
系统 SHALL 提供单一静态 `admin.html`（无构建、内联 CSS、内联 `Chart.js` ~200KB，`Chart is not defined` 时降级为 SVG（`try/catch` 包初始化，不泄露脚本错误，数值/表格始终可见），首访经 `fetch('/_admin/health',{credentials:'include'})` 探测无 `__Host-admin_token` Cookie（`HttpOnly`对`document.cookie`不可见）时展示居中密码输入框 `type=password autocomplete=current-password` 回车提交 `X-Admin-Token` 校验（`fetch('/_admin/health', {headers:{'X-Admin-Token':t}})`），成功由服务端 `Set-Cookie: __Host-admin_token=...; HttpOnly; Secure(由`request.scheme`判定，仅https); SameSite=Strict; Path=/; Max-Age=3600` 写入（`admin.html` 不写 `document.cookie`）并 `history.replaceState` 清可能残留的 `?access_token`，失败 401 抖动，`http` 下 `__Host-` 拒写时仅 `ENV==dev && ALLOW_LOOPBACK_NO_TOKEN==1` 回退为普通 `admin_token`（仍 `HttpOnly`; `https` 时 `Secure`/`http` 时不带 `Secure` 否则仍拒写; `SameSite=Lax`; `Path=/; Max-Age=3600` 仅去 `__Host-` 前缀）并黄条提示 TLS（`ENV==prod` 不回退仍 401））在 `/_admin/` 下访问，首帧展示：总览 KPI 卡（今日请求、脱敏请求占比、PII 命中总数、阻断数、上游 p95 延迟，p95 标注 `1h精确(低流量≈或50 RPS+ 永≈属预期)/24h≈/7d≈/30d≈` 含 `is_precise` + `≈` 语义）、时序趋势折线图（`1h` 分钟级 60 点/`24h` 小时粒度/`7d` 小时粒度/`30d` 日粒度，请求/token/延迟/p95/pii_requests 多序列，分桶 `LATENCY_BUCKETS=[10,25,50,100,200,400,800,1500,3000,5000,10000,Inf] ms` 支撑 `p95≈` 最差约30.4% @[800,1500)（等比约33%））、类型分布（PII 按 `kind`）、上游分布（按 `port`，所有 `*_887x` 端口均暴露同鉴权 `/_admin`）、最近事件表；所有数值 SHALL 精确（个位/小数一位）且与 `/_admin/metrics` 聚合一致。**Token 成本核算展示 SHALL 包含输入/输出/缓存命中三维度**：大盘 SHALL 展示「输入 tokens」「输出 tokens」「缓存命中 tokens（cached_read，成本核算关键，按折扣价计费）」「缓存写入 tokens（cached_write，仅 Anthropic 有值时展示，按写入价计费区别于命中折扣价）」合计与趋势（可切换 `1h|24h|7d|30d`），缓存命中 token 与输入/输出 token 分开展示（成本占比可视化），支持按 `upstream` 查看各上游的 token 成本结构。**Token 成本按 model 归因**：大盘 SHALL 提供按 `model` 的 token 分布（`tokens JSON` 按 model 分桶，无 model 记 `unknown_model`），展示各模型输入/输出/缓存命中 token 合计，支撑成本归因（`gpt-4o` vs `gpt-4o-mini` 单价差 20x）。**usage 缺失告警**：当窗口内 `unknown` 占比 >20% 时大盘 SHALL 显示黄条警告「缓存命中/成本核算失真，n% 请求无 usage」，不做估算补值。不主动发 `Content-Security-Policy` 头（交由反代），禁用 `onclick` 改 `addEventListener`（所有字段经`textContent`转义防XSS）。

#### Scenario: 首帧可见且数值精确

- **WHEN** 打开 `/_admin/` 大盘
- **THEN** 首帧无需滚动即可看到 5 个 KPI 卡与至少两条趋势线，数值与 `/_admin/metrics?range=24h` 返回的合计一致（精确到 1）；KPI/Token/分布统计值以 K/M/B 缩写显示（≥1e3 `1.2K`、≥1e6 `3.4M`、≥1e9 `1.2B`，1 位小数去尾零），**hover 显示完整精确值**（`title`/tooltip）；延迟 ms 与百分比不缩写

#### Scenario: 内联 Chart.js 失败仍可用

- **WHEN** `Chart.js` 未定义（内联加载失败或严格 CSP `script-src 'self'` 拦内联脚本）
- **THEN** 趋势与分布自动降级为纯 SVG 条形/折线，数值与表格仍完整可用（`try/catch` 包初始化，禁用 `onclick` 改 `addEventListener`（所有字段经`textContent`转义防XSS），`style`抽`class`，所有事件字段经`textContent`或转义后入DOM防XSS（`redact_summary`仅替密钥形态，HTML标签原样透传），图表同样降级，不泄露错误栈）

#### Scenario: 窗口与维度过滤

- **WHEN** 切换 `1h | 24h | 7d | 30d` 窗口或按 `kind/upstream/model` 过滤（`verdict` 已移除）
- **THEN** 图表与事件表联动刷新且请求参数与 `/_admin/metrics` 与 `/_admin/events` 的查询语义一致

#### Scenario: 缓存命中 token 成本展示

- **WHEN** 大盘加载（有 token usage 数据的窗口）
- **THEN** 首帧可见「输入 tokens / 输出 tokens / 缓存命中 tokens / 缓存写入 tokens（仅 Anthropic 有值时）」四卡（或一卡四值），趋势图含缓存命中 token 序列，且合计与 `/_admin/metrics` 的 `tokens JSON`（`prompt/completion/cached_read/cached_write`）一致；按 `upstream` 过滤后各上游 token 成本结构独立显示；按 `model` 过滤后各模型 token 分桶可见（`unknown_model` 单列）；窗口内 `unknown` 占比 >20% 时显示黄条警告

### Requirement: 事件 Inspector 与实时流

系统 SHALL 提供 `GET /_admin/events?limit&kind&upstream` 的环形缓冲视图（数据源仅 `recent_events`，`audit.log` 仅作 `raw-tail` 排障，不 merge；**`verdict` 参数与过滤已移除——LLM 事件 `verdict` 恒为空，无业务意义**；事件行 SHALL 含 `model` 字段（来自 `_metrics_ctx['model']`，无则 `unknown_model`））以及 `GET /_admin/events/stream` 的 SSE 实时推送（**除 2s 事件推送外，SHALL 每 15s 推送一次 `event: metrics` 全量指标快照**（含 `metrics`/`series`/`health` 数据，前端收到即更新 KPI/图表/token 四卡/上游分布，非事件区亦自动刷新）（鉴权三选一严格优先级 `X-Admin-Token` 头优先（`hmac.compare_digest`（等长摘要）时序安全比较）> `Cookie: __Host-admin_token`（`HttpOnly; Secure(由`request.scheme`判定，仅https); SameSite=Strict; Path=/; Max-Age=3600`，`ENV==dev` 回退为 `admin_token` 仍 `HttpOnly` 且 `https` 才 `Secure`/`http` 不带 `Secure`、`SameSite=Lax`）> `?access_token` 查询参数仅作 `EventSource` 兼容回退且仅限 SSE（`?access_token` 非空且 `path != /_admin/events/stream` 无条件 `401` 不评估 header/cookie），日志掩码 `access_token`，`history.replaceState` 清 URL，且 `GET /_admin/metrics` / `/_admin/events` 带 `?access_token` SHALL 返回 `401`；SSE 限 `max 5 concurrent SSE/IP` + `60s :ping` 心跳 + `5min` 服务端 `retry` 强制断开重连，超限 `429 + Retry-After` 不泄露指标；管理接口额外 `10/min/IP` 限流超限 `429 + Retry-After`（`on_disconnect` 清理计数器防泄漏））；事件 SHALL 仅含脱敏摘要（`redact_summary(raw,120)` 先脱敏后 `truncate(120)` 的 `[REDACTED:<kind>]` 单一路径，PII 明文不落 `recent_events` 与 SSE），不含明文；事件 `sse_events` 计数按 SSE 事件块（`event:`/`id:`+`data:` 同块计 1，v0.9.23-25 同块写出），合成终止事件（`truncated`）单列不计入；点击事件 SHALL 在**行旁 tooltip 式浮窗**展示 `request_id` 级摘要（命中类型、上游、model、tokens、延迟；`verdict` 已移除），浮窗跟随行定位，**hover 触发**（鼠标悬停行显示，移出/Esc/点击外部关闭），替代居中 modal。事件表 SHALL 新增 Cache% 列（输入 token 缓存命中率 `cached_read/input`，input 缺省回退 prompt，分母 0 显示 `-`，1 位小数，hover 显示 `cached_read / input` 绝对值）。首版 SHALL 不注册 `GET /_admin/metrics/prometheus`（请求返回 404，预留 `credential_proxy_*`）。不主动发 `CSP` 头。

#### Scenario: 事件可过滤可追溯

- **WHEN** 查询 `/_admin/events?upstream=8878&model=gpt-4o&limit=20`
- **THEN** 返回最近 20 条 `upstream==8878` 事件，每条含 `ts/request_id/upstream/model/pii_hits/cred_hits/tokens/latency` 且不含明文

#### Scenario: 事件表 Cache% 列

- **WHEN** 事件行含 token usage（`tokens[model].cached_read` 与 `input`）
- **THEN** 事件表 Cache% 列 = `cached_read/input*100%`（1 位小数）；input 缺省回退 `prompt`（OpenAI 协议无 `input` 字段，必须 `tok.input ?? tok.prompt`）；分母 0、usage 缺失或 `unknown:true` 显示 `-`（不显示 `0%`）；hover 显示 `cached_read / input` 绝对值（如 `12345 / 14800`）

#### Scenario: 实时推送

- **WHEN** 大盘开启 `Live` 且有新请求完成
- **THEN** `/_admin/events/stream` 在 2 秒内推送新事件行到前端表首

#### Scenario: SSE 兼容鉴权

- **WHEN** 浏览器原生 `EventSource` 无法携带自定义头（`X-Admin-Token`）
- **THEN** 携带 `Cookie` 的 SSE 请求返回 200 流，仅回退时带 `?access_token` 亦返回 200；无任何凭证的 SSE 返回 401 且不推送数据；`GET /_admin/metrics?access_token=x` 与 `GET /_admin/events?access_token=x` 返回 401（非 SSE 带 `?access_token` 拒）

## ADDED Requirements

### Requirement: 图表与分布 hover 数值提示

大盘折线图数据点与 PII 类型分布 SHALL 支持 hover 显示完整精确数值（Chart.js `tooltip` 回调或 SVG `title` 元素）：折线图数据点 hover 显示该时间桶的 `requests`/`tokens_prompt`/`tokens_completion`/`cached_read`/`p95`/`pii_requests` 精确值；PII kind 分布（条形/饼图）hover 显示该 kind 的完整计数（不缩写）。数值精确到 1，不因 K/M/B 缩写丢失精度。

#### Scenario: 折线图数据点 hover 精确值

- **WHEN** 鼠标悬停折线图某数据点（如 `requests` 序列某桶）
- **THEN** 显示该桶完整精确值（如 `1,234,567` 而非 `1.2M`），含该桶 `ts` 与所有序列值

#### Scenario: PII kind 分布 hover 精确值

- **WHEN** 鼠标悬停 PII 类型分布图某 kind 条/扇区
- **THEN** 显示该 kind 的完整计数（如 `12,345` 而非 `12.3K`）与占比

#### Scenario: 新增渲染点防 XSS

- **WHEN** 事件浮窗/tooltip、`fmtNum` `title` 精确值、Chart.js `tooltip.callbacks.label`、SVG `<title>` 渲染事件字段（model/request_id/raw_summary）
- **THEN** 全部经 `textContent`/`createTextNode`/`title` 属性赋值，禁止 `innerHTML`/`outerHTML`/`insertAdjacentHTML`；HTML 标签原样透传不执行；脱敏占位符 `__PII_*__`/`__VG_CRED_*__` 原样保留
