## Context

See proposal.md — Why。当前大盘 PII 分布以 `pii_by_type` 的 kind 级计数驱动，`admin.html:renderBar('pii')` 在 Chart.js/SVG 双路径 hover 仅展示 `kind: count`。`_pii.py` 的 `detect_and_redact` 在命中时持有明文值→`__PII_*__` 的映射（`GlobalPiiTokens/RequestScopedTokens`），但仅用于还原，不向 `_metrics.py` 透出值级信息；`_metrics.py` 的 `MetricsCollector` 仅聚合 kind 计数到 `daily_agg/hourly_agg` 与 `recent_events`，`metrics.sqlite` 无值级表。需在不破坏“PII 明文不落盘/不进 SSE”不变量的前提下，补值级掩码采样链路与 hover 下钻展示。

## Goals / Non-Goals

**Goals:**
- 按 kind 提供 TopN 掩码值及次数，hover 可见，默认不存明文
- 默认内存采样（1h 精确、重启清空），可选 `hash+掩码` 轻量持久化（7 天）
- Chart.js 与 SVG 双路径一致，防 XSS，开关可控
- 现有 `/_admin/*` 鉴权/限流/`no-store` 不变

**Non-Goals:**
- 不在 dashboard 展示 PII 明文（仅掩码），不提供“查看原文”按钮
- 不做 `/_admin/series` 的值级时间序列（仅当前窗口 TopN）
- 不做跨 kind 的全局 TopN 排行榜（仅 kind 内 TopN）
- 不引入新前端框架或额外 npm 依赖

## Decisions

### D1: 掩码生成点选在 `_pii.py` 命中回调内（明文不出作用域）

**决定：** 在 `_pii.py` 的联合正则命中回调（`_id_card_ok/_luhn_ok/_is_reserved_ip` 校验后）当场生成 `masked_sample`（phone: `138****8000`；email: `a***@b.com`；bank_card: `**** **** **** 6789`（仅后4，BIN 不保留）；ipv4: `192.168.**.**`；ipv6/api_key: `前4****后4`；其他: `前3****后3` 且 `<6` 时 `前1****后1`）与 `value_hash=sha256(明文).hexdigest()[:16]`（变量名 `value_hash`，持久化键为 `hash`、落盘列 `hash`）一并通过 `ContextVar _req_pii_var` 的 `pii_value_samples: dict[str, dict[str, dict]]`（`masked -> {count, hash}`）传给 `_metrics.py`，明文不跨模块。仅当 `PII_VALUE_SAMPLE_ENABLED=1` 且为对话请求（`is_chat_tail(tail)` 为真，`tail is None` 不采样）时才产采样；请求与响应侧均走同一守门（`scan(tail, is_chat_tail)`，未传 `tail` 则不产采样）；`incr_event` 锁外拷贝 `delta` 后原子替换 `ctx['pii_value_samples']={}`（禁止 `.clear()` 竞态，异常路径回退 `clear()` 仅兜底），`handler` 以 `Token` 隔离并 `finally` 逐个 `reset(tok)`（`reset` 失败显式 `set(None)` 防污染）防跨请求叠加。`masked_sample` 长度上限 64（含 `*`），超长截断。

**理由：** 明文生命周期最短，仅在检测作用域内可见；掩码形态与校验回调强绑定，避免二次正则误伤。`_pii.py` 写 `_req_pii_var` 需函数内延迟导入 `from _metrics import _req_pii_ctx` 防 ` _pii↔_metrics` 循环，或下沉 ContextVar 到 `_ctx.py`。

**备选：** 在 `_metrics.py` 收到明文再掩码——明文跨模块，增加泄漏面，否决。

### D2: 聚合用 `pii_value_samples: {kind: {masked_sample: {count, hash}}}` 结构，kind 内 TopN=5 + 总 kind 截断

**决定：** `_metrics.py` 的 `_DailyAgg/_HourlyAgg` 各加 `pii_value_samples`（`dict[str, dict[str, dict]]` 结构 `masked->{count, hash}`），`incr_event` 内按 `delta_pii_value_samples` 合并 `count+=count`（`hash` 首写 wins），kind 内按 `count` 降序截 Top5（聚合 Top5，展示取前 3），kind 总数沿用 `sanitize_kind` 白名单（≤8 kind），最差 8*5=40 条/请求；`recent_events` 入队时精简为 `{masked: count}` 不存 hash，且 kind 内按 `count` 降序截前 8（`sorted(...)[:8]` 不插第 9 项），`truncated` 仅 `ENABLED=1 && 非空 && 超 Top5` 时置位；`incr_event` 锁内仅排序截断不 `await`，`query_range('1h')` 在锁外快照后聚合。

**理由：** 控制内存与序列化体积（`json.dumps` 每 5min 一次），TopN 满足“看最多的是哪几个”诉求，无需全量。`masked->{count,hash}` 以 `masked` 为键，同掩码多明文碰撞时 `hash` 取首见（首写 wins）且 `count` 合并，去重语义明确。

**备选：** 存全量 `value_hash→count` 无截断——基数随流量线性增长，`metrics.sqlite` 每 5min 快照体积不可控，否决。`_day_key()` 复用 `datetime.now(timezone.utc).strftime(%Y-%m-%d)` 避免本地时区误用。

### D3: 默认内存、可选落盘双开关 `PII_VALUE_SAMPLE_ENABLED` / `PII_VALUE_SAMPLE_PERSIST`

**决定：** `PII_VALUE_SAMPLE_ENABLED=1` 启用采集与 API 透出（默认 0）；`PII_VALUE_SAMPLE_PERSIST=1` 才建 `pii_value_agg` 表并落盘（默认 0）。`enabled=0` 时 `_pii.py` 不产掩码、`_metrics.py` 不聚合、`/_admin/metrics` 返回 `pii_value_samples: {}`；`persist=0` 时仅内存环，重启清空。

**理由：** 默认不改变安全基线，需显式 opt-in；两开关解耦“看得到”与“存得住”。`PII_VALUE_SAMPLE_ENABLED` 热读每次 `os.getenv` 即读非模块快照；`PERSIST=1` 隐含 `ENABLED=1`，`query_range` 以 `ENABLED` 为准，`ENABLED=0` 时即使 `PERSIST=1` 亦返回 `{}` 不读盘。

**备选：** 单开关——无法区分“临时看”与“持久化”，否决。

### D4: 持久化表 `pii_value_agg` 仅存 `hash+masked_sample+count`，7 天滚动

**决定：** `CREATE TABLE IF NOT EXISTS pii_value_agg(day TEXT, upstream TEXT, kind TEXT, hash TEXT, masked_sample TEXT, count INT, PRIMARY KEY(day, upstream, kind, hash))`，`day=%Y-%m-%d` UTC，`count` 为当日累计（覆盖式 UPSERT），`_trim_old` 按 7 天 `DELETE WHERE day < ?`，文件 `0600`（`_chmod_0600`）。

**理由：** `hash` 用于去重/合并，`masked_sample` 用于展示，均非明文；按日聚合避免小时级膨胀。

**备选：** 按小时聚合——`168*8*5` 行/7d 仍可控但查询需跨小时归并，复杂度高，首版按日简化。

### D5: 前端 hover 扩展 `afterBody` + SVG `<title>` 多行

**决定：** `admin.html:renderBar('pii')` 的 Chart.js `tooltip.callbacks.label` 保持 `kind: count`（`Number(c.raw).toLocaleString()` 精确），新增 `afterBody` 返回多行数组 `Top 3: 138****8000 x5, ...`（取聚合 Top5 的前 3，`count` 均 `toLocaleString()` 精确非 `fmtNum` 缩写，需多行换行防窄屏溢出，`textContent` 文本通道不用 `innerHTML`）；SVG 降级 `rect <title>` 改为 `kind: count\n138****8000 x5\n...` 多行（`rect<title>` 与 `text title` 分置不同元素，禁止 `g` 级 `title`）；`PII SVG` 容器限宽 `Math.min(1200, ...)` 且 `overflow-x:auto`，`Top3` 换行展示；限流 `onerror fallbackTimer` 仅 `renderKpis` 已修正为 `renderKpis+renderTokens4+renderCharts` 全量刷新防陈旧；无采样时仅计数，`!is_precise` 时 `1h` 弱提示 `仅1h精确（样本不足/未持久化）`（原仅 `range!=1h` 已放宽），`truncated` 尾加 `…长尾仅计 pii_by_type`；`SSE` 的 `metrics` 快照响应头补 `Cache-Control: no-store`；PII `<rect>` 补 `tabindex/role` 与键盘可达（可选）。

**理由：** 复用现有 `Chart/SVG` 双路径，不新增依赖；`title`/`afterBody` 均为文本通道，XSS 面天然收敛。

**备选：** 新增独立弹窗——与现有“PII 分布”卡片语义重叠，增加交互成本，否决。

### D6: API 仅扩展 `/_admin/metrics`，不扩展 `series`

**决定：** `GET /_admin/metrics?range=1h|24h|7d|30d` 新增 `pii_value_samples: {kind: {masked: count}}`（精简不含 hash，`hash` 仅内部/落盘去重）字段；`1h` 从 `recent_events` 现场 TopN 精确聚合（`recent_events` 已为 `{masked:count}` ≤8），`24h/7d/30d` 若 `PII_VALUE_SAMPLE_PERSIST=1` 则从 `pii_value_agg` 归并否则返回 `{}` 并在响应加 `pii_value_samples_is_precise: bool` 标注（核验 `is_precise === true` 时才展示 TopN）。`pii_value_samples_truncated` 仅 `ENABLED=1 && 非空 && 超 Top5` 时置位。

**理由：** 值级是“当前窗口分布”而非时序，`series` 的桶序列无需值级；保持 `series` 轻量。

## Risks / Trade-offs

- [掩码仍可侧信道推断] → 聚合 Top5/展示 Top3，不透传 `hash` 到 API/事件/SSE，仅内部去重；开关默认关；`hash` 截断小空间仍可枚举，文档声明侧信道（phone 7 位暴露 1 万匿名集、email 首字符泄漏）可选 HMAC/每日盐；响应侧同守门防非对话样本泄露。
- [高基数截断导致长尾不可见] → 聚合 Top5（展示前3）截断文档化，`recent_events` 亦按 kind ≤8 截断（不插第 9 项）；API 顶层 `pii_value_samples_truncated: {kind: bool}` 且 `truncated:true` 仅当 `ENABLED=1 && 非空 && 超 Top5` 时置位；长尾仍在 `pii_by_type` 总数中，前端显示 `…长尾仅计 pii_by_type`。
- [内存环 1h 窗口外不可见] → `24h/7d` 需 `PERSIST=1` 才有值级，否则 hover 仅计数；前端据 `pii_value_samples_is_precise === true` 弱提示（1h 亦提示样本不足）。
- [掩码碰撞（不同明文同掩码）] → 以 `hash` 去重、`masked_sample` 展示，碰撞时计数合并但 hash 首写 wins（按 `masked_sample` 聚合不按 hash，碰撞低概率可接受）。
- [SQLite 写入放大] → 每 5min 快照 UPSERT 仅日级 40 行级别，`queue.Queue(maxsize=512)` 单写者串行（`QUEUE_MAXSIZE=512`，与 `dropped_snapshots` 一致），压力可忽略；`os.umask(0o077)` 紧邻建库后立即 `_chmod_0600(day, -wal, -shm)`；`7d DELETE WHERE day < ?` 实为 8 天窗口（含当天），文档/代码 `>= today-7d` 语义一致。
- [XSS via masked_sample] → 掩码仅含 `* . @` 等安全字符，仍经 `textContent`/`title` 文本通道，不进 `innerHTML`；`fallbackTimer onerror` 全量刷新防陈旧数据驻留。
- [fallback 陈旧残留] → 限流/断流回退定时器触发时全量重绘 `KPI+tokens+charts`（含 PII），避免仅 KPi 刷新导致 PII 柱陈旧。
- [hash 透传扩大泄漏面] → 已阻断：API/`recent_events`/`SSE` 均 `{masked:count}` 不含 hash，`hash` 仅内存聚合/落盘列，备份泄漏面最小。

## Migration Plan

1. 代码：`_pii.py` 加 `mask_pii_value(kind, value) -> str` 与 `ContextVar` 扩展；`_metrics.py` 加 `pii_value_samples` 聚合、上游可选表、TTL 清理、开关读取；`_admin.py` 透出 `pii_value_samples`；`admin.html` 扩展 `renderBar` tooltip/SVG。
2. 环境：新增 `PII_VALUE_SAMPLE_ENABLED` / `PII_VALUE_SAMPLE_PERSIST`（`config.yaml` / `docker-compose.yml` / `.env.example`），默认 `0`，无需重启即生效（采样开关热读）。
3. 数据：`metrics.sqlite` 首次 `PERSIST=1` 时建 `pii_value_agg`，历史无值级数据（空 `{}`），不迁移；`7d` 滚动自动清理。
4. 测试：新增 `tests/test_pii_value_samples.py` 与 `tests/observability_pii_value_test.py`，`ruff check/format --check` 必过。
5. 回滚：`PII_VALUE_SAMPLE_ENABLED=0` 即回退为仅计数的旧表现；`DROP TABLE pii_value_agg` 可选（保留亦无害）。

## Open Questions

- 掩码形态是否需按 kind 可配置（当前固定形态，首版够用，后续可加 `PII_MASK_TEMPLATE`）。
- `bank_card` 已定仅后4 `**** **** **** 6789`（BIN 不保留，合规）；`email` 形态当前 `a***@b.com` 已知首字符侧信道（本 change 保留以兼容存量掩码，后续迭代可改为 `***@***.com` 并重算掩码）；`ipv6/api_key` 6-7 字符归入 `前4****后4` 已在代码实现，与 `其他 <6 → 前1****后1` 分支文档对齐。
