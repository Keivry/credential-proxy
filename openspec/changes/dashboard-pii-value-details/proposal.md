## Why

credential-proxy 仪表盘的 PII 分布仅展示 `pii_by_type: {kind: count}` 的 kind 级计数，hover 只能看到 `phone: 12,345`，无法回答“是哪几个值命中最多、频次分布如何”的审计诉求。运营需要按 kind 下钻到具体匹配值（TopN）及次数来验证脱敏规则是否误伤/漏判、定位异常流量来源。但直接把 PII 明文写入 `metrics.sqlite` 会破坏“PII 明文不落盘/不进 SSE”的安全不变量，造成备份泄漏与合规风险，需提供带掩码、可开关、默认不存明文的值级方案。

## What Changes

- **值级采样采集**：`_pii.py` 命中时同步产出 `masked_sample`（掩码后示例，如 `138****8000 / a***@b.com / 192.168.**.**`，当场生成不存明文）与 `value_hash=sha256(明文)[:16]`（`value_hash` 为变量名，持久化键为 `hash`、落盘列 `hash`），`_metrics.py` 内部聚合 `pii_value_samples: {kind: {masked_sample: {count, hash}}}` TopN 聚合默认 5/kind（hover 展示取前 3），按 kind 上限 8 截断防基数爆炸；`recent_events` 入队精简为 `{masked: count}`（不存 hash，kind 内 ≤8 按 count 降序截断），对外 API 仅透出 `{masked: count}` 不含 hash。
- **内存为主、可选落盘**：默认仅内存 `recent_events` + `_daily` 内存聚合（`deque 10000` 现场聚合，`range=1h` 精确，重启清空）；`PII_VALUE_SAMPLE_PERSIST=1` 时才落盘到 `pii_value_agg` 轻量表（`hash+masked_sample+count`，不存明文，7 天滚动），默认关闭。
- **仪表盘 hover 下钻**：`admin.html` PII 分布 `renderBar('pii')` 的 Chart.js `tooltip.callbacks.afterBody` 与 SVG `<title>` 扩展为 `kind: count` 下的 `TopN 掩码值 x 次数` 列表（如 `phone: 123 (138****8000 x5, 139****1111 x2)`），无采样时仅显示计数（向后兼容）。
- **API 透出**：`/_admin/metrics?range=` 返回新增 `pii_value_samples: {kind: {masked: count}}`（精简不含 hash，`range=1h` 内存精确 `pii_value_samples_is_precise=true`，其余 `PERSIST` 依赖，空时 `false` 不读盘）与 `pii_value_samples_truncated`（仅 `ENABLED=1 && 非空 && 超 Top5` 时 `true`），`/_admin/series` 不新增值级序列；鉴权、限流、`no-store` 头与现有 `/_admin/*` 一致，`SSE` 亦补 `no-store`（含按请求限流后回退全量刷新不残留旧数据）。
- **安全与开关**：新增 `PII_VALUE_SAMPLE_ENABLED`（默认 0）与 `PII_VALUE_SAMPLE_PERSIST`（默认 0）双开关；掩码生成在 `_pii.py` 检测回调内、明文不出 `_pii.py` 作用域（`hash` 仅去重，小空间 PII 仍可枚举）；API/事件/SSE 均不透传 hash，仅 `masked->count`；`metrics.sqlite` 新增表含 `-wal/-shm 0600`；响应侧与请求侧同走 `is_chat_tail(tail)` 守门，`tail is None` 不采样。

## Capabilities

### New Capabilities

- `pii-value-samples`: PII 值级掩码采样与聚合——按 kind 收集 TopN 掩码值及次数，支撑分布 hover 下钻，默认内存、明文不落盘。

### Modified Capabilities

- `observability-metrics`: 增加 `pii_value_samples` 内存聚合与可选 `pii_value_agg` 持久化，`query_range` 返回值级采样，开关控制。
- `observability-dashboard`: PII 分布 hover 从仅计数扩展为“计数 + TopN 掩码值 x 次数”，Chart.js/SVG 双路径，防 XSS。

## Impact

- **代码**：`_pii.py`（掩码生成）、`_metrics.py`（`pii_value_samples` 聚合、内存 TopN、上游可选 `pii_value_agg` 表、TTL 清理）、`_admin.py`（`/_admin/metrics` 透出 `pii_value_samples`）、`admin.html`（`renderBar` tooltip/SVG title 扩展）。
- **API**：`GET /_admin/metrics?range=&model=&upstream=` 新增 `pii_value_samples: {kind: {masked: count}}`（精简不含 hash，向后兼容缺省 `{}`，`recent_events` 精简同形）；`series/events/health` 不变；鉴权/限流/`no-store` 不变；`hash` 仅内部/落盘去重不进 API/事件/SSE。
- **数据**：默认不新增持久化（重启清空）；开启 `PII_VALUE_SAMPLE_PERSIST=1` 时新增 `pii_value_agg(day TEXT, upstream TEXT, kind TEXT, hash TEXT, masked_sample TEXT, count INT, PRIMARY KEY(day, upstream, kind, hash))`（`day=%Y-%m-%d UTC`，聚合 Top5 展示 Top3）7 天滚动，文件 `0600`（含 `-wal/-shm`）。
- **安全**：明文不出 `_pii.py` → `_metrics.py` 仅传 `masked_sample+hash`；`hash` 为 `sha256` 截断仅内部去重不透传前端；`recent_events`/`events`/`SSE` 均 `{masked:count}` 不含 hash；掩码写入/展示均经 `textContent`/`title` 防 XSS；默认关闭需显式开启；响应侧同守门防中毒。
- **测试**：新增值级采样单测（掩码形态、TopN 截断、开关、hash 一致性）、dashboard hover 单测（Chart.js/SVG title 含掩码）、ruff 必过。
