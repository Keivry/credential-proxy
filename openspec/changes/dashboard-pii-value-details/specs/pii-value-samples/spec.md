## Purpose

为 PII 分布提供值级掩码采样与聚合，支撑仪表盘按 kind 下钻到具体匹配值（掩码后）及次数，默认不存明文、开关可控。

## ADDED Requirements

### Requirement: PII 值级掩码采样与聚合

系统 SHALL 在 PII 命中时产出值级掩码采样：在 `_pii.py` 命中回调内（明文作用域内，仅 `PII_VALUE_SAMPLE_ENABLED=1` 且 `is_chat_tail(tail)` 为真、`tail is None` 不采样、请求/响应侧同守门）生成 `masked_sample`（phone→`138****8000`；email→`***@***.com` 不透首字符；bank_card→`**** **** **** 6789` 仅后4；ipv4→`192.168.**.**`；ipv6/api_key→`前4****后4`（含 6-7 字符）；其他→`前3****后3` 且 `<6` 时 `前1****后1`，`masked_sample` 长度上限 64 含 `*`）与 `value_hash=_pii_value_hash(明文)`（`HMAC-SHA256(SALT,明文)[:16]` 当 `PII_VALUE_SAMPLE_HMAC_KEY` 设值，否则 `sha256[:16]`；变量名 `value_hash`，持久化键为 `hash`、落盘列 `hash` 仅内部去重不透 API），通过 `ContextVar _req_pii_var.pii_value_samples: dict[str, dict[str, dict]]`（`masked->{count, hash}`）透传到 `_metrics.py` 按 `kind` 聚合 TopN（聚合 5，展示取前 3，`recent_events` 精简为 `{masked:count}` 不含 hash 且 kind 内 ≤8 按 count 降序截断不插第 9 项），kind 总数受 `sanitize_kind` 白名单约束（≤8 kind，`incr_event` 消费后原子替换 `ctx['pii_value_samples']={}` 禁止 `.clear()` 竞态，`handler finally` 以 `Token reset` 失败回退 `set(None)`），明文不出 `_pii.py` 作用域，仅 `masked_sample+hash` 进入内部聚合/落盘，API/事件/SSE 仅 `{masked:count}`（`hash` 为 `HMAC-SHA256` 未设退化小空间可枚举，仅去重）。

#### Scenario: 掩码形态正确

- **WHEN** 命中 `phone=__PII_7_6716b652__`、`email=__PII_9_ac454d8d__`、`bank_card=6225880123456789`
- **THEN** 聚合中 `masked_sample` 分别为 `138****8000`、`***@***.com`、`**** **** **** 6789`，且 `hash` 为 `HMAC-SHA256(SALT,明文)[:16]` 未设退化 `sha256[:16]` 的 16 hex，不含明文；未设 SALT 时 hash 小空间仍可枚举仅去重。

#### Scenario: TopN 截断

- **WHEN** 同一 kind 内命中 10 个不同掩码值
- **THEN** `pii_value_samples[kind]` 仅保留按 `count` 降序 Top5（聚合 Top5，展示前3），顶层 `pii_value_samples_truncated[kind]==true` 仅当 `ENABLED=1 && 非空 && 超 Top5` 时置位；其余长尾仅计入 `pii_by_type` 总数，前端 `…长尾仅计 pii_by_type`。

#### Scenario: 开关默认关闭

- **WHEN** `PII_VALUE_SAMPLE_ENABLED` 未设置或为 `0`
- **THEN** 不产掩码、不聚合，`/_admin/metrics` 返回 `pii_value_samples: {}`，`_pii.py` 不增加额外开销。

#### Scenario: 明文不落盘与不进 SSE

- **WHEN** 任意窗口查询 `/_admin/metrics` 或 `/_admin/events` / `/_admin/events/stream`
- **THEN** 响应中不含 PII 明文，仅 `kind`、`count`、`masked_sample` 与 `[REDACTED:<kind>]` 形态；`/_admin/metrics` 的 `pii_value_samples` 为 `{masked: count}` 不含 `hash`，`recent_events`/`SSE` 亦不含 `hash`；`hash` 仅内部/落盘去重，不可还原明文。

### Requirement: 值级采样查询与持久化

`GET /_admin/metrics?range=1h|24h|7d|30d` SHALL 在 `PII_VALUE_SAMPLE_ENABLED=1` 时返回 `pii_value_samples: {kind: {masked: count}}`（精简不含 `hash`，聚合 Top5 展示前3，`recent_events` 亦 `{masked:count}` 且 kind 内 ≤8）与 `pii_value_samples_is_precise: bool`（`=== true` 才展示 TopN）及 `pii_value_samples_truncated`（仅 `ENABLED=1 && 非空 && 超 Top5` 时 `true`）；`range=1h` 时从内存 `recent_events` 现场聚合（精确，`is_precise` 与 `ring_coverage` 一致），`range=24h|7d|30d` 时若 `PII_VALUE_SAMPLE_PERSIST=1` 则从 `pii_value_agg` 日级归并否则返回 `{}` 且 `pii_value_samples_is_precise=false` 不读盘；`_handle_sse` 与 `/_admin/metrics` 响应头均含 `Cache-Control: no-store`，`recent_events` 入队截断为 `sorted(...)[:8]` 不插第9项。可选持久化表 SHALL 为 `pii_value_agg(day TEXT, upstream TEXT, kind TEXT, hash TEXT, masked_sample TEXT, count INT, PRIMARY KEY(day, upstream, kind, hash))` 按日覆盖式 UPSERT（`hash` 仅内部去重），7 天滚动 `DELETE WHERE day < ?`（含当天为 8 天窗口语义），文件与 `-wal/-shm` 均 `0600`。

#### Scenario: 1h 窗口精确

- **WHEN** `PII_VALUE_SAMPLE_ENABLED=1` 且请求 `/_admin/metrics?range=1h`
- **THEN** `pii_value_samples` 与近 1h 内存环现场 TopN 一致，且 `is_precise` 与 `ring_coverage` 一致。

#### Scenario: 24h 无持久化时为空

- **WHEN** `PII_VALUE_SAMPLE_ENABLED=1` 但 `PII_VALUE_SAMPLE_PERSIST=0` 且请求 `?range=24h`
- **THEN** `pii_value_samples: {}` 且 `pii_value_samples_is_precise: false`，不触发磁盘读。

#### Scenario: 持久化 7 天滚动

- **WHEN** `PII_VALUE_SAMPLE_PERSIST=1` 且跨 7 天持续写入
- **THEN** `pii_value_agg` 中 `day < today-7d` 的行被清理，查询不受影响，权限 `0600`。

#### Scenario: 未鉴权不泄露

- **WHEN** 未带 token 请求 `/_admin/metrics?range=1h`（即使 `PII_VALUE_SAMPLE_ENABLED=1`）
- **THEN** 返回 `401 {"error":"unauthorized"}`，不含 `pii_value_samples` 任何数据。
