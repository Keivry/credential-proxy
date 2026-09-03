## Purpose

防止占位符跨 SSE 分片被切断后提前输出或泄漏，保障无换行流与快慢双链行为一致。

## ADDED Requirements

### Requirement: 残缺前缀跨片持有

系统 SHALL 对未完成的 token 前缀做持有等待后续分片，不得提前输出残缺形态，也不得误删完整响应期 token。

#### Scenario: 跨片 token 不提前输出

- **WHEN** 上游分片在 `__VG_CRED_000` 与 `001__` 之间切断
- **THEN** 前段被持有不输出，待后段到达重组还原后整体输出

#### Scenario: 完整 token 不误删

- **WHEN** 文本尾为完整响应期 token 形态
- **THEN** 系统将其整体持有而非剥离，不得把合法占位符当残缺清理

### Requirement: 候选感知覆盖全类型

系统 SHALL 对无换行超长持有按 PII 前缀候选感知强制切分，内置全类型（`email/phone/id_card/bank_card/ipv4/ipv6/api_key`）+ `__VG_CRED__/__PII__` 保留前缀全覆盖；自定义规则按其已加载正则字面前缀族持有等待：命中前缀即持有，未命中则透传该分片并计 `custom_other` 候选未命中，主链不得为等待自定义前缀而无限持有。

#### Scenario: 邮箱跨片不泄漏

- **WHEN** `user@exa` 与 `mple.com` 被切在两个 `data:` 事件且无换行
- **THEN** 前段不提前 safe 发出，待重组后整体检测还原

#### Scenario: 快慢链行为一致

- **WHEN** 同一短分片流分别经 fast 链与 slow 链处理
- **THEN** 两者行缓冲语义一致，不得一链直接透传而另一链持有合并

#### Scenario: 自定义规则未命中前缀透传并计数

- **WHEN** 自定义正则前缀未被候选感知覆盖且分片无换行超长持有
- **THEN** 系统透传该分片并计 `custom_other` 候选未命中（计数位置：`_metrics.py sanitize_kind` 归一后的 `pii_by_type["custom_other"]` 指标桶，与 `/_admin/metrics` 的 `pii_by_type` 同口径），主链不得为等待自定义前缀而无限持有（持有超过 `LINE_BUF_FLUSH=16KB` 或 `LINE_BUF_MAX_AGE=30s` 即强制切分输出）

#### Scenario: refusal 通道同缓冲

- **WHEN** 上游分片发送 `delta.refusal` 或 Responses `refusal.delta` 且被切在保留前缀边界
- **THEN** 其与 `content` 共用同一行缓冲阈值（`LINE_BUF_FLUSH=16KB/LINE_BUF_MAX_AGE=30s`）与持有语义，不得单独透传短分片

### Requirement: WHATWG 分帧语义一致

系统 SHALL 在 fast 链与 slow 链使用同一 WHATWG 分帧语义（`CRLF/LF/CR` 统一切行、`:` 注释透传、`retry:` 仅 ASCII 数字、`data:` 冒号后单空格 `U+0020` 剥离），截断后残留不得与后续事件叠加。

#### Scenario: 回车分隔流快慢一致

- **WHEN** 同一含 `\r` / `\r\n` 分隔的 SSE 流分别经 fast 链与 slow 链处理
- **THEN** 两链切出行数一致且每行下游 `json.loads` 成功，截断残留经 `rfind` 清理后 `fast_data_buffer` 不与后续事件叠加
