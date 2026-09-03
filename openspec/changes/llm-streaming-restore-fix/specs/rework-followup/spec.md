## Purpose

收敛 Oracle 终审后残留的五项返工点：死代码去留、最小断言缺口、回退语义分叉、refusal 通道归属、多 data 行解析与截断对齐，全部以可验证行为断言闭环。

## ADDED Requirements

### Requirement: 死代码 `_release_pending_once` 去留收敛

系统 SHALL 删除或正式接线 `_release_pending_once` 死代码，二者取其一：删除则其定义与引用清零，`tasks.md` 1.3 描述同步为单次还原实现；接线则缓冲放行路径经由该函数单次还原，且 `tasks.md` 1.3 描述与代码调用关系一致。

#### Scenario: 死代码删除或接线

- **WHEN** 全仓库检索 `_release_pending_once` 符号
- **THEN** 或定义与引用均不存在（已删除且 `tasks.md` 1.3 不再描述经由它的还原），或放行路径唯一经由它做单次还原（`grep tool_calls_pending_events` 审计还原调用点唯一且与其接线，`tasks.md` 1.3 描述与代码一致）

### Requirement: 流式还原最小断言三件套

系统 SHALL 以回归用例锁定三条最小行为断言：上游 `id/usage` 透传一致、`n=2` 双路独立还原、`p@ss"quote` 含引号参数整段还原。

#### Scenario: id 与 usage 下游一致

- **WHEN** 上游 chunk 携带 `id/created/model/usage` 且文本含占位符
- **THEN** 还原后下游同事件 `id/created/model` 与上游逐字节一致，`usage（prompt_tokens/completion_tokens/total_tokens）` 数值不变，下游 `json.loads` 成功

#### Scenario: n=2 双路各自独立还原

- **WHEN** 上游 chunk 含 `choices[0]` 与 `choices[1]` 两路不同占位符文本
- **THEN** 两路按 `choices[i].index` 各自还原为各自明文，禁止一路明文广播到另一路，且两路 `finish_reason` 按原 `index` 保留

#### Scenario: 含引号参数整段还原

- **WHEN** 工具参数含 `p@ss"quote` 这类内嵌引号文本并经三协议任一通道攒整段 flush
- **THEN** 下游收到的 `arguments` 经 `json.loads` 成功且参数值与上游语义一致，不得出现 `Expecting ',' delimiter` 类解析失败

### Requirement: 回退语义收敛为透传原行

系统 SHALL 在 `_single_mapped_index` 为 None（无法按 `index` 定位目标路）时透传原行：原样转发上游行（含其 `id/model/choices` 结构），不得拼装裸最小事件替代；若确需重建，重建事件必须带回上游 `id/model`。

#### Scenario: 无法定位目标路时透传原行

- **WHEN** 还原路径遇到 `_single_mapped_index` 为 None 的 chunk（如畸形 `index` 缺失）
- **THEN** 系统原样透传该上游行，下游收到的 `id/model/choices` 与上游一致；若走重建分支，重建出的 `data:` 必须含上游 `id/model` 字段且 `json.loads` 成功

### Requirement: refusal 独立字段重建

系统 SHALL 将 `refusal` 作为独立字段重建还原，不得并入 `content`；若实现层面维持合并，则必须在 spec 中写明下游契约变更（下游按合并后语义解析，且 `delta.refusal` 不再独立出现）。

#### Scenario: refusal 独立还原不并入 content

- **WHEN** 上游分片发送 `delta.refusal`（或 Responses `refusal.delta`）且文本含占位符
- **THEN** 下游收到的 `delta.refusal` 为还原后文本且独立存在，同期 `delta.content` 不得混入 refusal 文本；若本 change 维持合并实现，则 spec 与下游契约文档同步写明合并语义，`delta.refusal` 字段不再独立断言

### Requirement: 多 data 行逐条解析与截断对齐

系统 SHALL 对 `data_buffer` 内同一事件的多行 `data:` 逐条独立解析还原，不得 `\n` 拼接后整体解析；慢链 `SSE_MAX_BUF=1MB` 截断补 `\r` 边界定位，与快链 `max(\n,\r)` 口径对齐。

#### Scenario: 多 data 行逐条解析

- **WHEN** 同一 SSE 事件含多行 `data:`（WHATWG 聚合）且各行含占位符
- **THEN** 每行独立 `loads` 还原后按原序输出，下游每行 `json.loads` 成功且全文零 `__PII__/__VG_CRED__` 残留，不得因 `\n` 拼接导致整块解析失败跌入续行重建

#### Scenario: 慢链截断补回车边界与快链对齐

- **WHEN** `\r` / `\r\n` 分隔的 SSE 流触发 `SSE_MAX_BUF=1MB` 截断
- **THEN** 慢链截断定位同时考虑 `\r` 与 `\n`（与快链 `max(\n,\r)` 同口径），截断残留经清理后不与后续事件叠加，快慢链切出行数一致
