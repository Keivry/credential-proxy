## Purpose

保障 SSE 流式还原不破坏上游 LLM 事件结构与语义，下游 SDK 按标准协议解析不报错。

## ADDED Requirements

### Requirement: 事件重建保留上游结构

系统 SHALL 在流式转发时保留上游 SSE 事件结构，仅替换文本 delta 字段，不得丢弃 `id/created/model/system_fingerprint/usage` 等协议字段；`usage` 存在时其数值语义不得改写（还原只改文本叶，不碰 token 计数）。

#### Scenario: chat chunk 保留结构

- **WHEN** 上游返回含 `id/created/model/system_fingerprint/choices[0].delta.content` 的 chat chunk 且内容含占位符
- **THEN** 下游收到的 chunk 仍含相同 `id/created/model/system_fingerprint`，`delta.content` 为还原后文本，JSON 可解析

#### Scenario: usage 与 created 透传保留

- **WHEN** 上游 chunk 携带 `created/system_fingerprint/usage（prompt_tokens/completion_tokens/total_tokens）`
- **THEN** 下游 chunk 保留相同 `created/system_fingerprint/usage` 数值，还原不得清零或丢弃该字段

#### Scenario: 多 choices 按 index 逐路替换

- **WHEN** 上游 chunk 含 `choices[0]` 与 `choices[1]` 两路 content（`n=2`，各路 `index` 不同、`finish_reason` 独立）
- **THEN** 两路按 `choices[i].index` 逐路替换各自 `delta.content/reasoning_content/tool_calls`，禁止把同一路 content 广播到所有路，且每路 `finish_reason` 按原 `index` 保留

#### Scenario: 序列化口径一致

- **WHEN** 系统重建或透传 SSE `data:` JSON（含合成拒绝事件与流末兜底事件）
- **THEN** 全链使用同一序列化口径 `_jdumps（ensure_ascii=False、separators=(',',':')）`，不得因空格/转义差异导致下游校验失败；裸 `json.dumps` 仅允许出现在测试快照与白名单内阻断合成占位构造，且须经 `_jdumps` 等价性断言

#### Scenario: 非字典解析结果透传不崩溃

- **WHEN** `data:` 行 `json.loads` 成功但解析结果非 dict（如 JSON 数组或字符串）
- **THEN** 系统整行透传不做字段替换，不得抛 `AttributeError`，下游 `json.loads` 仍成功

### Requirement: 多行块逐行还原

系统 SHALL 对含 `event:/id:/data:` 的多行 SSE 块逐行处理，`data:` 行独立还原，非 `data:` 行原样保留。

#### Scenario: event 行不进还原

- **WHEN** 上游发送 `event: content_block_delta` + `data: {...}` 同块
- **THEN** `event:` 行原样转发，仅 `data:` 行做还原，不得把事件名送入 token 清理

#### Scenario: 同事件多 data 行

- **WHEN** 同一事件含多行 `data:`（WHATWG 聚合）
- **THEN** 每行独立解析还原，不得拼接成非法 JSON 后透传

### Requirement: 缓冲事件单次还原

系统 SHALL 对审计缓冲的 `tool_calls` 事件只做一次还原转发，不得二次还原导致漂移或占位符泄漏。

#### Scenario: 缓冲放行不漂移

- **WHEN** 审计 verdict 为 allow 且缓冲中有 tool_calls 事件行
- **THEN** 缓冲行经单次还原后按原序放行，字节语义与上游一致

#### Scenario: 校验失败不泄漏占位符

- **WHEN** 还原后 JSON 校验失败需回退
- **THEN** 回退不得把未还原占位符原样发给下游而不告警，必须走残缺清理路径

### Requirement: 推理通道与终止原因多路规约

系统 SHALL 对 `reasoning_content/delta.reasoning` 按 `choices[i].index` 独立累积还原（与 `content` 同等走持有与单次还原），`finish_reason` 按路独立归属，多路竞态时先到先定、后到同路覆盖、异路不互斥。

#### Scenario: reasoning 按路累积

- **WHEN** 上游分片交替发送 `choices[0].delta.reasoning_content` 与 `choices[1].delta.reasoning_content`
- **THEN** 两路各自累积还原，禁止只保留首个非空 reasoning 或把一路 reasoning 广播到另一路

#### Scenario: finish_reason 多路竞态不互斥

- **WHEN** `choices[0]` 先到 `finish_reason=stop` 而 `choices[1]` 后到 `finish_reason=tool_calls`
- **THEN** 两路终止原因各自保留，系统不得以后到覆盖先到异路，也不得因一路终止而截断另一路未完成 delta
