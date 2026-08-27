## Purpose

定义 credential-proxy 在 LLM 上游流式响应截断（未收到完整终止事件）时的终止事件策略：区分「已 complete 的无害残留」与「未 complete 的真实截断」，前者静默丢弃，后者不再伪造成功终止而让下游走 stub/重试保护，防止残缺 tool_calls 被执行。

## ADDED Requirements

### Requirement: 已 complete 截断静默丢弃残留

当上游已发送终止事件（chat 的 `[DONE]`/`finish_reason`、responses 的 `response.completed`、anthropic 的 `message_stop`）后，连接断开导致 byte_buf / data_buffer 残留的完整事件（如尾部 `ping`、重复的 completed 对象），proxy SHALL 静默丢弃，不注入任何合成事件，不产生截断告警。该残留对下游无内容价值（终止语义已完整传达），丢弃不影响下游解析。

#### Scenario: responses 尾部 ping 残留静默丢弃

WHEN 上游在发送 `response.completed` 后连接断开，byte_buf 残留 `event: ping\ndata: {"type":"ping","cost":"0"}\n\n` 完整事件
THEN proxy 不注入任何合成事件，不告警，stream_meta 记录 `truncated_mode: silent_discard`，下游收到的流以 `response.completed` 正常结束

#### Scenario: chat 尾部重复 chunk 残留静默丢弃

WHEN 上游在发送 `finish_reason:stop` + `[DONE]` 后连接断开，byte_buf 残留一个完整 `chat.completion.chunk` 对象
THEN proxy 静默丢弃该残留，不合成 finish_reason 也不补发重复 `[DONE]`，下游收到的流以 `[DONE]` 正常结束，stream_meta 记录 `truncated_mode: silent_discard`

#### Scenario: chat 已 complete 但残留半截事件

WHEN 上游已发送 `finish_reason`（`seen_global_terminal=true`）但 byte_buf 残留半截 `chat.completion.chunk`（如 `data: {"id":"gen_...` 被切断）
THEN proxy 不置 `_truncated`（第一段判定含 `not seen_global_terminal` 条件），静默丢弃残留，不告警；下游已收到 `finish_reason` 视为完整

### Requirement: 未 complete 文本截断不再伪造成功终止

当上游流被截断且未发送终止事件（chat 无 `[DONE]`、responses 无 `response.completed`、anthropic 无 `message_stop`），且残留内容是文本/reasoning 分片，proxy SHALL NOT 合成 `finish_reason:stop` / `message_stop` / `[DONE]` 等成功终止事件；流 SHALL 以「无终止事件」状态结束（open-ended），使下游能识别流不完整而走 stub 保护或重试。

#### Scenario: chat 文本截断保持 open-ended

WHEN 上游发送多个 `chat.completion.chunk`（含 `reasoning`/`content` delta）后连接断开，未发送 `[DONE]`，byte_buf 残留半截 reasoning 文本
THEN proxy 不合成 `finish_reason:stop` 也不补发 `[DONE]`，流以最后一个已透传 chunk 结束，stream_meta 记录 `truncated_mode: open_ended`，下游（如 Hermes）识别到 `finish_reason is None` 而丢弃残缺文本

#### Scenario: anthropic 文本截断不合成 message_stop

WHEN 上游发送 `content_block_delta` 文本后连接断开，未发送 `message_stop`
THEN proxy 不合成 `message_stop`，流以最后一个已透传 delta 结束，下游识别流不完整

### Requirement: 未 complete tool_calls 截断丢弃残缺参数且不伪造成功

当上游流被截断且未发送终止事件，且残留包含 tool_calls / tool_use / function_call 分片，proxy SHALL 丢弃已累积的残缺工具调用参数（tool_calls_pending_events / tool_calls_buf / arg_buf 中的未完成参数），且 SHALL NOT 合成成功终止事件；使下游明确「工具调用不完整」而拒绝执行残缺参数（如 Hermes 的 mid-tool-call stream drop 保护）。

#### Scenario: chat tool_calls 截断丢弃残缺参数

WHEN 上游发送 tool_calls 分片 `arguments:"各"`、`"分支"`、`"都已"` 后连接断开，未发送 `[DONE]`，参数 JSON 不完整（缺右引号/右括号）
THEN proxy 丢弃已累积的残缺参数，不合成 `finish_reason:stop` 也不补发 `[DONE]`，下游识别工具调用不完整而拒绝执行

#### Scenario: anthropic tool_use 截断丢弃残缺参数

WHEN 上游发送 tool_use input 分片后连接断开，未发送 `content_block_stop` / `message_stop`
THEN proxy 丢弃残缺 tool_use 参数，不合成 `message_stop`，下游识别工具调用不完整

### Requirement: responses 截断保留 failed 语义

responses 协议路径，当上游流被截断且未发送 `response.completed` 时，proxy SHALL 合成 `response.failed` 事件（含截断原因），使下游明确请求失败而触发重试；该失败信号 SHALL 保留，不因「不伪造成功」原则而移除。

#### Scenario: responses 未 complete 截断合成 failed

WHEN 上游发送多个 `response.output_text.delta` 后连接断开，未发送 `response.completed`，byte_buf 残留半截文本
THEN proxy 合成 `response.failed` 事件（含 truncated 语义），下游（如 codex_runtime）识别 terminal status=failed 而报错重试

### Requirement: 截断模式可观测记录

proxy SHALL 在 stream_meta.json 记录每次截断的处理模式 `truncated_mode`，取值 `silent_discard`（已 complete 静默丢弃）、`open_ended`（未 complete 不伪造终止）、`synthesized_failed`（responses 合成 failed），便于审计与排查。

#### Scenario: 截断模式写入 stream_meta

WHEN 任何截断场景发生（已 complete 或未 complete）
THEN stream_meta.json 的 `truncated_mode` 字段记录对应模式值，且与截断处理分支一致
