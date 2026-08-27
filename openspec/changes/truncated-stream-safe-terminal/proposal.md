## Why

credential-proxy 的 SSE 流式转发在检测到上游截断（未收到终止事件）时，会**伪造成功终止事件**：chat/completions 路径合成 `finish_reason:stop` + `data: [DONE]`，anthropic 路径合成 `message_stop`。这会把真实截断伪装成「正常完成」，导致下游（Hermes）**不重试**，并将残缺内容当作完整结果——尤其危险的是 **tool_calls / tool_use / function_call 参数被截断时**，下游可能执行残缺的 JSON 参数（如 `arguments:"各分支都已` 缺右引号），造成错误命令执行。2026-08-27 实测 14 条截断中，8 条 chat 截断 `seen_terminal:false`（真截断）、3 条 responses 截断 `seen_terminal:true`（无害残留）、`req_ffaa34a13da4403d` 确认 tool_calls 参数残缺且合成事件未写入（客户端已断连）。

## What Changes

- **已 complete/done 的截断**：上游已发送 `response.completed` / `finish_reason` / `[DONE]` 后，byte_buf / data_buffer 残留的任何完整事件（如尾部 `ping`、重复的 `response.completed`）**静默丢弃**，不再告警、不再注入合成事件——流对下游已是完整语义，残留无内容价值（2026-08-27 实测 11/14 属此类，`seen_terminal:true` 且残留完整事件）
- **未 complete 的文本/reasoning 截断**：**不再伪造 `finish_reason:stop` / `message_stop`**，让流以「无终止事件」结束——下游（Hermes）会走 stub 保护（`finish_reason is None` → 丢弃残缺文本，不输出污染内容），或报错重试（空流 → EmptyStreamError → retrying）
- **未 complete 的 tool_calls / tool_use / function_call 截断**：**同样不再伪造成功终止**，且**丢弃已累积的残缺 tool_calls 参数**（`tool_calls_pending_events` / `tool_calls_buf`），让下游明确「工具调用不完整」而拒绝执行（Hermes 已实现 mid-tool-call stream drop 保护）
- **responses 路径保留 `response.failed` 合成**：responses 协议原生支持错误事件，补发 `response.failed`（含 truncated 语义）让下游（codex_runtime）报错重试，这是**正确的**失败信号，保持不变
- **新增 `TRUNCATED_TERMINAL_MODE` 可观测标记**：stream_meta.json 记录截断处理模式（`silent_discard` / `open_ended` / `synthesized_failed`），便于审计与后续排查

## Capabilities

### New Capabilities

- `truncated-stream-terminal`: 截断流的终止事件策略——已 complete 残留静默丢弃、未 complete 不再伪造成功终止、tool_calls 残缺丢弃、responses 保留 failed 语义

### Modified Capabilities

（无——本项目 openspec/specs/ 尚无基线，全部为新增能力）

## Impact

- **修改文件**：`_llm.py`（截断检测与合成逻辑：slow 路径 ~4354-4374、fast 路径 ~4975-5010；`_build_truncated_event*` 三个 builder 1271-1355；`tool_calls_pending_events` / `tool_calls_buf` 截断分支处理；stream_meta 记录）
- **新增文件**：`llm_truncation_test.py`（与仓库 `*_test.py` 命名约定一致）
- **API**：无对外 API 变更；`stream_meta.json` 新增 `truncated_mode` 字段（内部可观测性）
- **依赖**：无新增
- **测试**：新增截断场景测试（已 complete 静默丢弃 / 文本截断 open-ended / tool_calls 截断丢弃 + 不伪造成功 / responses failed 保留）；全量 pytest + ruff 必须保持通过
- **部署**：Docker 镜像 tag 升级
