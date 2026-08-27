# Design — truncated-stream-safe-terminal

## Context

见 proposal.md - Why。本 change 基于 2026-08-27 截断归因调查的实证：

- **14 条截断中 11 条 `seen_terminal:true`**：上游已发终止事件（`response.completed` / `[DONE]`），残留只是 byte_buf 里的完整事件（46B ping、34B ping、13042B/35253B completed 对象）——**无害残留**
- **3 条 `seen_terminal:false`**（chat 路径）：真截断，无终止事件
- **`req_ffaa34a13da4403d` 实测**：tool_calls 参数 `"各"→"分支"→"都已"` 被截断，JSON 不完整（缺右引号/括号），且合成事件**未写入**（客户端已断连 `SSE_CLIENT_GONE`，debug 日志被过滤）
- **Hermes 侧行为实测**（`/opt/hermes/agent/chat_completion_helpers.py`）：
  - `finish_reason is None` + 残缺 tool_calls → **mid-tool-call stream drop 保护**（丢弃参数，`_build_partial_stream_stub`）
  - `finish_reason is None` + 残缺文本 → **stub 保护**（丢弃，不输出污染）
  - 空流 → **`EmptyStreamError` → 重试**（attempt 2/3）
  - 若收到 `finish_reason:stop` → 认为成功，**保护全部绕过**

当前代码 `_llm.py`：截断检测 4282-4346 是**两段式**——第一段 4288 `if byte_buf or data_buffer: _truncated = True` **不区分是否已 complete**（这就是 11/14 条 `seen_terminal:true + truncated:true` 误报的根源：已收到 completed 但 byte_buf 残留尾部 ping/重复对象时仍告警+走合成分支）；第二段 4331-4346 `not seen_global_terminal` 时强制置位。合成逻辑 slow 路径 4354-4378（chat 补 `finish_reason:stop` + `[DONE]` + `TRUNCATED_MESSAGE`、anthropic 补 `message_stop`、responses 补 `response.failed`）、fast 路径 4975-5010（同构）、三个 builder `_build_truncated_event*` 1271-1355。另有 **4384-4391 边界：`seen_global_terminal=true` + chat + 未发 `[DONE]` 时补发恰 1 个 `[DONE]`——这是协议合规补全（上游已发 finish_reason 终止，补 `[DONE]` 收尾），非伪造成功，不在本 change 改动范围**。**问题核心：chat/anthropic 截断路径伪造成功终止（D1 场景误报 + D2/D3 场景伪装完成），把 Hermes 的三类保护全部绕过。**

## Goals / Non-Goals

**Goals**
- 已 complete 截断：静默丢弃残留，不告警不注入
- 未 complete 截断：不伪造成功终止，让下游走 stub/重试保护
- tool_calls/tool_use/function_call 残缺：丢弃参数，不执行
- responses 路径保留 `response.failed` 合成（协议原生失败语义）

**Non-Goals**
- 不改变正常流的转发行为（无截断时完全不变）
- 不实现 proxy 侧重试（重试是下游职责）
- 不改变审计/审批/脱敏机制
- 不修复 Hermes 侧行为（Hermes 的保护已完备，只需 proxy 不绕过）

## Decisions

### D1: 已 complete 截断 → 静默丢弃（不再告警）

- **实现**：`_truncated` 判定收紧为「`not seen_global_terminal` 且（`byte_buf` 或 `data_buffer` 残留）」——已 complete（`seen_global_terminal=true`）时即使 byte_buf/data_buffer 有残留，也不置 `_truncated`，直接走正常结束路径（flush 后 write_eof），不告警不注入
- **理由**：残留是完整事件（ping/completed 副本），无内容价值；告警 11/14 是误报，污染日志与排查
- **备选**：保留告警但降级为 debug → 仍产生噪音，且 stream_meta 的 `truncated:true` 误导；直接不置位最干净
- **风险**：若 byte_buf 残留的是**半截**事件（已 complete 但 buf 里有半个 chunk）→ 实际中已 complete 后 buf 残留都是完整事件（chunk 边界对齐）；若万一出现半截，走 D2 的 open_ended 分支

### D2: 未 complete 文本截断 → 不补成功终止（open-ended）

- **实现**：`_truncated=true` 且 `not seen_global_terminal` 时，chat/anthropic 路径**不再**调用 `_build_truncated_event*` 合成 `finish_reason:stop`/`message_stop`，也不补发 `[DONE]`；只 flush 已透传内容 + write_eof。stream_meta 记 `truncated_mode: open_ended`
- **理由**：Hermes 的 `finish_reason is None` stub 保护恰好需要「无终止事件」状态；伪造成功终止 = 绕过保护 = 残缺文本被当成功输出
- **备选**：合成 `finish_reason:"length"`（表示截断）→ 但 Hermes 对 `length` 可能视为「正常长度截断」而非「流损坏」，不触发 stub；且协议语义不准确
- **风险**：某些下游 SDK 对「无 `[DONE]` 的流」会抛 `IncompleteStreamError` → 这正是期望行为（下游重试）；若下游是纯透传工具（无保护逻辑）则可能拿到无终止流 → 但这是下游协议合规问题，proxy 不该伪造成功掩盖

### D3: 未 complete tool_calls 截断 → 丢弃残缺参数 + 不伪造成功

- **实现**：`_truncated=true` 且 `not seen_global_terminal` 且 `tool_calls_pending_events` / `tool_calls_buf` / `arg_buf` 非空时：
  1. **丢弃** `tool_calls_pending_events` 中未透传的残缺分片（不 flush）
  2. **不合成** `finish_reason:stop` / `message_stop` / `[DONE]`
  3. 已透传的残缺 tool_calls chunk（如 `arguments:"分支"`）**保留在流中**（无法撤回），但因为没有 finish_reason，Hermes 会走 mid-tool-call drop 保护丢弃整个工具调用
  4. stream_meta 记 `truncated_mode: open_ended` + `tool_calls_dropped: true`
- **理由**：Hermes 的 mid-tool-call drop 保护触发条件恰是「无 finish_reason + 有 tool_calls 残留」；保留已透传 chunk（不注入错误事件）让 Hermes 自然识别
- **备选**：注入合成 `finish_reason:"tool_calls"` + 空 arguments → 但这是「伪装的完整工具调用」，Hermes 会尝试执行空参数；且部分 SDK 对空参数报错不重试
- **风险**：若下游（非 Hermes）对「无 finish_reason 的 tool_calls 流」直接执行残缺参数 → proxy 无法完全保护，只能靠「不伪造成功」让流显式不完整；这是下游协议合规问题

### D4: responses 路径保留 `response.failed` 合成

- **实现**：responses 未 complete 截断时，**保持现状**（`_build_truncated_event_responses` 合成 `response.failed` + truncated 消息）
- **理由**：responses 协议原生支持 `response.failed`，Hermes codex_runtime 实测（`codex_runtime.py:1581-1583`）对 `final.status in {"incomplete", "failed"}` raise "Codex Responses stream terminal status=..." 错误 → 调用方重试；这是**正确的失败信号**，不属于「伪造成功」，与 D2/D3 不冲突
- **备选**：不合成 failed 让流 open-ended → 但 responses 协议要求每个 response 有终止状态（completed/failed/incomplete），无终止事件会导致下游挂起等待；合成 failed 是协议正确行为
- **风险**：若下游把 `response.failed` 当「最终失败」不重试 → 实测 Hermes 会重试；其他下游按协议语义处理

### D5: stream_meta 增加 `truncated_mode` 记录

- **实现**：stream_meta.json 写 `truncated_mode` 字段，取值 `silent_discard`（D1）/ `open_ended`（D2/D3）/ `synthesized_failed`（D4）
- **理由**：可观测性——排查时一眼区分「无害残留」与「真截断」及处理模式
- **备选**：不加字段 → 无法从 stream_meta 判断处理策略，排查依赖日志
- **风险**：字段兼容性——stream_meta.json 是内部调试文件，无外部消费者，向后兼容

## Risks / Trade-offs

- [Hermes 对 open-ended 文本流走 stub 而非重试（丢弃残缺文本，不自动重试）] → 这是 Hermes 设计：文本残缺可接受（末尾少几个 token），stub 标记让上层知晓；比「伪造成功输出污染文本」好
- [chat 协议无 failed 事件，无法像 responses 一样明确失败] → 用「无终止事件」表达失败；Hermes 已识别此语义
- [已透传的残缺 tool_calls 无法撤回] → 靠「无 finish_reason」触发下游 drop 保护；proxy 不注入伪造完成事件
- [某些下游 SDK 对无终止流抛 IncompleteStreamError 导致多次重试] → 这是期望行为（重试拿完整结果），成本是额外一次上游调用
- [改动影响正常流路径] → 所有改动只在 `_truncated` 分支内；无截断时零行为变化

## Migration Plan

1. 实现 D1-D5（`_llm.py` 截断分支 + stream_meta）
2. 新增 `llm_truncation_test.py` 覆盖三类场景
3. `pytest` + `ruff check` + `ruff format --check` 全量通过
4. 部署：Docker 镜像重建 + tag 升级（当前 146 测试全绿基线）
5. 回滚：git revert 本 change；行为回到「伪造成功终止」旧逻辑（有已知缺陷但可运行）

## Open Questions

无（调查已闭环：Hermes 保护逻辑、协议语义、实测数据均已确认）。
