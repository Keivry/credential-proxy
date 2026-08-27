# Tasks — truncated-stream-safe-terminal

## 1. 截断判定与合成逻辑改造（_llm.py）

- [x] 1.1 收紧 `_truncated` 判定第一段（4288）：`if byte_buf or data_buffer` 增加 `and not seen_global_terminal` 条件——已 complete（`seen_global_terminal=true`）时 byte_buf/data_buffer 残留不置 `_truncated`，走正常结束路径（静默丢弃残留）；第二段 4331-4346（`not seen_global_terminal` 强制置位）保留不变
  - 验收：`_llm.py` 4288 处判定含 `not seen_global_terminal`；已 complete + 残留完整事件 → `_truncated=false`，无告警无合成，stream_meta `truncated_mode=silent_discard`
- [x] 1.2 chat/anthropic 未 complete 截断：移除 `_build_truncated_event`（chat 合成 `finish_reason:stop` + `[DONE]` + TRUNCATED_MESSAGE）与 `_build_truncated_event_anthropic`（合成 `message_stop`）的调用；改为 flush 已透传内容 + write_eof，不补任何终止事件
  - 验收：slow 路径截断分支（~4354-4374）无 `_build_truncated_event` / `_build_truncated_event_anthropic` 调用；流以最后一个已透传 chunk 结束
- [x] 1.3 chat/anthropic 未 complete tool_calls 截断：检测 `tool_calls_pending_events` / `tool_calls_buf` / `arg_buf` 非空时，丢弃未透传的残缺分片（不 flush），不合成终止事件
  - 验收：截断分支对 tool_calls 残留走丢弃路径；`tool_calls_pending_events` 不写入网络流；stream_meta 记 `tool_calls_dropped: true`
- [x] 1.4 responses 未 complete 截断：保留 `_build_truncated_event_responses`（合成 `response.failed`）不变
  - 验收：responses 截断分支仍调用 `_build_truncated_event_responses`；合成 `response.failed` 写入流
- [x] 1.5 保留 4384-4391 边界回归：`seen_global_terminal=true` + chat + 未发 `[DONE]` → 仍补发恰 1 个 `[DONE]`（协议合规收尾，非伪造成功）；确保 1.1 改动不误伤此分支
  - 验收：该边界测试通过；正常终止（finish_reason 到达）的 chat 流仍以 `[DONE]` 收尾
- [x] 1.6 fast 路径同步：fast 截断分支（~4975-5010）应用与 slow 路径相同的 D1-D3 逻辑（已 complete 静默 / 未 complete 不伪造 / tool_calls 丢弃）
  - 验收：fast 路径截断分支与 slow 路径行为一致（无 `_build_truncated_event` chat 合成、responses 保留 failed）

## 2. stream_meta 可观测记录

- [x] 2.1 stream_meta.json 写入 `truncated_mode` 字段（`silent_discard` / `open_ended` / `synthesized_failed`）与 `tool_calls_dropped`（bool）
  - 验收：三种截断场景下 stream_meta.json 的 `truncated_mode` 与处理分支一致；已 complete → `silent_discard`，未 complete chat/anthropic → `open_ended`，responses → `synthesized_failed`

## 3. 测试

- [x] 3.1 新增 `llm_truncation_test.py`：已 complete + 残留完整事件 → 静默丢弃（不合成、不告警）
  - 验收：测试断言截断分支不注入合成事件、stream_meta `truncated_mode=silent_discard`
- [x] 3.2 新增：未 complete 文本截断 → open-ended（不合成 finish_reason:stop / message_stop / [DONE]）
  - 验收：测试断言流以最后一个 chunk 结束、无合成终止事件、stream_meta `truncated_mode=open_ended`
- [x] 3.3 新增：未 complete tool_calls 截断 → 丢弃残缺参数 + 不伪造成功
  - 验收：测试断言 `tool_calls_pending_events` 不写入流、无 finish_reason:stop、stream_meta `tool_calls_dropped=true`
- [x] 3.4 新增：responses 未 complete 截断 → 合成 `response.failed`
  - 验收：测试断言 `response.failed` 写入流、stream_meta `truncated_mode=synthesized_failed`
- [x] 3.5 全量回归：`pytest` + `ruff check` + `ruff format --check` 通过
  - 验收：三项命令全绿（现有 146 测试 + 新增测试）

## 4. 验证与部署

- [x] 4.1 用真实截断 session dump（如 `req_1492e320eafb451c`、`req_ffaa34a13da4403d`）做隔离回归：喂入 `response_original.jsonl` payload，确认输出行为符合 spec（不伪造成功终止）
  - 验收：隔离测试输出与 spec 的 Scenario 一致；无 `finish_reason:stop` 合成（chat）、tool_calls 残缺不执行
- [ ] 4.2 Docker 镜像重建 + tag 升级（当前 master 流程）
  - 验收：`docker build` 成功，镜像 tag 更新
