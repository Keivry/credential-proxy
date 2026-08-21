## Why

v0.9.x 上线后两类生产故障：① `PII_REDACTION_ENABLED=1` 时 LLM prompt cache 命中率暴跌（同一明文 PII 在连续相同请求中被替换为不同 `__PII_…__`，脱敏后正文仅小部分一致），② `AUDIT_MODE=approve/block/off` 下 `v0.9.5` 仍出现 `hermes JSONDecodeError: Expecting value line 1 col 1` 并重试 5 次后沉默（`credential-proxy 15:00` 仍在 `0.9.5` 时复现，`15:20` 降级到 `0.8.11` 后消失）。两者根因均在 `PII` 引入后新增的请求级可变状态与空流守门判定。

## What Changes

- **PII token 全局持久化（方案 B）**：废弃 `RequestScopedTokens` 每请求 `new` + `clear()` 的请求级隔离，改为进程级全局 `LRU` 持久映射（同凭据 `pwd_to_token` 语义，真 LRU 1000、上限与凭据 5000 区分，最久未用者先出）。`register` 改为 `async def` 并以 `asyncio.Lock` 保护，命中复用已生成 `__PII_<seq>_<rand8>__`，未命中一次性 `secrets.token_hex(4)` 后持久复用；同一明文跨请求得到同一占位符，脱敏后正文稳定，`LLM` cache 可命中。不再强求请求级隔离。
- **并发隔离**：`LLM` 代理中所有“每请求可变状态”收敛为两种：① `ContextVar`（`_pii_scope_var / _audit_arg_accum_var / _audit_hold_active_var / _audit_hold_buf_var / _audit_hold_bytes_var / _last_responses_tool_name_var / _last_anthropic_tool_name_var / _audit_created_ids_var`）用于跨 `await` 回调；② 请求闭包局部（`tool_calls_buf / tool_calls_pending_events / tool_calls_audited / tool_calls_blocked / sse_event_count / fast_sse_event_count / bytes_written / fast_bytes_written / audit_block_injected / is_responses_stream / is_anthropic_stream / content_buf / reasoning_buf / arg_buf` 等）用于流循环，从 `self` 实例变量迁移，消除并发覆盖与 `finally: _pii_cleanup` 误清活请求状态。
- **SSE/非流式永不 200 空体**：流式按“是否真正向 `resp` 写入过字节”守门（`bytes_written/fast_bytes_written` 仅 `await resp.write` 成功计数，`SSE_CLIENT_GONE/ConnectionResetError` 不计，`heavy/fast` 两路径一致且仅 `upstream.status==200` 时注入），非单纯 `sse_event_count`；`audit_hold` 悬挂时流末强制 `_reject_*_hold` 并按协议注入终止事件；`upstream.status != 200` 不注入（`502/401` 透传）；非流式在 `_strip_token_forms` 后再守门，空剥离结果转 `502` 且 `content-type: application/json`，`body={"error":{"message":"empty after strip"}}` 并记 `error` 日志。`heavy/fast` 两路径、三协议形态守门一致，确保 `hermes` 永远收到可解析的 `JSON/SSE` 而非 `200 0 bytes`。

## Capabilities

### New Capabilities

- `llm-stream-reliability`: LLM 代理 SSE/非流式响应的可靠性保证——永不透出 `200 空体/空流`，悬挂 `audit_hold` 流末兜底，`bytes_written` 守门

### Modified Capabilities

- `pii-redaction`: PII 脱敏的 token 生命周期从“请求级随机、请求结束即清理”改为“进程级全局持久 LRU、命中复用”，并发下请求状态隔离由 `ContextVar`/局部变量保证

## Impact

- **修改文件**：`_token.py`（`RequestScopedTokens` → 全局 `LRU` + `asyncio.Lock`）、`_pii.py`（`PiiMixin` 全局单例与 `ContextVar`）、`_llm.py`（`handler` 内每请求状态局部化 + `bytes_written` 守门 + `hold` 流末兜底 + 非流式剥离后 `502`）、`_audit.py`（如需 `ContextVar` 适配）、`proxy.py`（`_init_pii` 单例初始化）、`tests/*`（新增回归）、`openspec` 产物的归档（本 change 归档后写入 `openspec/specs`）
- **API/配置**：无新增环境变量；`PII_REDACTION_ENABLED` 语义不变，仅生命周期变更（**非 breaking**，但跨请求可关联同一 PII 值，属隐私-缓存权衡，已与用户确认接受）
- **部署**：`Docker` 镜像 `ghcr.io/keivry/credential-proxy` 重新构建；`hermes` 侧 `custom:opencode-go` 配置不变；`v0.8.11` 回退用户可直接升级到本修复版
