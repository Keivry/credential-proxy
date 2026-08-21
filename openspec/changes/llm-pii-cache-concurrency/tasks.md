## 1. PII 全局持久化

- [x] 1.1 重构 `_token.py` 的 `RequestScopedTokens` 为线程安全全局 `LRU`：`pii_p2t/pii_t2p resp_*` 常驻、命中复用、`_seq` 递增、`register` 改 `async def` 并以 `asyncio.Lock` 保护、上限 `PII_MAX_ENTRIES=1000` 单表上限（`pii/resp` 各 1000，总量≤2000，真 LRU `OrderedDict.move_to_end + popitem(last=False)` 最久未用者先出，与凭据 `5000` 区分）、全量调用点改为 `await register`
  - 验收：`await register("13812345678")` 连续两次返回同一 `__PII_…__`，不同值不同 `token`，`asyncio.Lock` 保护下并发 `register` 不丢号；`grep -rn "\.register(" _pii.py _llm.py | grep -v "async def register" | grep -v "await.*register"` 为空（全量调用点已 `await`，无 `coroutine never awaited`）；超限 1000 时最久未用者被淘汰（单表 1000 真 LRU 非 FIFO，`pii/resp` 各限 1000，总量≤2000）

- [x] 1.2 改造 `PiiMixin` 为全局单例：`_init_pii` 创建 `self._global_pii_scope` 单例，`_pii_request_scope()` 返回单例复用、`_pii_cleanup()` 不再 `clear()` 映射但每请求清空 `malformed` 限流计数，`_pii_detector.request_tokens` 始终指向单例
  - 验收：`PII_REDACTION_ENABLED=1` 时连续两请求 `body_text` 相同 → `out_body`（含 `__PII_…__`）完全一致，`cache` 可命中

- [x] 1.3 同步 `proxy.py` 与 `_pii.py` 的初始化与清理路径，移除每请求 `new/clear` 的残留引用
  - 验收：`grep -rn "RequestScopedTokens(" --include="*.py" _pii.py | wc -l` 为 0（`_pii.py` 仅 `from _token import ...RequestScopedTokens` 为兼容别名导入，无构造；构造已全迁 `GlobalPiiTokens(`，`_pii.py` 中 2 处），`grep -rn "RequestScopedTokens = GlobalPiiTokens" --include="*.py" _token.py | wc -l` 为 1（仅兼容别名定义），`grep -n "_pii_cleanup.*clear"` 仅清理 `malformed` 计数不含映射清空

## 2. 并发状态隔离

- [x] 2.1 将 `LLM` 代理每请求可变状态从 `self` 迁至 `ContextVar`/局部：至少 `pii_scope / audit_arg_accum / audit_hold_active / audit_hold_buf / audit_hold_bytes / last_responses_tool_name / last_anthropic_tool_name / tool_calls_buf / tool_calls_pending_events / tool_calls_audited / tool_calls_blocked / sse_event_count / fast_sse_event_count / bytes_written / audit_block_injected / is_responses_stream / is_anthropic_stream / content_buf / reasoning_buf / arg_buf` 等全量
  - 验收：`grep -rn "self\.tool_calls_\|self\.sse_event_\|self\.bytes_written\|self\.audit_block\|self\.is_.*stream" _llm.py` 为 0 且 handler 局部 `grep -n "^\s*tool_calls_\|bytes_written"` 命中；`self._pii_ / self._audit_ / self._last_` 的 `property` 透传（`_pii_scope_var.get()` 等）不计为残留实例变量，重链路 `audit_enabled()/pii_active()` 仍走 heavy 但并发不再串扰

- [x] 2.2 定义 `contextvars.ContextVar` 并在 `handler` 入口 `set`、 `finally` 中 `reset`，确保 `PiiDetector` 与 `AuditMixin` 回调通过 `ContextVar.get()` 读取而非 `self` 直读
  - 验收：并发 2 请求（不同 `PII` + 一请求进 `audit_hold`）回归通过，互不覆盖与串扰；`_pii_scope` 为全局持久化故 `set(get())` 仅捕获 Token 供 reset，`_audit_hold_buf` 以 `[]` 初始化并通过 getter 写回隔离

- [x] 2.3 增加并发回归单测：两协程并发 `pii_redact` + `audit_hold` 悬挂不影响另一流
  - 验收：`pytest -k concurrency` 新增用例通过

## 3. 空流/空体永不 200 透出

- [x] 3.1 重构 `_llm.py` 流式 `heavy/fast` 路径：新增 `bytes_written` 计数，每次 `await resp.write` 成功累加（`SSE_CLIENT_GONE/ConnectionResetError` 不计）；流末 `if bytes_written==0 and upstream.status==200:` 按 `tail` 形态注入（`chat→_build_block_event` / `responses→_build_block_event_responses` / `anthropic→_build_block_event_anthropic`），`upstream.status != 200` 时不注入
  - 验收：上游 `200 0 data` 空流 → 客户端收到 1 条可解析 `SSE` 而非 `0 bytes`，`hermes` 无 `JSONDecodeError`；上游 `502/401` 空体透传不注入

- [x] 3.2 流末悬挂 `audit_hold` 兜底：`finally` 前若 `hold_active` 仍真，`await _reject_*_hold` 并注入终止事件后再走 `bytes_written` 守门
  - 验收：构造 `function_call_arguments.delta` 后断流无 `item_done` 的用例，`hold` 被强制 `rejected` 且注入，客户端收到拒绝而非空流

- [x] 3.3 非流式剥离后空体守门：`_strip_token_forms(out_text)` 后 `if not out.strip(): return 502 {"error":{"message":"empty after strip"}}` 且 `Content-Type: application/json`
  - 验收：构造上游回包仅含幻觉 `__PII_…__` 的非流式用例，剥离后返回 `502` 且 `Content-Type: application/json`，`body` 含 `empty after strip`，而非 `200 ""`

## 4. 测试与门禁

- [x] 4.1 补 PII 稳定性与并发单测 + 空流单测，更新 `audit_approve_stream_test.py` 的空流断言为 `bytes_written` 语义
  - 验收：`pytest -q` 全绿（含新增 3+ 用例），`ruff check .` 与 `ruff format --check .` 全绿（`_llm.py` 的 ContextVar reset 以 `contextlib.suppress` 替代 `try/except pass`）

- [x] 4.2 本地联调：`PII_REDACTION_ENABLED=1` 下连续同请求脱敏后一致；`v1/responses` 空流与 `hold` 悬挂场景复现不复现
  - 验收：`pytest -k "concurrency or empty or global_lru or restore_move" -v` 自动化通过；`curl` 经 `credential-proxy` 到上游的脱敏后 `body` 两次 `diff` 为 0 为手动补充（需捕获上游请求体，非 `curl` 客户端直接可观测）

## 5. 版本与发布

- [x] 5.1  bump `pyproject.toml` / `README` 版本至 `v0.9.6`，更新 `CHANGELOG` 与 `openspec` 产物的归档前置
  - 验收：`openspec validate llm-pii-cache-concurrency --strict` 通过，`tasks.md` 全勾后 `openspec status` 显示 `All artifacts complete`（`CHANGELOG` 以 `README.md` 的 `v0.9.6` 条目为等效记录）
