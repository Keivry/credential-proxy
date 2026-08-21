## Context

见 `proposal.md Why`。`llm-privacy-gateway` 已上线（`v0.9.0-0.9.5`），`PII` 默认关闭、`AUDIT_MODE` 支持 `off/block/approve`，`LLM` 代理已覆盖 `chat/completions` / `v1/messages` / `v1/responses` 三协议的流式/非流式。`v0.9.5` 引入 `audit_block_injected` 永不空流但仍以 `sse_event_count` 守门，且 `PII` 仍为每请求 `new RequestScopedTokens` + `self._pii_scope` 共享实例变量。上游为 `opencode.ai/zen` 与 `commandcode`，`hermes` 侧 `codex_responses` 走 `v1/responses` SSE，命中空流即 `JSONDecodeError` 重试 5 次后沉默。

## Goals / Non-Goals

**Goals:**
- 同值 `PII` 跨请求稳定复用，`prompt cache` 可命中
- 并发 `LLM` 请求状态零覆盖、可重入
- 任何路径永不向客户端返回 `200 空体/空 SSE`

**Non-Goals:**
- 不引入新的持久化存储（`PII` 仍内存 `LRU`，重启后新随机可接受）
- 不改变 `PII` 检测规则与保留地址清单
- 不新增环境变量或对外 `API`

## Decisions

### D1 — PII 全局持久 LRU（方案 B）

**选择：** `_token.py RequestScopedTokens` 改为进程级全局单例 `GlobalPiiTokens`（`pii_p2t/pii_t2p + resp_* + _seq + asyncio.Lock + LRU 1000` 真 LRU 淘汰、最久未用者先出 `OrderedDict.move_to_end + popitem(last=False)`，与凭据 `MAX_TOKEN_ENTRIES=5000` 区分）。`PiiMixin._init_pii` 创建单例、`_pii_request_scope` 返回单例复用、`_pii_cleanup` 不再 `clear()`。`register` 改为 `async def register` 并以 `async with self._lock` 保护（同步 `def` 内不可 `await`，须与凭据 `_register_secret` 同为异步），命中复用已生成 `__PII_<seq>_<rand8>__`；未命中一次性 `secrets.token_hex(4)` 后持久。

**备选：** `HMAC(pepper,value)` 确定性（跨重启也稳定）——但需新增 `pepper` 密钥管理且首次即暴露可关联性；随机持久已满足“同值同 `token`”，重启后新随机的 cache miss 可接受，选更简单方案。

**理由：** 最小改动复用现有 `register` 逻辑，仅生命周期与签名变更；与凭据 `pwd_to_token` 语义一致，易于 `asyncio.Lock` 保护。

### D2 — 并发隔离用 ContextVar + 请求局部变量

**选择：** 将 `handler` 内所有每请求可变状态收敛为两种：① `ContextVar`（`_pii_scope_var / _audit_hold_active_var / _audit_hold_buf_var / _audit_hold_bytes_var / _audit_arg_accum_var / _last_responses_tool_name_var / _last_anthropic_tool_name_var`）用于跨 `await` 调用的 `PiiDetector` 与 `AuditMixin` 回调读取；② `handler` 闭包局部变量（`tool_calls_buf / tool_calls_pending_events / tool_calls_audited / tool_calls_blocked / sse_event_count / fast_sse_event_count / bytes_written / audit_block_injected / is_responses_stream / is_anthropic_stream / content_buf / reasoning_buf / arg_buf` 等）用于流循环。每请求 `token = contextvars.ContextVar.set()` → `finally` 中 `reset(token)`。

**备选：** 仅用局部变量透传参数——但 `PiiDetector` 与 `_audit.py` 回调深嵌，透传改动面大；`ContextVar` 对 `asyncio` 天然隔离且与 `asyncio.Lock` 兼容。

**理由：** `ContextVar` 是 `asyncio` 官方并发隔离原语，改动集中在 `proxy.py/_pii.py/_audit.py/_llm.py` 的状态存取点，无需改所有函数签名。显式枚举清单分两段验收：① `grep -rn "self\._pii_\|self\._audit_\|self\._last_" _llm.py _pii.py _audit.py` 仅在 `ContextVar` property 定义处命中；② `grep -rn "self\.tool_calls_\|self\.sse_event_\|self\.bytes_written\|self\.audit_block_injected\|self\.is_.*_stream" _llm.py` 为 0，且 `grep -n "^\s*tool_calls_\|^\s*sse_event_\|^\s*bytes_written\|^\s*audit_block_injected\|^\s*is_.*_stream" _llm.py` 命中 handler 局部定义，防止遗漏。

### D3 — 空体守门按 bytes_written，hold 悬挂流末强制处置

**选择：** `heavy/fast` 两路径各维护 `bytes_written/fast_bytes_written`（每次 `await resp.write` 成功累加，`SSE_CLIENT_GONE/ConnectionResetError` 不计数）。流末 `if bytes_written==0 and upstream.status==200:` 注入最小协议事件（`chat→_build_block_event`，`responses→_build_block_event_responses`，`anthropic→_build_block_event_anthropic`）；`upstream.status` 非 200 时不注入（`502/401` 透传）。`audit_hold` 若流末仍 `active`，先 `await _reject_*_hold(write, …)`（失败仍走守门）再走 `bytes_written` 守门。非流式在 `_strip_token_forms` 后 `if not out.strip(): return 502`，响应为 `application/json` 且 `body={"error":{"message":"empty after strip"}}`，`content-type: application/json`，并记 `error` 日志。

**备选：** 仅 `sse_event_count==0`——已证实 `hold` 缓冲场景下 `event_count>0` 但 `bytes_written==0` 仍空。

**理由：** “是否真正写过字节”是唯一与客户端可观测一致的守门条件，覆盖所有缓冲与剥离路径。

## Risks / Trade-offs

- [PII 跨请求可关联] → Mitigation: 已与用户确认接受，属隐私-缓存权衡；文档中明示，默认仍 `PII_REDACTION_ENABLED=0` 时无影响
- [全局 LRU 内存增长] → Mitigation: 上限 `1000` 单表上限（`pii/resp` 各 1000，总量≤2000，真 LRU `OrderedDict.move_to_end + popitem(last=False)` 最久未用者先出），与凭据 `5000` 区分，`LRU` 保证热值常驻、冷值淘汰；非 FIFO
- [ContextVar 遗漏点] → Mitigation: 分段扫描 `grep -rn "self\._pii_\|self\._audit_\|self\._last_"` 验 `self` 残留 + `grep -rn "self\.tool_calls_\|self\.sse_event_"` 为 0 + `grep -n "^\s*tool_calls_\|bytes_written"` 验局部，逐一迁 `ContextVar`/局部，`ruff` + `pytest` 拦截未迁引用；重链路 `audit_enabled()/pii_active()` 仍强制走 heavy，但 D2 隔离后不再串扰，性能开销为已知权衡
- [注入内容误判协议] → Mitigation: 按 `tail` 形态选注入器，`hermes` 三协议回归覆盖

## Migration Plan

1. 部署本镜像（`MIGRATION: PII` 映射重启后清空，首批请求重建，`cache` 短暂 `miss` 后稳定）
2. 回滚：直接回退镜像，`PII` 自动回每请求隔离（`cache` 再次穿透但功能可用）
3. 存量 `audit.log` 无需迁移

## Open Questions

无——三决策均已与用户确认（`PII` 选 `B`、并发必做、空体按 `bytes` 守门）。

