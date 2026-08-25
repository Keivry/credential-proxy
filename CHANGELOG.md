# Changelog

- **v0.9.11** — 补全增量 JSON-aware 遗漏：`_llm._flush_anthropic_buf/_flush_responses_buf` 与增量 `arg_buf`（`response.function_call_arguments.delta` / `input_json_delta.partial_json`）改走 `_pii_response_process_json_aware`（覆盖 `p@ss"quote`/`\u` 等特殊字符，片段不完整时自动回退 plain 且 safe/pending 分割保持），修复完整 `arg_buf` 的 `{"key":"p@ss"quote"}` 未转义导致 `Expecting ',' delimiter` 闭环；继续沿用 `len>1M` 与 `depth>5` 守卫
- **v0.9.10** — 修复嵌套 JSON 串的脱敏还原破坏：`_token._cred_json_walk` 与 `_pii._pii_json_walk` 对叶字符串内嵌套 JSON 递归 `walk→dumps(ensure_ascii=False)`，覆盖 `tool_calls.arguments` 等 `stringified JSON`；`_llm._pii_process_sse_line` 对 `data: {JSON}` 行做 JSON-aware（含 BOM `\ufeff` 剥离、`[DONE]`/空行早退、`data:[DONE]` 多空格兼容），替换 slow path 的 `data:` 行；非流式由 walk 层覆盖；`separators`/`ensure_ascii` 形态变更属语义等价（非字节级保持）；新增 7 个回归用例
- **v0.9.9** — JSON-aware 热修复：顶层 JSON 叶节点 `loads→walk→dumps`，修复 `\u` 劫持与 `p@ss"quote` 未转义两类 `JSONDecodeError`
- **v0.9.8** — 空 SSE/非 JSON 空体转 502 守门
- **v0.9.7** — 修复 `CREDENTIAL_PROXY_DEBUG_DIR` 对 Responses API 保存失效
- **v0.9.6** — PII 全局持久化 + 并发隔离 + 永不空流
