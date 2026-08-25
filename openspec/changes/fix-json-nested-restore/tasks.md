## 1. 嵌套 JSON 的 token/pii 层

- [x] 1.1 扩展 `_token.py` 的 `_cred_json_walk`：`str` 分支先 `lstrip("\ufeff")` 后 `strip` 再判 `{`/`[`，成功且 `json.loads` 为 `dict/list` 时递归 walk 后 `json.dumps(..., ensure_ascii=False, separators=(',',':'))` 回写，失败回退原 `redact_func`；同步覆盖 `_redact_json_aware` 与 `_restore_json_aware` 的叶处理（含 BOM 剥离）
  - 验收：`_redact('{"k":"{\"key\":\"__VG_CRED_000001__\"}"}')` 嵌套还原/脱敏后外层与内层均 `json.loads` 合法（含 `p@ss"quote`）；`"\ufeff{\"k\":\"__VG_CRED_000001__\"}"` 同正确；`"{not json"` 保持 plain
- [x] 1.2 扩展 `_pii.py` 的 `_pii_json_walk`：同 D1 嵌套分支（含 BOM 剥离），对内层递归 `await _pii_json_walk` 后 `dumps` 回写，异常回退 `detect_and_redact`
  - 验收：`pii_redact_json_aware('{"a":"{\"x\":\"13800138000\"}"}')` 内层手机号被替换且双层合法；`"\ufeff{\"a\":1}"` 合法

## 2. LLM 代理的 SSE 与非流式闭环

- [x] 2.1 新增 `_llm.py: async def _pii_process_sse_line(line: str, active_t2p: dict) -> str`：`payload = line.split(":",1)[1].lstrip(" \t") if ":" in line else ""`，`payload.lstrip("\ufeff").strip() in ("","[DONE]")` 早退原样，非 `lstrip("\ufeff").strip().startswith(('{','['))` 回退 `await self._pii_response_process(line, active_t2p)`，否则 `payload_aware = await self._pii_response_process_json_aware(payload, active_t2p)` 后 `return "data: " + payload_aware`，异常 `logger.debug` 回退 plain（含 PII 响应侧检测）
  - 验收：`data: {"choices":[{"delta":{"tool_calls":[{"function":{"arguments":"{\"key\":\"__VG_CRED_000001__\"}"}}]}}]}` 含 `p@ss"quote` 时 `json.loads(payload)` 与 `json.loads(arguments)` 均合法；`data: \ufeff{"a":1}` 同合法
- [x] 2.2a 替换 slow path 的 `data:` 行：`grep -n "await self._pii_response_process(line\|ev" _llm.py` 中 `is_responses_stream/is_anthropic_stream` 为 false 且非 fast 守门的 10 处（含 `tool_calls_pending_events` 两段放行、`_release_hold`/`_reject_*` 透传、非 content 事件、`byte_buf` 已除外）改为 `await self._pii_process_sse_line`
  - 验收：`grep -c "await self._pii_process_sse_line" _llm.py` ≥10；slow 区 `grep -c "await self._pii_response_process(line"` 仅残余 `byte_buf` 与 `_flush_*_buf` 内 `buf` 路径
- [x] 2.2b fast path 保持 plain：`_llm.py` 的 `active_t2p==0 and not _pii_active() and not audit_enabled()` 分支不替换，保留 `await self._pii_response_process(line, active_t2p)`
  - 验收：fast 区无 `_pii_process_sse_line`，slow 区全替换（`grep` 双断言通过）
- [x] 2.3 非流式嵌套由 walk 层覆盖（删除外层二次 loads）：`handler` 非流式 `out_text = await _pii_response_process_json_aware(resp_text, active_t2p)` 的嵌套已由 1.1 walk 递归覆盖，不另做二次 `loads/dumps`；仅在 walk 层实现嵌套
  - 验收：非流式 `{"choices":[{"message":{"tool_calls":[{"function":{"arguments":"{\"key\":\"__VG_CRED_000001__\"}"}}]}}]}` 含 `p@ss"quote` 时双层合法；代码中无外层二次 `json.loads(out_text)` 嵌套回写
- [x] 2.4 同步 `_strip_token_forms_json_aware` 的嵌套处理：叶字符串内嵌套 JSON 的 token 形态同走 `lstrip("\ufeff")→loads→walk(strip)→dumps`，保持幂等
  - 验收：`_strip_token_forms_json_aware('{"a":"{\"k\":\"__VG_CRED_000001__\"}"}')` 双层合法且 `__VG_CRED` 被剥离
- [x] 2.5 续行重建与 flush 缓冲显式处理：`_llm.py:2312` 续行重建的 `sanitized` 走 `_pii_process_sse_line('data: '+sanitized)`；`_flush_anthropic_buf/_flush_responses_buf` 的 `arg_buf` 为非完整行时仅 best-effort（`strip().lstrip("\ufeff")[0]∈{, [}` 则尝试嵌套，失败回退 plain），并在 design Non-Goals 显式豁免半行 flush
  - 验收：续行 `data: {"a":` + `sanitized` 重建后经 helper 双层合法；`arg_buf` 的 `"{not json"` 不抛异常

## 3. 测试

- [x] 3.1 新增 `pii_llm_test.py` 用例：`test_nested_tool_args_special_chars_stream` 与 `test_nested_tool_args_special_chars_non_stream`（凭据 `p@ss"quote` + `\u0031` 劫持），断言外层与内层 `json.loads` 均合法且值正确
  - 验收：两用例在 `.venv/bin/python -m pytest pii_llm_test.py -k nested -q` 通过
- [x] 3.2 边界与形态：`"{not json"` / `"\ufeff{\"a\":1}"` / `data: [DONE]` / `data:[DONE]` / `data:  ` / `data: not-json` / `data: \ufeff{"a":1}` / 空体 / `v1/models` 透传 / `{"a": 1}`→`{"a":1}` 语义等价（`json.loads` 相等）的 fallback 与序列化形态均不抛异常
  - 验收：`pytest -q 394+` 全绿；`json.loads` 语义等价断言通过

## 4. 门禁与发布

- [x] 4.1 `ruff check .` 与 `ruff format --check .` 全绿；`openspec validate fix-json-nested-restore --strict` 通过
  - 验收：三命令在仓库根均 exit 0
- [x] 4.2 版本与文档：`pyproject.toml` bump 至 `v0.9.10`，`README` 补充 `ensure_ascii=False` 非字节级保持声明
  - 验收：`grep -rn "ensure_ascii" README.md` 有记录
- [x] 4.3 日志/性能/CHANGELOG：`grep -rn "logger.debug.*回退" _llm.py _token.py _pii.py` 均存在且不拼接明文；叶内一次 `loads` 性能 best-effort（p95 回归 <5% 或声明零成本）；`CHANGELOG.md` 追加 `v0.9.10 修复嵌套 arguments 流式/非流式转义破坏`
  - 验收：`grep -n "0.9.10" CHANGELOG.md` 命中
