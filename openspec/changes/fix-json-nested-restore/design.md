## Context

当前态：`3e104fe (v0.9.9)` 引入 `_token._redact_json_aware/_restore_json_aware`、`_pii.pii_redact_json_aware`、`_llm._strip_token_forms_json_aware/_pii_response_process_json_aware`，对**顶层** JSON 文本做 `loads → walk 叶字符串 → dumps(ensure_ascii=False, separators=(',',':'))`，已修复请求侧 `\u` 劫持与响应侧 `p@ss"quote` 未转义两类 `JSONDecodeError`。约束：`proxy.py` 的 `body_text` 仅对三对话尾做 JSON-aware，其余尾原样透传；`dumps` 统一 `ensure_ascii=False`。

遗留：`handler` 流式 `data: {JSON}` 行与 `tool_calls.arguments` 等**叶内嵌套 JSON 字符串**未递归，`stripped.lstrip("\ufeff").startswith(('{','['))` 对 BOM 未剥离时回退 plain 且 `data:` 前缀未剥离导致恒 false，嵌套叶plain替换破坏内层 `{"key":"p@ss"quote"}`。

## Goals / Non-Goals

**Goals:**
- 流式/非流式、三协议的大 JSON 均经叶节点语义，`"`/`\`/`\n`/`\u` 均不破坏结构（含 BOM `\ufeff` 前缀）
- 嵌套 JSON 字符串（`arguments` 等）递归处理，失败回退 plain
- `data: ` SSE 行按 `split(":",1)` 剥离前缀后 JSON-aware，`[DONE]`/空/非 JSON 早退，`data:[DONE]`/`data:  [DONE]` 等形态兼容

**Non-Goals:**
- 不新增外层存储/配置，不改 `ensure_ascii`/`separators` 语义（空白压缩/`\uXXXX`→明文属显式声明，见 D4）
- 不引入对非对话尾（`v1/models` 等）的脱敏；不做 PII 全局跨请求过滤（另案）
- 不做 `arguments` 的 streaming 增量 JSON 合并，仅处理已落行的完整行；`_flush_anthropic_buf`/`_flush_responses_buf` 的 `arg_buf` 非完整行时仅做 best-effort，失败回退 plain（见 Risks）；`byte_buf` 半行残余不在 JSON-aware 范围（续行重建已覆盖）

## Decisions

**D1 嵌套判定：lstrip("\ufeff") 后 strip 再判 `{`/`[` + `json.loads` 成功且为 `dict/list` 才递归，且递归后 `dumps` 回写**

- 备选：对所有含 `{` 的叶字符串暴力尝试 → 误判率高、性能回归
- 选用：仅对可解析为容器类型的文本递归，`"{not json"` 等回退 plain，BOM 前缀 `\ufeff` 先剥离，成本一次 `loads`，命中率与 `audit_tool_call` 的 `arg_buf` 形态一致

**D2 流式行包装 `_pii_process_sse_line` 而非在每处重复 `if data: loads`**

- 备选：12 处各写一遍前缀剥离+JSON-aware → 遗漏与分歧风险
- 选用：单一 helper `async def _pii_process_sse_line(line: str, active_t2p: dict) -> str`，内部对 `payload = line.split(":",1)[1].lstrip(" \t")` 后 `payload.lstrip("\ufeff").strip() in ("","[DONE]")` 早退，非 `{`/`[` 开头回退 plain，否则对 payload 走 `await self._pii_response_process_json_aware(payload, active_t2p)`（含嵌套递归与 PII 响应侧检测），`[DONE]`/空/非 JSON 早退，异常内 `logger.debug` 后回退 plain，覆盖面与门禁可 grep 验证；fast path（`active_t2p==0 and not pii_active and not audit_enabled`）保持 plain 不替换

**D3 复用现有 walk，不新增序列化形态（嵌套由 walk 层递归，非外层二次 loads）**

- `_token._cred_json_walk` / `_pii._pii_json_walk` 内对 `str` 分支增加嵌套分支（含 BOM 剥离），其余 `dict/list` 分支不动；`_llm._pii_response_process_json_aware` 叶处理中对内层同 `loads→walk→dumps`；非流式整包 `out_text` 的嵌套已由 walk 覆盖，不另做外层二次 `loads/dumps`
- 备选：新增独立嵌套处理器 → 重复代码与两套转义口径
- 取舍：保持单口径 `ensure_ascii=False`，空白不保持属显式声明（见 Risks）

**D4 `separators=(',',':')` 与 `ensure_ascii=False` 保持 v0.9.9 口径，不做 `indent`**

- 中文由 `\uXXXX` 变明文属语义等价，极窄签名场景不在 LLM 上游出现，已在 `README` 补充声明

## Risks / Trade-offs

- [Risk] 递归 `loads/dumps` 额外开销 → Mitigation：仅叶字符串且 `lstrip("\ufeff").strip()[0]∈{, [}` 时尝试一次 `loads`，纯文本叶零成本；`arguments` 叶每行一次
- [Risk] 嵌套 JSON 内再嵌套多层 → Mitigation：递归 walk 天然支持多层，层数受 JSON 深度限制
- [Risk] `ensure_ascii=False` 形态变更（空白/转义） → Mitigation：与 v0.9.9 一致，已声明非字节级保持；spec 新增语义等价契约，任务 4.3 覆盖
- [Risk] 半行残余（跨 `\n` 截断）误判为非 JSON → Mitigation：残余仅在 `byte_buf` 半行路径（`grep` 已除外），续行重建已覆盖；半行回退 plain 不破坏续行重建的 `json.loads(sanitized)`，续行重建的 `sanitized` 走 `split(":",1)` 的 helper
- [Risk] `data:` 前缀多空格/`data:[DONE]` 无空格 → Mitigation：helper 用 `split(":",1)[1].lstrip(" \t")` 统一，`payload.lstrip("\ufeff").strip()` 判空/`[DONE]`
- [Risk] 跨请求 PII 关联 → Mitigation：本 change 不处理，仅在 Risks 显式声明，另案 `GlobalPiiTokens` 隔离；日志 `logger.debug` 不含明文
- [Risk] ReDoS/炸弹 JSON → Mitigation：嵌套 `loads` 仅对叶字符串一次且失败回退 plain，叶文本长度受上游 `PII_SCAN_INPUT_LIMIT=1M` 与 SSE 行长度约束

## Migration Plan

- 部署：随 `v0.9.10` 发布，无配置迁移、无数据迁移；回滚仅 `git revert` 三文件
- 验证：`pytest -q` 全绿 + `ruff check/format` + 2 个新增回归用例（嵌套 `arguments` 流式/非流式含 `"`）

## Open Questions

- 无（`PII_HOLD_MAX` 等保持 64 字节窗口语义，不改）
