## Why

v0.9.8~v0.9.14 的 JSON-aware 链路已把顶层/嵌套/SSE 行的 `p@ss"quote` / `\u` 破坏修复，但仍保留请求侧 `len>1M → plain str.replace` 回退，且新增的全量 `json.loads` 守门对每个请求做 6 次全量解析，happy path 冗余且 1MB 大包 12ms 偏慢。若守门触发全量回退会一次性泄漏整个 payload 的全部 secret。需一次性切换到 C 方案：无 plain 回退 + 最小叶子级回退 + orjson 加速。

## What Changes

- 移除三处 `len>1_048_576 → plain` 守门（`_token._redact/_restore`、`_pii.pii_redact_json_aware`），全量走 `loads→walk→dumps`（C 方案）
- 引入 `orjson`（有则用，无则回退 `stdlib json`），统一封装 `_jloads/_jdumps`，保持 `ensure_ascii=False, separators=(',',':')` 语义等价（空白压缩/`\u`→明文）
- `walk` 叶子级最小回退：仅对 `pat` 命中且值变化的叶子做 `jdumps(leaf)` 校验，失败仅回退该叶子并 `warning(path, leaf_preview)`，其他叶子保留脱敏/还原；全量 `jloads(out)` 兜底，仍失败才全量回退
- 外层 `_llm.py` 请求/响应二次校验仅在 `active_t2p` 非空时触发，happy path 0 次额外 loads
- SSE 行保持按行 JSON-aware，最小回退粒度为单行 payload

## Capabilities

### New Capabilities
<!-- 无新增能力，本 change 为对既有能力的增强 -->

### Modified Capabilities
- `json-safe-redaction`: 将 JSON 安全脱敏/还原从“全量回退 + 1M plain”升级为“orjson 全量 json-aware + 叶子级最小回退 + 按需全量兜底”，不再以大量全量 loads 为代价

## Impact

- 影响文件：`_token.py`、`_pii.py`、`_llm.py`、`requirements.txt`/`pyproject.toml`（新增 `orjson` 可选依赖）、`Dockerfile`（如需）、`openspec/specs/json-safe-redaction` 的 delta
- 影响 API：`POST /{tail}` 三对话尾（`chat/completions` / `v1/messages` / `v1/responses`）的请求脱敏与流式/非流式响应还原；`v1/models` 等非对话尾不透传脱敏逻辑不变
- 依赖：新增可选 `orjson>=3.9`（轮子 300KB，有则加速 3-5 倍，无则回退 stdlib，不阻断启动）
- 运维：日志 `warning` 从“全量 input/output 预览”细化为叶子级 `path + leaf_preview` + 全量兜底时才打全量预览；`ruff` / `pytest` 门禁保持
