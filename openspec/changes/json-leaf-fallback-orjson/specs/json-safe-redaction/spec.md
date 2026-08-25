## MODIFIED Requirements

### Requirement: Top-level JSON leaves SHALL remain valid JSON after redaction
系统在处理下游请求体为合法 JSON（object/array）时，对凭据/PII 的脱敏 SHALL 仅对解码后叶字符串值操作，再经 `jdumps(ensure_ascii=False, separators=(',',':'))` 回写，不在序列化文本上做子串替换；`len>1_048_576` 的大 JSON 亦 SHALL 走同一 json-aware 路径，不再回退 `plain`（`orjson` 时延 2-3ms，`stdlib` 12ms 亦可接受）。

#### Scenario: Large JSON still valid via orjson
- **WHEN** 请求体为 1.2MB 合法 JSON 且含 `p@ss"quote` 秘密
- **THEN** 脱敏后经 `orjson` 仍为合法 JSON 且秘密被替换为 token，耗时 <5ms

#### Scenario: Request with special chars stays valid JSON
- **WHEN** 请求体为 `{"content":"p@ss\"quote"}` 且凭据含 `"` 时走 `_redact_json_aware`
- **THEN** 输出仍为合法 JSON 且 `content` 解码后等于 token

### Requirement: Top-level JSON leaves SHALL remain valid JSON after restore
系统在处理上游响应体为合法 JSON 时的凭据/PII 还原 SHALL 同叶节点语义，`jdumps` 负责转义含 `"`/`\`/`\n` 的明文，不在序列化文本上做 `token→pwd` 的 plain 替换；大 JSON 同样走 json-aware。

#### Scenario: Response restore with quote stays valid via orjson
- **WHEN** 响应体为 `{"choices":[{"message":{"content":"echo __VG_CRED_000001__"}}]}` 且 token 映射到 `p@ss"quote`
- **THEN** 输出为合法 JSON 且 `content` 解码后为 `echo p@ss"quote`，`orjson` 与 `stdlib` 语义等价

### Requirement: Fallback SHALL stay closed on non-JSON and errors
当文本非合法 JSON 或内层解析抛异常时，系统 SHALL 回退到 plain 路径，不泄露异常且不破坏原文结构；但对合法 JSON 的大包 SHALL 不再以 `len` 为由回退 plain。

#### Scenario: Non-JSON body falls back
- **WHEN** 文本为 `hello __VG_CRED_000001__ world` 非 JSON
- **THEN** 走 plain 替换，输出为明文替换结果

#### Scenario: Malformed JSON fallback does not throw
- **WHEN** 文本为 `{"a": "unterminated`（缺引号）
- **THEN** 输出为 plain 替换结果，不抛 `JSONDecodeError` 到调用方

## ADDED Requirements

### Requirement: Leaf-level minimal fallback on JSON-aware redaction/restore
对合法 JSON 的每个叶字符串，系统 SHALL 仅在 `pat` 命中且替换前后不等时，对新值做 `jdumps(new_leaf)` 叶子级校验；若校验失败 SHALL 仅回退该叶子为原值并 `warning(path, leaf_preview, new_preview)`，其他叶子保留脱敏/还原；`path` 为 JSON Pointer 风格（如 `$.choices[0].message.content` 或 `$.tool_calls[0].function.arguments` 内层 `$.key`）。

#### Scenario: Single bad leaf does not leak other redactions
- **WHEN** 请求体为 `{"a":"secret1","b":"secret2"}` 且 `secret1` 映射值含不可序列化的 unpaired surrogate 而 `secret2` 正常
- **THEN** 输出仍为合法 JSON，`a` 回退为原值 `secret1`，`b` 仍为 token，日志含 `path=$.a`

#### Scenario: Nested leaf fallback isolated
- **WHEN** `arguments` 内层 JSON `{"key":"__VG_CRED_000001__","ok":"hi"}` 中 `key` 对应 token 映射值校验失败
- **THEN** 内层 `key` 叶回退，外层与内层其他字段仍正确，内外层均合法

### Requirement: orjson acceleration with stdlib fallback
系统 SHALL 优先使用 `orjson` 做 `loads/dumps`（`dumps` 返回 `bytes` 需 `.decode()`），若 `import orjson` 失败 SHALL 自动回退 `stdlib json` 且不阻断启动；两者 SHALL 保持 `ensure_ascii=False, separators=(',',':')` 的语义等价（空白压缩/`\u`→明文）。

#### Scenario: orjson available uses fast path
- **WHEN** 环境已 `pip install orjson`
- **THEN** `_jloads/_jdumps` 走 `orjson`，1.2MB 包耗时 <5ms

#### Scenario: orjson missing falls back to stdlib
- **WHEN** 环境未安装 `orjson`
- **THEN** 启动不报错，`_jloads/_jdumps` 走 `stdlib`，功能与校验一致，仅性能回退

### Requirement: Outer whole-JSON guard only on actual replacement
请求/响应侧的外层全量 `jloads(out)` 兜底 SHALL 仅在 `active_t2p` 非空（实际发生替换）时触发；若仍失败 SHALL 先尝试按叶子重建（复用 leaf fallback 逻辑），仍失败才全量回退并 `warning(input_preview, output_preview)`。

#### Scenario: No replacement no extra loads
- **WHEN** JSON 合法但 `active_t2p` 为空
- **THEN** 不做外层全量 `jloads` 校验，0 额外开销

#### Scenario: Whole guard triggers leaf rebuild before full fallback
- **WHEN** 全量 `jdumps` 后 `jloads(out)` 失败（仅理论兜底）
- **THEN** 系统先按叶子重建一次，仍失败才返回 `original` 并打全量预览 warning

### Requirement: SSE data lines SHALL remain valid JSON after restore with leaf fallback
对 `data: {JSON}` 行的 `payload`，系统 SHALL 同全量一致走叶子级校验，坏叶子仅回退该行内该叶子，其他行不受影响。

#### Scenario: Bad leaf in SSE line isolated
- **WHEN** 行 `data: {"choices":[{"delta":{"content":"hi __VG_CRED_000001__"}}]}` 中叶子校验失败
- **THEN** 该行内该叶子回退，该行仍为 `data: ` + 合法 JSON，其他 SSE 行正常
