## Context

当前态见 proposal：`v0.9.9~v0.9.14` 已把请求/响应/SSE 的顶层与嵌套 JSON 字符串做到 `loads→walk→dumps(ensure_ascii=False, separators=(',',':'))` 且支持 BOM 与 `[DONE]` 早退，但请求侧保留 `len>1M → plain`，新增全量守门对 happy path 多 6 次 `loads`，全量回退一次性泄漏整个 payload。约束：Mixin 多文件拆分、`proxy.py` 的 `body_text` 仅三对话尾 JSON-aware、`pii_enabled` 时先 PII 后凭据、`ruff`/`pytest` 门禁、`orjson` 可选。

## Goals / Non-Goals

**Goals:**
- C 方案：删除所有 `len>1M → plain`，大包亦走 json-aware，`orjson` 时延 2-3ms，`stdlib` 亦可接受
- A 粒度：叶子级最小回退，坏叶子仅回退自身，其他脱敏保留，泄漏最小
- 性能：happy path 无替换时 0 额外 `loads`，有替换时仅叶子级 `jdumps(小串)`，全量兜底仅异常触发

**Non-Goals:**
- 不改 `pii_redact` 的 `PII_HOLD_MAX`/`PII_SCAN_INPUT_LIMIT` 等限流，不动 `audit` 形态
- 不引入对 `v1/models` 等非对话尾的脱敏；不对 `tool_calls.arguments` 做流式增量合并，仅整行整包整叶子

## Decisions

**D1 orjson 封装 `_jloads/_jdumps`，无则回退 stdlib**
- 备选：直接 `import orjson` 强依赖 → 无轮子环境启动失败
- 选用：`try: import orjson; _jloads = orjson.loads; _jdumps = lambda o: orjson.dumps(o).decode()` else `stdlib`，调用方无感知；`orjson` 默认紧凑无空格、UTF-8 不转义，与 `ensure_ascii=False, separators=(',',':')` 等价，空白/`\u` 差异属 spec 声明的语义等价

**D2 叶子级校验仅在 `new_s != s` 时触发**
- 备选：每叶必 `dumps` → 99% 未命中叶子白付 0.003ms * 叶子数
- 选用：`pat.search` 命中且替换前后不等才 `jdumps(new_s)`，未命中 0 成本；失败 `warning(path, leaf_preview, new_preview)` 并 `return s`

**D3 walk 透传 `path`（JSON Pointer）**
- 备选：不传 path → warning 无法定位坏叶子
- 选用：`_cred_json_walk(obj, func, path="$")` 递归时 `f"{path}.{k}"` / `f"{path}[{i}]"`，叶子 warning 带 path，内层嵌套 JSON 字符串的内层 path 拼为 `f"{path}→$.inner"`

**D4 外层全量兜底仅 `active_t2p` 非空时触发，内部先叶子重建**
- 备选：每请求必全量 `jloads` → happy path 多 2 次大 loads
- 选用：`_llm.py` 的 `out_body` / `out_text` 二次校验前判 `has_cred or has_pii`，无替换直接跳过；若仍失败，复用 walk 的叶子重建再 `jdumps` 一次，仍失败才 `return original` 全量回退

**D5 嵌套 JSON 字符串叶子同走 orjson**
- 叶 `lstrip('\ufeff').strip()` 后 `{`/`[` 且 `jloads` 为 `dict/list` 时内层同 walk→jdumps，失败回退 leaf plain，保持与 `fix-json-nested-restore` 一致

## Risks / Trade-offs

- [Risk] `orjson` 对 `NaN/Infinity` 抛错而 `stdlib` 放过 → Mitigation：`_jloads` 外层 `try: orjson.loads except: fallback stdlib loads`，日志 `debug` 不阻断
- [Risk] `orjson.dumps` 与 `stdlib` 在 `\u2028` 等转义上文本不等 → Mitigation：spec 已声明语义等价以 `jloads` 相等验收，不做字符串相等断言
- [Risk] 叶子级 `jdumps` 对合法大叶子（1M 叶）开销 → Mitigation：叶级仅对 `new_s != s` 且叶长 < 1M 时校验，超长叶跳过校验直接信任 `jdumps`（整包 `jdumps` 已兜底）
- [Risk] `path` 透传在 `dict` 无序时不稳定 → Mitigation：仅用于日志定位，不参与逻辑分支
- [Risk] 离线环境无 `orjson` 轮子 → Mitigation：`requirements` 标 `orjson>=3.9` 为可选，`Dockerfile` 预装但启动回退保证可用

## Migration Plan

- 依赖：`pip install orjson`（本地）与 `Dockerfile`/`pyproject` 新增可选依赖；无则回退
- 部署：随 `v0.9.15` 发布，无配置/数据迁移；回滚 `git revert` 三文件 + `orjson` 可保留
- 验证：`ruff check/format` + `pytest 173` + 新增 `test_orjson_leaf_fallback`（1.2MB 含 `p@ss"quote` + 单坏叶子隔离 + SSE 单行隔离）+ 1MB 压测对比 `stdlib vs orjson` (<5ms vs 12ms)

## Open Questions

- 1MB 阈值是否保留为日志 `warning` 阈值（超 1MB 打 `extra_large_json` 调试日志）还是完全静默？暂定静默，待观测后补
