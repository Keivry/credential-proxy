## Why

当前 PII 网关在 `llm-privacy-gateway` 与后续 4 个 JSON 修复 change 后已可用，但对四家高星项目（LiteLLM 57k、Portkey 12.8k、protectai/llm-guard 3.2k、NVIDIA NeMo-Guardrails 7k）的横向对比显示仍有三处结构性短板：walk 逻辑在 `_token`/`_pii`/`_llm` 三处分叉易漂移、流式残余仍用 `str.replace` 存在重叠错位与前缀泄漏、Vault 下标分配简单递增在空洞场景会复用歧义且无模糊容错。这些是网关独有的复杂面，库派/编排派已用验证过的模式解决。

## What Changes

- 抽取统一 `json_walk` 能力：合并 `_token._cred_json_walk` / `_pii._pii_json_walk` / `_llm._pii_response_process_json_aware` 为单一共享实现（`utils/json_walk.py`），统一 `orjson`+BOM+depth+嵌套 `arguments` 递归+叶子级回退单口径，调用方仅传 `leaf_fn`。
- 加固 Vault 稳态映射：同值同 token（请求级 + Vault 已有值复用）、空洞跳过的 `next_available_index`（`secrets.token_hex(4)` 生成 `rand8` 组成 `__PII_<seq>_<rand8>__`，`_restore` 仅 `placeholder_exists` 时还原）、剩余前缀 `__PII_*`/`__VG_CRED_*` 的统一清理（借鉴 `TextReplaceBuilder` 倒序语义以 `sorted(reverse=True)` 等价实现，`hold` 侧阈值 `<64`），可选大小写不敏感/模糊还原（默认关闭，仅 `re.IGNORECASE`）。
- 加固流式残余：`byte_buf` SSE 帧完整性（WHATWG `CRLF/LF/CR` + `:` 注释透传 + 同事件多 `data:` 行 `data_buffer` 聚合 + `BOM` 单次剥离）+ 正文本 `line_buf` 按 `\n` 逻辑行缓冲替换（`\r\n`/`\r` 归一，覆盖 `content/reasoning/refusal` 与 `choices[]` 全量遍历 + Responses `refusal/reasoning_summary_text/audio.transcript` 等文本 `delta`）+ 工具参数 `arg_buf` 攒整段（覆盖 `function_call` 废弃形态与 `mcp/custom_tool/code_interpreter/shell` 等） + 注释保活（`: keepalive` 10s）与超长 16KB/30s 强制 flush，统一倒序残缺清理与截断合成。
- 检测侧硬化（默认关闭，不改现有行为）：`AnalyzerEngine` 级缓存（`lru_cache`）、保留地址前缀精确匹配（`10.`/`172.16.`-`172.31.`/`192.168.` 等含尾点/冒号）、ReDoS 线程超时守卫与输入上限、字典名单独立扫描不并入联合正则。

## Capabilities

### New Capabilities

- `json-walk-consolidation`: 统一 JSON 语义遍历与叶子级回退，消除三处 walk 分叉，覆盖嵌套 JSON 字符串与流式 `data:` 行。
- `vault-stable-mapping`: 稳态占位符映射与残缺清理，含同值复用、空洞跳过、随机段与可选模糊还原。
- `streaming-residual-hardening`: 流式三层缓冲（`byte_buf` 帧含 `data_buffer` 聚合/`line_buf` 正文行含 `refusal` 与 `choices` 全量/`arg_buf` 工具整段含 `function_call` 废弃与 `mcp/custom_tool` 等）的倒序安全替换、候选感知兜底、注释保活与超长强制（7 Requirements：SSE帧/line_buf/arg_buf/多choices/keepalive/超长/截断）。
- `pii-detection-hardening`: 检测健壮性细化（保留地址精确前缀、ReDoS 防护、字典独立扫描、Analyzer 缓存），默认关闭不改现有行为。

### Modified Capabilities

- `llm-privacy-gateway/streaming-*` 隐式行为细化（非 spec 文本修改）：`PII_HOLD_MAX` 字节窗口由 `line_buf` 行缓冲吸收，仅在 `16KB/30s` 超长强制路径保留前缀候选感知语义；`_strip_partials` 由散落正则收敛为单一函数

## Impact

- **新增文件**：`utils/json_walk.py`（`utils/json_walk.py`，共享 walk+`TextReplaceBuilder` 倒序语义，含 `sync json_walk` 与 `async json_walk_async` 双形态），新增单测 3 文件：`tests/vault_stable_test.py`、`tests/residual_hardening_test.py`、`tests/detection_hardening_test.py`（`tests/` 目录，若平铺则为根 `*_test.py`）
- **修改文件**：`_token.py`、`_pii.py`、`_llm.py`（接入共享 walk 与统一残缺清理 `_strip_partials`/`_has_partial_pii_candidate`，Vault `register/next_available_index/rand8` 主体在 `_pii.py`+`_token.py`）、`proxy.py` 仅做 `PII_FUZZY_RESTORE` 启动校验（非法值报错）（+ `uv.lock` 依赖锁由 `orjson` 引入）
- **API/配置**：新增 1 个默认关闭环境变量 `PII_FUZZY_RESTORE`（默认 `0`，`1` 时 `re.IGNORECASE`，非法值 `proxy.py` 启动时报错），不破坏现有 3 个对话尾与 `v1/models` 透传；`PII_VAULT_GAP_AWARE` 为内置稳态行为（`next_available_index` 空洞跳过）非开关；`PII_HOLD_MAX`/`PII_SCAN_INPUT_LIMIT`/`PII_RE_DOS_BUDGET` 等为 `llm-privacy-gateway` 已有常量复用；流式阈值 `SSE_MAX_BUF=1MB`/`LINE_BUF_FLUSH=16KB`/`LINE_BUF_MAX_AGE=30s`/`KEEPALIVE_INTERVAL=10s` 为硬编码常量非环境变量
- **依赖**：零新增依赖（复用 `orjson`/`secrets`/`lru_cache`/`ThreadPoolExecutor`/`asyncio.timeout`），复用 `presidio_anonymizer.TextReplaceBuilder` 倒序语义（不新增 presidio 依赖，仅借鉴模式）
- **测试/门禁**：`pytest` 全绿、`ruff check`/`format --check` 零告警；新增 11+ 回归用例覆盖 `streaming 11`+`vault 7`+`json-walk 7`+`detection 11` 场景（proposal 原 8-10 为估算，现按 spec 36 场景全覆盖）
