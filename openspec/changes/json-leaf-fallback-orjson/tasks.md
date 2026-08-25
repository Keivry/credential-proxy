## 1. 依赖与封装

- [x] 1.1 新增 `orjson` 可选依赖并封装 `_jloads/_jdumps`
  - 验收：`_token.py` 顶部 `try: import orjson; _jloads=orjson.loads; _jdumps=lambda o: orjson.dumps(o).decode()` else 回退 `stdlib`；`import orjson` 失败时启动不报错，`_jloads/_jdumps` 仍可用（`python -c "import _token; print(_token._jloads)"` 不抛）

## 2. _token.py 叶子级最小回退

- [x] 2.1 移除 `len>1_048_576 → plain` 并重写 `_cred_json_walk` 透传 `path`
  - 验收：`grep -n "1_048_576" _token.py` 0 命中；`_cred_json_walk(obj, func, path="$", _depth=0)` 可递归，日志 path 形如 `$.a[0].b`；`_depth>5` 仍直调 `func`

- [x] 2.2 `_redact_json_aware/_restore_json_aware` 叶子级校验与嵌套 orjson 化
  - 验收：`pat` 命中且 `new_s != s` 时 `jdumps(new_s)` 失败仅回退该叶子并 `warning` 带 `path`，其他叶子保留；叶 `lstrip('\ufeff').strip()` 后 `{`/`[` 且 `jloads` 为 `dict/list` 时内层同 walk→jdumps，`1.2MB` 含 `p@ss"quote` 仍合法且 <5ms（orjson）

## 3. _pii.py 叶子级最小回退

- [x] 3.1 同步 `pii_redact_json_aware` 与 `_pii_json_walk` 的 orjson + 叶子校验
  - 验收：`await _pii_json_walk` 内叶分支同 2.2；`pii_redact_json_aware` 无 `len>1M` plain，全走 json-aware；单坏叶子隔离场景 `{"a":"bad_secret","b":"good"}` 中 `a` 回退 `b` 仍 token

## 4. _llm.py 流式/非流式闭环

- [x] 4.1 封装 `_llm._jloads/_jdumps` 并改写 `_pii_response_process_json_aware` 与 `_pii_process_sse_line` 为 orjson
  - 验收：`grep -n "_jloads\|_jdumps" _llm.py` ≥4；`data: {JSON}` 行经 `_pii_process_sse_line` 仍走叶子校验，`[DONE]`/BOM 早退不变

- [x] 4.2 外层二次校验按需触发并先叶子重建
  - 验收：请求 `out_body` 二次校验仅 `has_cred or has_pii` 时做，非流式 `out_text` 校验后失败先叶子重建再全量回退；`active_t2p=={}` 时 0 额外 `jloads`（grep 二次校验前有 `if has_cred or has_pii`）

## 5. 测试与门禁

- [x] 5.1 新增回归用例 `test_orjson_leaf_fallback`
  - 验收：含 ① 1.2MB 大包 `p@ss"quote` 脱敏/还原合法且耗时断言 `<5ms`（orjson）/ `<15ms`（stdlib 回退）② 单坏叶子隔离 `{"a":"secret1","b":"secret2"}` ③ 嵌套 `arguments` 内层单叶回退 ④ SSE 单行隔离；`pytest -k orjson_leaf -q` 通过

- [x] 5.2 全量门禁与发布
  - 验收：`ruff check . && ruff format --check . && pytest -q` 全绿；`openspec validate json-leaf-fallback-orjson --strict` 通过；`pyproject.toml` / `Dockerfile` 的 `orjson` 为可选依赖，`CHANGELOG.md` 追加

