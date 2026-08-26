## Purpose

统一 LLM 网关的 JSON 语义遍历与叶子级回退能力，消除三处 walk 分叉，保证嵌套 JSON 字符串与流式 `data:` 行的脱敏/还原不破坏 `"`/`\`/`\n`/`\uXXXX` 与结构。

## ADDED Requirements

### Requirement: 统一 JSON walk 与叶子级回退

系统 SHALL 提供单一共享 `json_walk(obj, leaf_fn)`：对 `dict`/`list` 递归、`str` 叶内若 `lstrip("\ufeff").strip()` 后以 `{`/`[` 开头且可 `loads` 为 `dict`/`list` 则对内层同走 `walk→leaf_fn→dumps`，失败回退该叶原串；`depth>5` 时不递归内层但仍执行 `leaf_fn`；`orjson` 存在时用 `orjson` 否则 `json`，`dumps` 统一 `ensure_ascii=False, separators=(',',':')`；`original` 合法而 `output` 非法时回退原串（`_validate_json_roundtrip`）。

#### Scenario: 嵌套 arguments 不破坏转义
- **WHEN** 请求 `tool_calls[].function.arguments` 为含 `p@ss"quote` 的 JSON 字符串且走脱敏
- **THEN** 内层 `dumps` 后的外层 JSON 仍可 `loads`，`"` 已转义，不抛 `JSONDecodeError`

#### Scenario: BOM 前缀不误判非 JSON
- **WHEN** 叶字符串为 `\ufeff{"a":1}` 形态
- **THEN** `lstrip("\ufeff")` 后判为 JSON 并递归 walk，非直接 plain `replace`

#### Scenario: 纯文本叶零成本回退
- **WHEN** 叶字符串为无 `{`/`[` 的纯文本
- **THEN** 不尝试 `loads`，直接 `leaf_fn`，`_validate` 不触发

#### Scenario: 深度炸弹不递归但叶仍脱敏

- **WHEN** JSON 嵌套深度 >5 的叶字符串
- **THEN** 不再对内层 `loads→walk→dumps`，仅对该叶执行 `leaf_fn`，不回退整包

#### Scenario: 裸嵌套深度炸弹不崩溃

- **WHEN** `dict`/`list` 裸嵌套（`{"a":{"a":...}}`）深度 >5 或极端（3000 层）
- **THEN** 深度守卫对裸嵌套同样生效：`depth>5` 的内层不再递归 `loads→walk`；极端深度不抛 `RecursionError`（walk 入口兜底返回原对象），不崩溃请求

#### Scenario: original 合法而 output 非法回退原串

- **WHEN** 某叶 `leaf_fn` 替换后 `_validate_json_roundtrip` 判定 `output` 非法 JSON
- **THEN** 仅该叶回退原串，不影响其他叶，且不抛异常

#### Scenario: 叶异常仅该叶回退

- **WHEN** 某叶 `leaf_fn` 抛异常
- **THEN** 仅该叶回退原串，其余叶正常替换
#### Scenario: 流式 data 行统一走共享 walk

- **WHEN** 流式 `data: {"choices":[{"delta":{"content":"hi"}}]}` 行到达且 `active_t2p` 或 `pii_active` 生效
- **THEN** 由 `_pii_process_sse_line` 剥离 `data:` 前缀后对 `payload` 走共享 `json_walk`，`[DONE]`/空/非 JSON 早退

### Requirement: 单口径序列化不新增形态

系统 SHALL 在共享 walk 中保持 `ensure_ascii=False` 单口径，不新增 `indent` 或 `sort_keys`；`separators=(',',':')` 压缩空白属显式声明的语义等价，非字节级保持。

#### Scenario: 中文不保持 \uXXXX

- **WHEN** JSON 值含中文
- **THEN** `dumps` 后中文为明文而非 `\uXXXX`，`loads` 语义一致即合法

#### Scenario: 空白压缩可接受

- **WHEN** 原始 JSON 含缩进或多空格
- **THEN** 输出为压缩形态，`loads` 结果等价即合法
