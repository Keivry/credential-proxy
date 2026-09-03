## Purpose

保障流式工具调用参数的完整性与审计正确性，阻断后不泄漏残缺可执行参数，不误杀正常文本。

## ADDED Requirements

### Requirement: 工具参数攒整段单次处理

系统 SHALL 对工具参数分片做累积，仅在完成事件到达时单次还原与审计后转发，中间分片不得提前输出。

#### Scenario: 参数分片不提前输出

- **WHEN** 上游分片发送 `function_call_arguments.delta` / `partial_json` / `tool_calls.arguments` 增量
- **THEN** 系统累积不输出，直到 `content_block_stop` / `item_done` / `finish_reason=tool_calls` 到达才一次性还原转发

#### Scenario: 三协议语义一致

- **WHEN** 同一工具参数分别经 Anthropic / Responses / OpenAI 三协议传输
- **THEN** 三者均走累积后单次处理，不得一协议逐片输出而另一协议攒整段

### Requirement: 阻断后残缺参数不流出

系统 SHALL 在审计 deny 时丢弃未完成工具参数并注入拒绝事件，不得透传残缺 `arguments`。

#### Scenario: deny 丢弃残缺参数

- **WHEN** 工具调用审计 verdict 为 deny
- **THEN** 已累积参数被丢弃，下游收到拒绝消息而非残缺 tool_call，不得出现无 `finish_reason` 的半截参数

#### Scenario: 不误杀正常文本

- **WHEN** 普通 content 文本中出现 `tool_calls` 子串
- **THEN** 系统不得将其误判为工具调用而抑制转发，必须按文本路径正常还原

#### Scenario: 畸形分片跳过不崩溃

- **WHEN** 工具调用分片的 `index` 非 int 或 `function` 为 None
- **THEN** 系统跳过该分片不做累积，不得抛异常中断流

#### Scenario: 未识别形态整行透传不抑制

- **WHEN** 上游事件形态不在三协议已知集合内（非 `partial_json` / `function_call_arguments` / `tool_calls.arguments` / 文本 delta）
- **THEN** 系统整行透传不得抑制，下游 `json.loads` 成功
