## 1. PII 请求级 token 机制

- [x] 1.1 扩展 `_token.py`：新增请求级映射容器（`RequestScopedTokens`），支持独立于全局 `pwd_to_token` 的 `pii_p2t`/`pii_t2p`、`__PII_<seq>_<rand8>__` token 前缀生成（**含随机段，见 design D2 token 不可预测性**；rand8 = 8 位 hex 随机段，**必须用 CSPRNG 生成（`secrets.token_hex(4)`，禁止 `random`/时间派生）**，防占位符枚举；**格式不符 token 审计事件聚合限流**：同请求同类事件只记一次 + 计数，防批量注入刷审计日志）、同值去重复用 token、`_restore` 时请求级优先且**仅还原请求期注册 token**（响应期注册 token 形态匹配也原样保留）——**PII 未命中不查全局、原样保留；全局兜底仅凭据路径**（**PII 路径禁止触达全局凭据映射**）
  - 验收：请求级映射创建/还原/清理测试通过；同值复用同一 token；`__PII_` token 不进入全局 `pwd_to_token`
- [x] 1.2 单元测试：请求级映射生命周期（创建/还原/清理）、与全局凭据映射互不串扰、token 前缀不冲突、越界/格式不符 token 原样保留并记审计事件
  - 验收：上述四类用例全部覆盖且断言通过；PII 还原路径不触达全局凭据映射（代码级隔离断言）
- [x] 1.3 **PII 正则等价物**：为 `__PII_` 前缀新增独立的分片残缺清理正则（仿照 `_PARTIAL_TOKEN_RE` 但**独立常量、不 import 凭据正则**），并同步扩展 `_FULL_TOKEN_RE`/`TOKEN_STR_RE` 等价物与 `_split_safe_hold` hold 判定
  - 验收：`__PII_0000` 残缺前缀在流式分片边界被清理不泄漏；模型幻觉的完整 `__PII_*__` token 被剥离；凭据正则不受影响

## 2. PII 检测器（`_pii.py`）

- [x] 2.1 实现 `PiiDetector` 接口与 recognizer 注册表（正则 + 校验位/上下文强化）：大陆身份证（含校验位验证）、手机号（前缀段验证）、邮箱、银行卡（Luhn 校验）、IPv4、常见 API key 格式（sk-、ghp_ 等）；**内置强模式合并为单条联合正则（命名捕获组区分类型）**；**`\b` 全部改用 lookaround 边界**（中文环境 `\b` 失效，`联系13812345678处理` 必须命中）；**命名组约束**：合并前重名校验（与内置重名拒绝加载）、禁止嵌套命名组、单层命名组无分支重置依赖；**lastgroup 分类单测**（每种类型至少一例命中断言分类正确）
  - 验收：每种 recognizer 命中/漏报/边界用例覆盖（含误报如纯数字订单号）；低置信模式不脱敏；**`\b` 与 lookaround 对照用例**（中文紧贴/行首/行尾/中英混排/数字粘连）全绿；重名自定义正则被拒绝；lastgroup 分类单测全绿
- [x] 2.2 **IPv4/IPv6 保留地址豁免**：命中后按保留段（RFC1918/环回/链路本地/组播/文档前缀/ULA 等）判定，保留段原样保留不注册 token；**前缀字符串匹配**（`startswith`），不构造 ipaddress 对象；**前缀清单完整覆盖整个保留段**（172.16.–172.31. 全 16 段、224.–239.、240.–255.、100.64.–100.127.、fe8–feb IPv6 段），**前缀必须含尾点/冒号**（裸 `"10"` 误豁免 `100.x`、裸 `"2001:db8"` 误豁免 `2001:db80::`）；**IPv6 先 lower 再判定**；IPv6 正则粗筛 + 精确解析两级判定
  - 验收：`192.168.1.1`/`10.0.0.8`/`127.0.0.1`/`169.254.1.1`/`::1`/`fd00::1`/`fe80::a1`/`2001:db8::1` 原样保留；**段内边界值**（`172.31.255.255`、`225.0.0.1`、`241.0.0.1`、`100.127.255.255`、`febf::1`）原样保留；**非保留段**（`100.128.0.1`、`2001:db80::1`、大写 `FD00::1` 按保留处理）被替换；公网 IP（`8.8.8.8`、`2001:4860:4860::8888`）被替换；前缀匹配性能锚点（1MB body 9021 候选过滤 <5ms）
- [x] 2.3 **自定义正则（可配置）**：`PII_REDACTION_TYPES` 支持用户正则（工号、项目代号、内部域名等），命名捕获组并入联合正则；**ReDoS 防护**：`asyncio.to_thread` + `asyncio.wait_for`（100ms 预算）守卫 + 启动编译自检样本（**含对抗性长输入**，如 `a`×64 的 `(a+)+$`），超时/异常拒绝加载并告警；**独立线程池**（max_workers 1~2，与日志写 `run_in_executor` 不同池，僵尸线程隔离）；**超时处置**：跳过该规则 + 记审计告警（fail-open 但必报），连续超时（3 次）临时停用该规则；**输入上限**（单次扫描 ≤1MB 或按字段分块）
  - 验收：自定义正则命中/替换正确；`^(a+)+$` 恶意模式 100ms 内被拦截不卡死且告警记录；`\b` 正则被拒绝或自动改写（中文紧贴用例命中）；超时规则被跳过不阻断其余规则
- [x] 2.4 **字典型 recognizer（可配置）**：敏感名称名单（人名/工号/内部主机名/内部域名），精确匹配替换；**独立扫描不并入联合正则**；按长度降序 + `re.escape` + 编译缓存（**`dict_ver` 版本计数，配置加载/重载自增，热路径比对版本号决定重编译**）；**CJK 边界策略**：命中位置两侧非 CJK 字母数字（`(?<![\w\u4e00-\u9fff])name(?![...])`）才算命中，主机名/域名类名单可按类型放宽
  - 验收：名单名称被替换；同形词不误伤（`张三` 不误伤 `张三丰`、`张伟` 不命中 `张伟强`）；5000 名单单 chunk 扫描 <1ms（独立扫描锚点）；不并入联合正则（性能断言）；配置重载后旧缓存失效重编译
- [x] 2.5 单元测试：每种 recognizer 的命中/漏报/边界（误报如纯数字订单号、连续数字串）、还原正确性、base64 data URL 不误报、重复 PII 去重复用 token、**保留地址豁免**、**URL 上下文防误报**（`?id=` 长数字不判银行卡）
  - 验收：以对应测试通过为验收（pii_test.py 全绿）

## 3. PII 脱敏接入 `_llm.py`

- [x] 3.1 请求侧：`_llm.py` handler 中在现有 `_redact` 前插入 PII 检测（`PII_REDACTION_ENABLED` 时），统一输出脱敏 body；**重叠值策略**：同一明文既注册凭据又命中 PII 模式时，**凭据注册表命中的值优先走凭据路径**（PII 检测跳过已在凭据注册表中的明文，避免 PII 先掩码导致凭据 `_redact` 找不到明文、凭据侧审计/告警漏记），测试断言重叠值不产生双 token；`used_tokens` 收集同时覆盖凭据与 PII token，**且仅收集本次请求实际注册产生的 token**（凭据注册表命中 + PII 请求级映射，不收集任意 `TOKEN_RE` 形态匹配——关闭「prompt 字面量 `__VG_CRED_*__` → 回显 → 全局兜底还原」放大路径，见 design D2）；**门控判定同步扩展**（`_llm.py` 579 字节快路径 `__VG_CRED_`、658 JSON-aware、1300 fast path 三处须加 `__PII_`，纯 PII 请求不得走不还原的 fast path）
  - 验收：纯 PII 请求（无凭据）流式响应正确还原；三处门控含 PII 判定
- [x] 3.2 响应侧：按「**还原 → 响应侧检测 → 转发**」顺序执行（见 design D2）：`_restore` 还原请求级占位符 → 检测并**仅跳过本次还原路径产出的明文**（还原产物标记位判定，非值级跳过——模型独立输出与请求期同值 PII 仍掩码）→ 新检测值注册实时请求级映射；未脱敏 PII 回显替换为占位符；非流式与流式（SSE 各协议路径）都要覆盖；**增量扫描**（每 chunk 只扫新增 + 尾部持有，禁止全量重扫累积文本）
  - 验收：模型回显占位符场景客户端收到脱敏文本而非明文；还原后明文不被二次掩码；模型独立输出同值明文被掩码（非还原产物不放行）；200 chunk 流增量扫描耗时 < 全量重扫 1/10（性能断言）
- [x] 3.3 集成测试：请求含 PII + 凭据混合、流式响应还原、响应回显 PII 拦截、**明文 PII 跨分片切断的累积还原**（含断连残留不泄漏，见 design D2 明文分片累积）、**标点边界缓冲**（语义边界 flush + 字节窗口兜底）、**候选值感知切分**（IP/邮箱跨标点切断不漏检：`8.`/`8.8.`/`8.8.8.` 三种部分 IP 尾部形态 + `8.8.`+`8.8` 拼回完整 IP 后命中；IPv6 部分形态 `fe80::` 同理）、**超长明文 API key 切断**（`sk-ant-` 前缀 key 跨 3 chunk 切断不泄漏明文片段，见 design D2 明文长值切断边界声明）、**残缺 token 处理**（完整保留/残缺前缀剥离/残缺后缀暂存/流末丢弃，含 `__PII_0001_ab,` 尾部标点形态）——**测试配置引用见 8.1 环境变量清单**（`PII_REDACTION_ENABLED`/`PII_RESPONSE_SIDE`/`PII_HOLD_MAX`，与 8.1 保持一致）
  - 验收：混合请求两套 token 各还原各的互不串扰；断连残留按不完整明文处理不泄漏；标点边界下 safe 完整 flush、hold <64 字符；候选值切断（1/2/3 段尾点形态）不漏检；超长 key 跨 3 chunk 不泄漏明文片段；残缺 token（含尾部标点）不泄漏结构

## 4. 输出审计钩子（tool call 检测）

- [x] 4.1 新增 OpenAI chat/completions `delta.tool_calls` 分片累积（按 index 分组 name + arguments），**全程缓冲至审计 verdict 前不 flush**，在 `finish_reason == 'tool_calls'` 或流末触发审计点；注意跨分片伪还原与 null 值防御
  - 验收：三种协议 tool call 累积测试通过、PII/凭据残缺不泄漏、未出 verdict 无 tool call 事件流出
- [x] 4.2 审计触发点对齐已有完成事件：Anthropic `block_stop`、Responses `item_done`（读取 arg_buf 完整参数）；**审计读掩码前原始 arg_buf，PII 掩码在 flush 阶段**（见 design D3 审计对抗性）
  - 验收：审计读取的 args 为掩码前原文（含 IP 等可触发网络外传规则的形态）；掩码后文本不参与规则匹配
- [x] 4.3 集成测试：三种协议流式 tool call 分片累积 + 审计触发（真实 aiohttp，参考 `sse_stream_loop_test.py` 模式）
  - 验收：三协议 tool call 分片累积/审计触发用例全绿；跨分片伪还原与 null 值防御用例覆盖
- [x] 4.4 非流式整包响应审计：三协议提取 tool calls（OpenAI `choices[0].message.tool_calls` / Anthropic `content[].tool_use` / Responses `output[]`）+ 审计（提取与审计调用已完成；阻断注入随 Batch 5 `audit_tool_call` verdict 接入）+ 阻断注入集成测试（不因缺 SSE 完成事件跳过）
  - 验收：三协议非流式危险 tool call 均被拦截；安全 tool call 原样转发

## 5. 策略引擎与阻断模式（`_audit.py`）

- [x] 5.1 实现 `AuditMixin`：`audit_tool_call(name, args_json) -> AuditVerdict`（allow/deny 名单 + 危险模式规则：危险 shell 命令、敏感路径写入、网络外传）；**参数规范化**：合并重复空白、解析 `\uXXXX`/`\xXX` 转义、拆 `;`/`&&`/`|` 命令链、单层变量展开、`/bin/rm`/`find -delete` 别名形态、**`..` 路径段规范化**（见 design D3 审计对抗性）；**外部域名判定**：配置化内网域名后缀列表 + 公网后缀启发式，不解析 DNS（见 design D3）
  - 验收：规范化后规则命中（双空格、转义、变量拼接、multiline）与未规范化时失配的对照用例全绿
- [x] 5.2 内置默认策略 + `AUDIT_POLICY_FILE` 可选 YAML/JSON 加载（schema 精简）；**补 `examples/audit-policy.yaml` 示例策略文件**（含「检测器」维度示例与防护边界注释）
  - 验收：策略文件加载/缺省默认策略/非法策略文件报错三路径覆盖；示例文件可被 loader 解析
- [x] 5.3 阻断处置：危险 tool call 替换为「无 tool_calls 的 assistant 拒绝消息」（`finish_reason: stop`），后续流正常；非流式整包响应同样支持；**Anthropic/Responses 在首个可疑 delta 进入缓冲时即暂停 flush（`audit_precheck` 已实现，接线到 flush 路径随 Batch 6 预检暂停完成），阻断后发出协议终止事件（`block_stop`/`item_done`）避免 tool_use 块 dangling**（见 design D4 状态机）
  - 验收：注入消息协议结构合法（无 tool_calls、finish_reason: stop）；A/R 阻断后收到终止事件无 dangling tool_use 块；后续 content 照常转发
- [x] 5.4 单元测试：策略匹配（allow/deny/危险模式/边界/**规范化命中：双空格、`\u0072m` 转义、变量拼接、multiline**）、阻断注入的协议结构合法性（含终止事件）
  - 验收：以对应测试通过为验收（audit_test.py 全绿）

## 6. 审批模式

- [x] 6.1 复用 `_matrix.py` `_ask`/pending/超时机制：危险 tool call 挂起 → Matrix ✅/❎ 审批消息（含工具名与**先脱敏后截断的参数摘要**、`[REDACTED:<type>]` 密钥形态、超时提示）→ 批准后补发原格式事件 / 拒绝后注入拒绝消息 / 超时默认拒绝；**审批白名单校验**（发送者 ∈ 白名单 + reaction event id 精确匹配 + 幂等，见 design D4）；**审批消息发送失败（`_ask` 返回 None）立即按 rejected 处置 + 清理 pending**（见 design Risks，参照 `_credential.py:413-419` 先例）
  - 验收：非白名单 reaction 被忽略；同请求重复 reaction 只生效首次；摘要不含明文密钥/PII；`_ask` 返回 None 时 pending 立即清理且客户端收到拒绝结果
- [x] 6.2 流式挂起细节：挂起期间**继续读上游并缓冲**（上限 `AUDIT_HOLD_MAX_BYTES`，超限按 rejected fail-closed），审批完成统一放行/替换，不破坏 SSE 流结构；挂起期间按事件序缓冲后续 content；**缓冲中出现新的危险 tool call 一律 fail-closed 拒绝，不得未经审批放行**（见 design Risks）
  - 验收：缓冲超限按 rejected 注入拒绝且 pending 清理；挂起期间新危险调用被拒绝；缓冲 content 按事件序放行/替换
- [x] 6.3 集成测试：审批通过/拒绝/超时三种路径 + 流式完整性 + 白名单/幂等 + **发送失败**（`_ask`→None）+ **预检误判恢复**（首个可疑 delta 暂停 flush → 完整审计通过 → 恢复续传剩余 delta，无重复 flush）+ **预检同步暂停**（delta 到达同步置 pause，前缀匹配（`rm`→`rm -rf`）触发，await 判定不先于暂停）+ **正常结束不完整 tool call**（`finish_reason`/`[DONE]` 前正常结束但无终止事件 → fail-closed 丢弃 + 注入终止事件，不 flush 残缺参数）+ **拒绝后缓冲 content 丢弃**（rejected/expired/upstream_down 终态缓冲 content 不转发）
  - 验收：七条路径（含发送失败、预检恢复、预检同步暂停、正常结束不完整、拒绝缓冲丢弃）全绿；流式完整性断言（无重复拼接/无 dangling tool_use）
- [x] 6.4 审批取消/收尾：流结束/异常/客户端断连 → 取消审批（`event.set()` + `_cleanup_request`）+ handler `try/finally` 清理请求级映射 + 周期清扫兜底（**后台定时任务 60s 扫描孤儿 pending 置 rejected 并清理**——`_matrix.py` CMD_LOCK 为 lock 触发的一次性清空，语义不同，仅作启发参考，见 design D4）
  - 验收：客户端断连后 pending_requests 无僵尸条目；僵尸审批消息再点 ✅ 无效；周期清扫能回收模拟泄漏的孤儿条目
- [x] 6.5 **异常路径测试组**（注入失败场景，复用 `sse_stream_loop_test.py` 模式）：上游断连（ServerDisconnectedError）、SSE 流中断、坏 JSON、客户端提前断连（SSE_CLIENT_GONE）、超时、空流、**缓冲超限（hold overflow）**、**超时与上游断连同时触发（竞态，验证处置幂等——后到者发现 pending 已删则跳过）**
  - 验收：每条路径下 PII 映射清理、审批收尾、未审计 tool call fail-closed（不静默放行）；竞态路径无双注入/无重复终止事件

## 7. 审计日志

- [x] 7.1 追加写 `DATA_DIR/audit.log`（JSON Lines）：时间、检测类型、规则匹配、参数摘要（**先脱敏后截断**）、处置结果；**日志行 `json.dumps` 强制转义 + 剥离控制字符 `\\x00-\\x1f`；文件权限 0600；大小轮转（10MB × 5 份）**；**摘要脱敏使用实时请求级映射（含响应期新注册 PII），不得从掩码前快照取摘要**（见 design Risks）
  - 验收：日志行合法单 JSON；控制字符被剥离；0600 权限；轮转触发；响应期新 PII 明文不落盘
- [x] 7.2 单元测试：日志格式、敏感值不落盘、追加写与并发安全、**控制字符不产生伪造条目**、**写失败 fail-closed（阻断 + 告警）**、轮转触发
  - 验收：以对应测试通过为验收（audit_test.py 日志组全绿）

## 8. 配置与入口集成

- [x] 8.1 `proxy.py`：解析新环境变量（`PII_REDACTION_ENABLED`、`PII_RESPONSE_SIDE`、`PII_HOLD_MAX`（尾部持有上限，默认 64，取值 ≥1 正整数）、`AUDIT_MODE`、`AUDIT_TIMEOUT`、`AUDIT_HOLD_MAX_BYTES`、`AUDIT_POLICY_FILE`、`APPROVAL_WHITELIST`），组合 `PiiMixin` + `AuditMixin`；`AUDIT_TIMEOUT` 取值校验 **≥1s 且拒绝 110-130s 区间**（0/负值/竞态区间启动报错）；`AUDIT_MODE=approve` 且无 `APPROVAL_WHITELIST` 启动报错
  - 验收：非法 `AUDIT_TIMEOUT`（0/负/110-130）启动报错；`AUDIT_MODE=approve` 且无白名单配置时启动报错；`AUDIT_MODE=approve` 且配置白名单时正常启动；`PII_HOLD_MAX` 默认 64、非法值（0/负/非整数）启动报错
- [x] 8.2 轻量入口（llm-proxy-only / credential-proxy-only）按需引入 Mixin；**approve 模式仅完整 proxy（含 MatrixMixin）支持，轻量入口配置 approve 时启动报错或降级 block**；Docker entrypoint/compose 增加环境变量透传与文档；**README 配置表 + 默认关闭安全警示**（PII/审计默认关闭 = 未启用前明文与危险调用不受保护，见 design D5 安全警示）
  - 验收：轻量入口配置 approve 时明确报错或降级（不静默忽略）；文档含新环境变量配置表 + 默认关闭安全警示
- [x] 8.3 默认关闭回归验证：不配置新变量时全量测试通过、行为与现状一致
  - 验收：全量测试全绿；对照基线请求/响应字节级一致（无默认路径行为变化）
- [x] 8.4 **大 body 性能验证**：多 MB body（多模态 base64）逐 recognizer 扫描耗时上限（**分层锚点，见 design D1 性能策略**：扫描 ~90ms/1MB 联合正则、~0.8ms 纯文本粗筛、~124µs/1KB chunk、<100KB 请求扫描 ~9ms、字典启用时另计 ~5ms/100KB、每事件还原/分割/写出另计）；**粗筛 25x 仅在纯非 ASCII 无数字文本成立**（混合文本不适用）；**流式增量扫描锚点**：1MB 增量 ~90ms（**口径说明：1MB 增量锚点 = 联合正则 1MB 全量扫描 90ms**——增量扫描仅省去已处理部分，锚点值本身仍是全量扫描口径；2.3s 全量重扫为 200 chunk 场景的对照值，90x 为该场景比值，非 1MB 全量对照）
  - 验收：多 MB body 扫描耗时在声明锚点内（记录实测值，超限则修订 design 声明）；性能断言覆盖联合正则/粗筛/字典独立/增量扫描

## 9. 验证与发布

- [ ] 9.1 ruff check + ruff format --check + 全量 pytest 全绿（146 + 新增）
  - 验收：ruff 零告警；全量测试全绿
- [ ] 9.2 真实流量验证（llm-proxy-only 本地）：PII 请求/响应脱敏、危险 tool call 阻断、审批流程；验证 design.md Open Questions（`finish_reason` 可靠性、拒绝消息兼容性）；**补充验证项**：拒绝消息 + 后续 content 共存、纯 PII 请求流式还原、无 `finish_reason` 的流
  - 验收：每项验证输出实测记录（真实流量/日志截图）；Open Questions 结论回填 design.md
- [ ] 9.3 版本 bump（v0.9.x）+ README changelog + Docker 镜像 tag + 打 tag 触发 CI 全量构建（Docker + Go 二进制）；README 补新环境变量配置表与防护边界声明
  - 验收：v0.9.x tag 存在且 CI 全绿；README 含配置表与防护边界声明
