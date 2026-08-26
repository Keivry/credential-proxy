## Purpose

保证 PII/凭据占位符映射的稳态与还原健壮性，同一明文在映射生命周期内始终对应同一 token，空洞下标不复用歧义，残缺前缀不泄漏，必要时可容忍大小写漂移。

## ADDED Requirements

### Requirement: 同值同 token 与空洞跳过下标分配

系统 SHALL 在 `register(value)` 时先查请求级与全局 `value→placeholder` 既有映射，命中复用；未命中则收集 `vault_entities` 与本批次 `batch_tracker` 已用下标 `set`，取 `next_index=1 while in set: next+=1`，并用 `secrets.token_hex(4)` 生成 `rand8` 组成 `__PII_<seq>_<rand8>__`（凭据侧 `__VG_CRED_<seq>_<rand8>__` 同理）；`_restore` 仅还原映射中存在的 token，越界/格式不符原样保留并记审计事件。

#### Scenario: 同值复用同一 token
- **WHEN** 同一请求内两次 `register("13812345678")`
- **THEN** 两次返回同一 `__PII_1_<rand8>__`，Vault 不新增条目

#### Scenario: 空洞下标不复用歧义
- **WHEN** Vault 已有 `seq 1,3`（2 已删除）且注册新值
- **THEN** 新值分配 `seq 2` 而非 `4`，且不与存量值冲突

#### Scenario: 随机段不可枚举
- **WHEN** 客户端批量探测 `__PII_<seq>_<guess>__`
- **THEN** 猜测命中概率可忽略，`_restore` 仅还原精确存在 token，越界原样保留并审计

#### Scenario: 响应期新 token 不被还原
- **WHEN** 响应侧新检测 PII 注册为响应期 token
- **THEN** `_restore` 原样保留该形态，不还原为明文

### Requirement: 统一残缺清理与倒序替换

系统 SHALL 提供 `_strip_partials(text)` 合并凭据与 PII 两套残缺形态（完整 `__PII_<seq>_<rand8>__` 保留、残缺前缀 `__PII`/`__VG_CRED`/`__PII_<digits>`/`__PII_<seq>_<hex>` 剥离），`safe` 侧倒序语义（`TextReplaceBuilder` 逆序替换）避免重叠错位，`hold` 侧阈值 `<64` 持有。

#### Scenario: 残缺前缀不泄漏
- **WHEN** 流式 `safe` 含 `__PII_1_ab` 残缺前缀
- **THEN** `_strip_partials` 将其剥离，不转发给客户端

#### Scenario: 完整 token 保留
- **WHEN** `safe` 含完整 `__PII_1_ab12cd34__`
- **THEN** `_strip_partials` 原样保留，由 `_restore` 还原

#### Scenario: 倒序避免重叠错位
- **WHEN** 文本含两处重叠候选替换区间
- **THEN** 逆序替换后偏移正确，不错位

### Requirement: 可选大小写不敏感还原（默认关闭）

系统 SHALL 支持 `PII_FUZZY_RESTORE=1` 时对响应中的占位符做大小写不敏感还原（`re.IGNORECASE`），默认 `0` 时仅精确匹配，模糊命中时记审计。

#### Scenario: 默认精确还原
- **WHEN** `PII_FUZZY_RESTORE=0` 且响应含 `__pii_1_ab12cd34__` 小写形态
- **THEN** 不还原，原样保留

#### Scenario: 开启后大小写还原
- **WHEN** `PII_FUZZY_RESTORE=1` 且响应含 `__pii_1_ab12cd34__`
- **THEN** 大小写不敏感还原为原文并记审计
