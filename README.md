# credential-proxy

三因子认证凭据代理服务 — LLM 安全场景下的凭据存取管控方案。

```
Hermes Agent / 脚本  ── get 二进制 ──▶  Credential Proxy (Docker)
                                          ├─ 三因子认证（binary + secret + caller）
                                          ├─ KeePassXC 数据库
                                          ├─ TPM 2.0 硬件解封
                                          ├─ Matrix ✅/❎ 审批
                                          └─ LLM 脱敏反向代理
```

## 核心能力

- **凭据 API** — HTTP 接口查询 KeePass 条目，支持字段级粒度控制
- **三因子认证**（v0.8.0+）— `get_binary_hash` + `GET_BINARY_SECRET` + `caller_hash`，仅 `get` 二进制可通信
- **Caller 自动放行** — 脚本文件 SHA256 哈希绑定注册，哈希匹配自动放行，被篡改需重新审批
- **Matrix 审批** — 每笔凭据需用户 ✅/❎ 反应确认；支持注册审批（🔓 自动放行 / ✅ 普通审批 / ❎ 拒绝）
- **TPM 2.0 密封** — KeePass 主密码由硬件密封，磁盘被盗无法解密
- **LLM 脱敏代理** — 反向代理 LLM API 请求，凭据自动替换为 `__VG_CRED_NNNNNN__` 占位符，流式 SSE 实时还原
- **双向保护** — `get credential` 默认返回脱敏值（tokenized），脚本需显式 `--raw` 获取明文

## 架构

### Python 服务端（7 文件 Mixin 模式）

```
proxy.py            主入口 + CredentialProxy 主类
_credential.py      凭据 HTTP API（/credential /health）+ 三因子认证
_token.py           凭据脱敏/还原 — __VG_CRED_NNNNNN__ token
_tpm.py             TPM 硬件解封 KeePass 主密码
_matrix.py          Matrix Bot — 审批、解锁、注册审批
_registry.py        Caller 注册表 + 自动放行认证
_llm.py             LLM 反向代理 — SSE 流式 + JSON-aware token 还原
_sse.py             SSE 共享常量
```

轻量入口（无 Matrix/TPM/KeePass，仅 aiohttp）：

- `credential-proxy-only.py` — 凭据 API + LLM 代理（自动批准）
- `llm-proxy-only.py` — 纯 LLM 脱敏代理

### Go 客户端二进制

```
get/                独立 Go CLI 项目
├── main.go         入口 — credential / register / revoke / list / status
├── cmd/
│   ├── credential.go   获取凭据（支持 --raw）
│   ├── register.go     注册脚本 caller
│   └── revoke.go       吊销注册
└── internal/
    ├── auth.go         三因子认证构建
    ├── caller.go       /proc/PPID 调用者识别 + SHA256 哈希
    └── proxy.go        HTTP 客户端
```

### 三因子认证流程

```
get 二进制                         Credential Proxy
    │                                   │
    ├─ get_binary_hash=sha256(get)      │  因子 1：二进制完整性
    ├─ get_binary_secret=<env>          │  因子 2：部署密钥
    ├─ caller_hash=sha256(脚本)         │  因子 3：调用者身份
    │                                   │
    │  ─── POST /credential ─────────▶  │
    │                                   ├─ 三因子校验
    │                                   ├─ Caller 注册匹配？
    │                                   │   ├─ 匹配 → 自动放行 ✅
    │                                   │   └─ 不匹配 → Matrix 审批
    │                                   └─ 返回凭据（脱敏/原始）
    ◀── 响应 ─────────────────────────  │
```

## 快速开始

### 前置条件

- Linux 主机（生产建议 TPM 2.0 芯片）
- KeePassXC 数据库（.kdbx）+ 密钥文件（.key）
- Matrix 账号 + Homeserver

### Docker 部署（推荐）

```bash
# 1. 生成部署密钥
SECRET=$(openssl rand -hex 32)

# 2. 构建镜像
docker build -t credential-proxy .

# 3. 启动（基础版）
docker run -d --name credential-proxy \
  --device /dev/tpm0 --device /dev/tpmrm0 \
  -v /path/to/tpm:/data/tpm:ro \
  -v /path/to/keepass-db:/data/db:ro \
  -p 8877:8877 \
  -e HOMESERVER=https://matrix.example.com \
  -e ROOM_ID='!roomid:example.com' \
  -e MATRIX_ACCESS_TOKEN='syt_...' \
  -e GET_BINARY_HASH='sha256:...' \
  -e GET_BINARY_SECRET="$SECRET" \
  credential-proxy
```

或使用 `docker-compose.yml`（编辑后启动）：

```bash
docker compose up -d
```

### 客户端安装

```bash
# 从 GitHub Release 下载
curl -fsSL -o /usr/local/bin/get \
  https://github.com/Keivry/credential-proxy/releases/latest/download/get-credential-linux-amd64
chmod +x /usr/local/bin/get
```

### 基本用法

```bash
# 获取脱敏值（默认）
get credential 网易 授权码
# → __VG_CRED_000001__

# 获取原始值（仅限脚本，禁止终端直接调用）
get credential 网易 授权码 --raw
# → 实际密码

# 完整条目
get credential 和风天气
# → 标题: 和风天气
# → 用户名: admin
# → 密码: __VG_CRED_000042__
# → URL: https://api.qweather.com

# 注册脚本 caller（需 Matrix 审批）
get register --name "check-mail" \
  --entry "网易" --fields "授权码" \
  --desc "检查 163 邮箱" --auto

# 查看已注册 caller
get list

# 吊销注册
get revoke --name "check-mail"
```

## 安全设计

### 保护层次

| 层级 | 防御对象 | 机制 |
|:-----|:---------|:-----|
| Layer 1 | 外部容器/主机 | `get_binary_hash` + `GET_BINARY_SECRET` + `caller_hash` |
| Layer 2 | 同容器未授权脚本 | Caller 注册 → 仅已注册脚本可自动放行 |
| Layer 3 | 所有未注册请求 | Matrix 审批 |
| Layer 4 | LLM 提供商侧泄露 | Token 脱敏（`__VG_CRED_NNNNNN__`） |
| Layer 5 | 磁盘泄露 | TPM 硬件密封 |

### `--raw` 安全约束（v0.8.4+）

- **终端直接调用 `get credential X --raw`** 被拒绝：`caller_hash` 检测 fallback 到 `get` 自身 hash，等于 `get_binary_hash`
- **脚本内 `subprocess.run` 调用** 放行：`caller_hash` = 脚本文件 SHA256，不等于 `get_binary_hash`
- **服务端同时校验**：`GET_BINARY_HASH` 服务端常量，防止兼容模式下客户端伪造

## Observability 大盘（/_admin，v0.9.25+）

实时指标大盘（请求量/延迟分桶/p95/PII 与凭据命中率/Token 用量/审计分布/时序折线），单文件 `admin.html` 免构建。
- **筛选**：模型下拉（从 tokens 键 + 事件行 model 去重自动填充）+ 上游下拉，联动 KPI/图表/趋势/事件表。
- **时序趋势**：`/_admin/series` 折线（1h 分钟级 60 点 / 24h 24 点 / 7d 168 点 / 30d 30 点），Chart.js 增量更新，SVG 降级。
- **自动刷新**：SSE 事件 2s 推 + `event: metrics` 全量快照 15s 推（KPI/图表/token 四卡/上游分布自动更新；SSE 断开回退 15s 轮询）。
- **人性化数字**：KPI/token/分布以 K/M/B 缩写显示，hover 显示完整精确值；延迟 ms 与百分比不缩写。
- **事件表**：含 model 列 + Cache% 列（输入 token 缓存命中率 `cached_read/input`，hover 显示绝对值）；行 hover 显示脱敏摘要浮窗（Esc/点击外部关闭）。
- **v0.9.35 起统计口径**：仅对话端点（`chat/completions|v1/messages|v1/responses`）计入统计，非对话请求（`v1/models` 等）**彻底不计**（BREAKING，v0.9.34 及之前归 `other` 的口径废弃）；历史 `daily_agg`/`hourly_agg` 中 `other` 桶在滚动排出前仍含旧非对话数据，24h/7d/30d 对比建议以 1h 精确窗口为准。
- **模型筛选范围（Y-8 已知限制）**：`model=` 筛选在 1h 窗口精确（内存 ring 事件带 model 字段）；24h/7d/30d 为近似（DB 无按 model 分桶列，tokens 按 JSON 键存在性近似）。**重启后** 1h 视图仅显示重启以来的请求（ring 内存清空，DB 无 model 维度无法回填）——`is_precise=false` 时 model 视图可能为空属预期，切 24h/7d 看 DB 历史。

### 鉴权与绑定

- **`OBSERVABILITY_ADMIN_TOKEN` 必填**（未设/空值 `SystemExit` 拒绝启动；长度 <32 仅告警；与 `CREDENTIAL_ADMIN_TOKEN`/`MATRIX_ACCESS_TOKEN`/`admin_token` 文件值独立，重复即拒）。
- 凭证优先级：`X-Admin-Token` 头 > `__Host-admin_token` Cookie > `?access_token`（**仅 SSE** 回退）。非 SSE 带 `?access_token` **恒 401**（防历史 URL 复用）；`hmac.compare_digest`（等长 sha256 摘要）时序安全比较。
- Cookie：`HttpOnly` + `Secure`（仅 https；`ENV=dev` 且 `ALLOW_LOOPBACK_NO_TOKEN=1` 时 http 回退不带 `Secure`）；前端 `history.replaceState` 清除 URL 中的 `?access_token`；`admin.html` 密码输入框 `type=password autocomplete=current-password`。
- **端口绑定**：docker-compose 默认 `127.0.0.1:887x:887x`（仅回环）；`0.0.0.0` 直出 `/_admin` 无 TLS 风险极大，外部访问必须经 TLS 反代。
- **限流**：管理接口 `10/min/IP` 超限 `429 + Retry-After`；SSE `max 5 并发/IP` + `60s :ping` 心跳 + `5min` 服务端强制重连。
- **限流 IP 维度说明**：限流按 `request.remote`（直连对端 IP）计数，**不读代理头**（`X-Forwarded-For` 等，防伪造绕过）；空/None remote 归一为 `unknown` 单列桶。经 TLS 反代/负载均衡访问时对端 IP 为反代地址，**所有客户端共享同一限流桶**（合法管理员与攻击者互相挤占）——此场景请直连或让反代透传真实 IP（aiohttp `trust_proxy_headers` 需显式开启并配置可信代理白名单）。
- `OBSERVABILITY_DISABLE=1`：过渡逃生开关，`/_admin/*` 全 404（二期收紧）。

### 指标与存储

- `DATA_DIR/metrics.sqlite`（WAL + `busy_timeout=5000` + `synchronous=NORMAL` + `user_version=1`），文件含 `-wal`/`-shm` 均 `0600`（`os.umask(0o077)` + `wal_checkpoint(TRUNCATE)` 后重 chmod）。
- `daily_agg` 15 基础列 + 5 扩展列（`placeholder_prompt_injected`/`truncated_total`/`json_aware_success`/`json_leaf_fallback`/`json_full_fallback`），30 天滚动；`hourly_agg` 9 列轻量子集，7 天滚动。
- 每 5min **覆盖式 UPSERT**（`ON CONFLICT DO UPDATE SET col=excluded.col`）不翻倍；`QueueFull` 丢最老快照计 `dropped_snapshots`（覆盖式不丢数，跨窗口有补偿）；优雅关闭 `wal_checkpoint(TRUNCATE)`。
- 延迟 12 桶 `LATENCY_BUCKETS=[10,25,50,100,200,400,800,1500,3000,5000,10000,Inf]` ms；p95 由桶逆分位取中位近似（最差约 30.4% @[800,1500) 中位），`is_precise = (now-oldest_ts)>=3600 and len>=100`，低流量/高 TPS 时 `1h` 永为 `≈` 属设计预期。
- `ENOSPC` 磁盘满 → 降级内存-only，`health.sqlite_ok=false` + `sqlite_error` 非空，进程不崩，恢复后续写不回补。
- 摘要脱敏单一路径 `redact→truncate`：`__PII_*__`/`__VG_CRED_*__`/`sk-`/`xox*`/email → `[REDACTED:*]`，截断边界半字符保护（UTF-8）。
- **PII 占位符口径**：`PII_PLACEHOLDER_PROMPT=1` 注入说明不计 `pii_detected_total`/`bytes_in`，`health.placeholder_prompt_enabled` 反映开关。
- **PII 值级掩码采样（v0.9.43+，默认关闭）**：`PII_VALUE_SAMPLE_ENABLED=1` 时 PII 分布 hover 从仅计数扩展为 `计数 + TopN 掩码值 x 次数`（如 `phone: 123 (138****8000 x5, 139****1111 x2)`），掩码在 `_pii.py` 命中时当场生成（明文不出作用域，`masked_sample+hash(16hex)` 进入 `pii_value_samples` Top5 聚合展示前3；`email` 为 `***@***.com` 不透首字符），默认仅内存 `recent_events` 10k 环现场聚合（`range=1h` 精确 `is_precise` 同 `ring_coverage`，`PERSIST=0` 时 `24h/7d` 返回 `{}` 且 `is_precise=false` 不读盘，热切换原子），`PII_VALUE_SAMPLE_PERSIST=1` 时落盘 `pii_value_agg(day,upstream,kind,hash)` 按日覆盖式 UPSERT≤40行/日、7天滚动 `0600`（含 `-wal/-shm`）；hash 为 `HMAC-SHA256(PII_VALUE_SAMPLE_HMAC_KEY,明文)[:16]`（未设退化 `sha256[:16]` 小空间可枚举），`PII_VALUE_SAMPLE_HMAC_KEY` 设后防 phone 7位 1万枚举；前端 Chart.js `afterBody` + SVG `<title>` 多行 `kind: count\nmasked x count` 经 `textContent/title` 防 XSS，`truncated` 时尾加 `…长尾仅计 pii_by_type`，`!is_precise` 灰显`仅1h精确`；`recent_events` ≤8、`PII SVG` 限宽 `1200`、`prefers-reduced-motion` 无动画、`rect:focus` 可达。
- v0.9.25 基线：slow/fast 双路径埋点、`sse_events` 按块计、`truncated_total`、JSON-aware 三态、verdict 值域 `allow/deny`。

### 使用

```bash
# 打开大盘（浏览器访问；http 下仅 dev 回环免 token 模式可用）
open http://127.0.0.1:8878/_admin/

# API（JSON）
curl -H "X-Admin-Token: $OBSERVABILITY_ADMIN_TOKEN" http://127.0.0.1:8878/_admin/health
curl -H "X-Admin-Token: $OBSERVABILITY_ADMIN_TOKEN" "http://127.0.0.1:8878/_admin/metrics?range=24h"
curl -H "X-Admin-Token: $OBSERVABILITY_ADMIN_TOKEN" "http://127.0.0.1:8878/_admin/metrics?range=24h&model=gpt-4o&upstream=8878"
curl -H "X-Admin-Token: $OBSERVABILITY_ADMIN_TOKEN" "http://127.0.0.1:8878/_admin/series?range=24h"
curl -H "X-Admin-Token: $OBSERVABILITY_ADMIN_TOKEN" "http://127.0.0.1:8878/_admin/events?upstream=8878&model=gpt-4o&limit=20"

# SSE 实时流（query token 仅此处回退）
curl -N "http://127.0.0.1:8878/_admin/events/stream?access_token=$OBSERVABILITY_ADMIN_TOKEN"
```

## 配置

### 环境变量

| 变量 | 说明 | 默认值 |
|:-----|:-----|:------|
| `HOMESERVER` | Matrix homeserver URL | — |
| `ROOM_ID` | Matrix 审批房间 ID | — |
| `MATRIX_ACCESS_TOKEN` | Matrix Bot access token | — |
| `GET_BINARY_HASH` | `get` 二进制的 SHA256 | 空（跳过三因子认证） |
| `GET_BINARY_SECRET` | 部署共享密钥 | 空（跳过三因子认证） |
| `CREDENTIAL_PORT` | HTTP API 端口 | `8877` |
| `OBSERVABILITY_ADMIN_TOKEN` | `/_admin` 大盘鉴权 Token。**必填**：未设置/空值 → `SystemExit` 拒绝启动；长度 <32 仅 `logger.warning`（建议 ≥32）；须与 `CREDENTIAL_ADMIN_TOKEN`/`MATRIX_ACCESS_TOKEN`/`DATA_DIR/admin_token` 文件值**独立**（重复 → `SystemExit`） | —（必填） |
| `OBSERVABILITY_DISABLE` | `/_admin` 过渡逃生开关：`1` 时 `/_admin/*` 全 404 且跳过 Token 校验（二期收紧，生产不推荐） | 空（启用） |
| `DATA_DIR` | 数据目录 | `/data` |
| `TPM_DIR` | TPM 密封文件目录 | `$DATA_DIR/tpm` |
| `DB_DIR` | KeePass 数据库目录 | `$DATA_DIR/db` |
| `LLM_<PORT>` | LLM 脱敏代理端口 → 上游 URL | — |
| `PII_REDACTION_ENABLED` | 启用 PII 脱敏（请求/响应检测） | `0`（默认关闭） |
| `PII_RESPONSE_SIDE` | 启用响应侧 PII 检测（还原后新明文掩码） | `1` |
| `PII_HOLD_MAX` | 审计 hold 缓冲尾部持有上限（字符，仅审计挂起用；流式正文行缓冲由 `LINE_BUF_FLUSH=16KB`/`LINE_BUF_MAX_AGE=30s` 控制，见下方流式阈值） | `64` |
| `PII_FUZZY_RESTORE` | 模糊还原（大小写不敏感，仅 `re.IGNORECASE`，默认精确匹配，不含编辑距离） | `0` |
| `PII_DETECTION_HARDENING` | 检测侧硬化总闸（`1` 时启用：保留地址精确前缀 `fc:/fd:`/`10.` 等含尾点/冒号+`lower()`+`ip_network` 兜底 / ReDoS `ThreadPool(2)+timeout 0.1s` / 字典 CJK 边界 `(?<![\\w\\u4e00-\\u9fff])` / `@lru_cache(4)`，默认关闭不改变既有行为） | `0` |
| `PII_PLACEHOLDER_PROMPT` | 脱敏占位符说明注入开关：PII 脱敏实际产生占位符时向上游注入说明提示词（告知 `__PII_*__`/`__VG_CRED_*__` 为脱敏占位符、原样保留勿改写）。`0`/`false`/`no` 关闭（应急开关，不建议长期关闭——关闭后格式敏感占位符可能被上游改写导致还原失配） | `1`（默认开启） |
| `PII_PLACEHOLDER_PROMPT_TEXT` | 自定义占位符说明文案；未设置/空/全空白用内置默认（中文）；上限 4KB（超限截断并告警）；含合法形态占位符（`__PII_<seq>_<hex8>__`/`__VG_CRED_<digits>__`，大小写不敏感）时回退内置默认文案。⚠️ **信任边界：与 `SYSTEM_PROMPT` 同特权（注入直达上游 system 指令），仅运维可写，不可接受非可信用户输入** | 空（内置默认） |
| `PII_VALUE_SAMPLE_ENABLED` | PII 值级掩码采样总开关：`1` 时仪表盘 PII 分布 hover 展示 TopN 掩码值及次数（聚合 Top5 展示前3，掩码形如 `138****8000`/`***@***.com`/`**** **** **** 6789`/`192.168.**.**`/`前4****后4`，长度上限64，hash 为 `HMAC-SHA256(SALT,明文)[:16]` 未设退化 `sha256[:16]` 16hex 仅去重），仅对话端点 `is_chat_tail` 触发，非对话不采样；默认仅计数 | `0`（默认关闭，仅计数） |
| `PII_VALUE_SAMPLE_PERSIST` | PII 值级采样持久化：`1` 时将 `hash+masked_sample+count` 按日聚合持久化到 `metrics.sqlite:pii_value_agg(day,upstream,kind,hash)`（不存明文，仅掩码），7 天滚动 `DELETE WHERE day < ?`，文件含 `-wal/-shm` 均 `0600`；`1` 时隐含 `ENABLED=1`；默认 `0` 仅内存环（重启清空，`1h` 精确，`24h/7d` 需持久化） | `0`（默认内存-only） |
| `PII_VALUE_SAMPLE_HMAC_KEY` | PII 值级采样 hash 的 HMAC 盐（任意随机串，建议 `openssl rand -hex 32`）：设后 `hash=HMAC-SHA256(SALT,明文)[:16]` 防 phone 7位 1万匿名集枚举；未设退化 `sha256(明文)[:16]` 小空间可枚举（文档声明风险） | 空（退化 sha256） |
| `PII_VAULT_GAP_AWARE` | 内置稳态下标（非开关，`next_available_index` 空洞跳过，`__PII_<seq>_<rand8>__` 其中 `rand8=secrets.token_hex(4)`） | —（内置） |
| `PII_CUSTOM_RULES_FILE` | 自定义 PII 规则合并文件（推荐，含 `patterns` + `names` 两段，任一即可），JSON 或极简 YAML；与 `PII_CUSTOM_PATTERNS_FILE` / `PII_DICT_FILE` 可叠加 | 空（不加载） |
| `PII_CUSTOM_PATTERNS_FILE` | 仅自定义正则文件（别名 `PII_CUSTOM_PATTERN_FILE`），JSON/YAML `patterns: [{name, pattern}]`，单文件亦可扁平 `name: pattern` 映射 | 空（不加载） |
| `PII_DICT_FILE` | 仅敏感名称名单文件（别名 `PII_SENSITIVE_DICT_FILE` / `PII_SENSITIVE_NAMES_FILE`），JSON/YAML `names: [{name, type}]`，TXT 回退每行一名 | 空（不加载） |

> **自定义脱敏规则文件加载（pii-custom）：** 三变量均在 `parse_pii_env_config()` 启动校验——**文件不存在 / 解析失败 → 记 `errors` 并 `SystemExit` 拒绝启动（fail-closed，防静默未加载）**；空文件 / 零命中仅 `warning`。YAML 需单引号包裹含反斜杠的正则：`'(?P<emp_no>工号\d{6})'`（JSON 需双重转义 `\\d`）。详见 [自定义脱敏规则](#自定义脱敏规则)。

> **Vault 稳态与保留前缀**：`__PII_<seq>_<rand8>__`（`seq` 为 `next_available_index` 空洞跳过递增，`rand8=secrets.token_hex(4)` CSPRNG）与 `__VG_CRED_NNNNNN__` 为保留前缀，完整形态原样保留不剥离；`resp_p2t`（响应期注册）不还原为明文（仅请求期 `pii_t2p` 可还原），响应侧命中仅提升 LRU 不泄漏；并发 `register` 全程持 `asyncio.Lock` 原子覆盖 `used set` 快照与 `token` 写入，`asyncio.gather` 100 并发无下标冲突。
| `AUDIT_MODE` | 输出审计模式：`off`/`block`/`approve` | `off`（默认关闭） |
| `AUDIT_TIMEOUT` | 审批超时（秒）；**禁止 110-130s**（上游断连竞态窗口） | `90` |
| `AUDIT_HOLD_MAX_BYTES` | 审批挂起缓冲上限（字节） | `1048576` |
| `AUDIT_POLICY_FILE` | 审计策略文件（JSON 或极简 YAML） | 空（内置默认策略） |
| `APPROVAL_WHITELIST` | 审批人 Matrix user id（逗号分隔），`AUDIT_MODE=approve` 必填 | 空 |

> **流式阈值（WHATWG 三层缓冲，硬编码）**：`SSE_MAX_BUF=1MB` / `LINE_BUF_FLUSH=16KB` / `LINE_BUF_MAX_AGE=30s` / `KEEPALIVE_INTERVAL=10s`。`line_buf` 主触发为 `\\n` 行内还原，`16KB/30s` 仅兜底；持有期每 10s 发 SSE 注释 `: keepalive\\n\\n`（`comment` 非 `data:`，不计 `sse_event_count`，真数据 `_tracked_write` 重置计时，30s 持有至少 2 次保活，避免 `hermes inactivity 120s / aiohttp total 600s` 断连）；WHATWG SSE 按 `CRLF/LF/CR` 切行、`:` 注释透传、`retry:` 仅 ASCII 数字、`data:` 冒号后单空格 `U+0020` 剥离。

> **保留地址精确前缀（`PII_DETECTION_HARDENING=1` 时严格）**：`lower()` 后 `startswith` 含尾点/冒号前缀表 `10./127./169.254./192.168./172.16.-172.31./224.-239./240.-255./100.64.-100.127./fc:/fd:/fe80:-febf:/::1/2001:db8:`（`fc`/`fd` 仅冒号形态，裸 `10`/`2001:db8`/`fcfake` 不豁免）。

> **⚠️ 安全警示：PII 脱敏与输出审计默认关闭（fail-open）**
>
> 未显式启用前：**LLM 代理请求/响应中的明文敏感信息（身份证/手机号/密钥等）不脱敏**，危险 tool call（`rm -rf` 等）**不审计不拦截**。生产部署必须显式配置：
>
> ```bash
> # 启用 PII 脱敏
> PII_REDACTION_ENABLED=1
> # 启用输出审计（block = 自动拦截危险调用；approve = Matrix 人工审批）
> AUDIT_MODE=block        # 或 approve（需同时配置 APPROVAL_WHITELIST）
> APPROVAL_WHITELIST='@admin:matrix.example.com'
> ```
>
> 完整 proxy（`proxy.py`）支持 `AUDIT_MODE=approve`（含 Matrix 审批）；轻量入口（`llm-proxy-only.py` / `credential-proxy-only.py`）无 Matrix 审批能力，配置 `approve` 时会**降级为 block 并打印告警**。

## 自定义脱敏规则

内置 6 种（`email`/`phone`/`id_card`/`bank_card`/`ipv4`/`ipv6`/`api_key`）之外的企业敏感信息，通过**自定义正则** + **字典名单**参与同一脱敏管线（`__PII_<seq>_<rand8>__`，与内置同等替换与还原，不干扰 `__VG_CRED_*__` 凭据 token）。

示例文件：`examples/pii-custom.yaml`（推荐，YAML 合并版）+ `examples/pii-custom.json`（JSON 等价），开箱可 `docker compose` 挂载使用。

### 方式一：文件配置（推荐，生产环境）

```bash
# 1. 复制示例并按需编辑
cp examples/pii-custom.yaml /data/pii-custom.yaml
vim /data/pii-custom.yaml   # 增删 patterns / names

# 2. 环境变量指向文件（任选其一）
PII_CUSTOM_RULES_FILE=/data/pii-custom.yaml            # 合并文件（推荐，含 patterns + names）
# 或分离文件
PII_CUSTOM_PATTERNS_FILE=/data/pii-custom-patterns.yaml  # 仅正则
PII_DICT_FILE=/data/pii-custom-dict.yaml                # 仅名单（TXT 每行一名亦可）
# 别名：PII_CUSTOM_PATTERN_FILE / PII_SENSITIVE_DICT_FILE / PII_SENSITIVE_NAMES_FILE / PII_RULES_FILE

# 3. 启动（校验失败直接 SystemExit 拒绝启动，防静默未加载）
PII_REDACTION_ENABLED=1 PII_CUSTOM_RULES_FILE=/data/pii-custom.yaml docker compose up -d
# 启动日志应出现：PII 自定义正则已加载: 3 条 / PII 字典已加载: 6 条

# 4. 验证
curl -H "X-Admin-Token: $OBSERVABILITY_ADMIN_TOKEN" http://127.0.0.1:8878/_admin/metrics | jq .pii_by_type
# 命中后 pii_by_type 出现 emp_no / proj_code / inner_domain 等自定义 kind（sanitize_kind 消毒后 custom_other 归一除外）
```

文件格式：JSON（`{`/`[` 开头）或极简 YAML（与 `examples/audit-policy.yaml` 同款解析：顶层 `key:` + `"- name: ..."` 列表）。YAML 中含 `\d` 的正则必须**单引号**：`'(?P<emp_no>工号\d{6})'`（JSON 需双重转义 `\\d`）。

`examples/pii-custom.yaml` 结构：

```yaml
patterns:
  - name: emp_no
    pattern: '(?P<emp_no>工号\d{6})'
  - name: proj_code
    pattern: '(?P<proj_code>PRJ-[A-Z]{2}-\d{4})'
  - name: inner_domain
    pattern: '(?P<inner_domain>(?<![0-9A-Za-z._-])[A-Za-z0-9-]+\.corp\.local(?![0-9A-Za-z._-]))'
names:
  - name: 张三
    type: name
  - name: db-prod-01
    type: hostname
```

亦支持扁平映射简写（正则）：`{"emp_no": "(?P<emp_no>工号\\d{6})"}`；名单 TXT 回退：每行一名（`#` 注释忽略）。

三变量可叠加（先加载 `PII_CUSTOM_RULES_FILE`，再叠加 `PII_CUSTOM_PATTERNS_FILE` / `PII_DICT_FILE`），**文件不存在 / 解析失败 → `parse_pii_env_config()` 记 `errors` 并 `SystemExit`（fail-closed）**；空文件 / 零命中仅 `warning`。

挂载示例（`docker-compose.yml`）：

```yaml
volumes:
  - ./examples/pii-custom.yaml:/data/pii-custom.yaml:ro
environment:
  - PII_REDACTION_ENABLED=1
  - PII_CUSTOM_RULES_FILE=/data/pii-custom.yaml
```

### 方式二：代码层 API（高级 / 测试 / 动态注入）

```python
from _pii import PiiDetector
from _token import RequestScopedTokens

detector = PiiDetector(request_tokens=RequestScopedTokens())
detector.load_custom_patterns([
    ('emp_no', r'(?P<emp_no>工号\d{6})'),
    ('proj_code', r'(?P<proj_code>PRJ-[A-Z]{2}-\d{4})'),
])
detector.load_dict([
    ('张三', 'name'),
    ('db-prod-01', 'hostname'),
])
hits = await detector.scan('我的工号123456，联系张三，域名 db.corp.local')
# hits == [('emp_no','工号123456'), ('name','张三'), ('inner_domain','db.corp.local')]
out = await detector.detect_and_redact('工号123456')  # → '__PII_0_a1b2c3d4__'
```

启动期动态文件亦可：`detector.load_custom_patterns(_extract_patterns_from_data(_load_pii_raw_file(path)[0]))`（`_pii.py` 已导出 `_load_pii_raw_file` / `_extract_*` 供复用）。

### 约束（硬性，违规拒绝加载并告警）

**命名**：`name` 必须与 `(?P<name>...)` 内同名；与内置 6 种重名（`phone`/`email`/`id_card`/`bank_card`/`ipv4`/`ipv6`/`api_key`）直接拒绝。
**边界**：禁止 `\b`（中文紧贴下零命中，如 `联系__PII_50_149be4fc__处理`）；必须用 lookaround `(?<![\d])...(?!\d)` 或 `(?<![0-9A-Za-z._-])`。
**嵌套**：禁止嵌套命名组 `(?P<outer>(?P<inner>...))`，`lastgroup` 返回最内层导致分类错乱。
**ReDoS**：单规则 100ms `ThreadPool(2)+asyncio.timeout` 守卫，连续 3 次超时临时停用；超长输入按 1MB 分块扫描（不丢尾）。
**区间保护**：任何与 `__PII_*__`/`__VG_CRED_*__` 重叠的匹配整体跳过；值已在凭据 `credential_p2t` 中的跳过（凭据优先，避免双 token 串扰）。
**字典**：独立扫描不并入联合正则（5000 名单 124μs→13.8ms 分支爆炸已规避，实测 190μs/1KB）；`type=name/person` 走 CJK 边界 `(?<![\w\u4e00-\u9fff])`（`张三` 不误伤 `张三丰`），其余 `type` 仅挡 ASCII 粘连（`员工4999在` 命中，`abc员工4999x` 不命中）。

### 验证与排障

```bash
# 启动日志
docker logs credential-proxy | grep -E "PII 自定义|字典已加载|PII 配置错误"
# 指标大盘（pii_by_type 出现自定义 kind，hit/miss 计数）
curl -s -H "X-Admin-Token: $TOKEN" http://127.0.0.1:8878/_admin/metrics?range=1h | jq .pii_by_type
# 常见错误
# PII_CUSTOM_RULES_FILE 文件不存在 → 检查挂载路径与 :ro 权限
# 解析失败 → YAML 是否用单引号包裹正则？JSON 是否双重转义？
# 自定义正则含 \b → 拒绝加载，请改 lookaround
# 与内置重名 → 改名（如 phone_custom）
```

更多约束与性能锚点见 `openspec/changes/llm-privacy-gateway/specs/pii-redaction/spec.md` 与 `design.md D1`。

### Caller 注册

注册后将脚本文件的 SHA256 哈希绑定到 Proxy，实现篡改检测 + 自动放行。

```bash
# 从脚本文件内调用（自动检测 caller hash）
python3 /path/to/script.py
# 脚本内执行: subprocess.run(["get", "register", "--name", "...", ...])

# 或用 --script-path 在终端注册（v0.8.0+）
get register --name "my-script" \
  --entry "条目名" \
  --script-path /path/to/script.py \
  --desc "描述" --auto
```

## 开发

### 本地运行

```bash
# Python 虚拟环境
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 运行测试
PYTHONPATH="." pytest -q

# 启动开发版（自动批准，无需 Matrix）
CREDENTIAL_MASTER_PASSWORD="your-pw" python3 credential-proxy-only.py
```

### Go 客户端构建

```bash
cd get && go build -o get .
```

### 项目结构

```
├── proxy.py             主入口（完整版）
├── _credential.py        凭据 API + 三因子认证
├── _token.py             脱敏 / 还原
├── _tpm.py               TPM 硬件解封
├── _matrix.py            Matrix Bot
├── _registry.py          Caller 注册表
├── _llm.py               LLM 脱敏代理
├── _sse.py               SSE 共享常量
├── credential-proxy-only.py  轻量版（自动批准）
├── llm-proxy-only.py         极简版（仅 LLM 代理）
├── get/                  Go 客户端二进制
│   ├── main.go
│   ├── cmd/
│   └── internal/
├── test_*.py             测试
├── Dockerfile
├── docker-compose.yml
└── .github/workflows/    CI/CD
```

### 构建与发布

GitHub Actions 自动处理：

| 事件 | 动作 |
|:-----|:-----|
| `v*` tag 推送 | 构建 Docker 镜像 + Go 二进制 Release |
| `master` 推送 | 仅构建 Docker 镜像 |
| `master` 的 PR | 验证性构建（不推送） |

手动构建：

```bash
# Docker
docker build -t ghcr.io/keivry/credential-proxy:0.8.5 .

# Go binary
cd get && make build  # → /tmp/get-credential-linux-amd64
```

## 版本历史

- **v0.9.41** — 两项数据正确性修复：① **Responses 协议 usage 漏捕获**——`_capture_usage_ctx` 只找 `obj.response.response.usage`（双层），但 muse-spark（zen/go `/v1/responses`）实际是单层 `obj.response.usage` → 753 请求 usage 全漏；修复：优先单层 + fallback 双层；② **IPv6 时间戳误判**——ipv6 正则不要求 `::`，把 `HH:MM:SS` 时间戳误判为 IPv6（8878 端口 30 请求 4628 次误报）；修复：无 `::` 时必须完整 8 段，含 `::` 才允许压缩（RFC 4291），误判 72755 → 0；新增 20 测试用例（ipv6 时间戳 + usage 单层/双层）
- **v0.9.40** — 复审修复（v0.9.39 后续）：① **跨线程裸读竞态**——SSE 15s 快照经 `to_thread` 在 worker 线程跑查询，与主线程 `incr_event` 写 `recent_events`/`_daily` 跨线程并发，`ring_delta`/`_sum_counter`/`_query_1h`/`_query_memory_fallback`/`_series_1h` 五处裸迭代加锁快照（修复 `RuntimeError: deque mutated during iteration`）；② **Y-10b flush 标记原子化**——`_last_flush_ts` 标记与 `_snapshot` 快照同锁原子（先标后拍在锁外有 mark→snapshot 窗口双计，先拍后标漏计），`flush()` 异步入队不 mark debounce 防 DB 空；③ **fail-closed**——`_redact_extra_pii` 强化层异常返回 `[REDACTED:unverified]` 而非明文（防 `_pii` 导入失败时 id_card/bank_card/ipv4/ipv6 明文落盘）；④ **URL 参数防误报**——`_URL_QUERY_PARAM_RE` 原对单值恒 False 死码，改对 match 上下文判定（`?id=622588...` 订单号不再误判银行卡）；⑤ `_overlaps` superset 包裹漏判修复；⑥ 补 ipv6 公网/保留测试、URL 参数订单号测试、增强占位符保护测试（共 3 新用例）
- **v0.9.39** — 四维审查修复 20 项（v0.9.38 后续）：① **F-1 明文 PII 落盘**——`_metrics.py` 强化层 `_redact_extra_pii` 兜底 id_card（GB 校验位）/bank_card（Luhn）/ipv4/ipv6（保留段豁免），占位符区间排除防误伤，`redact_summary` 大文本预截断（limit×3+512）后脱敏性能约 2 倍；② **F-2 events?verdict 破坏性改参**——`_admin.py` 接受旧参数并标注 `verdict_deprecated`；③ Y-1 两处 `collector.flush()` 未 await 修复（RuntimeWarning 清零）；④ Y-2 `_RateLimiter` 双触发清扫（每 1000 次或距上次 >60s）+ SSE 断开 cleanup 接线；⑤ Y-3 Set-Cookie 非法字符拒绝签发（防 401 循环）；⑥ Y-4 `asyncio.Lock`→`threading.Lock` 跨线程互斥，8 个 `incr_sync_*` + `_snapshot`/`ring_stats`/`events` 加锁；⑦ Y-5 flush 去抖 `FLUSH_DEBOUNCE_S=2.0`（SSE 15s 风暴防锁 convoy），独立 `_last_flush_debounce_ts` 游标；⑧ Y-6 `_flush_loop` 异常保护不静默退出；⑨ Y-7 model 白名单含 `:` `@`（`gpt-4o:2024-08-06` 不再归 unknown_model）；⑩ Y-10 flush 先标后拍消除 ring_delta 双计/漏计窗口；⑪ Y-11 `is_chat_tail` 容忍一层自定义后缀；⑫ Y-12 `incr_sync_lru` 移出锁块；⑬ G-1~G-8 限流注释/重复导入/线程池回收/SSE 时钟回拨等清理；⑭ 新增 `tests/redact_extra_test.py` 14 用例（含确定性公网 IP 生成）
- **v0.9.38** — 仪表盘体验修复 6 项（v0.9.37 后续）：① 上游筛选 PII 关联修复——`incr_sync_pii_detected`/`incr_sync_pii_cache` 改先累进请求 ContextVar（`incr_event` 按正确上游合并），`_token.py` 去掉双计调用，`_query_1h` 的 `_daily` 合并仅在 model_filter（`db_recent is None`）时执行消除 pii_by_type/tokens 双计；② 限流提示 banner 改工具栏上方 tooltip（3s 自动消失）；③ 折线图两侧留白（数据区起点 `pad+gap`，gap=26）；④ 24h 最左 x 标签 `anchor=start` 修复溢出、未来区最右 `anchor=end`；⑤ y 轴画竖线 + 刻度横线向左 tick + 标尺文字移到轴左侧（`anchor=end`）；⑥ 未来区刻度间距与数据区统一（共用 `labelEvery` 节奏）
- **v0.9.37** — 仪表盘折线图/持久化修复 5 项：① 重启后 1h 折线图保留历史（`_series_1h` DB 小时兜底，ring 精确优先、DB 剩余量摊到空桶，守恒不双计）；② `_series_db` 桶 off-by-one 修复（24h/7d 缺最近 1 小时、30d 缺今天整天 → 含当前桶）；③ 折线图当前时间固定横轴 3/4 处、右侧 1/4 未来区留白；④ SVG 宽度响应式 + 7d hover 点抽稀；⑤ 事件 hover tooltip 错位修复（闭包捕获事件对象 + 真实鼠标坐标）
- **v0.9.17** — 三层缓冲/keepalive/WHATWG 帧声明：共享 `utils/json_walk.py` 薄包装三处、Vault `next_available_index` 空洞跳过/`rand8=secrets.token_hex(4)`/`__PII_<seq>_<rand8>__`/`PII_FUZZY_RESTORE=0`（`re.IGNORECASE`）、流式 `byte_buf` WHATWG/`line_buf 16KB/30s`/`arg_buf 一次性 walk`/`keepalive 10s`/截断合成 `seen_global_terminal`、检测硬化 `PII_DETECTION_HARDENING=0/1` 总闸（`fc:/fd:` 精确前缀/ReDoS/CJK/`lru_cache(4)`）；新增 3 测试 + `sentinel_{chat,anthropic,responses}.jsonl`（`scripts/sentinel_record.py --check`）
- **v0.9.14** — 细化 `byte_buf` 残余 `data:` 前缀走 SSE 行级 `json-aware`，避免残余 `plain` 回退破坏
- **v0.9.12** — 补全剩余流式 JSON-aware 遗漏：快路径 `data:`/`event:` 与 `byte_buf` 残余双路径改走 `json-aware` 且残余清理改用 `_strip_token_forms_json_aware`，修复 `p@ss"quote`/`\u` 在 fast/残余路径的 `Expecting value: line 1 column 1 (char 0)` 闭环
- **v0.9.11** — 补全增量 JSON-aware 遗漏：`_llm._flush_anthropic_buf/_flush_responses_buf` 与增量 `arg_buf`（`response.function_call_arguments.delta`/`input_json_delta.partial_json`）改走 `_pii_response_process_json_aware`，覆盖完整 `arg_buf` 的 `p@ss"quote`/`\u` 等特殊字符，片段不完整时自动回退 plain，修复 `{"key":"p@ss"quote"}` 未转义导致 `Expecting ',' delimiter` 闭环；继续沿用 `len>1M`/`depth>5` 守卫 + safe/pending 分割
- **v0.9.10** — 修复嵌套 JSON 串的脱敏还原破坏：① `_token.py:_cred_json_walk` 与 `_pii.py:_pii_json_walk` 的叶字符串若本身为 JSON（`lstrip("\ufeff")` 后 `strip` 再判 `{`/`[` 且可 `loads` 为 `dict/list`）则对内层同 walk 后 `dumps(ensure_ascii=False, separators=(',',':'))` 回写，覆盖 `tool_calls.arguments` 等 `stringified JSON` 场景；② `_llm.py` 新增 `_pii_process_sse_line` 对 `data: {JSON}` 行按 `split(":",1)` 剥离前缀后对 `payload.lstrip("\ufeff")` 做 JSON-aware（含嵌套与 BOM），`[DONE]`/空行早退，`data:[DONE]`/`data:  ` 多空格兼容，替换 slow path 的 `data:` 行（含 `tool_calls_pending_events`、`_flush_*` 透传行、续行重建 `sanitized`）；③ 非流式整包嵌套由 walk 层递归覆盖，不另做外层二次 `loads`；④ BOM `\ufeff` 统一剥离（外层 `lstrip("\ufeff").lstrip()`），半行残余仅 best-effort；⑤ `separators=(',',':')` 与 `ensure_ascii=False` 的空白压缩/`\uXXXX`→明文属语义等价，非字节级保持（已在 spec 显式契约）；新增 7 个回归用例（嵌套 `p@ss"quote`/`\u`/`\` + BOM + DONE 变体 + 语义等价）
- **v0.9.9** — JSON-aware 热修复：`_token._redact_json_aware/_restore_json_aware`、`_pii.pii_redact_json_aware`、`_llm._strip_token_forms_json_aware/_pii_response_process_json_aware` 对顶层 JSON 叶节点做 `loads→walk→dumps(ensure_ascii=False)`，修复 `\u` 劫持（`0031` 切 `a\u0031b`→`Invalid \escape`）与 `p@ss"quote` 未转义（`Expecting ',' delimiter`）两类 `JSONDecodeError`
- **v0.9.8** — 空 SSE/非 JSON 空体转 502：流式 `bytes_written==0` 且 `upstream.status==200` 时按尾缀注入最小可解析 SSE（`chat→_build_block_event`/`responses→_build_block_event_responses`/`anthropic→_build_block_event_anthropic`），`502/401` 透传；非流式 `_strip_token_forms` 后空体转 `502 application/json {"error":{"message":"empty after strip"}}`
- **v0.9.7** — 修复 `CREDENTIAL_PROXY_DEBUG_DIR` 对 Responses API 保存失效：① `_extract_conv_id` 新增 `data.response.id` 分支（`resp_*` 藏在 `response.created/in_progress/completed` 的 `response.id`，原逻辑仅认 `data.id`/`message.id` 导致 `conv_id=None` → `request.json/response.jsonl` 永不落地），同步覆盖 SSE 快/慢双路径；② 兼容 `tail` 无前导 `/` 的 `v1/responses` 尾缀判定（`1ad7700` 已修）与权限问题（`root` 创建目录后 `credential-proxy` 无法写入）排查
- **v0.9.6** — PII 全局持久化 + 并发隔离 + 永不空流：① `_token.py` `GlobalPiiTokens` 进程级 LRU（`PII_MAX_ENTRIES=1000` 真 LRU `move_to_end`，`async def register` + `asyncio.Lock`，命中复用，prompt cache 命中率恢复）；② `_pii.py`/`_llm.py` 全局单例复用，`_pii_cleanup` 不再 `clear`（仅每请求重置 malformed 计数）；③ `_llm.py` 每请求状态迁 `ContextVar`/局部（`pii_scope/audit_hold*/last_*` + 流循环 `tool_calls_*/bytes_written/is_*_stream/content_buf` 等全量），`handler` 入口 `set`/ `finally` `reset`（`_pii_scope` 全局持久化故仅捕获 Token）；④ 流式 `heavy/fast` 按 `bytes_written`（仅 `resp.write` 成功计数）守门，`upstream.status==200` 时按尾缀注入最小可解析 SSE（`chat→_build_block_event`/`responses→_build_block_event_responses`/`anthropic→_build_block_event_anthropic`），`502/401` 透传；⑤ 流末 `audit_hold` 悬挂强制 `rejected` 再守门；⑥ 非流式 `_strip_token_forms` 后空体转 `502 application/json {"error":{"message":"empty after strip"}}`；⚠️ 全局持久化属隐私-缓存权衡（已与用户确认接受）：同一明文跨请求映射至同一 `__PII_…__`，上游可关联，默认 `PII_REDACTION_ENABLED=0` 无影响，敏感场景建议调小 `PII_MAX_ENTRIES` 或定期 `clear()`
- **v0.9.5** — A 方案永不空流：`block / approve(expired/failed)` 审计拦截永不返回 `200 空 SSE`。① `_llm.py` 新增 `audit_block_injected` 追踪，`sse_event_count==0` 时区分审计拦截与上游空流：审计拦截已注入则 `info 审计拦截已注入` 而不计为错误，上游真空流则兜底注入 `BLOCK_MESSAGE`（按 `is_responses/is_anthropic` 选择 `chat/completions|v1/messages|v1/responses` 形态）再 `error`，`fast_sse(无审计)` 同理兜底；`SSE_CLIENT_GONE` 导致的首注入失败在流末重试补发，确保 `hermes` 永远收到一句可展示的 `该工具调用已被安全策略拦截…` 而非 `JSONDecodeError: line 1 column 1` 重试 5 次
- **v0.9.4** — 热修复：`AUDIT_MODE=approve` 零日志静默坑。① `_audit.py` 新增 MXID 格式校验 `^@[^\s:]+:[^\s:]+$`，`"@keivry@matrix.example"`（`@` 写成 `:`）等非法值在 `parse_audit_env_config(require_whitelist=True)` 直接 `errors` + `proxy.py SystemExit`，`_ensure_audit_init` 同步校验 `logger.error 成员格式非法` 并过滤非法成员后若空集合降级 `block`，彻底杜绝“非空但非法 → 审批永远等不到 ✅”的无日志假死；② `_llm.py` 的 `approve` 审批链路补全 `已发送/等待中/超时/结果` 四段 `info/warning/error` 日志，`SSE 空流` 警告提级为 `error`，0.9.3 的 `502 空体` 误判外，流式 0 事件亦可见
- **v0.9.3** — 热修复：Hermes `JSONDecodeError: Expecting value: line 1 column 1` 空体沉默问题 + `APPROVAL_WHITELIST` 引号包裹静默失效。① `_llm.py` 漏判 `v1/responses`：补全 `status>=400` 与空体警告的 Responses 分支，空体从 `200 空 JSON` 改为 `502 {"error":"upstream empty response"}` 显式错误（便于观测与 failover）；② 统一 `_extract_tool_calls_non_stream` 与 `_debug_save_eligible` 的 Responses 尾缀匹配为 `endswith('v1/responses')`（无斜杠，兼容 `v1/responses` 形态）；③ `_audit.py` 双处白名单解析剥除外层引号（兼容 compose 中 `APPROVAL_WHITELIST="@a:example"`），`'"@keivry@matrix.example"'` 不再静默失效
- **v0.9.2** — 热修复：`AUDIT_MODE=approve` 启动期 `no running event loop` 崩溃（孤儿清扫 `create_task` 从同步 `_ensure_audit_init` 移至 `run()` 显式生命周期 + `audit_tool_call` 异步兜底，轻量入口/测试入口不自启）
- **v0.9.1** — 审查修复合集（Round 15/17）：① ReDoS 二次方回溯防御（工具参数拆链/`_normalize_dotdot` 锚定+限长、`O(n)` 定位、`find --delete` 拆链防误匹配、耗时断言补绕过形态）；② 审计日志脱敏加固（PII `malformed` token 零明文、`deny` 摘要 `Bearer`/键值 `JSON` 形态、`_SECRET_PATTERNS` 补短键+前瞻防二次覆盖、`executor` `done_callback` 防异常吞没）；③ 审批白名单精确匹配+显式排除审计消息；④ `PII` 流式/非流式出口统一剥离残缺+完整幻觉 `token`；⑤ 审计审批分支可达性与 `PII` 残缺清理/单管道拆分修复
- **v0.9.0** — LLM 隐私网关正式版：① PII 脱敏（请求/响应双侧，`PII_REDACTION_ENABLED` / `PII_RESPONSE_SIDE` / `PII_HOLD_MAX`）；② 输出审计（`AUDIT_MODE=off|block|approve`、`AUDIT_POLICY_FILE`、`AUDIT_TIMEOUT`、`AUDIT_HOLD_MAX_BYTES`），block 模式危险工具调用阻断，approve 模式 Matrix ✅/❎ 审批（`APPROVAL_WHITELIST`）；③ JSONL 审计日志（10MB×5 轮转、0600、fail-closed）；④ 配置启动校验（非法值启动报错，approve 无白名单报错）；⑤ 真实流量验证修复：阻断后后续 content 转发、轻量入口统一 `_ensure_audit_init`（policy 初始化）、`_init_pii` 顺序修正。**安全警示**：PII 脱敏与输出审计默认关闭（保护默认 fail-open），生产启用需显式设置环境变量并配置策略
- **v0.8.11** — ① LLM 上游连接重试：`session.request()` 对瞬时连接异常（`ServerDisconnectedError` / `ClientConnectionError` / `TimeoutError`）指数退避重试 3 次（0.5s→1s→2s），仅在拿到响应头之前重试，修复 opencode-go 网关间歇性 Server disconnected 导致下游 500；② Matrix 异常保护：`_ask` 的 `room_send` 加保护（断连时 unlock_event 状态残留 → 永久 408 死锁），`_resolve_hash_change` task 异常不再无人检索；③ 凭据审批消息显示调用方信息（已注册：名称/用途/脚本路径；未注册：脚本路径+提示；终端直调单独标记）。新增集成测试（真实 aiohttp 模拟上游断开）+ matrix/credential 单元测试
- **v0.8.10** — LLM 代理空流检测：SSE 流结束且 0 个 data 事件（或非流式 200 空响应体）时打 WARNING（`LLM 上游返回空流...`），捕获上游 200+空 body 场景（客户端表现为 EmptyStreamError），此前该场景无任何日志
- **v0.8.9** — 公开仓库安全清理：移除历史中的内网 IP（默认值改为 `127.0.0.1`）、主机名与本地绝对路径；重写全部 git 历史并重建 GHCR 镜像。功能无变化
- **v0.8.8** — TPM 解封不再依赖持久化 primary.ctx：primary key 由 storage seed 确定性派生，每次解封前现场 `tpm2_createprimary`（owner + rsa2048 + sha256）生成，`seal.pub/seal.priv` 跨重启永久有效。修复主机重启后 `tpm2_load` 报 `integrity check failed (0x1DF)` 导致 TPM 解锁失败的问题（旧 primary.ctx 是 transient context 快照，重启后失效）。部署只需保留 seal.pub/seal.priv
- **v0.8.7** — 审查修复：① 续行重建路径 non-dict payload（JSON 数组/字符串）防御（与主循环对称，防 SSE 流截断）；② `content_block_stop` / responses `*.done` 事件清理 arg_buf（防跨块/跨 item 拼接伪还原，与 anthropic 的 block_stop 对称）；③ 新增 SSE 主循环集成测试（test_sse_stream_loop.py，真实 aiohttp：跨行数组/字符串透传、[DONE] 标记）
- **v0.8.6** — LLM 代理适配 Anthropic Messages API（/v1/messages）流式：content_block_delta 的 text_delta / thinking_delta / input_json_delta 分片 token 累积还原，保持 Anthropic 事件格式（`event:` 行 + data 结构）输出；非 content_block_delta 事件（message_start / message_stop 等）原样透传。至此三种协议（chat/completions、responses、messages）流式分片还原齐平
- **v0.8.5** — LLM 代理适配 OpenAI Responses API（/v1/responses）：SSE delta 事件（output_text / reasoning_text / function_call_arguments）分片 token 累积还原，保持原格式输出，无 chat/completions 格式污染；非流式 JSON 整包还原（原有）。首轮审查修复：flush 保留 pending（跨事件分片还原）、续行重建补 `data: ` 前缀、`_PARTIAL_TOKEN_RE` 覆盖全部残缺形态、幻觉 token 防重组泄漏
- **v0.8.4** — `--raw` 安全加固：禁止终端直接调用，强制脚本内使用
- **v0.8.0** — 三因子认证；移除 Token 降级系统；`get register --script-path`
- **v0.7.0** — Caller 注册表 + 自动放行 + 哈希变更通知
- **v0.6.0** — LLM 脱敏代理 + SSE 流式 token 还原
- **v0.5.0** — Go CLI 二进制 `get`
- **v0.4.0** — Mixin 架构拆分
- **v0.3.0** — TPM 硬件密封
- **v0.2.0** — Matrix 审批流程
- **v0.1.0** — 基础 KeePass HTTP API
