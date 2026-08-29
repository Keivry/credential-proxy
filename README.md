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
| `PII_VAULT_GAP_AWARE` | 内置稳态下标（非开关，`next_available_index` 空洞跳过，`__PII_<seq>_<rand8>__` 其中 `rand8=secrets.token_hex(4)`） | —（内置） |

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
