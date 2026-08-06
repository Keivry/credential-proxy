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
| `DATA_DIR` | 数据目录 | `/data` |
| `TPM_DIR` | TPM 密封文件目录 | `$DATA_DIR/tpm` |
| `DB_DIR` | KeePass 数据库目录 | `$DATA_DIR/db` |
| `LLM_<PORT>` | LLM 脱敏代理端口 → 上游 URL | — |

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

- **v0.8.11** — LLM 上游连接重试：`session.request()` 对瞬时连接异常（`ServerDisconnectedError` / `ClientConnectionError` / `TimeoutError`）指数退避重试 3 次（0.5s→1s→2s），仅在拿到响应头之前重试，修复 opencode-go 网关间歇性 Server disconnected 导致下游 500；同时修复 `_ask` 的 `room_send` 无异常保护（Matrix 断连时 unlock_event 状态残留 → 永久 408 死锁）与 `_resolve_hash_change` task 异常无人检索。新增集成测试（真实 aiohttp 模拟上游断开）+ matrix 单元测试
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
