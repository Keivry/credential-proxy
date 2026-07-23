# credential-proxy

Matrix 审批 + TPM 解封 + KeePassXC 后端的凭据代理服务。

**功能：**
- **凭据 API** — HTTP 接口查询 KeePass 条目，需 Matrix 房间 ✅/❎ 审批
- **TPM 解封** — KeePass 主密码由 TPM 2.0 硬件密封，磁盘被盗也无法解密
- **LLM 脱敏代理** — 反向代理 LLM API 请求，自动替换凭据为占位符

**构建：**

```bash
docker build -t credential-proxy .
```

**运行：**

```bash
docker run -d \
  --name credential-proxy \
  --device /dev/tpm0 --device /dev/tpmrm0 \
  -v /path/to/tpm-sealed:/data/tpm:ro \
  -v /path/to/keepass-db:/data/db:ro \
  -p 8877:8877 \
  -e HOMESERVER=https://matrix.example.com \
  -e ROOM_ID='!roomid:example.com' \
  -e MATRIX_ACCESS_TOKEN=*** \
  credential-proxy
```
