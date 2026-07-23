#!/bin/bash
set -e

# ── 验证必填环境变量 ──
: "${HOMESERVER:?未设置 HOMESERVER}"
: "${ROOM_ID:?未设置 ROOM_ID}"
: "${MATRIX_ACCESS_TOKEN:?未设置 MATRIX_ACCESS_TOKEN}"

# ── 确保数据目录存在 ──
mkdir -p /data/tpm /data/db

# ── 默认值 (可通过 env 覆盖) ──
export DATA_DIR="${DATA_DIR:-/data}"
export TPM_DIR="${TPM_DIR:-$DATA_DIR/tpm}"
export DB_DIR="${DB_DIR:-$DATA_DIR/db}"
export CREDENTIAL_PORT="${CREDENTIAL_PORT:-8877}"

echo "=== Credential Proxy ==="
echo "Homeserver: $HOMESERVER"
echo "Room: $ROOM_ID"
echo "Credential port: $CREDENTIAL_PORT"
echo "Data dir: $DATA_DIR"
echo "TPM dir: $TPM_DIR"
echo "DB dir: $DB_DIR"
echo "========================="

exec python3 /app/proxy.py "$HOMESERVER" "$ROOM_ID"
