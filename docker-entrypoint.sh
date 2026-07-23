#!/bin/bash
set -euo pipefail

# ── 验证必填环境变量 ──
: "${HOMESERVER:?HOMESERVER is required}"
: "${ROOM_ID:?ROOM_ID is required}"
: "${MATRIX_ACCESS_TOKEN:?MATRIX_ACCESS_TOKEN is required}"

# ── 默认值 (可通过 env 覆盖) ──
export DATA_DIR="${DATA_DIR:-/data}"
export TPM_DIR="${TPM_DIR:-$DATA_DIR/tpm}"
export DB_DIR="${DB_DIR:-$DATA_DIR/db}"
export CREDENTIAL_PORT="${CREDENTIAL_PORT:-8877}"

# ── 确保数据目录存在 ──
mkdir -p "$TPM_DIR" "$DB_DIR"

echo "=== Credential Proxy ==="
echo "Homeserver: $HOMESERVER"
echo "Room: $ROOM_ID"
echo "Credential port: $CREDENTIAL_PORT"
echo "Data dir: $DATA_DIR"
echo "TPM dir: $TPM_DIR"
echo "DB dir: $DB_DIR"
echo "========================="

exec python3 /app/proxy.py "$HOMESERVER" "$ROOM_ID" "$@"
