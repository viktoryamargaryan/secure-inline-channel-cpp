#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-psk.hex}"
umask 077
openssl rand -hex 32 > "$OUT"
echo "Created 32-byte PSK at $OUT. Copy the same file securely to both devices."
