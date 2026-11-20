#!/bin/sh
# 兼容包装：逻辑已在 ban 二进制里（ban dns ...）
#   sudo sh packaging/dns-takeover.sh status|apply|rollback
set -u
BIN=${BAN_BIN:-$(command -v ban 2>/dev/null || echo "$(dirname "$0")/../build-release/ban")}
exec "$BIN" dns "${1:-status}"
