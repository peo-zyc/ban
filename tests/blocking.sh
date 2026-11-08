#!/bin/sh
# 端到端拦截验证：确认规则真的能阻断连接，且白名单优先级更高。
#   unshare -rn tests/blocking.sh
set -u

BIN=${BIN:-/tmp/ban-build-test}
E=${ETC:-/tmp/ban-block}
PORT=${PORT:-18321}
FAILED=0

fail() { echo "FAIL: $*"; FAILED=1; }
ok() { echo "ok - $*"; }

rm -rf "$E"
mkdir -p "$E"
cat > "$E/ban.conf" <<EOF
backend = nft
action = reject
dns_enabled = false
hosts_file = $E/hosts
log_file = $E/ban.log
EOF
printf '127.0.0.1 localhost\n' > "$E/hosts"
# 清空白名单，便于测试 127.0.0.1 是否真的被拦
: > "$E/allow.conf"

ip link set lo up 2>/dev/null || true

python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null' EXIT INT TERM
sleep 1

try_connect() {
    curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" >/dev/null 2>&1
    return $?
}

try_connect
rc=$?
[ "$rc" -eq 0 ] || fail "封禁前连接应当成功（rc=$rc）"
ok "封禁前可正常连接"

"$BIN" --etc-dir "$E" add 127.0.0.1 || fail "add 127.0.0.1 失败"
try_connect
rc=$?
[ "$rc" -ne 0 ] || fail "封禁后连接仍然成功"
ok "封禁后连接被拒绝（curl rc=$rc）"

"$BIN" --etc-dir "$E" allow add 127.0.0.0/8 --comment loopback || fail "allow add 失败"
try_connect
rc=$?
[ "$rc" -eq 0 ] || fail "白名单未覆盖封禁（rc=$rc）"
ok "白名单优先于封禁"

"$BIN" --etc-dir "$E" del 127.0.0.1 || fail "del 失败"
"$BIN" --etc-dir "$E" flush --all || fail "flush 失败"
try_connect
rc=$?
[ "$rc" -eq 0 ] || fail "清理后连接未恢复（rc=$rc）"
ok "清理后连接恢复"

echo
if [ "$FAILED" -eq 0 ]; then
    echo "端到端拦截验证通过"
    exit 0
fi
echo "存在失败项"
exit 1
