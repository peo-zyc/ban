#!/bin/sh
# 隔离集成测试：需要在用户+网络命名空间中运行（见 run-integration.sh）
#   unshare -rn tests/integration.sh
set -u

BIN=${BIN:-/tmp/ban-build-test}
E=${ETC:-/tmp/ban-it}
FAILED=0

fail() { echo "FAIL: $*"; FAILED=1; }
ok() { echo "ok - $*"; }
note() { echo "note - $*"; }

rm -rf "$E"
mkdir -p "$E"
cat > "$E/ban.conf" <<EOF
backend = nft
action = reject
dns_mode = hosts
dns_enabled = true
ipv6 = true
enabled = true
hosts_file = $E/hosts
log_file = $E/ban.log
EOF
printf '127.0.0.1 localhost\n' > "$E/hosts"

echo "== 1. add IP / CIDR =="
"$BIN" --etc-dir "$E" add 1.2.3.4 203.0.113.0/24 2001:db8::1 --comment itest --for 1h
[ $? -eq 0 ] || fail "add 返回非 0"
nft list table inet ban > "$E/nft.txt" 2>&1 || fail "nft table not created"
grep -q "1\.2\.3\.4" "$E/nft.txt" || fail "1.2.3.4 未写入集合"
grep -q "203\.0\.113\.0/24" "$E/nft.txt" || fail "CIDR 未写入集合"
grep -q "2001:db8::1" "$E/nft.txt" || fail "IPv6 未写入集合"
grep -q "timeout" "$E/nft.txt" || note "内核未应用 timeout（降级模式）"
grep -q "@allow_v4 accept" "$E/nft.txt" || fail "白名单链规则缺失"
grep -q "reject" "$E/nft.txt" || fail "拦截规则缺失"
ok "规则已下发到 nftables"

echo "== 2. list =="
"$BIN" --etc-dir "$E" list | grep -q "1\.2\.3\.4" || fail "list 输出缺少条目"
"$BIN" --etc-dir "$E" --json list | grep -q '"count": 3' || fail "JSON list 计数错误"
ok "list / --json list"

echo "== 3. 白名单 =="
"$BIN" --etc-dir "$E" allow add 10.0.0.0/8 --comment lan || fail "allow add 失败"
nft list table inet ban | grep -q "10\.0\.0\.0/8" || fail "白名单未进入集合"
"$BIN" --etc-dir "$E" allow list | grep -q "10\.0\.0\.0/8" || fail "allow list 缺少条目"
ok "白名单添加"

echo "== 4. del =="
"$BIN" --etc-dir "$E" del 1.2.3.4 || fail "del 失败"
nft list table inet ban | grep -q "1\.2\.3\.4 " && fail "删除后仍在集合中"
ok "删除规则"

echo "== 5. disable / enable =="
"$BIN" --etc-dir "$E" disable || fail "disable 失败"
nft list table inet ban | grep -q "counter reject" && fail "停用后仍有拦截规则"
"$BIN" --etc-dir "$E" enable || fail "enable 失败"
nft list table inet ban | grep -q "counter" || fail "启用后拦截规则缺失"
ok "enable / disable"

echo "== 6. 域名（hosts 层）=="
"$BIN" --etc-dir "$E" add example.com --no-dns || fail "add domain 失败"
grep -q "0\.0\.0\.0 example\.com" "$E/hosts" || fail "hosts 托管区块缺少域名"
grep -q ":: example\.com" "$E/hosts" || fail "hosts 缺少 IPv6 条目"
# 重复添加不应产生重复条目
"$BIN" --etc-dir "$E" add example.com --no-dns >/dev/null 2>&1
[ "$(grep -c '0\.0\.0\.0 example\.com' "$E/hosts")" -eq 1 ] || fail "hosts 区块出现重复"
ok "hosts 区块写入且幂等"

echo "== 7. status / doctor =="
"$BIN" --etc-dir "$E" status | grep -q "防火墙后端" || fail "status 输出异常"
"$BIN" --etc-dir "$E" --json status | grep -q '"backend"' || fail "status JSON 异常"
"$BIN" --etc-dir "$E" doctor > "$E/doctor.txt" 2>&1 || fail "doctor 返回非 0"
grep -q "nftables" "$E/doctor.txt" || fail "doctor 未检测 nftables"
ok "status / doctor"

echo "== 8. export / import =="
"$BIN" --etc-dir "$E" export "$E/export.json" || fail "export 失败"
"$BIN" --etc-dir "$E" export --format text "$E/export.txt" || fail "text export 失败"
"$BIN" --etc-dir "$E" flush --all || fail "flush 失败"
"$BIN" --etc-dir "$E" list | grep -q "没有规则" || fail "flush 后仍有规则"
"$BIN" --etc-dir "$E" import "$E/export.json" || fail "import 失败"
"$BIN" --etc-dir "$E" list | grep -q "example\.com" || fail "import 未恢复规则"
grep -q "0\.0\.0\.0 example\.com" "$E/hosts" || fail "import 后 DNS 层未恢复"
ok "export / import"

echo "== 9. 临时封禁过期 + gc =="
"$BIN" --etc-dir "$E" add 9.9.9.9 --for 1s || fail "add --for 失败"
sleep 2
"$BIN" --etc-dir "$E" gc || fail "gc 失败"
"$BIN" --etc-dir "$E" list --expired | grep -q "9\.9\.9\.9" && fail "gc 未清理过期规则"
ok "临时封禁与 gc"

echo "== 10. refresh =="
"$BIN" --etc-dir "$E" refresh --quiet
[ $? -eq 0 ] || note "refresh 返回非 0（沙箱内可能无网络）"
ok "refresh 不崩溃"

echo "== 11. flush 清理 =="
"$BIN" --etc-dir "$E" flush --all || fail "flush 失败"
nft list table inet ban 2>&1 | grep -q "No such file" || note "nft 表仍存在（teardown 行为）"
grep -q "ban managed block" "$E/hosts" && fail "DNS 区块未清理"
ok "flush 清理防火墙与 DNS"

echo
if [ "$FAILED" -eq 0 ]; then
    echo "全部集成测试通过"
    exit 0
fi
echo "存在失败项"
exit 1
