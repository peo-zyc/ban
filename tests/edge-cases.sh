#!/bin/sh
# 边界用例扫描：找崩溃 / 错误行为
set -u
BIN=${BIN:-/tmp/ban-chk}
E=${ETC:-/tmp/ban-edge}
FAILED=0
fail() { echo "FAIL: $*"; FAILED=1; }
ok() { echo "ok - $*"; }

setup() {
    rm -rf "$E"; mkdir -p "$E"
    cat > "$E/ban.conf" <<EOF
backend = nft
dns_mode = hosts
dnsmasq_dir = $E/dnsmasq.d
hosts_file = $E/hosts
resolv_conf = $E/resolv.conf
log_file = $E/ban.log
EOF
    printf '127.0.0.1 localhost\n' > "$E/hosts"
    printf 'nameserver 127.0.0.1\n' > "$E/resolv.conf"
    : > "$E/allow.conf"
}
B() { "$BIN" --etc-dir "$E" "$@"; }

setup

echo "== a. 大小写/尾点域名归一 =="
B add Example.COM. --no-dns >/dev/null 2>&1
grep -q "0.0.0.0 example.com" "$E/hosts" || fail "域名未归一化为小写"
ok "域名归一化"

echo "== b. 重复目标去重 =="
B add 1.1.1.1 1.1.1.1 1.1.1.1 >/dev/null 2>&1
[ "$(B list --json | grep -c '1.1.1.1')" -eq 1 ] || fail "重复目标未被去重"
ok "重复目标去重"

echo "== c. 非法输入应报错而非崩溃 =="
B add "bad domain!" >/dev/null 2>&1; [ $? -ne 0 ] || fail "非法目标未报错"
B add 300.1.1.1 >/dev/null 2>&1; [ $? -ne 0 ] || fail "非法 IP 未报错"
B add 10.0.0.0/33 >/dev/null 2>&1; [ $? -ne 0 ] || fail "非法前缀未报错"
B add x --for 3x >/dev/null 2>&1; [ $? -ne 0 ] || fail "非法时长未报错"
ok "非法输入均报错"

echo "== d. 空配置目录（无 ban.conf）=="
rm -rf "$E/.empty"; mkdir -p "$E/.empty"
"$BIN" --etc-dir "$E/.empty" list >/dev/null 2>&1 || fail "空目录 list 失败"
"$BIN" --etc-dir "$E/.empty" --json status >/dev/null 2>&1 || fail "空目录 status 失败"
ok "空目录可用"

echo "== e. 纯数字域名被当作 ID 的歧义 =="
B add 0.0.0.0 >/dev/null 2>&1
B del 0.0.0.0 >/dev/null 2>&1
[ $? -eq 0 ] || fail "删 IP 0.0.0.0 失败"
ok "0.0.0.0 可正常删除"

echo "== f. IPv6 关闭时不应下发 v6 规则 =="
sed -i 's/^ipv6.*//' "$E/ban.conf"; echo "ipv6 = false" >> "$E/ban.conf"
B add 2001:db8::5 1.2.3.4 >/dev/null 2>&1
nft list table inet ban 2>/dev/null | grep -q "2001:db8::5" && fail "ipv6=false 仍下发 v6"
nft list table inet ban 2>/dev/null | grep -q "1.2.3.4" || fail "v4 未下发"
B del 2001:db8::5 1.2.3.4 >/dev/null 2>&1
ok "ipv6 开关生效"

echo "== g. export 到 stdout / import 从 stdin =="
B add stdin.test --no-dns >/dev/null 2>&1
B export - > "$E/dump.json" 2>/dev/null
[ -s "$E/dump.json" ] || fail "export - 为空"
B flush --all >/dev/null 2>&1
B import - < "$E/dump.json" >/dev/null 2>&1 || fail "import - 失败"
B list | grep -q "stdin.test" || fail "stdin 导入未恢复"
ok "stdout/stdin 管道可用"

echo "== h. 过期规则不应出现在默认 list =="
B add exp.test --for 1s --no-dns >/dev/null 2>&1
sleep 2
B list | grep -q "exp.test" && fail "过期规则出现在默认 list"
B list --expired | grep -q "exp.test" || fail "--expired 未显示过期规则"
ok "过期过滤正确"

echo "== i. flush 后 DNS 区块清空 =="
B flush --all >/dev/null 2>&1
grep -q "ban managed block" "$E/hosts" && fail "flush 后残留 hosts 区块"
ok "flush 清理 DNS"

echo "== j. 并发写不损坏状态 =="
i=1
while [ "$i" -le 20 ]; do
    B add "c$i.test" --no-dns >/dev/null 2>&1 &
    i=$((i + 1))
done
wait
B list --json > "$E/concur.json" 2>/dev/null
python3 -c "import json,sys; d=json.load(open('$E/concur.json')); print('规则数:', d['count'])" || fail "并发后 JSON 损坏"
B list >/dev/null 2>&1 || fail "并发后 list 失败"
ok "并发写未损坏状态"

echo
[ "$FAILED" -eq 0 ] && echo "边界用例全部通过" || echo "存在失败项"
exit $FAILED
