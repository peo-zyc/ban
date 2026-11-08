#!/bin/sh
# 回归测试：dnsmasq 被系统/NetworkManager 接管时的降级行为。
#   unshare -rn tests/dns-fallback.sh
set -u

BIN=${BIN:-/tmp/ban-build-test}
E=${ETC:-/tmp/ban-dnsfallback}
FAILED=0

fail() { echo "FAIL: $*"; FAILED=1; }
ok() { echo "ok - $*"; }

setup() {
    rm -rf "$E"
    mkdir -p "$E"
    cat > "$E/ban.conf" <<EOF
backend = nft
dns_mode = $1
dnsmasq_dir = $E/dnsmasq.d
hosts_file = $E/hosts
log_file = $E/ban.log
EOF
    printf '127.0.0.1 localhost\n' > "$E/hosts"
    : > "$E/allow.conf"
}

echo "== 1. 显式 dns_mode=dnsmasq 但 dnsmasq 未运行 → 应回退 hosts =="
setup dnsmasq
"$BIN" --etc-dir "$E" add example.com --no-dns >/dev/null 2>&1
grep -q "0.0.0.0 example.com" "$E/hosts" || fail "未回退写入 hosts 区块"
[ -f "$E/dnsmasq.d/ban.conf" ] && fail "回退后仍残留 dnsmasq 配置"
ok "回退 hosts 且清理 dnsmasq 残留"

echo "== 2. dns_mode=auto → 同样回退，且不残留 =="
setup auto
"$BIN" --etc-dir "$E" add auto.example --no-dns >/dev/null 2>&1
grep -q "0.0.0.0 auto.example" "$E/hosts" || fail "auto 模式未写入 hosts"
[ -f "$E/dnsmasq.d/ban.conf" ] && fail "auto 模式残留 dnsmasq 配置"
ok "auto 模式降级正常"

echo "== 3. 从 dnsmasq 切到 hosts：残留的 dnsmasq 配置应被清理 =="
setup hosts
mkdir -p "$E/dnsmasq.d"
printf 'address=/stale.test/0.0.0.0\n' > "$E/dnsmasq.d/ban.conf"
"$BIN" --etc-dir "$E" add stale.test --no-dns >/dev/null 2>&1
[ -f "$E/dnsmasq.d/ban.conf" ] && fail "切到 hosts 后 dnsmasq 配置未清理"
grep -q "0.0.0.0 stale.test" "$E/hosts" || fail "hosts 区块未写入"
ok "模式切换清理残留"

echo "== 4. hosts 区块幂等性（重复 add 不重复写） =="
"$BIN" --etc-dir "$E" add stale.test --no-dns >/dev/null 2>&1
[ "$(grep -c '0.0.0.0 stale.test' "$E/hosts")" -eq 1 ] || fail "hosts 出现重复条目"
ok "hosts 幂等"

echo "== 5. dns_mode=off → 清空 DNS 层 =="
rm -rf "$E"; mkdir -p "$E"
cat > "$E/ban.conf" <<EOF
backend = nft
dns_mode = hosts
dnsmasq_dir = $E/dnsmasq.d
hosts_file = $E/hosts
log_file = $E/ban.log
EOF
printf '127.0.0.1 localhost\n' > "$E/hosts"
: > "$E/allow.conf"
"$BIN" --etc-dir "$E" add off.test --no-dns >/dev/null 2>&1
grep -q "0.0.0.0 off.test" "$E/hosts" || fail "前置写入失败"
printf 'dns_enabled = false\n' >> "$E/ban.conf"
"$BIN" --etc-dir "$E" add other.test --no-dns >/dev/null 2>&1
grep -q "ban managed block" "$E/hosts" && fail "dns_enabled=false 后 hosts 区块未清理"
ok "关闭 DNS 层后清理干净"

echo "== 6. dnsmasq 真生效时不误降级（stub systemctl + 真实 dnsmasq）=="
rm -rf "$E"
mkdir -p "$E/dnsmasq.d" "$E/bin"
cat > "$E/ban.conf" <<EOF
backend = nft
dns_mode = dnsmasq
dnsmasq_dir = $E/dnsmasq.d
hosts_file = $E/hosts
resolv_conf = $E/resolv.conf
log_file = $E/ban.log
EOF
printf '127.0.0.1 localhost\n' > "$E/hosts"
: > "$E/allow.conf"
printf 'nameserver 127.0.0.1\n' > "$E/resolv.conf"

# 把 dnsmasq 伪装成 systemd 服务：reload 时真正重启一个本地实例
cat > "$E/bin/systemctl" <<EOF
#!/bin/sh
case "\$1" in
  is-active)
    if [ "\${2:-}" = "dnsmasq" ]; then echo active; exit 0; fi
    echo inactive; exit 3 ;;
  reload|restart)
    if [ "\${2:-}" = "dnsmasq" ]; then
      pkill -x dnsmasq 2>/dev/null
      sleep 0.2
      dnsmasq --no-resolv --no-hosts --port=53 --listen-address=127.0.0.1 \\
              --conf-dir="$E/dnsmasq.d" --pid-file="$E/dnsmasq.pid" \\
              --log-facility="$E/dnsmasq.log" >/dev/null 2>&1 &
      sleep 0.4
      exit 0
    fi
    exit 1 ;;
esac
exit 1
EOF
chmod +x "$E/bin/systemctl"

PATH="$E/bin:$PATH" "$BIN" --etc-dir "$E" add blocked.test --no-dns >/dev/null 2>&1
[ -f "$E/dnsmasq.d/ban.conf" ] || fail "dnsmasq 配置未写入"
grep -q "address=/blocked.test/0.0.0.0" "$E/dnsmasq.d/ban.conf" || fail "dnsmasq 配置内容不正确"
grep -q "ban managed block" "$E/hosts" && fail "dnsmasq 生效时不应再写 hosts 区块"
PATH="$E/bin:$PATH" "$BIN" --etc-dir "$E" status 2>/dev/null | grep -q "dnsmasq" || fail "status 未显示 dnsmasq 模式"
pkill -x dnsmasq 2>/dev/null
ok "dnsmasq 生效时保持 dnsmasq 模式，不误降级"

echo
if [ "$FAILED" -eq 0 ]; then
    echo "DNS 降级回归测试通过"
    exit 0
fi
echo "存在失败项"
exit 1
