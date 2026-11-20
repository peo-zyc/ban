#!/bin/sh
# 把 DNS 从 systemd-resolved 换成 NetworkManager 托管的 dnsmasq。
# 这样 dnsmasq 由 NM 启停、自动跟随上游，并加载 /etc/NetworkManager/dnsmasq.d
# （ban 的 drop-in 就写在那里）。
#
# 用法：
#   sudo sh packaging/dns-takeover.sh status      # 只看现状
#   sudo sh packaging/dns-takeover.sh apply       # 切换（可回滚）
#   sudo sh packaging/dns-takeover.sh rollback    # 回到 systemd-resolved
set -u

CONF_DIR=/etc/NetworkManager/conf.d
CONF=$CONF_DIR/90-ban-dns.conf
BAK=/etc/resolv.conf.ban-backup
NSS_BAK=/etc/nsswitch.conf.ban-backup
NSS=/etc/nsswitch.conf

die() { echo "错误: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "需要 root（请用 sudo 运行）"; }

show_port53() {
    echo "--- 53/UDP 监听 ---"
    ss -lunp 2>/dev/null | grep ':53 ' || echo "（无）"
}

show_status() {
    echo "systemd-resolved: $(systemctl is-enabled systemd-resolved 2>/dev/null || echo -) / $(systemctl is-active systemd-resolved 2>/dev/null || echo -)"
    echo "dnsmasq         : $(systemctl is-enabled dnsmasq 2>/dev/null || echo -) / $(systemctl is-active dnsmasq 2>/dev/null || echo -) $(systemctl is-failed dnsmasq 2>/dev/null | grep -q failed && echo '(failed)' || true)"
    echo "NetworkManager  : $(systemctl is-active NetworkManager 2>/dev/null || echo -)"
    echo "NM dns=         : $(grep -rhE '^\s*dns\s*=' "$CONF_DIR" /etc/NetworkManager/NetworkManager.conf 2>/dev/null || echo '(未设置)')"
    echo "resolv.conf     : $(readlink -f /etc/resolv.conf) -> $(grep -m1 '^nameserver' /etc/resolv.conf 2>/dev/null || echo 无)"
    echo "nsswitch hosts  : $(grep -E '^hosts:' /etc/nsswitch.conf 2>/dev/null || echo -)"
    show_port53
}

apply() {
    need_root
    command -v dnsmasq >/dev/null 2>&1 || die "未安装 dnsmasq（sudo pacman -S dnsmasq）"
    [ -d "$CONF_DIR" ] || die "未找到 $CONF_DIR（NetworkManager 是否安装？）"

    echo "==> 备份 /etc/resolv.conf"
    [ -e "$BAK" ] || cp -a /etc/resolv.conf "$BAK" 2>/dev/null || true

    echo "==> 让 NetworkManager 托管 dnsmasq"
    mkdir -p "$CONF_DIR" /etc/NetworkManager/dnsmasq.d
    cat > "$CONF" <<'EOF'
[main]
dns=dnsmasq
EOF

    echo "==> 停用 systemd-resolved"
    systemctl disable --now systemd-resolved.service 2>/dev/null || true
    systemctl reset-failed dnsmasq 2>/dev/null || true

    # nsswitch 里的 nss-resolve 会指向已停用的 resolved，去掉以免每次解析多一次失败
    if [ -f "$NSS" ] && grep -qE '^hosts:.*\bresolve\b' "$NSS"; then
        echo "==> 清理 /etc/nsswitch.conf 中的 resolve 模块"
        [ -e "$NSS_BAK" ] || cp -a "$NSS" "$NSS_BAK"
        sed -i -E '/^hosts:/{ s/\[!UNAVAIL=return\]//; s/\bresolve\b//; s/[[:space:]]+/ /g; s/:[[:space:]]*:/: /g }' "$NSS"
        grep -E '^hosts:' "$NSS"
    fi

    echo "==> 重启 NetworkManager（会 fork 自己的 dnsmasq）"
    systemctl restart NetworkManager || die "NetworkManager 重启失败"

    sleep 2
    echo
    show_status

    if ss -lun 2>/dev/null | grep -q ':53 '; then
        echo
        echo "==> 53 已重新监听"
    else
        echo
        echo "警告: 53 未被监听，DNS 可能不可用，请执行回滚: $0 rollback" >&2
        exit 1
    fi

    echo
    echo "下一步: sudo ban install && ban doctor"
}

rollback() {
    need_root
    echo "==> 移除 NM dns=dnsmasq 配置"
    rm -f "$CONF"

    echo "==> 恢复 systemd-resolved"
    systemctl enable --now systemd-resolved.service 2>/dev/null || true

    echo "==> 重启 NetworkManager"
    systemctl restart NetworkManager 2>/dev/null || true

    if [ -e "$BAK" ]; then
        echo "==> 还原 /etc/resolv.conf"
        cp -a "$BAK" /etc/resolv.conf 2>/dev/null || true
    fi

    if [ -e "$NSS_BAK" ]; then
        echo "==> 还原 /etc/nsswitch.conf"
        cp -a "$NSS_BAK" "$NSS" 2>/dev/null || true
    fi

    systemctl disable dnsmasq 2>/dev/null || true
    sleep 1
    echo
    show_status
    echo
    echo "已回滚。若 DNS 仍异常，执行: systemctl restart NetworkManager"
}

case "${1:-status}" in
    status) show_status ;;
    apply) apply ;;
    rollback) rollback ;;
    *) echo "用法: $0 [status|apply|rollback]" >&2; exit 2 ;;
esac
