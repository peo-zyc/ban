#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct DnsAnswer {
    std::vector<std::string> v4;
    std::vector<std::string> v6;
    bool ok = false;
    std::string error;
};

// 直接向上游 DNS 发 UDP 查询（A + AAAA）。
// 不经过 /etc/hosts 与 nsswitch，因此不会被本程序的 DNS 层封禁反向污染。
DnsAnswer dns_resolve(const std::string& domain, int timeout_ms = 3000);

// 当前实际使用的上游服务器列表（可能是 /run/systemd/resolve/resolv.conf 中的真实上游）
std::vector<std::string> dns_servers();

// 从指定 resolv.conf 风格文件读取 nameserver（供 doctor 使用）
std::vector<std::string> read_nameservers_from(const std::string& path);
