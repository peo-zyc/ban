#pragma once

#include <string>
#include <vector>

#include "config.h"

namespace dnsblock {

struct Info {
    std::string mode;    // dnsmasq | hosts | off
    std::string path;    // 实际写入的文件
    std::string detail;
};

// 解析实际使用的 DNS 阻断方式。
// auto：dnsmasq 已安装且服务在运行 → dnsmasq；否则 → hosts。
std::string detect_mode(const Config& cfg);

bool dnsmasq_installed();
bool dnsmasq_active(std::string* detail);
bool dnsmasq_usable(std::string* detail);

Info describe(const Config& cfg);

// 写入/更新 DNS 阻断。domains 为空等价于清除阻断。
bool apply(const Config& cfg, const std::vector<std::string>& domains, std::string* err);

// 移除本程序写入的所有 DNS 阻断。
bool teardown(const Config& cfg, std::string* err);

// 读取当前 /etc/hosts 中托管的域名数量（用于统计）
size_t count_hosts_entries(const Config& cfg);

}  // namespace dnsblock
