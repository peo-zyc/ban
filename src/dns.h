#pragma once

#include <string>
#include <vector>

#include "config.h"

namespace dnsblock {

struct Info {
    std::string mode;    // dnsmasq | hosts | off
    std::string path;    // 实际写入的主要文件
    std::string detail;  // 人类可读说明
};

// 解析实际使用的 DNS 阻断方式。
// auto：dnsmasq 可用（自身服务运行，或被 NetworkManager 托管）→ dnsmasq；否则 → hosts。
std::string detect_mode(const Config& cfg);

bool dnsmasq_installed();
bool dnsmasq_active(std::string* detail);
bool dnsmasq_usable(std::string* detail);

// NetworkManager 相关探测
bool networkmanager_active();
bool nm_dnsmasq_dir_present();
bool nm_hook_installed();

Info describe(const Config& cfg);

// 写入/更新 DNS 阻断。domains 为空等价于清除阻断。
// dnsmasq 模式下会验证是否真的生效；若被 NetworkManager 接管导致无效，
// 自动回退到 hosts 模式。
bool apply(const Config& cfg, const std::vector<std::string>& domains, std::string* err);

// 移除本程序写入的所有 DNS 阻断（两个目录 + hosts 区块）。
bool teardown(const Config& cfg, std::string* err);

// NetworkManager dispatcher 钩子：网络事件后重新下发规则，
// 防止 NM 重启 dnsmasq / 改写 resolv.conf 导致阻断静默失效。
bool install_nm_hook(const std::string& bin, const std::string& etc_dir, std::string* err);
bool remove_nm_hook(std::string* err);

size_t count_hosts_entries(const Config& cfg);
size_t count_dnsmasq_entries();

}  // namespace dnsblock
