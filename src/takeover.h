#pragma once

#include <string>

// 把系统 DNS 从 systemd-resolved 切换到 NetworkManager 托管的 dnsmasq。
// 这样 53 端口归 dnsmasq，ban 的 drop-in（/etc/NetworkManager/dnsmasq.d）才会被加载，
// 域名封禁因而支持 *.example.com 通配。
namespace takeover {

// 环境是否具备接管条件（不满足时 why 给出原因）
bool supported(std::string* why);

// 执行接管：写 NM 配置、停 resolved、清理 nsswitch、重启 NM，并校验 53 归属
bool apply(std::string* err);

// 回滚到 systemd-resolved
bool rollback(std::string* err);

// 打印当前 DNS 栈状态
void print_status();

}  // namespace takeover
