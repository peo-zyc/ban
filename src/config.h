#pragma once

#include <string>

// 全局配置。路径均由 etc_dir 派生，便于测试时重定向到临时目录。
struct Config {
    // ---------- 路径 ----------
    std::string etc_dir = "/etc/ban";
    std::string state_file;    // rules.conf
    std::string allow_file;    // allow.conf
    std::string cache_file;    // cache.json
    std::string conf_file;     // ban.conf
    std::string lock_file;     // rules.lock
    std::string log_file = "/var/log/ban.log";
    std::string hosts_file = "/etc/hosts";
    std::string resolv_conf = "/etc/resolv.conf";
    std::string dnsmasq_dir = "/etc/dnsmasq.d";
    std::string dnsmasq_file;  // dnsmasq_dir + "/ban.conf"
    std::string systemd_dir = "/usr/local/lib/systemd/system";
    std::string bindir = "/usr/local/bin";

    // ---------- 可持久化设置（ban.conf） ----------
    std::string backend = "auto";     // auto | nft | iptables
    std::string action = "reject";    // reject | drop
    std::string dns_mode = "auto";    // auto | dnsmasq | hosts | off
    bool dns_enabled = true;
    bool ipv6 = true;
    bool enabled = true;
    int refresh_interval_min = 10;

    static Config load(const std::string& etc_dir, std::string* err = nullptr);
    void derive_paths();
    bool save(std::string* err = nullptr) const;
};
