#include "config.h"

#include <cstdlib>

#include "log.h"
#include "util.h"

namespace {

bool parse_bool(const std::string& v, bool& out) {
    std::string s = util::to_lower(util::trim(v));
    if (s == "1" || s == "true" || s == "yes" || s == "on") {
        out = true;
        return true;
    }
    if (s == "0" || s == "false" || s == "no" || s == "off") {
        out = false;
        return true;
    }
    return false;
}

}  // namespace

void Config::derive_paths() {
    state_file = etc_dir + "/rules.conf";
    allow_file = etc_dir + "/allow.conf";
    cache_file = etc_dir + "/cache.json";
    conf_file = etc_dir + "/ban.conf";
    lock_file = etc_dir + "/rules.lock";
    dnsmasq_file = dnsmasq_dir + "/ban.conf";
}

Config Config::load(const std::string& etc_dir, std::string* err) {
    Config c;
    c.etc_dir = etc_dir;
    c.derive_paths();

    std::string text;
    if (!util::read_file(c.conf_file, text)) {
        // 配置文件不存在时使用默认值，不算错误。
        return c;
    }

    int lineno = 0;
    for (const std::string& raw : util::split(text, '\n', true)) {
        ++lineno;
        std::string line = util::trim(raw);
        if (line.empty() || line[0] == '#') continue;

        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            if (err) *err = c.conf_file + ":" + std::to_string(lineno) + " 缺少 '='";
            continue;
        }
        std::string key = util::to_lower(util::trim(line.substr(0, eq)));
        std::string val = util::trim(line.substr(eq + 1));

        if (key == "backend") {
            c.backend = util::to_lower(val);
        } else if (key == "action") {
            c.action = util::to_lower(val);
        } else if (key == "dns_mode") {
            c.dns_mode = util::to_lower(val);
        } else if (key == "dns_enabled") {
            parse_bool(val, c.dns_enabled);
        } else if (key == "ipv6") {
            parse_bool(val, c.ipv6);
        } else if (key == "enabled") {
            parse_bool(val, c.enabled);
        } else if (key == "refresh_interval_min") {
            int n = std::atoi(val.c_str());
            if (n > 0) c.refresh_interval_min = n;
        } else if (key == "hosts_file") {
            if (!val.empty()) c.hosts_file = val;
        } else if (key == "resolv_conf") {
            if (!val.empty()) c.resolv_conf = val;
        } else if (key == "dnsmasq_dir") {
            if (!val.empty()) {
                c.dnsmasq_dir = val;
                c.dnsmasq_file = c.dnsmasq_dir + "/ban.conf";
            }
        } else if (key == "log_file") {
            if (!val.empty()) c.log_file = val;
        }
    }

    if (c.backend != "auto" && c.backend != "nft" && c.backend != "iptables") {
        if (err) *err = "无效的 backend 值: " + c.backend;
        c.backend = "auto";
    }
    if (c.action != "reject" && c.action != "drop") {
        if (err) *err = "无效的 action 值: " + c.action;
        c.action = "reject";
    }
    if (c.dns_mode != "auto" && c.dns_mode != "dnsmasq" && c.dns_mode != "hosts" &&
        c.dns_mode != "off") {
        if (err) *err = "无效的 dns_mode 值: " + c.dns_mode;
        c.dns_mode = "auto";
    }
    return c;
}

bool Config::save(std::string* err) const {
    std::string s;
    s += "# ban configuration (managed by `ban`, safe to edit by hand while stopped)\n";
    s += "# backend: auto | nft | iptables\n";
    s += "backend = " + backend + "\n";
    s += "# action: reject | drop\n";
    s += "action = " + action + "\n";
    s += "# dns_mode: auto | dnsmasq | hosts | off\n";
    s += "dns_mode = " + dns_mode + "\n";
    s += std::string("dns_enabled = ") + (dns_enabled ? "true" : "false") + "\n";
    s += std::string("ipv6 = ") + (ipv6 ? "true" : "false") + "\n";
    s += std::string("enabled = ") + (enabled ? "true" : "false") + "\n";
    s += "refresh_interval_min = " + std::to_string(refresh_interval_min) + "\n";
    s += "hosts_file = " + hosts_file + "\n";
    s += "resolv_conf = " + resolv_conf + "\n";
    s += "dnsmasq_dir = " + dnsmasq_dir + "\n";
    s += "log_file = " + log_file + "\n";

    std::string mkerr;
    if (!util::is_directory(etc_dir) && !util::make_dirs(etc_dir, 0755, &mkerr)) {
        if (err) *err = mkerr;
        return false;
    }
    return util::write_file_atomic(conf_file, s, 0644, false, err);
}
