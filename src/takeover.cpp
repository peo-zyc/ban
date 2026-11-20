#include "takeover.h"

#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <vector>

#include "dns.h"
#include "log.h"
#include "util.h"

namespace takeover {
namespace {

const char* kNmConfDir = "/etc/NetworkManager/conf.d";
const char* kNmConf = "/etc/NetworkManager/conf.d/90-ban-dns.conf";
const char* kNss = "/etc/nsswitch.conf";
const char* kNssBak = "/etc/nsswitch.conf.ban-backup";
const char* kResolv = "/etc/resolv.conf";
const char* kResolvBak = "/etc/resolv.conf.ban-backup";
const char* kResolvLinkBak = "/etc/resolv.conf.ban-link";
const char* kResolved = "systemd-resolved.service";

void sleep_ms(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = static_cast<long>(ms % 1000) * 1000000L;
    ::nanosleep(&ts, nullptr);
}

bool run_ok(const std::vector<std::string>& argv, int timeout = 60) {
    return util::run(argv, "", timeout).ok();
}

// hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns
//   -> hosts: mymachines files myhostname dns
std::string rewrite_nsswitch(const std::string& text) {
    std::string out;
    for (const std::string& raw : util::split(text, '\n', true)) {
        std::string t = util::trim(raw);
        if (!util::starts_with(t, "hosts:")) {
            out += raw;
            out += "\n";
            continue;
        }
        std::vector<std::string> kept;
        for (const std::string& tok : util::split(t.substr(6), ' ', false)) {
            if (tok == "resolve") continue;  // nss-resolve 指向已停用的服务
            if (tok.size() > 2 && tok[0] == '[' && tok[1] == '!') continue;  // [!UNAVAIL=return]
            kept.push_back(tok);
        }
        out += "hosts:";
        if (!kept.empty()) out += " " + util::join(kept, " ");
        out += "\n";
    }
    return out;
}

// /etc/resolv.conf 里的 nameserver 是否都指向本机（dnsmasq）
bool resolv_points_local(std::string* first_ns) {
    std::string text;
    if (!util::read_file(kResolv, text)) return false;

    bool any = false;
    bool all_local = true;
    for (const std::string& raw : util::split(text, '\n', true)) {
        std::string line = util::trim(raw);
        if (!util::starts_with(line, "nameserver")) continue;
        std::string ns = util::trim(line.substr(std::strlen("nameserver")));
        if (ns.empty()) continue;
        any = true;
        if (first_ns && first_ns->empty()) *first_ns = ns;
        if (!(ns == "127.0.0.1" || ns == "::1" || ns == "127.0.0.53")) all_local = false;
    }
    return any && all_local;
}

// 记录 resolv.conf 原状：符号链接记目标，普通文件记内容
void backup_resolv() {
    char buf[4096] = {0};
    ssize_t n = ::readlink(kResolv, buf, sizeof(buf) - 1);
    if (n > 0) {
        util::write_file_atomic(kResolvLinkBak, std::string(buf, static_cast<size_t>(n)), 0644,
                                false, nullptr);
        return;
    }
    std::string content;
    if (util::read_file(kResolv, content)) {
        util::write_file_atomic(kResolvBak, content, 0644, true, nullptr);
    }
}

// 兜底：直接把 resolv.conf 指到本机 dnsmasq（去掉可能存在的旧符号链接）
void force_resolv_local() {
    ::unlink(kResolv);
    util::write_file_atomic(kResolv, "nameserver 127.0.0.1\nnameserver ::1\n", 0644, false, nullptr);
}

std::string unit_state(const char* unit) {
    util::ExecResult e = util::run({"systemctl", "is-active", unit}, "", 8);
    std::string s = util::trim(e.out);
    return s.empty() ? std::string("unknown") : s;
}

std::string unit_enabled(const char* unit) {
    util::ExecResult e = util::run({"systemctl", "is-enabled", unit}, "", 8);
    std::string s = util::trim(e.out);
    return s.empty() ? std::string("unknown") : s;
}

}  // namespace

bool supported(std::string* why) {
    if (!util::is_directory(kNmConfDir)) {
        if (why) *why = std::string("未找到 ") + kNmConfDir + "（系统未使用 NetworkManager）";
        return false;
    }
    if (!dnsblock::networkmanager_active()) {
        if (why) *why = "NetworkManager 未运行";
        return false;
    }
    if (!dnsblock::dnsmasq_installed()) {
        if (why) *why = "未安装 dnsmasq";
        return false;
    }
    return true;
}

bool apply(std::string* err) {
    std::string why;
    if (!supported(&why)) {
        if (err) *err = why;
        return false;
    }

    // 备份 nsswitch（仅首次）
    std::string nss;
    const bool have_nss = util::read_file(kNss, nss);
    if (have_nss && !util::path_exists(kNssBak)) {
        std::string e;
        if (!util::write_file_atomic(kNssBak, nss, 0644, true, &e)) {
            logx::warn("备份 nsswitch.conf 失败: " + e);
        }
    }

    // 备份 resolv.conf（可能是符号链接，记下链接目标）
    if (!util::path_exists(kResolvBak) && !util::path_exists(kResolvLinkBak)) {
        backup_resolv();
    }

    // 1) 让 NetworkManager 托管 dnsmasq，并让它直接写 resolv.conf。
    //    rc-manager=file：NM 会把 /etc/resolv.conf 写成 nameserver 127.0.0.1。
    //    否则在曾用 systemd-resolved 的系统上，/etc/resolv.conf 仍是指向
    //    /run/systemd/resolve/resolv.conf 的旧链接，解析会绕过 dnsmasq。
    std::string mkerr;
    if (!util::make_dirs(kNmConfDir, 0755, &mkerr)) {
        if (err) *err = mkerr;
        return false;
    }
    if (!util::write_file_atomic(kNmConf, "[main]\ndns=dnsmasq\nrc-manager=file\n", 0644, false,
                                 err)) {
        return false;
    }
    logx::debug(std::string("写入 ") + kNmConf);

    // 2) 停用 systemd-resolved（释放 127.0.0.53/54:53）
    run_ok({"systemctl", "disable", "--now", kResolved}, 60);
    run_ok({"systemctl", "reset-failed", "dnsmasq"}, 20);

    // 3) 清理 nsswitch 中的 resolve 模块
    if (have_nss) {
        std::string cleaned = rewrite_nsswitch(nss);
        if (cleaned != nss) {
            std::string e;
            if (!util::write_file_atomic(kNss, cleaned, 0644, true, &e)) {
                logx::warn("更新 nsswitch.conf 失败: " + e);
            } else {
                logx::debug("已从 nsswitch.conf 移除 resolve 模块");
            }
        }
    }

    // 4) 重启 NM，让它 fork 自己的 dnsmasq
    util::ExecResult r = util::run({"systemctl", "restart", "NetworkManager"}, "", 90);
    if (!r.ok()) {
        if (err) *err = "NetworkManager 重启失败: " + util::trim(r.err);
        return false;
    }

    // 5) 等待 dnsmasq 接管 53（最多约 6 秒）
    std::string owner;
    for (int i = 0; i < 20; ++i) {
        owner = dnsblock::port53_owner();
        if (owner == "dnsmasq") break;
        sleep_ms(300);
    }
    if (owner != "dnsmasq") {
        if (err) {
            *err = "53/UDP 未被 dnsmasq 接管（当前占用者: " + owner +
                   "）。请检查 journalctl -u NetworkManager，或执行 sudo ban dns rollback";
        }
        return false;
    }

    // 6) 确认解析真的走 dnsmasq
    std::string ns;
    if (!resolv_points_local(&ns)) {
        logx::warn("resolv.conf 仍指向 " + (ns.empty() ? std::string("未知") : ns) +
                   "，强制改为本机 dnsmasq");
        force_resolv_local();
        ns.clear();
        if (!resolv_points_local(&ns)) {
            if (err) *err = "无法把 /etc/resolv.conf 指向 127.0.0.1";
            return false;
        }
    }
    logx::debug("resolv.conf -> " + ns);
    return true;
}

bool rollback(std::string* err) {
    (void)err;
    util::remove_file(kNmConf);

    // 还原 nsswitch
    std::string bak;
    if (util::path_exists(kNssBak) && util::read_file(kNssBak, bak)) {
        std::string e;
        if (!util::write_file_atomic(kNss, bak, 0644, true, &e)) {
            logx::warn("还原 nsswitch.conf 失败: " + e);
        }
    }

    // 还原 resolv.conf：原来是符号链接就恢复链接，否则恢复内容
    std::string link;
    if (util::path_exists(kResolvLinkBak) && util::read_file(kResolvLinkBak, link)) {
        ::unlink(kResolv);
        ::symlink(util::trim(link).c_str(), kResolv);
        util::remove_file(kResolvLinkBak);
    } else if (util::path_exists(kResolvBak) && util::read_file(kResolvBak, bak)) {
        ::unlink(kResolv);
        util::write_file_atomic(kResolv, bak, 0644, true, nullptr);
        util::remove_file(kResolvBak);
    }

    run_ok({"systemctl", "enable", "--now", kResolved}, 60);
    run_ok({"systemctl", "restart", "NetworkManager"}, 90);
    run_ok({"systemctl", "disable", "dnsmasq"}, 20);
    return true;
}

void print_status() {
    std::printf("systemd-resolved : %s / %s\n", unit_enabled(kResolved).c_str(),
                unit_state(kResolved).c_str());
    std::printf("dnsmasq          : %s / %s\n", unit_enabled("dnsmasq").c_str(),
                unit_state("dnsmasq").c_str());
    std::printf("NetworkManager   : %s\n", unit_state("NetworkManager").c_str());
    std::printf("NM dns=          : %s\n",
                util::path_exists(kNmConf) ? "dnsmasq（ban 接管配置已就位）" : "未设置");
    std::printf("53/UDP 占用      : %s\n", dnsblock::port53_owner().c_str());

    std::string nss;
    if (util::read_file(kNss, nss)) {
        for (const std::string& raw : util::split(nss, '\n', true)) {
            if (util::starts_with(util::trim(raw), "hosts:")) {
                std::printf("nsswitch hosts   : %s\n", util::trim(raw).c_str());
                break;
            }
        }
    }

    std::printf("resolv.conf      : ");
    char buf[4096] = {0};
    ssize_t n = ::readlink(kResolv, buf, sizeof(buf) - 1);
    if (n > 0) {
        std::printf("%s", buf);
    } else {
        std::printf("（普通文件）");
    }
    std::string ns;
    if (resolv_points_local(&ns)) {
        std::printf(" -> nameserver %s（本机 dnsmasq）\n", ns.c_str());
    } else {
        std::string text;
        if (util::read_file(kResolv, text)) {
            for (const std::string& raw : util::split(text, '\n', true)) {
                if (util::starts_with(util::trim(raw), "nameserver")) {
                    std::printf(" -> %s（未指向 dnsmasq！）\n", util::trim(raw).c_str());
                    break;
                }
            }
        } else {
            std::printf(" -> 无法读取\n");
        }
    }
}

}  // namespace takeover
