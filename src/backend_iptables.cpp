#include <sstream>
#include <string>
#include <vector>

#include "backend_impl.h"
#include "log.h"
#include "util.h"

namespace {

struct ProtoSpec {
    const char* ipt;      // iptables / ip6tables
    const char* chain_out;
    const char* chain_fwd;
    const char* set_ban;
    const char* set_allow;
    const char* family;   // inet / inet6
};

const ProtoSpec kV4 = {"iptables", "BAN_OUT", "BAN_FWD", "ban_v4", "ban_allow_v4", "inet"};
const ProtoSpec kV6 = {"ip6tables", "BAN_OUT6", "BAN_FWD6", "ban_v6", "ban_allow_v6", "inet6"};

util::ExecResult ipt_run(const std::string& prog, const std::vector<std::string>& args,
                         const std::string& stdin_data = std::string()) {
    std::vector<std::string> argv;
    argv.push_back(prog);
    argv.push_back("-w");
    argv.push_back("5");
    for (const std::string& a : args) argv.push_back(a);
    return util::run(argv, stdin_data, 30);
}

bool chain_exists(const std::string& prog, const std::string& chain) {
    return ipt_run(prog, {"-S", chain}).ok();
}

bool ensure_chain(const std::string& prog, const std::string& chain, std::string* err) {
    if (!chain_exists(prog, chain)) {
        util::ExecResult r = ipt_run(prog, {"-N", chain});
        if (!r.ok()) {
            if (err) *err = "创建链 " + chain + " 失败: " + util::trim(r.err);
            return false;
        }
    }
    util::ExecResult f = ipt_run(prog, {"-F", chain});
    if (!f.ok()) {
        if (err) *err = "清空链 " + chain + " 失败: " + util::trim(f.err);
        return false;
    }
    return true;
}

void ensure_jump(const std::string& prog, const std::string& parent, const std::string& chain) {
    util::ExecResult c = ipt_run(prog, {"-C", parent, "-j", chain});
    if (!c.ok()) {
        ipt_run(prog, {"-I", parent, "1", "-j", chain});
    }
}

std::string ipset_counter(const std::string& set_name) {
    util::ExecResult r = util::run({"ipset", "list", set_name, "-t"}, "", 10);
    if (!r.ok()) return std::string();
    for (const std::string& raw : util::split(r.out, '\n', true)) {
        std::string line = util::trim(raw);
        if (util::starts_with(line, "Number of entries:")) {
            return util::trim(line.substr(std::string("Number of entries:").size()));
        }
    }
    return std::string();
}

void parse_counters(const std::string& out, uint64_t& pkts, uint64_t& bytes) {
    for (const std::string& raw : util::split(out, '\n', true)) {
        std::string line = raw;
        if (line.find("REJECT") == std::string::npos && line.find(" DROP") == std::string::npos) {
            continue;
        }
        std::istringstream iss(line);
        uint64_t p = 0;
        uint64_t b = 0;
        if (iss >> p >> b) {
            pkts += p;
            bytes += b;
        }
    }
}

}  // namespace

void IptablesBackend::detect_ipset() {
    if (ipset_checked_) return;
    ipset_checked_ = true;
    util::ExecResult r = util::run({"ipset", "--version"}, "", 5);
    have_ipset_ = r.ok();
}

bool IptablesBackend::available(std::string* err) {
    util::ExecResult r = util::run({"iptables", "--version"}, "", 5);
    if (!r.ok()) {
        if (err) *err = "未找到 iptables";
        return false;
    }
    util::ExecResult r2 = ipt_run("iptables", {"-L", "-n"});
    if (!r2.ok()) {
        if (err) {
            *err = "iptables 需要 root 权限: " + util::trim(r2.err.empty() ? r2.out : r2.err);
        }
        return false;
    }
    detect_ipset();
    return true;
}

namespace {

bool apply_proto(const ProtoSpec& spec, const std::vector<BannedEntry>& banned,
                 const std::vector<std::string>& allow, const Config& cfg, bool enabled,
                 bool use_timeout, int64_t now, std::string* err) {
    const std::string prog = spec.ipt;

    if (!ensure_chain(prog, spec.chain_out, err)) return false;
    if (!ensure_chain(prog, spec.chain_fwd, err)) return false;

    const char* verdict = (cfg.action == "drop") ? "DROP" : "REJECT";

    // 白名单优先：RETURN 直接跳出本链
    for (const std::string& cidr : allow) {
        ipt_run(prog, {"-A", spec.chain_out, "-d", cidr, "-j", "RETURN"});
        ipt_run(prog, {"-A", spec.chain_fwd, "-d", cidr, "-j", "RETURN"});
    }

    if (enabled) {
        for (const BannedEntry& e : banned) {
            if (e.cidr.empty()) continue;
            if (e.expires_at > 0 && e.expires_at <= now) continue;
            ipt_run(prog, {"-A", spec.chain_out, "-d", e.cidr, "-j", verdict});
            ipt_run(prog, {"-A", spec.chain_fwd, "-d", e.cidr, "-j", verdict});
        }
    }

    // 挂到系统链上
    ensure_jump(prog, "OUTPUT", spec.chain_out);
    ensure_jump(prog, "FORWARD", spec.chain_fwd);

    (void)use_timeout;
    return true;
}

std::string build_ipset_script(const ProtoSpec& spec, const std::vector<BannedEntry>& banned,
                               const std::vector<std::string>& allow, bool with_timeout,
                               int64_t now) {
    std::ostringstream os;
    os << "create " << spec.set_allow << " hash:net family " << spec.family << " -exist\n";
    if (with_timeout) {
        os << "create " << spec.set_ban << " hash:net family " << spec.family << " timeout 0 -exist\n";
    } else {
        os << "create " << spec.set_ban << " hash:net family " << spec.family << " -exist\n";
    }
    os << "flush " << spec.set_allow << "\n";
    os << "flush " << spec.set_ban << "\n";

    for (const std::string& cidr : allow) {
        os << "add " << spec.set_allow << " " << cidr << "\n";
    }
    for (const BannedEntry& e : banned) {
        if (e.cidr.empty()) continue;
        int64_t left = 0;
        if (e.expires_at > 0) {
            left = e.expires_at - now;
            if (left <= 0) continue;
        }
        os << "add " << spec.set_ban << " " << e.cidr;
        if (with_timeout && left > 0) os << " timeout " << left;
        os << "\n";
    }
    return os.str();
}

bool apply_proto_ipset(const ProtoSpec& spec, const std::vector<BannedEntry>& banned,
                       const std::vector<std::string>& allow, const Config& cfg, bool enabled,
                       int64_t now, std::string* err) {
    const std::string prog = spec.ipt;

    if (!ensure_chain(prog, spec.chain_out, err)) return false;
    if (!ensure_chain(prog, spec.chain_fwd, err)) return false;

    bool restored = false;
    std::string last_err;
    for (int attempt = 0; attempt < 2 && !restored; ++attempt) {
        const bool with_timeout = (attempt == 0);
        std::string script = build_ipset_script(spec, banned, allow, with_timeout, now);
        util::ExecResult r = util::run({"ipset", "restore", "-exist"}, script, 30);
        if (r.ok()) {
            restored = true;
            if (!with_timeout) {
                logx::warn("ipset 不支持条目级 timeout，临时封禁依赖 `ban gc` 定时清理");
            }
        } else {
            last_err = util::trim(r.err.empty() ? r.out : r.err);
        }
    }
    if (!restored) {
        if (err) *err = "ipset restore 失败: " + last_err;
        return false;
    }

    ipt_run(prog, {"-A", spec.chain_out, "-m", "set", "--match-set", spec.set_allow, "dst", "-j",
                   "RETURN"});
    ipt_run(prog, {"-A", spec.chain_fwd, "-m", "set", "--match-set", spec.set_allow, "dst", "-j",
                   "RETURN"});

    if (enabled) {
        const char* verdict = (cfg.action == "drop") ? "DROP" : "REJECT";
        ipt_run(prog, {"-A", spec.chain_out, "-m", "set", "--match-set", spec.set_ban, "dst", "-j",
                       verdict});
        ipt_run(prog, {"-A", spec.chain_fwd, "-m", "set", "--match-set", spec.set_ban, "dst", "-j",
                       verdict});
    }

    ensure_jump(prog, "OUTPUT", spec.chain_out);
    ensure_jump(prog, "FORWARD", spec.chain_fwd);
    return true;
}

}  // namespace

bool IptablesBackend::apply(const FirewallInput& in, const Config& cfg, std::string* err) {
    detect_ipset();
    const int64_t now = util::now_epoch();

    std::string e1;
    std::string e2;
    bool ok = true;

    if (have_ipset_) {
        ok = apply_proto_ipset(kV4, in.banned_v4, in.allow_v4, cfg, in.enabled, now, &e1) && ok;
        ok = apply_proto_ipset(kV6, in.banned_v6, in.allow_v6, cfg, in.enabled, now, &e2) && ok;
    } else {
        if (in.banned_v4.size() + in.banned_v6.size() > 200) {
            logx::warn("未安装 ipset，将逐条写入 " +
                       std::to_string(in.banned_v4.size() + in.banned_v6.size()) +
                       " 条规则，建议安装 ipset 以提升性能");
        }
        ok = apply_proto(kV4, in.banned_v4, in.allow_v4, cfg, in.enabled, false, now, &e1) && ok;
        ok = apply_proto(kV6, in.banned_v6, in.allow_v6, cfg, in.enabled, false, now, &e2) && ok;
    }

    if (!ok && err) *err = !e1.empty() ? e1 : e2;
    return ok;
}

bool IptablesBackend::teardown(std::string* err) {
    (void)err;
    detect_ipset();

    const ProtoSpec* specs[2] = {&kV4, &kV6};

    for (const ProtoSpec* spec : specs) {
        const std::string prog = spec->ipt;
        ipt_run(prog, {"-D", "OUTPUT", "-j", spec->chain_out});
        ipt_run(prog, {"-D", "FORWARD", "-j", spec->chain_fwd});
        ipt_run(prog, {"-F", spec->chain_out});
        ipt_run(prog, {"-X", spec->chain_out});
        ipt_run(prog, {"-F", spec->chain_fwd});
        ipt_run(prog, {"-X", spec->chain_fwd});
        if (have_ipset_) {
            util::run({"ipset", "destroy", spec->set_ban}, "", 10);
            util::run({"ipset", "destroy", spec->set_allow}, "", 10);
        }
    }
    return true;
}

bool IptablesBackend::stats(FirewallStats& out, std::string* err) {
    out = FirewallStats();
    out.backend = "iptables";
    detect_ipset();
    out.detail = have_ipset_ ? "filter 表 + ipset" : "filter 表（逐条规则）";

    bool any = false;

    if (have_ipset_) {
        std::string n4 = ipset_counter(kV4.set_ban);
        std::string n6 = ipset_counter(kV6.set_ban);
        std::string a4 = ipset_counter(kV4.set_allow);
        std::string a6 = ipset_counter(kV6.set_allow);
        if (!n4.empty()) {
            out.banned_v4 = static_cast<size_t>(std::stoull(n4));
            any = true;
        }
        if (!n6.empty()) {
            out.banned_v6 = static_cast<size_t>(std::stoull(n6));
            any = true;
        }
        if (!a4.empty()) {
            out.allow_v4 = static_cast<size_t>(std::stoull(a4));
            any = true;
        }
        if (!a6.empty()) {
            out.allow_v6 = static_cast<size_t>(std::stoull(a6));
            any = true;
        }
    }

    for (const ProtoSpec* spec : {&kV4, &kV6}) {
        util::ExecResult r = ipt_run(spec->ipt, {"-L", spec->chain_out, "-v", "-n", "-x"});
        if (r.ok()) {
            any = true;
            parse_counters(r.out, out.packets, out.bytes);
        }
    }

    out.available = any;
    if (!any && err) *err = "iptables 规则尚未创建";
    return any;
}
