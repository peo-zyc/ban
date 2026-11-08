#include "commands.h"

#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "backend.h"
#include "backend_impl.h"
#include "config.h"
#include "dns.h"
#include "json.h"
#include "log.h"
#include "model.h"
#include "resolver.h"
#include "store.h"
#include "util.h"

namespace {

const char* kVersion = "1.0.0";
const char* kDefaultEtcDir = "/etc/ban";

enum ExitCode {
    kOk = 0,
    kErr = 1,
    kUsage = 2,
    kPerm = 3,
    kDep = 4,
    kPartial = 5,
};

struct Ctx {
    Config cfg;
    bool json = false;
    bool verbose = false;
    bool quiet = false;
};

struct Opts {
    std::vector<std::string> pos;
    std::map<std::string, std::string> val;
    std::set<std::string> flag;

    bool has(const std::string& k) const {
        return val.find(k) != val.end() || flag.find(k) != flag.end();
    }
    std::string get(const std::string& k, const std::string& def = std::string()) const {
        std::map<std::string, std::string>::const_iterator it = val.find(k);
        return it == val.end() ? def : it->second;
    }
};

const std::set<std::string>& value_opts() {
    static const std::set<std::string> s = {"for",     "comment", "type",  "format",
                                            "dns",     "backend", "action", "interval",
                                            "bindir",  "output",  "timeout"};
    return s;
}

bool parse_opts(const std::vector<std::string>& args, Opts& out, std::string& err) {
    bool literal = false;
    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (literal) {
            out.pos.push_back(a);
            continue;
        }
        if (a == "--") {
            literal = true;
            continue;
        }
        if (util::starts_with(a, "--")) {
            std::string body = a.substr(2);
            size_t eq = body.find('=');
            if (eq != std::string::npos) {
                out.val[body.substr(0, eq)] = body.substr(eq + 1);
                continue;
            }
            if (value_opts().count(body)) {
                if (i + 1 >= args.size()) {
                    err = "--" + body + " 需要一个参数";
                    return false;
                }
                out.val[body] = args[++i];
            } else {
                out.flag.insert(body);
            }
            continue;
        }
        if (a.size() > 1 && a[0] == '-' && a[1] != '-') {
            std::string body = a.substr(1);
            if (body == "y") {
                out.flag.insert("yes");
            } else if (body == "f") {
                out.flag.insert("force");
            } else if (body == "A") {
                out.flag.insert("all");
            } else {
                err = "未知选项: " + a;
                return false;
            }
            continue;
        }
        out.pos.push_back(a);
    }
    return true;
}

// ============================ 输出辅助 ============================

size_t disp_width(const std::string& s) {
    size_t w = 0;
    for (size_t i = 0; i < s.size();) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            w += 1;
            i += 1;
            continue;
        }
        unsigned int cp = 0;
        size_t len = 1;
        if ((c & 0xE0) == 0xC0) {
            cp = c & 0x1Fu;
            len = 2;
        } else if ((c & 0xF0) == 0xE0) {
            cp = c & 0x0Fu;
            len = 3;
        } else if ((c & 0xF8) == 0xF0) {
            cp = c & 0x07u;
            len = 4;
        } else {
            w += 1;
            i += 1;
            continue;
        }
        for (size_t k = 1; k < len && i + k < s.size(); ++k) {
            cp = (cp << 6) | static_cast<unsigned int>(static_cast<unsigned char>(s[i + k]) & 0x3F);
        }
        i += len;
        bool wide = (cp >= 0x1100 && cp <= 0x115F) || (cp >= 0x2E80 && cp <= 0xA4CF) ||
                    (cp >= 0xAC00 && cp <= 0xD7A3) || (cp >= 0xF900 && cp <= 0xFAFF) ||
                    (cp >= 0xFE30 && cp <= 0xFE6F) || (cp >= 0xFF00 && cp <= 0xFF60) ||
                    (cp >= 0xFFE0 && cp <= 0xFFE6);
        w += wide ? 2 : 1;
    }
    return w;
}

std::string pad(const std::string& s, size_t width) {
    size_t d = disp_width(s);
    if (d >= width) return s;
    return s + std::string(width - d, ' ');
}

std::string expires_text(const Rule& r, int64_t now) {
    if (r.expires_at <= 0) return "permanent";
    if (r.expires_at <= now) return "expired";
    return "in " + util::format_duration(r.expires_at - now);
}

bool require_root() {
    if (util::is_root()) return true;
    std::fprintf(stderr, "错误: 需要 root 权限，请使用 sudo 运行。\n");
    return false;
}

std::string read_stdin() {
    std::string out;
    char buf[8192];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), stdin)) > 0) out.append(buf, n);
    return out;
}

// ============================ 会话 ============================

struct Session {
    StoreLock lock;
    Store store;

    explicit Session(const Config& cfg) : store(cfg) {}

    bool begin(const Config& cfg, std::string* err) {
        if (!lock.acquire(cfg.lock_file, err)) return false;
        return store.load(err);
    }
};

bool apply_all(Ctx& ctx, Store& st, bool include_dns, std::string* err) {
    const int64_t now = util::now_epoch();

    std::unique_ptr<FirewallBackend> backend = make_backend(ctx.cfg, err);
    if (!backend) return false;

    FirewallInput in;
    st.collect_banned(in.banned_v4, in.banned_v6, ctx.cfg.ipv6, now);
    st.collect_allow(in.allow_v4, in.allow_v6);
    in.enabled = ctx.cfg.enabled;

    if (!backend->apply(in, ctx.cfg, err)) return false;

    if (include_dns) {
        std::vector<std::string> domains;
        if (ctx.cfg.enabled && ctx.cfg.dns_enabled) domains = st.active_domains(now);
        std::string derr;
        if (!dnsblock::apply(ctx.cfg, domains, &derr)) {
            logx::warn("DNS 层应用失败: " + derr);
        }
    }
    return true;
}

bool resolve_into_cache(Store& st, const std::string& domain) {
    DnsAnswer a = dns_resolve(domain, 2500);
    ResolveCacheEntry& ce = st.cache[domain];

    if (a.ok) {
        ce.v4 = a.v4;
        ce.v6 = a.v6;
        ce.resolved_at = util::now_epoch();
        ce.error.clear();
        if (ce.v4.empty() && ce.v6.empty()) {
            ce.error = "解析结果为空";
            logx::debug("域名 " + domain + " 未解析到任何地址");
        } else {
            logx::debug("解析 " + domain + " -> " + std::to_string(ce.v4.size()) + " IPv4 / " +
                        std::to_string(ce.v6.size()) + " IPv6");
        }
        return true;
    }

    if (ce.v4.empty() && ce.v6.empty()) ce.error = a.error;
    logx::warn("解析 " + domain + " 失败（保留旧结果）: " + a.error);
    return false;
}

bool classify_target(const std::string& raw, const std::string& hint, RuleType& type,
                     std::string& value, std::string& err) {
    std::string s = util::trim(raw);
    if (s.empty()) {
        err = "目标为空";
        return false;
    }

    const std::string want = util::to_lower(hint.empty() ? "auto" : hint);

    if (want == "auto") {
        std::string canon;
        bool v6 = false;
        if (util::parse_cidr(s, canon, v6)) {
            type = RuleType::Cidr;
            value = canon;
            return true;
        }
        if (util::is_ip_literal(s)) {
            type = RuleType::Ip;
            value = util::normalize_ip(s);
            return true;
        }
        std::string d = util::normalize_domain(s);
        if (!d.empty()) {
            type = RuleType::Domain;
            value = d;
            return true;
        }
        err = "无法识别的目标: " + s + "（应为域名 / IP / CIDR）";
        return false;
    }

    if (want == "domain") {
        std::string d = util::normalize_domain(s);
        if (d.empty()) {
            err = "非法域名: " + s;
            return false;
        }
        type = RuleType::Domain;
        value = d;
        return true;
    }

    if (want == "ip") {
        bool v6 = false;
        if (!util::parse_ip(s, v6)) {
            err = "非法 IP: " + s;
            return false;
        }
        type = RuleType::Ip;
        value = util::normalize_ip(s);
        return true;
    }

    if (want == "cidr") {
        bool v6 = false;
        if (util::parse_ip(s, v6)) {
            type = RuleType::Cidr;
            value = util::normalize_ip(s) + (v6 ? "/128" : "/32");
            return true;
        }
        std::string canon;
        if (!util::parse_cidr(s, canon, v6)) {
            err = "非法 CIDR: " + s;
            return false;
        }
        type = RuleType::Cidr;
        value = canon;
        return true;
    }

    err = "无效的 --type 值: " + hint + "（可选 auto/domain/ip/cidr）";
    return false;
}

// ============================ add / del ============================

int cmd_add(Ctx& ctx, const Opts& o) {
    if (!require_root()) return kPerm;
    if (o.pos.empty()) {
        std::fprintf(stderr, "用法: ban add <域名|IP|CIDR>... [--for 30m] [--comment 文本]\n");
        return kUsage;
    }

    int64_t ttl = 0;
    if (o.has("for")) {
        if (!util::parse_duration(o.get("for"), ttl)) {
            std::fprintf(stderr, "错误: 无法解析时间长度 '%s'（示例: 30s 15m 2h 7d 1w）\n",
                         o.get("for").c_str());
            return kUsage;
        }
    }
    const int64_t expires_at = ttl > 0 ? util::now_epoch() + ttl : 0;
    const std::string comment = o.get("comment");
    const std::string type_hint = o.get("type", "auto");
    const bool no_dns = o.has("no-dns");

    Session s(ctx.cfg);
    std::string err;
    if (!s.begin(ctx.cfg, &err)) {
        logx::error(err);
        return kErr;
    }

    int added = 0, updated = 0, failed = 0;
    std::vector<std::string> newly_resolved;

    for (const std::string& raw : o.pos) {
        RuleType type = RuleType::Ip;
        std::string value;
        if (!classify_target(raw, type_hint, type, value, err)) {
            logx::error(err);
            ++failed;
            continue;
        }

        Rule* existing = s.store.find_by_value(value);
        if (existing) {
            existing->expires_at = expires_at;
            if (!comment.empty()) existing->comment = comment;
            ++updated;
            if (type == RuleType::Domain && !no_dns) newly_resolved.push_back(value);
            continue;
        }

        s.store.add_rule(type, value, expires_at, comment);
        ++added;
        if (type == RuleType::Domain && !no_dns) newly_resolved.push_back(value);
    }

    if (added == 0 && updated == 0) return failed ? kErr : kOk;

    for (const std::string& d : newly_resolved) resolve_into_cache(s.store, d);

    if (!s.store.save(&err)) {
        logx::error(err);
        return kErr;
    }
    if (!s.store.save_cache(&err)) logx::warn(err);

    if (!apply_all(ctx, s.store, true, &err)) {
        logx::error("下发规则失败: " + err);
        return kPartial;
    }

    if (!ctx.quiet) {
        if (added) logx::info("已添加 " + std::to_string(added) + " 条规则");
        if (updated) logx::info("已更新 " + std::to_string(updated) + " 条规则");
        if (failed) logx::warn(std::to_string(failed) + " 个目标被跳过");
    }
    return failed ? kPartial : kOk;
}

int cmd_del(Ctx& ctx, const Opts& o) {
    if (!require_root()) return kPerm;
    if (o.pos.empty()) {
        std::fprintf(stderr, "用法: ban del <ID|域名|IP|CIDR>...\n");
        return kUsage;
    }

    Session s(ctx.cfg);
    std::string err;
    if (!s.begin(ctx.cfg, &err)) {
        logx::error(err);
        return kErr;
    }

    int removed = 0, missing = 0;
    for (const std::string& raw : o.pos) {
        const std::string sarg = util::trim(raw);
        if (sarg.empty()) continue;

        uint64_t as_id = 0;
        if (util::parse_u64(sarg, as_id)) {
            if (s.store.remove_by_id(static_cast<int64_t>(as_id))) {
                ++removed;
                continue;
            }
        }

        RuleType type = RuleType::Ip;
        std::string value;
        std::string cerr;
        if (classify_target(sarg, "auto", type, value, cerr)) {
            Rule* r = s.store.find_by_value(value);
            if (r) {
                s.store.remove_by_id(r->id);
                ++removed;
                continue;
            }
        }

        logx::warn("未找到规则: " + sarg);
        ++missing;
    }

    if (removed == 0) return missing ? kErr : kOk;

    if (!s.store.save(&err)) {
        logx::error(err);
        return kErr;
    }
    if (!apply_all(ctx, s.store, true, &err)) {
        logx::error("下发规则失败: " + err);
        return kPartial;
    }

    if (!ctx.quiet) logx::info("已删除 " + std::to_string(removed) + " 条规则");
    return missing ? kPartial : kOk;
}

// ============================ list ============================

int cmd_list(Ctx& ctx, const Opts& o) {
    Store st(ctx.cfg);
    std::string err;
    st.load(&err);
    st.load_cache();
    if (!err.empty()) logx::warn(err);

    const int64_t now = util::now_epoch();
    const bool show_expired = o.has("expired");
    const std::string type_filter = util::to_lower(o.get("type"));

    std::vector<const Rule*> rows;
    for (const Rule& r : st.rules) {
        if (!show_expired && r.is_expired(now)) continue;
        if (!type_filter.empty() && type_filter != "all" &&
            type_filter != rule_type_name(r.type)) {
            continue;
        }
        rows.push_back(&r);
    }

    if (ctx.json) {
        Json arr = Json::array();
        for (const Rule* r : rows) {
            Json j = Json::object();
            j.set("id", Json::integer(r->id));
            j.set("type", Json::string(rule_type_name(r->type)));
            j.set("value", Json::string(r->value));
            j.set("created_at", Json::integer(r->created_at));
            j.set("expires_at", Json::integer(r->expires_at));
            j.set("expired", Json::boolean(r->is_expired(now)));
            j.set("comment", Json::string(r->comment));
            arr.push(j);
        }
        Json root = Json::object();
        root.set("count", Json::integer(static_cast<int64_t>(rows.size())));
        root.set("rules", arr);
        std::printf("%s\n", root.dump(2).c_str());
        return kOk;
    }

    if (rows.empty()) {
        std::printf("（没有规则）\n");
        return kOk;
    }

    std::printf("%s %s %s %s %s\n", pad("ID", 5).c_str(), pad("TYPE", 7).c_str(),
                pad("TARGET", 34).c_str(), pad("EXPIRES", 14).c_str(), "COMMENT");
    std::printf("%s %s %s %s %s\n", pad("-----", 5).c_str(), pad("------", 7).c_str(),
                pad("----------------------------------", 34).c_str(),
                pad("--------------", 14).c_str(), "-------");
    for (const Rule* r : rows) {
        std::printf("%s %s %s %s %s\n", pad(std::to_string(r->id), 5).c_str(),
                    pad(rule_type_name(r->type), 7).c_str(), pad(r->value, 34).c_str(),
                    pad(expires_text(*r, now), 14).c_str(), r->comment.c_str());
    }
    std::printf("\n共 %zu 条", rows.size());
    if (!show_expired) {
        size_t nexp = st.count_expired(now);
        if (nexp > 0) std::printf("（另有 %zu 条已过期，用 --expired 查看）", nexp);
    }
    std::printf("\n");
    return kOk;
}

// ============================ status ============================

std::string timer_state() {
    util::ExecResult r = util::run({"systemctl", "is-active", "ban-refresh.timer"}, "", 8);
    std::string s = util::trim(r.out);
    return s.empty() ? "unknown" : s;
}

int cmd_status(Ctx& ctx, const Opts& o) {
    (void)o;
    Store st(ctx.cfg);
    st.load();
    st.load_cache();

    const int64_t now = util::now_epoch();
    const size_t active = st.count_active(now);
    const size_t expired = st.count_expired(now);

    size_t n_domain = 0, n_ip = 0, n_cidr = 0;
    for (const Rule& r : st.rules) {
        if (r.is_expired(now)) continue;
        if (r.type == RuleType::Domain) ++n_domain;
        else if (r.type == RuleType::Ip) ++n_ip;
        else ++n_cidr;
    }

    FirewallStats fw;
    std::string ferr;
    std::unique_ptr<FirewallBackend> backend = make_backend(ctx.cfg, &ferr);
    if (backend) backend->stats(fw, &ferr);

    dnsblock::Info di = dnsblock::describe(ctx.cfg);

    if (ctx.json) {
        Json root = Json::object();
        root.set("version", Json::string(kVersion));
        root.set("enabled", Json::boolean(ctx.cfg.enabled));
        root.set("backend", Json::string(backend ? backend->name() : "none"));
        root.set("backend_available", Json::boolean(fw.available));
        root.set("backend_detail", Json::string(fw.detail));
        root.set("rules_active", Json::integer(static_cast<int64_t>(active)));
        root.set("rules_expired", Json::integer(static_cast<int64_t>(expired)));
        root.set("domains", Json::integer(static_cast<int64_t>(n_domain)));
        root.set("ip_rules", Json::integer(static_cast<int64_t>(n_ip)));
        root.set("cidr_rules", Json::integer(static_cast<int64_t>(n_cidr)));
        root.set("whitelist", Json::integer(static_cast<int64_t>(st.allow.size())));
        root.set("fw_banned_v4", Json::integer(static_cast<int64_t>(fw.banned_v4)));
        root.set("fw_banned_v6", Json::integer(static_cast<int64_t>(fw.banned_v6)));
        root.set("fw_packets", Json::uinteger(fw.packets));
        root.set("fw_bytes", Json::uinteger(fw.bytes));
        root.set("dns_mode", Json::string(di.mode));
        root.set("dns_path", Json::string(di.path));
        root.set("timer", Json::string(timer_state()));
        std::printf("%s\n", root.dump(2).c_str());
        return kOk;
    }

    std::printf("ban %s\n", kVersion);
    std::printf("状态        : %s\n", ctx.cfg.enabled ? "启用" : "已停用");
    std::printf("防火墙后端  : %s%s\n", backend ? backend->name() : "不可用",
                fw.available ? "" : "（规则未创建）");
    if (!fw.detail.empty()) std::printf("  详情      : %s\n", fw.detail.c_str());
    std::printf("规则        : %zu 生效", active);
    if (expired) std::printf("，%zu 已过期", expired);
    std::printf("（域名 %zu / IP %zu / CIDR %zu）\n", n_domain, n_ip, n_cidr);
    std::printf("白名单      : %zu 条\n", st.allow.size());
    std::printf("集合条目    : IPv4 %zu / IPv6 %zu\n", fw.banned_v4, fw.banned_v6);
    std::printf("已拦截流量  : %s 数据包 / %s\n", util::human_number(fw.packets).c_str(),
                util::human_bytes(fw.bytes).c_str());
    std::printf("DNS 层      : %s\n", di.detail.c_str());
    if (!di.path.empty()) std::printf("  文件      : %s\n", di.path.c_str());
    std::printf("定时刷新    : ban-refresh.timer = %s\n", timer_state().c_str());
    if (!ferr.empty() && !fw.available) std::printf("  提示      : %s\n", ferr.c_str());
    return kOk;
}

// ============================ refresh / gc ============================

int cmd_refresh(Ctx& ctx, const Opts& o) {
    if (!require_root()) return kPerm;

    Session s(ctx.cfg);
    std::string err;
    if (!s.begin(ctx.cfg, &err)) {
        logx::error(err);
        return kErr;
    }

    const int64_t now = util::now_epoch();
    std::vector<std::string> domains = s.store.active_domains(now);
    if (domains.empty()) {
        if (!ctx.quiet) logx::info("没有域名规则，无需刷新");
        return kOk;
    }

    int okn = 0, failn = 0;
    for (const std::string& d : domains) {
        if (resolve_into_cache(s.store, d)) ++okn;
        else ++failn;
    }

    s.store.prune_expired(now);

    if (!s.store.save(&err)) logx::error(err);
    if (!s.store.save_cache(&err)) logx::warn(err);

    if (!apply_all(ctx, s.store, true, &err)) {
        logx::error("下发规则失败: " + err);
        return kPartial;
    }

    if (!ctx.quiet) {
        logx::info("刷新完成: " + std::to_string(okn) + " 个域名成功" +
                   (failn ? "，" + std::to_string(failn) + " 个失败（保留旧结果）" : std::string()));
    }
    (void)o;
    return failn ? kPartial : kOk;
}

int cmd_gc(Ctx& ctx, const Opts& o) {
    if (!require_root()) return kPerm;

    Session s(ctx.cfg);
    std::string err;
    if (!s.begin(ctx.cfg, &err)) {
        logx::error(err);
        return kErr;
    }

    const int64_t now = util::now_epoch();
    size_t n = s.store.prune_expired(now);
    if (n == 0) {
        logx::debug("没有需要清理的过期规则");
        return kOk;
    }

    if (!s.store.save(&err)) {
        logx::error(err);
        return kErr;
    }
    if (!apply_all(ctx, s.store, true, &err)) {
        logx::error("下发规则失败: " + err);
        return kPartial;
    }
    if (!ctx.quiet) logx::info("已清理 " + std::to_string(n) + " 条过期规则");
    (void)o;
    return kOk;
}

// ============================ allow ============================

int cmd_allow(Ctx& ctx, const Opts& o) {
    const std::string sub = o.pos.empty() ? std::string("list") : util::to_lower(o.pos[0]);

    if (sub == "list" || sub == "ls") {
        Store st(ctx.cfg);
        st.load();
        if (ctx.json) {
            Json arr = Json::array();
            for (const AllowEntry& a : st.allow) {
                Json j = Json::object();
                j.set("cidr", Json::string(a.cidr));
                j.set("comment", Json::string(a.comment));
                arr.push(j);
            }
            Json root = Json::object();
            root.set("count", Json::integer(static_cast<int64_t>(st.allow.size())));
            root.set("whitelist", arr);
            std::printf("%s\n", root.dump(2).c_str());
            return kOk;
        }
        std::printf("%s %s\n", pad("CIDR", 26).c_str(), "COMMENT");
        for (const AllowEntry& a : st.allow) {
            std::printf("%s %s\n", pad(a.cidr, 26).c_str(), a.comment.c_str());
        }
        if (st.allow.empty()) std::printf("（白名单为空）\n");
        return kOk;
    }

    if (!require_root()) return kPerm;

    if (sub == "add" || sub == "del" || sub == "remove") {
        if (o.pos.size() < 2) {
            std::fprintf(stderr, "用法: ban allow %s <CIDR>... [--comment 文本]\n", sub.c_str());
            return kUsage;
        }

        Session s(ctx.cfg);
        std::string err;
        if (!s.begin(ctx.cfg, &err)) {
            logx::error(err);
            return kErr;
        }

        int changed = 0;
        for (size_t i = 1; i < o.pos.size(); ++i) {
            std::string input = util::trim(o.pos[i]);
            bool v6 = false;
            std::string canon;
            if (!util::parse_cidr(input, canon, v6)) {
                if (util::parse_ip(input, v6)) {
                    canon = util::normalize_ip(input) + (v6 ? "/128" : "/32");
                } else {
                    logx::error("非法 CIDR/IP: " + input);
                    continue;
                }
            }

            if (sub == "add") {
                bool exists = false;
                for (const AllowEntry& a : s.store.allow) {
                    if (a.cidr == canon) {
                        exists = true;
                        break;
                    }
                }
                if (exists) {
                    logx::debug("白名单已存在: " + canon);
                    continue;
                }
                AllowEntry a;
                a.cidr = canon;
                a.comment = o.get("comment");
                s.store.allow.push_back(a);
                ++changed;
            } else {
                for (size_t k = 0; k < s.store.allow.size(); ++k) {
                    if (s.store.allow[k].cidr == canon) {
                        s.store.allow.erase(s.store.allow.begin() + static_cast<long>(k));
                        ++changed;
                        break;
                    }
                }
            }
        }

        if (changed == 0) {
            if (!ctx.quiet) logx::info("白名单无变化");
            return kOk;
        }

        if (!s.store.save(&err)) {
            logx::error(err);
            return kErr;
        }
        if (!apply_all(ctx, s.store, false, &err)) {
            logx::error("下发规则失败: " + err);
            return kPartial;
        }
        if (!ctx.quiet) {
            logx::info(std::string(sub == "add" ? "已添加 " : "已移除 ") + std::to_string(changed) +
                       " 条白名单");
        }
        return kOk;
    }

    std::fprintf(stderr, "用法: ban allow <add|del|list> ...\n");
    return kUsage;
}

// ============================ enable / disable / flush ============================

int cmd_toggle(Ctx& ctx, bool enable) {
    if (!require_root()) return kPerm;

    ctx.cfg.enabled = enable;
    std::string err;
    if (!ctx.cfg.save(&err)) {
        logx::error("保存配置失败: " + err);
        return kErr;
    }

    Session s(ctx.cfg);
    if (!s.begin(ctx.cfg, &err)) {
        logx::error(err);
        return kErr;
    }

    if (!apply_all(ctx, s.store, true, &err)) {
        logx::error("下发规则失败: " + err);
        return kPartial;
    }

    if (!ctx.quiet) logx::info(enable ? "封禁已启用" : "封禁已停用（规则保留，未生效）");
    return kOk;
}

int cmd_flush(Ctx& ctx, const Opts& o) {
    if (!require_root()) return kPerm;

    Session s(ctx.cfg);
    std::string err;
    if (!s.begin(ctx.cfg, &err)) {
        logx::error(err);
        return kErr;
    }

    const size_t removed = s.store.rules.size();
    s.store.rules.clear();
    s.store.cache.clear();
    if (o.has("all")) s.store.allow.clear();

    if (!s.store.save(&err)) {
        logx::error(err);
        return kErr;
    }
    if (!s.store.save_cache(&err)) logx::warn(err);

    std::unique_ptr<FirewallBackend> backend = make_backend(ctx.cfg, &err);
    if (backend) {
        std::string terr;
        if (!backend->teardown(&terr)) logx::warn("清理防火墙规则: " + terr);
    } else {
        logx::warn(std::string("未清理防火墙规则: ") + err);
    }

    std::string derr;
    if (!dnsblock::teardown(ctx.cfg, &derr)) logx::warn("清理 DNS 阻断: " + derr);

    if (!ctx.quiet) {
        logx::info("已清空 " + std::to_string(removed) + " 条规则" +
                   (o.has("all") ? "，并重置白名单" : ""));
    }
    return kOk;
}

// ============================ export / import ============================

std::string export_json(Store& st) {
    Json root = Json::object();
    root.set("version", Json::integer(1));
    root.set("tool", Json::string("ban"));
    root.set("generated_at", Json::integer(util::now_epoch()));

    Json rules = Json::array();
    for (const Rule& r : st.rules) {
        Json j = Json::object();
        j.set("id", Json::integer(r.id));
        j.set("type", Json::string(rule_type_name(r.type)));
        j.set("value", Json::string(r.value));
        j.set("created_at", Json::integer(r.created_at));
        j.set("expires_at", Json::integer(r.expires_at));
        j.set("comment", Json::string(r.comment));
        rules.push(j);
    }
    root.set("rules", rules);

    Json allow = Json::array();
    for (const AllowEntry& a : st.allow) {
        Json j = Json::object();
        j.set("cidr", Json::string(a.cidr));
        j.set("comment", Json::string(a.comment));
        allow.push(j);
    }
    root.set("allow", allow);

    Json cache = Json::array();
    for (std::map<std::string, ResolveCacheEntry>::const_iterator it = st.cache.begin();
         it != st.cache.end(); ++it) {
        Json j = Json::object();
        j.set("name", Json::string(it->first));
        Json v4 = Json::array();
        for (const std::string& ip : it->second.v4) v4.push(Json::string(ip));
        Json v6 = Json::array();
        for (const std::string& ip : it->second.v6) v6.push(Json::string(ip));
        j.set("v4", v4);
        j.set("v6", v6);
        j.set("resolved_at", Json::integer(it->second.resolved_at));
        cache.push(j);
    }
    root.set("cache", cache);

    return root.dump(2);
}

std::string export_text(Store& st) {
    std::string out = "# ban export v1\n# --- rules ---\n";
    for (const Rule& r : st.rules) out += r.serialize() + "\n";
    out += "# --- allow ---\n";
    for (const AllowEntry& a : st.allow) out += a.serialize() + "\n";
    return out;
}

int cmd_export(Ctx& ctx, const Opts& o) {
    Store st(ctx.cfg);
    st.load();
    st.load_cache();

    const std::string format = util::to_lower(o.get("format", "json"));
    std::string data;
    if (format == "text" || format == "conf") {
        data = export_text(st);
    } else if (format == "json") {
        data = export_json(st) + "\n";
    } else {
        std::fprintf(stderr, "错误: 未知格式 '%s'（可选 json/text）\n", format.c_str());
        return kUsage;
    }

    const std::string out_path = o.get("output", o.pos.empty() ? std::string() : o.pos[0]);
    if (out_path.empty() || out_path == "-") {
        std::fwrite(data.data(), 1, data.size(), stdout);
        return kOk;
    }

    std::string err;
    if (!util::write_file_atomic(out_path, data, 0600, false, &err)) {
        logx::error(err);
        return kErr;
    }
    if (!ctx.quiet) logx::info("已导出到 " + out_path);
    return kOk;
}

bool import_json_text(Ctx& ctx, const std::string& text, bool replace, std::string* err) {
    Json root;
    std::string perr;
    if (!Json::parse(text, root, &perr)) {
        *err = "解析 JSON 失败: " + perr;
        return false;
    }

    Session s(ctx.cfg);
    if (!s.begin(ctx.cfg, err)) return false;

    if (replace) {
        s.store.rules.clear();
        s.store.allow.clear();
        s.store.cache.clear();
    }

    std::vector<std::string> to_resolve;

    if (const Json* rules = root.find("rules")) {
        if (rules->is_array()) {
            for (size_t i = 0; i < rules->size(); ++i) {
                const Json& j = rules->at(i);
                const Json* type = j.find("type");
                const Json* value = j.find("value");
                if (!type || !value) continue;

                RuleType rt = RuleType::Ip;
                if (!rule_type_from_name(type->as_string(), rt)) continue;

                std::string v;
                std::string cerr;
                if (!classify_target(value->as_string(), rule_type_name(rt), rt, v, cerr)) {
                    logx::warn("跳过无效条目: " + value->as_string());
                    continue;
                }

                int64_t exp = 0;
                if (const Json* e = j.find("expires_at")) exp = e->as_int(0);
                std::string comment;
                if (const Json* c = j.find("comment")) comment = c->as_string();

                if (s.store.find_by_value(v)) continue;
                s.store.add_rule(rt, v, exp, comment);
                if (rt == RuleType::Domain) to_resolve.push_back(v);
            }
        }
    }

    if (const Json* allow = root.find("allow")) {
        if (allow->is_array()) {
            for (size_t i = 0; i < allow->size(); ++i) {
                const Json* cidr = allow->at(i).find("cidr");
                if (!cidr) continue;
                std::string canon;
                bool v6 = false;
                if (!util::parse_cidr(cidr->as_string(), canon, v6)) continue;
                bool exists = false;
                for (const AllowEntry& a : s.store.allow) {
                    if (a.cidr == canon) {
                        exists = true;
                        break;
                    }
                }
                if (exists) continue;
                AllowEntry a;
                a.cidr = canon;
                if (const Json* c = allow->at(i).find("comment")) a.comment = c->as_string();
                s.store.allow.push_back(a);
            }
        }
    }

    if (const Json* cache = root.find("cache")) {
        if (cache->is_array()) {
            for (size_t i = 0; i < cache->size(); ++i) {
                const Json& j = cache->at(i);
                const Json* name = j.find("name");
                if (!name) continue;
                ResolveCacheEntry ce;
                if (const Json* v4 = j.find("v4")) {
                    for (size_t k = 0; k < v4->size(); ++k) ce.v4.push_back(v4->at(k).as_string());
                }
                if (const Json* v6 = j.find("v6")) {
                    for (size_t k = 0; k < v6->size(); ++k) ce.v6.push_back(v6->at(k).as_string());
                }
                if (const Json* at = j.find("resolved_at")) ce.resolved_at = at->as_int(0);
                s.store.cache[name->as_string()] = ce;
            }
        }
    }

    for (const std::string& d : to_resolve) resolve_into_cache(s.store, d);

    if (!s.store.save(err)) return false;
    if (!s.store.save_cache(err)) logx::warn(*err);

    if (!apply_all(ctx, s.store, true, err)) return false;
    return true;
}

bool import_text_format(Ctx& ctx, const std::string& text, bool replace, std::string* err) {
    Session s(ctx.cfg);
    if (!s.begin(ctx.cfg, err)) return false;

    if (replace) {
        s.store.rules.clear();
        s.store.allow.clear();
        s.store.cache.clear();
    }

    enum Section { Rules, Allow } section = Rules;
    std::vector<std::string> domains;

    for (const std::string& raw : util::split(text, '\n', true)) {
        std::string line = util::rtrim(raw);
        if (line.empty()) continue;
        if (line[0] == '#') {
            if (line.find("--- allow ---") != std::string::npos) section = Allow;
            else if (line.find("--- rules ---") != std::string::npos) section = Rules;
            continue;
        }

        if (section == Allow) {
            AllowEntry a;
            if (!AllowEntry::deserialize(line, a)) continue;
            bool exists = false;
            for (const AllowEntry& x : s.store.allow) {
                if (x.cidr == a.cidr) {
                    exists = true;
                    break;
                }
            }
            if (!exists) s.store.allow.push_back(a);
            continue;
        }

        Rule r;
        if (!Rule::deserialize(line, r)) {
            logx::warn("跳过无法解析的行: " + line);
            continue;
        }
        if (s.store.find_by_value(r.value)) continue;
        s.store.add_rule(r.type, r.value, r.expires_at, r.comment);
        if (r.type == RuleType::Domain) domains.push_back(r.value);
    }

    for (const std::string& d : domains) resolve_into_cache(s.store, d);

    if (!s.store.save(err)) return false;
    if (!s.store.save_cache(err)) logx::warn(*err);
    if (!apply_all(ctx, s.store, true, err)) return false;
    return true;
}

int cmd_import(Ctx& ctx, const Opts& o) {
    if (!require_root()) return kPerm;

    std::string text;
    if (o.pos.empty() || o.pos[0] == "-") {
        text = read_stdin();
    } else {
        if (!util::read_file(o.pos[0], text)) {
            logx::error("无法读取 " + o.pos[0]);
            return kErr;
        }
    }
    if (util::trim(text).empty()) {
        logx::error("输入为空");
        return kUsage;
    }

    const bool replace = o.has("replace");

    size_t i = 0;
    while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) ++i;
    const bool is_json = i < text.size() && text[i] == '{';

    std::string err;
    bool ok = is_json ? import_json_text(ctx, text, replace, &err)
                      : import_text_format(ctx, text, replace, &err);
    if (!ok) {
        logx::error("导入失败: " + err);
        return kErr;
    }
    if (!ctx.quiet) logx::info("导入完成");
    return kOk;
}

// ============================ systemd / install ============================

bool systemd_available() {
    return util::is_directory("/run/systemd/system") && util::path_exists("/bin/systemctl");
}

std::string unit_restore(const std::string& bin, const std::string& state_file,
                         const std::string& etc_dir) {
    std::ostringstream os;
    os << "[Unit]\n"
       << "Description=ban: restore blocked domain/IP rules at boot\n"
       << "Documentation=man:ban(1)\n"
       << "ConditionPathExists=" << state_file << "\n"
       << "After=local-fs.target\n"
       << "Before=network-pre.target\n"
       << "Wants=network-pre.target\n"
       << "\n[Service]\n"
       << "Type=oneshot\n"
       << "RemainAfterExit=yes\n"
       << "Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
       << "ExecStart=" << bin << " --etc-dir " << etc_dir << " restore --quiet\n"
       << "ProtectSystem=strict\n"
       << "ProtectHome=yes\n"
       << "PrivateTmp=yes\n"
       << "NoNewPrivileges=yes\n"
       << "ReadWritePaths=" << etc_dir << " /etc/hosts /etc/dnsmasq.d /var/log\n"
       << "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\n"
       << "\n[Install]\n"
       << "WantedBy=multi-user.target\n";
    return os.str();
}

std::string unit_refresh(const std::string& bin, const std::string& state_file,
                         const std::string& etc_dir) {
    std::ostringstream os;
    os << "[Unit]\n"
       << "Description=ban: refresh domain IP mappings and expire old rules\n"
       << "ConditionPathExists=" << state_file << "\n"
       << "After=network-online.target\n"
       << "Wants=network-online.target\n"
       << "\n[Service]\n"
       << "Type=oneshot\n"
       << "Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
       << "ExecStart=" << bin << " --etc-dir " << etc_dir << " refresh --quiet\n"
       << "ExecStart=" << bin << " --etc-dir " << etc_dir << " gc --quiet\n"
       << "ProtectSystem=strict\n"
       << "ProtectHome=yes\n"
       << "PrivateTmp=yes\n"
       << "NoNewPrivileges=yes\n"
       << "ReadWritePaths=" << etc_dir << " /etc/hosts /etc/dnsmasq.d /var/log\n"
       << "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\n";
    return os.str();
}

std::string unit_timer(int interval_min) {
    int m = interval_min > 0 ? interval_min : 10;
    std::ostringstream os;
    os << "[Unit]\n"
       << "Description=ban: periodic refresh timer\n"
       << "\n[Timer]\n"
       << "OnBootSec=90s\n"
       << "OnUnitActiveSec=" << m << "min\n"
       << "RandomizedDelaySec=30s\n"
       << "AccuracySec=15s\n"
       << "Persistent=true\n"
       << "Unit=ban-refresh.service\n"
       << "\n[Install]\n"
       << "WantedBy=timers.target\n";
    return os.str();
}

int cmd_install(Ctx& ctx, const Opts& o) {
    if (!require_root()) return kPerm;

    if (o.has("bindir")) ctx.cfg.bindir = o.get("bindir");
    if (o.has("backend")) ctx.cfg.backend = util::to_lower(o.get("backend"));
    if (o.has("action")) ctx.cfg.action = util::to_lower(o.get("action"));
    if (o.has("interval")) {
        int n = std::atoi(o.get("interval").c_str());
        if (n > 0) ctx.cfg.refresh_interval_min = n;
    }

    std::string err;
    std::string mkerr;
    if (!util::make_dirs(ctx.cfg.etc_dir, 0755, &mkerr)) {
        logx::error(mkerr);
        return kErr;
    }

    if (!util::path_exists(ctx.cfg.conf_file)) {
        if (!ctx.cfg.save(&err)) {
            logx::error("写入配置失败: " + err);
            return kErr;
        }
    }

    // 安装二进制自身
    const std::string target_bin = ctx.cfg.bindir + "/ban";
    const std::string self = util::self_exe_path();
    if (!self.empty() && self != target_bin) {
        std::string data;
        if (!util::read_file(self, data)) {
            logx::error("读取自身可执行文件失败: " + self);
            return kErr;
        }
        if (!util::make_dirs(ctx.cfg.bindir, 0755, &mkerr)) {
            logx::error(mkerr);
            return kErr;
        }
        if (!util::write_file_atomic(target_bin, data, 0755, false, &err)) {
            logx::error("安装二进制失败: " + err);
            return kErr;
        }
    }

    if (!o.has("no-systemd")) {
        if (!systemd_available()) {
            logx::warn("未检测到运行中的 systemd，跳过开机恢复与定时刷新配置");
        } else {
            if (!util::make_dirs(ctx.cfg.systemd_dir, 0755, &mkerr)) {
                logx::error(mkerr);
                return kErr;
            }
            if (!util::write_file_atomic(ctx.cfg.systemd_dir + "/ban-restore.service",
                                         unit_restore(target_bin, ctx.cfg.state_file,
                                                      ctx.cfg.etc_dir),
                                         0644, false, &err) ||
                !util::write_file_atomic(ctx.cfg.systemd_dir + "/ban-refresh.service",
                                         unit_refresh(target_bin, ctx.cfg.state_file,
                                                      ctx.cfg.etc_dir),
                                         0644, false, &err) ||
                !util::write_file_atomic(ctx.cfg.systemd_dir + "/ban-refresh.timer",
                                         unit_timer(ctx.cfg.refresh_interval_min), 0644, false,
                                         &err)) {
                logx::error("写入 systemd 单元失败: " + err);
                return kErr;
            }

            util::run({"systemctl", "daemon-reload"}, "", 30);
            util::ExecResult r1 =
                util::run({"systemctl", "enable", "--now", "ban-restore.service"}, "", 60);
            util::ExecResult r2 =
                util::run({"systemctl", "enable", "--now", "ban-refresh.timer"}, "", 60);
            if (!r1.ok()) logx::warn("启用 ban-restore.service 失败: " + util::trim(r1.err));
            if (!r2.ok()) logx::warn("启用 ban-refresh.timer 失败: " + util::trim(r2.err));
        }
    }

    Session s(ctx.cfg);
    if (!s.begin(ctx.cfg, &err)) {
        logx::error(err);
        return kErr;
    }
    if (!apply_all(ctx, s.store, true, &err)) {
        logx::error("初始下发失败: " + err);
        return kPartial;
    }

    if (!ctx.quiet) {
        std::string refresh_desc;
        if (o.has("no-systemd")) {
            refresh_desc = "未配置";
        } else {
            refresh_desc = "ban-refresh.timer（每 " +
                           std::to_string(ctx.cfg.refresh_interval_min) + " 分钟）";
        }
        std::printf("安装完成。\n");
        std::printf("  可执行文件 : %s\n", target_bin.c_str());
        std::printf("  配置目录   : %s\n", ctx.cfg.etc_dir.c_str());
        std::printf("  开机恢复   : %s\n",
                    o.has("no-systemd") ? "未配置" : "ban-restore.service");
        std::printf("  定时刷新   : %s\n", refresh_desc.c_str());
    }
    return kOk;
}

int cmd_uninstall(Ctx& ctx, const Opts& o) {
    if (!require_root()) return kPerm;

    if (systemd_available()) {
        util::run({"systemctl", "disable", "--now", "ban-refresh.timer"}, "", 30);
        util::run({"systemctl", "stop", "ban-restore.service"}, "", 30);
        util::run({"systemctl", "disable", "ban-restore.service"}, "", 30);
        util::remove_file(ctx.cfg.systemd_dir + "/ban-restore.service");
        util::remove_file(ctx.cfg.systemd_dir + "/ban-refresh.service");
        util::remove_file(ctx.cfg.systemd_dir + "/ban-refresh.timer");
        util::run({"systemctl", "daemon-reload"}, "", 30);
    }

    std::string err;
    std::unique_ptr<FirewallBackend> backend = make_backend(ctx.cfg, &err);
    if (backend) backend->teardown(&err);
    dnsblock::teardown(ctx.cfg, &err);

    if (o.has("purge")) {
        util::remove_file(ctx.cfg.state_file);
        util::remove_file(ctx.cfg.allow_file);
        util::remove_file(ctx.cfg.cache_file);
        util::remove_file(ctx.cfg.conf_file);
        util::remove_file(ctx.cfg.lock_file);
        ::rmdir(ctx.cfg.etc_dir.c_str());
        util::remove_file(ctx.cfg.bindir + "/ban");
        if (!ctx.quiet) logx::info("已卸载并清除配置");
    } else if (!ctx.quiet) {
        logx::info("已停止并移除 systemd 单元与防火墙/DNS 规则（保留 " + ctx.cfg.etc_dir + "）");
    }
    return kOk;
}

// ============================ restore / doctor ============================

int cmd_restore(Ctx& ctx, const Opts& o) {
    if (!require_root()) return kPerm;

    Store st(ctx.cfg);
    std::string err;
    st.load(&err);
    st.load_cache();
    if (!err.empty()) logx::warn(err);

    // 开机时不解析域名，仅用缓存恢复 IP 层规则；域名解析交给 ban-refresh.timer
    if (!apply_all(ctx, st, true, &err)) {
        logx::error("恢复规则失败: " + err);
        return kErr;
    }
    logx::debug("规则已恢复");
    (void)o;
    return kOk;
}

void check_line(bool ok, const std::string& title, const std::string& detail) {
    if (ok) {
        std::printf("  \033[32m✓\033[0m %s", title.c_str());
    } else {
        std::printf("  \033[31m✗\033[0m %s", title.c_str());
    }
    if (!detail.empty()) std::printf(" — %s", detail.c_str());
    std::printf("\n");
}

void warn_line(const std::string& title, const std::string& detail) {
    std::printf("  \033[33m!\033[0m %s", title.c_str());
    if (!detail.empty()) std::printf(" — %s", detail.c_str());
    std::printf("\n");
}

int cmd_doctor(Ctx& ctx, const Opts& o) {
    (void)o;
    std::printf("ban doctor\n\n");

    std::printf("[权限与环境]\n");
    check_line(util::is_root(), "root 权限", util::is_root() ? "" : "多数操作需要 sudo");
    check_line(systemd_available(), "systemd",
               systemd_available() ? "" : "无 systemd：开机恢复/定时刷新不可用");

    util::ExecResult uname = util::run({"uname", "-r"}, "", 5);
    if (uname.ok()) std::printf("  内核: %s\n", util::trim(uname.out).c_str());

    std::printf("\n[防火墙后端]\n");
    {
        NftBackend nft;
        std::string e;
        bool ok = nft.available(&e);
        check_line(ok, "nftables", ok ? "" : e);
    }
    {
        IptablesBackend ipt;
        std::string e;
        bool ok = ipt.available(&e);
        check_line(ok, "iptables", ok ? "" : e);
    }
    {
        std::string e;
        std::unique_ptr<FirewallBackend> chosen = make_backend(ctx.cfg, &e);
        check_line(chosen != nullptr, "自动选择的防火墙后端",
                   chosen ? std::string(chosen->name()) : e);
    }
    {
        bool has_ipset = util::run({"ipset", "--version"}, "", 5).ok();
        if (!has_ipset) {
            warn_line("未安装 ipset", "iptables 后端将逐条写入规则，规则较多时较慢");
        } else {
            check_line(true, "ipset 可用", "");
        }
    }

    std::printf("\n[DNS 层]\n");
    dnsblock::Info di = dnsblock::describe(ctx.cfg);
    std::string ddetail;
    bool dactive = dnsblock::dnsmasq_active(&ddetail);
    check_line(dnsblock::dnsmasq_installed(), "dnsmasq 已安装",
               dnsblock::dnsmasq_installed() ? "" : "可选，安装后可支持子域通配");
    if (dnsblock::dnsmasq_installed()) {
        check_line(dactive, "dnsmasq 正在运行", ddetail);
    }
    std::printf("  当前 DNS 阻断方式: %s\n", di.detail.c_str());

    std::string hosts;
    bool hosts_readable = util::read_file(ctx.cfg.hosts_file, hosts);
    check_line(hosts_readable, "/etc/hosts 可读",
               hosts_readable ? "" : "无法读取，hosts 模式不可用");

    std::string nss;
    bool nss_ok = util::read_file("/etc/nsswitch.conf", nss) &&
                  nss.find("hosts:") != std::string::npos &&
                  nss.find("files") != std::string::npos;
    check_line(nss_ok, "nsswitch 中 hosts 使用 files",
               nss_ok ? "" : "hosts 模式可能不生效（需 'hosts: files ...'）");

    std::vector<std::string> servers = dns_servers();
    std::string joined = util::join(servers, ", ");
    check_line(!servers.empty(), "上游 DNS 服务器", joined.empty() ? "未找到" : joined);

    bool loopback_only = !servers.empty();
    for (const std::string& s : servers) {
        if (!(s == "::1" || util::starts_with(s, "127."))) {
            loopback_only = false;
            break;
        }
    }
    if (loopback_only && di.mode == "hosts") {
        warn_line("DNS 与 hosts 模式组合", "上游只有回环地址，解析可能被 hosts 影响；建议启用 dnsmasq");
    }

    std::printf("\n[状态]\n");
    Store st(ctx.cfg);
    st.load();
    st.load_cache();
    const int64_t now = util::now_epoch();
    std::printf("  规则: %zu 生效 / %zu 过期\n", st.count_active(now), st.count_expired(now));
    std::printf("  白名单: %zu 条\n", st.allow.size());
    std::printf("  配置目录: %s%s\n", ctx.cfg.etc_dir.c_str(),
                util::is_directory(ctx.cfg.etc_dir) ? "" : "（不存在，尚未执行 ban install）");
    std::printf("  定时刷新: %s\n", timer_state().c_str());

    return kOk;
}

// ============================ help ============================

void print_help() {
    std::printf(
        "ban %s — Linux 域名/IP 封禁工具（规则常驻内核，无常驻进程）\n"
        "\n"
        "用法: ban <命令> [参数] [选项]\n"
        "\n"
        "封禁管理:\n"
        "  add <域名|IP|CIDR>...      添加封禁（域名同时写入 DNS 层与解析后的 IP）\n"
        "                             --for 30m        临时封禁，到期自动失效\n"
        "                             --comment 文本   备注\n"
        "                             --type domain|ip|cidr  强制指定类型\n"
        "                             --no-dns         跳过解析（仅做 DNS 层阻断）\n"
        "  del <ID|目标>...           删除封禁\n"
        "  list                       列出规则        --json  --expired  --type <t>\n"
        "  status                     查看运行状态    --json\n"
        "  enable / disable           启用 / 停用封禁（规则保留）\n"
        "  flush                      清空全部规则并移除防火墙/DNS 阻断  --all 同时重置白名单\n"
        "\n"
        "域名与过期维护:\n"
        "  refresh                    重新解析所有域名并更新 IP 集合\n"
        "  gc                         清理已过期规则\n"
        "\n"
        "白名单:\n"
        "  allow list                 查看白名单\n"
        "  allow add <CIDR>...        添加白名单  --comment 文本\n"
        "  allow del <CIDR>...        删除白名单\n"
        "\n"
        "配置迁移:\n"
        "  export [文件]              导出规则  --format json|text  --output 文件\n"
        "  import [文件]              导入规则  --replace 覆盖而非合并\n"
        "\n"
        "系统集成:\n"
        "  install                    安装二进制、systemd 单元并启用开机恢复与定时刷新\n"
        "                             --bindir 目录   --interval 分钟   --no-systemd\n"
        "  uninstall                  移除 systemd 单元与规则  --purge 同时删除配置\n"
        "  restore                    仅按已保存配置恢复规则（供 systemd 调用）\n"
        "  doctor                     环境自检\n"
        "\n"
        "全局选项:\n"
        "  --json        以 JSON 输出（list/status/allow list）\n"
        "  --etc-dir 目录  使用指定的配置目录（默认 /etc/ban）\n"
        "  -v/--verbose  详细日志    -q/--quiet  安静模式\n"
        "  -h/--help     显示帮助    -V/--version 版本\n",
        kVersion);
}

}  // namespace

int cli_main(int argc, char** argv) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) args.push_back(argv[i]);

    std::string etc_dir = kDefaultEtcDir;
    bool verbose = false, quiet = false, json = false;
    std::vector<std::string> rest;

    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (a == "-v" || a == "--verbose") {
            verbose = true;
        } else if (a == "-q" || a == "--quiet") {
            quiet = true;
        } else if (a == "--json") {
            json = true;
        } else if (a == "--etc-dir") {
            if (i + 1 >= args.size()) {
                std::fprintf(stderr, "错误: --etc-dir 需要一个目录参数\n");
                return kUsage;
            }
            etc_dir = args[++i];
        } else if (util::starts_with(a, "--etc-dir=")) {
            etc_dir = a.substr(std::strlen("--etc-dir="));
        } else if (a == "-h" || a == "--help") {
            print_help();
            return kOk;
        } else if (a == "-V" || a == "--version") {
            std::printf("ban %s\n", kVersion);
            return kOk;
        } else {
            rest.push_back(a);
        }
    }

    Ctx ctx;
    ctx.verbose = verbose;
    ctx.quiet = quiet;
    ctx.json = json;

    std::string cerr;
    ctx.cfg = Config::load(etc_dir, &cerr);
    logx::init(ctx.cfg.log_file, verbose, quiet);
    if (!cerr.empty()) logx::warn(cerr);

    if (rest.empty()) {
        print_help();
        return kUsage;
    }

    const std::string cmd = util::to_lower(rest[0]);
    std::vector<std::string> cmd_args(rest.begin() + 1, rest.end());

    Opts o;
    std::string oerr;
    if (!parse_opts(cmd_args, o, oerr)) {
        std::fprintf(stderr, "错误: %s\n", oerr.c_str());
        return kUsage;
    }

    int rc = kOk;
    if (cmd == "add") rc = cmd_add(ctx, o);
    else if (cmd == "del" || cmd == "delete" || cmd == "rm") rc = cmd_del(ctx, o);
    else if (cmd == "list" || cmd == "ls") rc = cmd_list(ctx, o);
    else if (cmd == "status" || cmd == "st") rc = cmd_status(ctx, o);
    else if (cmd == "refresh") rc = cmd_refresh(ctx, o);
    else if (cmd == "gc") rc = cmd_gc(ctx, o);
    else if (cmd == "allow" || cmd == "white" || cmd == "whitelist") rc = cmd_allow(ctx, o);
    else if (cmd == "enable") rc = cmd_toggle(ctx, true);
    else if (cmd == "disable") rc = cmd_toggle(ctx, false);
    else if (cmd == "flush" || cmd == "clear") rc = cmd_flush(ctx, o);
    else if (cmd == "export") rc = cmd_export(ctx, o);
    else if (cmd == "import") rc = cmd_import(ctx, o);
    else if (cmd == "install") rc = cmd_install(ctx, o);
    else if (cmd == "uninstall") rc = cmd_uninstall(ctx, o);
    else if (cmd == "restore") rc = cmd_restore(ctx, o);
    else if (cmd == "doctor") rc = cmd_doctor(ctx, o);
    else if (cmd == "help") {
        print_help();
        rc = kOk;
    } else {
        std::fprintf(stderr, "错误: 未知命令 '%s'（运行 ban --help 查看用法）\n", cmd.c_str());
        rc = kUsage;
    }

    logx::shutdown();
    return rc;
}
