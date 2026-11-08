#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "backend_impl.h"
#include "json.h"
#include "log.h"
#include "store.h"
#include "util.h"

namespace {

const char* kTable = "ban";

std::string temp_path() {
    char tmpl[] = "/tmp/ban-nft-XXXXXX";
    int fd = ::mkstemp(tmpl);
    if (fd >= 0) ::close(fd);
    return std::string(tmpl);
}

bool exec_script(const std::string& script, std::string* err) {
    std::string path = temp_path();
    if (path.empty() || path == "/tmp/ban-nft-XXXXXX") {
        if (err) *err = "无法创建临时文件";
        return false;
    }
    std::string werr;
    if (!util::write_file_atomic(path, script, 0600, false, &werr)) {
        ::unlink(path.c_str());
        if (err) *err = werr;
        return false;
    }
    util::ExecResult r = util::run({"nft", "-f", path}, "", 30);
    ::unlink(path.c_str());
    if (r.ok()) return true;

    if (err) {
        std::string msg = util::trim(r.err.empty() ? r.out : r.err);
        if (msg.empty()) msg = "nft 退出码 " + std::to_string(r.status);
        *err = msg;
    }
    return false;
}

void emit_set(std::ostringstream& os, const std::string& name, const std::string& type,
              bool interval, bool with_timeout, bool automerge, bool use_size,
              const std::string& elements) {
    os << "\tset " << name << " {\n";
    os << "\t\ttype " << type << "\n";
    if (use_size) os << "\t\tsize 65535\n";

    std::vector<std::string> flags;
    if (interval) flags.push_back("interval");
    if (with_timeout) flags.push_back("timeout");
    if (!flags.empty()) os << "\t\tflags " << util::join(flags, ", ") << "\n";
    if (automerge && interval) os << "\t\tauto-merge\n";
    if (!elements.empty()) os << "\t\telements = { " << elements << " }\n";
    os << "\t}\n\n";
}

std::string render_banned(const std::vector<BannedEntry>& entries, bool with_timeout,
                          int64_t now) {
    std::vector<std::string> parts;
    parts.reserve(entries.size());
    for (const BannedEntry& e : entries) {
        if (e.cidr.empty()) continue;
        if (e.expires_at > 0) {
            int64_t left = e.expires_at - now;
            if (left <= 0) continue;
            if (with_timeout) {
                parts.push_back(e.cidr + " timeout " + std::to_string(left) + "s");
            } else {
                parts.push_back(e.cidr);
            }
        } else {
            parts.push_back(e.cidr);
        }
    }
    return util::join(parts, ", ");
}

std::string build_script(const FirewallInput& in, const Config& cfg, bool with_timeout,
                         bool automerge, int64_t now) {
    std::ostringstream os;
    os << "table inet " << kTable << " {\n";

    emit_set(os, "allow_v4", "ipv4_addr", true, false, true, false,
             util::join(in.allow_v4, ", "));
    emit_set(os, "allow_v6", "ipv6_addr", true, false, true, false,
             util::join(in.allow_v6, ", "));
    emit_set(os, "banned_v4", "ipv4_addr", true, with_timeout, automerge, true,
             render_banned(in.banned_v4, with_timeout, now));
    emit_set(os, "banned_v6", "ipv6_addr", true, with_timeout, automerge, true,
             render_banned(in.banned_v6, with_timeout, now));

    const char* verdict = (cfg.action == "drop") ? "drop" : "reject";

    // 注意：链名不能叫 "fwd"（nft 保留字），否则解析失败
    struct ChainSpec {
        const char* name;
        const char* hook;
    };
    const ChainSpec chains[2] = {{"ban_out", "output"}, {"ban_fwd", "forward"}};

    for (const ChainSpec& c : chains) {
        os << "\tchain " << c.name << " {\n";
        os << "\t\ttype filter hook " << c.hook
           << " priority filter; policy accept;\n";
        os << "\t\tip daddr @allow_v4 accept\n";
        os << "\t\tip6 daddr @allow_v6 accept\n";
        if (in.enabled) {
            os << "\t\tip daddr @banned_v4 counter " << verdict << "\n";
            os << "\t\tip6 daddr @banned_v6 counter " << verdict << "\n";
        }
        os << "\t}\n\n";
    }

    os << "}\n";
    return os.str();
}

}  // namespace

bool NftBackend::available(std::string* err) {
    util::ExecResult r = util::run({"nft", "--version"}, "", 5);
    if (!r.ok()) {
        if (err) *err = "未找到可用的 nft 命令（请安装 nftables）";
        return false;
    }
    util::ExecResult r2 = util::run({"nft", "list", "tables"}, "", 5);
    if (!r2.ok()) {
        if (err) {
            std::string msg = util::trim(r2.err.empty() ? r2.out : r2.err);
            *err = "nft 无法操作规则（需要 root / CAP_NET_ADMIN）：" + msg;
        }
        return false;
    }
    return true;
}

bool NftBackend::apply(const FirewallInput& in, const Config& cfg, std::string* err) {
    const int64_t now = util::now_epoch();

    struct Variant {
        bool timeout;
        bool automerge;
    };
    const Variant variants[4] = {{true, true}, {true, false}, {false, true}, {false, false}};

    std::string last_err;

    // 1) 单事务原子替换：先声明再删除再重建，nft 会把整个文件当作一个 batch 提交
    for (const Variant& v : variants) {
        std::string script = std::string("table inet ") + kTable + "\ndelete table inet " + kTable +
                             "\n" + build_script(in, cfg, v.timeout, v.automerge, now);
        if (exec_script(script, &last_err)) {
            if (!v.timeout) {
                logx::warn("当前内核不支持集合 timeout，临时封禁将依赖 `ban gc` 定时清理");
            }
            return true;
        }
        logx::debug("nft 原子替换失败（timeout=" + std::to_string(v.timeout) +
                    " automerge=" + std::to_string(v.automerge) + "）: " + last_err);
    }

    // 2) 退化路径：先删除旧表，再逐级降级特性
    util::run({"nft", "delete", "table", "inet", kTable}, "", 10);
    for (const Variant& v : variants) {
        if (exec_script(build_script(in, cfg, v.timeout, v.automerge, now), &last_err)) {
            if (!v.timeout) {
                logx::warn("当前内核不支持集合 timeout，临时封禁将依赖 `ban gc` 定时清理");
            }
            return true;
        }
        logx::debug("nft 应用失败: " + last_err);
    }

    if (err) *err = last_err;
    return false;
}

bool NftBackend::teardown(std::string* err) {
    util::ExecResult r = util::run({"nft", "delete", "table", "inet", kTable}, "", 15);
    if (r.ok()) return true;

    std::string msg = util::trim(r.err.empty() ? r.out : r.err);
    if (msg.find("No such file or directory") != std::string::npos ||
        msg.find("does not exist") != std::string::npos) {
        return true;  // 表本来就不存在
    }
    if (err) *err = msg;
    return false;
}

bool NftBackend::stats(FirewallStats& out, std::string* err) {
    out = FirewallStats();
    out.backend = "nft";
    out.detail = std::string("table inet ") + kTable;

    util::ExecResult r = util::run({"nft", "-j", "list", "table", "inet", kTable}, "", 15);
    if (!r.ok()) {
        out.available = false;
        std::string msg = util::trim(r.err.empty() ? r.out : r.err);
        if (msg.find("No such file or directory") != std::string::npos) {
            out.detail = "规则表尚未创建（尚未封禁任何内容）";
            if (err) *err = out.detail;
        } else {
            out.detail = msg;
            if (err) *err = msg;
        }
        return false;
    }

    Json root;
    std::string perr;
    if (!Json::parse(r.out, root, &perr)) {
        out.available = false;
        out.detail = "解析 nft JSON 输出失败: " + perr;
        if (err) *err = out.detail;
        return false;
    }

    const Json* items = root.find("nftables");
    if (items && items->is_array()) {
        for (size_t i = 0; i < items->size(); ++i) {
            const Json& item = items->at(i);

            if (const Json* set = item.find("set")) {
                const Json* name = set->find("name");
                if (!name) continue;
                size_t count = 0;
                const Json* elems = set->find("elem");
                if (elems && elems->is_array()) count = elems->size();

                const std::string n = name->as_string();
                if (n == "banned_v4") out.banned_v4 = count;
                else if (n == "banned_v6") out.banned_v6 = count;
                else if (n == "allow_v4") out.allow_v4 = count;
                else if (n == "allow_v6") out.allow_v6 = count;
                continue;
            }

            if (const Json* rule = item.find("rule")) {
                const Json* exprs = rule->find("expr");
                if (!exprs || !exprs->is_array()) continue;

                bool is_drop = false;
                uint64_t pkts = 0;
                uint64_t bytes = 0;
                for (size_t k = 0; k < exprs->size(); ++k) {
                    const Json& ex = exprs->at(k);
                    if (ex.find("drop") || ex.find("reject")) is_drop = true;
                    if (const Json* c = ex.find("counter")) {
                        if (const Json* p = c->find("packets")) pkts += p->as_uint();
                        if (const Json* b = c->find("bytes")) bytes += b->as_uint();
                    }
                }
                if (is_drop) {
                    out.packets += pkts;
                    out.bytes += bytes;
                }
            }
        }
    }

    out.available = true;
    return true;
}
