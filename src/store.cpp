#include "store.h"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include "json.h"
#include "log.h"
#include "util.h"

// ============================ 锁 ============================

StoreLock::~StoreLock() { release(); }

bool StoreLock::acquire(const std::string& path, std::string* err) {
    release();

    std::string dir = util::dirname_of(path);
    std::string mkerr;
    if (!util::is_directory(dir) && !util::make_dirs(dir, 0755, &mkerr)) {
        if (err) *err = mkerr;
        return false;
    }

    int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        if (err) *err = "无法打开锁文件 " + path + ": " + std::strerror(errno);
        return false;
    }
    if (::flock(fd, LOCK_EX) != 0) {
        if (err) *err = "获取锁失败 " + path + ": " + std::strerror(errno);
        ::close(fd);
        return false;
    }
    fd_ = fd;
    return true;
}

void StoreLock::release() {
    if (fd_ >= 0) {
        ::flock(fd_, LOCK_UN);
        ::close(fd_);
        fd_ = -1;
    }
}

// ============================ 默认白名单 ============================

namespace {

const char* kDefaultAllow[][2] = {
    {"127.0.0.0/8", "loopback (IPv4)"},
    {"::1/128", "loopback (IPv6)"},
    {"169.254.0.0/16", "link-local (IPv4)"},
    {"fe80::/10", "link-local (IPv6)"},
    {"224.0.0.0/4", "multicast (IPv4)"},
    {"ff00::/8", "multicast (IPv6)"},
};

}  // namespace

// ============================ 读写 ============================

bool Store::load(std::string* err) {
    (void)err;
    rules.clear();
    allow.clear();
    cache.clear();
    next_id = 1;

    std::string text;
    if (util::read_file(cfg_.state_file, text)) {
        for (const std::string& raw : util::split(text, '\n', true)) {
            std::string line = util::rtrim(raw);
            if (line.empty()) continue;
            if (line[0] == '#') {
                if (util::starts_with(line, "# next_id=")) {
                    next_id = std::atoll(line.substr(10).c_str());
                    if (next_id <= 0) next_id = 1;
                }
                continue;
            }
            Rule r;
            if (Rule::deserialize(line, r)) {
                rules.push_back(r);
                if (r.id >= next_id) next_id = r.id + 1;
            } else {
                logx::warn("忽略无法解析的规则行: " + line);
            }
        }
    }

    bool have_allow_file = util::read_file(cfg_.allow_file, text);
    if (have_allow_file) {
        for (const std::string& raw : util::split(text, '\n', true)) {
            std::string line = util::rtrim(raw);
            if (line.empty() || line[0] == '#') continue;
            AllowEntry a;
            if (AllowEntry::deserialize(line, a)) {
                allow.push_back(a);
            } else {
                logx::warn("忽略无法解析的白名单行: " + line);
            }
        }
    }

    // 仅当白名单文件不存在时才注入内置默认项：
    // 这样「清空白名单」是用户的明确意图，不会被悄悄还原。
    if (!have_allow_file) {
        for (const auto& pair : kDefaultAllow) {
            AllowEntry a;
            a.cidr = pair[0];
            a.comment = pair[1];
            allow.push_back(a);
        }
    }

    return true;
}

bool Store::save(std::string* err) const {
    std::string mkerr;
    if (!util::is_directory(cfg_.etc_dir) && !util::make_dirs(cfg_.etc_dir, 0755, &mkerr)) {
        if (err) *err = mkerr;
        return false;
    }

    std::string out = "# ban rules v1 next_id=" + std::to_string(next_id) + "\n";
    out += "# id\ttype\tvalue\tcreated_at\texpires_at\tcomment\n";
    for (const Rule& r : rules) out += r.serialize() + "\n";
    if (!util::write_file_atomic(cfg_.state_file, out, 0600, false, err)) return false;

    std::string aout = "# ban whitelist v1\n# cidr\tcomment\n";
    for (const AllowEntry& a : allow) aout += a.serialize() + "\n";
    if (!util::write_file_atomic(cfg_.allow_file, aout, 0600, false, err)) return false;

    return true;
}

bool Store::load_cache(std::string* err) {
    cache.clear();
    std::string text;
    if (!util::read_file(cfg_.cache_file, text)) return true;  // 无缓存不算错误

    Json root;
    std::string perr;
    if (!Json::parse(text, root, &perr)) {
        if (err) *err = "解析 " + cfg_.cache_file + " 失败: " + perr;
        return false;
    }

    const Json* entries = root.find("entries");
    if (!entries || !entries->is_array()) return true;

    for (size_t i = 0; i < entries->size(); ++i) {
        const Json& e = entries->at(i);
        const Json* name = e.find("name");
        if (!name) continue;
        ResolveCacheEntry ce;
        const Json* v4 = e.find("v4");
        if (v4 && v4->is_array()) {
            for (size_t k = 0; k < v4->size(); ++k) ce.v4.push_back(v4->at(k).as_string());
        }
        const Json* v6 = e.find("v6");
        if (v6 && v6->is_array()) {
            for (size_t k = 0; k < v6->size(); ++k) ce.v6.push_back(v6->at(k).as_string());
        }
        const Json* at = e.find("resolved_at");
        if (at) ce.resolved_at = at->as_int(0);
        const Json* er = e.find("error");
        if (er) ce.error = er->as_string();
        cache[name->as_string()] = ce;
    }
    return true;
}

bool Store::save_cache(std::string* err) const {
    Json root = Json::object();
    root.set("version", Json::integer(1));
    root.set("generated_at", Json::integer(util::now_epoch()));

    Json entries = Json::array();
    for (const auto& kv : cache) {
        Json e = Json::object();
        e.set("name", Json::string(kv.first));
        Json v4 = Json::array();
        for (const std::string& ip : kv.second.v4) v4.push(Json::string(ip));
        Json v6 = Json::array();
        for (const std::string& ip : kv.second.v6) v6.push(Json::string(ip));
        e.set("v4", v4);
        e.set("v6", v6);
        e.set("resolved_at", Json::integer(kv.second.resolved_at));
        if (!kv.second.error.empty()) e.set("error", Json::string(kv.second.error));
        entries.push(e);
    }
    root.set("entries", entries);

    std::string mkerr;
    if (!util::is_directory(cfg_.etc_dir) && !util::make_dirs(cfg_.etc_dir, 0755, &mkerr)) {
        if (err) *err = mkerr;
        return false;
    }
    return util::write_file_atomic(cfg_.cache_file, root.dump(2), 0600, false, err);
}

// ============================ 查询 / 修改 ============================

Rule* Store::find_by_value(const std::string& value) {
    for (Rule& r : rules) {
        if (r.value == value) return &r;
    }
    return nullptr;
}

Rule* Store::find_by_id(int64_t id) {
    for (Rule& r : rules) {
        if (r.id == id) return &r;
    }
    return nullptr;
}

bool Store::remove_by_id(int64_t id) {
    for (size_t i = 0; i < rules.size(); ++i) {
        if (rules[i].id == id) {
            rules.erase(rules.begin() + static_cast<long>(i));
            return true;
        }
    }
    return false;
}

int64_t Store::add_rule(RuleType type, const std::string& value, int64_t expires_at,
                        const std::string& comment) {
    Rule r;
    r.id = next_id++;
    r.type = type;
    r.value = value;
    r.created_at = util::now_epoch();
    r.expires_at = expires_at;
    r.comment = comment;
    rules.push_back(r);
    return r.id;
}

size_t Store::prune_expired(int64_t now) {
    size_t before = rules.size();
    rules.erase(std::remove_if(rules.begin(), rules.end(),
                               [now](const Rule& r) { return r.is_expired(now); }),
                rules.end());
    return before - rules.size();
}

void Store::collect_banned(std::vector<BannedEntry>& out_v4, std::vector<BannedEntry>& out_v6,
                           bool include_v6, int64_t now) const {
    std::map<std::string, int64_t> seen;  // cidr -> 最长过期时间
    auto put = [&seen](const std::string& cidr, int64_t exp) {
        auto it = seen.find(cidr);
        if (it == seen.end() || it->second < exp) seen[cidr] = exp;
    };

    for (const Rule& r : rules) {
        if (r.is_expired(now)) continue;

        if (r.type == RuleType::Ip) {
            bool v6 = false;
            if (!util::parse_ip(r.value, v6)) continue;
            if (v6 && !include_v6) continue;
            put(util::normalize_ip(r.value), r.expires_at);
        } else if (r.type == RuleType::Cidr) {
            std::string canon;
            bool v6 = false;
            if (!util::parse_cidr(r.value, canon, v6)) continue;
            if (v6 && !include_v6) continue;
            put(canon, r.expires_at);
        } else {
            auto it = cache.find(r.value);
            if (it == cache.end()) continue;
            for (const std::string& ip : it->second.v4) put(ip, r.expires_at);
            if (include_v6) {
                for (const std::string& ip : it->second.v6) put(ip, r.expires_at);
            }
        }
    }

    out_v4.clear();
    out_v6.clear();
    for (const auto& kv : seen) {
        bool v6 = false;
        if (!util::parse_ip(kv.first, v6)) {
            std::string canon;
            if (!util::parse_cidr(kv.first, canon, v6)) continue;
        }
        BannedEntry e;
        e.cidr = kv.first;
        e.expires_at = kv.second;
        (v6 ? out_v6 : out_v4).push_back(e);
    }
}

void Store::collect_allow(std::vector<std::string>& out_v4,
                          std::vector<std::string>& out_v6) const {
    out_v4.clear();
    out_v6.clear();
    for (const AllowEntry& a : allow) {
        std::string canon;
        bool v6 = false;
        if (util::parse_cidr(a.cidr, canon, v6)) {
            (v6 ? out_v6 : out_v4).push_back(canon);
            continue;
        }
        if (util::parse_ip(a.cidr, v6)) {
            std::string ip = util::normalize_ip(a.cidr);
            (v6 ? out_v6 : out_v4).push_back(ip + (v6 ? "/128" : "/32"));
        }
    }
}

std::vector<std::string> Store::active_domains(int64_t now) const {
    std::vector<std::string> out;
    for (const Rule& r : rules) {
        if (r.type != RuleType::Domain) continue;
        if (r.is_expired(now)) continue;
        out.push_back(r.value);
    }
    return out;
}

size_t Store::count_active(int64_t now) const {
    size_t n = 0;
    for (const Rule& r : rules) {
        if (!r.is_expired(now)) ++n;
    }
    return n;
}

size_t Store::count_expired(int64_t now) const {
    size_t n = 0;
    for (const Rule& r : rules) {
        if (r.is_expired(now)) ++n;
    }
    return n;
}
