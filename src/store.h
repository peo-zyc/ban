#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "config.h"
#include "model.h"

// 独占文件锁，串行化所有写操作。
class StoreLock {
public:
    StoreLock() {}
    ~StoreLock();
    StoreLock(const StoreLock&) = delete;
    StoreLock& operator=(const StoreLock&) = delete;

    bool acquire(const std::string& path, std::string* err);
    void release();

private:
    int fd_ = -1;
};

// 持久化状态的读写。所有写操作都通过「读-改-写-原子替换」完成。
class Store {
public:
    explicit Store(const Config& cfg) : cfg_(cfg) {}

    bool load(std::string* err = nullptr);
    bool save(std::string* err = nullptr) const;

    bool load_cache(std::string* err = nullptr);
    bool save_cache(std::string* err = nullptr) const;

    Rule* find_by_value(const std::string& value);
    Rule* find_by_id(int64_t id);
    bool remove_by_id(int64_t id);
    int64_t add_rule(RuleType type, const std::string& value, int64_t expires_at,
                     const std::string& comment);
    size_t prune_expired(int64_t now);

    // 汇总下发给防火墙的条目（已去重，同一地址保留最长过期时间）。
    void collect_banned(std::vector<BannedEntry>& out_v4, std::vector<BannedEntry>& out_v6,
                        bool include_v6, int64_t now) const;
    void collect_allow(std::vector<std::string>& out_v4, std::vector<std::string>& out_v6) const;

    std::vector<std::string> active_domains(int64_t now) const;
    size_t count_active(int64_t now) const;
    size_t count_expired(int64_t now) const;

    std::vector<Rule> rules;
    std::vector<AllowEntry> allow;
    std::map<std::string, ResolveCacheEntry> cache;
    int64_t next_id = 1;

private:
    const Config& cfg_;
};
