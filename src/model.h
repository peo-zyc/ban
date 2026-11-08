#pragma once

#include <cstdint>
#include <string>
#include <vector>

enum class RuleType { Domain, Ip, Cidr };

const char* rule_type_name(RuleType t);
bool rule_type_from_name(const std::string& s, RuleType& out);

// 单条封禁规则。expires_at == 0 表示永久。
struct Rule {
    int64_t id = 0;
    RuleType type = RuleType::Ip;
    std::string value;
    int64_t created_at = 0;
    int64_t expires_at = 0;
    std::string comment;

    bool is_expired(int64_t now) const { return expires_at > 0 && expires_at <= now; }

    // 以 TAB 分隔的一行；comment 中的 TAB/换行会被替换为空格。
    std::string serialize() const;
    static bool deserialize(const std::string& line, Rule& out);
};

// 白名单条目（CIDR），优先级高于封禁。
struct AllowEntry {
    std::string cidr;
    std::string comment;

    std::string serialize() const;
    static bool deserialize(const std::string& line, AllowEntry& out);
};

// 域名解析缓存（refresh 时更新）
struct ResolveCacheEntry {
    std::vector<std::string> v4;
    std::vector<std::string> v6;
    int64_t resolved_at = 0;
    std::string error;
};

// 下发给防火墙后端的条目
struct BannedEntry {
    std::string cidr;      // 单个 IP 或 CIDR
    int64_t expires_at = 0;
};
