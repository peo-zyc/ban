#include "model.h"

#include <cstdlib>

#include "util.h"

const char* rule_type_name(RuleType t) {
    switch (t) {
        case RuleType::Domain: return "domain";
        case RuleType::Ip: return "ip";
        case RuleType::Cidr: return "cidr";
    }
    return "ip";
}

bool rule_type_from_name(const std::string& s, RuleType& out) {
    if (s == "domain") {
        out = RuleType::Domain;
        return true;
    }
    if (s == "ip") {
        out = RuleType::Ip;
        return true;
    }
    if (s == "cidr") {
        out = RuleType::Cidr;
        return true;
    }
    return false;
}

namespace {

std::string sanitize_field(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        if (c == '\t' || c == '\n' || c == '\r') c = ' ';
    }
    return out;
}

}  // namespace

std::string Rule::serialize() const {
    return std::to_string(id) + "\t" + rule_type_name(type) + "\t" + value + "\t" +
           std::to_string(created_at) + "\t" + std::to_string(expires_at) + "\t" +
           sanitize_field(comment);
}

bool Rule::deserialize(const std::string& line, Rule& out) {
    std::vector<std::string> f = util::split(line, '\t', true);
    if (f.size() < 5) return false;

    out.id = std::atoll(f[0].c_str());
    if (out.id <= 0) return false;
    if (!rule_type_from_name(f[1], out.type)) return false;
    out.value = f[2];
    out.created_at = std::atoll(f[3].c_str());
    out.expires_at = std::atoll(f[4].c_str());
    out.comment = f.size() > 5 ? f[5] : std::string();
    return !out.value.empty();
}

std::string AllowEntry::serialize() const { return cidr + "\t" + sanitize_field(comment); }

bool AllowEntry::deserialize(const std::string& line, AllowEntry& out) {
    std::vector<std::string> f = util::split(line, '\t', true);
    if (f.empty() || f[0].empty()) return false;
    out.cidr = f[0];
    out.comment = f.size() > 1 ? f[1] : std::string();
    return true;
}
