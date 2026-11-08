#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "config.h"
#include "model.h"

struct FirewallStats {
    bool available = false;
    std::string backend;
    std::string detail;
    size_t banned_v4 = 0;
    size_t banned_v6 = 0;
    size_t allow_v4 = 0;
    size_t allow_v6 = 0;
    uint64_t packets = 0;
    uint64_t bytes = 0;
};

struct FirewallInput {
    std::vector<BannedEntry> banned_v4;
    std::vector<BannedEntry> banned_v6;
    std::vector<std::string> allow_v4;
    std::vector<std::string> allow_v6;
    bool enabled = true;
};

class FirewallBackend {
public:
    virtual ~FirewallBackend() {}
    virtual const char* name() const = 0;
    virtual bool available(std::string* err) = 0;
    virtual bool apply(const FirewallInput& in, const Config& cfg, std::string* err) = 0;
    virtual bool teardown(std::string* err) = 0;
    virtual bool stats(FirewallStats& out, std::string* err) = 0;
};

// 按 cfg.backend（auto/nft/iptables）选择并创建后端。
// 返回 nullptr 时 err 中包含原因。
std::unique_ptr<FirewallBackend> make_backend(const Config& cfg, std::string* err);
