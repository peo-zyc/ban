#pragma once

#include "backend.h"

// nftables 后端：单表 `inet ban`，白名单集合 + 封禁集合（带 timeout 自动过期），
// output 与 forward 两个 hook 均生效（后者覆盖容器/NAT 出站）。
class NftBackend : public FirewallBackend {
public:
    const char* name() const override { return "nft"; }
    bool available(std::string* err) override;
    bool apply(const FirewallInput& in, const Config& cfg, std::string* err) override;
    bool teardown(std::string* err) override;
    bool stats(FirewallStats& out, std::string* err) override;
};

// iptables 后端：优先用 ipset 集合；无 ipset 时退化为逐条规则。
class IptablesBackend : public FirewallBackend {
public:
    const char* name() const override { return "iptables"; }
    bool available(std::string* err) override;
    bool apply(const FirewallInput& in, const Config& cfg, std::string* err) override;
    bool teardown(std::string* err) override;
    bool stats(FirewallStats& out, std::string* err) override;

private:
    bool have_ipset_ = false;
    bool ipset_checked_ = false;
    void detect_ipset();
};
