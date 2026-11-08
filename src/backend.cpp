#include "backend_impl.h"

#include "log.h"
#include "util.h"

std::unique_ptr<FirewallBackend> make_backend(const Config& cfg, std::string* err) {
    if (cfg.backend == "nft") {
        std::unique_ptr<FirewallBackend> b(new NftBackend());
        std::string e;
        if (!b->available(&e)) {
            if (err) *err = e;
            return nullptr;
        }
        return b;
    }
    if (cfg.backend == "iptables") {
        std::unique_ptr<FirewallBackend> b(new IptablesBackend());
        std::string e;
        if (!b->available(&e)) {
            if (err) *err = e;
            return nullptr;
        }
        return b;
    }

    // auto：优先 nftables
    {
        std::unique_ptr<FirewallBackend> b(new NftBackend());
        std::string e;
        if (b->available(&e)) {
            logx::debug("自动选择后端: nftables");
            return b;
        }
        logx::debug(std::string("nftables 不可用，尝试 iptables: ") + e);
    }
    {
        std::unique_ptr<FirewallBackend> b(new IptablesBackend());
        std::string e;
        if (b->available(&e)) {
            logx::debug("自动选择后端: iptables");
            return b;
        }
        if (err) *err = "没有可用的防火墙后端: " + e;
    }
    return nullptr;
}
