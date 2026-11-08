#include "resolver.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>

#include "util.h"

namespace {

std::string g_resolv_conf = "/etc/resolv.conf";

bool is_loopback_server(const std::string& ip) {
    if (ip == "::1") return true;
    if (util::starts_with(ip, "127.")) return true;
    return false;
}

bool parse_server_addr(const std::string& srv, struct sockaddr_storage& ss, socklen_t& slen) {
    std::string s = srv;
    size_t pct = s.find('%');
    if (pct != std::string::npos) s = s.substr(0, pct);  // 去掉 zone id

    std::memset(&ss, 0, sizeof(ss));
    struct sockaddr_in* a4 = reinterpret_cast<struct sockaddr_in*>(&ss);
    if (::inet_pton(AF_INET, s.c_str(), &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port = htons(53);
        slen = sizeof(*a4);
        return true;
    }
    struct sockaddr_in6* a6 = reinterpret_cast<struct sockaddr_in6*>(&ss);
    if (::inet_pton(AF_INET6, s.c_str(), &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(53);
        slen = sizeof(*a6);
        return true;
    }
    return false;
}

uint16_t next_query_id() {
    static unsigned counter = 0;
    ++counter;
    uint32_t v = static_cast<uint32_t>(::getpid()) * 2654435761u + static_cast<uint32_t>(::time(nullptr)) +
                 counter;
    return static_cast<uint16_t>(v & 0xFFFF);
}

bool build_query(std::vector<uint8_t>& pkt, const std::string& name, uint16_t qtype, uint16_t id) {
    pkt.clear();
    pkt.resize(12, 0);
    pkt[0] = static_cast<uint8_t>(id >> 8);
    pkt[1] = static_cast<uint8_t>(id & 0xFF);
    pkt[2] = 0x01;  // RD
    pkt[3] = 0x00;
    pkt[4] = 0x00;
    pkt[5] = 0x01;  // QDCOUNT = 1

    for (const std::string& label : util::split(name, '.')) {
        if (label.empty() || label.size() > 63) return false;
        pkt.push_back(static_cast<uint8_t>(label.size()));
        pkt.insert(pkt.end(), label.begin(), label.end());
    }
    pkt.push_back(0);

    pkt.push_back(static_cast<uint8_t>(qtype >> 8));
    pkt.push_back(static_cast<uint8_t>(qtype & 0xFF));
    pkt.push_back(0x00);
    pkt.push_back(0x01);  // IN
    return true;
}

bool skip_name(const uint8_t* buf, size_t len, size_t& off) {
    while (off < len) {
        uint8_t c = buf[off];
        if (c == 0) {
            ++off;
            return true;
        }
        if ((c & 0xC0) == 0xC0) {
            if (off + 1 >= len) return false;
            off += 2;
            return true;
        }
        if (c > 63) return false;
        off += 1 + static_cast<size_t>(c);
    }
    return false;
}

const char* rcode_text(int rcode) {
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        default: return "RCODE";
    }
}

bool parse_response(const uint8_t* buf, size_t len, uint16_t expect_id,
                    std::vector<std::string>& out, bool& rcode_ok, std::string& err) {
    rcode_ok = false;
    if (len < 12) {
        err = "响应过短";
        return false;
    }
    uint16_t id = static_cast<uint16_t>((buf[0] << 8) | buf[1]);
    if (id != expect_id) {
        err = "响应 ID 不匹配";
        return false;
    }
    uint8_t flags1 = buf[2];
    uint8_t flags2 = buf[3];
    if ((flags1 & 0x80) == 0) {
        err = "响应不是应答包";
        return false;
    }
    int rcode = flags2 & 0x0F;
    if (rcode != 0) {
        err = std::string("DNS 返回 ") + rcode_text(rcode);
        return false;
    }
    rcode_ok = true;

    uint16_t qd = static_cast<uint16_t>((buf[4] << 8) | buf[5]);
    uint16_t an = static_cast<uint16_t>((buf[6] << 8) | buf[7]);

    size_t off = 12;
    for (uint16_t i = 0; i < qd; ++i) {
        if (!skip_name(buf, len, off)) {
            err = "问题段损坏";
            return false;
        }
        off += 4;
        if (off > len) {
            err = "问题段越界";
            return false;
        }
    }

    for (uint16_t i = 0; i < an; ++i) {
        if (!skip_name(buf, len, off)) {
            err = "答案段损坏";
            return false;
        }
        if (off + 10 > len) {
            err = "答案段越界";
            return false;
        }
        uint16_t type = static_cast<uint16_t>((buf[off] << 8) | buf[off + 1]);
        uint16_t rdlen = static_cast<uint16_t>((buf[off + 8] << 8) | buf[off + 9]);
        off += 10;
        if (off + rdlen > len) {
            err = "rdata 越界";
            return false;
        }
        if (type == 1 && rdlen == 4) {
            char b[INET_ADDRSTRLEN] = {0};
            struct in_addr a;
            std::memcpy(&a, buf + off, 4);
            if (::inet_ntop(AF_INET, &a, b, sizeof(b))) out.push_back(b);
        } else if (type == 28 && rdlen == 16) {
            char b[INET6_ADDRSTRLEN] = {0};
            struct in6_addr a;
            std::memcpy(&a, buf + off, 16);
            if (::inet_ntop(AF_INET6, &a, b, sizeof(b))) out.push_back(b);
        }
        off += rdlen;
    }
    return true;
}

bool query_one(const std::string& server, const std::string& name, uint16_t qtype,
               std::vector<std::string>& out, int timeout_ms, std::string& err) {
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    if (!parse_server_addr(server, ss, slen)) {
        err = "无法解析 DNS 服务器地址: " + server;
        return false;
    }

    std::vector<uint8_t> pkt;
    uint16_t id = next_query_id();
    if (!build_query(pkt, name, qtype, id)) {
        err = "构造查询失败";
        return false;
    }

    int fd = ::socket(ss.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        err = std::string("socket: ") + std::strerror(errno);
        return false;
    }

    bool ok = false;
    do {
        if (::sendto(fd, pkt.data(), pkt.size(), 0, reinterpret_cast<struct sockaddr*>(&ss), slen) <
            0) {
            err = std::string("sendto: ") + std::strerror(errno);
            break;
        }

        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = ::poll(&pfd, 1, timeout_ms);
        if (pr <= 0) {
            err = "DNS 查询超时 (" + server + ")";
            break;
        }

        uint8_t buf[1500];
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            err = std::string("recv: ") + std::strerror(errno);
            break;
        }

        bool rcode_ok = false;
        if (!parse_response(buf, static_cast<size_t>(n), id, out, rcode_ok, err)) break;
        ok = true;
    } while (false);

    ::close(fd);
    return ok;
}

}  // namespace

std::vector<std::string> read_nameservers_from(const std::string& path) {
    std::vector<std::string> servers;
    std::string text;
    if (!util::read_file(path, text)) return servers;
    for (const std::string& raw : util::split(text, '\n', true)) {
        std::string line = util::trim(raw);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        std::vector<std::string> tok = util::split(line, ' ', false);
        if (tok.size() >= 2 && util::to_lower(tok[0]) == "nameserver") {
            std::string srv = tok[1];
            if (std::find(servers.begin(), servers.end(), srv) == servers.end()) {
                servers.push_back(srv);
            }
        }
    }
    return servers;
}

std::vector<std::string> dns_servers() {
    const bool is_default = (g_resolv_conf == "/etc/resolv.conf");

    std::vector<std::string> primary = read_nameservers_from(g_resolv_conf);

    bool all_loopback = !primary.empty();
    for (const std::string& s : primary) {
        if (!is_loopback_server(s)) {
            all_loopback = false;
            break;
        }
    }

    if (is_default && (primary.empty() || all_loopback)) {
        // systemd-resolved 场景：/etc/resolv.conf 只有 127.0.0.53，
        // 真实上游记录在 /run/systemd/resolve/resolv.conf。
        std::vector<std::string> real = read_nameservers_from("/run/systemd/resolve/resolv.conf");
        std::vector<std::string> filtered;
        for (const std::string& s : real) {
            if (!is_loopback_server(s)) filtered.push_back(s);
        }
        if (!filtered.empty()) return filtered;
        if (!real.empty()) return real;
    }
    return primary;
}

void set_resolv_conf(const std::string& path) {
    if (!path.empty()) g_resolv_conf = path;
}

DnsAnswer dns_resolve(const std::string& domain, int timeout_ms) {
    DnsAnswer ans;
    std::string name = util::normalize_domain(domain);
    if (name.empty()) {
        ans.error = "非法域名: " + domain;
        return ans;
    }

    std::vector<std::string> servers = dns_servers();
    if (servers.empty()) {
        ans.error = "未找到可用的 DNS 服务器 (/etc/resolv.conf)";
        return ans;
    }

    static const uint16_t kTypes[2] = {1, 28};  // A, AAAA
    bool any_ok = false;
    std::string last_err;

    for (uint16_t qtype : kTypes) {
        for (const std::string& srv : servers) {
            std::vector<std::string> ips;
            std::string err;
            if (query_one(srv, name, qtype, ips, timeout_ms, err)) {
                any_ok = true;
                for (const std::string& ip : ips) {
                    (qtype == 1 ? ans.v4 : ans.v6).push_back(ip);
                }
                break;
            }
            last_err = err;
        }
    }

    std::sort(ans.v4.begin(), ans.v4.end());
    ans.v4.erase(std::unique(ans.v4.begin(), ans.v4.end()), ans.v4.end());
    std::sort(ans.v6.begin(), ans.v6.end());
    ans.v6.erase(std::unique(ans.v6.begin(), ans.v6.end()), ans.v6.end());

    ans.ok = any_ok;
    if (!any_ok) ans.error = last_err.empty() ? "解析失败" : last_err;
    return ans;
}
