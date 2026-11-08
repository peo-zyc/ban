#include "util.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>

namespace util {

// ============================ 字符串 ============================

std::string ltrim(const std::string& s) {
    size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    return s.substr(i);
}

std::string rtrim(const std::string& s) {
    size_t n = s.size();
    while (n > 0 && std::isspace(static_cast<unsigned char>(s[n - 1]))) --n;
    return s.substr(0, n);
}

std::string trim(const std::string& s) { return rtrim(ltrim(s)); }

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::vector<std::string> split(const std::string& s, char sep, bool keep_empty) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) {
            if (keep_empty || !cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (keep_empty || !cur.empty()) out.push_back(cur);
    return out;
}

std::string join(const std::vector<std::string>& parts, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out += sep;
        out += parts[i];
    }
    return out;
}

std::string replace_all(std::string s, const std::string& from, const std::string& to) {
    if (from.empty()) return s;
    std::string out;
    size_t pos = 0;
    while (true) {
        size_t k = s.find(from, pos);
        if (k == std::string::npos) {
            out.append(s, pos, std::string::npos);
            break;
        }
        out.append(s, pos, k - pos);
        out += to;
        pos = k + from.size();
    }
    return out;
}

// ============================ 子进程 ============================

namespace {

void write_all_fd(int fd, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;  // EPIPE 等，忽略
        }
        off += static_cast<size_t>(n);
    }
}

}  // namespace

ExecResult run(const std::vector<std::string>& argv, const std::string& stdin_data,
               int timeout_sec) {
    ExecResult r;
    if (argv.empty()) return r;

    int outp[2] = {-1, -1};
    int errp[2] = {-1, -1};
    int inp[2] = {-1, -1};
    const bool need_stdin = !stdin_data.empty();

    if (::pipe(outp) != 0) return r;
    if (::pipe(errp) != 0) {
        ::close(outp[0]);
        ::close(outp[1]);
        return r;
    }
    if (need_stdin && ::pipe(inp) != 0) {
        ::close(outp[0]);
        ::close(outp[1]);
        ::close(errp[0]);
        ::close(errp[1]);
        return r;
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        for (int fd : {outp[0], outp[1], errp[0], errp[1], inp[0], inp[1]}) {
            if (fd >= 0) ::close(fd);
        }
        return r;
    }

    if (pid == 0) {
        if (need_stdin) {
            ::dup2(inp[0], STDIN_FILENO);
        } else {
            int devnull = ::open("/dev/null", O_RDONLY);
            if (devnull >= 0) ::dup2(devnull, STDIN_FILENO);
        }
        ::dup2(outp[1], STDOUT_FILENO);
        ::dup2(errp[1], STDERR_FILENO);

        for (int fd : {outp[0], outp[1], errp[0], errp[1], inp[0], inp[1]}) {
            if (fd >= 0) ::close(fd);
        }

        std::vector<char*> cargv;
        cargv.reserve(argv.size() + 1);
        for (const std::string& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
        cargv.push_back(nullptr);
        ::execvp(cargv[0], cargv.data());
        ::_exit(127);
    }

    ::close(outp[1]);
    ::close(errp[1]);
    outp[1] = -1;
    errp[1] = -1;

    if (need_stdin) {
        ::close(inp[0]);
        inp[0] = -1;
        std::string payload = stdin_data;
        if (payload.back() != '\n') payload.push_back('\n');
        write_all_fd(inp[1], payload);
        ::close(inp[1]);
        inp[1] = -1;
    }

    struct pollfd fds[2];
    fds[0].fd = outp[0];
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    fds[1].fd = errp[0];
    fds[1].events = POLLIN;
    fds[1].revents = 0;
    int open_fds = 2;

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec > 0 ? timeout_sec : 1);
    char buf[8192];

    while (open_fds > 0) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - std::chrono::steady_clock::now())
                        .count();
        if (left <= 0) {
            r.timed_out = true;
            break;
        }
        int pr = ::poll(fds, 2, static_cast<int>(left));
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) {
            r.timed_out = true;
            break;
        }
        for (int i = 0; i < 2; ++i) {
            if (fds[i].fd < 0) continue;
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            ssize_t n = ::read(fds[i].fd, buf, sizeof(buf));
            if (n > 0) {
                (i == 0 ? r.out : r.err).append(buf, static_cast<size_t>(n));
            } else if (n == 0) {
                ::close(fds[i].fd);
                fds[i].fd = -1;
                --open_fds;
            } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                ::close(fds[i].fd);
                fds[i].fd = -1;
                --open_fds;
            }
        }
    }

    if (fds[0].fd >= 0) ::close(fds[0].fd);
    if (fds[1].fd >= 0) ::close(fds[1].fd);

    if (r.timed_out) ::kill(pid, SIGKILL);

    int st = 0;
    while (::waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR) break;
    }

    if (r.timed_out) {
        r.status = -1;
    } else if (WIFEXITED(st)) {
        r.status = WEXITSTATUS(st);
    } else {
        r.status = -1;
    }
    return r;
}

// ============================ 文件 ============================

std::string dirname_of(const std::string& path) {
    size_t k = path.find_last_of('/');
    if (k == std::string::npos) return ".";
    if (k == 0) return "/";
    return path.substr(0, k);
}

std::string basename_of(const std::string& path) {
    size_t k = path.find_last_of('/');
    if (k == std::string::npos) return path;
    return path.substr(k + 1);
}

bool read_file(const std::string& path, std::string& out) {
    out.clear();
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    char buf[8192];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
    bool ok = (std::ferror(f) == 0);
    std::fclose(f);
    return ok;
}

bool path_exists(const std::string& path) {
    struct stat st;
    return ::lstat(path.c_str(), &st) == 0;
}

bool is_directory(const std::string& path) {
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) return false;
    return S_ISDIR(st.st_mode);
}

bool make_dirs(const std::string& path, unsigned mode, std::string* err) {
    if (path.empty()) return true;
    if (is_directory(path)) return true;

    std::string cur;
    size_t i = 0;
    if (path[0] == '/') {
        cur = "/";
        i = 1;
    }
    while (i <= path.size()) {
        size_t k = path.find('/', i);
        std::string part = path.substr(i, k == std::string::npos ? std::string::npos : k - i);
        if (!part.empty()) {
            if (cur.empty() || cur.back() != '/') cur += "/";
            cur += part;
            struct stat st;
            if (::stat(cur.c_str(), &st) != 0) {
                if (::mkdir(cur.c_str(), static_cast<mode_t>(mode)) != 0 && errno != EEXIST) {
                    if (err) *err = "创建目录失败 " + cur + ": " + std::strerror(errno);
                    return false;
                }
            } else if (!S_ISDIR(st.st_mode)) {
                if (err) *err = "路径已存在且不是目录: " + cur;
                return false;
            }
        }
        if (k == std::string::npos) break;
        i = k + 1;
    }
    return true;
}

bool remove_file(const std::string& path) {
    if (::unlink(path.c_str()) == 0) return true;
    return errno == ENOENT;
}

bool write_file_atomic(const std::string& path, const std::string& data, unsigned mode,
                       bool preserve_meta, std::string* err) {
    struct stat oldst;
    bool have_old = preserve_meta && ::stat(path.c_str(), &oldst) == 0;

    std::string dir = dirname_of(path);
    std::string tmp = dir + "/." + basename_of(path) + ".tmp." + std::to_string(::getpid());

    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, static_cast<mode_t>(mode));
    if (fd < 0) {
        if (err) *err = "无法写入 " + tmp + ": " + std::strerror(errno);
        return false;
    }

    size_t off = 0;
    bool ok = true;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        off += static_cast<size_t>(n);
    }
    if (ok && ::fsync(fd) != 0) ok = false;
    ::close(fd);

    if (!ok) {
        ::unlink(tmp.c_str());
        if (err) *err = "写入失败 " + tmp + ": " + std::strerror(errno);
        return false;
    }

    if (have_old) {
        ::chmod(tmp.c_str(), oldst.st_mode & 07777);
        if (::chown(tmp.c_str(), oldst.st_uid, oldst.st_gid) != 0) {
            // 非 root 时忽略
        }
    }

    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        if (err) *err = "替换 " + path + " 失败: " + std::strerror(errno);
        return false;
    }

    int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) {
        ::fsync(dfd);
        ::close(dfd);
    }
    return true;
}

// ============================ 地址 ============================

bool parse_ip(const std::string& s, bool& is_v6) {
    if (s.empty() || s.find('/') != std::string::npos) return false;
    struct in_addr a4;
    if (::inet_pton(AF_INET, s.c_str(), &a4) == 1) {
        is_v6 = false;
        return true;
    }
    struct in6_addr a6;
    if (::inet_pton(AF_INET6, s.c_str(), &a6) == 1) {
        is_v6 = true;
        return true;
    }
    return false;
}

bool is_ip_literal(const std::string& s) {
    bool v6 = false;
    return parse_ip(s, v6);
}

bool parse_cidr(const std::string& s, std::string& canon, bool& is_v6) {
    size_t k = s.find('/');
    if (k == std::string::npos) return false;
    std::string ip = s.substr(0, k);
    std::string ps = s.substr(k + 1);
    if (ip.empty() || ps.empty() || ps.size() > 3) return false;
    for (char c : ps) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    int prefix = std::atoi(ps.c_str());

    struct in_addr a4;
    if (::inet_pton(AF_INET, ip.c_str(), &a4) == 1) {
        if (prefix < 0 || prefix > 32) return false;
        uint32_t v = ntohl(a4.s_addr);
        uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
        a4.s_addr = htonl(v & mask);
        char b[INET_ADDRSTRLEN] = {0};
        ::inet_ntop(AF_INET, &a4, b, sizeof(b));
        canon = std::string(b) + "/" + std::to_string(prefix);
        is_v6 = false;
        return true;
    }

    struct in6_addr a6;
    if (::inet_pton(AF_INET6, ip.c_str(), &a6) == 1) {
        if (prefix < 0 || prefix > 128) return false;
        for (int i = 0; i < 16; ++i) {
            int bits = prefix - i * 8;
            if (bits >= 8) continue;
            if (bits <= 0) {
                a6.s6_addr[i] = 0;
                continue;
            }
            unsigned char m = static_cast<unsigned char>(0xFFu << (8 - bits));
            a6.s6_addr[i] = static_cast<unsigned char>(a6.s6_addr[i] & m);
        }
        char b[INET6_ADDRSTRLEN] = {0};
        ::inet_ntop(AF_INET6, &a6, b, sizeof(b));
        canon = std::string(b) + "/" + std::to_string(prefix);
        is_v6 = true;
        return true;
    }
    return false;
}

bool is_cidr_literal(const std::string& s) {
    std::string c;
    bool v6 = false;
    return parse_cidr(s, c, v6);
}

std::string normalize_ip(const std::string& s) {
    struct in_addr a4;
    if (::inet_pton(AF_INET, s.c_str(), &a4) == 1) {
        char b[INET_ADDRSTRLEN] = {0};
        ::inet_ntop(AF_INET, &a4, b, sizeof(b));
        return b;
    }
    struct in6_addr a6;
    if (::inet_pton(AF_INET6, s.c_str(), &a6) == 1) {
        char b[INET6_ADDRSTRLEN] = {0};
        ::inet_ntop(AF_INET6, &a6, b, sizeof(b));
        return b;
    }
    return std::string();
}

bool looks_like_domain(const std::string& s) {
    if (s.empty() || s.size() > 253) return false;
    if (s.find('/') != std::string::npos) return false;
    if (is_ip_literal(s)) return false;
    if (s.front() == '.' || s.back() == '.') return false;
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == '.') {
            if (i > 0 && s[i - 1] == '.') return false;
            continue;
        }
        if (!(std::isalnum(c) || c == '-' || c == '_')) return false;
    }
    return true;
}

std::string normalize_domain(const std::string& s) {
    std::string d = to_lower(trim(s));
    while (!d.empty() && d.back() == '.') d.pop_back();
    if (!looks_like_domain(d)) return std::string();
    return d;
}

bool cidr_contains(const std::string& cidr, const std::string& ip) {
    std::string c;
    bool cv6 = false;
    if (!parse_cidr(cidr, c, cv6)) return false;
    bool iv6 = false;
    if (!parse_ip(ip, iv6)) return false;
    if (cv6 != iv6) return false;

    std::string cip = c.substr(0, c.find('/'));
    size_t slash = c.find('/');
    int prefix = std::atoi(c.substr(slash + 1).c_str());

    unsigned char cbytes[16] = {0};
    unsigned char ibytes[16] = {0};
    size_t len = cv6 ? 16 : 4;
    if (::inet_pton(cv6 ? AF_INET6 : AF_INET, cip.c_str(), cbytes) != 1) return false;
    if (::inet_pton(cv6 ? AF_INET6 : AF_INET, ip.c_str(), ibytes) != 1) return false;

    int full = prefix / 8;
    int rem = prefix % 8;
    for (int i = 0; i < full && i < static_cast<int>(len); ++i) {
        if (cbytes[i] != ibytes[i]) return false;
    }
    if (rem > 0 && full < static_cast<int>(len)) {
        unsigned char m = static_cast<unsigned char>(0xFFu << (8 - rem));
        if ((cbytes[full] & m) != (ibytes[full] & m)) return false;
    }
    return true;
}

// ============================ 时间 ============================

bool parse_duration(const std::string& in, int64_t& seconds) {
    std::string s = to_lower(trim(in));
    if (s.empty()) return false;
    if (s == "forever" || s == "never" || s == "permanent" || s == "0") {
        seconds = 0;
        return true;
    }
    int64_t total = 0;
    size_t i = 0;
    while (i < s.size()) {
        size_t start = i;
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) ++i;
        if (i == start) return false;
        int64_t n = 0;
        for (size_t k = start; k < i; ++k) {
            n = n * 10 + (s[k] - '0');
            if (n > 1000000000LL) return false;
        }
        int64_t mult = 1;
        if (i < s.size()) {
            switch (s[i]) {
                case 's': mult = 1; break;
                case 'm': mult = 60; break;
                case 'h': mult = 3600; break;
                case 'd': mult = 86400; break;
                case 'w': mult = 604800; break;
                default: return false;
            }
            ++i;
        }
        total += n * mult;
        if (total > 3153600000LL) return false;
    }
    seconds = total;
    return true;
}

std::string format_duration(int64_t seconds) {
    if (seconds <= 0) return "0s";
    int64_t parts[5] = {0, 0, 0, 0, 0};  // w d h m s
    int64_t left = seconds;
    parts[0] = left / 604800; left %= 604800;
    parts[1] = left / 86400;  left %= 86400;
    parts[2] = left / 3600;   left %= 3600;
    parts[3] = left / 60;     left %= 60;
    parts[4] = left;
    static const char* suffix[5] = {"w", "d", "h", "m", "s"};
    std::string out;
    for (int i = 0; i < 5; ++i) {
        if (parts[i] == 0) continue;
        if (!out.empty()) out += " ";
        out += std::to_string(parts[i]);
        out += suffix[i];
    }
    return out.empty() ? "0s" : out;
}

int64_t now_epoch() { return static_cast<int64_t>(::time(nullptr)); }

std::string format_epoch(int64_t epoch, const char* fmt) {
    if (epoch <= 0) return "-";
    std::time_t t = static_cast<std::time_t>(epoch);
    struct tm tmv;
    if (!::localtime_r(&t, &tmv)) return "-";
    char buf[64] = {0};
    if (std::strftime(buf, sizeof(buf), fmt, &tmv) == 0) return "-";
    return buf;
}

std::string iso_now() {
    return format_epoch(now_epoch(), "%Y-%m-%dT%H:%M:%S%z");
}

// ============================ 杂项 ============================

bool is_root() { return ::geteuid() == 0; }

std::string self_exe_path() {
    char buf[4096] = {0};
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return std::string();
    return std::string(buf, static_cast<size_t>(n));
}

std::string human_number(uint64_t n) {
    std::string s = std::to_string(n);
    std::string out;
    int count = 0;
    for (int i = static_cast<int>(s.size()) - 1; i >= 0; --i) {
        out.insert(out.begin(), s[static_cast<size_t>(i)]);
        if (++count % 3 == 0 && i > 0) out.insert(out.begin(), ',');
    }
    return out;
}

std::string human_bytes(uint64_t n) {
    static const char* unit[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = static_cast<double>(n);
    int u = 0;
    while (v >= 1024.0 && u < 4) {
        v /= 1024.0;
        ++u;
    }
    char buf[64];
    if (u == 0) {
        std::snprintf(buf, sizeof(buf), "%llu %s", static_cast<unsigned long long>(n), unit[u]);
    } else {
        std::snprintf(buf, sizeof(buf), "%.2f %s", v, unit[u]);
    }
    return buf;
}

bool parse_u64(const std::string& s, uint64_t& out) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    errno = 0;
    char* end = nullptr;
    unsigned long long v = std::strtoull(s.c_str(), &end, 10);
    if (errno != 0 || end == s.c_str() || *end != '\0') return false;
    out = static_cast<uint64_t>(v);
    return true;
}

}  // namespace util
