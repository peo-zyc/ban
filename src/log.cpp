#include "log.h"

#include <syslog.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>

namespace logx {
namespace {

std::string g_path;
bool g_verbose = false;
bool g_quiet = false;
bool g_syslog_open = false;

const char* color_for(const char* level) {
    if (std::strcmp(level, "ERROR") == 0) return "\033[31m";
    if (std::strcmp(level, "WARN") == 0) return "\033[33m";
    if (std::strcmp(level, "DEBUG") == 0) return "\033[90m";
    return "\033[36m";
}

void emit(const char* level, const std::string& text, bool to_terminal, int syslog_prio) {
    std::string ts;
    {
        std::time_t t = std::time(nullptr);
        struct tm tmv;
        char buf[32] = {0};
        if (::localtime_r(&t, &tmv) && std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv)) {
            ts = buf;
        }
    }

    if (to_terminal && (!g_quiet || std::strcmp(level, "ERROR") == 0 ||
                        std::strcmp(level, "WARN") == 0)) {
        bool tty = ::isatty(STDERR_FILENO) == 1;
        if (tty) {
            std::fprintf(stderr, "\033[90m%s\033[0m %s%s\033[0m %s\n", ts.c_str(),
                         color_for(level), level, text.c_str());
        } else {
            std::fprintf(stderr, "%s %s %s\n", ts.c_str(), level, text.c_str());
        }
    }

    if (!g_path.empty()) {
        std::string line = ts + " " + level + " " + text + "\n";
        FILE* f = std::fopen(g_path.c_str(), "a");
        if (f) {
            std::fwrite(line.data(), 1, line.size(), f);
            std::fclose(f);
        }
    }

    if (g_syslog_open) {
        ::syslog(syslog_prio, "%s", text.c_str());
    }
}

}  // namespace

void init(const std::string& path, bool verbose, bool quiet) {
    g_path = path;
    g_verbose = verbose;
    g_quiet = quiet;
    if (!g_syslog_open) {
        ::openlog("ban", LOG_PID, LOG_AUTHPRIV);
        g_syslog_open = true;
    }
}

void shutdown() {
    if (g_syslog_open) {
        ::closelog();
        g_syslog_open = false;
    }
}

bool verbose_enabled() { return g_verbose; }

void info(const std::string& s) { emit("INFO", s, true, LOG_INFO); }
void warn(const std::string& s) { emit("WARN", s, true, LOG_WARNING); }
void error(const std::string& s) { emit("ERROR", s, true, LOG_ERR); }
void debug(const std::string& s) {
    if (!g_verbose) return;
    emit("DEBUG", s, true, LOG_DEBUG);
}

}  // namespace logx
