#pragma once

#include <string>

namespace logx {

// 初始化日志：写文件 + syslog(LOG_AUTHPRIV)。
// path 为空时只写 syslog。quiet 抑制 info/debug 的终端输出。
void init(const std::string& path, bool verbose, bool quiet);
void shutdown();
bool verbose_enabled();

void info(const std::string& s);
void warn(const std::string& s);
void error(const std::string& s);
void debug(const std::string& s);

}  // namespace logx
