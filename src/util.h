#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace util {

// ---------- 字符串 ----------
std::string ltrim(const std::string& s);
std::string rtrim(const std::string& s);
std::string trim(const std::string& s);
std::string to_lower(std::string s);
bool starts_with(const std::string& s, const std::string& prefix);
bool ends_with(const std::string& s, const std::string& suffix);
std::vector<std::string> split(const std::string& s, char sep, bool keep_empty = false);
std::string join(const std::vector<std::string>& parts, const std::string& sep);
std::string replace_all(std::string s, const std::string& from, const std::string& to);

// ---------- 子进程 ----------
struct ExecResult {
    int status = -1;          // -1 表示启动失败或超时
    bool timed_out = false;
    std::string out;
    std::string err;
    bool ok() const { return status == 0; }
};

// 直接 execvp，不经过 shell，参数安全。
ExecResult run(const std::vector<std::string>& argv,
               const std::string& stdin_data = std::string(),
               int timeout_sec = 30);

// ---------- 文件 ----------
bool read_file(const std::string& path, std::string& out);
bool write_file_atomic(const std::string& path, const std::string& data,
                       unsigned mode = 0644, bool preserve_meta = false,
                       std::string* err = nullptr);
bool path_exists(const std::string& path);
bool is_directory(const std::string& path);
bool make_dirs(const std::string& path, unsigned mode, std::string* err);
bool remove_file(const std::string& path);
std::string dirname_of(const std::string& path);
std::string basename_of(const std::string& path);

// ---------- 地址 ----------
bool parse_ip(const std::string& s, bool& is_v6);
bool parse_cidr(const std::string& s, std::string& canon, bool& is_v6);
bool is_ip_literal(const std::string& s);
bool is_cidr_literal(const std::string& s);
bool looks_like_domain(const std::string& s);
std::string normalize_ip(const std::string& s);   // 规范化，失败返回空串
std::string normalize_domain(const std::string& s);
bool cidr_contains(const std::string& cidr, const std::string& ip);

// ---------- 时间 ----------
bool parse_duration(const std::string& s, int64_t& seconds);
std::string format_duration(int64_t seconds);
int64_t now_epoch();
std::string format_epoch(int64_t epoch, const char* fmt = "%Y-%m-%d %H:%M:%S");
std::string iso_now();

// ---------- 杂项 ----------
bool is_root();
std::string self_exe_path();
std::string human_bytes(uint64_t n);
std::string human_number(uint64_t n);
bool parse_u64(const std::string& s, uint64_t& out);

}  // namespace util
