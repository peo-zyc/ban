#include "json.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// ============================ 构造 ============================

Json Json::boolean(bool b) {
    Json j;
    j.type_ = Type::Bool;
    j.bool_ = b;
    return j;
}

Json Json::number(double d) {
    Json j;
    j.type_ = Type::Number;
    j.num_ = d;
    return j;
}

Json Json::integer(int64_t v) {
    Json j;
    j.type_ = Type::Number;
    j.num_ = static_cast<double>(v);
    return j;
}

Json Json::uinteger(uint64_t v) {
    Json j;
    j.type_ = Type::Number;
    j.num_ = static_cast<double>(v);
    return j;
}

Json Json::string(const std::string& s) {
    Json j;
    j.type_ = Type::String;
    j.str_ = s;
    return j;
}

Json Json::array() {
    Json j;
    j.type_ = Type::Array;
    return j;
}

Json Json::object() {
    Json j;
    j.type_ = Type::Object;
    return j;
}

// ============================ 访问 ============================

bool Json::as_bool(bool def) const {
    if (type_ == Type::Bool) return bool_;
    if (type_ == Type::Number) return num_ != 0.0;
    return def;
}

double Json::as_double(double def) const {
    if (type_ == Type::Number) return num_;
    if (type_ == Type::String) return std::atof(str_.c_str());
    return def;
}

int64_t Json::as_int(int64_t def) const {
    if (type_ == Type::Number) return static_cast<int64_t>(num_);
    if (type_ == Type::String) return static_cast<int64_t>(std::atoll(str_.c_str()));
    return def;
}

uint64_t Json::as_uint(uint64_t def) const {
    if (type_ == Type::Number) return num_ <= 0 ? 0 : static_cast<uint64_t>(num_);
    if (type_ == Type::String) return static_cast<uint64_t>(std::strtoull(str_.c_str(), nullptr, 10));
    return def;
}

std::string Json::as_string(const std::string& def) const {
    if (type_ == Type::String) return str_;
    return def;
}

size_t Json::size() const {
    if (type_ == Type::Array) return arr_.size();
    if (type_ == Type::Object) return obj_.size();
    return 0;
}

const Json& Json::at(size_t i) const {
    static const Json kNull;
    if (type_ != Type::Array || i >= arr_.size()) return kNull;
    return arr_[i];
}

const Json* Json::find(const std::string& key) const {
    if (type_ != Type::Object) return nullptr;
    for (const auto& kv : obj_) {
        if (kv.first == key) return &kv.second;
    }
    return nullptr;
}

Json& Json::set(const std::string& key, Json value) {
    if (type_ != Type::Object) {
        type_ = Type::Object;
        arr_.clear();
    }
    for (auto& kv : obj_) {
        if (kv.first == key) {
            kv.second = std::move(value);
            return *this;
        }
    }
    obj_.emplace_back(key, std::move(value));
    return *this;
}

Json& Json::push(Json value) {
    if (type_ != Type::Array) {
        type_ = Type::Array;
        obj_.clear();
    }
    arr_.push_back(std::move(value));
    return *this;
}

// ============================ 序列化 ============================

std::string Json::quote(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
    return out;
}

void Json::dump_into(std::string& out, int indent, int depth) const {
    const bool pretty = indent >= 0;
    auto newline = [&](int d) {
        if (!pretty) return;
        out.push_back('\n');
        out.append(static_cast<size_t>(indent * d), ' ');
    };

    switch (type_) {
        case Type::Null:
            out += "null";
            break;
        case Type::Bool:
            out += bool_ ? "true" : "false";
            break;
        case Type::Number: {
            double v = num_;
            if (std::isfinite(v) && v == std::floor(v) && std::fabs(v) < 9.0e15) {
                char buf[32];
                std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
                out += buf;
            } else {
                char buf[40];
                std::snprintf(buf, sizeof(buf), "%.17g", v);
                out += buf;
            }
            break;
        }
        case Type::String:
            out += quote(str_);
            break;
        case Type::Array: {
            out.push_back('[');
            for (size_t i = 0; i < arr_.size(); ++i) {
                if (i) out.push_back(',');
                newline(depth + 1);
                arr_[i].dump_into(out, indent, depth + 1);
            }
            if (!arr_.empty()) newline(depth);
            out.push_back(']');
            break;
        }
        case Type::Object: {
            out.push_back('{');
            for (size_t i = 0; i < obj_.size(); ++i) {
                if (i) out.push_back(',');
                newline(depth + 1);
                out += quote(obj_[i].first);
                out.push_back(':');
                if (pretty) out.push_back(' ');
                obj_[i].second.dump_into(out, indent, depth + 1);
            }
            if (!obj_.empty()) newline(depth);
            out.push_back('}');
            break;
        }
    }
}

std::string Json::dump(int indent) const {
    std::string out;
    dump_into(out, indent, 0);
    return out;
}

// ============================ 解析 ============================

namespace {

class Parser {
public:
    explicit Parser(const std::string& text) : t_(text), i_(0) {}

    bool parse_document(Json& out, std::string& err) {
        ws();
        if (!parse_value(out, err)) return false;
        ws();
        if (i_ != t_.size()) return fail(err, "末尾存在多余内容");
        return true;
    }

private:
    const std::string& t_;
    size_t i_;

    void ws() {
        while (i_ < t_.size()) {
            char c = t_[i_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                ++i_;
            } else {
                break;
            }
        }
    }

    bool fail(std::string& err, const char* msg) {
        err = std::string(msg) + " (位置 " + std::to_string(i_) + ")";
        return false;
    }

    bool parse_value(Json& out, std::string& err) {
        ws();
        if (i_ >= t_.size()) return fail(err, "意外的结尾");
        char c = t_[i_];
        if (c == '{') return parse_object(out, err);
        if (c == '[') return parse_array(out, err);
        if (c == '"') {
            std::string s;
            if (!parse_string(s, err)) return false;
            out = Json::string(s);
            return true;
        }
        if (c == 't') {
            if (t_.compare(i_, 4, "true") == 0) {
                i_ += 4;
                out = Json::boolean(true);
                return true;
            }
            return fail(err, "非法字面量");
        }
        if (c == 'f') {
            if (t_.compare(i_, 5, "false") == 0) {
                i_ += 5;
                out = Json::boolean(false);
                return true;
            }
            return fail(err, "非法字面量");
        }
        if (c == 'n') {
            if (t_.compare(i_, 4, "null") == 0) {
                i_ += 4;
                out = Json();
                return true;
            }
            return fail(err, "非法字面量");
        }
        if (c == '-' || (c >= '0' && c <= '9')) return parse_number(out, err);
        return fail(err, "非法字符");
    }

    bool parse_number(Json& out, std::string& err) {
        size_t start = i_;
        if (i_ < t_.size() && t_[i_] == '-') ++i_;
        while (i_ < t_.size() && t_[i_] >= '0' && t_[i_] <= '9') ++i_;
        if (i_ < t_.size() && t_[i_] == '.') {
            ++i_;
            while (i_ < t_.size() && t_[i_] >= '0' && t_[i_] <= '9') ++i_;
        }
        if (i_ < t_.size() && (t_[i_] == 'e' || t_[i_] == 'E')) {
            ++i_;
            if (i_ < t_.size() && (t_[i_] == '+' || t_[i_] == '-')) ++i_;
            while (i_ < t_.size() && t_[i_] >= '0' && t_[i_] <= '9') ++i_;
        }
        if (i_ == start) return fail(err, "非法数字");
        std::string num = t_.substr(start, i_ - start);
        out = Json::number(std::strtod(num.c_str(), nullptr));
        return true;
    }

    static void append_utf8(std::string& out, unsigned int cp) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    bool parse_hex4(unsigned int& out, std::string& err) {
        if (i_ + 4 > t_.size()) return fail(err, "\\u 转义不完整");
        out = 0;
        for (int k = 0; k < 4; ++k) {
            char c = t_[i_ + static_cast<size_t>(k)];
            out <<= 4;
            if (c >= '0' && c <= '9') {
                out |= static_cast<unsigned int>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                out |= static_cast<unsigned int>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                out |= static_cast<unsigned int>(c - 'A' + 10);
            } else {
                return fail(err, "\\u 转义非法");
            }
        }
        i_ += 4;
        return true;
    }

    bool parse_string(std::string& out, std::string& err) {
        if (i_ >= t_.size() || t_[i_] != '"') return fail(err, "期望字符串");
        ++i_;
        out.clear();
        while (i_ < t_.size()) {
            char c = t_[i_++];
            if (c == '"') return true;
            if (c != '\\') {
                out.push_back(c);
                continue;
            }
            if (i_ >= t_.size()) return fail(err, "转义不完整");
            char e = t_[i_++];
            switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    unsigned int cp = 0;
                    if (!parse_hex4(cp, err)) return false;
                    if (cp >= 0xD800 && cp <= 0xDBFF && i_ + 6 <= t_.size() &&
                        t_[i_] == '\\' && t_[i_ + 1] == 'u') {
                        i_ += 2;
                        unsigned int lo = 0;
                        if (!parse_hex4(lo, err)) return false;
                        if (lo >= 0xDC00 && lo <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        } else {
                            append_utf8(out, cp);
                            cp = lo;
                        }
                    }
                    append_utf8(out, cp);
                    break;
                }
                default:
                    return fail(err, "未知转义");
            }
        }
        return fail(err, "字符串未闭合");
    }

    bool parse_array(Json& out, std::string& err) {
        ++i_;  // [
        out = Json::array();
        ws();
        if (i_ < t_.size() && t_[i_] == ']') {
            ++i_;
            return true;
        }
        while (true) {
            Json v;
            if (!parse_value(v, err)) return false;
            out.push(std::move(v));
            ws();
            if (i_ >= t_.size()) return fail(err, "数组未闭合");
            if (t_[i_] == ',') {
                ++i_;
                continue;
            }
            if (t_[i_] == ']') {
                ++i_;
                return true;
            }
            return fail(err, "数组期望 , 或 ]");
        }
    }

    bool parse_object(Json& out, std::string& err) {
        ++i_;  // {
        out = Json::object();
        ws();
        if (i_ < t_.size() && t_[i_] == '}') {
            ++i_;
            return true;
        }
        while (true) {
            ws();
            std::string key;
            if (!parse_string(key, err)) return false;
            ws();
            if (i_ >= t_.size() || t_[i_] != ':') return fail(err, "对象期望 :");
            ++i_;
            Json v;
            if (!parse_value(v, err)) return false;
            out.set(key, std::move(v));
            ws();
            if (i_ >= t_.size()) return fail(err, "对象未闭合");
            if (t_[i_] == ',') {
                ++i_;
                continue;
            }
            if (t_[i_] == '}') {
                ++i_;
                return true;
            }
            return fail(err, "对象期望 , 或 }");
        }
    }
};

}  // namespace

bool Json::parse(const std::string& text, Json& out, std::string* err) {
    std::string local;
    Parser p(text);
    if (!p.parse_document(out, local)) {
        if (err) *err = local;
        return false;
    }
    return true;
}
