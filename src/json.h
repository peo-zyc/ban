#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// 极简 JSON 实现（无第三方依赖）。
// 用于：解析 `nft -j` 输出、持久化解析结果缓存、import/export。
class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Json() : type_(Type::Null), bool_(false), num_(0) {}

    static Json boolean(bool b);
    static Json number(double d);
    static Json integer(int64_t v);
    static Json uinteger(uint64_t v);
    static Json string(const std::string& s);
    static Json array();
    static Json object();

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_bool() const { return type_ == Type::Bool; }
    bool is_number() const { return type_ == Type::Number; }
    bool is_string() const { return type_ == Type::String; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_object() const { return type_ == Type::Object; }

    bool as_bool(bool def = false) const;
    double as_double(double def = 0.0) const;
    int64_t as_int(int64_t def = 0) const;
    uint64_t as_uint(uint64_t def = 0) const;
    std::string as_string(const std::string& def = std::string()) const;

    size_t size() const;
    const Json& at(size_t i) const;
    const Json* find(const std::string& key) const;
    Json& set(const std::string& key, Json value);
    Json& push(Json value);

    std::string dump(int indent = -1) const;
    static bool parse(const std::string& text, Json& out, std::string* err = nullptr);

private:
    Type type_;
    bool bool_;
    double num_;
    std::string str_;
    std::vector<Json> arr_;
    std::vector<std::pair<std::string, Json>> obj_;

    void dump_into(std::string& out, int indent, int depth) const;
    static std::string quote(const std::string& s);
};
