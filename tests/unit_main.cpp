// 轻量单元测试：不引入第三方测试框架，失败即返回非 0。
#include <cstdio>
#include <string>
#include <vector>

#include "json.h"
#include "model.h"
#include "util.h"

static int g_failed = 0;
static int g_total = 0;

static void check(bool cond, const std::string& what) {
    ++g_total;
    if (!cond) {
        ++g_failed;
        std::printf("FAIL: %s\n", what.c_str());
    }
}

static void test_ip() {
    bool v6 = false;
    check(util::parse_ip("1.2.3.4", v6) && !v6, "parse_ip v4");
    check(util::parse_ip("::1", v6) && v6, "parse_ip v6");
    check(!util::parse_ip("1.2.3.256", v6), "parse_ip invalid");
    check(!util::parse_ip("example.com", v6), "parse_ip domain rejected");

    std::string canon;
    check(util::parse_cidr("10.1.2.3/8", canon, v6) && canon == "10.0.0.0/8" && !v6,
          "parse_cidr mask v4");
    check(util::parse_cidr("2001:db8::1/32", canon, v6) && canon == "2001:db8::/32" && v6,
          "parse_cidr mask v6");
    check(!util::parse_cidr("10.0.0.0/33", canon, v6), "parse_cidr prefix range");
    check(!util::parse_cidr("10.0.0.0", canon, v6), "parse_cidr requires slash");

    check(util::cidr_contains("192.168.0.0/16", "192.168.5.7"), "cidr_contains true");
    check(!util::cidr_contains("192.168.0.0/16", "10.0.0.1"), "cidr_contains false");
    check(util::cidr_contains("10.0.0.0/8", "10.255.255.255"), "cidr_contains boundary");
}

static void test_domain() {
    check(util::normalize_domain("Example.COM.") == "example.com", "normalize_domain");
    check(util::normalize_domain("bad/name").empty(), "normalize_domain rejects slash");
    check(util::looks_like_domain("a-b.example.com"), "looks_like_domain");
    check(!util::looks_like_domain("1.2.3.4"), "looks_like_domain rejects ip");
}

static void test_duration() {
    int64_t s = 0;
    check(util::parse_duration("30m", s) && s == 1800, "duration 30m");
    check(util::parse_duration("1h30m", s) && s == 5400, "duration 1h30m");
    check(util::parse_duration("7d", s) && s == 604800, "duration 7d");
    check(util::parse_duration("permanent", s) && s == 0, "duration permanent");
    check(!util::parse_duration("abc", s), "duration invalid");
    check(util::format_duration(5400) == "1h 30m", "format_duration");
}

static void test_json() {
    const std::string text =
        "{\"nftables\":[{\"set\":{\"name\":\"banned_v4\",\"elem\":[\"1.2.3.4\"]}},"
        "{\"rule\":{\"expr\":[{\"counter\":{\"packets\":7,\"bytes\":420}},{\"drop\":null}]}}]}";
    Json root;
    std::string err;
    check(Json::parse(text, root, &err), "json parse: " + err);

    const Json* arr = root.find("nftables");
    check(arr && arr->is_array() && arr->size() == 2, "json array size");
    if (arr && arr->size() == 2) {
        const Json* set = arr->at(0).find("set");
        check(set && set->find("name")->as_string() == "banned_v4", "json set name");
        check(set->find("elem")->size() == 1, "json set elem count");

        const Json* rule = arr->at(1).find("rule");
        const Json* exprs = rule ? rule->find("expr") : nullptr;
        check(exprs && exprs->size() == 2, "json rule exprs");
        if (exprs && exprs->size() == 2) {
            const Json* c = exprs->at(0).find("counter");
            check(c && c->find("packets")->as_uint() == 7, "json counter packets");
            check(exprs->at(1).find("drop") != nullptr, "json drop expr");
        }
    }

    Json o = Json::object();
    o.set("a", Json::integer(1));
    o.set("b", Json::string("x\"y"));
    Json round;
    std::string err2;
    check(Json::parse(o.dump(), round, &err2), "json roundtrip parse");
    check(round.find("b")->as_string() == "x\"y", "json escape roundtrip");

    check(!Json::parse("{", round, &err2), "json rejects truncated");
}

static void test_rule_roundtrip() {
    Rule r;
    r.id = 3;
    r.type = RuleType::Domain;
    r.value = "example.com";
    r.created_at = 100;
    r.expires_at = 200;
    r.comment = "test\tcomment";

    Rule back;
    check(Rule::deserialize(r.serialize(), back), "rule deserialize");
    check(back.id == 3 && back.type == RuleType::Domain && back.value == "example.com" &&
              back.expires_at == 200,
          "rule roundtrip fields");
    check(back.comment.find('\t') == std::string::npos, "rule comment tab sanitized");

    AllowEntry a;
    a.cidr = "10.0.0.0/8";
    a.comment = "lan";
    AllowEntry ab;
    check(AllowEntry::deserialize(a.serialize(), ab) && ab.cidr == "10.0.0.0/8", "allow roundtrip");
}

int main() {
    test_ip();
    test_domain();
    test_duration();
    test_json();
    test_rule_roundtrip();

    std::printf("%d/%d 通过\n", g_total - g_failed, g_total);
    return g_failed == 0 ? 0 : 1;
}
