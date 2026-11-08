#!/usr/bin/env python3
"""把 dist/ 下的产物上传到 GitHub Release。

用法:
    GH_TOKEN=xxx python3 packaging/upload-release.py v1.0.0

环境变量:
    GH_TOKEN / GITHUB_TOKEN  GitHub token（必需，不会被打印）
    REPO                     默认 peo-zyc/ban
    DIST                     默认 dist
    NOTES                    默认 CHANGELOG.md
"""
import json
import mimetypes
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
UPLOADS = "https://uploads.github.com"

TOKEN = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
if not TOKEN:
    sys.exit("错误: 缺少 GH_TOKEN 环境变量")

REPO = os.environ.get("REPO", "peo-zyc/ban")
DIST = os.environ.get("DIST", "dist")
NOTES = os.environ.get("NOTES", "CHANGELOG.md")
TAG = sys.argv[1] if len(sys.argv) > 1 else "v1.0.0"


def call(method, url, data=None, ctype="application/json"):
    headers = {
        "Authorization": "Bearer " + TOKEN,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ban-release-script",
    }
    if data is not None:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode("utf-8", "replace")}


# 1) 创建 release（已存在则复用）
body = ""
if os.path.exists(NOTES):
    with open(NOTES, encoding="utf-8") as f:
        body = f.read()

payload = json.dumps(
    {
        "tag_name": TAG,
        "name": "ban " + TAG,
        "body": body,
        "draft": False,
        "prerelease": False,
    },
    ensure_ascii=False,
).encode("utf-8")

status, rel = call("POST", f"{API}/repos/{REPO}/releases", payload)
if status == 422:
    st2, rel = call("GET", f"{API}/repos/{REPO}/releases/tags/{TAG}")
    if st2 != 200:
        sys.exit(f"创建 release 失败: {rel}")
    print(f"release 已存在，复用 id={rel['id']}")
    # 同步标题与正文，避免 CHANGELOG 更新后 Release 仍是旧内容
    patch = json.dumps(
        {"name": "ban " + TAG, "body": body}, ensure_ascii=False
    ).encode("utf-8")
    st3, updated = call("PATCH", f"{API}/repos/{REPO}/releases/{rel['id']}", patch)
    if st3 in (200, 201):
        rel = updated
        print("release 正文已同步")
    else:
        print(f"警告: 更新 release 正文失败 ({st3})")
elif status not in (200, 201):
    sys.exit(f"创建 release 失败 ({status}): {rel}")
else:
    print(f"release 已创建: {rel['html_url']}")

release_id = rel["id"]
asset_ids = {a["name"]: a["id"] for a in rel.get("assets", [])}
REPLACE = os.environ.get("REPLACE", "") not in ("", "0", "false", "no")

# 2) 上传 dist/ 下所有文件
if not os.path.isdir(DIST):
    sys.exit(f"错误: 目录不存在 {DIST}")

for name in sorted(os.listdir(DIST)):
    path = os.path.join(DIST, name)
    if not os.path.isfile(path):
        continue
    if name in asset_ids:
        if not REPLACE:
            print(f"  - {name}: 已存在，跳过")
            continue
        st_del, _ = call(
            "DELETE", f"{API}/repos/{REPO}/releases/assets/{asset_ids[name]}"
        )
        if st_del not in (200, 204):
            print(f"  - {name}: 删除旧资产失败 ({st_del})")
            continue
        print(f"  - {name}: 旧资产已删除，重新上传")
    with open(path, "rb") as f:
        data = f.read()
    ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
    url = (
        f"{UPLOADS}/repos/{REPO}/releases/{release_id}/assets"
        f"?name={urllib.parse.quote(name)}"
    )
    st, res = call("POST", url, data, ctype)
    if st not in (200, 201):
        print(f"  - {name}: 上传失败 ({st}) {res}")
    else:
        print(f"  - {name}: 已上传 {len(data)} 字节")

print(rel["html_url"])
