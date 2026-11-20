#!/usr/bin/env python3
"""通过 GitHub Git Data API 推送 HEAD，且无需本地存在 base commit。

与 api-push.py 的区别：base 由 `--base-sha <sha>` 指定，改动集合通过
「远端 tree (API) vs 本地 tree (git ls-tree)」比对得出，因此不需要 fetch。

用法:
    GH_TOKEN=xxx python3 packaging/api-push-tree.py v1.0.2 --base-sha 27ddeef...
"""
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"
TOKEN = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
if not TOKEN:
    sys.exit("错误: 缺少 GH_TOKEN")
REPO = os.environ.get("REPO", "peo-zyc/ban")


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def call(method, path, payload=None):
    data = json.dumps(payload, ensure_ascii=False).encode() if payload is not None else None
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + TOKEN,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ban-api-push-tree",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode("utf-8", "replace")}


def remote_blobs(tree_sha):
    st, t = call("GET", f"/repos/{REPO}/git/trees/{tree_sha}?recursive=1")
    if st != 200:
        sys.exit(f"读取远端 tree 失败: {t}")
    return {e["path"]: (e["sha"], e["mode"]) for e in t["tree"] if e.get("type") == "blob"}


def local_blobs():
    out = git("ls-tree", "-r", "HEAD")
    d = {}
    for line in out.splitlines():
        meta, path = line.split("\t", 1)
        mode, _typ, sha = meta.split()
        d[path] = (sha, mode)
    return d


def main():
    tag = None
    base_sha = None
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--base-sha":
            base_sha = args[i + 1]
            i += 2
        else:
            tag = args[i]
            i += 1
    if not base_sha:
        sys.exit("需要 --base-sha")

    st, base_commit = call("GET", f"/repos/{REPO}/git/commits/{base_sha}")
    if st != 200:
        sys.exit(f"读取 base commit 失败: {base_commit}")
    base_tree = base_commit["tree"]["sha"]

    rmt = remote_blobs(base_tree)
    loc = local_blobs()

    entries = []
    for path, (sha, mode) in sorted(loc.items()):
        if rmt.get(path, (None, None))[0] == sha:
            continue
        with open(path, "rb") as f:
            content = base64.b64encode(f.read()).decode()
        st, blob = call("POST", f"/repos/{REPO}/git/blobs", {"content": content, "encoding": "base64"})
        if st not in (200, 201):
            sys.exit(f"上传 blob 失败 {path}: {blob}")
        entries.append({"path": path, "mode": mode, "type": "blob", "sha": blob["sha"]})
        print(f"  blob {path} ({mode})")

    for path in sorted(set(rmt) - set(loc)):
        entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
        print(f"  del  {path}")

    if not entries:
        print("没有差异")
        return

    st, tree = call("POST", f"/repos/{REPO}/git/trees", {"base_tree": base_tree, "tree": entries})
    if st not in (200, 201):
        sys.exit(f"创建 tree 失败: {tree}")
    head_tree = git("rev-parse", "HEAD^{tree}").strip()
    if tree["sha"] != head_tree:
        sys.exit(f"tree 不一致: 远端 {tree['sha']} != 本地 {head_tree}")
    print(f"  tree {tree['sha']} 与本地一致")

    message = git("log", "-1", "--format=%B", "HEAD")
    author = {
        "name": git("log", "-1", "--format=%an").strip(),
        "email": git("log", "-1", "--format=%ae").strip(),
        "date": git("log", "-1", "--format=%aI").strip(),
    }
    committer = {
        "name": git("log", "-1", "--format=%cn").strip(),
        "email": git("log", "-1", "--format=%ce").strip(),
        "date": git("log", "-1", "--format=%cI").strip(),
    }
    st, commit = call(
        "POST",
        f"/repos/{REPO}/git/commits",
        {"message": message, "tree": tree["sha"], "parents": [base_sha],
         "author": author, "committer": committer},
    )
    if st not in (200, 201):
        sys.exit(f"创建 commit 失败: {commit}")
    print(f"  commit {commit['sha']}")

    st, res = call("PATCH", f"/repos/{REPO}/git/refs/heads/main",
                   {"sha": commit["sha"], "force": True})
    if st not in (200, 201):
        sys.exit(f"更新 main 失败: {res}")
    print("  main 已更新")

    if tag:
        msg = git("for-each-ref", f"refs/tags/{tag}", "--format=%(contents)").rstrip("\n")
        tagger = {
            "name": git("for-each-ref", f"refs/tags/{tag}", "--format=%(taggername)").strip(),
            "email": git("for-each-ref", f"refs/tags/{tag}", "--format=%(taggeremail)").strip().strip("<>"),
            "date": git("for-each-ref", f"refs/tags/{tag}", "--format=%(taggerdate:iso-strict)").strip(),
        }
        st, tobj = call("POST", f"/repos/{REPO}/git/tags",
                        {"tag": tag, "message": msg or tag, "object": commit["sha"],
                         "type": "commit", "tagger": tagger})
        if st not in (200, 201):
            sys.exit(f"创建 tag 失败: {tobj}")
        st, r = call("POST", f"/repos/{REPO}/git/refs",
                     {"ref": f"refs/tags/{tag}", "sha": tobj["sha"]})
        if st == 422:
            st, r = call("PATCH", f"/repos/{REPO}/git/refs/tags/{tag}",
                         {"sha": tobj["sha"], "force": True})
        if st not in (200, 201):
            sys.exit(f"更新 tag 失败: {r}")
        print(f"  tag {tag} 已更新")
    print("完成")


if __name__ == "__main__":
    main()
