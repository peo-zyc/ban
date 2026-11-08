#!/usr/bin/env python3
"""通过 GitHub Git Data API 推送当前 HEAD（当 github.com:443 的 git 传输不可用、
但 api.github.com 正常时的替代方案）。

原理：用 base_tree 重建同一棵树，并复用本地提交的 author/committer 元数据，
使远端生成的 commit SHA 与本地完全一致。

用法:
    GH_TOKEN=xxx python3 packaging/api-push.py v1.0.1 [--base origin/main]
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
    url = path if path.startswith("http") else API + path
    data = json.dumps(payload, ensure_ascii=False).encode() if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + TOKEN,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ban-api-push",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode("utf-8", "replace")}


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else None
    base_ref = "origin/main"
    if "--base" in sys.argv:
        base_ref = sys.argv[sys.argv.index("--base") + 1]

    head = git("rev-parse", "HEAD").strip()
    head_tree = git("rev-parse", "HEAD^{tree}").strip()
    base = git("rev-parse", base_ref).strip()
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

    st, base_commit = call("GET", f"/repos/{REPO}/git/commits/{base}")
    if st != 200:
        sys.exit(f"读取基线提交失败: {base_commit}")
    base_tree = base_commit["tree"]["sha"]

    diff = git("diff", "--name-status", "--no-renames", f"{base}..HEAD").strip()
    if not diff:
        print("没有需要推送的改动")
        return

    entries = []
    for line in diff.splitlines():
        status, path = line.split("\t", 1)
        if status == "D":
            entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
            continue
        with open(path, "rb") as f:
            content = base64.b64encode(f.read()).decode()
        st, blob = call("POST", f"/repos/{REPO}/git/blobs", {"content": content, "encoding": "base64"})
        if st not in (200, 201):
            sys.exit(f"上传 blob 失败 {path}: {blob}")
        ls = git("ls-tree", "HEAD", "--", path).split()
        mode = ls[0] if ls else "100644"
        entries.append({"path": path, "mode": mode, "type": "blob", "sha": blob["sha"]})
        print(f"  blob {path} -> {blob['sha'][:12]} ({mode})")

    st, tree = call("POST", f"/repos/{REPO}/git/trees", {"base_tree": base_tree, "tree": entries})
    if st not in (200, 201):
        sys.exit(f"创建 tree 失败: {tree}")
    if tree["sha"] != head_tree:
        sys.exit(f"tree 不一致: 远端 {tree['sha']} != 本地 {head_tree}")
    print(f"  tree {tree['sha']} 与本地一致")

    st, commit = call(
        "POST",
        f"/repos/{REPO}/git/commits",
        {
            "message": message,
            "tree": tree["sha"],
            "parents": [base],
            "author": author,
            "committer": committer,
        },
    )
    if st not in (200, 201):
        sys.exit(f"创建 commit 失败: {commit}")
    if commit["sha"] != head:
        print(f"警告: 远端 commit {commit['sha']} 与本地 {head} 不同（内容一致）")
    else:
        print(f"  commit {commit['sha']} 与本地一致")

    force = "--force" in sys.argv
    st, res = call("PATCH", f"/repos/{REPO}/git/refs/heads/main", {"sha": commit["sha"], "force": force})
    if st not in (200, 201):
        sys.exit(f"更新 main 失败: {res}")
    print(f"  main -> {commit['sha'][:12]}")

    if tag:
        msg = git("for-each-ref", f"refs/tags/{tag}", "--format=%(contents)").rstrip("\n")
        tagger = {
            "name": git("for-each-ref", f"refs/tags/{tag}", "--format=%(taggername)").strip(),
            "email": git("for-each-ref", f"refs/tags/{tag}", "--format=%(taggeremail)").strip().strip("<>"),
            "date": git("for-each-ref", f"refs/tags/{tag}", "--format=%(taggerdate:iso-strict)").strip(),
        }
        st, tobj = call(
            "POST",
            f"/repos/{REPO}/git/tags",
            {"tag": tag, "message": msg or tag, "object": commit["sha"], "type": "commit", "tagger": tagger},
        )
        if st not in (200, 201):
            sys.exit(f"创建 tag 失败: {tobj}")
        st, r = call("POST", f"/repos/{REPO}/git/refs", {"ref": f"refs/tags/{tag}", "sha": tobj["sha"]})
        if st == 422:
            st, r = call(
                "PATCH",
                f"/repos/{REPO}/git/refs/tags/{tag}",
                {"sha": tobj["sha"], "force": force},
            )
        if st not in (200, 201):
            sys.exit(f"创建 tag ref 失败: {r}")
        print(f"  tag {tag} -> {tobj['sha'][:12]}")

    print("完成")


if __name__ == "__main__":
    main()
