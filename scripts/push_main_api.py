#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 main 分支 fast-forward 到本地 HEAD —— 本机 git push 被代理挡掉时的兜底。

为什么需要它：本机 git push 走系统代理（HTTP_PROXY 指向本地端口），代理链路
对 github.com 经常返回 CONNECT tunnel failed 502 / Empty reply，直连又连不上
github.com:443。但 api.github.com 是通的（发布 gh-pages 一直走这里）。
所以用 Git Data API 复刻一次 fast-forward push：

  拿远端 main 的 tree（递归）→ 和本地 HEAD 的 tree 逐文件比对 →
  只上传新增/变化的 blob → 生成新 tree（base_tree = 远端旧树）→
  建「带父节点」的 commit → PATCH main ref（force=False 保证不覆盖别人）。

为什么对比「远端 tree」而不是 git diff：
  用 git diff 需要本地有远端的 commit/tree 对象；本机 push 失败时往往
  git fetch 也被同一个代理挡掉，本地根本没有远端对象。用 API 直接拉
  远端的 tree 清单，再和本地工作区算出来的 blob sha 对比，完全脱离本地
  git 对远端对象的依赖，任何状态下都能算出「到底该传哪几个文件」。

和 publish_pages.py 的区别：
  publish_pages 是「孤立 commit + 完整快照」，推到 gh-pages 分支；
  这里是「带父节点的增量提交」，推到 main 分支，等价于 git push 的 fast-forward。

用法：
    python3 scripts/push_main_api.py            # 把 origin/main 推到本地 HEAD
    python3 scripts/push_main_api.py --dry-run  # 只打印会做什么，不真的推
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import publish_pages as pp  # noqa: E402  复用 api / blob / local_blob_sha

REPO = "rayassassin/vuln-watch"
BRANCH = "main"
ROOT = Path(__file__).resolve().parent.parent


def get_token() -> str:
    """优先 git credential（本机 keychain），退到 gh，再退到发布用的 PAT。"""
    try:
        out = subprocess.run(
            ["git", "credential", "fill"],
            input=b"protocol=https\nhost=github.com\n\n",
            capture_output=True, timeout=20,
        ).stdout.decode("utf-8", "replace")
        for line in out.splitlines():
            if line.startswith("password="):
                return line.split("=", 1)[1].strip()
    except Exception:  # noqa: BLE001
        pass
    return pp.resolve_token()


def local_head() -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True, check=True).stdout.strip()


def local_tree() -> dict[str, tuple[str, bytes]]:
    """本地 HEAD 的 {路径: (blob_sha, 内容)}。只含 git 跟踪的文件。"""
    paths = subprocess.run(["git", "ls-tree", "-r", "--name-only", "HEAD"],
                           cwd=ROOT, capture_output=True, text=True,
                           check=True).stdout.split()
    out: dict[str, tuple[str, bytes]] = {}
    for p in paths:
        data = (ROOT / p).read_bytes()
        out[p] = (pp.local_blob_sha(data), data)
    return out


def remote_tree(tree_sha: str, token: str) -> dict[str, str]:
    """远端某 tree 的 {路径: blob_sha}。递归拉一次。"""
    data = pp.api("GET", f"/repos/{REPO}/git/trees/{tree_sha}?recursive=1", token)
    return {e["path"]: e["sha"] for e in data.get("tree", []) if e.get("type") == "blob"}


def main() -> int:
    ap = argparse.ArgumentParser(description="main 分支 fast-forward 兜底")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    token = get_token()
    head = local_head()

    ref = pp.api("GET", f"/repos/{REPO}/git/refs/heads/{BRANCH}", token)
    old_sha = ref["object"]["sha"]
    if old_sha == head:
        print("已是最新，无需推送")
        return 0
    old_tree = pp.api("GET", f"/repos/{REPO}/git/commits/{old_sha}", token)["tree"]["sha"]

    remote = remote_tree(old_tree, token)
    local = local_tree()

    entries: list[dict] = []
    changed: list[str] = []
    for path, (lsha, data) in local.items():
        if remote.get(path) != lsha:
            blob = pp.make_blob(REPO, data, token)
            mode = "100755" if (ROOT / path).stat().st_mode & 0o111 else "100644"
            entries.append({"path": path, "mode": mode, "type": "blob", "sha": blob})
            changed.append("+" + path)
    for path in remote:
        if path not in local:
            entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
            changed.append("-" + path)

    if not entries:
        print("内容无差异（本地与远端 tree 相同），无需推送")
        return 0

    msg = subprocess.run(["git", "log", "-1", "--format=%s", "HEAD"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout.strip()
    print(f"main: {old_sha[:7]} → {head[:7]}  「{msg}」")
    print(f"  变化 {len(changed)} 项：{'、'.join(changed)}")
    if args.dry_run:
        print("--dry-run：未推送")
        return 0

    new_tree = pp.api("POST", f"/repos/{REPO}/git/trees", token,
                      {"base_tree": old_tree, "tree": entries})["sha"]
    new_commit = pp.api("POST", f"/repos/{REPO}/git/commits", token,
                        {"message": msg, "tree": new_tree, "parents": [old_sha]})["sha"]
    pp.api("PATCH", f"/repos/{REPO}/git/refs/heads/{BRANCH}", token,
           {"sha": new_commit, "force": False})
    print(f"✅ main 已推到 {new_commit[:7]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
