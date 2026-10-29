#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 main 分支 fast-forward 到本地 HEAD —— 本机 git push 被代理挡掉时的兜底。

为什么需要它：本机 git push 走系统代理（HTTP_PROXY 指向本地端口），代理链路
对 github.com 经常返回 CONNECT tunnel failed 502 / Empty reply，直连又连不上
github.com:443。但 api.github.com 是通的（发布 gh-pages 一直走这里）。
所以用 Git Data API 复刻一次 fast-forward push：

  拿远端 main 的 tree 当 base_tree → 上传改动文件的 blob → 生成新 tree →
  建「带父节点」的 commit → PATCH main ref（force=False 保证不会意外覆盖别人）。

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
import publish_pages as pp  # noqa: E402  复用 api / blob / tree 的口径

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


def changed_files(base: str) -> list[tuple[str, str]]:
    """本地 HEAD 相对 base 的变化，返回 (状态, 路径)。状态 M/A/D。"""
    out = subprocess.run(["git", "diff", "--name-status", base, "HEAD"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [tuple(line.split("\t")) for line in out.splitlines() if "\t" in line]


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

    changes = changed_files(old_sha)
    if not changes:
        print("没有文件变化（可能只是 commit message 不同）")
        return 0

    entries: list[dict] = []
    for status, path in changes:
        p = ROOT / path
        if status == "D":
            entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
        elif p.exists():
            blob = pp.make_blob(REPO, p.read_bytes(), token)
            mode = "100755" if p.stat().st_mode & 0o111 else "100644"
            entries.append({"path": path, "mode": mode, "type": "blob", "sha": blob})
        else:
            print(f"跳过无法处理的 {status} {path}")
    if not entries:
        print("没有可上传的文件")
        return 0

    msg = subprocess.run(["git", "log", "-1", "--format=%s", "HEAD"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout.strip()
    print(f"main: {old_sha[:7]} → {head[:7]}  「{msg}」")
    print(f"  改动 {len(changes)} 个文件：{'、'.join(s for _, s in changes)}")
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
