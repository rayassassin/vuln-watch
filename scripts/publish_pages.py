#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 web/ 下的全景看板发布到 GitHub Pages。

设计取舍 —— 为什么每次 force push 一个孤立 commit：
  data.json 现在几 MB，一天两次正常提交，一年下来仓库历史能涨到几个 GB。
  每次新建 orphan commit 再 force push，旧对象不进任何分支，GitHub 侧 GC 之后
  仓库体积稳定在「一份快照」的量级。代价是没有历史版本可回溯——
  这个页面本来也不需要，要历史就去 state.db 和服务器上的备份。

token 取值顺序（服务器上放在 0600 文件里，别写进仓库）：
  GH_PAGES_TOKEN  →  GITHUB_TOKEN  →  本机 gh auth token

用法：
  python3 scripts/publish_pages.py                 # 发布
  python3 scripts/publish_pages.py --dry-run       # 只组装，不推
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPO = "rayassassin/vuln-watch-pages"
DEFAULT_BRANCH = "gh-pages"


def sh(cmd: list[str], cwd: Path | None = None, quiet: bool = False) -> str:
    # 本机开发环境的 HTTP(S)_PROXY 会让 git 走 CONNECT 隧道，对 github.com 常返回 502。
    # git 直连即可，所以这里显式把代理摘掉；服务器上本来就没有这些变量，无副作用。
    env = dict(os.environ)
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                "ALL_PROXY", "all_proxy"):
        env.pop(key, None)
    env["GIT_TERMINAL_PROMPT"] = "0"

    r = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env,
                       capture_output=True, text=True)
    if r.returncode != 0:
        out = (r.stdout or "") + (r.stderr or "")
        # 千万别把带 token 的 URL 原样打出来
        raise RuntimeError(f"{' '.join(cmd[:3])} 失败：{out.strip()[:400]}")
    if not quiet:
        for line in (r.stdout or "").strip().splitlines():
            print(f"   {line}")
    return r.stdout or ""


def resolve_token() -> str:
    for key in ("GH_PAGES_TOKEN", "GITHUB_TOKEN"):
        val = os.environ.get(key, "").strip()
        if val:
            return val
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except Exception:  # noqa: BLE001
        raise SystemExit(
            "没有可用的 GitHub token。二选一：\n"
            "  · 本机：gh auth login\n"
            "  · 服务器：把 fine-grained PAT 写进 /opt/vuln-watch/.pages_token（chmod 600），\n"
            "    并在 cron 环境里 export GH_PAGES_TOKEN=$(cat ...)"
        )


def main() -> int:
    ap = argparse.ArgumentParser(description="发布全景看板到 GitHub Pages")
    ap.add_argument("--source", default=str(ROOT / "web"), help="web 目录")
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--branch", default=DEFAULT_BRANCH)
    ap.add_argument("--dry-run", action="store_true", help="只组装，不推送")
    args = ap.parse_args()

    src = Path(args.source)
    index, data = src / "index.html", src / "data.json"
    for f in (index, data):
        if not f.exists():
            raise SystemExit(f"缺少 {f}，先跑一次 collect.py 生成数据")

    size_mb = data.stat().st_size / 1024 / 1024
    print(f"发布源：{index.name} + {data.name}（{size_mb:.1f} MB）")

    token = "" if args.dry_run else resolve_token()
    with tempfile.TemporaryDirectory(prefix="vuln-pages-") as tmp:
        work = Path(tmp)
        sh(["git", "init", "-q", "-b", args.branch], cwd=work)
        shutil.copy2(index, work / "index.html")
        shutil.copy2(data, work / "data.json")
        # .nojekyll：不加的话 GitHub 会走 Jekyll，下划线开头的文件会被吞
        (work / ".nojekyll").write_text("", encoding="utf-8")
        # 顶层 index.html 已经是看板本体，data.json 用相对路径取，Pages 子路径下也能跑

        sh(["git", "add", "-A"], cwd=work)
        sh(["git", "-c", "user.name=vuln-watch", "-c", "user.email=vuln-watch@local",
            "commit", "-q", "-m",
            f"publish {datetime.now().strftime('%Y-%m-%d %H:%M')} "
            f"({data.stat().st_size // 1024} KB)"], cwd=work, quiet=True)

        if args.dry_run:
            print(f"[dry-run] 已组装到 {work}，未推送")
            for f in sorted(work.iterdir()):
                if f.name != ".git":
                    print(f"   {f.name}")
            return 0

        url = f"https://x-access-token:{token}@github.com/{args.repo}.git"
        print(f"推送到 {args.repo} / {args.branch} …")
        sh(["git", "push", "-q", "--force", url, f"HEAD:{args.branch}"], cwd=work)

    print(f"\n✅ 已发布：https://{args.repo.split('/')[0]}.github.io/"
          f"{args.repo.split('/')[1]}/")
    print("   Pages 首次构建要 1-2 分钟，之后每次发布约 30 秒生效")
    return 0


if __name__ == "__main__":
    sys.exit(main())
