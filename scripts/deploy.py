#!/usr/bin/env python3
"""把本机 repo 的 HEAD 同步到远端服务器。

设计取舍：
  只传 git 已跟踪的文件（git archive），服务器上的 state.db、.env、日志一律不动。
  这样「版本同步」是单向的、可重复的，不会本机覆盖服务器的运行状态。

  这个仓库是**公开**的，所以本文件里不出现任何主机、账号、密码、服务器路径：
    连接信息 → 环境变量 / 本机凭据文件（见 deploy.env.example）
    远程目录 → 同上，默认值只是本项目的通用约定
  传输靠同目录的 scripts/remote_put.exp（通用 expect 助手，不含任何密钥）。

用法：
    python3 scripts/deploy.py              # 同步 HEAD
    python3 scripts/deploy.py --check      # 只检查配置与连通性，不传文件
    python3 scripts/deploy.py --restart    # 同步后跑一次 --status 自检

配置来源（后者覆盖前者）：
    1. 本机凭据文件：$VW_SECRETS_FILE，默认 ~/.config/vuln-watch/deploy.env
    2. 进程环境变量

必需项：VW_SSH_HOST / VW_SSH_PORT / VW_SSH_USER / VW_SSH_PASS
可选项：VW_REMOTE_DIR（默认 /opt/vuln-watch）、VW_RELEASES_DIR、
        VW_WECOM_APP_ENV、VW_WECOM_FEEDS（自建应用通道的凭据与收件人来源）
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECT = ROOT / "scripts" / "remote_put.exp"
DEFAULT_SECRETS = Path.home() / ".config" / "vuln-watch" / "deploy.env"

REQUIRED = ("VW_SSH_HOST", "VW_SSH_PORT", "VW_SSH_USER", "VW_SSH_PASS")


def load_config() -> dict[str, str]:
    """凭据文件打底，环境变量覆盖。文件格式就是 KEY=VALUE，允许 # 注释。"""
    cfg: dict[str, str] = {}
    path = Path(os.environ.get("VW_SECRETS_FILE") or DEFAULT_SECRETS).expanduser()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    for k in ("VW_SSH_HOST", "VW_SSH_PORT", "VW_SSH_USER", "VW_SSH_PASS",
              "VW_REMOTE_DIR", "VW_RELEASES_DIR", "VW_WECOM_APP_ENV", "VW_WECOM_FEEDS"):
        if os.environ.get(k):
            cfg[k] = os.environ[k]

    # 兼容历史命名，避免已有凭据文件失效
    alias = {"ECS_HOST": "VW_SSH_HOST", "ECS_PORT": "VW_SSH_PORT",
             "ECS_USER": "VW_SSH_USER", "ECS_PASS": "VW_SSH_PASS"}
    for old, new in alias.items():
        if not cfg.get(new) and cfg.get(old):
            cfg[new] = cfg[old]

    missing = [k for k in REQUIRED if not cfg.get(k)]
    if missing:
        sys.exit(
            f"缺少配置：{', '.join(missing)}\n"
            f"  做法：把 scripts/deploy.env.example 复制到 {DEFAULT_SECRETS}\n"
            "       （chmod 600）并填好，或者直接 export 这些环境变量"
        )
    cfg.setdefault("VW_REMOTE_DIR", "/opt/vuln-watch")
    cfg.setdefault("VW_RELEASES_DIR", str(Path(cfg["VW_REMOTE_DIR"]).parent / "_releases"))
    return cfg


def run_expect(cfg: dict, *args: str) -> int:
    if not EXPECT.exists():
        sys.exit(f"缺少 {EXPECT}")
    env = dict(os.environ)
    env.update({k: cfg[k] for k in REQUIRED})
    proc = subprocess.run(["expect", "-f", str(EXPECT), *args],
                          env=env, capture_output=True, text=True)
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if out:
        print("   " + out.replace("\n", "\n   "))
    return proc.returncode


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def build_run_sh(cfg: dict) -> str:
    """服务器上的启动包装。可选段缺失时写成注释，不制造隐性故障。"""
    dest = cfg["VW_REMOTE_DIR"]
    lines = ["#!/bin/sh", "# 由 scripts/deploy.py 生成，每次部署会覆盖", "set -eu",
             "export WECOM_CHANNEL=app"]
    app_env = cfg.get("VW_WECOM_APP_ENV", "").strip()
    if app_env:
        lines.append(f'export WECOM_APP_ENV="{app_env}"')
    else:
        lines.append("# VW_WECOM_APP_ENV 未配置：自建应用通道会缺凭据")
    feeds = cfg.get("VW_WECOM_FEEDS", "").strip()
    if feeds:
        lines.append(
            f'export WX_TOUSER="$(python3 -c "import json;print(json.load(open(\'{feeds}\'))'
            f'.get(\'chat_id\',\'\'))" 2>/dev/null || true)"'
        )
    else:
        lines.append("# VW_WECOM_FEEDS 未配置：收件人退化为自动解析授权人")
    lines += [f"cd {dest}", 'exec python3 collect.py "$@"', ""]
    return "\n".join(lines)


def main() -> int:
    check_only = "--check" in sys.argv
    restart = "--restart" in sys.argv

    cfg = load_config()
    dest, rel = cfg["VW_REMOTE_DIR"], cfg["VW_RELEASES_DIR"]
    print(f"目标：{cfg['VW_SSH_USER']}@{cfg['VW_SSH_HOST']}:{cfg['VW_SSH_PORT']} → {dest}")

    if check_only:
        ok = run_expect(cfg, "run", "uname -sr; python3 -V; test -d %s && echo dir-ok" % dest)
        print("✅ 连通且目录存在" if ok == 0 else "❌ 连接或目录检查失败")
        return ok

    sha = git("rev-parse", "--short", "HEAD")
    dirty = git("status", "--porcelain")
    if dirty:
        print("⚠️  工作区有未提交改动，本次只同步已提交的 HEAD")
        for line in dirty.splitlines():
            print("   " + line)

    tar = f"/tmp/vuln-watch-{sha}.tar.gz"
    subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar.gz",
                    "-o", tar, "HEAD"], check=True)
    size = os.path.getsize(tar)
    print(f"打包 HEAD {sha} → {size} 字节")

    print("1/3 上传")
    if run_expect(cfg, "put", tar, f"{rel}/vuln-watch-{sha}.tar.gz") != 0:
        return 1

    print("2/3 解包（保留 state.db / .env / 日志）")
    cmd = (f"set -e; mkdir -p {dest} {rel}; "
           f"tar -xzf {rel}/vuln-watch-{sha}.tar.gz -C {dest}; "
           f"echo {sha} > {dest}/.version; "
           f"rm -f {rel}/vuln-watch-{sha}.tar.gz")
    if run_expect(cfg, "run", cmd) != 0:
        return 1

    print("3/3 写入启动包装与权限")
    local_run = "/tmp/vuln-watch-run.sh"
    Path(local_run).write_text(build_run_sh(cfg), encoding="utf-8")
    if run_expect(cfg, "put", local_run, f"{dest}/run.sh") != 0:
        return 1
    cmd = f"set -e; chmod 755 {dest}/run.sh; ls -1 {dest}; echo '--- version ---'; cat {dest}/.version"
    if run_expect(cfg, "run", cmd) != 0:
        return 1

    for f in (tar, local_run):
        try:
            os.unlink(f)
        except OSError:
            pass

    print(f"\n✅ 服务器 {dest} 已同步到 {sha}")
    if restart:
        print("自检：")
        run_expect(cfg, "run", f"{dest}/run.sh --status || true")
    else:
        print(f"   运行：{dest}/run.sh --dry-run --days 1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
