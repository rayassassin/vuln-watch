#!/usr/bin/env python3
"""把本机 repo 的 HEAD 同步到云服务器 /opt/vuln-watch。

设计取舍：
  只传 git 已跟踪的文件（git archive），服务器上的 state.db、.env、日志一律不动。
  这样「版本同步」是单向的、可重复的，不会本机覆盖服务器的运行状态。

用法：
    python3 scripts/deploy.py             # 同步 HEAD
    python3 scripts/deploy.py --restart   # 同步后顺手跑一次 --status 自检
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECRETS = Path.home() / ".config" / "vuln-watch" / "deploy.env"
REMOTE_EXP = Path(__file__).with_name("remote_put.exp")

DEST = "/opt/vuln-watch"
RELDIR = "/opt/_staging"
APP_ENV = "/path/to/wecom_app.env"
FEEDS = "/path/to/feeds.json"

# 服务器上的启动包装：通道固定为自建应用，收件人从已有的 feeds.json 取，
# 不在这个文件里硬编码任何 ID 或密钥。
RUN_SH = f"""#!/bin/sh
# 由 scripts/deploy.py 生成，每次部署会覆盖
set -eu
export WECOM_CHANNEL=app
export WECOM_APP_ENV={APP_ENV}
export WX_TOUSER="$(python3 -c "import json;print(json.load(open('{FEEDS}')).get('chat_id',''))")"
cd {DEST}
exec python3 collect.py "$@"
"""


def load_creds() -> dict:
    if not SECRETS.exists():
        sys.exit(f"缺少凭据文件：{SECRETS}")
    env = dict(os.environ)
    for line in SECRETS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    for k in ("ECS_HOST", "ECS_PORT", "ECS_USER", "ECS_PASS"):
        if not env.get(k):
            sys.exit(f"凭据缺少 {k}")
    return env


def expect(env: dict, *args: str) -> int:
    cmd = ["expect", "-f", str(REMOTE_EXP), *args]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    out = (r.stdout or "").strip()
    if out:
        print("   " + out.replace("\n", "\n   "))
    if r.returncode != 0:
        print(f"   ! 远程操作失败（exit={r.returncode}）：{(r.stderr or '').strip()[:300]}")
    return r.returncode


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def main() -> int:
    sha = git("rev-parse", "--short", "HEAD")
    dirty = git("status", "--porcelain")
    if dirty:
        print("⚠️  工作区有未提交改动，本次只同步已提交的 HEAD")
        for line in dirty.splitlines():
            print("   " + line)

    env = load_creds()
    tar = f"/tmp/vuln-watch-{sha}.tar.gz"
    subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar.gz", "-o", tar, "HEAD"], check=True)
    size = os.path.getsize(tar)
    print(f"打包 HEAD {sha} → {size} 字节")

    print("1/3 上传")
    if expect(env, "put", tar, f"{RELDIR}/vuln-watch-{sha}.tar.gz") != 0:
        return 1

    print("2/3 解包（保留 state.db / .env / 日志）")
    cmd = (
        f"set -e; mkdir -p {DEST}; "
        f"tar -xzf {RELDIR}/vuln-watch-{sha}.tar.gz -C {DEST}; "
        f"echo {sha} > {DEST}/.version; "
        f"rm -f {RELDIR}/vuln-watch-{sha}.tar.gz"
    )
    if expect(env, "run", cmd) != 0:
        return 1

    print("3/3 写入启动包装与权限")
    run_sh_local = "/tmp/vuln-watch-run.sh"
    Path(run_sh_local).write_text(RUN_SH, encoding="utf-8")
    if expect(env, "put", run_sh_local, f"{DEST}/run.sh") != 0:
        return 1
    cmd = (
        f"set -e; chmod 755 {DEST}/run.sh; "
        f"ls -1 {DEST}; echo '--- version ---'; cat {DEST}/.version"
    )
    if expect(env, "run", cmd) != 0:
        return 1

    os.unlink(tar)
    os.unlink(run_sh_local)
    print(f"\n✅ 服务器 /opt/vuln-watch 已同步到 {sha}")
    print("   运行：/opt/vuln-watch/run.sh --dry-run --days 1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
