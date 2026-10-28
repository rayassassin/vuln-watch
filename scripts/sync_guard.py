#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
双活一致性守卫 —— 备案期间保证 GitHub Pages 与自有服务器永远同一份内容。

为什么需要它：
  看板同时挂在两处——Pages（备案前唯一公网入口）和自有服务器（备案后主站）。
  两边由同一份 web/ 目录喂数据，但「同一份目录」不等于「一定同步」：
  Pages 发布那一步会失败（GitHub 5xx、token 过期、网络抖），容器会挂，
  本机改了代码也可能忘了 deploy。任何一条都会让两个入口悄悄对不上，
  而且没人会发现——所以要有东西每天盯着，并且能自己修。

守卫做四件事，按「能自己修就自己修，修不好才喊人」的顺序：
  1. 容器不在 → docker compose up -d 拉起来
  2. Pages 快照落后（blob sha 不一致）→ 自动重发一次
  3. 重发后复检，仍不一致 → 企微告警
  4. 服务器代码版本落后 GitHub main → 企微告警（提示跑 deploy）

为什么用 blob sha 而不是下载比对：
  git blob sha1 = sha1("blob <len>\\0" + content)，GitHub Contents API 直接返回，
  本地同口径算一遍即可。4 MB 的 data.json 不用下载，比对成本几乎为零。

为什么默认静默：
  每天跑两次，正常时只写日志。告警一多就没人看了，
  只在「自己修不好」的时候才推企微。

退出码：0 一致或已自愈；1 有未恢复的不一致（可直接用于监控）。

用法：
    python3 scripts/sync_guard.py              # 完整检查 + 自愈
    python3 scripts/sync_guard.py --dry-run    # 只报不做（本机试跑用）
    python3 scripts/sync_guard.py --json       # 机器可读
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

BASE = Path(os.environ.get("VW_BASE") or "/opt/vuln-watch")
WEB = BASE / "web"
LOGDIR = BASE / "logs"
TOKEN_FILE = BASE / ".pages_token"
CONTAINER = os.environ.get("VW_WEB_CONTAINER") or "vuln-watch-web"
REPO = "rayassassin/vuln-watch"
BRANCH = "gh-pages"
# 与 healthcheck 保持同一个清单：改一处就要改另一处，别忘
WATCH = ("index.html", "data.json", "data-lite.json")


def log(msg: str) -> None:
    print(f"[{time.strftime('%F %T')}] {msg}", flush=True)


def run(cmd: list[str], timeout: int = 600) -> tuple[int, str]:
    """跑一条命令，返回 (退出码, 合并输出)。超时按失败处理。"""
    try:
        p = subprocess.run(cmd, cwd=str(BASE), capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"超时 {timeout}s"
    except OSError as exc:
        return 127, str(exc)


# ---------------------------------------------------------------- blob sha

def local_blob_sha(path: Path) -> str:
    """git blob sha1：sha1("blob <len>\\0" + content)。与 GitHub 口径完全一致。"""
    import hashlib
    raw = path.read_bytes()
    h = hashlib.sha1()
    h.update(f"blob {len(raw)}\0".encode())
    h.update(raw)
    return h.hexdigest()


def remote_blob_sha(name: str, token: str) -> tuple[str, str]:
    """问 GitHub 远端某个文件的 blob sha。返回 (sha, 错误信息)。"""
    import urllib.error
    import urllib.request

    # 公开仓库匿名也能读；带 token 只是为了不受限流影响
    url = f"https://api.github.com/repos/{REPO}/contents/{name}?ref={BRANCH}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "vuln-watch-sync-guard",
        "Accept": "application/vnd.github+json",
    })
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        # 不走代理：服务器到 GitHub 的链路抖，代理会掩盖真实情况
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=30) as resp:
            return (json.loads(resp.read()) or {}).get("sha", ""), ""
    except urllib.error.HTTPError as exc:
        return "", f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return "", f"{type(exc).__name__}: {exc}"


def drift_files(token: str) -> tuple[list[str], list[str]]:
    """比对三份文件。返回 (落后的文件名, 查询失败的文件名)。"""
    drift: list[str] = []
    broken: list[str] = []
    for name in WATCH:
        p = WEB / name
        if not p.exists():
            broken.append(f"{name}(本地缺失)")
            continue
        rsha, err = remote_blob_sha(name, token)
        if err or not rsha:
            broken.append(f"{name}({err or '远端不存在'})")
            continue
        if rsha != local_blob_sha(p):
            drift.append(name)
    return drift, broken


# ---------------------------------------------------------------- 自愈动作

def ensure_container(dry: bool) -> tuple[str, str]:
    """容器不在就拉起来。返回 (状态, 说明)。"""
    rc, out = run(["docker", "ps", "--format", "{{.Names}}"])
    if rc != 0:
        return "skip", "本机没有 docker"
    if CONTAINER in (out or "").split():
        return "ok", "容器在运行"
    if dry:
        return "fail", f"容器 {CONTAINER} 不在（dry-run 未拉起）"
    comp = BASE / "deploy" / "docker-compose.yml"
    if not comp.exists():
        comp = BASE / "deploy" / "compose.yml"
    rc2, out2 = run(["docker", "compose", "-f", str(comp), "up", "-d"], timeout=300)
    return ("ok" if rc2 == 0 else "fail"), \
        (f"已拉起 {CONTAINER}" if rc2 == 0 else f"拉起失败：{out2[-200:]}")


def republish(dry: bool) -> tuple[bool, str]:
    """重发一次 Pages。服务器是权威源，所以补发永远从服务器发。"""
    if not TOKEN_FILE.exists():
        return False, f"缺少 {TOKEN_FILE}，无法补发"
    if dry:
        return True, "dry-run 未真正发布"
    env = dict(os.environ, GH_PAGES_TOKEN=TOKEN_FILE.read_text(encoding="utf-8").strip())
    try:
        p = subprocess.run([sys.executable, "scripts/publish_pages.py"],
                           cwd=str(BASE), capture_output=True, text=True,
                           timeout=900, env=env)
        return p.returncode == 0, (p.stdout or "")[-300:] or (p.stderr or "")[-300:]
    except subprocess.TimeoutExpired:
        return False, "发布超时 900s"


def remote_head() -> tuple[str, str]:
    """GitHub main 分支最新 commit sha（前 7 位）。用于发现代码版本落后。"""
    import urllib.error
    import urllib.request
    url = f"https://api.github.com/repos/{REPO}/commits/main"
    req = urllib.request.Request(url, headers={"User-Agent": "vuln-watch-sync-guard"})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=30) as resp:
            return (json.loads(resp.read()) or {}).get("sha", "")[:7], ""
    except Exception as exc:  # noqa: BLE001
        return "", f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------- 告警

def alert(subject: str, body: str, dry: bool) -> bool:
    """告警只发本人，不广播——这是运维故障，不是漏洞通报。"""
    if dry:
        log(f"[dry-run] 将告警：{subject}")
        return True
    try:
        sys.path.insert(0, str(BASE))
        import yaml  # noqa: PLC0415
        import collect  # noqa: PLC0415
        cfg = yaml.safe_load((BASE / "vuln-watch.yaml").read_text(encoding="utf-8"))
        return bool(collect.push_wecom_app(f"**{subject}**\n\n{body}", cfg, broadcast=False))
    except Exception as exc:  # noqa: BLE001
        log(f"告警推送异常：{exc}")
        return False


# ---------------------------------------------------------------- 主流程

def pages_enabled() -> bool:
    """
    Pages 是否还在服役。

    备案下来之后 Pages 要退场，届时把 cron 里的 VW_PUBLISH_PAGES 设成 0 即可。
    这里必须跟着一起关：否则 Pages 停更后守卫会天天报「远端落后」，
    把真故障淹没在噪音里。
    """
    flag = (os.environ.get("VW_PUBLISH_PAGES") or "1").strip().lower()
    return flag not in ("0", "false", "no", "off")


def main() -> int:
    ap = argparse.ArgumentParser(description="双活一致性守卫")
    ap.add_argument("--dry-run", action="store_true", help="只报不做")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    args = ap.parse_args()

    LOGDIR.mkdir(parents=True, exist_ok=True)
    token = TOKEN_FILE.read_text(encoding="utf-8").strip() if TOKEN_FILE.exists() else ""
    report: dict = {"checked_at": time.strftime("%F %T"), "actions": [], "alerts": []}

    # 1. 容器
    st, note = ensure_container(args.dry_run)
    log(f"容器：{st} — {note}")
    report["container"] = {"status": st, "detail": note}
    if st == "fail":
        report["alerts"].append(f"容器 {CONTAINER} 拉不起来：{note}")

    # 2. 比对
    if not pages_enabled():
        log("VW_PUBLISH_PAGES=0：Pages 已退场，跳过远端比对")
        report["pages"] = "disabled"
        drift, broken = [], []
    else:
        drift, broken = drift_files(token)
        log(f"比对 {len(WATCH)} 份文件：落后 {drift or '无'}，查询失败 {broken or '无'}")
        report["drift_before"] = drift
        report["broken"] = broken
        if broken:
            report["alerts"].append("远端 blob 查询失败：" + "、".join(broken))

    # 3. 落后就自动补发，再复检
    if drift:
        ok, out = republish(args.dry_run)
        log(f"自动补发：{'成功' if ok else '失败'} {out[:120]}")
        report["actions"].append(f"republish:{'ok' if ok else 'fail'}")
        if ok:
            # Pages 构建有延迟，等一会儿再问才问得到新内容
            time.sleep(8 if not args.dry_run else 0)
            drift2, broken2 = drift_files(token)
            log(f"复检：落后 {drift2 or '无'}")
            report["drift_after"] = drift2
            if drift2:
                report["alerts"].append(
                    f"补发后仍不一致：{'、'.join(drift2)}（Pages 可能构建失败）")
        else:
            report["alerts"].append(f"补发失败：{out[:200]}")

    # 4. 代码版本
    ver_file = BASE / ".version"
    local_ver = ver_file.read_text(encoding="utf-8").strip() if ver_file.exists() else ""
    head, herr = remote_head()
    report["version"] = {"server": local_ver, "github": head}
    if herr:
        log(f"代码版本：查不到 GitHub main（{herr}）")
    elif head and local_ver and head != local_ver:
        report["alerts"].append(
            f"服务器代码 {local_ver} 落后 GitHub main {head}，"
            f"本机跑 `python3 scripts/deploy.py` 同步")
    log(f"代码版本：服务器 {local_ver or '?'} / GitHub {head or '?'}")

    # 5. 收尾
    if report["alerts"]:
        body = "\n".join(f"- {a}" for a in report["alerts"])
        sent = alert("🟡 看板双活链路不同步", body, args.dry_run)
        log(f"告警已推送：{sent}")
        report["alert_sent"] = sent
    else:
        log("两边一致，无需处理")

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if report["alerts"] else 0


if __name__ == "__main__":
    sys.exit(main())
