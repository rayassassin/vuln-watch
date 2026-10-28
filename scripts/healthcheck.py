#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
两条看板链路的一致性自检 —— 一条命令回答「两套环境是不是都在跑、数据是不是同一份」。

背景：域名备案期间，看板同时挂在两个地方
  ① GitHub Pages（本仓库 gh-pages 分支）—— 备案前唯一公网可达的入口
  ② 自有服务器（nginx 容器挂载 web/）—— 备案后的主站
两边由同一份 web/ 目录喂数据，理论上永远一致。但「理论」不管用：
容器可能挂了、发布可能失败、也可能一边更新了一边没更新。所以要能随时验。

核心手法：不下载 4 MB。GitHub Contents API 会返回文件的 git blob sha1，
本地用同样口径算一遍（sha1("blob <len>\\0" + content)），相等即同一份内容。
于是「两边是否同步」变成一个几乎零成本的元数据比对。

退出码：0 全部正常；1 有链路异常或两边不一致（可直接用于监控）。

用法：
    python3 scripts/healthcheck.py            # 全量检查
    python3 scripts/healthcheck.py --json     # 机器可读输出
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import publish_pages as pp  # noqa: E402  复用 api/blob sha 口径，保证与发布脚本同源

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
LOCAL_PORTS = (80, 8080)
GH_PAGES_KINDS = ("index.html", "data.json")


# ---------------------------------------------------------------- 小工具


class Result:
    """一行检查结果。状态只有 ok / fail / warn / skip 四种。"""

    def __init__(self):
        self.rows: list[dict] = []

    def add(self, name: str, status: str, detail: str = "") -> None:
        self.rows.append({"name": name, "status": status, "detail": detail})

    @property
    def failed(self) -> bool:
        return any(r["status"] == "fail" for r in self.rows)

    def render(self) -> str:
        icon = {"ok": "✅", "fail": "❌", "warn": "⚠️ ", "skip": "➖"}
        width = max(len(r["name"]) for r in self.rows) + 2
        out = []
        for r in self.rows:
            name = r["name"] + " " * (width - len(r["name"]))
            out.append(f"  {icon.get(r['status'], '?')} {name}{r['detail']}")
        return "\n".join(out)


def http_probe(url: str, timeout: int = 25, want_json: bool = False) -> tuple[bool, str]:
    """直接 GET，返回 (是否 2xx, 描述)。刻意不走代理，免得本地代理掩盖真实可达性。"""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={"User-Agent": "vuln-watch-health"})
    t0 = time.time()
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
            cost = time.time() - t0
            note = f"HTTP {resp.status} · {len(raw):,} B · {cost:.2f}s"
            if want_json:
                try:
                    data = json.loads(raw)
                except Exception:  # noqa: BLE001
                    return False, note + " · 内容不是合法 JSON"
                n = len(data.get("entries") or [])
                note += f" · {n:,} 条 · {data.get('generated_at', '?')}"
            return 200 <= resp.status < 300, note
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {str(exc)[:70]}"


def size_probe(url: str, timeout: int = 30, retries: int = 3) -> tuple[bool, int, str]:
    """
    只取前 2 KB，用 Content-Range / Content-Length 读出远端文件总大小。

    为什么要这么绕：从国内拉 GitHub Pages 的 4 MB data.json 要 60～100 秒，
    上一次自检就是卡在这里超时而报“错”。而“页面能不能打开”和“文件多大”
    都不需要真把 4 MB 拉下来——字节数跟本地一致，加上 blob sha 比对，
    已经足以证明远端就是那一份。

    重试是必要的：Fastly 对来自国内机房的 Range 请求偶尔直接 reset
    （Errno 104），跟服务本身无关，多试一次就好。
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    headers = {"User-Agent": "vuln-watch-health", "Range": "bytes=0-2047"}
    last = ""
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with opener.open(req, timeout=timeout) as resp:
                resp.read()
                status = resp.status
                crange = resp.headers.get("Content-Range") or ""
                clen = resp.headers.get("Content-Length") or ""
                total = crange.rsplit("/", 1)[-1] if "/" in crange else clen
                total = int(total) if total.isdigit() else 0
                return 200 <= status < 300, total, f"HTTP {status} · 远端 {total:,} B"
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
            if exc.code < 500:
                return False, 0, last
        except Exception as exc:  # noqa: BLE001
            last = f"{type(exc).__name__}: {str(exc)[:60]}"
        if attempt < retries:
            time.sleep(2 * attempt)
    return False, 0, last


def docker_health(container: str) -> tuple[str, str]:
    if not any(Path(p).exists() for p in ("/usr/bin/docker", "/usr/local/bin/docker")):
        return "skip", "本机没有 docker"
    try:
        r = subprocess.run(["docker", "inspect", "-f", "{{.State.Health.Status}}", container],
                           capture_output=True, text=True, timeout=30)
    except Exception as exc:  # noqa: BLE001
        return "skip", f"docker 调用失败：{str(exc)[:50]}"
    st = (r.stdout or "").strip()
    if r.returncode != 0:
        return "fail", f"容器 {container} 不存在"
    return ("ok" if st == "healthy" else "fail"), f"{container} = {st}"


def remote_blob_sha(repo: str, branch: str, name: str, token: str) -> tuple[str, str]:
    try:
        meta = pp.api("GET", f"/repos/{repo}/contents/{name}?ref={branch}", token) or {}
        return (meta.get("sha") or ""), ""
    except pp.ApiError as exc:
        return "", f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return "", str(exc)[:60]


# ---------------------------------------------------------------- 主流程


def read_web_urls(cfg_file: Path) -> dict:
    """
    取 web.public_url / web.backup_url。
    优先 yaml；没装 PyYAML 的机器（比如只有系统 python 的 Mac）就用极简正则兜底，
    因为这两个值直接决定「日报里那行链接能不能打开」，不该因为缺个包就跳过检查。
    """
    text = ""
    try:
        text = cfg_file.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        import yaml  # noqa: PLC0415
        return (yaml.safe_load(text) or {}).get("web") or {}
    except Exception:  # noqa: BLE001
        import re  # noqa: PLC0415
        out = {}
        for key in ("public_url", "backup_url"):
            m = re.search(rf'^\s*{key}:\s*["\']?([^"\'\n#]+)', text, re.M)
            if m:
                out[key] = m.group(1).strip()
        return out


def main() -> int:
    ap = argparse.ArgumentParser(description="看板双链路一致性自检")
    ap.add_argument("--repo", default=pp.DEFAULT_REPO)
    ap.add_argument("--branch", default=pp.DEFAULT_BRANCH)
    ap.add_argument("--source", default=str(WEB))
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args()

    res = Result()
    src = Path(args.source)
    data_file = src / "data.json"
    index_file = src / "index.html"

    # ---- 1. 本地数据本身 ----
    if not data_file.exists():
        res.add("本地数据文件", "fail", f"缺少 {data_file}")
        print(res.render())
        return 1
    raw = data_file.read_bytes()
    try:
        payload = json.loads(raw)
        entries = payload.get("entries") or []
        gen = payload.get("generated_at", "?")
        rng = (payload.get("range") or {})
        res.add("本地数据文件", "ok",
                f"{len(raw):,} B · {len(entries):,} 条 · {gen} · "
                f"{rng.get('from', '?')} → {rng.get('to', '?')}")
    except Exception as exc:  # noqa: BLE001
        res.add("本地数据文件", "fail", f"JSON 解析失败：{exc}")
        print(res.render())
        return 1

    # ---- 2. 自有服务器容器 ----
    st, detail = docker_health(os.environ.get("VW_WEB_CONTAINER", "vuln-watch-web"))
    res.add("自有服务器容器", st, detail)

    # ---- 3. 本机 HTTP 端口（容器是否真的在对外服务）----
    # 这台机器没有 docker 就不必查本地端口：开发机上本来就没跑容器，
    # 那不该被算成故障，否则本机自检永远是红的，反而没人看。
    if st == "skip":
        res.add("本机 HTTP 端口", "skip", "非服务节点，跳过")
    else:
        for port in LOCAL_PORTS:
            ok, note = http_probe(f"http://127.0.0.1:{port}/", timeout=10)
            res.add(f"本机 :{port} 首页", "ok" if ok else "warn", note)

        # data.json 走一遍，确认挂载目录能被容器读到
        ok, note = http_probe(f"http://127.0.0.1:{LOCAL_PORTS[-1]}/data.json",
                              timeout=30, want_json=True)
        res.add("本机 data.json", "ok" if ok else "fail", note)

    # ---- 4. GitHub Pages 远端快照是否与本地同一份 ----
    token = ""
    for key in ("GH_PAGES_TOKEN", "GITHUB_TOKEN"):
        val = os.environ.get(key, "").strip()
        if val:
            token = val
            break
    if not token:
        token_file = ROOT / ".pages_token"
        if token_file.exists():
            token = token_file.read_text(encoding="utf-8").strip()
    if not token:
        try:
            token = subprocess.run(["gh", "auth", "token"], capture_output=True,
                                   text=True, timeout=15).stdout.strip()
        except Exception:  # noqa: BLE001
            token = ""   # 匿名也能读公开仓库，继续

    drift = []
    for name in GH_PAGES_KINDS:
        local_path = src / name
        if not local_path.exists():
            res.add(f"远端 {name}", "warn", "本地没有该文件，跳过比对")
            continue
        rsha, err = remote_blob_sha(args.repo, args.branch, name, token)
        lsha = pp.local_blob_sha(local_path.read_bytes())
        if err:
            res.add(f"远端 {name}", "fail", f"查询失败：{err}")
            drift.append(name)
        elif not rsha:
            res.add(f"远端 {name}", "fail", "远端不存在（Pages 可能还是空的）")
            drift.append(name)
        elif rsha == lsha:
            res.add(f"远端 {name}", "ok", f"blob {rsha[:10]} 与本地一致")
        else:
            res.add(f"远端 {name}", "fail",
                    f"blob {rsha[:10]} ≠ 本地 {lsha[:10]}（远端是旧版）")
            drift.append(name)

    # ---- 5. 公网可达性（Pages 那条是备案前唯一的对外入口）----
    # data.json 不下载全文，只比远端字节数（从国内拉 4 MB 要一两分钟，会把自检拖成超时）
    owner, name = args.repo.split("/")
    site = f"https://{owner}.github.io/{name}/"
    ok, note = http_probe(site, timeout=30)
    res.add("GitHub Pages 首页", "ok" if ok else "fail", f"{site} · {note}")

    ok, total, note = size_probe(site + "data.json")
    if ok and total == len(raw):
        res.add("GitHub Pages 数据", "ok", f"{note}（与本地一致）")
    elif ok and total:
        res.add("GitHub Pages 数据", "fail", f"{note}（本地 {len(raw):,} B，远端是旧版）")
    elif not drift:
        # 抽样下载失败，但上面 blob sha 已经逐文件证明远端就是这份内容。
        # 这属于「探测方式受限」（Fastly 对 Range 请求偶发 reset），不是页面坏了，
        # 不应该和「内容对不上」一个等级 —— 否则真出问题时就没人信告警了。
        res.add("GitHub Pages 数据", "warn", f"公网抽样失败（{note}），内容已由 blob sha 验证一致")
    else:
        res.add("GitHub Pages 数据", "fail", note)

    # ---- 6. 日报里给的地址是否能打开 ----
    cfg_file = ROOT / "vuln-watch.yaml"
    if cfg_file.exists():
        web = read_web_urls(cfg_file)
        for label, key in (("日报主入口", "public_url"), ("日报备用入口", "backup_url")):
            url = str(web.get(key) or "").strip()
            if not url:
                res.add(label, "skip", "未配置")
                continue
            ok, note = http_probe(url, timeout=30)
            res.add(label, "ok" if ok else "warn", f"{url} · {note}")

    # ---- 输出 ----
    if args.json:
        print(json.dumps({"ok": not res.failed, "rows": res.rows},
                         ensure_ascii=False, indent=2))
    else:
        print("看板双链路自检")
        print(res.render())
        print()
        if res.failed:
            bad = [r["name"] for r in res.rows if r["status"] == "fail"]
            print(f"❌ 异常：{', '.join(bad)}")
            if drift:
                print("   远端快照不是最新 → cd 到项目根目录跑：")
                print("   GH_PAGES_TOKEN=$(cat .pages_token) python3 scripts/publish_pages.py")
        else:
            print("✅ 两条链路都在正常服务，数据一致")

    return 0 if not res.failed else 1


if __name__ == "__main__":
    sys.exit(main())
