#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
补 GitHub Advisory 的历史数据（带包名）。

由来：早期版本的 fetch_github_advisories 没取 vulnerabilities[].package.name，
导致 GHSA 条目在页面上组件名是空的，"命中自有组件"也标不出来，
Spring / Jackson 这些 Maven 包的漏洞直接被算成"无组件"。
代码已修，但历史条目需要重新拉一次 GHSA 才能补上字段。

为什么要拆成两步：
  匿名调 GitHub API 只有 60 次/小时，六个生态拉全量必然被限流。
  本机有 gh 登录态（5000 次/小时），所以在本机拉，把结果搬到服务器合并。
  token 不出本机，服务器只接收纯数据。

用法：
  本机：python3 scripts/patch_ghsa.py fetch --out /tmp/ghsa_raw.json
  服务器：python3 scripts/patch_ghsa.py merge /tmp/ghsa_raw.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import collect  # noqa: E402


def load_cfg() -> dict:
    cfg = yaml.safe_load((ROOT / "vuln-watch.yaml").read_text(encoding="utf-8"))
    return collect.load_subscriptions(cfg)


def cmd_fetch(args: argparse.Namespace) -> int:
    cfg = load_cfg()
    since = datetime.fromisoformat(args.since).replace(tzinfo=timezone.utc)
    ecos = collect._gh_ecosystems(cfg)
    names = {a.get("name") for a in cfg["osv"]["assets"] if a.get("name")}
    print(f"拉取 {args.since} 至今的 GitHub Advisory：{', '.join(ecos)}")
    raw = collect.fetch_github_advisories(
        ecos, since, cfg, max_pages=args.pages, watch_names=names,
    )
    out = Path(args.out)
    out.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
    with_pkg = sum(1 for r in raw if r.get("asset"))
    print(f"✅ {len(raw)} 条（带包名 {with_pkg} 条）→ {out}（{out.stat().st_size // 1024} KB）")
    return 0


def cmd_merge(args: argparse.Namespace) -> int:
    cfg = load_cfg()
    bf = cfg.get("backfill") or {}
    raw = json.loads(Path(args.path).read_text(encoding="utf-8"))
    print(f"读入 {len(raw)} 条，开始归一化 ...")

    cfg_bf = dict(cfg)
    cfg_bf["policy"] = {**cfg["policy"], "stale_days": 0,
                        "min_cvss": float(bf.get("min_cvss", 7.0))}

    kev = collect.fetch_cisa_kev(cfg)
    cves = sorted({i["cve"].upper() for i in raw
                   if i.get("cve") and (i.get("cvss") or 0) >= 6.5})
    epss = collect.fetch_epss(cves, cfg)
    items = collect.normalize_and_score(raw, kev, epss, cfg_bf, [], [])
    print(f"归一化后 {len(items)} 条")

    now = datetime.now(timezone.utc)
    stats = {
        "scanned": len(raw),
        "since": datetime.fromisoformat(args.since).replace(tzinfo=timezone.utc),
        "until": now,
        "sources": ["GitHub", "KEV", "EPSS"],
        "degraded": [],
    }
    collect.write_web_data(items, stats, cfg_bf, mode="patch")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="补 GHSA 历史数据（带包名）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="本机拉取（用 gh 登录态，不受匿名限流）")
    f.add_argument("--since", default="2026-01-01")
    f.add_argument("--pages", type=int, default=20)
    f.add_argument("--out", default="/tmp/ghsa_raw.json")
    f.set_defaults(func=cmd_fetch)

    m = sub.add_parser("merge", help="服务器合并进 data.json")
    m.add_argument("path")
    m.add_argument("--since", default="2026-01-01")
    m.set_defaults(func=cmd_merge)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
