#!/usr/bin/env python3
"""
回填厂商列：把能"推断出来"的厂商补进历史条目。

背景：厂商(Vendor)和产品(Product)是两列，CPE 是唯一硬证据。但历史数据里
  37% 的条目 NVD 没给 CPE，厂商列是空的，看板上整列都是「—」。
  其中两类其实有可靠线索，只是之前没用：

  1. Oracle 的 CPU 标题是固定句式，产品名就写在句子里：
     "Vulnerability in the Workflow product of Oracle E-Business Suite"
     ——厂商必为 Oracle，产品是 Workflow。这类公告经常没有 CPE。
  2. 带命名空间的包名里就写着组织名：
     github.com/siyuan-note/siyuan/kernel → SiYuan
     code.gitea.io/gitea                 → Gitea
     @budibase/server                    → Budibase

  裸包名（django、litellm、nltk）没有组织信息，这类保持为空——
  瞎猜一个厂商比空着更有害，宁可让筛选器少一个维度。

只补空值，绝不覆盖已有厂商。改完原子替换，出错不动原文件。

用法：
    python3 scripts/backfill_vendor.py            # 回填 web/data.json
    python3 scripts/backfill_vendor.py --dry-run  # 只看会改什么，不落盘
    python3 scripts/backfill_vendor.py --file X   # 指定其它数据文件
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_collect():
    """复用 collect.py 里的解析函数，避免同一套规则写两份。"""
    spec = importlib.util.spec_from_file_location("collect", ROOT / "collect.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fill_entry(e: dict, C) -> str:
    """给单个条目补厂商，返回改动类型：oracle / package / 空串表示没动。"""
    if e.get("vendor"):
        return ""
    title = e.get("title") or ""

    # 1. Oracle CPU 句式：厂商 + 产品一起拿到
    vendor, prod = C._oracle_title_vp(title)
    if vendor:
        e["vendor"] = vendor
        # 组件列之前只能填厂商名（Oracle），现在有真产品名就换掉
        if prod and (not e.get("component") or e.get("component") == vendor):
            e["component"] = prod
        return "oracle"

    # 2. 包名里的组织前缀
    org, _ = C._pkg_org_product(e.get("component") or "")
    if org:
        e["vendor"] = C._org_name(org)
        return "package"

    return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=str(ROOT / "web" / "data.json"))
    ap.add_argument("--dry-run", action="store_true", help="只统计不落盘")
    args = ap.parse_args()

    C = load_collect()
    path = Path(args.file)
    if not path.exists():
        print(f"数据文件不存在：{path}")
        return 1

    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("entries", data if isinstance(data, list) else [])
    before = sum(1 for e in entries if e.get("vendor"))

    changed = Counter()
    samples: list[str] = []
    for e in entries:
        kind = fill_entry(e, C)
        if not kind:
            continue
        changed[kind] += 1
        if len(samples) < 12:
            samples.append(f"  [{kind}] {e.get('cve','')}  "
                           f"厂商={e.get('vendor','')!r}  组件={e.get('component','')!r}")

    after = sum(1 for e in entries if e.get("vendor"))
    print(f"条目总数      : {len(entries)}")
    print(f"厂商覆盖率    : {before} → {after}  "
          f"({before / max(len(entries),1):.1%} → {after / max(len(entries),1):.1%})")
    print(f"本次改动      : Oracle 标题 {changed['oracle']} 条，"
          f"包名组织 {changed['package']} 条")
    print("样例：")
    print("\n".join(samples) if samples else "  （无）")

    if args.dry_run:
        print("\n--dry-run：未写盘")
        return 0
    if not changed:
        print("没有需要回填的条目")
        return 0

    # 原子写：先写临时文件再替换，避免写到一半被 nginx 读到半个 JSON
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)
    print(f"\n已写回：{path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
