#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
一次性回填：把看板里历史条目的「厂商 / 组件」纠正成 CPE 的 Vendor / Product。

背景：早期版本没有解析 NVD 的 configurations，组件名是从 CNA 归属和标题猜的，
结果 Oracle / Apache / PHP 这类**厂商名**被当成组件显示，粒度粗到无法对应
自有资产。正确做法是用 NVD 页面「Affected Products」那一栏的数据，也就是 CPE
里的 product 字段。

为什么走 NVD 年度全量 feed（nvdcve-2.0-YYYY.json.gz）而不是逐条查 API：
  8090 条 × 无 key 限流 5 req/30s ≈ 13 小时，有 key 也得一个多小时。
  feed 一份 42 MB 全量下载，本地匹配几秒完成。代价是磁盘和内存。

两种用法：
  # 有内存/带宽的机器：下载 feed、建映射、就地应用
  python3 scripts/backfill_vendor_product.py --years 2026

  # 服务器：复用别人建好的映射，不下 42 MB、不解析几百 MB JSON
  python3 scripts/backfill_vendor_product.py --map /tmp/cpe_map.json

映射文件可以重复用，重复应用是幂等的（只覆盖 vendor/product，其余字段不动）。
"""

from __future__ import annotations

import argparse
import gzip
import importlib.util
import json
import os
import re
import shutil
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# 直接复用 collect.py 里的 CPE 解析，保证新旧数据用的是同一套口径
_spec = importlib.util.spec_from_file_location("collect", ROOT / "collect.py")
collect = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(collect)

FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
UA = "vuln-watch/1.0 (internal-security-monitor)"


def log(msg: str) -> None:
    print(msg, flush=True)


def download_feed(year: int, cache_dir: Path) -> Path:
    """下载年度 feed 到本地缓存。42 MB，走 gzip 原样落盘。"""
    cache_dir.mkdir(parents=True, exist_ok=True)
    dst = cache_dir / f"nvdcve-2.0-{year}.json.gz"
    if dst.exists() and dst.stat().st_size > 1_000_000:
        log(f"  复用缓存 {dst.name}（{dst.stat().st_size // 1024 // 1024} MB）")
        return dst
    url = FEED_URL.format(year=year)
    log(f"  下载 {url} ...")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    tmp = dst.with_suffix(dst.suffix + ".part")
    with urllib.request.urlopen(req, timeout=180) as resp, open(tmp, "wb") as fh:
        shutil.copyfileobj(resp, fh, length=1 << 20)
    os.replace(tmp, dst)
    log(f"  已下载 {dst.stat().st_size // 1024 // 1024} MB")
    return dst


def build_map(feed_path: Path, wanted: set[str]) -> dict[str, dict]:
    """
    扫描 feed，只为 wanted 里的 CVE 提取 (vendor, product)。

    兼容两种 schema：
      - 2.0 feed 的新格式：vulnerabilities[].cve.id / cve.configurations
      - 1.1 feed 的旧格式：CVE_Items[].cve.CVE_data_meta.ID / cve.configurations
    """
    log(f"  解析 {feed_path.name}（{feed_path.stat().st_size // 1024 // 1024} MB）...")
    opener = gzip.open if feed_path.suffix == ".gz" else open
    with opener(feed_path, "rb") as fh:
        doc = json.load(fh)

    raw = doc.get("vulnerabilities") or doc.get("CVE_Items") or []
    log(f"  feed 共 {len(raw)} 条，目标 {len(wanted)} 条")

    out: dict[str, dict] = {}
    for wrap in raw:
        cve = wrap.get("cve") or {}
        cve_id = cve.get("id") or ((cve.get("CVE_data_meta") or {}).get("ID")) or ""
        if not cve_id or cve_id not in wanted:
            continue
        vendor, product, products = collect._nvd_affected(cve)
        if not product:
            continue
        out[cve_id] = {"vendor": vendor, "product": product, "products": products[:20]}
    log(f"  命中 CPE 的 {len(out)} 条")
    return out


def load_entries(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, payload: dict) -> None:
    """原子写：看板文件被 nginx 容器直接挂着读，写一半会被访客拿到。"""
    blob = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(blob, encoding="utf-8")
    os.replace(tmp, path)


# 一眼就能看出是厂商、不是产品的名字。NVD 里有一批条目（尤其 Oracle 的季度
# CPU）发布时还没分析完，configurations 是空的，组件名只能从标题里捞。
# 只对这批做标题推断，避免把 vm2 这种包名改坏。
VENDOR_LIKE = {
    "oracle", "apache", "php", "python", "microsoft", "google", "apple", "cisco",
    "ibm", "redhat", "red hat", "linux", "debian", "canonical", "ubuntu", "adobe",
    "vmware", "f5", "mysql", "oracle corporation", "sap", "siemens", "schneider",
    "huawei", "hpe", "hewlett packard", "netapp", "dell", "broadcom", "intel",
    "amd", "nvidia", "mozilla", "oracle", "jenkins", "gitlab", "atlassian",
}

# "Vulnerability in Oracle Essbase (component: Security)" → Oracle Essbase
_TITLE_PRODUCT_RE = re.compile(
    r"(?:vulnerabilit(?:y|ies)|weakness(?:es)?|issue|flaw)\s+in\s+(?:the\s+)?(.+?)\s*(?:\(|\.\s|,\s|$)",
    re.I,
)

# 标题里跟在厂商名后面的常见普通名词，不是产品名。
# 没有这道闸，"Python library" 会被当成产品名叫 Library。
_NOT_PRODUCT = {
    "library", "libraries", "product", "products", "component", "components",
    "server", "servers", "framework", "platform", "software", "application",
    "package", "module", "plugin", "extension", "tool", "tools", "client",
    "api", "sdk", "driver", "service", "services", "system", "systems",
    "version", "versions", "release", "releases", "code", "program",
    "database", "engine", "runtime", "environment", "before", "prior",
}


def guess_product_from_title(title: str, vendor_like: str) -> str:
    """
    标题里捞产品名。只在"现有组件名是厂商名"时才用，且要求厂商名是
    提取结果的前缀——拿不准就返回空，宁可继续显示厂商名也不乱猜。
    """
    if not title or not vendor_like:
        return ""
    m = _TITLE_PRODUCT_RE.search(title)
    if not m:
        return ""
    tail = m.group(1).strip()
    # 前缀必须是那个厂商名，剩下的一段才是产品
    if not tail.lower().startswith(vendor_like.lower()):
        return ""
    rest = tail[len(vendor_like):].strip(" -:")
    rest = re.sub(r"\s+", " ", rest)
    # 标题常常一句话列好几个产品，只取第一个
    # "Java SE, Oracle GraalVM for JDK"           → Java SE
    # "SOA Suite product of Oracle Fusion ..."    → SOA Suite
    # "Camel Saxon component"                     → Camel Saxon
    rest = re.split(r"\s+product\s+of\s+|\s+of\s+Oracle\s+|,\s*|\s+and\s+", rest, flags=re.I)[0]
    rest = re.sub(r"\s+(component|products?|versions?)\s*$", "", rest, flags=re.I).strip()
    if not rest or len(rest) > 40:
        return ""
    # 产品名里不该再出现从句
    if any(w in rest.lower() for w in (" allows ", " could ", " when ", " where ")):
        return ""
    if rest.lower() in _NOT_PRODUCT or rest.split()[0].lower() in _NOT_PRODUCT:
        return ""
    return rest


def brand_from_title(title: str, product: str, comp: str) -> str:
    """
    标题里通常写着产品的正确品牌写法：
      product=litellm  标题 "LiteLLM: Privilege Escalation ..."  → LiteLLM
      product=mlflow   标题 "MLflow vulnerable to ..."           → MLflow
    CPE 的 product 是强制小写的，机械首字母大写只能得到 Litellm 这种怪胎。
    只认"标题首词小写化后恰好等于 product"这一种情况，拿不准就不改。
    """
    if not product or not title or not product.islower():
        return ""
    head = re.split(r"[\s:,;(\[]", title.strip())[0].strip("`'\"")
    if not head or head.islower() or head.lower() != product:
        return ""      # 标题首词本身没大写，或从一开始就不是产品名
    return head if head != comp else ""


def apply_map(payload: dict, cpe: dict[str, dict]) -> tuple[int, int]:
    """
    就地把 vendor / product / component 纠正过来。

    component 用 CPE 的 product 覆盖——它是 NVD 官方的 Affected Products，
    比早期从标题和 CNA 猜出来的名字权威。没命中的保持原样，不臆测。

    最后一轮做同名统一：同一个产品可能一半条目走 CPE（Openclaw）、
    一半走包名（openclaw），不统一的话筛选栏会出现两个 chip。
    """
    filled = changed = guessed = 0
    entries = payload.get("entries") or []

    for e in entries:
        key = (e.get("cve") or "").upper()
        info = cpe.get(key)
        if not info:
            # NVD 还没分析完的条目没有 CPE，组件名仍是厂商名。
            # 这时从标题里捞产品名，捞不到就维持原样。
            comp = (e.get("component") or "").strip()
            if comp.lower() in VENDOR_LIKE and not e.get("product"):
                guess = guess_product_from_title(e.get("title", ""), comp)
                if guess:
                    e["vendor"] = comp       # 那个"组件名"其实正是厂商
                    e["component"] = collect._pretty_name(guess)
                    guessed += 1
            continue
        filled += 1
        if e.get("vendor") != info["vendor"] or e.get("product") != info["product"]:
            changed += 1
        e["vendor"] = collect._pretty_name(info["vendor"])
        e["product"] = info["product"]
        pretty = collect._pretty_name(info["product"])
        if pretty and e.get("component") != pretty:
            e["component"] = pretty

    # 写法规范化：把历史遗留的 Java Se / Openwebui 这类大小怪胎统一到别名表。
    # 带斜杠的是 GitHub 资产全路径（github.com/org/repo），原样保留，别乱动。
    branded = 0
    for e in entries:
        ven = e.get("vendor") or ""
        if ven and "/" not in ven:
            e["vendor"] = collect._pretty_name(ven)

        comp = e.get("component") or ""
        if not comp or "/" in comp:
            continue      # 空值、以及 github.com/org/repo 这类资产全路径，原样保留
        if e.get("product"):
            # CPE 命中的才需要美化：CPE product 强制小写，得还原成能看的名字
            e["component"] = collect._pretty_name(e["product"])
        # 品牌写法以标题为准（litellm → LiteLLM）。
        # 没命中 CPE 时 product 是空的，这时拿组件名自身当候选——
        # 包名本来就该保持原样，只有标题里写着更权威的写法才改。
        cand = e.get("product") or (comp.lower() if " " not in comp else "")
        brand = brand_from_title(e.get("title", ""), cand, comp)
        if brand:
            e["component"] = brand
            branded += 1
    if branded:
        log(f"  品牌写法 {branded} 条（如 litellm → LiteLLM）")

    # 未命中 CPE 的条目：写法向已命中的同名产品看齐
    canon: dict[str, str] = {}
    for e in entries:
        comp = e.get("component") or ""
        if e.get("product") and comp:
            canon.setdefault(comp.lower(), comp)
    unified = 0
    for e in entries:
        if e.get("product"):
            continue
        comp = e.get("component") or ""
        target = canon.get(comp.lower())
        if target and target != comp:
            e["component"] = target
            unified += 1
    if unified:
        log(f"  同名统一 {unified} 条（如 openclaw → OpenClaw）")
    if guessed:
        log(f"  标题推断 {guessed} 条（NVD 未标注 CPE 的条目，如 Oracle → Essbase）")
    return filled, changed


def main() -> int:
    ap = argparse.ArgumentParser(description="回填历史条目的厂商/组件（CPE Vendor/Product）")
    ap.add_argument("--data", default=str(ROOT / "web" / "data.json"), help="看板数据文件")
    ap.add_argument("--lite", default=str(ROOT / "web" / "data-lite.json"), help="首屏轻量包（存在才处理）")
    ap.add_argument("--years", default="", help="feed 年份，逗号分隔；留空则按数据里的发布日期推断")
    ap.add_argument("--map", default="", help="复用现成的 CPE 映射文件（服务器用，不下载 feed）")
    ap.add_argument("--map-out", default="", help="把建好的映射另存，供其它机器复用")
    ap.add_argument("--cache-dir", default=str(ROOT / ".feed-cache"), help="feed 下载缓存目录")
    ap.add_argument("--dry-run", action="store_true", help="只统计不写盘")
    args = ap.parse_args()

    data_path = Path(args.data)
    if not data_path.exists():
        log(f"找不到 {data_path}，先跑一次 collect.py")
        return 1

    payload = load_entries(data_path)
    entries = payload.get("entries") or []
    wanted = {(e.get("cve") or "").upper() for e in entries if e.get("cve")}
    log(f"看板 {len(entries)} 条，其中 {len(wanted)} 条带 CVE 号")

    cpe: dict[str, dict] = {}
    if args.map:
        cpe = json.loads(Path(args.map).read_text(encoding="utf-8"))
        log(f"载入映射 {args.map}：{len(cpe)} 条")
    else:
        years = [y.strip() for y in args.years.split(",") if y.strip()]
        if not years:
            pubs = sorted({(e.get("published") or "")[:4] for e in entries if e.get("published")})
            years = [y for y in pubs if y.isdigit()]
        if not years:
            log("推断不出年份，用 --years 指定")
            return 1
        log(f"需要 feed 年份：{', '.join(years)}")
        cache = Path(args.cache_dir)
        for y in years:
            feed = download_feed(int(y), cache)
            cpe.update(build_map(feed, wanted))
        if args.map_out:
            Path(args.map_out).write_text(
                json.dumps(cpe, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            log(f"映射已另存 {args.map_out}（{len(cpe)} 条）")

    if not cpe:
        log("没拿到任何 CPE 映射，不改动")
        return 1

    filled, changed = apply_map(payload, cpe)
    log(f"全量包：命中 {filled} 条，实际修正 {changed} 条")

    lite_path = Path(args.lite)
    if lite_path.exists():
        lite = load_entries(lite_path)
        lf, lc = apply_map(lite, cpe)
        log(f"轻量包：命中 {lf} 条，实际修正 {lc} 条")
    else:
        lite = None

    if args.dry_run:
        log("dry-run，未写盘")
        return 0

    save_json(data_path, payload)
    log(f"已写入 {data_path}（{data_path.stat().st_size // 1024} KB）")
    if lite is not None:
        save_json(lite_path, lite)
        log(f"已写入 {lite_path}（{lite_path.stat().st_size // 1024} KB）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
