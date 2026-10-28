#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln-watch — 漏洞情报采集与企业微信推送

数据源：
  NVD(按 CNA 过滤) / OSV(组件精准匹配) / CISA KEV / FIRST EPSS / Packagist

用法：
  python collect.py --dry-run      # 只采集和打印，不推送
  python collect.py                # 采集 + 推送企微
  python collect.py --days 30      # 临时回看 30 天（首次跑建议这样）
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
import yaml

ROOT = Path(__file__).resolve().parent
CFG_PATH = ROOT / "vuln-watch.yaml"
DB_PATH = ROOT / "state.db"
UA = "vuln-watch/1.0 (internal-security-monitor)"

# 网络请求统一超时与重试配置
TIMEOUT = 30
RETRIES = 3


# ---------------------------- 基础设施 ----------------------------

def log(msg: str) -> None:
    """带时间戳的日志输出"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def http_get(url: str, **kwargs: Any) -> requests.Response:
    """GET 带指数退避重试。任何一源失败都不应让整条流水线崩掉。"""
    last_exc: Exception | None = None
    timeout = kwargs.pop("timeout", TIMEOUT)  # 必须弹出，否则与默认值冲突
    for attempt in range(1, RETRIES + 1):
        try:
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": UA, **kwargs.pop("headers", {})}, **kwargs)
            resp.raise_for_status()
            return resp
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < RETRIES:
                wait = 2 ** attempt
                log(f"  ! 请求失败({attempt}/{RETRIES}) {url[:70]} — {exc}，{wait}s 后重试")
                time.sleep(wait)
    raise RuntimeError(f"请求彻底失败：{url} — {last_exc}")


def http_post(url: str, payload: dict, **kwargs: Any) -> requests.Response:
    """POST 带重试，用于 OSV 查询"""
    last_exc: Exception | None = None
    timeout = kwargs.pop("timeout", TIMEOUT)
    for attempt in range(1, RETRIES + 1):
        try:
            resp = requests.post(
                url, json=payload, timeout=timeout,
                headers={"User-Agent": UA, "Content-Type": "application/json", **kwargs.pop("headers", {})},
                **kwargs,
            )
            resp.raise_for_status()
            return resp
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < RETRIES:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"请求彻底失败：{url} — {last_exc}")


# ---------------------------- 状态存储 ----------------------------

def init_db() -> sqlite3.Connection:
    """已推送记录和运行水位。用 SQLite 是为了跨次运行去重不重复打扰。"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY, first_seen TEXT, pushed INTEGER DEFAULT 0)")
    conn.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)")
    conn.commit()
    return conn


def db_get(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
    return row[0] if row else None


def db_set(conn: sqlite3.Connection, key: str, val: str) -> None:
    conn.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, val))
    conn.commit()


def is_seen(conn: sqlite3.Connection, vuln_id: str) -> bool:
    return conn.execute("SELECT 1 FROM seen WHERE id=?", (vuln_id,)).fetchone() is not None


def mark_seen(conn: sqlite3.Connection, vuln_id: str, pushed: bool) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO seen(id, first_seen, pushed) VALUES(?,?,?)",
        (vuln_id, datetime.now(timezone.utc).isoformat(), 1 if pushed else 0),
    )
    conn.commit()


# ---------------------------- 采集器 ----------------------------

def fetch_cisa_kev(cfg: dict) -> dict[str, dict]:
    """CISA KEV：已确认在野利用的漏洞清单。信噪比最高的源，只有千余条。"""
    log("拉取 CISA KEV ...")
    try:
        data = http_get(cfg["feeds"]["cisa_kev"]).json()
    except Exception as exc:  # noqa: BLE001
        log(f"  ! KEV 失败，跳过：{exc}")
        return {}
    result = {
        v["cveID"]: {
            "kev": True,
            "kev_added": v.get("dateAdded", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
            "name": v.get("vulnerabilityName", ""),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
        }
        for v in data.get("vulnerabilities", [])
    }
    log(f"  KEV 目录 {len(result)} 条")
    return result


def fetch_epss(cve_ids: list[str], cfg: dict) -> dict[str, float]:
    """FIRST EPSS：未来 30 天被利用的概率。免费无 key，支持批量传 CVE。"""
    if not cve_ids:
        return {}
    log(f"查询 EPSS（{len(cve_ids)} 个 CVE）...")
    out: dict[str, float] = {}
    try:
        # 单次最多带 100 个，分批避免 URL 过长
        for i in range(0, len(cve_ids), 100):
            batch = cve_ids[i:i + 100]
            resp = http_get(f"{cfg['feeds']['epss_api']}?cve={','.join(batch)}", timeout=25)
            for row in resp.json().get("data", []):
                try:
                    out[row["cve"].upper()] = float(row["epss"])
                except (KeyError, ValueError):
                    continue
    except Exception as exc:  # noqa: BLE001
        log(f"  ! EPSS 失败，将只用 CVSS 和 KEV 评分：{exc}")
    return out


def fetch_nvd_by_cna(
    cna: str, since: datetime, until: datetime, cfg: dict,
    date_field: str = "lastMod", page_size: int = 200, max_pages: int = 30,
) -> list[dict]:
    """
    按 CNA（CVE 编号机构）拉取某厂商全产品线的 CVE，带分页。

    date_field 决定用哪个时间维度筛：
      - "lastMod"   —— 日常增量巡检用。窗口只有 1 天，落在这个区间的必然是新的。
      - "published" —— 历史回填必须用这个。lastMod 会把早年漏洞因为"改了句描述"
                        也算进最近一年，回填出来就变成一堆 2019 年的东西。
    """
    api_key = os.environ.get(cfg["nvd"]["api_key_env"], "").strip()
    headers = {"apiKey": api_key} if api_key else {}
    # NVD 要求 ISO8601 带时区，用 UTC
    fmt = "%Y-%m-%dT%H:%M:%S.000+00:00"
    s_str = since.astimezone(timezone.utc).strftime(fmt)
    e_str = until.astimezone(timezone.utc).strftime(fmt)
    params: dict[str, Any] = {"sourceIdentifier": cna, "resultsPerPage": page_size}
    if date_field == "published":
        params["pubStartDate"], params["pubEndDate"] = s_str, e_str
    else:
        params["lastModStartDate"], params["lastModEndDate"] = s_str, e_str

    # 无 key 限流 5 次/30 秒，有 key 50 次/30 秒。分页会连发多个请求，必须礼让。
    nap = 1.0 if api_key else 7.0
    log(f"拉取 NVD CNA={cna} [{since.strftime('%Y-%m-%d')} → {until.strftime('%Y-%m-%d')}] ...")

    raw: list[dict] = []
    total: int | None = None
    start = 0
    for page in range(max_pages):
        params["startIndex"] = start
        try:
            data = http_get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params, headers=headers, timeout=90,
            ).json()
        except Exception as exc:  # noqa: BLE001
            log(f"  ! NVD 失败 {cna} p{page + 1}：{exc}")
            break
        if total is None:
            total = int(data.get("totalResults", 0) or 0)
        batch = data.get("vulnerabilities", []) or []
        raw.extend(batch)
        start += len(batch)
        if not batch or start >= (total or 0):
            break
        time.sleep(nap)

    items: list[dict] = []
    for wrap in raw:
        cve = wrap.get("cve", {})
        cve_id = cve.get("id", "")
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        if not cve_id or desc.startswith(("Rejected reason", "DEPRECATED", "** REJECT **")):
            continue  # 拒收的作废号，直接跳过

        # 取最高版本 CVSS，同时保留向量用于推导攻击条件
        score = 0.0
        vector = ""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cvss_data = metrics[key][0].get("cvssData", {})
                s = float(cvss_data.get("baseScore", 0) or 0)
                if s > score:
                    score = s
                    vector = cvss_data.get("vectorString", "")
                if score > 0:
                    break

        items.append({
            "id": cve_id, "cve": cve_id, "title": desc[:180],
            "cvss": score, "cvss_vector": vector, "cvss_exact": True,
            "source": f"NVD/CNA:{cna}",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "published": cve.get("published", "")[:10],
            # CISA 官方处置动作，比我们瞎猜的修复建议权威
            "cisa_action": cve.get("cisaRequiredAction", "") or "",
            "cisa_due": cve.get("cisaActionDue", "") or "",
        })

    log(f"  拿到 {len(items)} 条（{cna}，原始 {len(raw)}/{total or '?'}）")
    if not api_key:
        time.sleep(7)  # 无 key 限流 5 req/30s，礼貌等待
    return items


def fetch_nvd_window(
    cna: str, start: datetime, end: datetime, cfg: dict,
    date_field: str = "published", chunk_days: int = 100,
) -> list[dict]:
    """
    回填用：NVD 单次查询的时间区间不能超过 120 天，这里按 100 天切段再合并。
    用 100 而不是 120，是给时区和 NVD 内部取整留余量。
    """
    out: list[dict] = []
    cur = start
    while cur < end:
        nxt = min(cur + timedelta(days=chunk_days), end)
        out.extend(fetch_nvd_by_cna(
            cna, cur, nxt, cfg, date_field=date_field,
            page_size=2000, max_pages=20,
        ))
        cur = nxt
    return out


def fetch_osv_asset(asset: dict, lookback_days: int, error_sink: list | None = None) -> list[dict]:
    """
    OSV：按包坐标 + 版本精确匹配。命中即代表你的项目真的用了受影响版本。

    error_sink：查询失败时把组件名记进去，让日报能如实标注"这个源没取到"，
    否则网络挂掉和"今天真的没漏洞"在消息里长得一模一样。
    """
    payload: dict[str, Any] = {"package": {"name": asset["name"], "ecosystem": asset.get("eco", "Maven")}}
    has_version = bool(str(asset.get("version") or "").strip())
    if has_version:
        payload["version"] = str(asset["version"]).strip()

    try:
        data = http_post("https://api.osv.dev/v1/query", payload).json()
    except Exception as exc:  # noqa: BLE001
        log(f"  ! OSV 失败 {asset['name']}：{exc}")
        if error_sink is not None:
            error_sink.append(asset["name"])
        return []

    cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    include_old = bool(asset.get("include_old"))
    items: list[dict] = []
    for v in data.get("vulns", []):
        # 统一按公布时间过滤：配了版本的也要过，否则该组件历史上的老漏洞会全被倒出来。
        # 想一次性盘点某组件的全部漏洞，给该 asset 加 include_old: true。
        stamp = (v.get("published") or v.get("modified") or "")[:20]
        if stamp and stamp < cutoff and not include_old:
            continue
        aliases = v.get("aliases", []) or []
        cve = next((a for a in aliases if a.startswith("CVE-")), "")
        if not cve and str(v.get("id", "")).startswith("CVE-"):
            cve = v["id"]
        # OSV 的 severity[].score 若以 CVSS: 开头就是标准向量，顺手拿来用
        vector = next(
            (s.get("score", "") for s in (v.get("severity") or []) if str(s.get("score", "")).startswith("CVSS:")),
            "",
        )
        items.append({
            "id": v.get("id", ""), "cve": cve, "title": (v.get("summary") or v.get("details", "")[:160]),
            "cvss": _extract_osv_severity(v), "cvss_exact": False, "source": f"OSV/{asset.get('eco')}",
            "cvss_vector": vector,
            "url": f"https://osv.dev/vulnerability/{v.get('id', '')}",
            "published": (v.get("published") or "")[:10],
            "asset": asset["name"],
            "asset_version": str(asset.get("version") or "未指定"),
            "affected_range": extract_affected_range(v),
            "exact_match": has_version,
        })
    return items


def _cvss_from_string(s: str) -> float:
    """把 CRITICAL/HIGH/MODERATE/LOW 之类的等级词换算成近似分值。"""
    s = (s or "").upper()
    if "CRITICAL" in s:
        return 9.5
    if "HIGH" in s:
        return 8.0
    if "MEDIUM" in s or "MODERATE" in s:
        return 5.5
    if "LOW" in s:
        return 2.5
    return 0.0


def _extract_osv_severity(v: dict) -> float:
    """
    从 OSV 记录里挖严重级别。
    注意：OSV 的 severity[].score 是 CVSS vector 字符串（CVSS:3.1/AV:N/...），
    里面并没有现成分值，直接字符串匹配 CRITICAL 会永远返回 0。
    真正的等级在 database_specific.severity 里。
    """
    ds = v.get("database_specific") or {}
    score = _cvss_from_string(str(ds.get("severity") or ""))
    if score:
        return score
    for aff in v.get("affected", []) or []:
        s = _cvss_from_string(str((aff.get("database_specific") or {}).get("severity") or ""))
        if s:
            return s
    for item in v.get("severity", []) or []:
        s = _cvss_from_string(str(item.get("score") or ""))
        if s:
            return s
    return 0.0


# ---------------------------- 影响分析 ----------------------------
# 光说"有个高危漏洞"没有决策价值。真正需要回答的是：
# 打进来之后会怎样、谁能打、我哪些版本中招。

# 漏洞类型 -> 实际业务后果。按顺序匹配，命中即用。
IMPACT_RULES: list[tuple[tuple[str, ...], str]] = [
    (("remote code execution", "arbitrary code", "code execution", "command injection",
      "代码执行", "命令执行", "rce"),
     "远程代码执行，攻击者可在服务器上执行任意命令，等同拿下主机"),
    (("deserialization", "反序列化"),
     "反序列化漏洞，构造恶意对象即可触发代码执行，常被用于拿 shell"),
    (("authentication bypass", "auth bypass", "improper authentication", "authentication by capture",
      "认证绕过", "身份验证绕过"),
     "身份认证绕过，未授权即可访问受保护资源，常被用于直接进入后台"),
    (("path traversal", "directory traversal", "path equivalence", "路径遍历", "目录遍历"),
     "路径遍历，可越权读取或写入服务器文件，通常可进一步提权或植入后门"),
    (("sql injection", "sql注入"),
     "SQL 注入，可读取或篡改数据库内容，严重时可写入文件获取权限"),
    (("cross-site scripting", "xss", "跨站脚本"),
     "跨站脚本，可窃取管理员会话，进而劫持后台操作"),
    (("ssrf", "server-side request forgery"),
     "SSRF，可借服务器身份探测或攻击内网，绕过边界防护"),
    (("xslt", "template injection", "表达式注入", "el injection"),
     "模板或表达式注入，可能演变为任意代码执行"),
    (("privilege escalation", "elevation of privilege", "权限提升"),
     "权限提升，可从低权限账户获取更高权限"),
    (("information disclosure", "information leak", "sensitive data", "missing encryption",
      "信息泄露", "敏感信息"),
     "敏感信息泄露，可能暴露凭据、密钥或业务数据"),
    (("denial of service", "resource exhaustion", "throttling", "dos", "拒绝服务"),
     "拒绝服务，可致服务不可用，影响业务连续性"),
    (("improper access control", "incorrect authorization", "improper authorization",
      "authorization bypass", "越权"),
     "访问控制缺陷，可越权访问他人或管理员数据"),
    (("improper input validation", "improper neutralization", "输入验证"),
     "输入校验不严，可被构造恶意请求触发异常行为，常是其他漏洞的入口"),
]

AV_LABEL = {"N": "可远程利用", "A": "需相邻网络", "L": "需本地访问", "P": "需物理接触"}
PR_LABEL = {"N": "无需任何认证", "L": "需低权限账户", "H": "需高权限账户"}


def classify_impact(title: str) -> str:
    """从标题/描述判断漏洞被利用后的实际后果。识别不出时返回空串，不硬编。"""
    t = (title or "").lower()
    for keys, consequence in IMPACT_RULES:
        if any(k in t for k in keys):
            return consequence
    return ""


def parse_cvss_vector(vector: str) -> dict[str, str]:
    """
    解析 CVSS 向量，取出攻击条件和 CIA 三要素。
    这比"CVSS 9.8"有用得多——同样是 9.8，能不能远程打、要不要登录，处置紧迫性完全不同。
    """
    out: dict[str, str] = {}
    for part in (vector or "").split("/"):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        out[k.upper()] = v.upper()
    return out


def describe_cvss(vector: str) -> str:
    """把 CVSS 向量翻译成一句人能看懂的攻击条件描述。"""
    m = parse_cvss_vector(vector)
    if not m:
        return ""
    bits = []
    if m.get("AV") in AV_LABEL:
        bits.append(AV_LABEL[m["AV"]])
    if m.get("PR") in PR_LABEL:
        bits.append(PR_LABEL[m["PR"]])
    # CIA：高影响才值得说
    cia = [name for key, name in (("C", "机密性"), ("I", "完整性"), ("A", "可用性")) if m.get(key) == "H"]
    if len(cia) == 3:
        bits.append("机密性/完整性/可用性全失")
    elif cia:
        bits.append("影响" + "、".join(cia))
    return " · ".join(bits)


def extract_affected_range(v: dict) -> str:
    """从 OSV 记录里还原受影响版本区间，直接告诉人"哪些版本中招"。"""
    parts: list[str] = []
    for aff in v.get("affected", []) or []:
        for r in aff.get("ranges", []) or []:
            intro = fixed = None
            for e in r.get("events", []) or []:
                if "introduced" in e and e["introduced"] != "0":
                    intro = e["introduced"]
                elif "fixed" in e:
                    fixed = e["fixed"]
            if fixed and len(parts) < 2:
                parts.append(f"{intro or '早期版本'} 至 {fixed} 之前")
    if not parts:
        # 退化方案：取受影响版本列表的首尾
        for aff in v.get("affected", []) or []:
            versions = aff.get("versions") or []
            if versions:
                parts.append(f"{versions[0]} ~ {versions[-1]}" if len(versions) > 1 else versions[0])
                break
    return "；".join(parts[:2])


def fetch_packagist_update(since_ts: int, cfg: dict) -> list[dict]:
    """Packagist：PHP 生态全量新增公告。免认证，自带 Composer 版本约束。"""
    log("拉取 Packagist 新增通告 ...")
    try:
        data = http_get(f"{cfg['feeds']['packagist_api']}?updatedSince={since_ts}", timeout=60).json()
    except Exception as exc:  # noqa: BLE001
        log(f"  ! Packagist 失败：{exc}")
        return []

    items: list[dict] = []
    for pkg, advs in (data.get("advisories") or {}).items():
        for a in advs:
            items.append({
                "id": a.get("advisoryId", ""), "cve": a.get("cve") or "",
                "title": f"[{pkg}] {a.get('title', '')}"[:180],
                "cvss": _cvss_from_string(a.get("severity", "")), "cvss_exact": False,
                "source": "Packagist", "url": a.get("link", ""),
                "published": (a.get("reportedAt") or "")[:10],
                "asset": pkg, "asset_version": a.get("affectedVersions", ""),
                "exact_match": True,
            })
    log(f"  拿到 {len(items)} 条")
    return items


# OSV 的 ecosystem 名与 GitHub Advisory REST 的枚举值不一致，必须映射，
# 否则 GitHub 直接返回 422（Maven / Packagist 都是错的写法）。
GH_ECO_MAP = {
    "Maven": "maven", "Packagist": "composer", "PyPI": "pip",
    "npm": "npm", "Go": "go", "crates.io": "rust", "NuGet": "nuget",
}


def fetch_github_advisories(
    ecosystems: list[str], since: datetime, cfg: dict, max_pages: int = 3,
) -> list[dict]:
    """
    GitHub Advisory：匿名可调但限流 60 次/小时，配 GITHUB_TOKEN 提到 5000。
    published 参数要传日期区间 "A..B"，不是 ">=A"。
    max_pages：日常增量 3 页（300 条）够用；一年回填要放大。
    """
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    published = f"{since.strftime('%Y-%m-%d')}..{today}"
    items: list[dict] = []

    for eco in ecosystems:
        gh_eco = GH_ECO_MAP.get(eco)
        if not gh_eco:
            continue
        page = 1
        while page <= max_pages:
            try:
                resp = http_get(cfg["feeds"]["github_advisories"], params={
                    "ecosystem": gh_eco, "per_page": 100, "page": page, "published": published,
                }, headers=headers)
                batch = resp.json()
            except Exception as exc:  # noqa: BLE001
                log(f"  ! GitHub Advisory 失败 {gh_eco} p{page}：{exc}")
                break
            if not isinstance(batch, list) or not batch:
                break
            for a in batch:
                items.append({
                    "id": a.get("ghsa_id", ""), "cve": (a.get("cve_id") or "").upper(),
                    "title": (a.get("summary") or "")[:180],
                    "cvss": float((a.get("cvss") or {}).get("score") or 0), "cvss_exact": True,
                    "source": f"GitHub/{gh_eco}", "url": a.get("html_url", ""),
                    "published": (a.get("published_at") or "")[:10],
                })
            if len(batch) < 100:
                break
            page += 1
            time.sleep(1)
        time.sleep(1)

    log(f"GitHub Advisory 拿到 {len(items)} 条")
    return items


# ---------------------------- 归一化与打分 ----------------------------

def normalize_and_score(
    items: list[dict], kev: dict, epss: dict, cfg: dict,
    keywords: list[str], excludes: list[str] | None = None,
) -> list[dict]:
    """
    合并去重 -> 打标 -> 评分 -> 过滤。
    以 CVE 为准，没有 CVE 时退化为源内 ID。
    """
    policy = cfg["policy"]
    excludes = excludes or []
    merged: dict[str, dict] = {}

    for it in items:
        key = it.get("cve") or it.get("id")
        if not key:
            continue
        if key in merged:
            # 同一条漏洞被多个源捞到时合并来源；CVSS 优先采信精确值
            cur = merged[key]
            new_exact = it.get("cvss_exact", False)
            if new_exact and not cur.get("cvss_exact", False):
                cur["cvss"], cur["cvss_exact"] = it.get("cvss", 0.0), True
            elif new_exact == cur.get("cvss_exact", False):
                cur["cvss"] = max(cur.get("cvss", 0), it.get("cvss", 0))
            if it["source"] not in cur["sources"]:
                cur["sources"].append(it["source"])
            if it.get("asset") and it["asset"] not in cur.get("assets", []):
                cur.setdefault("assets", []).append(it["asset"])
            if it.get("exact_match"):
                cur["exact_match"] = True
            # 补全影响分析所需的字段，先到先得但不覆盖已有值
            for f in ("cvss_vector", "affected_range", "cisa_action", "cisa_due"):
                if it.get(f) and not cur.get(f):
                    cur[f] = it[f]
            continue
        merged[key] = {
            "key": key, "cve": it.get("cve", ""), "title": it.get("title", ""),
            "cvss": it.get("cvss", 0.0), "cvss_exact": it.get("cvss_exact", False),
            "sources": [it["source"]],
            "url": it.get("url", ""), "published": it.get("published", ""),
            "assets": [it["asset"]] if it.get("asset") else [],
            "asset_version": it.get("asset_version", ""),
            "affected_range": it.get("affected_range", ""),
            "cvss_vector": it.get("cvss_vector", ""),
            "cisa_action": it.get("cisa_action", ""),
            "cisa_due": it.get("cisa_due", ""),
            "exact_match": it.get("exact_match", False),
        }

    results: list[dict] = []
    for v in merged.values():
        cve = v["cve"].upper()
        k = kev.get(cve) if cve else None
        v["kev"] = bool(k)
        if k:
            v["kev_added"] = k.get("kev_added", "")
            v["ransomware"] = k.get("ransomware", "")
            v["kev_vendor"] = k.get("vendor", "")
            v["kev_product"] = k.get("product", "")
        v["epss"] = epss.get(cve, 0.0)

        # 影响分析：被利用后会造成什么后果、需要什么攻击条件
        v["impact"] = classify_impact(v["title"])
        v["attack_cond"] = describe_cvss(v.get("cvss_vector", ""))

        # 关键词粗筛：只对"非组件精确匹配"的条目生效，
        # 组件精确命中的不再二次过滤，避免误杀。
        if not v["exact_match"] and keywords:
            blob = f"{v['title']} {' '.join(v.get('assets', []))}".lower()
            if not any(kw.lower() in blob for kw in keywords):
                continue
            # 排除词：避免"Redis Lua overflow in Apache Kvrocks"这类串台误报
            if excludes and any(x.lower() in blob for x in excludes):
                continue

        # 综合分：在野利用权重最高，其次 CVSS，再叠 EPSS 概率
        score = 0.0
        if v["kev"]:
            score += 100
        if v["cvss"] >= 9.0:
            score += 50
        elif v["cvss"] >= policy["min_cvss"]:
            score += 30
        score += v["epss"] * 40
        v["score"] = round(score, 1)

        # 分级。核心思想：CVSS 高分不等于要半夜爬起来。
        # 只有三种情况配 P0：已确认在野利用 / 自己的组件且致命 / 致命且大概率被利用。
        cvss, epss_v, exact = v["cvss"], v["epss"], v["exact_match"]
        if v["kev"]:
            v["level"] = "P0"
        elif exact and cvss >= policy["always_push_cvss"]:
            v["level"] = "P0"
        elif cvss >= policy["always_push_cvss"] and epss_v >= policy["epss_threshold"]:
            v["level"] = "P0"
        elif exact and cvss >= policy["min_cvss"]:
            v["level"] = "P1"  # 自己项目用的组件，必须看
        elif cvss >= policy["min_cvss"] and epss_v >= policy["epss_threshold"]:
            v["level"] = "P1"
        elif cvss >= policy["min_cvss"]:
            v["level"] = "P2"  # 分数高但与你无关且无人利用，降级观察
        else:
            continue  # 低分且无在野利用迹象，不打扰

        # 陈旧条目：NVD 的窗口按 lastModified 算，几年前的漏洞改个措辞也会被捞进来。
        # 日报只报增量，老漏洞一律不占版面（已进 KEV 的除外，那说明出了新情况）。
        stale_days = int(policy.get("stale_days", 0) or 0)
        if stale_days and not v["kev"]:
            pub = (v.get("published") or "")[:10]
            if pub:
                try:
                    pub_dt = datetime.fromisoformat(pub).replace(tzinfo=timezone.utc)
                    if (datetime.now(timezone.utc) - pub_dt).days > stale_days:
                        continue
                except ValueError:
                    pass

        results.append(v)

    results.sort(key=lambda x: (x["score"], x["cvss"]), reverse=True)
    return results


# ---------------------------- 输出与推送 ----------------------------

LEVEL_ICON = {"P0": "🔴", "P1": "🟠", "P2": "🟡"}
LEVEL_TITLE = {"P0": "立即处置", "P1": "本周处置", "P2": "观察列表"}

# 组件坐标 -> 人能看懂的名字
COMPONENT_ALIAS = {
    "tomcat-catalina": "Apache Tomcat", "tomcat-embed-core": "Tomcat Embedded",
    "spring-core": "Spring Framework", "spring-webmvc": "Spring MVC",
    "spring-boot": "Spring Boot", "spring-security-web": "Spring Security",
    "log4j-core": "Log4j2", "logback-classic": "Logback", "fastjson": "Fastjson",
    "jackson-databind": "Jackson", "shiro-core": "Shiro", "struts2-core": "Struts2",
    "dubbo": "Dubbo", "mysql-connector-j": "MySQL Connector",
    "laravel/framework": "Laravel", "symfony/http-kernel": "Symfony",
    "topthink/framework": "ThinkPHP", "guzzlehttp/guzzle": "Guzzle",
    "phpmailer/phpmailer": "PHPMailer", "monolog/monolog": "Monolog",
}
SEP = "━" * 14


# 从标题反推组件名，补 NVD 条目没有 asset 坐标的情况
TITLE_HINTS = [
    ("apache tomcat", "Apache Tomcat"), ("tomcat", "Apache Tomcat"),
    ("weblogic", "Oracle WebLogic"), ("struts", "Apache Struts"),
    ("activemq", "ActiveMQ"), ("pulsar", "Apache Pulsar"),
    ("kafka", "Apache Kafka"), ("solr", "Apache Solr"),
    ("airflow", "Apache Airflow"), ("ofbiz", "Apache OFBiz"),
    ("apache http server", "Apache HTTPD"), ("httpd", "Apache HTTPD"),
    ("nginx", "Nginx"), ("openssl", "OpenSSL"), ("openssh", "OpenSSH"),
    ("spring framework", "Spring Framework"), ("spring boot", "Spring Boot"),
    ("redis", "Redis"), ("elasticsearch", "Elasticsearch"),
    ("jenkins", "Jenkins"), ("gitlab", "GitLab"), ("zookeeper", "ZooKeeper"),
]

# CNA 归属映射：NVD 条目没有资产坐标也没有明显标题特征时的最后兜底
CNA_VENDOR = {
    "security@apache.org": "Apache",
    "security@php.net": "PHP",
    "secalert_us@oracle.com": "Oracle",
}

# 分级严重度排序，数字越小越严重。合并同一 CVE 的多份记录时取更严重的一级
LEVEL_RANK = {"P0": 0, "P1": 1, "P2": 2}


def _component_name(v: dict) -> str:
    """给出条目的组件可读名，取不到就返回空串，不硬凑。"""
    for asset in v.get("assets", []):
        short = asset.split(":")[-1] if ":" in asset else asset
        if short in COMPONENT_ALIAS:
            return COMPONENT_ALIAS[short]
        if asset in COMPONENT_ALIAS:
            return COMPONENT_ALIAS[asset]
        return short
    # 没有资产坐标时，从标题里认
    title = (v.get("title") or "").lower()
    for key, name in TITLE_HINTS:
        if key in title:
            return name
    # 再退一层：KEV 里有官方厂商/产品名，比标题猜得准
    if v.get("kev_vendor"):
        prod = v.get("kev_product") or ""
        return f"{v['kev_vendor']} {prod}".strip()
    # 最后退到 CNA 归属：至少让人知道这是 Apache 还是 Oracle 的洞
    for src in v.get("sources", []):
        if src.startswith("NVD/CNA:"):
            vendor = CNA_VENDOR.get(src.split("NVD/CNA:", 1)[1], "")
            if vendor:
                return vendor
    return ""


def _short_action(text: str) -> str:
    """
    CISA 的 requiredAction 经常是几百字的合规模板，全是 BOD 条款引用，
    对工程师没有任何操作价值。这类压缩成一句话，其余保留但截断。
    """
    t = (text or "").strip()
    if not t:
        return ""
    if "BOD 26-04" in t or "Forensics Triage" in t:
        return "按厂商公告升级；无法修复的立即下线该服务"
    return t[:90] + ("…" if len(t) > 90 else "")


def _render_item(idx: int, v: dict, full: bool = True) -> list[str]:
    """
    单条漏洞的多行描述。信息密度优先，但不堆砌。

    full=True 用于 P0/P1：影响 + 条件 + 范围 + 处置 + 链接
    full=False 用于紧凑列表：只留影响与条件各一行，把篇幅让给条数
    """
    cve = v["cve"] or v["key"]
    comp = _component_name(v)
    head = f"**{idx}. {cve}**"
    if comp:
        head += f" · {comp}"

    # 第二行：分数 + 关键标签
    cvss_str = f"CVSS {v['cvss']:.1f}" if v.get("cvss_exact") else f"CVSS≈{v['cvss']:.1f}"
    tags = [cvss_str]
    if v["kev"]:
        tags.append("已进 KEV")
    if v["epss"] > 0:
        tags.append(f"EPSS {v['epss']:.0%}")
    if v.get("ransomware") == "Known":
        tags.append("勒索软件在用")
    lines = [head, "　" + " ｜ ".join(tags)]

    # 影响：被利用之后会怎样
    lim = 70 if full else 48
    if v.get("impact"):
        lines.append(f"　▸ {v['impact']}")
    elif v.get("title"):
        t = v["title"][:lim]
        lines.append(f"　▸ {t}")

    # 攻击条件：谁能打、要不要登录
    if v.get("attack_cond"):
        lines.append(f"　▸ {v['attack_cond']}")

    if not full:
        # 紧凑模式到此为止，链接附在行尾省一行
        if v["url"]:
            lines.append(f"　▸ [详情]({v['url']})")
        return lines

    # 受影响范围
    rng = v.get("affected_range") or v.get("asset_version")
    if rng and rng != "未指定":
        lines.append(f"　▸ 范围：{rng[:80]}")

    # CISA 官方处置动作，比自拟建议权威（但是模板文字会压掉）
    action = _short_action(v.get("cisa_action", ""))
    if action:
        lines.append(f"　▸ 处置：{action}")
    if v["url"]:
        lines.append(f"　▸ [详情]({v['url']})")
    return lines


def render_markdown(items: list[dict], stats: dict) -> str:
    """
    渲染日报。格式对齐资讯简报：先给时间和数量，再分组给具体条目。
    信息层级：一眼看到今天几条、几条要紧、每条会有什么后果。
    """
    if not items:
        return ""
    since: datetime = stats["since"]
    until: datetime = stats["until"]
    scanned = stats.get("scanned", 0)
    sources = stats.get("sources", [])

    p0 = [i for i in items if i["level"] == "P0"]
    p1 = [i for i in items if i["level"] == "P1"]
    p2 = [i for i in items if i["level"] == "P2"]

    lines = [
        f"**🛡 漏洞情报全景 · {until.strftime('%m月%d日 %H:%M')}**",
        "",
        f"📅 统计区间　{since.strftime('%m-%d %H:%M')} → {until.strftime('%m-%d %H:%M')}",
        f"📊 采集 **{scanned}** 条 · 命中 **{len(items)}** 条",
        f"　　🔴 立即处置 {len(p0)} ｜ 🟠 本周处置 {len(p1)} ｜ 🟡 观察 {len(p2)}",
    ]
    if sources:
        lines.append(f"🔍 数据源　{' · '.join(sources)}")
    if stats.get("degraded"):
        lines.append(f"⚠️ {'；'.join(stats['degraded'])}")

    idx = 0
    # 日报控制在一条消息内看完：P0 详述、P1 紧凑、P2 只留编号
    if p0:
        lines += ["", SEP, "", f"**🔴 立即处置（{len(p0)} 条）**", ""]
        for v in p0:
            idx += 1
            lines += _render_item(idx, v, full=True)
            lines.append("")

    if p1:
        lines += [SEP, "", f"**🟠 本周处置（{len(p1)} 条）**", ""]
        for v in p1:
            idx += 1
            lines += _render_item(idx, v, full=False)
            lines.append("")

    # P2 只列编号，不占篇幅
    if p2:
        names = "、".join((x["cve"] or x["key"]) for x in p2[:8])
        more = f" 等 {len(p2)} 条" if len(p2) > 8 else ""
        lines += [SEP, "", f"**🟡 观察列表**　{names}{more}", ""]

    return "\n".join(lines).strip()


def render_degraded(stats: dict) -> str:
    """
    没有条目、但有数据源故障时发的短消息。
    这种情况最危险：一次代理故障会让日报安静得像"一切太平"，
    所以宁可多发一条，也要把"结果不完整"说到明面上。
    """
    until = stats["until"]
    lines = [
        f"**⚠️ 漏洞情报巡检异常 · {until.strftime('%m月%d日')}**",
        "",
        f"📅 统计区间　{stats['since'].strftime('%m-%d %H:%M')} → {until.strftime('%m-%d %H:%M')}",
        f"📊 采集 {stats.get('scanned', 0)} 条，没有可推送条目",
        "",
        "但以下数据源本轮异常，**结果不完整**，不能当作今天没有漏洞：",
    ]
    for d in stats.get("degraded", []):
        lines.append(f"❗ {d}")
    lines += [
        "",
        "修复网络或代理后手动补跑一次：",
        "`/opt/vuln-watch/run.sh --days 1`",
    ]
    return "\n".join(lines)


def _load_web_data(out_file: Path) -> dict:
    """
    读取既有网页数据，兼容早期"按天数组"格式，
    避免升级格式时把已经攒下的历史冲掉。
    """
    if not out_file.exists():
        return {"entries": []}
    try:
        raw = json.loads(out_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"entries": []}
    if isinstance(raw, list):          # 旧格式：每天一个快照
        merged: list[dict] = []
        for day in raw:
            merged.extend(day.get("entries") or [])
        return {"entries": merged}
    if isinstance(raw, dict):
        return raw
    return {"entries": []}


def _web_entry(v: dict) -> dict:
    """把内部条目压成前端消费的行。只留页面要用的字段，一年数据量不小。"""
    return {
        "cve": v.get("cve") or v.get("key", ""),
        "level": v.get("level", ""),
        "cvss": round(v.get("cvss", 0.0), 1),
        "cvss_exact": bool(v.get("cvss_exact")),
        "kev": bool(v.get("kev")),
        "epss": round(v.get("epss", 0.0), 4),
        "ransomware": v.get("ransomware", ""),
        "impact": (v.get("impact") or "")[:120],
        "attack_cond": (v.get("attack_cond") or "")[:120],
        "affected_range": (v.get("affected_range") or "")[:120],
        "component": _component_name(v),
        "title": (v.get("title") or "")[:150],
        "url": v.get("url", ""),
        "sources": v.get("sources", []),
        "exact_match": bool(v.get("exact_match")),
        "published": (v.get("published") or "")[:10],
    }


def write_web_data(items: list[dict], stats: dict, cfg: dict, mode: str = "daily") -> None:
    """
    把条目导出为 web/data.json，供前端全景页读取。

    格式 v2：单对象。entries 是扁平去重清单，daily 是按"发布日期"分桶的统计。
    早先是"每天一个快照"的数组，回填一年会变成 365 个块、同一条漏洞还会在
    多个块里重复；改成单清单后，跨天去重、按时间筛选、趋势聚合都直接得多。

    与推送的关系：纯旁路，不碰 state.db 水位，也不影响日报发送。
    """
    out_dir = Path(ROOT) / "web"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "data.json"

    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    old = _load_web_data(out_file)

    # 以 CVE 为主键合并。同一条漏洞被回填和日常巡检都抓到时，保留信息更全的一份
    book: dict[str, dict] = {}
    for e in old.get("entries") or []:
        key = (e.get("cve") or "").upper()
        if key:
            book[key] = e

    fresh = 0
    for v in items:
        e = _web_entry(v)
        key = (e["cve"] or "").upper()
        if not key:
            continue
        prev = book.get(key)
        if prev is None:
            fresh += 1
        else:
            # 旧条目里有、新条目里缺的字段补回来（例如回填拿不到的版本范围）
            for f, val in prev.items():
                if not e.get(f) and val:
                    e[f] = val
            # 分级取更严重的那个：宁可多报一级，也别把 P0 降成 P2
            if LEVEL_RANK.get(e.get("level"), 9) > LEVEL_RANK.get(prev.get("level"), 9):
                e["level"] = prev["level"]
        book[key] = e

    # 保留窗口：默认 400 天，比一年略宽，避免回填后旧数据瞬间消失
    retention = int((cfg.get("backfill") or {}).get("retention_days", 400))
    cutoff = (now - timedelta(days=retention)).strftime("%Y-%m-%d")
    entries = [e for e in book.values() if not e.get("published") or e["published"] >= cutoff]
    entries.sort(key=lambda e: (e.get("published") or "", e.get("cvss") or 0), reverse=True)

    # 按发布日期分桶，供前端画趋势。
    # 用发布日期而不是采集日，否则回填那天所有历史都会堆成一根柱子。
    buckets: dict[str, dict] = {}
    for e in entries:
        d = e.get("published") or today
        b = buckets.setdefault(d, {"date": d, "hit": 0, "p0": 0, "p1": 0, "p2": 0})
        b["hit"] += 1
        lv = e.get("level")
        if lv in ("P0", "P1", "P2"):
            b[lv.lower()] += 1

    def count(lv: str) -> int:
        return sum(1 for e in entries if e.get("level") == lv)

    payload = {
        "format": 2,
        "generated_at": now.isoformat(),
        "mode": mode,
        "range": {
            "from": entries[-1].get("published") if entries else "",
            "to": entries[0].get("published") if entries else "",
        },
        "stats": {
            "total": len(entries),
            "p0": count("P0"),
            "p1": count("P1"),
            "p2": count("P2"),
            "kev": sum(1 for e in entries if e.get("kev")),
            "exact": sum(1 for e in entries if e.get("exact_match")),
            "scanned": stats.get("scanned", 0),
            "new_this_run": fresh,
        },
        "last_run": {
            "date": today,
            "at": now.isoformat(),
            "mode": mode,
            "hit": len(items),
            "p0": sum(1 for v in items if v.get("level") == "P0"),
            "p1": sum(1 for v in items if v.get("level") == "P1"),
            "p2": sum(1 for v in items if v.get("level") == "P2"),
        },
        "sources": stats.get("sources", []),
        "degraded": stats.get("degraded", []),
        "daily": [buckets[d] for d in sorted(buckets)],
        "entries": entries,
    }

    out_file.write_text(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    size_kb = out_file.stat().st_size / 1024
    log(
        f"网页数据已写入 web/data.json（本轮 {len(items)} 条，新增 {fresh} 条，"
        f"累计 {len(entries)} 条 / {len(buckets)} 天，{size_kb:.0f} KB）"
    )


def split_by_bytes(text: str, max_bytes: int) -> list[str]:
    chunks, cur = [], ""
    for line in text.split("\n"):
        candidate = f"{cur}\n{line}" if cur else line
        if len(candidate.encode("utf-8")) > max_bytes and cur:
            chunks.append(cur)
            cur = line
        else:
            cur = candidate
    if cur:
        chunks.append(cur)
    return chunks


def push_wecom(text: str, cfg: dict) -> bool:
    """推送到企业微信群机器人"""
    hook = os.environ.get(cfg["wecom"]["webhook_env"], "").strip()
    if not hook:
        log(f"! 未设置环境变量 {cfg['wecom']['webhook_env']}，跳过推送")
        return False
    ok = True
    for idx, chunk in enumerate(split_by_bytes(text, cfg["wecom"]["max_bytes"]), 1):
        try:
            resp = requests.post(hook, json={"msgtype": "markdown", "markdown": {"content": chunk}}, timeout=15)
            body = resp.json()
            if body.get("errcode") != 0:
                log(f"  ! 推送第 {idx} 段失败：{body}")
                ok = False
            else:
                log(f"  推送第 {idx} 段成功（{len(chunk.encode('utf-8'))} 字节）")
        except Exception as exc:  # noqa: BLE001
            log(f"  ! 推送异常：{exc}")
            ok = False
        time.sleep(1)
    return ok


def _resolve_chat_id(cfg: dict) -> str:
    """
    确定推送目标。优先级：环境变量 > 配置文件 > 从 wecom-cli 取当前授权人。
    默认发给自己（授权人）是最合理的默认行为。
    """
    import re
    import subprocess

    env_key = cfg["wecom"].get("chat_id_env", "WECOM_CHAT_ID")
    chat_id = os.environ.get(env_key, "").strip() or str(cfg["wecom"].get("chat_id") or "").strip()
    if chat_id:
        return chat_id
    try:
        r = subprocess.run(["wecom-cli", "identity", "whoami"], capture_output=True, text=True, timeout=30)
        ctx = json.loads(r.stdout).get("extra_identity_context", "")
        m = re.search(r"授权真人用户身份：[\s\S]*?ID：([A-Za-z0-9_\-]+)", ctx)
        if m:
            return m.group(1)
    except Exception as exc:  # noqa: BLE001
        log(f"  ! 自动解析授权人失败：{exc}")
    return ""


def push_wecom_cli(text: str, cfg: dict) -> bool:
    """
    走 wecom-cli 发送，复用已授权的企业微信机器人通道。
    相比群机器人 webhook，好处是不用把密钥写进配置文件、不受 20 条/分钟限制。
    """
    import subprocess

    chat_id = _resolve_chat_id(cfg)
    if not chat_id:
        log("! 未能确定推送目标，跳过 CLI 推送（检查 wecom-cli 授权状态）")
        return False

    ok = True
    for idx, chunk in enumerate(split_by_bytes(text, cfg["wecom"]["max_bytes"]), 1):
        payload = {"chat_id": chat_id, "msg_type": "markdown", "markdown": {"content": chunk}}
        try:
            r = subprocess.run(
                ["wecom-cli", "message", "aibot", "send", "--json",
                 json.dumps(payload, ensure_ascii=False)],
                capture_output=True, text=True, timeout=90,
            )
            try:
                body = json.loads(r.stdout)
            except (json.JSONDecodeError, TypeError):
                body = {}
            if r.returncode != 0 or body.get("success") is not True:
                log(f"  ! CLI 推送第 {idx} 段失败：{(r.stderr or r.stdout).strip()[:200]}")
                ok = False
            else:
                log(f"  CLI 推送第 {idx} 段成功（{len(chunk.encode('utf-8'))} 字节）")
        except Exception as exc:  # noqa: BLE001
            log(f"  ! CLI 推送异常：{exc}")
            ok = False
        time.sleep(1)
    return ok


def _load_app_creds(cfg: dict) -> dict:
    """
    企业微信自建应用凭据。优先级：环境变量 > 0600 的 env 文件。
    凭证永远不进配置文件、不进仓库，这是硬约束。
    """
    keys = ("WX_CORPID", "WX_SECRET", "WX_AGENTID")
    creds = {k: os.environ.get(k, "").strip() for k in keys}
    if all(creds.values()):
        return creds

    env_file = (
        os.environ.get(cfg["wecom"].get("app_env_file_env", "WECOM_APP_ENV"), "").strip()
        or str(cfg["wecom"].get("app_env_file") or "").strip()
    )
    if env_file:
        p = Path(env_file).expanduser()
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip() in keys and not creds.get(k.strip()):
                    creds[k.strip()] = v.strip()
        else:
            log(f"  ! 应用凭据文件不存在：{p}")
    return creds


def _app_access_token(corpid: str, secret: str) -> str:
    resp = requests.get(
        "https://qyapi.weixin.qq.com/cgi-bin/gettoken",
        params={"corpid": corpid, "corpsecret": secret}, timeout=15,
    )
    body = resp.json()
    if body.get("errcode"):
        raise RuntimeError(f"errcode={body.get('errcode')} {body.get('errmsg')}")
    return body["access_token"]


def push_wecom_app(text: str, cfg: dict) -> bool:
    """
    走企业微信自建应用 message/send。服务器上没有 wecom-cli，这条通道才是主力。
    注意：应用若配置了可信 IP 白名单，未授权 IP 调用会报 60020，此时只能在该 IP 的机器上发。
    """
    creds = _load_app_creds(cfg)
    missing = [k for k in ("WX_CORPID", "WX_SECRET", "WX_AGENTID") if not creds.get(k)]
    if missing:
        log(f"! 自建应用凭据缺失：{','.join(missing)}，跳过推送")
        return False

    touser = (
        os.environ.get(cfg["wecom"].get("touser_env", "WX_TOUSER"), "").strip()
        or str(cfg["wecom"].get("touser") or "").strip()
        or _resolve_chat_id(cfg)
    )
    if not touser:
        log("! 未能确定应用消息收件人（设置环境变量 WX_TOUSER 或配置 wecom.touser）")
        return False

    try:
        token = _app_access_token(creds["WX_CORPID"], creds["WX_SECRET"])
    except Exception as exc:  # noqa: BLE001
        log(f"! 获取 access_token 失败：{exc}")
        return False

    # 应用消息 markdown 上限 2048 字节，实际按 1800 切，留出多段续标的空间
    limit = min(int(cfg["wecom"]["max_bytes"]), int(cfg["wecom"].get("app_max_bytes", 1800)))
    ok = True
    for idx, chunk in enumerate(split_by_bytes(text, limit), 1):
        payload = {
            "touser": touser,
            "msgtype": "markdown",
            "agentid": int(creds["WX_AGENTID"]),
            "markdown": {"content": chunk},
        }
        try:
            resp = requests.post(
                "https://qyapi.weixin.qq.com/cgi-bin/message/send",
                params={"access_token": token}, json=payload, timeout=20,
            )
            body = resp.json()
            if body.get("errcode") != 0:
                log(f"  ! 应用推送第 {idx} 段失败：errcode={body.get('errcode')} {body.get('errmsg')}")
                ok = False
            else:
                log(f"  应用推送第 {idx} 段成功（{len(chunk.encode('utf-8'))} 字节）")
        except Exception as exc:  # noqa: BLE001
            log(f"  ! 应用推送异常：{exc}")
            ok = False
        time.sleep(1)
    return ok


# ---------------------------- 主流程 ----------------------------

def run_backfill(cfg: dict, days: int) -> int:
    """
    一次性历史回填：把最近 N 天的漏洞灌进全景页，**不推送任何消息**。

    两条刻意的设计：
    1. 不写 state.db 水位、不 mark_seen。
       mark_seen 尤其危险——回填会把整整一年的漏洞标成"已读"，
       明天真有新漏洞时日常任务就当成旧的漏掉了。
    2. 区间只取到"昨天 00:00"，今天产生的留给日常任务去推送。
       这样回填和推送各管一段，既不重复也不漏。
    """
    bf = cfg.get("backfill") or {}
    now = datetime.now(timezone.utc)
    end = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=days)
    log(f"历史回填区间：{start.strftime('%Y-%m-%d')} → {end.strftime('%Y-%m-%d')}（{days} 天，不推送）")

    # 回填必须放宽两处策略，否则一年数据会被"只报新增"的规则全部过滤掉：
    #   stale_days=0 → 关掉"发布超过 N 天丢弃"
    #   keyword_watch → 全景页按 CNA 全量收录，不再做关键词粗筛
    cfg_bf = dict(cfg)
    cfg_bf["policy"] = {
        **cfg["policy"],
        "stale_days": 0,
        "min_cvss": float(bf.get("min_cvss", cfg["policy"]["min_cvss"])),
    }
    use_keywords = bool(bf.get("keyword_filter", False))
    keywords = cfg.get("keyword_watch", []) if use_keywords else []
    excludes = cfg.get("keyword_exclude", []) if use_keywords else []

    raw: list[dict] = []

    # 1) NVD：按 CNA 拉厂商全量，按发布时间切段
    chunk = int(bf.get("nvd_chunk_days", 100))
    for cna in cfg["nvd"].get("cnas", []):
        raw.extend(fetch_nvd_window(cna, start, end, cfg, date_field="published", chunk_days=chunk))

    # 2) OSV：组件维度，回填窗口 = 整个区间
    log("按组件清单查询 OSV（历史窗口）...")
    osv_failed: list[str] = []
    assets_all = cfg["osv"].get("assets", [])
    for asset in assets_all:
        hits = fetch_osv_asset(asset, days, osv_failed)
        if hits:
            log(f"  {asset['name']}@{asset.get('version') or '未指定'} → {len(hits)} 条")
        raw.extend(hits)

    # 3) Packagist PHP 生态
    raw.extend(fetch_packagist_update(int(start.timestamp()), cfg))

    # 4) GitHub Advisory
    ecos = sorted({a.get("eco", "Maven") for a in assets_all})
    raw.extend(fetch_github_advisories(ecos, start, cfg, max_pages=int(bf.get("gh_max_pages", 12))))

    total_scanned = len(raw)
    log(f"原始采集 {total_scanned} 条，开始富化与打分 ...")

    # 5) KEV + EPSS
    kev = fetch_cisa_kev(cfg)
    cves = sorted({i["cve"].upper() for i in raw if i.get("cve")})
    epss = fetch_epss(cves, cfg)

    items = normalize_and_score(raw, kev, epss, cfg_bf, keywords, excludes)

    # 兜底上限：正常一年约两千条，但 Oracle 季度批量公告一次能灌上千条，
    # 万一某天数据源异常放大，别让 data.json 撑爆页面。
    cap = int(bf.get("max_entries", 6000))
    if len(items) > cap:
        log(f"  ! 命中 {len(items)} 条超过上限 {cap}，按严重度截断（在野利用与高分优先）")
        items = items[:cap]

    log(f"回填命中 {len(items)} 条（P0 {sum(1 for i in items if i['level']=='P0')} / "
        f"P1 {sum(1 for i in items if i['level']=='P1')} / "
        f"P2 {sum(1 for i in items if i['level']=='P2')}）")

    srcs: list[str] = []
    for i in raw:
        name = i["source"].split("/")[0].split(":")[0]
        if name not in srcs:
            srcs.append(name)
    for extra in ("KEV", "EPSS"):
        if extra not in srcs:
            srcs.append(extra)

    degraded: list[str] = []
    if not kev:
        degraded.append("CISA KEV 未取到，在野利用标记失效")
    if osv_failed:
        degraded.append(f"OSV {len(osv_failed)}/{len(assets_all)} 个组件失败")

    stats = {
        "scanned": total_scanned,
        "since": start,
        "until": end,
        "sources": srcs,
        "degraded": degraded,
    }
    write_web_data(items, stats, cfg_bf, mode="backfill")
    log("回填完成。未推送任何消息，也未改动 state.db 水位。")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="漏洞情报采集与企业微信推送")
    ap.add_argument("--dry-run", action="store_true", help="只采集打印，不推送")
    ap.add_argument("--days", type=int, default=0, help="覆盖回看天数")
    ap.add_argument("--backfill", type=int, default=0, metavar="DAYS",
                    help="历史回填：抓最近 N 天漏洞写入全景页，不推送、不动水位")
    ap.add_argument("--via", choices=["cli", "webhook", "app", "both"], default="",
                    help="推送通道，默认读配置 wecom.channel（可用环境变量 WECOM_CHANNEL 覆盖）")
    ap.add_argument("--no-commit", action="store_true",
                    help="照常推送，但不写入已读水位（用于验收预览，下次仍会重发）")
    ap.add_argument("--config", default=str(CFG_PATH))
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    # 回填是独立通道：不碰推送、不碰水位，跑完就退出
    if args.backfill > 0:
        return run_backfill(cfg, args.backfill)

    conn = init_db()
    now = datetime.now(timezone.utc)

    # 窗口：只推最近 N 天（默认 1 天）。水位只用来"缩短"窗口，绝不用来"拉长"，
    # 否则某次失败或首次运行会把几天的存量一次性倒出来。
    last_run = db_get(conn, "last_run")
    days = args.days or int(cfg["nvd"].get("lookback_days", 1))
    window_start = now - timedelta(days=days)
    since = window_start
    if last_run:
        try:
            prev = datetime.fromisoformat(last_run)
            if prev.tzinfo is None:
                prev = prev.replace(tzinfo=timezone.utc)
            since = max(prev, window_start)   # 取较晚者，水位再旧也不回补历史
        except ValueError:
            pass
    log(f"采集窗口：{since.strftime('%Y-%m-%d %H:%M')} UTC 起（上限 {days} 天）")

    raw: list[dict] = []

    # 1) NVD 按 CNA 拉厂商全家桶
    for cna in cfg["nvd"].get("cnas", []):
        raw.extend(fetch_nvd_by_cna(cna, since, now, cfg))

    # 2) OSV 按组件精确匹配。窗口与 NVD 保持一致，否则 7 天的旧数据会混进来
    log("按组件清单查询 OSV ...")
    osv_failed: list[str] = []
    assets_all = cfg["osv"].get("assets", [])
    for asset in assets_all:
        hits = fetch_osv_asset(asset, days, osv_failed)
        if hits:
            log(f"  {asset['name']}@{asset.get('version') or '未指定'} → {len(hits)} 条")
        raw.extend(hits)

    # 3) Packagist PHP 新增
    raw.extend(fetch_packagist_update(int(since.timestamp()), cfg))

    # 4) GitHub Advisory
    ecos = sorted({a.get("eco", "Maven") for a in cfg["osv"].get("assets", [])})
    raw.extend(fetch_github_advisories(ecos, since, cfg))

    total_scanned = len(raw)
    log(f"原始采集 {total_scanned} 条，开始归一化打分 ...")

    # 5) 富化：KEV + EPSS
    kev = fetch_cisa_kev(cfg)
    cves = sorted({i["cve"].upper() for i in raw if i.get("cve")})
    epss = fetch_epss(cves, cfg)

    items = normalize_and_score(
        raw, kev, epss, cfg,
        cfg.get("keyword_watch", []), cfg.get("keyword_exclude", []),
    )
    items = [i for i in items if not is_seen(conn, i["key"])]

    # 按等级配额截断：P0 全推，P1/P2 限流，避免一次刷几十条把人劝退
    quota = cfg["policy"].get("quota", {})
    by_level: dict[str, list[dict]] = {"P0": [], "P1": [], "P2": []}
    for i in items:
        by_level[i["level"]].append(i)
    items = (
        by_level["P0"][: quota.get("P0", 10)]
        + by_level["P1"][: quota.get("P1", 10)]
        + by_level["P2"][: quota.get("P2", 6)]
    )
    log(f"过滤后待推送 {len(items)} 条 "
        f"(P0 {len(by_level['P0'])} / P1 {len(by_level['P1'])} / P2 {len(by_level['P2'])} 待选)")

    # 统计本轮实际有数据返回的源，报告里如实列出，不虚标
    srcs: list[str] = []
    for i in raw:
        name = i["source"].split("/")[0].split(":")[0]
        if name not in srcs:
            srcs.append(name)
    for extra in ("KEV", "EPSS"):
        if extra not in srcs:
            srcs.append(extra)

    # 源可用性：网络挂掉和"今天真的没漏洞"在消息里必须能区分开。
    # 否则一次代理故障就会伪装成一切太平。
    degraded: list[str] = []
    if not kev:
        degraded.append("CISA KEV 未取到，在野利用标记失效")
    if osv_failed:
        if len(osv_failed) >= len(assets_all):
            degraded.append("OSV 全部失败，组件精确匹配未生效")
        else:
            degraded.append(f"OSV {len(osv_failed)}/{len(assets_all)} 个组件失败")

    stats = {
        "scanned": total_scanned,
        "since": since.astimezone(),
        "until": now.astimezone(),
        "sources": srcs,
        "degraded": degraded,
    }

    if not items and not degraded:
        log("无新增高危漏洞，静默退出")
        db_set(conn, "last_run", now.isoformat())
        return 0

    text = render_markdown(items, stats) if items else render_degraded(stats)

    # 网页数据：把命中条目 + 统计导出为 JSON，供 web/ 前端读取展示。
    # 纯只读旁路，不影响推送与 state.db 水位。dry-run 也照写，便于本机预览。
    write_web_data(items, stats, cfg)

    if args.dry_run:
        print("\n" + "=" * 60)
        print(text)
        print("=" * 60)
        log(f"dry-run 模式，未推送。消息体积 {len(text.encode('utf-8'))} 字节")
        return 0

    channel = (
        args.via
        or os.environ.get("WECOM_CHANNEL", "").strip()
        or cfg["wecom"].get("channel", "cli")
    )
    success = False
    if channel in ("cli", "both"):
        success = push_wecom_cli(text, cfg) or success
    if channel in ("webhook", "both"):
        success = push_wecom(text, cfg) or success
    if channel in ("app", "both"):
        success = push_wecom_app(text, cfg) or success

    if args.no_commit:
        # 验收预览：消息照发，但不留痕，保证正式定时任务仍会完整推送一次
        log("no-commit 模式：已推送但未写入水位，下次运行会重发")
        return 0 if success else 1

    for it in items:
        mark_seen(conn, it["key"], pushed=success)
    if success:
        db_set(conn, "last_run", now.isoformat())
    else:
        # 推送失败不推进水位，下次重试，绝不静默丢消息
        log("! 推送未完全成功，水位不推进，下次运行会重试")
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        log(f"严重错误：{exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
