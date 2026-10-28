#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
定制化订阅 —— 把"我在用 X"变成"X 的漏洞会被抓到"。

为什么单独一个命令：
  主配置 vuln-watch.yaml 的价值一半在注释（每条订阅都写了为什么关注它），
  程序回写 yaml 会把注释和排版全冲掉。所以自定义订阅存在独立的
  subscriptions.yaml 里，collect.py 启动时合并进去，主配置永远人写人读。

三种订阅方式，按你手上的信息选：
  1. 报个常见名字        → 查内置目录，自动判断是包坐标还是关键词
       python scripts/subscribe.py add vue
  2. 报精确包坐标 + 版本  → 走 OSV 精确匹配，命中即"你真的在用受影响版本"
       python scripts/subscribe.py add "org.springframework:spring-core" --eco Maven --version 5.3.31
  3. 报个产品名（无包坐标）→ 走 NVD 关键词，适合 nginx / postgresql 这类
       python scripts/subscribe.py add nginx --keyword

其他：
  python scripts/subscribe.py list
  python scripts/subscribe.py test vue --days 30     # 先看 30 天能命中多少，再决定加不加
  python scripts/subscribe.py remove vue
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import collect  # noqa: E402

SUB_PATH = ROOT / "subscriptions.yaml"

HEADER = """\
# ============================================================
# 自定义订阅（由 scripts/subscribe.py 维护，也可以手改）
#
# collect.py 每次启动会把这个文件合并进 vuln-watch.yaml：
#   assets   → 追加到 osv.assets（包坐标精确匹配）
#   keywords → 追加到 nvd.keywords（NVD 关键词通道）
#
# 加完记得回填一次，页面才会有历史：
#   python collect.py --since 2026-01-01
# ============================================================
"""

# 内置目录：常见名字 -> 订阅方式。
# asset 走 OSV 精确匹配（最好带版本）；keyword 走 NVD 关键词（没有包坐标的产品）。
CATALOG: dict[str, dict] = {
    # ---- 服务器 / 中间件（没有包坐标，只能关键词）----
    "nginx": {"kind": "keyword", "keyword": "nginx"},
    "openresty": {"kind": "keyword", "keyword": "openresty"},
    "postgresql": {"kind": "keyword", "keyword": "postgresql"},
    "postgres": {"kind": "keyword", "keyword": "postgresql"},
    "mysql": {"kind": "keyword", "keyword": "mysql"},
    "mariadb": {"kind": "keyword", "keyword": "mariadb"},
    "redis": {"kind": "keyword", "keyword": "redis"},
    "mongodb": {"kind": "keyword", "keyword": "mongodb"},
    "elasticsearch": {"kind": "keyword", "keyword": "elasticsearch"},
    "rabbitmq": {"kind": "keyword", "keyword": "rabbitmq"},
    "kafka": {"kind": "keyword", "keyword": "kafka"},
    "zookeeper": {"kind": "keyword", "keyword": "zookeeper"},
    "docker": {"kind": "keyword", "keyword": "docker"},
    "kubernetes": {"kind": "keyword", "keyword": "kubernetes"},
    "k8s": {"kind": "keyword", "keyword": "kubernetes"},
    "jenkins": {"kind": "keyword", "keyword": "jenkins"},
    "gitlab": {"kind": "keyword", "keyword": "gitlab"},
    "zabbix": {"kind": "keyword", "keyword": "zabbix"},
    "openssl": {"kind": "keyword", "keyword": "openssl"},
    "openssh": {"kind": "keyword", "keyword": "openssh"},
    "weblogic": {"kind": "keyword", "keyword": "weblogic"},
    "tomcat": {"kind": "keyword", "keyword": "tomcat"},
    "jetty": {"kind": "keyword", "keyword": "jetty"},
    "httpd": {"kind": "keyword", "keyword": "apache http server"},
    "php": {"kind": "keyword", "keyword": "php"},
    "python": {"kind": "keyword", "keyword": "python"},
    "java": {"kind": "keyword", "keyword": "java"},

    # ---- Java 生态（包坐标）----
    "spring": {"kind": "asset", "eco": "Maven", "name": "org.springframework:spring-core", "match": ["spring"]},
    "spring-core": {"kind": "asset", "eco": "Maven", "name": "org.springframework:spring-core", "match": ["spring"]},
    "spring-boot": {"kind": "asset", "eco": "Maven", "name": "org.springframework.boot:spring-boot", "match": ["spring-boot"]},
    "spring-security": {"kind": "asset", "eco": "Maven", "name": "org.springframework.security:spring-security-web", "match": ["spring-security"]},
    "log4j": {"kind": "asset", "eco": "Maven", "name": "org.apache.logging.log4j:log4j-core", "match": ["log4j"]},
    "logback": {"kind": "asset", "eco": "Maven", "name": "ch.qos.logback:logback-classic", "match": ["logback"]},
    "fastjson": {"kind": "asset", "eco": "Maven", "name": "com.alibaba:fastjson", "match": ["fastjson"]},
    "jackson": {"kind": "asset", "eco": "Maven", "name": "com.fasterxml.jackson.core:jackson-databind", "match": ["jackson"]},
    "shiro": {"kind": "asset", "eco": "Maven", "name": "org.apache.shiro:shiro-core", "match": ["shiro"]},
    "struts": {"kind": "asset", "eco": "Maven", "name": "org.apache.struts:struts2-core", "match": ["struts"]},
    "struts2": {"kind": "asset", "eco": "Maven", "name": "org.apache.struts:struts2-core", "match": ["struts"]},
    "dubbo": {"kind": "asset", "eco": "Maven", "name": "org.apache.dubbo:dubbo", "match": ["dubbo"]},
    "mybatis": {"kind": "asset", "eco": "Maven", "name": "org.mybatis:mybatis", "match": ["mybatis"]},
    "hutool": {"kind": "asset", "eco": "Maven", "name": "cn.hutool:hutool-all", "match": ["hutool"]},
    "netty": {"kind": "asset", "eco": "Maven", "name": "io.netty:netty-handler", "match": ["netty"]},
    "guava": {"kind": "asset", "eco": "Maven", "name": "com.google.guava:guava", "match": ["guava"]},
    "mysql-connector": {"kind": "asset", "eco": "Maven", "name": "com.mysql:mysql-connector-j", "match": ["mysql-connector"]},

    # ---- 前端 / Node ----
    "vue": {"kind": "asset", "eco": "npm", "name": "vue", "match": ["vue"]},
    "vue-router": {"kind": "asset", "eco": "npm", "name": "vue-router", "match": ["vue-router"]},
    "react": {"kind": "asset", "eco": "npm", "name": "react", "match": ["react"]},
    "next": {"kind": "asset", "eco": "npm", "name": "next", "match": ["next.js"]},
    "nextjs": {"kind": "asset", "eco": "npm", "name": "next", "match": ["next.js"]},
    "axios": {"kind": "asset", "eco": "npm", "name": "axios", "match": ["axios"]},
    "express": {"kind": "asset", "eco": "npm", "name": "express", "match": ["express"]},
    "lodash": {"kind": "asset", "eco": "npm", "name": "lodash", "match": ["lodash"]},
    "jquery": {"kind": "asset", "eco": "npm", "name": "jquery", "match": ["jquery"]},
    "element-plus": {"kind": "asset", "eco": "npm", "name": "element-plus", "match": ["element-plus"]},
    "element-ui": {"kind": "asset", "eco": "npm", "name": "element-ui", "match": ["element-ui"]},

    # ---- Python ----
    "django": {"kind": "asset", "eco": "PyPI", "name": "django", "match": ["django"]},
    "flask": {"kind": "asset", "eco": "PyPI", "name": "flask", "match": ["flask"]},
    "fastapi": {"kind": "asset", "eco": "PyPI", "name": "fastapi", "match": ["fastapi"]},
    "requests": {"kind": "asset", "eco": "PyPI", "name": "requests", "match": ["requests"]},
    "urllib3": {"kind": "asset", "eco": "PyPI", "name": "urllib3", "match": ["urllib3"]},
    "cryptography": {"kind": "asset", "eco": "PyPI", "name": "cryptography", "match": ["cryptography"]},
    "sqlalchemy": {"kind": "asset", "eco": "PyPI", "name": "sqlalchemy", "match": ["sqlalchemy"]},
    "psycopg2": {"kind": "asset", "eco": "PyPI", "name": "psycopg2", "match": ["psycopg2"]},
    "celery": {"kind": "asset", "eco": "PyPI", "name": "celery", "match": ["celery"]},
    "aiohttp": {"kind": "asset", "eco": "PyPI", "name": "aiohttp", "match": ["aiohttp"]},
    "tornado": {"kind": "asset", "eco": "PyPI", "name": "tornado", "match": ["tornado"]},
    "pillow": {"kind": "asset", "eco": "PyPI", "name": "pillow", "match": ["pillow"]},
    "jinja2": {"kind": "asset", "eco": "PyPI", "name": "jinja2", "match": ["jinja2"]},
    "numpy": {"kind": "asset", "eco": "PyPI", "name": "numpy", "match": ["numpy"]},

    # ---- PHP ----
    "laravel": {"kind": "asset", "eco": "Packagist", "name": "laravel/framework", "match": ["laravel"]},
    "thinkphp": {"kind": "asset", "eco": "Packagist", "name": "topthink/framework", "match": ["thinkphp"]},
    "symfony": {"kind": "asset", "eco": "Packagist", "name": "symfony/http-kernel", "match": ["symfony"]},
    "guzzle": {"kind": "asset", "eco": "Packagist", "name": "guzzlehttp/guzzle", "match": ["guzzle"]},
    "phpmailer": {"kind": "asset", "eco": "Packagist", "name": "phpmailer/phpmailer", "match": ["phpmailer"]},
}


def load_subs() -> dict:
    if not SUB_PATH.exists():
        return {"assets": [], "keywords": []}
    data = yaml.safe_load(SUB_PATH.read_text(encoding="utf-8")) or {}
    data.setdefault("assets", [])
    data.setdefault("keywords", [])
    return data


def dump_subs(data: dict) -> str:
    """手写序列化。yaml.dump 会把 flow style 拍成多行，读起来像天书。"""
    lines = [HEADER, "assets:"]
    for a in data["assets"]:
        match = ", ".join(a.get("match") or [])
        lines.append(
            f'  - {{ eco: {a["eco"]}, name: "{a["name"]}", '
            f'version: "{a.get("version", "")}", match: [{match}] }}'
        )
    if not data["assets"]:
        lines.append("  []")
    lines += ["", "keywords:"]
    for k in data["keywords"]:
        lines.append(f"  - {k}")
    if not data["keywords"]:
        lines.append("  []")
    return "\n".join(lines) + "\n"


def resolve(name: str, eco: str = "", version: str = "", as_keyword: bool = False) -> dict:
    """把用户输入解析成一条订阅。"""
    raw = name.strip()
    key = raw.lower()

    if as_keyword:
        return {"kind": "keyword", "keyword": key}

    if key in CATALOG:
        item = dict(CATALOG[key])
        if version and item["kind"] == "asset":
            item["version"] = version
        return item

    # 显式给了生态，或长得像 Maven 坐标（group:artifact）
    if eco or (":" in raw and "/" not in raw):
        eco_name = eco or "Maven"
        if eco_name not in collect.GH_ECO_MAP:
            raise SystemExit(f"不认识的生态：{eco_name}（可选 {'/'.join(collect.GH_ECO_MAP)}）")
        return {"kind": "asset", "eco": eco_name, "name": raw,
                "version": version, "match": [raw.split(":")[-1].lower()]}

    # 都不像就退化成关键词：至少能从 NVD 里把提到它的漏洞捞出来
    print(f"  · “{raw}”不在内置目录里，按 NVD 关键词订阅（想精确匹配请加 --eco）")
    return {"kind": "keyword", "keyword": key}


def cmd_add(args: argparse.Namespace) -> int:
    item = resolve(args.name, args.eco, args.version, args.keyword)
    data = load_subs()

    if item["kind"] == "keyword":
        kw = item["keyword"]
        cfg = collect.load_subscriptions(yaml.safe_load(
            (ROOT / "vuln-watch.yaml").read_text(encoding="utf-8")))
        if kw in (cfg.get("nvd", {}).get("keywords") or []):
            print(f"已订阅（关键词）：{kw}，无需重复添加")
            return 0
        data["keywords"].append(kw)
        print(f"✅ 已添加关键词订阅：{kw}")
    else:
        name = item["name"]
        if any(a.get("name") == name for a in data["assets"]):
            print(f"已订阅（组件）：{name}，无需重复添加")
            return 0
        # 主配置里可能已经订了同一个包（内置清单比自定义清单更常见），也要拦住
        base_names = {
            a.get("name") for a in
            (yaml.safe_load((ROOT / "vuln-watch.yaml").read_text(encoding="utf-8"))
             .get("osv", {}).get("assets") or [])
        }
        if name in base_names:
            print(f"内置订阅里已有该组件：{name}，无需重复添加")
            return 0
        data["assets"].append(item)
        ver = item.get("version") or "未指定（拉全部版本，噪声略高）"
        print(f"✅ 已添加组件订阅：{item['eco']} / {name} @ {ver}")

    SUB_PATH.write_text(dump_subs(data), encoding="utf-8")
    print(f"   写入 {SUB_PATH.relative_to(ROOT)}")
    print("   下一步：python collect.py --since 2026-01-01    # 回填补历史")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    key = args.name.strip().lower()
    data = load_subs()
    before_a, before_k = len(data["assets"]), len(data["keywords"])

    hit = resolve(key, as_keyword=(key in CATALOG and CATALOG[key]["kind"] == "keyword"))
    if hit["kind"] == "keyword":
        data["keywords"] = [k for k in data["keywords"] if k.lower() != hit["keyword"]]
    else:
        data["assets"] = [a for a in data["assets"] if a.get("name") != hit["name"]]

    if len(data["assets"]) == before_a and len(data["keywords"]) == before_k:
        print(f"没找到订阅项：{args.name}（只在 subscriptions.yaml 里找，主配置请手改）")
        return 1
    SUB_PATH.write_text(dump_subs(data), encoding="utf-8")
    print(f"✅ 已移除：{args.name}")
    return 0


def cmd_list(_: argparse.Namespace) -> int:
    cfg = collect.load_subscriptions(
        yaml.safe_load((ROOT / "vuln-watch.yaml").read_text(encoding="utf-8"))
    )
    data = load_subs()
    base_assets = len(cfg["osv"]["assets"]) - len(data["assets"])
    base_kw = len(cfg["nvd"].get("keywords") or []) - len(data["keywords"])

    print(f"内置订阅：{base_assets} 个组件、{base_kw} 个关键词（vuln-watch.yaml）")
    print(f"自定义订阅：{len(data['assets'])} 个组件、{len(data['keywords'])} 个关键词"
          f"（subscriptions.yaml）")
    if data["assets"]:
        print("\n自定义组件：")
        for a in data["assets"]:
            print(f"  · {a['eco']:10} {a['name']}  @ {a.get('version') or '未指定'}")
    if data["keywords"]:
        print("\n自定义关键词：")
        for k in data["keywords"]:
            print(f"  · {k}")
    print("\nNVD 关键词通道（两个文件合并后）：")
    print("  " + "、".join(cfg.get("nvd", {}).get("keywords") or []))
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    """先试跑再订阅：多少条、都是什么级别的，看完再决定要不要加。"""
    cfg = collect.load_subscriptions(
        yaml.safe_load((ROOT / "vuln-watch.yaml").read_text(encoding="utf-8"))
    )
    item = resolve(args.name, args.eco, args.version, args.keyword)
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=args.days)
    print(f"试查窗口：{since:%Y-%m-%d} → {now:%Y-%m-%d}\n")

    if item["kind"] == "keyword":
        print(f"通道：NVD 关键词 “{item['keyword']}”")
        hits = collect.fetch_nvd_keyword(item["keyword"], since, now, cfg)
    else:
        print(f"通道：OSV {item['eco']} / {item['name']} @ {item.get('version') or '未指定'}")
        hits = collect.fetch_osv_asset(item, args.days)

    if not hits:
        print("\n没查到条目。可能原因：窗口内确实没有，或版本太新不受影响。")
        return 0

    print(f"\n命中 {len(hits)} 条，按 CVSS 取前 {min(10, len(hits))} 条：\n")
    for h in sorted(hits, key=lambda x: x.get("cvss", 0), reverse=True)[:10]:
        print(f"  {h.get('cvss', 0):>4.1f}  {h.get('cve') or h.get('id'):18} "
              f"{h.get('published', '')}  {(h.get('title') or '')[:60]}")
    print(f"\n确认要订阅就执行：python scripts/subscribe.py add {args.name}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="定制化订阅漏洞监控对象")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="添加订阅")
    a.add_argument("name", help="软件名（vue / nginx）或包坐标（group:artifact / pkg）")
    a.add_argument("--eco", default="", help="生态：Maven / PyPI / npm / Packagist / Go / NuGet")
    a.add_argument("--version", default="", help="你的实际版本，给了才能精确匹配受影响范围")
    a.add_argument("--keyword", action="store_true", help="强制按 NVD 关键词订阅")
    a.set_defaults(func=cmd_add)

    r = sub.add_parser("remove", help="移除订阅")
    r.add_argument("name")
    r.set_defaults(func=cmd_remove)

    ls = sub.add_parser("list", help="查看当前订阅")
    ls.set_defaults(func=cmd_list)

    t = sub.add_parser("test", help="试查命中情况（不写入）")
    t.add_argument("name")
    t.add_argument("--eco", default="")
    t.add_argument("--version", default="")
    t.add_argument("--keyword", action="store_true")
    t.add_argument("--days", type=int, default=30)
    t.set_defaults(func=cmd_test)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
