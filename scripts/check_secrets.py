#!/usr/bin/env python3
"""提交前敏感信息扫描。

设计原则：只拦「确定是凭证」和「确定是内网信息」的东西，不做模糊猜测，
否则误报会让人直接 `--no-verify`，那这层防线就废了。

用法：
    python scripts/check_secrets.py            # 扫全部已跟踪文件
    python scripts/check_secrets.py --staged   # 只扫暂存区（pre-commit 用）
退出码 0 = 通过，1 = 发现疑似敏感信息。
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ---- 规则：(名称, 正则, 说明) ----
RULES: list[tuple[str, str, str]] = [
    # 平台 token
    ("GitHub Token", r"\bgh[pousr]_[A-Za-z0-9]{36,}", "GitHub 个人访问令牌"),
    ("GitHub fine-grained", r"\bgithub_pat_[A-Za-z0-9_]{50,}", "GitHub 细粒度令牌"),
    ("AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b", "AWS 访问密钥"),
    ("Slack Token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}", "Slack 令牌"),
    ("OpenAI/Anthropic Key", r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}", "大模型 API Key"),
    ("微信/企业微信 Secret", r"\b[A-Za-z0-9_-]{32,}\b(?=.*(?:secret|corpsecret|agentid))", "企微应用 Secret"),
    # 企微群机器人 webhook：key 为 UUID 形态，最容易误提交
    ("企微机器人 Webhook", r"qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[0-9a-f-]{20,}", "群机器人地址即凭证"),
    # 通用键值对（要求值足够长且带引号，避免把 api_key_env 这类变量名当凭证）
    # 注意：不能用 \bpassword\b —— DB_PASSWORD 里下划线是单词字符，前面没有词边界，
    # 这条漏判过真实密码，所以改成允许前后粘连标识符字符。
    (
        "硬编码密钥赋值",
        r"""(?i)[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[A-Za-z0-9_.-]*\s*[:=]\s*["'][^"'\s]{12,}["']""",
        "疑似硬编码密码/密钥",
    ),
    # 请求头里的实际凭证值（排除 $VAR / {var} / <占位符>）
    (
        "请求头凭证",
        r"""(?i)authorization["']?\s*[:=]\s*["']?(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{20,}""",
        "请求头里带了明文凭证",
    ),
    # 私钥块
    ("私钥文件内容", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "私钥不能入库"),
    # 企微会话 ID（业务敏感）
    ("企微会话 ID", r"\bwo[A-Za-z0-9_-]{20,}\b", "企业微信 chat_id"),
    # 内网痕迹
    ("公网 IP", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", "具体 IP 地址"),
    ("本机绝对路径", r"/Users/[A-Za-z0-9._-]+/|/home/[A-Za-z0-9._-]+/|[A-Za-z]:\\\\Users\\\\", "含用户名的本机路径"),
    # 本仓库是公开的：别的项目的服务器目录、本机工具链结构都不该外泄
    ("跨项目服务器路径", r"/opt/(?!vuln-watch)[a-z][a-z0-9-]{2,}/", "其它项目在服务器上的目录"),
    ("本机工具链路径", r"/Users/[A-Za-z0-9._-]+/(?:WorkBuddy|\.workbuddy)|\.workbuddy/(?:secrets|tools)", "本机工具链/密钥目录"),
    # 企微应用 agentid 是具体数字，和变量名要区分开
    ("企微 agentid 值", r"(?i)agentid\s*[:=]\s*['\"]?\d{4,}", "企微应用 agentid"),
]

# 白名单：这些是文档/代码里必须出现的示例值或公开信息
ALLOW_PATTERNS = [
    r"127\.0\.0\.1",
    r"0\.0\.0\.0",
    r"255\.255\.255",
    r"\b\d+\.\d+\.\d+\.\d+/",          # 子网/前缀写法
    r"security@apache\.org",
    r"security@php\.net",
    r"secalert_us@oracle\.com",
    r"api\.first\.org",
    r"services\.nvd\.nist\.gov",
    r"packagist\.org",
    r"api\.osv\.dev",
    r"api\.github\.com",
    r"cisa\.gov",
    r"qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=xxx",  # 文档占位符
    r"api_key_env",
    r"token_env",
    # 文档里用的保留地址（RFC 5737 / RFC 2606），不是真实主机
    r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.",
    r"example\.(?:com|org|net)",
    # 只放行「明确是变量或占位符」的写法。这里曾经写成 \{?\$?\{?\w+\}?\}?，
    # 全部可选等于任何 Bearer xxx 都能过，等于没这条规则。
    r"Bearer (?:\$\{?\w+\}?|\{\w+\}|<\w+>)",
    r"Bearer <[^>]+>",
]

SKIP_SUFFIX = {".db", ".sqlite", ".log", ".png", ".jpg", ".jpeg", ".gif", ".webp",
               ".zip", ".gz", ".pdf", ".ico", ".woff", ".woff2", ".ttf"}
SKIP_FILES = {"state.db", "package-lock.json", "yarn.lock"}
SELF = Path(__file__).resolve()


def sh(*args: str) -> str:
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=True).stdout


def staged_files() -> list[str]:
    out = sh("git", "diff", "--cached", "--name-only", "--diff-filter=ACMR")
    return [f for f in out.split() if f]


def tracked_files() -> list[str]:
    return [f for f in sh("git", "ls-files").split() if f]


def scan(paths: list[str]) -> list[tuple[str, int, str, str, str]]:
    hits = []
    for rel in paths:
        p = ROOT / rel
        if p.resolve() == SELF or p.suffix.lower() in SKIP_SUFFIX or p.name in SKIP_FILES:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for name, pattern, why in RULES:
                for m in re.finditer(pattern, line):
                    snippet = m.group(0)
                    if any(re.search(a, snippet) or re.search(a, line) for a in ALLOW_PATTERNS):
                        continue
                    masked = snippet[:6] + "*" * max(0, len(snippet) - 10) + snippet[-4:] \
                        if len(snippet) > 12 else snippet[:2] + "***"
                    hits.append((rel, lineno, name, masked, why))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="提交前敏感信息扫描")
    ap.add_argument("--staged", action="store_true", help="只扫暂存区（pre-commit 钩子用）")
    args = ap.parse_args()

    files = staged_files() if args.staged else tracked_files()
    if not files:
        print("没有需要扫描的文件")
        return 0

    hits = scan(files)
    if not hits:
        print(f"✅ 敏感信息扫描通过（{len(files)} 个文件）")
        return 0

    print(f"❌ 发现 {len(hits)} 处疑似敏感信息，已阻止提交\n")
    for rel, lineno, name, masked, why in hits:
        print(f"  {rel}:{lineno}  [{name}] {masked}  —— {why}")
    print("\n处理方式：")
    print("  · 真实凭证：立即作废并轮换，然后从代码里删掉，改从环境变量读取")
    print("  · 文档示例：用 xxx / <your-key> 之类占位符，并加进 ALLOW_PATTERNS")
    print("  · 确认误报：把特征加进 scripts/check_secrets.py 的 ALLOW_PATTERNS")
    return 1


if __name__ == "__main__":
    sys.exit(main())
