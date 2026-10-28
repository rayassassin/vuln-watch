#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 web/ 下的全景看板发布到 GitHub Pages。

为什么不用 git push（血泪史，别再改回去）：
  data.json 现在 4 MB 上下。"clone → commit → push" 要走 pack 协议加一条长连接，
  本机代理链路报 Error in the HTTP2 framing layer / CONNECT tunnel failed 502，
  云服务器到 github.com 报 GnuTLS recv error (-110)。两条链路都不稳，
  重试只是赌运气，还要在服务器上留一个 .git 目录。

  改成 Git Data API 之后是四五个独立的 HTTPS POST：
      blobs（每个文件一条） → trees → commits → 改 ref
  没有 pack、没有长连接、不需要本地仓库，每个请求都是几十 KB 的 JSON，
  失败是「这一个请求失败」，重发即可，便宜且可诊断。

为什么和代码同一个仓库、但用独立分支：
  看板 = 本仓库的 gh-pages 分支，Pages 源就指向这个分支的根目录。
  该分支每次只有一个无父 commit（孤立快照），main 的代码历史完全不受影响，
  也不需要第二个仓库、第二个仓库权限。这是「一个仓库两用」最干净的做法。

体积控制 —— 为什么 commit 故意没有父节点：
  每次新建 orphan commit 再 force 覆盖 gh-pages，旧对象不进任何分支，
  GitHub 侧 GC 之后仓库体积稳定在「一份快照」的量级。
  代价是没有历史版本可回溯 —— 这个页面本来也不需要。
  反过来说：绝不能把这几个文件提交到 main，4 MB × 一天两次会把代码历史撑爆。

只依赖标准库（urllib / base64 / hashlib），服务器上的 python3 不必装 requests。

为什么每轮先问一次远端：
  判断「要不要发」不看本地状态文件，而是直接比 GitHub Contents API 返回的
  文件 blob sha（就是 git blob sha1，口径完全一致）。好处：零下载（不拉 4 MB）、
  不会因为「本地记着发过了」而漏发、远端被外部改过也能立刻发现。
  本地曾经用 .pages_state 指纹，但那个文件不进版本库，每部署一次就丢，
  还会在远端被改动时误报「已是最新」。cron 一天两轮，多发一次总比漏发强，
  所以校验失败时一律当作需要发布。

token：fine-grained PAT，只授权 rayassassin/vuln-watch（仓库本身），
  权限 Contents: Read and write（想让脚本自动启用 Pages 再加 Pages: Read and write）。
  注意：Pages 必须从公开仓库发布才能免费用，所以这个仓库是 public。
  取值顺序：GH_PAGES_TOKEN → GITHUB_TOKEN → 本机 gh auth token
  服务器上放 /opt/vuln-watch/.pages_token（chmod 600），cron 里 export 进来。

用法：
  python3 scripts/publish_pages.py                  # 发布
  python3 scripts/publish_pages.py --dry-run        # 只校验文件，不联网
  python3 scripts/publish_pages.py --force          # 内容没变也重发
  python3 scripts/publish_pages.py --ensure-pages   # 顺带确认 Pages 已启用
  python3 scripts/publish_pages.py --wait 300       # 等 Pages 构建完成
  python3 scripts/publish_pages.py --method git     # 应急：退回 git push
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

API = "https://api.github.com"
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPO = "rayassassin/vuln-watch"
DEFAULT_BRANCH = "gh-pages"

# 顶层 .nojekyll：GitHub 默认走 Jekyll，下划线开头的文件会被吞掉
NOJEKYLL = (".nojekyll", b"")


# ---------------------------------------------------------------- HTTP 底座


class ApiError(RuntimeError):
    """带状态码的 API 错误，方便上层区分 404（不存在）与 401（token 不对）。"""

    def __init__(self, method: str, path: str, code: int, detail: str):
        super().__init__(f"{method} {path} → HTTP {code} {detail}".strip())
        self.code = code
        self.path = path


def api(method: str, path: str, token: str, body: dict | None = None,
        timeout: int = 120, retries: int = 3) -> dict:
    """调 GitHub REST。4xx 直接抛（不重试，重试也没用），5xx/网络错误退避重试。"""
    url = path if path.startswith("http") else API + path
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "vuln-watch-publish",
    }
    # 空 token = 匿名。公开仓库的只读接口不需要鉴权，
    # scripts/healthcheck.py 在没有凭据的机器上也就能核对远端快照。
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload:
        headers["Content-Type"] = "application/json"

    last: Exception | None = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
            return json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:300]
            except Exception:  # noqa: BLE001
                pass
            last = ApiError(method, path, exc.code, detail)
            # 401/403/404/422 是确定性失败；429 与 5xx 才值得再来一次
            if exc.code not in (429,) and exc.code < 500:
                raise last
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = RuntimeError(f"{method} {path} 网络错误：{exc}")
        if attempt < retries:
            time.sleep(2 * attempt)
    assert last is not None
    raise last


def resolve_token() -> str:
    for key in ("GH_PAGES_TOKEN", "GITHUB_TOKEN"):
        val = os.environ.get(key, "").strip()
        if val:
            return val
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except Exception:  # noqa: BLE001
        raise SystemExit(
            "没有可用的 GitHub token。二选一：\n"
            "  · 本机：gh auth login\n"
            "  · 服务器：fine-grained PAT 写进 /opt/vuln-watch/.pages_token（chmod 600），\n"
            "    cron 里 export GH_PAGES_TOKEN=\"$(cat /opt/vuln-watch/.pages_token)\""
        )


# ---------------------------------------------------------------- Git Data API


def make_blob(repo: str, content: bytes, token: str) -> str:
    """上传一个 blob，返回 sha。4 MB 的文件 base64 之后约 5.4 MB，一次 POST 足够。"""
    body = {"content": base64.b64encode(content).decode("ascii"), "encoding": "base64"}
    return api("POST", f"/repos/{repo}/git/blobs", token, body, timeout=300)["sha"]


def make_tree(repo: str, entries: list[dict], token: str) -> str:
    """不带 base_tree → 生成一棵只含这几个文件的树，天然就是「完整快照」。"""
    return api("POST", f"/repos/{repo}/git/trees", token, {"tree": entries})["sha"]


def make_commit(repo: str, tree_sha: str, message: str, token: str) -> str:
    """parents 为空 → 孤立 commit，旧对象不挂在分支上，仓库体积不膨胀。"""
    body = {"message": message, "tree": tree_sha, "parents": []}
    return api("POST", f"/repos/{repo}/git/commits", token, body)["sha"]


def set_ref(repo: str, branch: str, commit_sha: str, token: str) -> str:
    """有分支就强更，没有就新建。返回一句可读的结果描述。"""
    ref_path = f"/repos/{repo}/git/refs/heads/{branch}"
    try:
        api("GET", ref_path, token)
        api("PATCH", ref_path, token, {"sha": commit_sha, "force": True})
        return f"强制覆盖 {branch}"
    except ApiError as exc:
        if exc.code != 404:
            raise
        api("POST", f"/repos/{repo}/git/refs", token,
            {"ref": f"refs/heads/{branch}", "sha": commit_sha})
        return f"新建 {branch}"


def ensure_pages(repo: str, branch: str, token: str) -> str:
    """Pages 没开就开（legacy 构建，直接从分支取静态文件）。失败只告警不中断。"""
    try:
        info = api("GET", f"/repos/{repo}/pages", token)
        return f"Pages 已启用（{info.get('build_type') or 'legacy'} / {info.get('status') or '-'}）"
    except ApiError as exc:
        if exc.code != 404:
            return f"[warn] 查询 Pages 状态失败：{exc}"
    try:
        api("POST", f"/repos/{repo}/pages", token,
            {"source": {"branch": branch, "path": "/"}, "build_type": "legacy"})
        return "已启用 Pages（legacy，源自分支根目录）"
    except ApiError as exc:
        # fine-grained PAT 没给 Pages 写权限时会是 403，不影响发布本身
        return f"[warn] 启用 Pages 失败（{exc.code}）：到仓库 Settings → Pages 手动选 {branch} 分支"


def wait_build(repo: str, token: str, timeout: int) -> tuple[bool, str]:
    """
    等 Pages 构建完。返回 (是否正常, 描述)。
    只有「构建报错」算失败；超时只告警不算失败 —— 构建慢不该触发告警，
    GitHub 那边排队是常事，等下一轮再确认就行。
    """
    deadline = time.time() + timeout
    last = "unknown"
    while time.time() < deadline:
        try:
            b = api("GET", f"/repos/{repo}/pages/builds/latest", token)
            last = b.get("status") or "unknown"
            if last == "built":
                return True, f"构建完成（{b.get('duration')} ms）"
            if last == "errored":
                return False, f"Pages 构建报错：{(b.get('error') or {}).get('message') or '-'}"
        except ApiError as exc:
            return True, f"[warn] 查询构建状态失败：{exc}"
        time.sleep(10)
    return True, f"[warn] 等待 {timeout}s 仍未完成，当前状态 {last}"


# ---------------------------------------------------------------- 兜底：git push


def sh(cmd: list[str], cwd: Path | None = None, quiet: bool = False) -> str:
    # 本机 HTTP(S)_PROXY 会让 git 走 CONNECT 隧道，对 github.com 常返 502；直连即可
    env = dict(os.environ)
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                "ALL_PROXY", "all_proxy"):
        env.pop(key, None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    r = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env,
                       capture_output=True, text=True)
    if r.returncode != 0:
        out = (r.stdout or "") + (r.stderr or "")
        raise RuntimeError(f"{' '.join(cmd[:3])} 失败：{out.strip()[:400]}")
    if not quiet:
        for line in (r.stdout or "").strip().splitlines():
            print(f"   {line}")
    return r.stdout or ""


def git_publish(files: dict[str, bytes], repo: str, branch: str, token: str,
                message: str) -> None:
    with tempfile.TemporaryDirectory(prefix="vuln-pages-") as tmp:
        work = Path(tmp)
        sh(["git", "init", "-q", "-b", branch], cwd=work)
        for name, content in files.items():
            (work / name).write_bytes(content)
        sh(["git", "add", "-A"], cwd=work)
        sh(["git", "-c", "user.name=vuln-watch", "-c", "user.email=vuln-watch@local",
            "commit", "-q", "-m", message], cwd=work, quiet=True)
        url = f"https://x-access-token:{token}@github.com/{repo}.git"
        last: Exception | None = None
        for attempt in range(1, 4):
            try:
                sh(["git", "-c", "http.version=HTTP/1.1", "push", "-q", "--force",
                    url, f"HEAD:{branch}"], cwd=work)
                return
            except RuntimeError as exc:
                last = exc
                print(f"   推送失败（{attempt}/3）：{str(exc)[:120]}")
                time.sleep(3 * attempt)
        if last:
            raise last


# ---------------------------------------------------------------- 主流程


def collect_files(src: Path) -> dict[str, bytes]:
    """要发布的文件集合。页面是单文件应用，data.json 用相对路径取。"""
    index, data = src / "index.html", src / "data.json"
    for f in (index, data):
        if not f.exists():
            raise SystemExit(f"缺少 {f}，先跑一次 collect.py 生成数据")
    files = {
        "index.html": index.read_bytes(),
        "data.json": data.read_bytes(),
        NOJEKYLL[0]: NOJEKYLL[1],
    }
    return files


def fingerprint(files: dict[str, bytes]) -> str:
    """内容指纹，仅用于日志与 --dry-run 展示。"""
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode())
        h.update(b"\0")
        h.update(files[name])
    return h.hexdigest()


def local_blob_sha(content: bytes) -> str:
    """
    算 git blob sha1，口径与 GitHub Contents API 返回的 sha 完全一致：
        sha1("blob <字节数>\\0" + content)
    这样只看元数据就能判断「远端那份是不是和我本地这份一样」，不用下载 4 MB。
    """
    h = hashlib.sha1()
    h.update(b"blob %d\0" % len(content))
    h.update(content)
    return h.hexdigest()


def remote_is_current(files: dict[str, bytes], repo: str, branch: str,
                      token: str) -> tuple[bool, str]:
    """
    远端 gh-pages 上每个文件的 blob sha 都和本地一致 → 不必重发。

    比本地指纹文件可靠：.pages_state 不进版本库，部署一次就丢；
    而 Pages 被外部改过、token 换过仓库时，本地指纹还会骗你说「已是最新」。
    查不动（网络/权限问题）时一律返回 False，宁可多发一次也不要漏发。
    """
    diffs: list[str] = []
    for name, content in files.items():
        try:
            meta = api("GET", f"/repos/{repo}/contents/{name}?ref={branch}", token) or {}
        except ApiError as exc:
            if exc.code == 404:
                return False, f"远端尚无 {name}"
            return False, f"远端校验失败（{exc.code}）"
        except Exception as exc:  # noqa: BLE001
            return False, f"远端校验失败（{str(exc)[:60]}）"
        rsha = meta.get("sha") or ""
        lsha = local_blob_sha(content)
        if not rsha:
            diffs.append(f"{name} 缺失")
        elif rsha != lsha:
            diffs.append(f"{name} 已变")
    return (not diffs), "、".join(diffs) if diffs else "三份文件均一致"


def main() -> int:
    ap = argparse.ArgumentParser(description="发布全景看板到 GitHub Pages")
    ap.add_argument("--source", default=str(ROOT / "web"), help="web 目录")
    ap.add_argument("--repo", default=DEFAULT_REPO, help="owner/name")
    ap.add_argument("--branch", default=DEFAULT_BRANCH)
    ap.add_argument("--dry-run", action="store_true", help="只校验文件，不联网")
    ap.add_argument("--force", action="store_true", help="内容没变化也重新发布")
    ap.add_argument("--ensure-pages", action="store_true", help="顺带确认 Pages 已启用")
    ap.add_argument("--wait", type=int, default=0, metavar="SEC",
                    help="等待 Pages 构建完成的秒数（0 = 不等）")
    ap.add_argument("--method", choices=("api", "git"), default="api",
                    help="api = Git Data API（默认）；git = 应急退回 git push")
    args = ap.parse_args()

    src = Path(args.source)
    files = collect_files(src)
    size_mb = len(files["data.json"]) / 1024 / 1024
    print(f"发布源：{src} 共 {len(files)} 个文件，data.json {size_mb:.2f} MB")

    if args.dry_run:
        for name, content in sorted(files.items()):
            print(f"   {name:<12} {len(content):>9,} B")
        print(f"   指纹 {fingerprint(files)[:16]}")
        print("[dry-run] 未联网")
        return 0

    token = resolve_token()

    # 先问远端：真的需要发吗？cron 一天两次，绝大部分轮次其实就是这几份文件
    if not args.force:
        same, why = remote_is_current(files, args.repo, args.branch, token)
        if same:
            print(f"远端已是最新（{why}），跳过发布（--force 可强制重发）")
            if args.wait > 0 or args.ensure_pages:
                if args.ensure_pages:
                    print(f"   pages → {ensure_pages(args.repo, args.branch, token)}")
            return 0
        print(f"远端需要更新：{why}")

    message = (f"publish {datetime.now().strftime('%Y-%m-%d %H:%M')} "
               f"({len(files['data.json']) // 1024} KB)")
    build_ok = True

    if args.method == "git":
        print(f"git push 到 {args.repo} / {args.branch} …")
        git_publish(files, args.repo, args.branch, token, message)
    else:
        print(f"Git Data API 发布到 {args.repo} / {args.branch} …")
        try:
            api("GET", f"/repos/{args.repo}", token)
        except ApiError as exc:
            if exc.code == 404:
                raise SystemExit(
                    f"仓库 {args.repo} 不存在或 token 无权访问。\n"
                    "  先手工建一个公开仓库（Pages 免费账号需要 public），再重跑。"
                )
            if exc.code == 401:
                raise SystemExit("token 无效或已过期，检查 .pages_token")
            raise

        # 大文件先传，失败就早点失败，省得后面白建 tree
        entries = []
        for name in ("index.html", "data.json", NOJEKYLL[0]):
            sha = make_blob(args.repo, files[name], token)
            print(f"   blob {name:<12} {len(files[name]):>9,} B  → {sha[:10]}")
            entries.append({"path": name, "mode": "100644",
                            "type": "blob", "sha": sha})

        tree_sha = make_tree(args.repo, entries, token)
        print(f"   tree → {tree_sha[:10]}")
        commit_sha = make_commit(args.repo, tree_sha, message, token)
        print(f"   commit → {commit_sha[:10]}（无父节点）")
        print(f"   ref → {set_ref(args.repo, args.branch, commit_sha, token)}")

        if args.ensure_pages:
            print(f"   pages → {ensure_pages(args.repo, args.branch, token)}")
        if args.wait > 0:
            build_ok, desc = wait_build(args.repo, token, args.wait)
            print(f"   build → {desc}")

    owner, name = args.repo.split("/")
    print(f"\n✅ 已发布：https://{owner}.github.io/{name}/")
    print("   Pages 首次构建要 1-2 分钟，之后每次发布约 30 秒生效")
    # 构建报错时给非 0：cron 靠退出码判断「这套环境到底更新了没有」
    return 0 if build_ok else 2


if __name__ == "__main__":
    sys.exit(main())
