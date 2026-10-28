#!/bin/sh
# 供服务器 cron 调用。与 run.sh 的区别：负责日志落盘 + 双链路维护 + 失败告警。
# 告警走同一应用通道（尽力而为）；通道本身挂掉时至少留日志。
#
# 安装目录、token 位置都从环境变量取，默认值只是本项目的中性约定，
# 换台机器部署只要设 VW_BASE 即可，不必改脚本。
#
# 看板是「双活」的，同一份 web/ 数据同时供给两条独立链路：
#   ① GitHub Pages —— 发布到本仓库 gh-pages 分支（Git Data API），全球可达，
#      不依赖这台服务器，是域名备案完成之前的对外正式入口。
#   ② 自有服务器   —— nginx 容器只读挂载 web/ 目录，采集写完即刻生效。
# 两条都跑，一条挂了另一条还能看；挂了哪条会单独提示，不会互相掩盖。
# 想让某条彻底停掉：VW_PUBLISH_PAGES=0（停 Pages）或 VW_CHECK_WEB=0（停容器检查）。
set -u

BASE=${VW_BASE:-/opt/vuln-watch}
export VW_BASE="$BASE"
LOGDIR="$BASE/logs"
mkdir -p "$LOGDIR"
LOG="$LOGDIR/cron-$(date +%Y%m%d).log"
TOKEN_FILE=${VW_PAGES_TOKEN_FILE:-$BASE/.pages_token}
WEB_CONTAINER=${VW_WEB_CONTAINER:-vuln-watch-web}
PUBLISH_PAGES=${VW_PUBLISH_PAGES:-1}     # 默认发布，双活；设 0 才停
CHECK_WEB=${VW_CHECK_WEB:-1}             # 默认检查容器
PAGES_WAIT=${VW_PAGES_WAIT:-90}          # 等 Pages 构建的秒数，0 = 不等

WEB_STATE=ok      # ok / fail / skip —— 自有服务器容器
PAGES_STATE=ok    # ok / fail / skip —— GitHub Pages

{
    echo "=== $(date '+%F %T') start ==="
    # 显式限定一天：日报只覆盖最近 24h，不因水位落后而回补历史
    "$BASE/run.sh" --days 1
    rc=$?
    echo "=== $(date '+%F %T') exit $rc ==="

    if [ "$rc" -eq 0 ]; then
        # ---- 链路 ②：自有服务器容器 ----
        # collect.py 写完 data.json 的那一刻，挂载目录的访客就已经拿到新数据，
        # 中间没有发布步骤，所以这里只需要确认容器还活着。容器挂了页面就是白屏。
        if [ "$CHECK_WEB" = "1" ]; then
            if command -v docker >/dev/null 2>&1; then
                st=$(docker inspect -f '{{.State.Health.Status}}' "$WEB_CONTAINER" 2>/dev/null || echo missing)
                echo "=== $(date '+%F %T') web container: $st ==="
                if [ "$st" != "healthy" ]; then
                    WEB_STATE=fail
                    # 容器挂了就地拉一次，多数情况（Docker 重启、OOM）能自己起来。
                    # 拉不起来才是真故障，由下面的告警负责喊人。
                    echo "--- 尝试自动恢复 ---"
                    ( cd "$BASE/deploy" && docker compose up -d 2>&1 | tail -5 ) || true
                    sleep 3
                    st2=$(docker inspect -f '{{.State.Health.Status}}' "$WEB_CONTAINER" 2>/dev/null || echo missing)
                    echo "--- 恢复后状态：$st2 ---"
                    [ "$st2" = "healthy" ] && WEB_STATE=ok
                fi
            else
                echo "[warn] 未找到 docker，跳过自有服务器容器检查"
                WEB_STATE=skip
            fi
        else
            echo "[skip] VW_CHECK_WEB=0，跳过容器检查"
            WEB_STATE=skip
        fi

        # ---- 链路 ①：GitHub Pages ----
        # 备案完成之前这条是唯一公网可达的入口，必须每轮跟着更新。
        if [ "$PUBLISH_PAGES" = "1" ]; then
            if [ -f "$TOKEN_FILE" ]; then
                echo "=== $(date '+%F %T') publish pages ==="
                cd "$BASE" && GH_PAGES_TOKEN="$(cat "$TOKEN_FILE")" \
                    python3 scripts/publish_pages.py --ensure-pages --wait "$PAGES_WAIT"
                prc=$?
                echo "=== $(date '+%F %T') publish exit $prc ==="
                [ "$prc" -eq 0 ] || PAGES_STATE=fail
            else
                echo "[warn] 未配置 $TOKEN_FILE，本轮跳过 Pages 发布"
                PAGES_STATE=skip
            fi
        else
            echo "[skip] VW_PUBLISH_PAGES=0，跳过 Pages 发布"
            PAGES_STATE=skip
        fi
    fi
} >> "$LOG" 2>&1

# 两条链路有任何一条不正常就说一声，别让人以为页面还在。
# 一天只提醒一次（marker），全部恢复后清掉，不会变成刷屏。
ALERT_MARK="$LOGDIR/.web_alert"
if [ "$WEB_STATE" = "ok" ] && [ "$PAGES_STATE" = "ok" ]; then
    rm -f "$ALERT_MARK"
elif [ "$rc" -eq 0 ] && [ ! -f "$ALERT_MARK" ] && { [ "$WEB_STATE" != "ok" ] || [ "$PAGES_STATE" != "ok" ]; }; then
    python3 - "$WEB_STATE" "$PAGES_STATE" "$LOG" "$WEB_CONTAINER" "$TOKEN_FILE" >> "$LOG" 2>&1 <<'PY'
import os, sys
base = os.environ.get("VW_BASE") or "/opt/vuln-watch"
sys.path.insert(0, base)
import yaml, collect

web_state, pages_state, logfile, container, token_file = sys.argv[1:6]
cfg = yaml.safe_load(open(os.path.join(base, "vuln-watch.yaml"), encoding="utf-8"))
web = cfg.get("web") or {}
main_url = (web.get("public_url") or "").strip()
backup_url = (web.get("backup_url") or "").strip()

# 哪条挂了、哪条还活着，说清楚，别只说「看板异常」
lines = []
if web_state == "fail":
    lines.append("· 自有服务器容器不健康（页面可能打不开）")
elif web_state == "skip":
    lines.append("· 自有服务器容器未检查（服务器上没有 docker）")

if pages_state == "fail":
    lines.append("· GitHub Pages 发布或构建失败（线上还是上一版）")
elif pages_state == "skip":
    lines.append(f"· GitHub Pages 未发布（缺 {token_file}）")

alive = []
if web_state == "ok" and backup_url:
    alive.append(f"自有服务器 {backup_url}")
if pages_state == "ok" and main_url:
    alive.append(f"GitHub Pages {main_url}")
if alive:
    lines.append("")
    lines.append("**仍在正常服务**：" + "；".join(alive))

if web_state == "fail":
    lines.append("")
    lines.append("排查与恢复：")
    lines.append(f"  docker ps -a | grep {container}")
    lines.append(f"  docker logs {container} --tail 50")
    lines.append(f"  cd {base}/deploy && docker compose up -d")

if pages_state == "skip":
    lines.append("")
    lines.append("补一个 fine-grained PAT（仅本仓库，Contents: Read and write）写进")
    lines.append(f"{token_file} 并 chmod 600 即可。")

tail = ""
try:
    ls = [l.rstrip() for l in open(logfile, encoding="utf-8", errors="ignore").read().splitlines() if l.strip()]
    tail = "\n".join(ls[-5:])
except OSError:
    pass

msg = ("**🟡 看板有一条链路异常**\n\n"
       "日报推送正常，但看板的双活链路其中一条出了问题：\n\n"
       + "\n".join(lines)
       + f"\n\n**日志尾部**\n{tail[:600]}")
ok = collect.push_wecom_app(msg, cfg)
print(f"[alert] 看板告警推送{'成功' if ok else '失败'}")
PY
    : > "$ALERT_MARK"
fi

if [ "$rc" -ne 0 ]; then
    python3 - "$LOG" >> "$LOG" 2>&1 <<'PY'
import os, sys
base = os.environ.get("VW_BASE") or "/opt/vuln-watch"
sys.path.insert(0, base)
import yaml, collect

logfile = sys.argv[1]
cfg = yaml.safe_load(open(os.path.join(base, "vuln-watch.yaml"), encoding="utf-8"))
tail = ""
try:
    lines = [l.rstrip() for l in open(logfile, encoding="utf-8", errors="ignore").read().splitlines() if l.strip()]
    tail = "\n".join(lines[-6:])
except OSError:
    pass

msg = (
    "**🔴 漏洞日报推送失败**\n\n"
    "定时任务退出码非 0，本轮未完成推送。\n"
    f"日志：{logfile}\n\n"
    f"**最后几行**\n{tail[:900]}"
)
ok = collect.push_wecom_app(msg, cfg)
print(f"[alert] 失败告警推送{'成功' if ok else '也失败了，只能看日志'}")
PY
fi

exit "$rc"
