#!/bin/sh
# 供服务器 cron 调用。与 run.sh 的区别：负责日志落盘 + 失败告警。
# 告警走同一应用通道（尽力而为）；通道本身挂掉时至少留日志。
#
# 安装目录、token 位置都从环境变量取，默认值只是本项目的中性约定，
# 换台机器部署只要设 VW_BASE 即可，不必改脚本。
set -u

BASE=${VW_BASE:-/opt/vuln-watch}
export VW_BASE="$BASE"
LOGDIR="$BASE/logs"
mkdir -p "$LOGDIR"
LOG="$LOGDIR/cron-$(date +%Y%m%d).log"
TOKEN_FILE=${VW_PAGES_TOKEN_FILE:-$BASE/.pages_token}
WEB_STATE=ok        # ok / fail / skip，看板容器可用性，用于决定要不要发提示
WEB_CONTAINER=${VW_WEB_CONTAINER:-vuln-watch-web}

{
    echo "=== $(date '+%F %T') start ==="
    # 显式限定一天：日报只覆盖最近 24h，不因水位落后而回补历史
    "$BASE/run.sh" --days 1
    rc=$?
    echo "=== $(date '+%F %T') exit $rc ==="

    # 看板现在由 nginx 容器直接挂载采集输出目录对外服务：
    # collect.py 写完 data.json 的那一刻，访客就已经能拿到新数据，
    # 中间没有任何发布步骤，也就不存在「发布失败」这回事。
    # 这里只做一件事：确认容器还活着。容器挂了页面就是白屏，必须吭声。
    if [ "$rc" -eq 0 ]; then
        if command -v docker >/dev/null 2>&1; then
            st=$(docker inspect -f '{{.State.Health.Status}}' "$WEB_CONTAINER" 2>/dev/null || echo missing)
            echo "=== $(date '+%F %T') dashboard container: $st ==="
            [ "$st" = "healthy" ] || WEB_STATE=fail
        else
            echo "[warn] 未找到 docker，跳过看板可用性检查"
            WEB_STATE=skip
        fi

        # 可选：仍想往 GitHub Pages 同步一份当异地备份，设 VW_PUBLISH_PAGES=1。
        # 默认关闭：页面已经在本机对外服务，再发一份纯属浪费两次请求。
        if [ "${VW_PUBLISH_PAGES:-0}" = "1" ] && [ -f "$TOKEN_FILE" ]; then
            echo "=== $(date '+%F %T') publish pages (backup) ==="
            cd "$BASE" && GH_PAGES_TOKEN="$(cat "$TOKEN_FILE")" \
                python3 scripts/publish_pages.py || echo "[warn] 备份发布失败（不影响主站）"
        fi
    fi
} >> "$LOG" 2>&1

# 看板打不开要说一声，别让人以为页面还在。
# 一天只提醒一次（marker），修好之后第一次检查通过就清掉，不会变成刷屏。
ALERT_MARK="$LOGDIR/.web_alert"
if [ "$WEB_STATE" = "ok" ]; then
    rm -f "$ALERT_MARK"
elif [ "$rc" -eq 0 ] && [ ! -f "$ALERT_MARK" ]; then
    python3 - "$WEB_STATE" "$LOG" "$WEB_CONTAINER" >> "$LOG" 2>&1 <<'PY'
import os, sys
base = os.environ.get("VW_BASE") or "/opt/vuln-watch"
sys.path.insert(0, base)
import yaml, collect

state, logfile, container = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = yaml.safe_load(open(os.path.join(base, "vuln-watch.yaml"), encoding="utf-8"))

if state == "skip":
    why = "服务器上找不到 docker 命令，无法检查看板容器状态。"
else:
    tail = ""
    try:
        lines = [l.rstrip() for l in open(logfile, encoding="utf-8", errors="ignore").read().splitlines() if l.strip()]
        tail = "\n".join(lines[-5:])
    except OSError:
        pass
    why = (f"容器 {container} 状态不是 healthy（可能已退出或反代上游挂了）。\n\n"
           "排查与恢复：\n"
           f"  docker ps -a | grep {container}\n"
           f"  docker logs {container} --tail 50\n"
           f"  cd {base}/deploy && docker compose up -d\n\n"
           f"日志尾部：\n{tail[:600]}")

msg = f"**🟡 看板容器异常**\n\n日报推送正常，但全景看板可能已经打不开了。\n\n{why}"
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
