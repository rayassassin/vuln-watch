#!/bin/sh
# 供服务器 cron 调用。与 run.sh 的区别：负责日志落盘 + 失败告警。
# 告警走同一应用通道（尽力而为）；通道本身挂掉时至少留日志。
set -u

BASE=/opt/vuln-watch
LOGDIR="$BASE/logs"
mkdir -p "$LOGDIR"
LOG="$LOGDIR/cron-$(date +%Y%m%d).log"

{
    echo "=== $(date '+%F %T') start ==="
    # 显式限定一天：日报只覆盖最近 24h，不因水位落后而回补历史
    "$BASE/run.sh" --days 1
    rc=$?
    echo "=== $(date '+%F %T') exit $rc ==="

    # 采集成功后把看板推到 GitHub Pages。
    # 这一步失败不能算日报失败：消息已经发出去了，页面晚一轮更新而已，
    # 所以只记 warn 不改 rc，避免误触发「🔴 推送失败」告警。
    if [ "$rc" -eq 0 ]; then
        if [ -f "$BASE/.pages_token" ]; then
            echo "=== $(date '+%F %T') publish pages ==="
            cd "$BASE" && GH_PAGES_TOKEN="$(cat "$BASE/.pages_token")" \
                python3 scripts/publish_pages.py || echo "[warn] Pages 发布失败，看板未更新（不影响日报）"
        else
            echo "[skip] 未配置 $BASE/.pages_token，跳过 Pages 发布"
        fi
    fi
} >> "$LOG" 2>&1

if [ "$rc" -ne 0 ]; then
    python3 - "$LOG" >> "$LOG" 2>&1 <<'PY'
import sys
sys.path.insert(0, "/opt/vuln-watch")
import yaml, collect

logfile = sys.argv[1]
cfg = yaml.safe_load(open("/opt/vuln-watch/vuln-watch.yaml", encoding="utf-8"))
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
