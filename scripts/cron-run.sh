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
    "$BASE/run.sh"
    rc=$?
    echo "=== $(date '+%F %T') exit $rc ==="
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
