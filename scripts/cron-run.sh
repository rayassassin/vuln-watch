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
PAGES_STATE=ok      # ok / fail / skip，看板发布结果，用于决定要不要发提示

{
    echo "=== $(date '+%F %T') start ==="
    # 显式限定一天：日报只覆盖最近 24h，不因水位落后而回补历史
    "$BASE/run.sh" --days 1
    rc=$?
    echo "=== $(date '+%F %T') exit $rc ==="

    # 采集成功后把看板发布到 GitHub Pages（走 Git Data API，见 publish_pages.py）。
    # 这一步失败不能算日报失败：消息已经发出去了，页面晚一轮更新而已，
    # 所以不改 rc，避免误触发「🔴 推送失败」告警；但也不能静默，
    # 下面单独发一条 🟡 提示，让人知道线上看板还停在上一版。
    if [ "$rc" -eq 0 ]; then
        if [ -f "$TOKEN_FILE" ]; then
            echo "=== $(date '+%F %T') publish pages ==="
            cd "$BASE" && GH_PAGES_TOKEN="$(cat "$TOKEN_FILE")" \
                python3 scripts/publish_pages.py || PAGES_STATE=fail
        else
            echo "[warn] 未配置 $TOKEN_FILE，本轮跳过看板发布"
            PAGES_STATE=skip
        fi
    fi
} >> "$LOG" 2>&1

# 看板没更新要说一声，别让人以为页面挂了还没人管。
# 一天只提醒一次（marker），修好之后第一次发布成功就清掉，不会变成刷屏。
ALERT_MARK="$LOGDIR/.pages_alert"
if [ "$PAGES_STATE" = "ok" ]; then
    rm -f "$ALERT_MARK"
elif [ "$rc" -eq 0 ] && [ ! -f "$ALERT_MARK" ]; then
    python3 - "$PAGES_STATE" "$LOG" "$TOKEN_FILE" >> "$LOG" 2>&1 <<'PY'
import os, sys
base = os.environ.get("VW_BASE") or "/opt/vuln-watch"
sys.path.insert(0, base)
import yaml, collect

state, logfile, token_file = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = yaml.safe_load(open(os.path.join(base, "vuln-watch.yaml"), encoding="utf-8"))

if state == "skip":
    why = (f"服务器上没有 {token_file}，看板一直停在旧版本。\n"
           "建一个 fine-grained PAT（仅本仓库，Contents: Read and write）"
           "写进这个文件，chmod 600 即可。")
else:
    tail = ""
    try:
        lines = [l.rstrip() for l in open(logfile, encoding="utf-8", errors="ignore").read().splitlines() if l.strip()]
        tail = "\n".join(lines[-5:])
    except OSError:
        pass
    why = f"发布脚本报错，详情看日志尾部：\n{tail[:700]}"

msg = f"**🟡 看板未更新**\n\n日报推送正常，但 Pages 发布没成功，线上还是上一版。\n\n{why}"
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
