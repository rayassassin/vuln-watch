# vuln-watch

漏洞情报采集 + 企业微信推送。面向 Java / PHP / Tomcat / Nginx 技术栈。

## 它解决什么问题

公开漏洞源每天新增几百条，全推到群里等于没推。这个工具做的是**先确认"这个漏洞打到的是不是你的东西"**，再决定要不要叫醒你。

实测一轮：453 条原始数据 → 25 条命中 → 其中真正该立刻处理的只有 2 条。

## 快速开始

```bash
# 1. 看效果（不推送）
python collect.py --dry-run --days 3

# 2. 正式推送（走已授权的企业微信机器人，无需配 webhook）
python collect.py

# 3. 验收预览：照发但记不住，下次仍会完整推送
python collect.py --days 1 --no-commit

# 4. 指定通道
python collect.py --via cli        # cli | webhook | both

# 5. 回填全景页：从 2026-01-01 到现在（不推送、不动水位）
python collect.py --since 2026-01-01
```

生产环境跑在云服务器，每天 00:00 和 12:00 由系统 cron 触发；本机只做开发与同步（见下面「部署到云服务器」）。

可选环境变量：

| 变量 | 作用 | 不配的后果 |
|---|---|---|
| `NVD_API_KEY` | NVD 限流 5→50 req/30s | 每次多等 20 秒，功能不缺 |
| `GITHUB_TOKEN` | GitHub Advisory 限流 60→5000/小时 | 数据量大时可能被限流 |
| `WECOM_CHAT_ID` | 覆盖推送目标 | 自动用授权人身份 |
| `WECOM_VULN_WEBHOOK` | 群机器人地址（仅 `--via webhook` 需要） | CLI 通道不受影响 |

## 数据源与接入方式

| 源 | 覆盖 | 接入 |
|---|---|---|
| NVD（按 CNA 过滤） | Apache / PHP / Oracle / Python / F5+NGINX 全产品线 | REST API 2.0，`sourceIdentifier` 参数 |
| NVD（关键词通道） | nginx / postgresql / vue / redis / k8s / docker —— 没有自家 CNA 的产品 | `keywordSearch` + `keywordExactMatch` |
| OSV.dev | Maven / Composer / npm / PyPI / Go | `POST /v1/query`，包名+版本精确匹配 |
| CISA KEV | 已确认在野利用的漏洞 | 直下 JSON |
| FIRST EPSS | 未来 30 天被利用概率 | `api.first.org/data/v1/epss`，批量传 CVE |
| GitHub Advisory | **按生态全量**：Maven / PyPI / npm / Packagist / Go / NuGet | REST `/advisories`，按 ecosystem 分页 |
| Packagist | PHP 全量新增通告 | `?updatedSince=<timestamp>`，免认证 |

> **为什么非要关键词通道**：实测 `cna@postgresql.org` 返回 0 条，`security@nginx.com` 也是 0 条，
> nginx 的 CVE 主要由 F5 作为 CNA 分配（已订阅 `f5sirt@f5.com`），但覆盖不全。
> 这类"没有自家 CNA"的产品只能靠 `keywordSearch` 捞，代价是噪声高——
> 所以抓到后会再做一道「关键词必须出现在描述前 100 字」的判定，
> 挡掉那种"WordPress 插件正文里顺带提了一句 nginx"的误报。

## 日报长什么样

信息分层：先告诉你今天有多少、几条要紧，再告诉你每条会有什么后果。

```
🛡 漏洞情报全景 · 10月27日

📅 统计区间　10-27 12:00 → 10-28 12:00
📊 采集 446 条 · 命中 25 条
　　🔴 立即处置 9 ｜ 🟠 本周处置 10 ｜ 🟡 观察 6
🔍 数据源　NVD · OSV · Packagist · KEV · EPSS

━━━━━━━━━━━━━━

🔴 立即处置（9 条）

1. CVE-2025-24813 · Apache Tomcat
　CVSS≈9.5 ｜ 已进 KEV ｜ EPSS 100%
　▸ 影响：远程代码执行，攻击者可在服务器上执行任意命令，等同拿下主机
　▸ 条件：可远程利用 · 无需任何认证 · 机密性/完整性/可用性全失
　▸ 范围：11.0.0-M1 至 11.0.3 之前；10.1.0-M1 至 10.1.35 之前
　▸ 查看详情（链接）

　其余 4 条：CVE-2026-65905、CVE-2026-65182、…

━━━━━━━━━━━━━━

🟠 本周处置（10 条）
…

━━━━━━━━━━━━━━

🟡 观察列表　CVE-2026-29146、CVE-2023-46589、…
```

**每条包含四要素**，缺哪个就不写哪个，不硬凑：

| 字段 | 来源 | 作用 |
|---|---|---|
| 影响 | 从标题语义归类（RCE / 认证绕过 / 路径遍历 / SSRF / DoS 等 13 类） | 说清打进来之后会怎样，而不只是"高危" |
| 条件 | 解析 CVSS 向量（AV / PR / C-I-A） | 可远程还是需内网、要不要登录，直接决定紧迫性 |
| 范围 | OSV 的 affected ranges / Packagist 的 Composer 约束 | 哪些版本中招，不用再点进链接找 |
| 处置 | CISA 的 requiredAction | 官方口径，比自己编建议可靠 |

**为什么不是全部展开**：P0 最多展开 5 条、P1 最多 6 条，其余折叠成 CVE 编号。25 条全展开的日报没人会读完，而不读完的日报等于没发。

## 设计要点（改动前先看这里）

**1. 用 CNA 订阅厂商，而不是逐个爬公告页。**
`sourceIdentifier` 一个参数就能拿到整个厂商生态的 CVE。配置里已内置三个实测有效的：

- `security@apache.org` → 3044 条（Tomcat / Struts / Kafka / ActiveMQ / Solr / Dubbo…）
- `secalert_us@oracle.com` → 12520 条（JDK / WebLogic / MySQL）
- `security@php.net` → 106 条

更多 CNA 在 https://www.cve.org/PartnerInformation/ListofPartners 查。

**2. 组件匹配用 purl + 版本，不用关键词搜。**
`keywordSearch=tomcat` 会返回一堆无关结果。用 `org.apache.tomcat:tomcat-catalina` + 版本号查 OSV，命中就是真命中。

**3. 分级不看 CVSS 绝对值。**
一个 CVSS 9.8 但 EPSS 0.01 的 WebLogic 漏洞，和你一个 CVSS 7.5 且已进 KEV 的 Tomcat 漏洞，优先级完全不是一回事。当前规则：

- **P0**：进了 CISA KEV / 命中自有组件且 CVSS≥9 / CVSS≥9 且 EPSS≥0.1
- **P1**：命中自有组件且 CVSS≥7 / CVSS≥7 且 EPSS≥0.1
- **P2**：CVSS≥7，其余情况降级观察

**4. 推送失败不推进水位。**
`state.db` 里记 `last_run`，只有推送成功才更新。失败下轮自动重试，杜绝静默丢消息。

**5. 企微 2048 字节限制。**
`split_by_bytes()` 按行切分，`max_bytes` 默认 6000。注意两个限制不是一回事：CLI 通道单条上限 20480 字节，群机器人 webhook 才是 2048。

## 部署到云服务器

生产跑在一台Linux 服务器上，目录 `/opt/vuln-watch`。

```bash
# 本机改完代码、提交后，一条命令同步
python3 scripts/deploy.py
```

同步逻辑：`git archive` 只打包已跟踪文件 → 上传到中转目录 → 解包到 `/opt/vuln-watch`
→ 写 `.version`（当前 commit sha）→ 重新生成 `run.sh`。
**服务器上的 `state.db`、`.env`、`logs/` 一律不动**，所以同步不会把已推送水位冲掉。

服务器侧文件：

| 文件 | 作用 |
|---|---|
| `run.sh` | 启动包装，固定 `WECOM_CHANNEL=app`，收件人从既有 `feeds.json` 取 |
| `scripts/cron-run.sh` | cron 入口：落日志 + 失败告警 |
| `logs/cron-YYYYMMDD.log` | 每天的运行日志 |
| `.version` | 当前部署的 commit |

定时任务（服务器 crontab）：

```
0 0,12 * * * /opt/vuln-watch/scripts/cron-run.sh
```

每天 00:00 与 12:00 各抓一次。两次窗口都取最近 24h，刻意留重叠，
配合 `state.db` 的 `mark_seen` 水位去重：宁可多查一遍，不漏；已推过的 CVE 不会重复推。

**为什么必须在服务器上跑**：自建应用配了可信 IP 白名单，本机出口 IP 调 `message/send`
会被拒（`errcode 60020`）。服务器在名单内，本机不在。本机想直发只能走 `channel: cli`（wecom-cli）。

**失败一定告警**：`cron-run.sh` 捕获非 0 退出码，通过同一应用通道发「🔴 漏洞日报推送失败」
并附日志最后几行；告警本身失败也会在日志里留一行，不留静默黑洞。

## 定制化订阅：我用了 X，就盯 X

不用改主配置，一条命令：

```bash
python scripts/subscribe.py add vue                         # 常见名字，自动判断该走包坐标还是关键词
python scripts/subscribe.py add "org.springframework:spring-core" --eco Maven --version 5.3.31
python scripts/subscribe.py add nginx --keyword             # 没有包坐标的产品
python scripts/subscribe.py test nginx --days 30            # 先看两周能命中多少，再决定加不加
python scripts/subscribe.py list                            # 看现在都订了什么
python scripts/subscribe.py remove vue
```

写入独立的 `subscriptions.yaml`（纯数据文件，不动主配置的注释），
`collect.py` 每次启动自动合并进去。加完回填一次：
`python collect.py --since 2026-01-01`。

内置目录覆盖了 60 多个常见组件（nginx / postgresql / redis / vue / react / django /
flask / spring / log4j / shiro / laravel / thinkphp …）。不在目录里的名字会退化成
NVD 关键词订阅并给出提示。

## 网页可视化（web/）

除企业微信推送外，`collect.py` 每次运行还会把命中条目导出到 `web/data.json`，
由 `web/index.html` 渲染成情报全景看板（浅色主题，视觉参照 ai-radix 的全景页）。

```bash
# 首次 / 换口径：回填 2026-01-01 到现在，页面才有"全景"可看
python3 collect.py --since 2026-01-01

# 之后每次日常运行都会把新命中合并进同一份 data.json
python3 collect.py --dry-run --days 1

# 本地预览
cd web && python3 -m http.server 8080      # http://localhost:8080
```

页面包含：统计条（收录量 / P0 / P1 / KEV）、时间范围筛选（7/30/90/365 天 / 全部）、
分级与标签筛选、组件筛选、搜索、排序（默认**按发布日期倒序**，最新在最前）、
表格 / 卡片两种视图、**每页 50 条分页**（顶部有紧凑翻页，底部有完整页码）、
命中趋势图（跨度超 70 天自动按月聚合）。

### 发布到 GitHub Pages

看板不在服务器上对外提供服务，而是推到一个纯静态仓库：

**https://rayassassin.github.io/vuln-watch-pages/**

```bash
python3 scripts/publish_pages.py                # 手动发一次
python3 scripts/publish_pages.py --dry-run      # 只校验文件，不联网
python3 scripts/publish_pages.py --force        # 内容没变也重发
python3 scripts/publish_pages.py --ensure-pages # 顺带确认 Pages 已启用
python3 scripts/publish_pages.py --wait 120     # 等 Pages 构建完成
python3 scripts/publish_pages.py --method git   # 应急：退回 git push
```

服务器上 cron 会在采集成功后自动发布（`cron-run.sh` 里调用）。需要一次性配 token：

1. GitHub → Settings → Developer settings → Personal access tokens → **Fine-grained tokens**
2. Repository access 只勾 `vuln-watch-pages`，权限给 **Contents: Read and write**
   （想让它自动启用 Pages 再补 **Pages: Read and write**）
3. 服务器上落盘：`echo '<token>' > /opt/vuln-watch/.pages_token && chmod 600 /opt/vuln-watch/.pages_token`

没有这个文件时，cron 跳过发布，并发一条 **🟡 看板未更新** 提示（一天最多一次，
修好后自动停止），**不影响日报推送**。

**为什么走 Git Data API 而不是 git push**：data.json 4 MB，`clone → commit → push`
要走 pack 协议加一条长连接。实测本机代理链路报 `Error in the HTTP2 framing layer` /
`CONNECT tunnel failed 502`，云服务器到 github.com 报 `GnuTLS recv error (-110)`，
两条链路都不可靠，重试只是赌运气。改成 `blobs → tree → commit → 改 ref` 之后
是四五个独立的 HTTPS POST，单个请求几十 KB，失败只影响这一次请求。
脚本只用标准库（`urllib` / `base64`），服务器 python3 不需要装 `requests`。

**为什么每次是一个无父 commit**：一天两次、每次几 MB 的常规提交，一年能把仓库历史
撑到几个 GB。每次新建 orphan commit 再 force 覆盖 ref，旧对象不进任何分支，
GitHub 侧 GC 之后体积稳定在「一份快照」的量级。代价是没有历史版本可回溯，
而这个页面本来也不需要——要历史去 state.db。

另外脚本会记一个内容指纹 `.pages_state`，数据没变化就直接跳过，cron 不白跑一次 API。

### 回填 vs 日常，两条通道各管一段

| | `--since` / `--backfill N` | 日常运行 |
|---|---|---|
| 目的 | 给全景页灌历史基数 | 发现新漏洞并推送 |
| NVD 时间字段 | `pubStartDate`（按发布时间） | `lastModStartDate`（按修改时间） |
| 时间区间 | `--since` 固定起点到现在；`--backfill N` 从 N 天前到现在 | 上次运行至今，上限 1 天 |
| NVD 通道 | CNA + 关键词 | CNA + 关键词 |
| 推送 | **不推送** | 推送企业微信 |
| `state.db` 水位 | **不写、不 mark_seen** | 成功才推进 |
| `stale_days` | 关闭（否则历史数据全被过滤） | 2 天 |
| 关键词粗筛 | 默认关闭（按订阅的 CNA 全量收录） | 开启 |
| 配额截断 | 不截断（仅 12000 条兜底） | P0:5 / P1:4 / P2:4 |

**为什么回填不写水位、不 mark_seen**：回填会把几百天的漏洞标成「已读」，
第二天真有新漏洞时日常任务就把它当旧的漏掉了。区间取到"此刻"是因为回填不推送，
不存在与日报重复的问题，取到此刻才不会在 data.json 里留一段"今天已发布但没人抓"的空洞。

### data.json 格式（v2）

单对象，不再是「每天一个快照」的数组：

```
{
  format: 2, generated_at, mode: "backfill" | "daily",
  range: {from, to},                     // 按发布日期
  stats: {total, p0, p1, p2, kev, exact, scanned, new_this_run},
  last_run: {date, hit, p0, p1, p2},     // 只反映最近一次运行
  sources: [], degraded: [],
  daily: [{date, hit, p0, p1, p2}],      // 按发布日期分桶，给趋势图用
  entries: [{cve, level, cvss, epss, kev, component, impact, ...}]
}
```

按 CVE 去重合并：回填和日常巡检都抓到同一条时，保留信息更全的一份，
分级取更严重的那个。保留窗口 400 天（`backfill.retention_days`）。

设计要点：
- 纯只读旁路，不碰推送与 `state.db` 水位；网页挂了不影响日报
- `web/data.json` 由脚本现场生成，**不入库**（`.gitignore` 已排除），服务器/本机各自维护
- 旧版「按天数组」格式仍能读入，升级不丢已攒的历史

## 凭证与配置安全

**这个仓库不放任何凭证。** 所有密钥一律走环境变量，配置里只写变量名：

| 需要的东西 | 放哪 | 仓库里的写法 |
|---|---|---|
| NVD API Key | 环境变量 `NVD_API_KEY` | `api_key_env: NVD_API_KEY` |
| GitHub Token | 环境变量 `GITHUB_TOKEN` | 代码里 `os.environ.get(...)` |
| 企微群机器人地址 | 环境变量 `WECOM_VULN_WEBHOOK` | `webhook_env: WECOM_VULN_WEBHOOK` |
| 推送目标会话 | 运行时从授权身份解析 | `chat_id: ""`（保持空） |

`state.db` 不入库：它记录「哪些漏洞已经推过」。多台机器共用同一份水位会让漏报变常态。

**双重拦截**：

```bash
# 每个 clone 执行一次，启用提交前检查
git config core.hooksPath .githooks
```

- 本地：`.githooks/pre-commit` 扫暂存区，命中即阻止提交
- 远端：暂未启用。GitHub Actions 的工作流文件需要 token 具备 `workflow` 权限，
  当前账号只有 `repo`，推送带 workflow 的提交会被拒。要开的话先执行
  `gh auth refresh -s workflow`，再补一个 `python scripts/check_secrets.py` 的 job。

扫描规则在 `scripts/check_secrets.py`，覆盖 GitHub token、企微 webhook key / 会话 ID、硬编码密码、请求头明文凭证、私钥块、公网 IP、含用户名的本机路径。误报就把特征加进 `ALLOW_PATTERNS`，**不要关规则**。

即使钩子被 `--no-verify` 绕过，`python scripts/check_secrets.py` 仍是推送前的最后一道人工闸门。

## 日常维护

只改 `vuln-watch.yaml` 里的两块：

- `osv.assets` —— 加/删组件、更新版本号。版本号建议从 `pom.xml`、`composer.lock` 自动提取
- `keyword_watch` / `keyword_exclude` —— 中间件关键词，以及串台误报的排除词

## 已知限制

- **CNVD / CNNVD 无法自动接入**。官方没有公开 REST API，只有注册用户可下载的每周 XML 批包。网上流传的 `api.cnvd.org.cn` 是编的示例，别照着写。要覆盖国产软件漏洞，现阶段的选项是自己写 XML 解析，或买微步 / 奇安信的商业订阅。
- **Tomcat、Nginx 官方公告页没有 JSON**，只能爬 HTML。本工具用 NVD 的 CVE 记录间接覆盖，时效性比官方页晚半天到一天。
- **关键词匹配有天花板**。比如 "Redis Lua overflow in Apache Kvrocks" 会因为含 redis 被误捞。这类靠 `keyword_exclude` 手工补，不是长久解。真正可靠的是补全 `osv.assets`。
- OSV 里 `CVSS≈` 前缀表示分值由严重级别换算（CRITICAL→9.5 / HIGH→8.0），不是 NVD 真实 base score。要精确值走 NVD 或 GitHub Advisory 那一路。
- **「影响」是规则匹配出来的，不是人工研判**。13 类关键词规则命中不了时，会退化成显示原始描述。遇到归类不准的，往 `IMPACT_RULES` 里补词即可。这块能力有上限——真要做深度研判还得人来。

## 文件

- `vuln-watch.yaml` —— 配置，日常只改这个
- `collect.py` —— 采集、归一化、打分、推送
- `state.db` —— 已推送记录和运行水位（SQLite，删掉等于重置）
