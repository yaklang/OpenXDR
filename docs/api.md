# REST API 参考

Base: `http://<server>:8080`。除 `POST /api/login` 外全部需要会话 cookie
（`openxdr_session`）。权限约定：**GET = viewer 及以上，写操作 = analyst 及以上，
`/api/users`、`/api/audit`、`/api/settings` 与 `/api/groups` 写操作 = admin**。

## 认证

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | `{"username","password"}` → 设置会话 cookie。失败按源 IP 指数退避 |
| POST | `/api/logout` | 吊销当前会话 |
| GET | `/api/me` | 当前用户 `{username, role}` |

## 事件与告警

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/incidents?status=&assetId=&limit=&offset=` | incident 列表（按创建时间倒序），含派生严重度、告警数与 `groupId`（第一条有资产的告警所在资产的组，无则 null）；`status` 另支持 `unresolved`（= open + triaged）与 `review`（需人工复核：未结案，且 AI 未判良性或最高告警级别 ≥ 4，与 Webhook 推送同一口径）；`limit` 默认 50、范围 1..500，`offset` 默认 0；响应头 `X-Total-Count` 为分页前的匹配总数；`assetId` 筛涉及该主机的事件 |
| GET | `/api/incidents/{id}` | 详情：实体图、告警明细（含原始事件）、AI verdict、`groupId` |
| POST | `/api/incidents/{id}/status` | `{"status":"open\|closed\|false_positive","note":"…"}`；closed 为属实已处置、false_positive 为误报或良性，两者必须写 `note`（1–2000 字），记录结案人与时间并作为案例喂回研判；改回 open 清掉结案信息 |
| GET | `/api/incidents/groups?status=review\|unresolved` | 按规则归并（只是视图，不改 incident）：未结案事件按「主告警的规则 + 主机」分组，主告警取事件里级别最高的告警（同级取最早）；情报命中的规则 ID 形如 `intel:ip:1.2.3.4`，同一目标自然归一组。每组含 `ruleId`、`ruleTitle`、`assetId`、`hostname`、`count`、`severity`、`firstAt` / `lastAt`（事件创建时间）、`verdicts`（`benign` / `suspicious` / `malicious` / `none` 各几个）与组内事件 `incidents`（同列表项）；按事件数、最近时间倒序。`status` 默认 `review`，只接受 `review` / `unresolved`；最多扫最近 2000 个事件，超出时 `X-Truncated: 1`，`X-Total-Count` 为匹配总数 |
| POST | `/api/incidents/batch-status` | 批量结案 `{"ids":[…],"status":"closed\|false_positive","note":"…","confirmMalicious":false}`：一次 1–200 个，口径与单个结案一致（理由规则、结案人与时间、作为人工案例回喂研判），一个事务内全部成功或全部不动，逐条写 `incident_status` 审计。任一事件不存在（404）、不在调用者有 analyst 权限的组内（403）、已被结案（409）或需写理由却没写（400）都整批拒绝；含 AI 判恶意的事件按 `false_positive` 结案必须 `confirmMalicious: true`，否则 409。说明原样等于这批里某个事件的 AI 结案建议时，整批记为 `resolution_source=ai_proposal`。返回 `{"resolved":n}` |
| GET | `/api/findings?status=&assetId=&ids=&limit=&offset=` | 运维待办（巡检 AI 登记，按组裁剪，可按资产筛选），含主机名、首次与最近发现时间；`limit` 默认 500、范围 1–500，`offset` 默认 0；`X-Total-Count` 返回筛选后总数，仍有后续页时带 `X-Truncated: 1`；可用逗号分隔的 `ids` 精确查询最多 10 条会话引用；无效 `assetId`、空或无效 `ids` 返回 400 |
| POST | `/api/findings/{id}/status` | `{"status":"open\|resolved\|ignored","note":"…"}`，需组内 analyst；resolved / ignored 必须写原因，忽略原因会交给巡检 AI，之后不再登记，写审计 `finding_status`；组管理员发起的 Pi 对话里 AI 可按用户明确要求代为忽略，口径相同（见 `docs/pi-backend.md`「运维待办」） |
| GET | `/api/incidents/{id}/report` | 事件报告（Markdown 附件下载）：判定、攻击链、涉及实体、告警时间线、处置记录、处置建议 |
| GET | `/api/events` | 原始事件检索，参数见下 |
| GET | `/api/events/{id}/related` | 与这条日志有确定关联的日志，按关联方式分组：ancestor 父进程链 / process 同一进程 / child 子进程 / connection 同一连接 / peer 别的主机连同一远端 / nearby 同主机前后两分钟；只取调用者可见的资产 |
| POST | `/api/events/{id}/explain?lang=&refresh=` | 问 AI（analyst）：发起后台解读并立即返回任务 `{id,status,result,error}`。模型读这条日志与上面的候选，`result` 含判定（benign / suspicious / malicious / unknown）、结论、依据、下一步，以及从候选里挑出的相关日志。已有在跑的或已有结果时直接返回它，`refresh=1` 才重新解读；未配置研判与标注模型时 503 |
| GET | `/api/events/{id}/explain?lang=` | 读自己对这条日志的最近一次解读：`status` 为 none / running / done / failed；前端在 running 时轮询。解读按发起人存，保留 7 天 |
| GET | `/api/stats` | 概览：24h 降噪漏斗、告警趋势、按级别的告警分布（`alertsBySeverity`）、Top 规则、资产在线率；`reviewIncidents` 为需人工复核的事件数（口径同 `status=review`） |
| GET | `/api/rules` | 引擎当前加载的规则（热重载后即时反映），含数据源覆盖标记与 ATT&CK 标签 |
| GET | `/api/attack` | ATT&CK 覆盖矩阵：按杀伤链顺序的战术列与技术格，含未打标签、无数据源的规则数 |
| GET | `/api/temporal-gaps?assetId=&from=&to=&limit=` | 该资产的时序检测缺口（`candidate_limit` / `late`），详见 [时序检测](temporal-detection.md#缺口查询接口) |
| GET | `/api/temporal-rule-snapshots?limit=&alertId=` | 已归档的时序规则版本（**全局 admin / analyst**，角色每次从库里取），按首次使用时间倒序：`{items:[{revision,createdAt,format,baseRuleCount,temporalRules}],truncated}`；`limit` 默认 20、范围 1..100。带 `alertId` 时只返回该告警命中时的版本（单事件告警、旧版本告警或调用者看不到的告警返回空列表） |
| GET | `/api/temporal-rule-snapshots/{revision}?rule=` | 按版本哈希取当时的时序规则：`{revision,createdAt,rules:[{id,title,author,kind,groupBy,severity,windowSeconds,threshold,minAssets,references,source,base}]}`，`base` 为该规则引用的基础规则原文；`rule` 只取一条（不存在 404）。按原文重算版本哈希，归档被改动或格式不支持时 500 拒绝展示。权限同上 |

`GET /api/events` 参数：`from`/`to`（RFC3339，默认近 24h）、`assetId`、
`classUid`（1001 文件 / 1007 进程 / 3002 认证 / 4001 网络 / 4003 DNS /
201002 注册表 / 100001 日志）、
`source`（agent/sensor/syslog）、`q`（对事件里的字段值做不区分大小写的子串匹配，通配符按字面量处理；不匹配字段名，口径见 [事件表分区](event-partitioning.md#关键词检索索引)）、
`limit`（≤200，默认 100）。响应是对象 `{items, truncated, coverage}`：`items` 为事件行；
`truncated` 表示返回条数达到 `limit`（可能还有更早的，同时带响应头 `X-Truncated: 1`）；
`coverage` 为 `{hot_searched, cold_searched, scan_complete, reason}`，`reason` 非空即本次没查全——
`hot_keyword_degraded`（关键词检索超出时限，只覆盖最近数据）、`keyword_not_searched`（关键词不搜冷归档）、
`no_archive_schema`、`scan_incomplete`、`before_archive`，冷归档口径见 [冷归档](event-archive.md)。
各类事件的字段 schema 见 [events.md](events.md)。

## 威胁情报

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/intel` | IOC 清单（含命中计数） |
| POST | `/api/intel` | 单条：`{"kind":"ip\|domain\|hash","value","source","severity","note","expiresInDays"}`，kind 缺省自动识别 |
| POST | `/api/intel/import` | 批量：`{"text":"一行一条","source","severity","expiresInDays"}`，类型自动识别，重复跳过，`#` 行忽略 |
| DELETE | `/api/intel/{id}` | 删除 |
| GET | `/api/intel/feeds` | 情报订阅：`{feeds:[{id,name,url,severity,enabled,count,hits,syncedAt,attemptedAt,error}], hits:[命中过的订阅情报], intervalHours}`。`syncedAt` 为最近成功、`attemptedAt` 为最近尝试；配置读取失败返回 500。`/api/intel` 列表不含订阅条目 |
| PUT | `/api/intel/feeds` | `{"enabled":["feodo",...]}` 保存开关并立即同步（admin）；必须提供数组，全部关闭用 `{"enabled":[]}`，缺失或 null 返回 400，不修改配置 |
| POST | `/api/intel/feeds/sync` | 立即同步（admin） |

## 误报抑制

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/suppressions` | 抑制清单（含压掉次数）；非 admin 只见本组资产的抑制，全局抑制仅 admin 可见 |
| POST | `/api/suppressions` | `{"ruleId","assetId"(空=全局),"reason","expiresInDays"(0=长期)}`；需该资产所在组的 analyst，全局抑制仅 admin，否则 403 |
| DELETE | `/api/suppressions/{id}` | 撤销，权限同创建（按该抑制的资产判断） |

## 已知自动化

按 SSH 登录身份认出的运维自动化（平台自动识别或组管理员手动添加），命中的告警不进事件与研判（高危例外除外），见
[检测链路 · 已知自动化](detection.md#已知自动化serverinternalautomation)。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/trusted-sources?groupId=` | 列表（含已停用、已过期，不含已删除；带命中次数与最近命中、`origin`(auto/manual)、`pinned`、`evidence` 识别依据、`revokeCause`(verdict=系统按结论停用)、`revokeIncidentId`）；组内成员可看，`groupId` 可省略（看全部可见组） |
| GET | `/api/trusted-sources/candidates?groupId=` | 组内窗口内的 SSH 登录，按（用户、指纹；非公钥登录按来源地址）归并，带登录天数 / 次数 / 主机数、告警与结论统计和 `reason`：`eligible` / `no_key` / `public` / `scattered` / `flagged` / `irregular` / `quiet` / `pending` / `few_verdicts`，另有 `covered`（已被生效条目覆盖）、`declined`（人停用或删除过）、`disabled`（自动识别已关闭）；组管理员 |
| POST | `/api/trusted-sources` | 手动添加 `{"groupId","name","reason","keyFingerprint","sourceCidr","loginUser","expiresInDays"(1–365)}`；指纹与网段至少一个，只填网段时不宽于 /24；组管理员，落审计 |
| PATCH | `/api/trusted-sources/{id}` | 调整 `{"name","reason","expiresInDays"(1–365，从现在起算),"pinned","enabled"}`，字段可选、至少一个；启用已过期的须同时给有效期；重新启用系统停用的会自动固定；组管理员，落审计（`trusted_source_updated` / `_enabled` / `_revoked`），已删除 409 |
| DELETE | `/api/trusted-sources/{id}` | 删除（隐藏并停用，记录保留，自动识别的不会再被加回）；组管理员，落审计，重复删除 409 |
| POST | `/api/trusted-sources/{id}/revoke` | 停用（保留记录，立即生效），同 `PATCH {"enabled":false}`；组管理员，落审计，重复停用 409 |

`GET /api/events` 的条目与 `GET /api/incidents/{id}` 的告警带 `automation: {id, name, watch}`（来自可信来源时；`watch` 为高危例外）。

## 响应处置

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/commands?incidentId=&assetId=&view=summary` | 指令历史，可按事件或主机筛选；传 `page`（1–100000）和 `pageSize`（1–100，默认 20）返回 `{items,total}`，不传 `page` 保持最多 100 条数组。控制台使用 `summary`，不读取或返回 `cmd/stdout/stderr`，保留结果摘要与检测关联。省略 `view` 或使用 `full` 保留完整返回；其他值返回 400 |
| GET | `/api/commands/{id}` | 指令详情，按资产组校验权限，包含完整命令与输出 |
| POST | `/api/commands` | `{"kind":"kill_process\|isolate_host\|unisolate_host\|exec\|block_network\|unblock_network\|quarantine_file\|restore_file\|disable_account\|enable_account","assetId","incidentId","pid","target"}`（一律真执行，没有演练模式）；封锁、隔离文件、锁定账号必须带 `target`（IP / 网段 / 域名、文件绝对路径、账号名），不合法或会封到 server 自己时 400；`exec` 另带 `"cmd"`（必填）与 `"timeoutMs"`（0 = agent 默认 60s），结果回写 `exitCode` / `stdout` / `stderr` / `truncated`（各截断到 64KB） |

需 server 配置 `RESPONSE_ENABLED=true`；隔离要求 `ISOLATION_ALLOW` 包含 server
的 gRPC 端点，否则 agent 拒绝执行。

## 资产与管理

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/assets` | 资产清单（含 `groupId`，未分组为 null；`agentVersion` 为 agent 自报版本） |
| GET | `/api/assets/{id}/config` | 该主机的采集配置 |
| PUT | `/api/assets/{id}/config` | 设置采集配置：`{"fileWatchDirs":[...],"collectFiles":true,"collectAuth":true,"collectPersist":true,"collectNetwork":true,"collectInventory":true,"collapsePeriodic":true}`。随 agent 下次注册（重连或重启）生效；`collectNetwork` 在 Linux eBPF 与 Windows ETW 路径生效 |
| GET | `/api/assets/{id}/profile` | 资产画像：区域、暴露级别、云环境、监听端口、依赖与 AI 标注。改标注、指派区域与资产图谱、攻击面、区域定义等接口见 [资产图谱与攻击面](asset-map.md#接口) |
| GET | `/api/users` | 用户列表（admin） |
| POST | `/api/users` | 建号：`{"username","password","role"}`（admin） |
| POST | `/api/users/{id}/password` | 重置密码（admin） |
| DELETE | `/api/users/{id}` | 删号（admin） |
| GET | `/api/audit?q=` | 审计日志（admin，最新 500 条）；`q` 对用户名、动作、对象、详情做不区分大小写的子串匹配；取满 500 条时带 `X-Truncated: 1` |
| GET | `/api/settings/notify` | 通知配置 `{url,format,linkBase,minSeverity}`（admin）。未保存过时返回环境变量默认值 |
| PUT | `/api/settings/notify` | 保存通知配置（admin）；`format` 取 generic / dingtalk / feishu / wecom，地址须为 http(s) |
| POST | `/api/settings/notify/test` | 用请求体里的配置（不保存）发一条测试消息（admin），推送失败返回 502 |
| GET | `/api/setup` | 安装初始化状态 `{agreementVersion,accepted,acceptedBy,acceptedAt,onboarded}`（所有登录用户）。已有组或主机的实例 `onboarded` 恒为 true |
| POST | `/api/setup/agreement` | 管理员同意用户协议 `{version}`，版本须与当前 `agreementVersion` 一致，否则 409；落审计 `agreement_accepted` |
| POST | `/api/setup/onboarded` | 结束首次引导 `{skipped:[...]}`（admin），须先同意协议；落审计 `onboarding_finished` 并记下跳过的步骤 |
| GET | `/api/settings/ai` | AI 与外部情报配置（admin）：端点、研判/标注模型、Pi 模型、反向解析、VT 转情报阈值；密钥只返回是否已设与末四位；`source` 标明每项来自控制台还是环境变量 |
| PUT | `/api/settings/ai` | 修改（admin）：只改出现的字段；密钥传空串表示清空；`reset` 列出的项回到环境变量。未配置 `HOST_CREDENTIAL_KEY` 时拒绝保存密钥 |
| POST | `/api/settings/ai/test` | 用请求体里未保存的值测试（admin）：`target` 为 model / piModel 时发一句最短对话，vt 时查一个公共地址；失败返回 502 |
| GET | `/api/settings/ai/accuracy?days=` | 研判准确度（admin，默认 90 天）：总体、按研判模型、按规则的独立复核数、AI 判良性数与其中的漏判、AI 告警数与其中的误判、采纳 AI 与自动结案数，及最近 10 条漏判与误判。只有人写理由的结案算独立复核 |
| GET | `/api/settings/ai/usage?days=&tz=` | AI 用量（admin）：按天、用途（chat / task / triage / annotate / explain）、模型聚合的 token 与调用次数，及用量最多的 10 个会话 |

## 资产组

一台主机属于至多一个组；用户在每个组内有各自角色（admin / analyst / viewer），
全局 admin 天然是所有组的 admin。实现见 `server/internal/api/groups.go`。

**按组裁剪**：非 admin 用户在资产、事件、告警、incident、指令、采集配置、统计与 incident 报告上
只看得到自己所在组的资产（`server/internal/api/scope.go`）。未分组资产与无归属数据（如 syslog）
只有全局 admin 可见；incident 的全部告警都落在可见资产上才可见，跨组 incident 只有 admin 能看。
写操作在全局角色之外，还要求目标资产所在组内角色达到 analyst，否则 403；读不到的资源一律 404。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/groups` | 当前用户可见的组：`[{"id","name","role","assetCount"}]`，非成员看不到 |
| POST | `/api/groups` | 建组：`{"name"}`（admin） |
| DELETE | `/api/groups/{id}` | 删组：资产退回未分组，成员关系清除（admin） |
| GET | `/api/groups/{id}/members` | 成员名单（组 admin） |
| PUT | `/api/groups/{id}/members/{userId}` | 设定成员角色：`{"role"}`，不存在则添加（admin） |
| DELETE | `/api/groups/{id}/members/{userId}` | 移除成员（admin） |
| PUT | `/api/groups/{id}/assets/{assetId}` | 资产归入该组，离开原组（admin） |
| DELETE | `/api/groups/{id}/assets/{assetId}` | 资产移出该组；不在此组返回 409（admin） |

建组自带 AI 高风险命令名单并自动开通组查询身份；删组一并回收（见 `docs/pi-backend.md`）。

## 身份

全局身份图（合并规则与边界见 [身份来源与关联](identity-correlation.md#全局身份图)）。读按组成员（viewer 起），
确认/拒绝/撤销要求组内 analyst 以上；不可见与不存在统一 404，列表组外返回空。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/identities?groupId=&q=&kind=&limit=&offset=` | 组内身份列表 `{items,truncated}`；`q` 匹配账号名 / SID / 主机名，`kind` 为 `directory` / `host`，`limit` 1–200 |
| GET | `/api/identities/{id}?hours=` | 身份详情：`identity`、链接的 `accounts`（依据、置信度、证据、来源、近期登录）、`history`（最近 50 条撤销记录）；`hours` 默认 168，1–720 |
| GET | `/api/identities/{id}/candidates` | 合并候选（同名、相似名、SID 对应多个目录账号），最多 50 条，带方向与拒绝记录 |
| POST | `/api/identities/{id}/links` | `{"accountId"}` 确认把账号并入该身份；候选已不成立或已被拒绝时 409；落审计 `identity_link_confirmed` |
| POST | `/api/identities/{id}/rejections` | `{"accountId"}` 判定不是同一人；落审计 `identity_candidate_rejected` |
| DELETE | `/api/identity-links/{id}` | 撤销人工链接，账号回到默认归属；系统链接 409；落审计 `identity_link_revoked` |
| DELETE | `/api/identity-rejections/{id}` | 撤销拒绝；落审计 `identity_candidate_rejection_revoked` |
| GET | `/api/assets/{id}/identity-accounts?hours=` | 资产账号视图：`accounts`（近期登录与所属身份）、`unmatched`（未关联到账号的 Linux 登录）、`pending`（待后台关联数）；`hours` 默认 24 |

登录观察、本地账号快照与目录状态等只读接口见 [身份来源与关联](identity-correlation.md)。

## 主机接入

文档导入、凭据管理和 SSH 纳管接口见 [文档导入与主机纳管](host-enrollment.md#api)。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/enroll-tokens/status` | 在线接入是否可用：`{enabled, reason, platforms}`，`reason` 说明缺什么配置 |
| GET | `/api/enroll-tokens?groupId=` | 本组令牌列表（组 admin），不含明文 |
| POST | `/api/enroll-tokens` | `{"groupId","days"}` 签发令牌（组 admin），`days` 缺省 7、最长 30；明文 `token` 只在此返回一次 |
| DELETE | `/api/enroll-tokens/{id}` | 撤销令牌（组 admin） |

以下端点**免登录**，由安装脚本调用：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/enroll/install.sh` | Linux 安装脚本，参数 `<控制台地址> <令牌>` |
| GET | `/api/enroll/install.ps1` | Windows 安装脚本，参数同上 |
| GET | `/api/enroll/agent/{platform}` | agent 安装包，`linux-amd64` / `linux-arm64` / `windows-amd64` |
| POST | `/api/enroll/register` | `Authorization: Bearer <令牌>`，请求体 `{"hostname","os","csr"}`；返回 `{server, ca, cert}`。令牌无效 401，主机名已有在线 agent 或主机已在别组 409，接入未启用 503 |

## 对接示例：定时同步情报源

```bash
# 登录拿 cookie
curl -c cookie.txt -X POST http://xdr:8080/api/login \
  -d '{"username":"feeds-bot","password":"..."}'

# 把情报源导出的清单灌进去，30 天有效期
curl -b cookie.txt -X POST http://xdr:8080/api/intel/import \
  -H 'Content-Type: application/json' \
  -d "{\"text\": \"$(tr '\n' '\\n' < feed.txt)\", \"source\": \"feed-x\", \"expiresInDays\": 30}"
```

## 资产台账导出

`POST /api/assets/export` 使用登录 cookie，viewer 可导出可见组内资产。请求：

```json
{"format":"csv","selection":{"mode":"filter","q":"web","groupId":""}}
```

`format` 为 `csv` 或 `json`。筛选模式匹配主机名（不区分大小写）或 IP 子串，
`groupId` 空表示全部可见组，`ungrouped` 表示未分组（仅全局 admin 可见）。
勾选模式改为 `selection: {"mode":"ids","ids":["UUID"]}`，不能混用筛选条件。
若勾选了无权访问或已删除资产，整次返回 404，不能部分导出。

最多 10,000 条、编码后最多 32 MiB；超过返回 422，应缩小范围，不静默截断。
CSV 为 UTF-8 BOM，固定英文表头，多个 IP 用分号分隔，危险表格公式前加单引号；
JSON 保留原值，结构为 `{schemaVersion, exportedAt, filters, count, items}`。
字段仅含资产标识、主机名、OS、IP、组、agent/sensor 版本与最近心跳及主机状态，
不包含密码、私钥、配置或原始健康数据。

响应带附件文件名、`X-Exported-At`、`X-Export-Count`、`X-Request-ID` 和 `Cache-Control: no-store`。
导出审计表示服务端生成并开始交付，不代表客户端保存成功。

## 外部系统只读 API

机器接口使用 `/api/integration/v1/`，仅接受 `Authorization: Bearer oxi_...`，不接受浏览器 cookie；
该令牌也不能访问浏览器管理 API。契约见 [integration-v1.yaml](openapi/integration-v1.yaml)。

不需要额外环境变量：游标签名密钥由 `HOST_CREDENTIAL_KEY` 派生，未配置主密钥时返回 503。
更换主密钥使旧游标失效，但不会吊销 Token。没有启用的集成和有效 Token 就没有外部访问。
`GET/PUT /api/system-integrations/outbound-allow`（全局管理员）读写事件推送的内网放行清单 `{entries,locked}`，
环境变量 `INTEGRATION_WEBHOOK_ALLOW` 配置时 `locked=true`，修改返回 409。
管理员在「系统集成」创建身份、负责人、授权组和 scope，再签发 1–365 天 Token（默认 90 天）。
空组列表不授予任何资源权限。Token 秘密仅显示一次，后端只存摘要；轮换采用签发新令牌后吊销旧令牌。

| 方法 | 路径 | Scope |
|---|---|---|
| GET | `/api/integration/v1/assets?q=&groupId=&limit=&cursor=` | `assets:read` |
| GET | `/api/integration/v1/assets/{id}` | `assets:read` |
| GET | `/api/integration/v1/incidents?status=&createdFrom=&createdTo=&limit=&cursor=` | `incidents:read` |
| GET | `/api/integration/v1/incidents/{id}` | `incidents:read` |

分页默认 100、最大 500，按 ID 排序，响应含 `items,nextCursor,hasMore,observedAt`。
创建时间范围采用含下界、不含上界。游标有效期一小时，绑定身份、Token、过滤条件、组及权限版本；
权限变化后从第一页重新查询。跨页不保证一致快照，不能仅因一次全量读取缺失就自动删除 CMDB 资产。
跨组 incident 只有全部告警资产都在授权组内才可见；无告警或无归属告警不开放。
每个集成在每个节点平均 60 请求/分钟、突发 20，429 带 `Retry-After`；不等于集群全局硬额度。

浏览器管理入口（全局 admin，cookie）：`GET/POST /api/system-integrations`、
`PUT /api/system-integrations/{id}`、`GET/POST /api/system-integrations/{id}/tokens`、
`DELETE /api/system-integrations/{id}/tokens/{tokenId}`。集成更新为完整替换，包含
`name,purpose,ownerId,enabled,scopes,groupIds`；令牌签发包含 `days,scopes`。
删除仍负责启用中集成的用户返回 409，须先转交或停用。

### 事件订阅与工单回写

集成增加 `tickets:write` 和 `incidents:resolve` scope。启用回写还必须在集成管理中设置
`resolutionEnabled=true`、`allowedResolutions`（closed/false_positive/open 的子集）。
恶意判定按误报关闭还需要 `allowMaliciousFalsePositive` 和调用方 `confirmMalicious=true`。

- `PUT /api/integration/v1/incidents/{id}/tickets/{externalId}`：`{url,status,title}`，只修改本集成工单关联，不改变事件状态。
- `POST /api/integration/v1/incidents/{id}/resolution`：`{externalId,expectedRevision,status,note,operator?,confirmMalicious?}`；必须先关联本集成工单，关闭或误报说明不可为空。
- 两个写接口均要求 `Idempotency-Key`；同键同请求复用结果，同键不同请求返回 409。
  幂等窗口 7 天，复用前重新核验当前权限；过期后仍有版本与工单唯一约束保护。
- `GET /api/incidents/{id}/tickets` 为浏览器查看关联工单的接口，权限与事件详情相同。

`suricata:write` scope 供 Suricata 探针写入告警：`POST /api/integration/v1/suricata/events`，集成须恰好授权一个组，
不受上述限流，详见 [suricata.md](suricata.md)。

管理员 cookie API：

| 方法 | 路径，相对 `/api/system-integrations/{id}` | 说明 |
|---|---|---|
| GET / POST | `/subscriptions` | 列表/创建；创建返回一次性 base64 签名秘密及 keyId |
| PUT | `/subscriptions/{subscriptionId}` | 完整更新 name/url/groupIds/kinds/enabled；movePending 默认 false |
| DELETE | `/subscriptions/{subscriptionId}` | 停用并软删除，取消积压，历史记录保留 |
| POST | `/subscriptions/{subscriptionId}/rotate` | 暂停且无活跃在途租约后轮换密钥，仅返回一次秘密；待发消息改用新密钥 |
| POST | `/subscriptions/{subscriptionId}/test` | 排队 integration.test 消息，不生成真实 incident |
| GET | `/deliveries?status=&subscriptionId=&from=&to=&limit=&offset=` | 状态、订阅与 RFC3339 时间筛选；默认 50 条、最大 200，返回 items/total/limit/offset/truncated 及全集成积压 summary；送达不代表工单创建成功 |
| GET | `/deliveries/{deliveryId}/attempts` | 最近 100 次投递尝试，不存远端完整响应 |
| POST | `/deliveries/{deliveryId}/retry` | 重放 dead 投递，保留 eventId，重置 24 小时尝试窗口 |

订阅事件为 incident.created、incident.triaged、incident.evidence_updated、incident.status_changed。
默认建议订阅 triaged，无 AI 部署可订阅 created。暂停期间新事件不补发；旧积压保留。
URL 更改默认保留旧积压目标；movePending=true 显式改投尚未发送和失败记录，在途请求无法撤回。
签名头为 `X-OpenXDR-Event-ID`、`X-OpenXDR-Timestamp`（Unix 秒）、`X-OpenXDR-Key-ID`、
`X-OpenXDR-Signature`。使用 base64 解码后的秘密，对 UTF-8
`timestamp + "." + eventId + "." + rawBody` 计算 HMAC-SHA256，签名为小写十六进制。
接收方须校验时间窗口（建议 5 分钟）、签名并持久去重。事件可能重复及乱序，使用 revision 防止旧状态覆盖新状态。


## 独立欺骗引擎

引擎使用独立运行协议，管理接口仍走 cookie 和组权限。契约类型定义在 `server/deception/contract/engine.go`，实施说明见 [运行包说明](../integrations/dygk/README.md)。

| 方法和路径 | 权限与用途 |
| --- | --- |
| `GET /api/deception/releases` | 登录后读取最近 200 个已登记版本 |
| `GET /api/deception/hosted-release` | 当前托管引擎回报的可用版本，未在线时返回 null |
| `POST /api/deception/releases` | 全局 admin 准入版本，字段 `engine/version/digest/protocol/stateSchema` |
| `POST /api/deception/releases/{id}/disable` | 全局 admin 停用版本，后续运行认证拒绝 |
| `GET /api/decoys/{id}/revisions` | 当前资产组 viewer，最多 100 条并返回 `more` |
| `POST /api/decoys/{id}/revisions` | 组管理员且全局至少 analyst；传 `releaseId/config/expectedRevision`，`config.hosted=true` 由平台统一启动；确认旧实例已停止后创建不可变修订 |
| `POST /api/decoys/{id}/stop` | 同上；只请求停止，202 不代表实例已退出 |
| `GET /api/deception-runtime/v1/deployments/{id}/config` | 单登记 Bearer 令牌，绑定资产当前组和修订 |
| `POST .../handshake` | 实例、修订和精确产物握手并领取 starting 租约 |
| `POST .../lease` | 单实例状态转换，需 `X-Decoy-Instance` 和 `X-Decoy-Revision` |
| `POST .../observations` | 每批 1–100 条白名单事实，按事件 ID 确认持久化；相同 ID 不同内容 409 |

观察字段为 `eventId/streamEpoch/sequence/occurredAt/session/kind/count`；不接受 IP、自由文本、平台身份或原始请求体。新协议每登记滚动 24 小时最多 10000 条；旧接口保持每日 1000 条。旧路径不会接受已启用修订的登记，防止协议降级。

### 研判执行记录

`GET /api/incidents/{id}/triage-runs?page=1`：沿用事件的 viewer/组权限，
每页 20 条，按开始时间倒序返回 `{items, more}`。记录字段为 snake_case：
`started_at/ready_at/finished_at`、`trigger`、`status`、`model`、`error_code`、
`duration_ms/model_ms/tool_ms`、`model_calls/tool_calls/tool_errors`、`tool_details`（顺序数组，工具名、duration_ms、failed，可选 returned/truncated；不含查询原文）、
`input_tokens/output_tokens`。`ready_at` 未知时省略；
`lease_replaced` 表示崩溃后接管，结束时刻为发现中断的时刻，不是真实执行结束时刻。
不返回模型凭据、提示词或原始工具结果。仅有本版本上线后的记录。

运行中记录的 `heartbeat_valid` 按事件当前执行身份与心跳判断；为 false 时界面显示未确认，不能据旧 running 记录断言任务仍在运行。
