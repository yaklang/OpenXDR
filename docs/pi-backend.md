# Pi 会话与命令审批后端

实现位置：`server/internal/piruntime`、`agentchat`、`commandgate`、`api/agentsessions.go`、
`api/commandpolicy.go`。总体设计见 [AI 原生架构](ai-native.md)，JSONL 细节见
[runner 说明](../server/pi-runtime/README.md)。当前实现是 SDK runner，不是 Pi CLI extension。

## 配置

| 环境变量 | 默认值 | 用途 |
|---|---|---|
| `PI_MODEL` | 空（关闭 Pi 对话） | Chat Completions 模型名，独立于旧 triage 的 `AI_MODEL` |
| `AI_BASE_URL` | `http://localhost:11434/v1` | 与旧 triage 共用模型端点 |
| `AI_API_KEY` | 空 | 模型凭据，仅通过子进程 stdin 传递 |
| `PI_RUNNER_PATH` | `/app/pi-runtime/runner.mjs` | 容器内 runner；本地运行改为绝对路径 |
| `PI_TIMEOUT_SECONDS` | `1800` | 一轮对话总超时，含模型、工具和审批等待 |
| `PI_GROUP_DAILY_TOKENS` | `0` | 每组近 24 小时 Pi 会话（对话与预设任务）输入加输出 token 上限，0 不限。到顶时新一轮拒绝发起；正在跑的在下一次模型调用前停下，对话回到可继续状态，任务记失败 |
| `PI_APPROVAL_TIMEOUT_SECONDS` | `600` | AI 和人工 exec 审批等待上限 |
| `PI_QUERY_DATABASE_URLS` | 空 | JSON 对象：组 UUID → 专属只读 DSN；未配置的组不开放 SQL |
| `RESPONSE_ENABLED` | `false` | 现有响应总开关，exec 同样受其控制 |
| `SANDBOX_URL` | 空（本机 runner） | 配置后 Pi 改在 sandboxd 的隔离容器里运行，见下文「沙箱模式」 |
| `SANDBOX_KEY` | 空 | 与 sandboxd 的共享密钥，至少 32 个字符 |
| `SANDBOX_CA_FILE` | 空 | 校验 sandboxd 证书的 CA；空用系统根证书 |

Pi 不注册内置文件和 shell 工具，平台只暴露 exec/track/ignore/identify/egress/memories/remember/forget/suppress/propose_close/report，以及已配置组的 query。suppress 提交抑制草案，组管理员批准后才生效，见 [检测链路 · 抑制](detection.md#抑制serverinternalsuppress)。identify 把对某个监听服务的调查结论写回资产（来源 investigation，不覆盖人工标注），见 [资产图谱与攻击面](asset-map.md#服务说明与调查)；egress 同样写回对某个公网外联的调查结论（只收这台主机确实连过的公网地址）。
没有新增对外工具执行端口，身份、组和来源均由 Go 绑定，模型不能修改；命令一律真执行，没有演练模式。
每轮上下文包含本组最多 200 台资产的 UUID、主机名和 OS；超出会标注截断。
每轮最多「组内主机数 × 20 + 遗留待办数 + 32」次模型调用（32–256），预算写进系统提示让模型留出提交报告的余量，每次输出最多 8192 token。exec 送入模型的 stdout/stderr 各最多 16 KiB，截断标记为 `truncated=true`，Command 记录仍保留原始回执。GLM 显式关闭模板 thinking。未实现费用预算或自动历史压缩。

## 结案建议

AI 不能结案：人工结案会作为案例回喂研判，AI 自己结案再喂回自己就成了自我强化。AI 查证完一个事件后用
`propose_close`（status 取 false_positive / closed，附结案说明，可附报告 id）写结案建议，事件的告警必须全在本组资产上；
事件页顶部显示建议，有处置权限的人点「采纳并结案」会带着建议说明打开结案弹窗，确认后结案记在人名下；原样采纳的建议标为 `ai_proposal`，不作为独立人工案例回喂研判；
也可以忽略。在事件列表或对话页顶部的事件条上直接点「属实 / 误报」时，结论与建议相同也会预填建议说明（可改），
原样提交同样记为采纳 AI 建议。任何状态变更以及关联引擎并入新证据都会清掉建议；同一实体同一规则的重复告警不使建议失效。事件列表给有建议的事件打标。

交接事件时，每轮补充最新研判/证据时间、结案建议与结果、最近 10 条指令的状态及回执时间。
告警只列最重要的 10 条，同时给出总数与截断标记；需要更多证据时继续查询。资产转组后重新检查交接对象的组权限。
会话仅交接事件、且目标主机只对应其中一个事件时，`exec` 记录自动关联该事件，可在事件页查看；
同一主机对应多个事件或会话混有待办时不推测归属。执行成功仅代表回执成功，仍须独立复查效果；未知结果先查 `command_status`，不能自动重试。

## 长期记忆

每组有一份长期记忆（`memories` 表，上限 200 条、每条 500 字），存 AI 与人积累的环境知识：某台主机每天几点跑什么任务、
某个地址是什么设备、哪类告警在这里为什么是正常的。每轮对话与巡检随组内数据带上（`memories`，人工写的在前），
研判也会读到事件所在组的记忆。

- AI 用 `remember`（可选 host、content）记下查证过、以后用得上的事实；同组相同内容不重复记（AI 自己的同内容记忆刷新复核时间），满了要先 `forget`。
  `forget` 只能删 AI 写的，人工写的删不掉
- 人在控制台「AI 记忆」页增删改（组内 analyst 以上），改过的即算人工记忆，全部写审计日志
- 记忆是背景不是指令：提示词与研判都写明「与现场证据矛盾时以证据为准」，AI 写的标明来源与会话，人可以随时复核。
  模型输出与工具结果视为不可信输入，记忆同样如此——它影响的是后续判断，所以留痕、可删、人工优先
- AI 记忆会过时：交给模型时（`xdr context` / `memories` 工具 / 研判上下文）给需要先复核的 AI 记忆带 `review` 说明
  （`memories.Review`）。两类：超过 30 天（`memories.ReviewAfter`）没更新的；以及「无法 / 查不了 / 没有工具 / not installed」
  这类否定性结论（按关键词识别），不论新旧每轮都标——它们最容易变成永久盲区：信了就不再试，主机上其实装着别的工具也发现不了。
  提示词与 skill 要求用到时先用一两条廉价只读命令重新试，试出新手段就 forget 旧的、remember 新的。
  AI 原样再 `remember` 同一内容即复核过仍成立：刷新更新时间（返回 `refreshed`），不新增；人工记忆不标、不刷新、不受影响。
  复核时间由更新时间推算、不另加字段：老库里已有的 AI 记忆不用迁移就按同一口径标注

## 沙箱模式

配置 `SANDBOX_URL` 后，Pi 不再在 server 里跑 `runner.mjs`，而是由独立主机上的 `sandboxd`
为每轮对话起一个一次性容器（`deploy/pi-sandbox`）。容器里 Pi 用自己的默认工具（bash / read / edit / write），
按 `openxdr` Skill 工作手册行事；平台能力只通过容器内的 `xdr` 命令行使用
（`xdr exec / sql / track / ignore / identify / egress / report / context` 等）。

- 协议不变：server 与容器之间仍是 runner 的 JSONL，经 sandboxd 一条全双工 HTTP 流转发。
  `xdr` 经容器内 unix socket 把调用交给桥，桥发 `tool_request` 回平台——组、发起人、
  高风险命令名单与审批、只读查询身份、审计全部照旧在 server 一侧完成。
  模型一次发出的多个调用由 server 并发处理（各自一个 goroutine，回写结果串行），一条在等审批或跑长命令时
  别的照常进行；本轮结束前先取消、再等在途的处理收手。
- 容器不持有任何平台凭据，也不需要访问平台网络；模型端点与凭据随每轮请求传入。
- 容器限制：只读根文件系统、工作目录 tmpfs、去掉全部能力、禁止提权、限内存 / CPU / 进程数，
  专用网桥。出口只放行模型端点、入口只放行 server 节点由宿主防火墙负责（`deploy/pi-sandbox/firewall.sh`）。
  出口其余连接一律拒绝（TCP 回 RST、其余回 ICMP）而不是丢弃，沙箱里访问外网立刻失败、不挂到超时；
  镜像里的 `curl` / `wget` 换成直接报错退出的包装（`no-egress`），说明沙箱没有外网、查 IP 归属用 `xdr sql` 查 `ip_infos`。
  `xdr` 自己用 `/usr/bin/curl` 走 unix socket，不受影响。这只是让失败说得清楚，隔离仍靠防火墙
- 会话历史每轮随请求带入；GLM 开启模板思考并跨轮保留。历史超过 `PI_HISTORY_FOLD_KB`（默认 64）KB 时，
  最近约一半预算的消息（最新一条无论多大）原样保留，更早的工具结果超过 1 KB 的只留开头 400 字与「已折叠，原文多少字节，
  需要细节请重新查询」的说明；助手消息与思考过程不动，消息条数与工具调用配对不变（`agentchat/compact.go`）。
  只影响发给模型的内容，库里与界面仍是原文；2 MiB 的上限按折叠后算。生产最大的 6 个会话折叠后小 43%～86%。
  一轮运行内部 Pi 自己累积的上下文由 Pi 自带压缩处理。
- 默认工具在沙箱里可以随意读写、写脚本处理数据，这是这条路比平台工具 schema 稳定的原因：
  对平台的一切影响仍然只能经过 `xdr`。
- `xdr` 子命令参数不够时只打印该子命令那一行用法并指出缺的参数；`forget` 给的 ID 不是合法 UUID 时，
  能按前缀唯一对上本组 AI 记忆就提示完整 ID（只提示不代删），否则说明格式。镜像里的 `jq` 是薄包装：
  参数带 `->` 且报语法错时在 stderr 补一句「用点路径，不是 SQL 的 `->`」，输出与退出码不变。

sandboxd 配置（环境变量）：

| 环境变量 | 默认值 | 用途 |
|---|---|---|
| `SANDBOXD_ADDR` | `:8090` | 监听地址 |
| `SANDBOXD_KEY` | 必填 | 共享密钥，至少 32 个字符 |
| `SANDBOXD_TLS_CERT` / `SANDBOXD_TLS_KEY` | 空 | 两者同时配置才启用 TLS；生产必须配置 |
| `SANDBOX_IMAGE` | `openxdr-pi-sandbox:latest` | 沙箱镜像 |
| `SANDBOX_NETWORK` | `openxdr-sandbox` | 容器所在 Docker 网络 |
| `SANDBOX_MEMORY` / `SANDBOX_CPUS` / `SANDBOX_PIDS` | `1g` / `1.5` / `256` | 单个容器的资源上限 |
| `SANDBOX_WORK_SIZE` | `512m` | 工作目录 tmpfs 大小 |
| `SANDBOX_MAX_RUNS` | `4` | 同时运行的容器数，满了返回 503 |
| `SANDBOX_MAX_MINUTES` | `60` | 单个容器最长存活时间 |

部署步骤见 [`deploy/pi-sandbox/README.md`](../deploy/pi-sandbox/README.md)。

## 前端接口

所有请求使用现有会话 cookie 与同源保护。请求字段采用下表的 camelCase；直接返回的
Ent 实体字段采用 snake_case（例如 `group_id`、`created_at`）。

| 接口 | 请求 | 权限与响应 |
|---|---|---|
| `POST /api/agent-sessions` | `{groupId,title?,subjects?}` | 组 analyst；创建 idle 会话，返回 201 + 实体。`subjects` 是「交给 AI」绑定的对象，`incident:<id>` 或 `finding:<id>`，最多 10 个且必须都属于该组；绑定后每轮把这些对象的当前状态（事件含研判与最要紧的 10 条告警及证据）放进系统提示，事件仍由人结案，AI 只给结案建议 |
| `GET /api/agent-sessions?groupId=...` | — | 组 viewer；最近 100 个会话 |
| `GET /api/agent-sessions/{id}` | — | 组 viewer；单个会话状态与元数据 |
| `GET /api/agent-sessions/{id}/messages?afterSeq=0` | — | 组 viewer；seq 升序，每页最多 1000 条，下一页传最后一条 seq |
| `POST /api/agent-sessions/{id}/messages` | `{prompt}` | 发起人且仍为组 analyst，会话须为 idle；在后台开跑，返回 202 + `{id}` |
| `POST /api/agent-sessions/{id}/cancel` | — | 发起人或组 admin；写入停止请求，返回 204 |
| `GET /api/agent-reports?groupId=...` | — | 组 viewer；最近 100 个原始 Markdown 报告，每份带 `summary` 与当前用户的 `read` |
| `GET /api/agent-reports/{id}` | — | 组 viewer；报告实体 |
| `POST /api/agent-reports/{id}/read` | — | 组 viewer；标为当前用户已读（重复无害），返回 204 |
| `POST /api/agent-reports/read?groupId=...` | — | 组 viewer；列表里的最近 100 份全部标为当前用户已读 |
| `GET /api/commands/{id}` | — | 资产所属组 viewer；未分组资产仅全局 admin，可查询迟到回执 |
| `GET /api/command-policies?groupId=...` | — | 组 admin；名单 |
| `POST /api/command-policies` | `{groupId,origin,pattern}` | 组 admin；创建名单，返回 201 |
| `DELETE /api/command-policies/{id}` | — | 组 admin；删除，返回 204 |
| `GET /api/approvals?groupId=...` | — | 组 admin；最近 100 个审批（含终态） |
| `POST /api/approvals/{id}/decision` | `{approve:true或false}` | 组 admin；原子决定，返回 204，重复/过期返回 409 |

对话在服务端后台运行，与发起请求的连接无关：前端切页、关闭浏览器都不影响。
前端轮询 `GET /api/agent-sessions/{id}` 看 `status`（running → idle/failed），
用 `afterSeq` 增量拉取消息。停止请求写入 `cancel_requested_at`，运行所在节点每 2 秒检查一次，
命中后取消本轮，未完成的工具调用补写结果消息，会话回到 idle 可继续追问。

`StopReason=length/max_turns` 表示截断/轮数耗尽，不能展示为完整巡检成功。
轮数耗尽（`max_turns`）或调查阶段到点时，服务端先补齐半截的工具调用，
再在同一会话上带全部历史续一次收尾（最多 4 次调用）。调查阶段的「到点」按本会话实测的模型单轮耗时算：
剩余时间少于 `3 × 单轮 + 1 分钟` 就截停调查进入收尾，至少留 3 分钟（运行期限很短时取五分之一），至多留运行期限的一半。
单轮耗时是 assistant 消息相对上一条消息（提问或最后一个工具结果）的间隔，取最近 5 轮里最慢的一轮；
工具执行（等审批、长命令）落在 assistant 与其后的工具结果之间，不计入。3 倍对应收尾要的三轮：写报告、
格式不合格退回重写、交完报告后的最后一轮；1 分钟是起沙箱容器、取历史与入库的开销。前几天单轮 5–17 秒时仍是 3 分钟；
2026-10-21 推理端变慢（平均 98 秒、最长 229 秒）时会提前约 12.5 分钟收尾，原来的 3 分钟连一轮都不够。
截止时已在提交的 `report` 调用不随期限取消，在 15 秒宽限内写完。收尾：
两种会话都只留 `report`：对话会话要求直接用文字总结、不再调用工具，任务会话要求提交报告；未覆盖的检查项标「未验证」。
不能一个工具都不给：历史里有工具调用时 pi-ai 会发空的 `tools` 数组，vLLM 等端点直接 400。收尾消息照常入库。
停止只终止推理与审批等待，已下发的命令不会因此撤销。
同一会话只允许一个 running 请求；失败会话不自动重试，需检查命令记录后另建会话。
进程异常退出导致遗留 running 状态时，不自动恢复或重放主机操作。

## exec 与审批

`exec` 参数：`{host:资产UUID,cmd:完整命令,timeout?:秒}`，timeout 为 1–300，默认 agent 的 60 秒。
执行只允许当前组资产；等待审批后会再次检查成员角色和资产归组。

- 名单一律是高风险名单（mode `deny`），AI 与人工各一份：命令命中本组该来源任一条目就挂起、
  等组 admin 审批，其余直接执行。空名单意味着没有额外审批。创建名单时 mode 固定为 `deny`，
  请求体仍是 `{groupId,origin,pattern}`。
- pattern 为 Go 正则，在整条命令里**非锚定搜索**：`\brm\s` 也命中 `x && rm -rf /`、`/bin/rm -rf`。
  需要只匹配开头或整条时自己写 `^`、`$`。创建时校验能否编译。
  **这不是 shell AST 解析**，变量、别名、编码等写法可以绕开，名单只是拦住常见的高风险操作。
- 新建的组自带一套 AI 高风险名单（`commandgate.DefaultAIDeny`，Linux 与 Windows 各一套）：
  递归/强制删除、格式化与分区、`dd of=`、关机重启、停用服务、结束进程、防火墙改动、账户变更、
  卸载软件包、zfs/zpool destroy|rollback、Proxmox 停机销毁与集群变更、`crontab -r`、
  下载脚本直接交给 shell、重定向或 `tee` 写入 `/etc` `/boot` `/usr` `/bin` `/sbin` `/lib`、
  读取 `/etc/shadow` 与 SSH 私钥，容器重建与拉镜像（`docker compose` / `docker-compose` / `podman compose` 的
  up、down、restart、rm、stop 等，`docker` / `podman` 的 run、create、start、pull、rm、rmi、restart、stop、kill、prune
  及 `container` / `image` 等管理命令写法，重定向或 `tee` 写 compose 文件；套在 `pct exec`、`docker exec`、
  `lxc-attach`、`sh -c` 里同样命中，`docker ps/inspect/logs` 不受影响）；Windows 侧覆盖关机重启、递归删除、格式化磁盘、停止/禁用服务、
  禁用网卡、本地账户与管理员组变更、Defender 设置、结束进程与防火墙改动。只读巡检命令不受影响。
  删组时名单一并清掉。
- **名单不交给模型。** 系统提示只告诉模型：命令直接执行，少数高风险操作会暂停等组管理员批准、
  管理员已收到通知，这不是拒绝，不要改写或拆分命令绕开，先做不依赖它的工作，最后列出待批准的操作。
  等待超时返回给模型的同样是「仍在等待批准（已通知），暂未执行」；管理员明确驳回时才告诉它
  没被批准、不要换写法重复。
- 每条审批创建时经通知配置外发一次（标题「待批准：AI 请求执行高风险命令」或人工对应标题，
  正文含组、主机、发起人和截断到 300 字的命令，链接 `/approvals`）；发送失败只记日志。
- 升级时启动迁移：删掉全部旧版 AI 免审批（ai/allow）条目，只给这次删到条目的组补一份默认高风险名单。
  再次启动没有 allow 条目可删，管理员主动清空的名单不会被补回。
- 默认名单上线后再加的条目按版本补（`defaultsAdded`，版本记在 settings 表 `commandgate.defaults_version`）：
  启动时给还留着 AI 高风险名单的组补上新版本的条目，组里已有同样写法的跳过，AI 名单整个清空的组不补；
  每个版本只补一次，管理员之后删掉新条目不会被补回。管理员改过写法的旧条目同样不动。
- 名单之外照样受组权限与 `RESPONSE_ENABLED` 约束。审批只批准原始资产、命令与超时的组合，
  批准后按原样真执行。
- 审批状态：pending → approved/rejected；approved 只能原子消费一次变为 consumed；
  超时变 expired，客户端取消变 cancelled。过期批准不能消费。
- 每个有效格式的 exec 请求先写审计；名单变更与审批决定均与审计同事务提交。
  命令下发与最终回执沿用现有 Command 表。

旧 `POST /api/commands` 的 `kind=exec` 已接入相同名单与审批，origin 固定 human，
同样真执行；它仍是阻塞 HTTP 请求，另开审批界面批准后才返回。
结束进程与隔离/解除隔离继续走 `RESPONSE_ENABLED` 与 `ISOLATION_ALLOW` 闸门。
等待回执超时意味着执行结果未知，不代表命令没有执行，不自动再次下发。
所有动作在重连时都不自动补发，避免原动作已执行但回执丢失造成重复执行或覆盖较新的处置意图。
跨节点投递确认失败记录为 `unknown`，不能据此断言执行失败（no responders 等能证明没下发的瞬断先在 server 内部有界重试，
见 [集群](cluster.md#选主瞬断)）；无法识别或未指定状态的回执也保持 unknown，
不写完成时间或把缺省退出码当作执行结果。
合法迟到回执仍可将 unknown 更新为终态；回执绑定已验证的 agent 流及其资产，
终态不能被重复回执或较晚的 sent 更新覆盖。此实现不宣称 exactly-once 保证。

## SQL 查询身份

`query` 参数为 `{sql}`；返回 columns、rows、truncated。每次只读事务，5 秒超时、
最多 200 行和 8 KiB 序列化结果（含列名和元数据）。大行在数据库端拦截后才传输，
超限显式截断，不把部分结果当作完整覆盖；零行或首行超限时 columns 可能为空。
SQL 出错时把 PostgreSQL 报错原文（只取 message）返回给模型，便于它自行改正；超时单独报「查询超过 5 秒被取消」并提示收窄范围，
不混成语法错误（本地期限与角色 statement_timeout 同时到点，先到的报错不同，两种都按超时报）。
跨视图 `alerts JOIN events` 会让 events 全表扫描（security_barrier 视图不能把连接条件下推成主键查找），
所以另有 `alert_events` 视图在视图内部按主键回查告警对应的事件，按 incident_id / rule_id 过滤在生产实测为毫秒级。
视图只有 rule_id，规则名由平台在系统提示数据的 `rule_titles` 里给出（本组近 7 天命中过的规则）。

每个组使用**独立登录角色**，只能 SELECT 该组固定过滤条件的视图，读不到其他组视图、业务基表，
也没有特权角色成员身份。视图的组过滤由数据库定义固化，不依赖可被 SQL 修改的 session setting。
平台拒绝 superuser、CREATEROLE、CREATEDB、REPLICATION、BYPASSRLS 或能直接 SELECT
业务基表（包括列级授权）的账号。

**自动开通**（`server/internal/queryrole`）：平台数据库账号有 CREATEROLE（或是超级用户）时，
建组即为该组建 schema `xdr_g_<组 UUID 末 12 位>` 与角色 `<schema>_ro`，随机密码存在组记录上
（不经任何接口返回）；server 启动时给所有组补齐并刷新视图定义，删组时回收 schema 与角色。
开通用事务级 advisory lock 串行化，集群多节点并发安全。HA 部署在 patroni 初始化时已给 openxdr
账号 CREATEROLE；已有集群执行一次 `ALTER ROLE openxdr CREATEROLE`。

**手工开通**：平台账号没有 CREATEROLE 时（启动日志会提示），用 `deploy/pi-query/group-views.sql`
（psql 变量传组 UUID、schema、角色与密码，可重复执行）建视图与角色，再写进
`PI_QUERY_DATABASE_URLS`（JSON：组 UUID → DSN）。手工配置的身份始终优先于自动开通，
**而且不会随版本刷新**：升级后要重跑一遍脚本，否则模型拿到的视图与 skill 文档对不上；能自动开通就不要手工配置。
两种方式建的视图相同，都按组固化过滤：assets（含 agent 版本、失联时间、AI 画像、监听端口、云环境与服务 / 外联调查结论）、
events、alerts、alert_events（告警连同原始事件；两者带可信来源标注 automation_id / automation_watch）、incidents、commands、findings（运维待办）、
suppressions（本组主机上的抑制，不含全局抑制）、trusted_sources（本组登记的可信自动化来源，只读，Pi 没有登记或撤销的工具）、
memories（长期记忆）、asset_links（本组主机发起的连接聚合）、ip_infos（只含本组主机连过的地址与本组告警里出现的地址）、managed_addresses（全平台已纳管主机的地址与是否本组，不含主机名与组名：
别组纳管的主机不再被报成「未纳管」，组隔离只多透露「这个地址已纳管」）、
reports（历史报告，供定时任务与上一轮对比）。incident 与 REST 同口径（全部告警都在本组才可见），
角色只读、5 秒超时、最多 5 个连接。
不得填写平台的 `DATABASE_URL`，也不要让不同组共用可读全部组的账号。

组未开通时完全不注册 query，不回退到平台数据库账号。SQL 不能用于写入报告；报告走
`report({title,summary,markdown,level})`，平台强制绑定当前组和会话。所有报告同一格式（`internal/report/format.go`）：
标题最多 50 字（定时任务的标题由平台固定为任务名，周期报告标题一致、下一轮按标题找得到上一份）；`summary` 是一句话结论，
最多 120 字、不换行，列表、推送与页头都用它；正文去掉模型自写的一级标题，按二级标题
「结论 / 需要人处理 / 证据 / 推断 / 未验证 / 已执行的操作」分节，结论、需要人处理、未验证三节必须有，缺了带骨架退回。
页头（标题、级别、来源、时间、结论）由平台渲染，控制台预览、HTML、PDF 一致。`level` 取 `ok`（没有需要人处理的事项，只存档）、
`attention`（默认，有需要人处理的事项）或 `urgent`（需要立即处理）；定时任务的报告只有 attention 与 urgent 会推送通知，
urgent 的标题加「【紧急】」。报告中心可只看需处理的报告。

## 运维待办

`track({host,key,title,detail?,severity,status})` 按（组、主机、key）登记或复查一条待办，
`status=open` 新登记或确认仍在（之前标过修复的会重开），`status=resolved` 表示复查确认已修复，
`status=withdrawn` 撤回本轮新登记的条目（直接删除，遗留待办不能撤回）。只收需要人处理的问题：
severity 只有 low / medium / high，detail 必填，每轮最多新登记 10 条。
主机必须属于本组；没有对应待办时不能标修复。人工 `ignored` 的待办 track 原样返回忽略原因、不做改动。
每轮会话的系统提示数据带 `open_findings`（遗留）与 `ignored_findings`（忽略及原因，各最多 100 条），
模型据此先复查遗留、不再报忽略项；轮数预算按遗留条数加宽。人在控制台「运维待办」标已处理或忽略，
接口见 `docs/api.md`。删组、主机换组或移出组时，该主机在原组的待办一并删除。

用户在对话里明确要求忽略某条待办时，AI 用 `ignore({host,key,reason})`（沙箱里是 `xdr ignore <主机名> <key> <理由>`）
代为忽略，效果与待办页人工忽略完全一致（同一段 `internal/findings` 逻辑）：状态改为 ignored、原因写进 note、
`resolved_by` 记发起对话的用户，审计 `finding_status` 记在该用户名下，说明里附「AI 会话 <id> 代 <用户> 执行」。
闸门：只认 kind=chat、发起人是人类用户的会话，且每次调用都从库里重新读该用户在会话所属组的角色，必须是组管理员；
定时任务（system 身份）与非组管理员发起的对话一律拒绝，并告诉模型把要忽略的项写进回复或报告由人处理。
skill 里写明只有用户明确要求时才能用，不得自行决定忽略。

## 预设任务

实现：`server/internal/schedule`（加载、同步、调度）、`agentchat/task.go`（任务会话）、
`api/tasks.go`、`api/reportrender.go`。任务定义在仓库 `tasks/*.yml`，与 `rules/` 同构管理：

```yaml
id: daily-host-inspection      # 必填，库中主键
name: 每日主机巡检
name_en: Daily host inspection # 英文界面显示的名字
category: ops                  # ops 运维 / security 安全 / report 报告，任务页按它分类
description: "……"              # 一句话说明（中英各一），任务页显示
description_en: "……"
enabled: false                 # 首次入库时的全局默认开关，缺省为开；之后启停归界面，改 YAML 不覆盖
schedule: "0 2 * * *"          # 五段 cron，支持 @daily 与 CRON_TZ= 前缀
model: ""                      # 空用 PI_MODEL
targets: { group: "*" }        # "*" 每组各跑一次，或写组名
approval_timeout: 10m          # 高风险命令的审批等待，到期不执行
prompt: |
  ……
```

- 未知字段、坏 cron、重复 id 的文件整份跳过并记日志；YAML 删除的任务标记 removed，保留历史。
- **开关分两层**：任务的全局默认（平台 admin 在任务页改），以及按组的开关（该组管理员即可设置，覆盖全局默认，
  可恢复为跟随默认）。仓库自带的预设任务除每日巡检外都是 `enabled: false`，按组按需开启。
- **自带的预设任务**（`tasks/`，时间按北京时间错开，避免同时占满并发）：

  | 分类 | 任务 | 周期 | 数据来源 |
  |---|---|---|---|
  | 运维 | 每日主机巡检（默认开启） | 每天 10:00 | 主机命令 + 平台数据，全量复查待办 |
  | 运维 | 采集健康检查 | 每天 09:30 | 平台数据 |
  | 运维 | 备份验证 | 每天 09:00 | 按记忆登记的备份位置上机核对 |
  | 运维 | 证书到期检查 | 周二 10:00 | 主机命令 |
  | 运维 | 补丁与重启 | 周四 10:00 | 主机命令 |
  | 运维 | 容量趋势预测 | 周五 14:00 | 主机命令 + 上一轮报告 |
  | 运维 | 中间件健康 | 周五 15:00 | 主机命令（只读，不猜口令） |
  | 运维 | AI 记忆整理 | 每月 3 日 10:00 | 平台数据 |
  | 安全 | 安全事件积压清理 | 每天 11:00 | 平台数据，良性的写结案建议 |
  | 安全 | 暴露面周检 | 周一 10:30 | 平台数据 + 上机查明未知服务 |
  | 安全 | 账户与权限审计 | 周二 14:00 | 主机命令 + 上一轮报告 |
  | 安全 | 降噪复盘 | 周三 10:30 | 平台数据，提交带条件的抑制提议 |
  | 安全 | 持久化点基线复核 | 周三 14:00 | 主机命令 + 记忆里的基线 |
  | 安全 | 外联复核 | 周四 14:00 | 平台数据 + 上机核对 |
  | 安全 | 容器审计 | 周五 10:00 | 主机命令 |
  | 安全 | 可疑文件扫描 | 周日 03:30 | 主机命令（低优先级 IO） |
  | 安全 | 安全基线抽查 | 每月 1 日 14:00 | 主机命令 |
  | 安全 | 抑制与情报复核 | 每月 2 日 10:00 | 平台数据 |
  | 报告 | 安全周报 | 周一 09:00 | 平台数据 + 上一份周报 |
  | 报告 | 采集覆盖月报 | 每月 1 日 09:30 | 平台数据 |

  所有任务只用只读命令，问题用 track 登记（按任务约定的 key 前缀，如 `cert:`、`patch:`），抑制与结案只提议不执行；
  专项任务只复查与自己主题相关的遗留待办，每日巡检全量复查。环境差异（备份在哪、哪些是正常行为）靠长期记忆，
  不写死在提示词里。
- 调度器集群单活，每 `SCHEDULE_INTERVAL_SECONDS` 重载 YAML 并检查到期；从上次运行起算下一个触发点，
  停机或停用期间错过的周期只补跑一次。空组不跑；同组上一轮未结束则跳过本轮。
  接管时遗留的 running 记为失败，不重放。到点后按组错峰、受全集群并发上限约束，见下文「错峰与并发上限」。
- 任务会话 `kind=task`、`initiator=system`。**系统身份不是用户**：审批闸门对它不查用户与组内角色，
  但要求会话是本组任务会话，资产作用域、名单（按 AI 来源的高风险名单）、审批与
  `RESPONSE_ENABLED` 照常生效，命令真执行；审批人看到的发起人为 `system`。用户名 `system` 保留，不能创建。
- **定时任务的只读命令自动批准**：任务半夜跑、没人审批，名单误伤的只读巡检命令（grep 模式里的 `kill`、
  `stat /etc/shadow` 看时间戳、`last -x shutdown`）以前只能等到过期，巡检缺项还白耗十分钟。
  现在任务会话里命中名单的命令，若目标是 Linux 主机且通过 `commandgate.ReadOnly` 判定，直接批准执行，
  照常留一条审批记录（状态 consumed、批准人 `system`）并写审计 `approval_auto`。判定按 shell 规则切段，
  每段的程序都要在只读清单里且参数无副作用；命令替换、`sh -c`、`eval`、`xargs`、`find -exec`、awk 的
  `system()`/重定向、写到 `/dev/null` 以外的重定向、清单外的程序一律不认。提到 `/etc/shadow`、SSH 私钥的段只许
  看元数据（ls / stat / test）；密钥路径出现在 for 列表、变量赋值或输入重定向里时，整条命令都只许看元数据。
  会改东西或读密钥内容的命令照旧等人审批；对话会话不走自动批准（有人在场）。
- 截断、收尾出错或会话结束时没有提交报告，一律记为失败；收尾时报告已经交上、只是收尾轮数在最后一句话前用完、
  或运行期限截掉了交报告之后的那一轮的不算失败（报告就是任务的产出，整轮重跑只会白耗半小时）。
- **保底报告**：运行期限到了模型仍没交报告（推理端变慢时常见），平台用会话里已拿到的证据整理一份部分报告入库，
  与正常报告同表同格式（标题仍是任务名，level 固定 `attention`：巡检不完整本身需要人知道），开头注明
  「模型未在时限内完成，以下为平台根据已执行命令与查询结果整理」。内容只有事实：已执行的工具调用（命令、SQL）
  与结果摘要（各截 1500 字节，出错的标出错，没拿到结果的标未取得；沙箱内 `read` 读 skill 不列）、
  等待批准到期未执行的命令、任务说明里编号的检查项（全部标「未验证」）。模型的文字、思考与结论一概不进报告，平台不做判断。
  会话 `status` 记 `succeeded`、`error` 记「模型未在时限内完成，已由平台根据已执行的命令与查询结果生成保底报告」，
  与正常完成（`error` 为空）、失败（`failed`）区分；任务运行记录 `succeeded`，接口 `GET /api/tasks/{id}/runs` 带 `partial: true`，
  控制台标「部分完成」。保底报告照常推送，不发「任务失败」通知，也不重跑。停机或失去租约（取消而非到期）不出保底报告。失败后立即换一个新会话重跑一次
  （同一行运行记录改挂新会话，失败那次的会话与错误留在会话历史里）；超时不重跑。
  停机（发版滚动重启）或失去租约打断的一轮记为 `interrupted`、不发失败通知，接手的 leader 下个调度周期
  用新会话重跑同一轮；只重跑最近一轮且 12 小时以内的，进程崩溃后由执行期限清理的仍按失败处理（结果未知，不重放）。
  重跑仍失败才算这一轮失败。失败与报告都经通知配置外发
  （报告附摘要与 HTML 链接，链接前缀取通知配置里的控制台地址）；推送失败只记日志，不重试。

### 错峰与并发上限

所有任务会话共用同一个模型端点。`targets: { group: "*" }` 的任务以前每组同一分钟开跑，
曾有两个组的每日巡检同时开跑，每轮推理从 5–17 秒涨到平均 98 秒，两轮都超时失败；组越多、
不同任务恰好同一时刻越严重。现在分两道：

- **错峰**（`SCHEDULE_SPREAD_MINUTES`，默认 15，0 关闭）：每个组在计划时间后固定偏移
  `fnv64a(任务 ID, 组 ID) mod 窗口` 秒开跑，窗口 = min(`SCHEDULE_SPREAD_MINUTES`, 这一轮到下一轮间隔的 1/4)。
  偏移只取决于任务与组，同一组每天同一时刻（每日巡检 `0 10 * * *` 某组固定在 10:07:23 之类）；
  周期短的任务窗口跟着缩小（`*/5` 最多 75 秒），不会越过下一次计划时间。不同任务在同一组上也各自错开。
  任务页「下次上班」按当前组的偏移后时间显示（接口 `nextRuns`）。立即运行与停机打断的重跑不错峰。
- **并发上限**（`SCHEDULE_MAX_RUNNING`，默认 1）：全集群同一时刻运行中的定时任务会话不超过上限。
  计数以库里 `kind=task`、`status=running` 的会话为准（再与本节点在跑的数取大，覆盖失败重试换会话的间隙），
  所以 leader 切换后上一任未收尾的会话照样占额度，不会超发；进程被强杀留下的会话要等执行期限清理后才释放额度。
  人发起的对话会话（`kind=chat`）不计入，也不受这个上限约束。
  拉不起的到期项排队，每次检查按「立即运行 > 被打断的重跑 > 定时触发、同类按开跑时刻先后」拉起；
  排队满这一轮的周期（每日任务 24 小时、`*/5` 任务 5 分钟）仍没轮到就跳过，记一条 `skipped` 运行
  （错误「定时任务并发上限已满，排队超过一个周期仍没轮到，跳过本轮」），下一轮从跳过时刻起算，
  排队期间又到期的周期一并跳过，不会补跑成串积压。排队起点只记在 leader 内存里，leader 切换后重新起算。
  被打断的重跑不走跳过，超过 12 小时自然不再重跑。
- **立即运行**（`POST /api/tasks/{id}/run`）是人触发的：不错峰，受并发上限但排在最前，
  不会抢占已经在跑的会话；同样排满一个周期未轮到会跳过。
- 与发版打断的重跑兼容：被打断的那一轮记 `interrupted`，其会话随即收尾为失败、不占额度；接手的 leader
  按上限优先重跑，重跑沿用原运行记录与计划时间，不再加偏移。

默认 1 偏保守：单个端点（尤其自建推理服务）串行时每轮最快，每日巡检十来个组也能在一两个小时内跑完。
端点能并行推理（云端 API、多卡推理服务）再调大。人与定时任务共用端点时，建议上限至少给人留出余量：
端点能稳定并行 N 路，就把 `SCHEDULE_MAX_RUNNING` 设成 N−1 以下，让值班的人随时有一路可用。

| 接口 | 权限 | 说明 |
|---|---|---|
| `GET /api/tasks` | viewer | 任务列表：含 nameEn、description(En)、category、全局默认 `enabled` 与 `groupEnabled`（只含调用者看得到的组）；`nextRuns` 为各看得到且启用的组下一次开跑时间（含错峰偏移），`nextRun` 取其中最早的 |
| `PATCH /api/tasks/{id}` | admin | `{enabled?, customSchedule?}`：全局默认开关与周期；`customSchedule` 传空串恢复 YAML 周期 |
| `PUT /api/tasks/{id}/groups/{groupId}` | 组 admin | `{enabled: true / false / null}`：该组单独开关，null 恢复跟随全局默认；写审计 |
| `POST /api/tasks/{id}/run` | admin | 立即运行：记下请求时间，调度器下一次检查时对每个开启的组各跑一轮；所有组都未开启时返回 409 |
| `GET /api/tasks/{id}/runs` | viewer | 最近 100 次运行，按组裁剪 |
| `GET /api/agent-reports/{id}/html` | 组 viewer | goldmark 渲染，原始 HTML 与危险链接被丢弃，带 CSP；打开即标为已读 |
| `GET /api/agent-reports/{id}/pdf` | 组 viewer | headless Chromium 打印，禁外网；找不到 Chromium 返回 503；下载即标为已读 |

已读按人记（`report_reads`，报告 × 用户唯一）：一个人看过不影响别人。侧栏「报告」的计数是当前组未读、且级别不是 ok 的份数。

## 验证与后续

- `server/pi-runtime`: `npm ci --ignore-scripts && npm test`。
- `server`: `go build ./...`、`go vet ./...`、`go test ./...`。
- 集成测试：`INTEGRATION_DATABASE_URL=测试库 go test -tags integration -p 1 ./...`。
  必须使用可清空的独立测试库。
- 第 5 步可按上述接口制作会话、审批和报告页面。
- 第 6 步见上文「预设任务」。前端对话页（主入口）提供审批与命令名单（组 admin）、
  报告列表（HTML 新标签页 / PDF 下载）与任务页（admin 启停、改周期，运行记录可跳转会话）。
- 本次验证使用 mock 模型与模拟 agent 通道，尚未进行真实模型/受管主机验收。

## 执行容量与异常恢复

每个 server 进程最多同时启动 4 个 Pi 子进程，另容纳 32 个等待请求；
PDF 最多同时渲染 2 份，另容纳 8 个等待请求。队列满时返回失败，取消请求会释放名额。
以上是单节点限制，多节点总容量随节点数增长。定时任务另有全集群并发上限 `SCHEDULE_MAX_RUNNING`
（见「错峰与并发上限」），超出的目标排队等下一次检查，不为排队的组提前建运行记录或启动 goroutine。

会话入库保存固定执行期限 `run_expires_at`：总超时包含排队时间，并额外留 1 分钟清理宽限。
每分钟将超期且仍为 `running` 的会话和关联任务运行标记为失败，不重放任何命令；
其他节点尚未到期的会话不受影响。升级前没有期限的旧记录，等待本节点一个完整运行上限
及清理宽限后再恢复；升级时应使用一致的 `PI_TIMEOUT_SECONDS` 并完成所有节点替换。

报告独立 HTML 自带 CSP，只允许内联样式及 data 图片；HTTP 页面额外启用 sandbox。
PDF 的 Chromium 同时设置阻断代理（包括 loopback）与 DNS 规则，禁止报告里的 IP 或域名外链请求。
任务定义与运行记录均按组可见；没有任何组的普通用户看不到通配组任务定义。

调度按 `(task_id, group_id)` 分别计算到期时间，从任务持久创建时间起算；
运行记录保存 `scheduled_at`，同任务、同组、同触发时刻有数据库唯一约束。
只启动部分组后发生重启，尚未启动的组会补跑一次，不重放已启动组的命令。
Windows 隔离的 WFP 权重设计依据 [Microsoft Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)：
许可和默认阻断置于同一独立子层；不覆盖其他产品或系统策略的阻断。

### 专用只读身份集成验证

`TestQueryDedicatedGroupView` 在配置 INTEGRATION_DATABASE_URL 后默认创建随机隔离登录角色，
仅授予测试视图权限，结束清理角色与授权；测试连接用户须有创建/回收角色权限，仅对隔离测试库运行。
仍可同时提供 PI_TEST_QUERY_DSN 和 PI_TEST_QUERY_ROLE 使用预配置测试身份，缺少其中一个会失败。
覆盖组视图可见性、基表/列级授权拒绝、写语句和包装逃逸拒绝、行数/字节截断及重复列名保留。
这不替代生产角色配置、真实组视图与权限回收验收。
