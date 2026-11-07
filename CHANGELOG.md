# 变更记录

格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。
0.x 期间接口、配置与数据库结构仍可能不兼容变更，升级前请看对应条目。

## [Unreleased]

### 升级须知

- 编排文件不再默认注入 `CONTAINMENT_ENABLED=false` / `CONTAINMENT_SCOPE=lab`，自主响应的开关与范围交给控制台；
  `.env` 里显式写了这两个变量的部署，它们成为锁定值，控制台只读，行为不变。

### 新增

- **控制台开关自主响应**：「自主响应」页由全局 admin 开关、改范围（`lab` / `all`），开启前确认，各节点 5 秒内生效并记审计；
  没开 `RESPONSE_ENABLED` 时说明原因。关闭只停新的处置，已生效的照常对账、到期复核或解除（此前关闭后已生效的处置不再自动到期）。
- **自定义检测规则**：「检测规则 → 自定义规则」可新建、编辑、启停、删除 Sigma 规则，或批量导入 YAML（一个文件可含多条）；
  保存前可在近期事件上检查并回测。规则存库、叠在规则目录之上，本节点立即生效、其他节点一个重载周期内生效；
  须显式写 `id`、不得与内置规则重名、不收时序信号规则。Elastic、Wazuh 等规则请先转换为 Sigma。

- **普通良性事件恢复自动结案**：研判为良性、只建议观察的低危事件不再需要 Pi 结案提案，由独立结案审计直接复核原始事件，
  审计须为每个原始事件引用真实字段作为正面证据、服务端逐条比对后才按误报结案；高危、情报命中、核心资产、人工接管、
  研判后仍在命中的事件不进入。此前 11-05 收紧后普通事件的良性自动结案实际不可达。

- **研判能看到授权上下文**：研判上下文加入涉事主机近 14 天的运维待办、管理员执行决定与设备清单监听端口；
  登录会话符合当前有效登记的可信自动化（含登记晚于告警的）也会注明来源。调查能力版本升到 4，
  卡在「来源与授权待核实」的旧结论按新能力重研判一次。
- 运维待办跟进：管理员决定已落实且复查证实生效的，不再登记成等人工验收，按已恢复流程交独立效果复核。

### 修复

- 规则误报：Shell History Tampering 的 `history -c` 要求是独立命令（celery 队列 `audit_history -c 1` 曾被误报）；
  管道下载执行的下载信号不再计入输出写文件、上传数据、访问本机回环的 curl 与默认写文件的 wget。
- ThreatFox 订阅一直同步失败（「情报源超过 10 万条上限」）：认证导出是半年全量，现只取导出中最近 14 天首次出现的 IOC。

## [0.4.0] - 2026-11-05

从这一版起，OpenXDR 是一个**自治**的平台：从察觉到处置自己走完，确定性的攻击信号秒级遏制，不等研判、不等人；人在事后审阅、一键撤回。
同时把 OpenXDR 自己当成最高等级的资产来保护——能自主动手的安全平台，本身就是攻击者最想拿下的目标。
本版的设计与验收都来自 2026-11 一次真实的内网跳板攻击复盘，见 [跨主机攻击的关联与升级](docs/attack-campaign-design.md)
与 [自主响应与自身防护](docs/autonomous-response-design.md)。

### 本版要点 / Highlights

- **自主响应**：内网横向喷洒、爆破得手、数据库拉起 shell、高级别情报命中，秒级自动遏制——
  隔离攻击容器或实验机、封锁来源、锁定被攻破的账号、结束恶意进程、隔离恶意文件；租约到期由 AI 复核，带熔断与一键撤回。
  *Autonomous containment of lateral spray, brute-force success, database-spawned shells and high-severity intel hits,
  with per-host response tiers assigned by AI, leases reviewed by AI at expiry, a fuse and one-click rollback.*
- **按角色与处置等级下手**：遏制攻击来源、受害方只做外科手术式处置；AI 给每台资产定实验 / 生产 / 核心三档等级。
  *Contain the source, operate surgically on victims; every asset gets a lab / production / core tier.*
- **平台自身防护**：响应指令端到端签名、agent 安装包离线发布签名、审计日志 HMAC 链、控制面配置与节点 agent 自我监控、
  控制面端口收口。*Signed commands, offline-signed agent releases, a sealed audit chain and self-monitoring of the control plane.*
- **跨主机攻击的关联与升级**：按资产 + 容器分桶、受害方横向证据、内网喷洒合成告警、研判明细抽样、通知看门狗。
  *Cross-host campaign correlation and escalation that no longer splits one attack into many "suspicious" incidents.*
- **AI 全自动执行**：AI 发起的高风险命令与抑制草案由 AI 审计员当场评审，不再整夜等人点批准；硬拒绝清单兜底。
  *AI-initiated high-risk commands and suppression drafts are reviewed by an AI auditor instead of waiting for a human.*

### 升级须知

- **开了 `RESPONSE_ENABLED` 必须配 `COMMAND_SIGNING_KEY_FILE`**，否则 server 拒绝启动。一行安装脚本会自动生成 `certs/command-signing.key`；
  自己编排的用 `gencerts` 生成（已有则沿用），多节点必须是同一把。**先升 server 再升 agent**：新 agent 只执行签名指令，
  首次注册时固定公钥，之后不换，私钥要和 CA 一起备份。
- 数据库结构有变化，启动时自动建：新表 `containments`；`assets` 加 `response_tier`、`response_tier_reason`，`zones` 加 `response_tier`，
  `audit_logs` 加 `seq`、`seal`，`lateral_evidence` 加 `src_ip`；另有下文各节提到的列与索引。
- 自主响应默认关闭（`CONTAINMENT_ENABLED=false`）；建议先用 `CONTAINMENT_SCOPE=lab` 只处置涉及实验等级主机的攻击，观察一段时间再放开。
- HA 部署：渲染新增必填 `PATRONI_RESTAPI_PASSWORD`；`guard.sh` 多管 NATS 6222 与 IPv6，重装 `openxdr-guard@` 后重启生效；
  编排新增 `SELFWATCH_PATRONI_URL`。详见「安全：HA 部署模板加固」。
- 已有库的关键词检索索引不在启动时现建，见「存储」；手工开通 Pi 查询身份的重跑 `deploy/pi-query/group-views.sql`。
- 沙箱模式下 sandboxd 的 `SANDBOX_MAX_MINUTES` 要不小于新的 Pi 运行期限，见「AI 全自动执行」。

### 自主响应（见 [自主响应与自身防护](docs/autonomous-response-design.md)）

- 处置引擎（`internal/containment`，单活，每 5 秒一轮）：确定性信号命中后直接遏制，不等研判与人工。
  平台指令、已知自动化引起的告警不处置。

  | 信号 | 处置 |
  |---|---|
  | 内网横向喷洒 `xdr:internal-lateral-spray` | 认出发起攻击的容器就只隔离容器；实验等级的主机认不出容器才隔离整机；受害方封锁实际看到的来源地址 |
  | 爆破得手 `xdr:bruteforce-success` | 封锁登录来源、锁定被攻破的账号（内置账号与核心主机不锁）；来源是纳管主机时按喷洒同样遏制 |
  | 数据库拉起 shell（新规则 `lnx_database_spawns_shell`） | 结束该进程；从 PostgreSQL 后端进程标题取出客户端地址，在数据库主机上封锁 |
  | 情报命中 IP / 域名 / 文件哈希（级别 ≥ 4） | 封锁；本机主动外连时结束进程（入站命中不碰本机服务）；进程自身哈希命中时隔离文件 |

- 处置等级：资产分实验 / 生产 / 核心三档，AI 资产标注时一并给出（重要程度高于 2 却给实验的按生产处理），人工可改且锁定，
  区域可整体指定；运行 OpenXDR server 的资产始终是核心。实验可以隔离整机，生产不隔离，核心只封锁与结束确认恶意的进程，
  两台核心之间不互封。新接口 `PUT /api/assets/{id}/response-tier`，区域增删改带 `responseTier`。
- 容器隔离：agent 新增 `ISOLATE_CONTAINER` / `UNISOLATE_CONTAINER`，进容器自己的网络命名空间丢弃全部流量，宿主机与其他容器不受影响；
  用宿主机网络的容器拒绝执行。
- 租约：封锁与隔离按租约生效，新证据续期；到期配了模型先由 AI 复核（只能解除或续期，出错按续期，最长 7 天），没配模型直接解除。
  结束进程、隔离文件、锁定账号一次性执行，不自动恢复。原地 exec 的进程（`sh -c` 变成目标程序）按 exec 后的身份结束。
- 熔断：一小时内生效的处置超过 `CONTAINMENT_MAX_PER_HOUR`（默认 10）、或一个组同时隔离超过纳管主机的 20% 就只记录不执行。
  每个决定（包括没执行的）都落 `containments` 与审计。
- 控制台新增「自主响应」页面：开关、范围与熔断状态，决策记录与指令结果，人工解除或恢复（解除之前的证据不再触发同一处置），处置策略矩阵。
  新接口 `GET /api/containments`、`GET /api/containments/status`、`POST /api/containments/{id}/lift`。
- 配置：`CONTAINMENT_ENABLED`（默认关）、`CONTAINMENT_SCOPE`（`lab` / `all`）、`CONTAINMENT_TTL_HOURS`、`CONTAINMENT_MAX_PER_HOUR`。
- agent 补全父进程：父进程不在注册表里但还活着时（PostgreSQL、sshd 这类 fork 不 exec 的后端），启动事件现场从 `/proc` 补上名字、路径与命令行，
  按父进程判断的规则才认得出 `COPY ... FROM PROGRAM`。
- 指令归属与健康检查判定收口：server `cmdorigin` 严格按事件携带的 `platform_command.uid` 核对平台指令，不再按命令子串模糊归属无标事件；agent 只对自身直接子进程读取环境区的 `OPENXDR_COMMAND_ID`（子 shell 仅沿 `/proc/<ppid>/status` 父进程链继承已登记指令），容器健康检查严格要求命令行与容器配置的 `HEALTHCHECK` 逐字一致，拿不准的一律照常告警。

### 平台自身防护

- 响应指令端到端签名：每条指令装进绑定目标 agent、一小时有效的 Ed25519 签名信封（`COMMAND_SIGNING_KEY_FILE`）。
  agent 首次注册固定公钥，只执行验签通过的指令；数据库、跨节点 NATS 或单条投递链路被人摸到，都伪造不出 agent 肯执行的指令。
- agent 安装包发布签名：`server/cmd/signrelease` 用离线私钥给安装包签名（`<安装包>.sig`），server 随升级指示下发、自己不持有私钥；
  构建时设 `OPENXDR_RELEASE_PUBKEY` 的 agent 下载前先验签，拿下 server 节点也推不了恶意 agent。开源默认构建不嵌公钥，行为不变。
  见 [主机接入](docs/host-enrollment.md#安装包发布签名)。
- 审计防篡改（`internal/auditchain`）：审计日志事后封存成 HMAC 链，密钥由指令签名私钥派生、不在库里；每 10 分钟全量校验，
  断链出 `xdr:audit-tamper`（5 级）。最新编号导出为 `openxdr_audit_sealed_seq`，HA 告警规则 `OpenXDRAuditChainShrunk` 在它倒退时报警；
  平台 admin 可用 `GET /api/audit/chain` 手动核对。
- 自身监控（`internal/selfwatch`）：Patroni 动态配置（DCS）被改出 `xdr:control-plane-change`（pg_hba、`*_command`、预加载库等 5 级），
  运行 OpenXDR server 的节点 agent 停止上报出 `xdr:core-agent-silent`（4 级）。HA 编排配 `SELFWATCH_PATRONI_URL`。

### 安全：HA 部署模板加固

生产遭遇内网横向（无认证的 Patroni REST 被改写 pg_hba，再借超级用户 `COPY ... FROM PROGRAM`
读走容器环境变量里的口令），模板据此收紧，详见 `deploy/ha/README.md` 的「安全边界」。

- Patroni REST 写接口要求 Basic 认证（`patroni-admin`，新增必填渲染变量 `PATRONI_RESTAPI_PASSWORD`）；
  只读探测接口不变，HAProxy 与 Prometheus 无需改。容器设 `PATRONICTL_CONFIG_FILE`，patronictl 自动带口令。
- pg_hba 移到本地 `postgresql.pg_hba`，DCS 动态配置改不动；仅容器内 unix socket 用 `trust`，
  TCP 只收本机与两个节点（`scram-sha-256`），initdb 留下的 127.0.0.1 / ::1 `trust` 行随之去掉。
  删掉 Patroni 4 已不支持的 `bootstrap.users` 与 `bootstrap.pg_hba`。
- patroni 容器不再收 `OPENXDR_PASSWORD`、`REPLICATION_PASSWORD` 环境变量：初始化读渲染出的
  `runtime/openxdr-db-password`（0400），replicator 由 Patroni 创建；只挂 etcd 所需的三个证书文件。
- 新增 `deploy/ha/guard.sh` 与 `openxdr-guard@.service`：节点 5432 / 8008 / 6222、witness 2379 / 6222 按来源放行，
  IPv4 与 IPv6 各一条（etcd、NATS 监听 `0.0.0.0` 实际是双栈）。NATS 集群路由 6222 拿到口令就能以集群成员身份读写整个事件流，不能只靠口令。
- **升级须知**：渲染需新增 `PATRONI_RESTAPI_PASSWORD`；重新渲染后先跑 `prepare-runtime.sh` 再重建 patroni，
  逐节点进行；已手工装过防火墙的环境按 README 迁移，避免两套链并存。

### AI 全自动执行

- AI 发起的高风险命令不再阻塞等人工审批：命中组名单时由 AI 审计员（`commandreview`，用会话自己的模型）当场评审，
  批准即执行、拒绝附理由，结果记审批（决定人 `ai-reviewer`）与审计 `approval_ai_reviewed`，评审出错按拒绝。
  生产上巡检与对话常因夜里没人点批准、每条命令白等 10 分钟而撞到运行期限。人工发起的命令照旧等组管理员。
- 硬拒绝清单：停止或卸载 OpenXDR agent、关机重启、清空日志命令历史或审计、清空防火墙、格式化或覆写磁盘，
  AI 发起的一律不执行、不送评审（不论是否命中组名单）。
- 运行期限与轮数放宽为兜底上限：`PI_TIMEOUT_SECONDS` 默认 1800 → 14400（4 小时），新增 `PI_MAX_TURNS`（默认 500，最大 1000），
  取代按主机数估算、最多 256 轮的预算；runner 与沙箱桥的轮数上限同步放到 1000。
  **沙箱模式需同步把 sandboxd 的 `SANDBOX_MAX_MINUTES` 调到不小于运行期限**（默认 60 分钟会先掐断长会话），并重建沙箱镜像。
- 用户名 `ai-reviewer` 保留给平台身份，不能注册。
- 抑制草案不再等组管理员审批：Pi 会话的 `suppress` 提议与误报统计的草案一生成就由 AI 审计员（`suppressreview`）评审，
  单活租约 `suppression-review` 每 5 分钟兜底积压与重启。有会话用会话的模型，否则用平台模型，都没配留给人审。
  审计员对范围从严（无条件、高危与凭据/清痕迹/关防护/情报类规则要求精确条件，拿不准就拒绝），收到的回复不合格按拒绝；模型调不通（端点、超时、HTTP 错误）时草案留在待批准、下一轮重试——
  与命令不同，草案多等没有代价，拒绝却会让误报统计冷却 30 天。
  批准与人工批准共用一套落库（生效、有效期从批准时重算），决定人 `ai-reviewer`，理由记审计 `suppression_ai_reviewed`，
  会话提议的结论直接回给模型。生产上 13 条草案等了 1–5 天没人批，目标噪声每天约 3500 条告警并反复送研判。
  仍待批准的组管理员照常可手动审批，生效的照常可撤销。**升级后积压的待批草案会在 leader 拿到租约后逐条评审。**

### 跨主机攻击的关联与升级（P0，见 `docs/attack-campaign-design.md`）

- 时间窗归并按「资产 + 容器」分桶：同一台宿主机上一个容器的噪声撑不住另一个容器的 incident，宿主机自身的告警仍按资产。
  生产上 uos-server 的跳板容器约 280 条告警（多条 4 级）全被并进 11-01 建的、靠巡检噪声续着的老 incident。
- 时间窗只由有意义的告警续期：锚点是级别 ≥ 3 或确知高危例外的告警，以及 incident 的第一条告警；低危重复照常并入、不续期。
- 高危（级别 ≥ 4 或确知高危例外）不被老 incident 吸收：不按粗键复发归并，经血缘、横向、时间窗都不挂到 AI 已判良性的 incident 上。
  精确实体的复发（同一情报 IP 隔几小时再扫）仍并回，良性结论照样适用。
- 受害方证据认横向、允许跨组：告警事件的登录来源 / 入站对端唯一属于另一台纳管主机时，直接并进源主机时间窗内级别最高的未结案、
  非良性 incident，图上记横向边；优先于本机时间窗。多台主机共用的地址（docker 网桥）不认。原有的源主机侧连接记录横向保留为兜底。
  跨组 incident 只对全局 admin 与覆盖全部资产的组可见（REST、Pi 组视图、外部联动订阅同一口径），不因关联扩大可见范围。
- 新合成告警 `xdr:internal-lateral-spray`（级别 5，列入高危例外）：同一台纳管主机的地址 60 分钟内在 ≥ 3 台其他纳管主机上
  出现登录失败或被告警命中的入站，告警落在源主机上、不挂事件，按 60 分钟去重（一轮喷洒一条，后来的受害主机累加计数、刷新 detail），
  detail 列出受害主机地址与次数；平台指令、已知自动化与容器健康检查不计。生产近三天按此回放只在这次攻击上触发一次。
  受害方证据记在新表 `lateral_evidence`（启动时自动建）。
- 回放验收 `validation/campaign/`：2026-11-02 Prowl 跳板事件的脱敏事件序列走真实入库与关联，关联与研判的改动都要过这条用例。

### 跨组视角

- 巡检与会话不再把别组纳管的主机报成「未纳管」：组查询视图新增 `managed_addresses(ip, in_group)`，列出全平台已纳管主机的地址、
  只标是否本组，不给主机名与组名；AI 判断未纳管前先查它。生产上「采集验证测试」组把生产基础设施组的两台 OpenXDR 节点报成了未纳管邻居。
  自动开通的组随 server 启动刷新视图，手工开通的需重跑 `deploy/pi-query/group-views.sql`。
- 资产图谱新增「全部组」开关（仅全局管理员）：所有组的资产画进一张图，跨组的连接连成主机到主机的边；按组看时别组主机仍只露地址。
- 组查询视图 `ip_infos`、`alert_events` 回查原始事件时带上告警时间：每条告警只探一个日分区，原先只按 id 要把几十个日分区挨个探一遍；
  组只读身份关掉 JIT（分区多时估价虚高触发编译，一次就几秒）。生产上 `ip_infos` 原本 29 秒必超 5 秒限制，改后约 0.15 秒。
  自动开通的组随 server 启动生效，手工开通的需重跑 `deploy/pi-query/group-views.sql`。

### 研判

- 研判明细不再取最早的 50 条：先保证每条规则、每台主机、每个容器各一条（级别最高中最新的，按级别优先占名额），
  余下一半给级别最高的、一半给最新的，按时间排序并注明是抽样；失败减半后仍按级别优先覆盖。重研判的新增明细同样先每条规则一条再按级别补。
  明细行带容器名与 uid。生产上 uos-server 的 incident 三天 2389 条告警，后来跳板容器里的高危告警只出现在计数里，
  研判 56 次摘要始终没提攻击。明细的事件改按 `(id, ts)` 查，只碰一个分区。
- 重复告警不再触发重研判：已研判的事件并入普通规则的告警时按（规则, 资产）认新证据，这台主机上这条规则已在事件里，
  再来多少次、命令行怎么变都只并入计数，不再记新证据；新规则、新资产、级别升高照旧，高危例外规则（情报、凭据窃取等）
  仍按实体认、头一回出现仍立即重研判。生产上容器健康检查与开发机命令每几分钟一条、命令行各不相同，按实体认时
  单个事件三天重研判 96 次，全平台三天 305 次普通重研判（约 7900 万输入 token），按新口径估算至多约 84 次。

### 冷归档

- 新增事件冷归档（#8，感谢 @LordCasser）：`cmd/eventarchive` 把过期事件编码成 zstd 冷块存进 `event_archive_chunks`（实测压缩约 15 倍），
  分影子归档 → 逐事件对拍 → 单日切换移出热表 → 按需整日还原；`/api/events` 与调查入口可冷热合流读取，关键词不搜冷块并在 `coverage` 里说明。
  开关 `EVENT_ARCHIVE_READ`、`EVENT_ARCHIVE_DEDUP` 默认关闭；单日切换要求 events 已按天分区，生产启用按 [冷归档](docs/event-archive.md) 第 12 节试点。
- `/api/events` 响应从数组改为对象 `{items, truncated, coverage}`，`coverage.reason` 说明本次没查全的原因（见 [API](docs/api.md)）。
- 事件引用与过期清理之间加同日生命周期锁：入库每批事务开头按 UTC 日升序一次取共享锁，janitor 过期清理逐日取排他锁，
  关闭「清理与告警引用交错留下悬空引用」的窗口；时序求值缺口按 `TEMPORAL_GAP_RETENTION_DAYS`（默认 30）独立清理。

### 采集

- agent 指令通道断开（多半是 server 重启）重连前重报一次注册，分发版本、采集配置或注册身份变了就重新建立会话：
  此前 server 重启后只有指令通道在重连，不会重新注册，换了 `dist/` 里的版本也推不下去（生产上 6 台要逐台重启 agent 才升级）。
- 周期折叠覆盖监控脚本与容器健康检查：父进程是 bash 为命令替换、管道 fork 的子 shell（不 exec，采集端看不到）时，
  现场读 `/proc/<ppid>` 认父进程，只用于折叠键；键里的命令行抹掉 16 位以上十六进制串与 5 位以上数字，docker 健康检查的
  `runc` 不再每次都是新键。生产上这几类（`free`/`awk`/`grep` 监控循环、`runc init`）原来逐条上报，是进程事件的大头。
- agent 默认不再上报平凡退出（`suppressTrivialExit`，默认开）：退出码 0 且存活不到 2 秒的进程只留启动事件，
  非零、未知退出码与长命进程照常上报；内置规则不依赖退出事件。显式 `{"suppressTrivialExit": false}` 可关。
- agent 离线缓存批次改为带格式版本的 gzip 落盘（实测约为原文的 9%），旧格式照常读取。
  **回退到旧版 agent 时，新格式的未补传批次会被当成损坏移入隔离区**，回退前先等缓存补传完。
- sensor 上行 gRPC 可选 gzip（`SENSOR_GRPC_COMPRESSION=gzip`，默认关闭）。

### 容器健康检查

- docker 容器的健康检查（HEALTHCHECK）按已知自动化处理：agent 读容器配置 `config.v2.json` 的 `Healthcheck.Test`，
  容器里命令行与它逐字相同、由容器外拉起的进程及其后代，事件 `container` 带 `healthcheck: true`；server 只认 agent 上报的事件上的标记，
  告警照常入库、单独去重，不进关联与研判、不计入态势统计，凭据窃取、清日志、关防护、破坏、情报命中这些高危例外照常研判。
  生产上 10-30 起每天约 3500 条告警来自 `nc -z`、`/dev/tcp` 这类健康检查，一个 incident 因此重研判 87 次。
- 数据库：`alerts` 新增 `healthcheck` 列（启动时自动建）；组查询视图 `alerts`、`alert_events` 带上这一列，
  手工开通 Pi 查询身份的需重跑 `deploy/pi-query/group-views.sql`。
- **要升级 agent 才生效**：旧 agent 不打标记，server 照常告警。

### 存储

- 关键词检索索引收窄：新索引 `events_search_trgm` 只索引事件里的字段值，去掉 UUID 与 32 位以上的十六进制串（进程 uid、文件哈希），
  生产抽样每行三元组从 253 个降到 79 个；旧的 `events_raw_trgm`（整个 `raw::text`）在生产上有 29 GB。控制台检索与研判工具
  `query_events` 共用同一口径：不再匹配字段名与 JSON 结构，UUID、哈希类关键词回退原文匹配不漏结果，纯数字关键词不再命中 UUID 与哈希内部的片段。
  新库启动即建；**已有库启动时不现建**，按旧索引照常检索，在线建好新索引并重启后切换，步骤见
  [事件表分区](docs/event-partitioning.md#关键词检索索引)。

### 通知看门狗

- 推送目标为空或连续 3 次发送失败、且有需人工处理的事件超过 15 分钟没推送时，控制台常驻红色横幅
  「通知未送达：N 个需人工处理的事件没有推送（原因）」（admin 全局、其他用户在总览），推送 leader 每 10 分钟一条 WARN 日志。
  生产上推送目标被清空后几天没人发现，期间高危事件一条没推。
- 新接口 `GET /api/notify/health`；新指标 `openxdr_notify_configured`、`openxdr_notify_pending_incidents`、
  `openxdr_notify_consecutive_failures`、`openxdr_notify_last_success_timestamp_seconds`，建议的 Grafana 告警见 `docs/deployment.md`。
- 发送结果（最近成功、最近失败与原因、连续失败数）存 `settings` 表 `notify.health`，集群各节点一致；换推送地址时清零连续失败。

### 修复

- 队列监控先检查流副本健康，每轮流与分片查询共用 5 秒时限，避免多个分片依次超时导致副本健康指标长时间不更新。分片查询失败保留上次待办值，不将查询失败记成零积压；新增逐分片成功采样时间指标，并在超时后从下一分片继续轮询，避免后续分片长期饥饿。

- 已知自动化按 id 预加载告警事件，events 分区后要在每个分区上各探一次（生产 41 个分区、几千条告警 3–6 秒，还与分区退役抢锁）：
  改为按 (id, ts) 逐对 LATERAL 查询只碰一个分区（实测 3.8 s → 44 ms），个别时间对不上的再按 id 补查；候选接口改为单独挂路由拿原始连接。
- 入库耗时指标口径：按批入库后 `openxdr_event_processing_seconds` 把等待同批其他事件与提交也算进来，批越大数越大，
  与「单事件处理耗时」和 P95 告警阈值对不上。改回只算这条事件自己的处理；整批（含取锁与提交）另记
  `openxdr_event_batch_seconds` 与 `openxdr_event_batch_size`。
- 分区迁移工具要求执行身份是 events 的属主，每一步都检查：以超级用户执行时新表与函数归错人，镜像触发器以 server 身份写新表被拒，
  生产上入库停了约 5 分钟。超级用户在连接串加 `role=<属主>` 即可。

- 分区表退役过期日分区每轮都失败：`DETACH` 排队等父表排他锁、只等 3 秒，任何一条更长的读都会让它超时，
  生产上与同为 5 分钟周期的已知自动化扫描（按 id 预加载事件要探全部分区，单次 3–6 秒）每轮相撞；排队期间入库写入也被堵最多 3 秒。
  改为 `NOWAIT` 每 100ms 试一次、最多 30 秒，不再排队堵写入。

- 事件关键词检索在大库上超时：规划器把子串关键词的命中率估得过低（生产 6600 万行上把 `dockerd` 估成 5858 行），
  只走 trgm 索引、时间范围当事后过滤，整个保留期的候选行都要重算检索函数，常见词控制台 60 秒 504，研判 `query_events`
  15 秒超时失败，断开后数据库里的查询还在跑。现在按开销可控的三档检索：先逐行过滤最近 1 万行（高频词在这一步凑够），
  再给 trgm 索引 5 秒（罕见词），最后逐行过滤最近 20 万行；总时限 20 秒，超时的那档取消数据库查询，
  没覆盖整个时间窗口时返回已有结果并标为截断（控制台提示收窄条件，研判工具 `truncated`）。

## [0.3.0] - 2026-10-28

### 升级须知

- 数据库结构有变化（`incidents`、`trusted_sources`、`alerts`、`suppressions` 加列，新增 `ssh_logins` 与系统集成的几张表），
  启动时自动建；研判状态语义有变，见「研判」。
- events 新增两个部分索引 `event_process_guid_ts`、`event_conn_tuple_ts`，**已有库不会在启动时补建**：
  大库升级前先按 [事件表分区](docs/event-partitioning.md) 在主库 `CREATE INDEX CONCURRENTLY` 建好并核对 `indisvalid`，
  再滚动发布。不建也能运行，只是日志关联按进程、按连接回溯时可能扫大量历史事件。
- 手工开通 Pi 查询身份的，重跑 `deploy/pi-query/group-views.sql`。
- 已装的 Windows 主机重新执行一次安装命令，计划任务检查间隔才改成每分钟（见「修复」）。

### 研判

- 重研判限流：已研判的事件并入新证据后不再立即重开重判，记为「待重研判」，距上次研判满 `AI_RETRIAGE_COOLDOWN_MINUTES`
  （默认 30 分钟）再一次性带上冷却期内的全部新告警重研判；级别升高或头一回出现的情报命中、凭据窃取等高危类告警（与可信来源的
  高危例外同一口径）不等冷却。生产上 Windows 测试机一个被系统例行变更反复并入的事件 7 小时被重研判 43 次，按新口径重放为 15 次。
- 队列公平：每轮 5 个名额里新事件占多数、按创建先后；重研判保底 1 个，升级类在前、按上次研判先后轮转，不再按创建时间把老事件永远排在队首。
- 研判失败只退避失败的那一个（1、2、4…分钟，封顶 1 小时），同批后面的照常研判；重试时告警明细按失败次数减半。
  此前队首一个超时就中止整批，下一轮又从它开始，其余事件全被饿死。
- 重研判的上下文写明此前研判过几次、上次结论，以及上次之后新增告警的按规则汇总与最新几条明细。
- 通知：普通新证据冷却期间按旧结论照常推送，不卡住；升级类等新结论；研判连续失败 3 次后不再等，不带结论照推。
  良性自动结案跳过待重研判与分析师重开的事件。
- 控制台事件状态旁标「待重研判」「升级待重研判」，详情页显示上次研判时间、次数与研判失败退避；Pi 只读视图 `incidents`
  新增 `triaged_at`、`triage_count`、`retriage` 列（手工开通查询身份的需重跑 `deploy/pi-query/group-views.sql`）。
- 数据库：`incidents` 新增 `triaged_at`、`triage_count`、`evidence_at`、`urgent_at`、`triage_failures`、`triage_retry_at`
  列（启动时自动建）。状态语义变化：关联引擎不再把已研判的事件改回 `open`，`open` 只表示还没有可用结论。
  升级前已研判、之后又并入证据的旧事件没有 `triaged_at`，按待重研判处理。
- 结论校验：verdict、0–100 的 confidence 与非空 summary 缺一不可；JSON 无效、字段不合规或输出被截断时，复用已有调查上下文、
  撤掉工具只做一次格式修正，仍失败按研判失败退避，不计研判次数、不覆盖上一份有效结论、不触发处置钩子。
  此前解析失败的结论会被当成研判完成。
- 正在研判：执行时写 `triage_started_at`，每 15 秒续 `triage_heartbeat_at`，心跳 1 分钟内有效才算在跑；
  事件列表与详情标「正在研判」和本轮开始时间，重研判期间保留上轮结论，排队、冷却与退避不显示为执行中。
  数据库：`incidents` 新增这两列（启动时自动建）。
- 模型适配：DeepSeek flash / pro 与 GLM 一样在后台研判时关闭思考，避免短输出预算被思考耗尽。

### 系统集成

- 资产导出：资产页按筛选或勾选导出 CSV / JSON，落审计。
- 外部系统只读 API：全局管理员在「系统集成」建集成、配负责人、授权组与 scopes，签发 Bearer Token（只存摘要，可到期、吊销）；
  资产、事件只读接口带签名分页游标，契约见 [OpenAPI](docs/openapi/integration-v1.yaml)。
  游标密钥由 `HOST_CREDENTIAL_KEY` 按用途派生，不需要额外环境变量；没有主密钥时集成 API 返回 503。
- 事件订阅推送：事件状态变更经发件箱签名推送到 Webhook，带重试、租约与发送前权限复核；暂停订阅不阻塞其他订阅，停用集成取消积压。
  默认只放行公网 HTTPS，内网目标在控制台「内网推送放行」填精确域名或 CIDR（`INTEGRATION_WEBHOOK_ALLOW` 设置时作为锁定值）；
  环回、链路本地与元数据地址始终拒绝，不跟随重定向、不走代理。
- 外部工单：关联外部工单，受控结案回写（幂等键、`expectedRevision`）；外部结案不计入误报统计与 AI 准确度。
- Suricata EVE 告警接入：`POST /api/integration/v1/suricata/events`，Token 须带 `suricata:write` 且恰好一个授权组；
  只收 `alert`，重传幂等，按地址对去重，按组内资产 IP 归属，东西向两端各出告警并横向关联，未知归属仅全局管理员可见。
  另附一次性导入工具 `cmd/suricata-import`。详见 [Suricata 接入](docs/suricata.md)。
- 数据库：新增 `integrations`、`integration_tokens`、`integration_groups`、`integration_subscriptions`、`integration_events`、
  `integration_deliveries`、`integration_attempts`、`integration_idempotencies`、`external_tickets` 表，`incidents` 新增
  `integration_revision` 列（启动时自动建）。

### 已知自动化（原「可信自动化来源」）

- 自动识别：平台定期从 agent 核对过出处的 SSH 登录里认出运维自动化，满足条件直接生效，不用再手工登记——公钥登录、内网单个固定地址
  （同一把钥匙不同地址分开判断）、近 7 天至少 3 天共 20 次登录、触发过的告警全部已有结论且都是良性（人工误报 1 个，或 AI 良性 3 个；
  高危事件的 AI 良性不作数），回看 30 天没被判可疑以上；公网来源与非公钥登录不自动识别。条目标「自动识别」、带依据，
  默认 30 天有效、持续满足就续期、不再出现就过期；生效与停用都推送通知并以 system 落审计。被判可疑以上时自动停用，固定的与人工登记的条目同样生效（人工条目只看登记之后的结论）。
- 自动停用：它的告警一旦被判属实、恶意或可疑，立即停用并通知，近期被它放过的告警重新送去研判；固定的条目同样停用。
- 用户可调整：改名与说明、改有效期、固定（自动逻辑不再续期或改动）、停用 / 启用、删除；人停用或删除过的不会被自动加回，
  重新启用被系统停用的会自动固定。手动添加照旧。新增 `PATCH` / `DELETE /api/trusted-sources/{id}`，候选接口改为说明每个登录身份为什么（没）被认出来。
- 控制台：「可信自动化」改名「已知自动化」，告警标注随之改为「已知自动化：<名称>」；页面说明改成产品语言，实现原理收进默认折叠的「工作原理」；
  自动与手动条目同一列表，近期 SSH 登录收进折叠区，用来解释为什么没被认出来。
- 新增配置 `AUTOMATION_AUTO_*`（总开关默认开），见部署手册。数据库：`trusted_sources` 新增 `origin`、`pinned`、`evidence`、`notice`、
  `revoke_cause`、`revoke_incident_id`、`confirmed_at`、`deleted_at`、`deleted_by` 列，新增 `ssh_logins` 登录台账表（启动时自动建）。
  生产目前只有约两天的 login_session 数据，按上述条件还没有来源会被识别（唯一的公钥身份只登录了 2 天，且有一个事件未研判）。

- 运维脚本与第三方 AI 运维插件（如 Termix 的 AI 运维）经 SSH 跑的巡检、探测命令不再变成 incident：组管理员在「可信自动化」页
  按 SSH 登录身份（公钥指纹、来源网段、登录用户）登记可信来源，命中的告警照常入库、标注「来自可信自动化：<名称>」，
  但不进关联、研判与推送，也不计入态势统计。只认登录事实，不提供按命令行或进程名放行。
- 凭据窃取、清日志 / 清历史、削弱防御、破坏与情报命中属于高危例外，即使来自可信来源也照常研判——密钥被盗用时不能全盲。
- 与抑制同等治理：按组生效、有效期必填（1–365 天）、可撤销、命中持续计数，登记与撤销落审计；只有组管理员能登记，Pi 没有对应工具。
  页面列出组内近 7 天 agent 核对过出处的 SSH 登录，可直接从中登记。
- agent（Linux）：journald 的 sshd 日志改用 JSON 读取，按内核凭据核对出自 root 身份的 sshd 后解析公钥指纹；
  按内核审计会话号把登录归属（`login_session`）挂到会话里的每个进程上。需要 pam_loginuid；容器内的 sshd 与 Windows 不支持。
- 数据库：新增 `trusted_sources` 表，`alerts` 新增 `automation_id`、`automation_watch` 列（启动时自动建）；
  组只读视图 `alerts` / `alert_events` 带这两列，新增 `trusted_sources` 视图，手工开通查询身份的需重跑 `deploy/pi-query/group-views.sql`。

### 检测

- 新增 Windows 规则「User-Level COM Hijack (HKCU CLSID Server)」（T1546.015）：HKCU CLSID 的 InprocServer32 / LocalServer32
  默认值新建或改写即报，排除 Program Files 下的服务器与 OneDrive、经典 Teams 会议插件的按用户注册（按目录 + 文件名收窄），
  删除与 ThreadingModel 等附属值不报。
- 新增 Windows 规则「Windows Audit Policy Disabled」（T1562.002）：4719 的审计变更含成功移除（%%8448）或失败移除（%%8450）报 high，
  只开启审计不报。两条都在生产 7 天数据上回测，只命中第四轮实机回放的两次测试，无误报（生产只有一台 Windows 测试机）。
- 信号规则：Sigma 规则顶层加 `openxdr_signal: true`（级别必须 informational，放 `rules/signals/`）即只作时序规则的输入，
  命中不单独告警、不进去重 / 关联 / 研判 / 通知，未启用时序检测时不生效；只有被时序规则引用的信号才写候选。
  规则页标「时序信号」，ATT&CK 覆盖不计；detectcheck 新增 `expect: signal`；backtest 单事件模式统计信号命中，
  时序模式报告每条基础规则的候选量与单实体窗口峰值。
- 时序规则新增 `temporal` 类型：窗口内多条基础规则各由不同事件命中、不论先后（同一时刻也算），只在凑齐那一刻出命中。
- 新增时序规则 `temporal:linux-download-pipe-shell`：脚本或交互式 shell 里 `curl … | bash` 的两个兄弟进程（curl / wget 启动、
  不带脚本参数的 shell，两条都是信号规则）5 秒内共现。生产 7 天回测命中 2 次：实机回放与一次平台一行命令安装流量探针。
- 新增时序规则 `temporal:linux-bruteforce-success-recon`：同账号失败 ×5 → 成功登录（信号规则）→ 侦察命令，与原「失败集中 → 侦察」并存
  （成功登录不可见时后者兜底）。生产 7 天无一次失败登录，回测 0 次。三条信号 7 天共写候选 1854 条，单实体窗口峰值 122 条，
  离候选上限很远。按父进程分组评估后仍不做，数据见 [temporal-rules/README.md](temporal-rules/README.md)。
- backtest 时序模式先提交只读事务再喂入回放状态：副本冲突在提交时才报时，整段重试会重复喂入并误报「未按 (时间, ID) 递增」。
- Windows 自身维护不再刷服务与计划任务告警（测试机一夜 140 多条并进一个 incident 反复重研判）：
  - 「Windows Service Installed or Tampered」改名「Windows Service Installed or Execution Target Changed」：新建服务照报，
    修改只报换了执行目标（ImagePath / ServiceDll / FailureCommand）的，启动类型、运行状态的翻转不报（停安全服务仍由
    Security Service Stopped 报）。旧版 agent 的修改事件说不清改了什么，照旧全报，升级 agent 后才降噪。
  - 新增「Built-in Windows Service Hijacked」（high）：改前 ImagePath 在 Windows 目录下的服务，ImagePath 被改到 Windows 目录外
    或改成 PowerShell / cmd / mshta 等解释器、用户可写目录，或 ServiceDll、FailureCommand 被改。
  - 「Scheduled Task File Created or Modified」不再报系统自带任务（`Tasks\Microsoft\Windows\`）的修改，新增
    「Built-in Scheduled Task Modified」（low）接住；新增「Built-in Scheduled Task Hijacked」（high）：自带任务的动作被换成
    Windows / Defender 平台目录外的程序、解释器、用户目录或 URL。新建与删除照旧。
  - 服务规则的 ATT&CK 标注从 T1543.001（macOS Launch Agent）更正为 T1543.003。
  - 生产 7 天回测（OPENXDR-TESTWIN）：计划任务 medium 246 → 39（全是新建），207 条维护修改降为 low；服务规则在现存（旧版 agent）
    事件上仍是 681，按旧值还原出新版 agent 的事件再求值为 7（5 次新建 + Defender 更新挪了 2 个服务的路径）；两条 high 均 0 次。
    回放里的 `sc.exe create`、`schtasks /create`、直接写 `Tasks\atomic` 仍命中。
  - detectcheck 用例可写 `level`：命中规则的最高级别必须正好是它，守住「维护是 low、劫持是 high」。
- Sigma 求值提速：同一事件跨规则复用字段解析与小写结果，求值缓冲按规则快照复用；真实规则集上单事件求值耗时降 30%–60%，
  分配几乎归零（#3，感谢 @chAng-L19）。

### 资产图谱

- 公网地址离线归属：新增本地离线 IP 库（DB-IP Lite，CC BY 4.0），在 `ip_infos` 补全时先查 AS 号、AS 组织名与国家
  （新字段 `ipdb_asn` / `ipdb_org` / `ipdb_country` / `ipdb_at`，启动时自动加列），不向任何外部服务发送地址；
  VirusTotal 有配置时照旧补充，两边字段分开存。私网与保留地址不查。库目录 `IPDB_DIR`，发版镜像自带当月库，
  本地构建为空库降级（启动日志说明）；`openxdr-ipdb` 命令下载更新并校验，替换后自动加载。
  组只读视图 `ip_infos`、AI 研判上下文（新增「公网地址背景」段）与控制台外联明细（AS 号、DB-IP 署名）同步带上。

### 流量探针

- sensor 产品化接入，与 agent 同一套机制：平台管理员在「添加主机」切到「流量探针」签发令牌，
  `curl -fsSL <控制台>/api/enroll/sensor-install.sh | sudo sh -s -- <控制台> <令牌> <网卡>` 一行安装
  （不带网卡只列出本机网卡后退出），本机生成私钥、server 签发 `sensor:<主机名>` 证书、写 systemd 服务。
  令牌分用途（`enroll_tokens.kind`），agent 令牌签不出探针证书，反之亦然；探针令牌只有平台管理员能签。
  gRPC 拦截器按证书用途隔离通道：`sensor:` 证书进不了 agent 通道，`host:` 证书进不了探针通道，探针证书只能以本机主机名上报。
  gencerts 的通用证书照旧两边可用。
- sensor 安装包与 agent 放同一个 `AGENT_DIST_DIR`（官方镜像已内置 `openxdr-sensor-linux-amd64`），新增 `/api/enroll/sensor/{platform}` 下载；
  探针注册时按哈希自动升级：经 gRPC 下载、校验、自检、旧版留 `.prev`、推完在途会话后重启，失败继续跑旧版。`AGENT_AUTO_UPGRADE=false` 同时关闭。
- 抓包状态与 agent 采集状态同口径上报（网卡、后端、抓包线程、内核丢包、上报队列丢弃、包/秒、会话/分钟），
  资产列表来源标 sensor、资产详情新增「流量探针」卡片；抓包降级、不可用与探针失联走「主机采集异常」通知。
  资产新增 `sensor_version`、`sensor_seen`、`sensor_health`、`sensor_problem` 列，启动时自动建。
- 只握手不发请求的 TLS 会话标注 `tls.handshake_only`（探针跟客户端方向 TLS record，跟丢不标）。不单独告警，写进 Pi 技能说明供研判使用。
- 行为变化：sensor 会话的源地址不是纳管资产时归到目的端资产（公网打进反代网关的会话归到网关上），组视图与研判由此可见；
  资产图谱按入站记这类会话。此前这些会话不挂资产。
- 修复：AF_PACKET 内核丢包计数按读取清零的增量当成累计值上报，多 worker 时还互相覆盖。

### 采集

- agent（Windows）：服务快照加上 ServiceDll（`Parameters\ServiceDll`）与 FailureCommand，修改事件带旧值 `reg_value.prev_data`
  与变了的字段 `reg_value.changed`；计划任务快照读任务 XML 的 Exec / ComHandler 动作，事件带 `task.actions`，动作变了的修改带
  `task.prev_actions`。升级后首轮静默建基线，不会把存量服务按新格式报一遍修改。
- 发版新增 arm64 的 Linux agent（静态链接，带 eBPF）与流量探针：`openxdr-agent-linux-arm64`、`openxdr-sensor-linux-arm64`
  随 server 镜像与 Release 附件分发，arm64 主机一行接入不再 404。CI 增加 arm64 的构建、clippy 与测试。
- 采集活性检测：进程（ETW / eBPF / netlink）、网络（ETW / eBPF）、文件（fanotify / inotify / RDCW）三条通道记录最近一次收到原始事件的时刻，
  静默久了先自检（拉起一个立即退出的系统程序、回环自连一次 TCP、改写状态目录下的自检文件），自检也看不到就把能力降为 degraded
  并带原因（进程 5 分钟、网络 10 分钟、文件 30 分钟），事件恢复后自动回到 active。自检事件在 agent 内认出并丢弃，不进库、不触发规则。
  以前 ETW 会话还在、事件全无时健康状态照报 active。降级原因进「主机采集异常」通知与资产页采集状态；新增 Prometheus 指标
  `openxdr_collector_capability_problem_hosts{capability,state,silent}` 与告警规则 `OpenXDRCollectorSilent`。
  **先升级 server 再升级 agent**：旧 server 会拒收带降级原因的采集状态。
- 采集失明后自动重建：活性检测判为降级后，agent 在进程内重建该采集器——Windows 停掉并重建固定名 ETW 会话，
  Linux eBPF 重新载入并挂载对应那组程序（进程、网络各一组，互不牵连），netlink 重新订阅，fanotify / inotify / RDCW 重新挂上监控目标。
  降级 1 分钟后试第一次，再隔 5、15 分钟各一次，之后每小时一次；先停旧实例再起新的，不重复上报，进程注册表与连接采样表跨重建保留
  （退出事件照样复用启动 GUID），文件监控重建不补报已有文件。采集状态新增 `rebuilds`（降级期间已重建几次）与 `recoveries`
  （自动恢复几次），控制台显示，重建次数写进通知文字但不进签名。同样须**先升级 server**：旧 server 会拒收带这两个字段的采集状态。
- Windows 网络采集补齐 TCP 入站（TcpAccept，归属到监听进程）、UDP 出站与 IPv6 的 TCP 出站，能力改报 `network: etw / active`；
  发往 UDP 53 的出站按进程采样，绕过系统解析器自己发 DNS 报文的程序（nslookup 等）不再被 Dnscache 服务的查询压掉。
- Windows DNS 采集：ETW DNS-Client 的查询完成事件（3008）按发起进程归属，归一化成与 Linux 同构的 4003 事件，
  出站连接按本机见过的应答回填域名。看到的是系统解析器 API 层（含缓存命中），没有服务器地址与 TTL。
- Windows 短命进程的连接 / DNS 事件先于它的启动事件到达时，启动事件沿用先到事件占位的进程 GUID，血缘不再断开。
- Windows 持久化快照覆盖所有已加载的用户配置单元：以前 agent 以 SYSTEM 运行，读到的 HKCU 是 SYSTEM 自己的，
  交互用户在自己 HKCU 下写的 Run 键、COM 劫持（CLSID InprocServer32）都看不到。现在枚举 `HKEY_USERS` 下的用户 SID
  逐个读同一组持久化点，事件路径仍写 `HKCU\...`（规则不用改），新增 `user.uid`（SID）与 `user.name`（`DOMAIN\user`）记配置单元属主。
  只覆盖已加载的（已登录用户），不挂载离线用户的 NTUSER.DAT；用户登录/登出导致的配置单元加载卸载不产生增删事件。

- Windows agent 有日志了：以前由 SYSTEM 计划任务拉起，输出全部丢失。现在写到 `C:\ProgramData\OpenXDR\logs\agent.log`
  （每行带 UTC 时间与 pid，10 MB 滚动、共留 5 份，目录继承 OpenXDR 目录只给 SYSTEM 与管理员的权限）；panic 也记进去。
  写入是同步的，升级、身份变化后紧接着退出的最后几行不丢。Linux 不变，仍走 stderr → journald。

### 修复

- Windows agent 自动升级后最长要等 5 分钟才被拉起，期间整机不采集：计划任务的「失败时重新启动」只管任务没拉起来，
  进程以非零码退出（升级后的 75）不触发，实机验证过；重启全靠每 5 分钟一次的检查，检查碰上旧进程还在排空时还会被跳过一轮。
  安装脚本把检查改为每分钟一次（重复触发在已运行时忽略）。**已装的主机重新执行安装命令才生效**，
  或以管理员执行 docs/install.md 常见问题里的一行命令只改检查间隔；agent 不自己改计划任务。
- Windows 同名 ETW 会话的停止口径：实机验证过，旧会话被按名停掉、同名新会话起来后再 drop 旧句柄，停掉的是新会话。
  配置切换时上一轮采集的收尾与新一轮启动并发，可能把新的进程 / 网络 / DNS 会话停掉。现在每个会话名记代次，
  已被同名新会话顶替的旧句柄不再按句柄停。

- Windows 用户登录/登出时，系统按模板增删的每用户服务实例（`CDPUserSvc_xxxxx` 等）被服务快照报成服务新增与删除，
  每次注销都会命中 Autostart Registry Entry or Service Deleted。实例不再进快照（须有同名用户服务模板且 ImagePath 一致），模板照常监控。
- 资产图谱出现 `0.0.0.0` / `::` 节点：agent 在 `udp_sendmsg` 采样时，未连接的 UDP 套接字（tailscaled 之类的 sendto）
  源地址还是未指定地址，原样上报后成了依赖边的一端。agent 改为在同一网络命名空间里按路由查出口地址，查不到就省略源地址、
  `conn_tuple` 源地址留空；server 把缺省或未指定的源地址记到上报资产自己的地址上，不成节点。
  旧库里的未指定源地址依赖边归属不可信（多台资产连同一目的会落在同一行），资产图谱引擎启动时删除，活跃连接随新事件重新长出。
- JetStream 换 leader 时 agent 上报连接被整条断开（`raft: not leader`）、跨节点 exec 被判成 unknown：
  事件发布与指令投递对能证明没被接收的错误（no responders、raft 非 leader、旧连接拒收）在 server 内部有界重试约 5 秒；
  可能已下发的失败仍记 unknown、不重发。依据见 [集群](docs/cluster.md#选主瞬断)。
- 控制台走查修正：只有流量探针的主机在资产详情里最近心跳显示「—」、来源显示「日志」，改为按探针心跳显示、来源标 sensor；
  按规则归并视图在窄屏被撑出页面（规则名被挤成一列一个字），窄屏把级别、主机与事件数收到规则名下面；英文下「事件数」表头与时间折行；
  规则名被截断时悬停只看得到规则 ID，改为显示完整规则名；结案弹窗的长事件标题压在关闭按钮下、「理由选填」说明与字数统计重叠；
  抑制页要横向拖动才看得到批准 / 拒绝，宽屏把操作列钉在右侧（钉住列的表头不再透出底下的文字）。
- 通知回执：飞书、钉钉、企业微信除 HTTP 状态外还检查回执里的业务状态码，非零、缺失或坏回执都算失败，incident 通知不标已投递、
  下周期重试；此前机器人拒收（如关键词不符）也被当成发送成功。generic 仍只看 HTTP 2xx。
- 关联引擎并入新证据时清掉 AI 结案建议，免得按旧证据的建议结案；同实体同规则的重复告警不清。
- 控制台：各列表页表格卡片统一留白与布局；态势总览没有告警时规则排行返回空数组而不是 null，页面不再报错；
  资产详情的统计卡片可用键盘打开，点击后跳到对应标签并聚焦；态势总览「最近任务运行」英文界面显示任务英文名，研判次数英文为 `rounds: N`。

### 关联

- 复发归并：同资产、同规则、同实体（情报 IOC、DNS 域名、网络对端 IP、文件路径、进程映像+命令行；容器入键）的告警
  超出关联时间窗后并回仍未结案的 incident，不再每隔几小时新开一个；跨度上限 `CORRELATE_RECUR_HOURS` 默认 24 小时，
  已结案的不重开。已研判的 incident 收到同实体复发不重开重判；级别升高时重开并清推送标记，重新研判后按新结论再决定推送。
- 进程类复发归并加一档粗键（`CORRELATE_RECUR_COARSE`，默认开）：同用户、同父进程映像、同映像的告警命令行不同也并回未结案 incident；
  解释器与命令包装器（sh/bash/python/powershell/cmd/timeout/sudo 等）仍只按完整命令行，不把不同行为并到一起；
  首次出现（`xdr:new-process`）按主机+用户+父进程并。粗键并入的告警照常重开重判，同级不重新推送。
  进程实体的精确键同时带上执行用户与父进程映像，映像路径按 merged-usr 归一（`/bin/bash` 与 `/usr/bin/bash` 视为同一程序）。
  研判上下文新增按规则的告警汇总，并进来多少条同类告警一眼可见。

### 降噪

- 误报统计回喂规则层：同一规则在同一主机上被人反复判误报（默认近 30 天 ≥5 次、误报率 ≥90%、期间没有判属实）时，
  后台单活任务生成抑制草案，挂进组管理员审批，批准前不生效。按域名 / 对端 / 文件 / 注册表 / 进程等实体收窄，
  实体分散时才给整条规则并明确标注（shell / 解释器等通用映像不算实体）；高危及以上的规则不出草案；
  原样采纳 AI 结案建议与系统自动结案的误报不计入。已有同范围抑制或待批草案不重复，
  被拒后 30 天内不再提。抑制页标出「来源：误报统计」并列出依据。参数 `FP_SUPPRESS_*`，见部署文档。
  数据库：`suppressions` 新增 `evidence` 列（启动时自动建）。

### 存储

- events 按 UTC 日分区：新库直接建分区表，保留期改为整分区退役（被引用的证据并入月归档分区）；指向 events 的外键改由触发器维护。
  老库照旧运行，用 `cmd/eventpartition` 在线迁移（镜像触发器同步、分批回填可续跑、逐日核对、短锁切换、可回滚），步骤见 [事件表分区](docs/event-partitioning.md)。
- events 新增部分索引 `event_process_guid_ts`、`event_conn_tuple_ts`，日志关联按进程、父进程与连接取最早事件时走索引，
  不再按时间扫整个历史库。新库与新分区自动带上，已有库需手工在线建，见「升级须知」。

### AI 会话

- 新增 `xdr ignore <主机名> <key> <理由>`：用户在对话里明确要求时由 AI 代为忽略待办，与待办页人工忽略共用同一段逻辑与审计，
  记在发起人名下并注明会话。只在组管理员发起的对话里可用（每次调用从库里重新判权），定时任务与非组管理员的对话一律拒绝。
- 对话页顶部事件条点「属实 / 误报」时与事件列表同口径：预填结论相同的 AI 结案建议，原样提交记为采纳。
- 定时任务的收尾时机按本会话实测的模型单轮耗时算：剩余时间少于「3 × 最近 5 轮里最慢的一轮 + 1 分钟」就截停调查、
  要模型交报告（至少 3 分钟，至多运行期限的一半；等审批、长命令等工具耗时不计入）。原来固定提前 3 分钟，推理端变慢到
  单轮一两分钟时来不及交报告，整轮失败、证据全部作废。
- 运行期限到了模型仍没交报告时，平台整理一份保底报告（level `attention`）：只列已执行的命令、查询与结果摘要、等待批准未执行的命令，
  任务要求的检查项全部标「未验证」，不含模型结论。会话记为完成并在 `error` 注明是保底报告，运行记录接口带 `partial`，
  控制台标「部分完成」；照常推送，不再发「任务失败」。交了报告后期限只截掉最后一轮的，不再算失败；截止时正在提交的报告允许写完。
- 修复：沙箱模式下运行期限到了 Pi 不返回（HTTP/2 取消请求打断不了正在读的响应体），要等沙箱下一行输出，
  会话终态写不进去、只能等执行期限清理成「结果未知」；现在到期立即返回。
- `xdr` 参数不够时只打印该子命令的用法并指出缺的参数；`forget` 的 ID 不完整时按前缀提示完整 ID；
  沙箱里的 jq 遇到 SQL 写法 `->` 报语法错时补一句提示。
- 事件交接：每轮补充最新研判 / 证据时间、结案建议与结果、最近 10 条指令的状态与回执时间；告警只列最重要的 10 条并给出总数与截断标记；
  资产转组后重新检查交接对象的组权限。会话只交接事件、且目标主机只对应其中一个事件时，`exec` 记录自动挂到该事件上。

### 定时任务

- 按组错峰：`targets: { group: "*" }` 的任务不再每组同一分钟开跑，每组在计划时间后固定偏移 hash(任务, 组) 秒，
  窗口 `SCHEDULE_SPREAD_MINUTES`（默认 15，0 关闭）且不超过任务周期的 1/4；同一组每天同一时刻。
  任务页「下次上班」按当前组的偏移后时间显示，`GET /api/tasks` 新增 `nextRuns`（组 → 时间）。
- 全集群并发上限 `SCHEDULE_MAX_RUNNING`（默认 1）：以库里运行中的任务会话计数，leader 切换后不超发；人发起的对话不计入。
  超出的排队，按立即运行 > 被打断的重跑 > 定时触发拉起；排满一个周期仍没轮到就跳过，运行记录记 `skipped`。
  起因：两个组的每日巡检同时开跑，共用端点的每轮推理从 5–17 秒涨到平均 98 秒，两轮都超时失败。
  原先单节点最多并行 4 个组任务的限制由此取代；端点能并行推理的部署按需调大。
- 立即运行不错峰、受上限但排最前。

### 运维

- HA 节点外备份与隔离恢复验收：`deploy/ha/backup.py` 从主库导出一致性逻辑快照，`verify-backup.py` 在无网络临时容器里完整恢复并核对
  行数、事件时间范围与无效索引，结束后清理；步骤、容量处理顺序与 83.7 GiB 生产库的实测见 [备份与恢复](deploy/ha/backup-recovery.md)。
- Windows 处置后状态复核：`deploy/pilot/verify-response.py` 对已成功的处置指令经平台正常 exec 权限链发起只读探测，
  输出当前状态与是否符合预期，不重放处置、不自动下结论，见 [处置复核](deploy/pilot/response-verification.md)。

## [0.2.1] - 2026-10-20

### 修复

- Windows 进程采集会静默停止：ETW 会话随机命名，agent 被强杀或升级退出时会话泄漏，Kernel-Process 可挂的会话数用尽后
  收不到任何进程事件，健康状态仍显示正常。会话改用固定名并在启动前停掉同名旧会话。
  **升级后请重启一次 Windows 主机**（或 `logman stop n4r1b-trace-<…> -ets`）清掉旧版本漏下的会话。
- 发版：多架构镜像的编译阶段改在构建机本架构上交叉编译。0.1.0 与 0.2.0 的发版流程都卡在 QEMU 里编 arm64 没有跑完，
  本版是第一个带 GitHub Release 与 GHCR 镜像的版本，0.2.0 的变更一并包含。

## [0.2.0] - 2026-10-20

### 身份关联

- 全局身份图：账号登记、目录账号作锚点、Windows SID 强证据链接、Linux 登录关联当时的设备清单，后台单活增量更新。
- 控制台身份页：身份列表（默认不列系统账号）与详情、合并候选的确认 / 拒绝 / 撤销（落审计）；资产页本地账号显示近期登录并可跳到身份。
- 目录来源新增 Authentik（只读 API 令牌读用户列表），与 Keycloak / Entra / AD / LDAP 同一套 `IDENTITY_SOURCES_JSON` 配置。
  compose 透传 `AUTHENTIK_TOKEN`；用别的变量名时需自行在 compose 里加一行。
- Pi 组只读视图加身份、账号、链接与登录关联。

### 时序检测

- 时序规则库从 3 条扩到 20 条（新规则先在生产 7 天数据上回测，Linux 侦察集中命中全是运维自动化，未收录）：爆破后侦察、Windows 侦察集中、下载执行后建持久化、凭据读取后打包 / 外传 / 可疑外联、
  防御削弱后可疑执行，以及 Windows 对应链路；每条在 `temporal-rules/README.md` 写明窗口、阈值理由与已知误报。
- 新增基础规则：SSH 私钥读取（只认读取 / 拷贝 / 编码工具与按私钥名搜索）。
- `group_by: account` 按同组规范化用户名跨主机累计；`event_count` 支持 `min_assets`。
- 时序规则按不可变版本目录发布（`SHA256SUMS` 校验、`current` 链接原子切换），告警可查看命中时的规则原文。
- `cmd/backtest` 支持时序规则：按事件时间在内存回放。

### 降噪与复核

- 事件页「按规则归并」视图：按最高级别告警的规则 + 主机分组，显示组内数量与研判分布，可整组结案。
- 批量结案接口 `POST /api/incidents/batch-status`：一个事务全部成功或全部不动；含 AI 判恶意的事件按误报关需二次确认；逐条审计，人工结论照常回喂研判。

### AI 巡检

- 定时任务里只读命令自动批准；只读判定覆盖 RAID / SMART 查看、`pct exec` / `docker exec` 容器内只读命令、`visudo -c`、`vtysh show` 等巡检常用写法。
- 报告格式统一（一句话结论、固定分节、平台渲染页头），按人记已读。
- 停机时等定时任务收尾，被发版打断的巡检记为 interrupted 并由接手节点重跑。
- AI 工具报错带上可直接改对的信息。

### 资产

- 设备清单上报系统显示名（Linux `PRETTY_NAME`、Windows 注册表）与监听进程所属软件包。

### 平台与运维

- HA 发布脚本带上时序规则版本目录；事件流副本健康度进指标并加告警，NATS 显式通告路由地址。
- 采集端加固：Windows 读命令行按本地缓冲长度读、inotify 事件头非对齐读取、AF_XDP 环计数器 acquire/release、打开失败不泄漏映射与 fd。
- 前端走查修正：情报命中可读标题、事件操作列不再被裁、报告页适配窄屏。

## [0.1.0] - 2026-10-19

第一个公开版本。

### 安装与发布

- 一行安装：`install.sh` 生成口令与密钥、签发 mTLS 证书、配好 HTTPS（公网域名自动申请 Let's Encrypt，内网地址用自建 CA），装好即可在控制台添加主机；重复执行即升级。
- 发版自动化：推 `v*` 标签即构建 GHCR 镜像（amd64 / arm64）与 GitHub Release。server 镜像内置默认规则、预设任务与 agent 安装包，升级镜像在线 agent 跟着升级。
- Linux agent 安装包静态链接（musl）并带 eBPF，CentOS 7 这类老发行版也能直接运行。
- [安装文档](docs/install.md) 同时写给 AI agent，README 给出一句可直接交给 Claude Code / Codex 等代为安装的提示词。
- 发版前依赖安全清零：server 升到 Go 1.26 并升级 x/net、x/crypto、x/text、grpc（govulncheck 无可达漏洞）；agent / sensor 升级 rustls 0.23.46、h2 0.4.20（cargo audit 无告警）；前端与主页 npm audit 无告警。

### 定时任务

- 预设 19 个运维与安全定时任务（采集健康、备份验证、证书到期、补丁与重启、容量趋势、中间件健康、事件积压、暴露面、账户审计、
  降噪复盘、持久化基线、外联复核、容器审计、可疑文件、安全基线、抑制与情报复核、记忆整理、安全周报、采集覆盖月报），默认关闭。
- 任务按组开关：组管理员即可为本组开启，覆盖全局默认；任务页按运维 / 安全 / 报告分类、只看已启用。
- 报告分级：ok 只存档不推送，attention 推送，urgent 标题加「【紧急】」；报告中心可只看需处理的。
- AI 只读查询新增待办、抑制、记忆、依赖边、外联地址信息与历史报告视图，资产视图补上画像与监听端口，均按组隔离。

### 接入与纳管

- 控制台按组签发接入令牌，Linux / Windows 一行命令安装 agent，本机生成私钥、server 签发主机绑定证书。
- agent 经已认证的 gRPC 通道自动升级，校验哈希与自检后替换，保留上一版。
- 运维文档导入（YAML / JSON / Markdown 代码块与表格），凭据 AES-256-GCM 加密、按组授权 SSH 纳管。
- 按主机下发采集配置，坏配置退回内置默认。

### 采集

- agent：进程启停（eBPF → netlink → ETW → 轮询自动降级）、敏感文件（fanotify / inotify / ReadDirectoryChangesW）、
  持久化点快照、登录与安全日志、网络出站、内核模块加载。
- agent 细粒度采集（Linux）：TCP 入站（归属到监听服务进程）与 UDP 出站；本机与容器的 DNS 问答（AF_PACKET，按源端口归属进程），
  出站连接回填解析过的域名；进程与连接带所属容器（docker / LXC / QEMU 等）；退出事件带退出码与运行时长；
  长名字进程不再被截成 15 字节；注册表随进程退出删除，长驻服务的连接不再挂不回进程树。
- sensor：AF_PACKET v3 / AF_XDP 双后端，DNS、TLS（SNI / JA3 / JA3S / 证书）、HTTP 元数据。
- syslog 接入（UDP + TCP，RFC3164 / RFC5424）；入库前脱敏。

### 检测与降噪

- Sigma 兼容规则引擎，热重载，ATT&CK 覆盖矩阵；`validation/` 语料与 `detectcheck` 在 CI 守住检测能力。
- 威胁情报碰撞（IP / 域名 / 哈希），内置 abuse.ch 等公开订阅。
- 持久去重、可撤销且有有效期的误报抑制、按实体关联成事件图、UEBA 首次出现检测、爆破得手升级。
- AI 研判：带只读调查工具主动查证后定性。
- 事件结案与结案说明；需人工复核的口径（未判良性或高危及以上）；低危良性事件到期自动结案。

### AI 助手与巡检

- AI 助手对话：在组内主机执行命令、按组只读视图查库、登记运维待办、提交报告。
- 命令高风险名单：命中即阻塞等组管理员批准并通知，其余直接执行；人工与 AI 分别配置。
- 事件与待办可多选「交给 AI」，对象当前状态随每轮注入上下文。
- AI 结案建议：AI 用 propose_close 给事件写结案建议（定性、说明、报告），事件页一键采纳（结案记在人名下）或忽略。
- 抑制支持字段条件（具体域名、命令行特征、对端地址等，最多 3 条 AND），事件页标误报时默认只抑制告警里的那个值；
  AI 的抑制提议必须带条件，且要对得上真实命中过的事件。
- AI 提议抑制、人批准：AI 对查证过的反复误报提交抑制草案（单台主机、真实命中过的规则、理由必填、最长 90 天），
  主机所在组的管理员在抑制页批准或拒绝，批准后立即生效；被拒过的 30 天内不再接受。
- AI 长期记忆：AI 用 remember / forget 维护组内环境知识（上限 200 条），每轮对话、巡检与研判都会带上；
  人在「AI 记忆」页增删改，人工写的优先、AI 删不掉，改动写审计。
- 检测规则扩充到 181 条：引入 SigmaHQ 社区 Linux / DNS 规则 131 条（按生产回测剔除 12 条高频低价值与误报），
  自研容器逃逸、docker.sock 滥用、特权容器、PVE hookscript / QEMU 参数注入、PVE 账户与权限变更、虚拟机销毁、
  DNS 长随机子域、公网连入管理端口等规则；引擎支持 cidr / windash 修饰符与正则标志，补齐父进程、用户、连接方向字段对齐；
  新增 `cmd/backtest` 规则回测工具；规则作者随告警、事件、报告与通知展示。
- 平台指令触发的告警单独处理：agent 给指令拉起的进程树打标，server 核对指令后把告警挂在指令上，不组成事件、不进研判与态势统计，
  AI 统计威胁时排除自己的命令；指令拉起的进程不进 UEBA 基线。
- 沙箱模式：Pi 在独立主机的一次性容器里用默认工具与 Skill 工作，平台能力只经 `xdr` 命令行，判权、审批与审计仍在平台。
- 对话在服务端后台运行，切页不打断，可随时停止。
- 预设任务按 cron 定时巡检，报告 HTML / PDF 渲染。

### 资产图谱与攻击面

- agent 上报设备清单：监听端口与属主进程、云环境（AWS / Azure / GCP / 阿里云 / 腾讯云元数据）。
- 网络事件聚合成资产依赖图，未纳管地址与互联网一并画出；按区域分泳道展示。
- AI 标注资产角色、功能说明与重要程度：入库、事实变化、定时与人工触发；人工修改即锁定。
- 区域：组内网段定义 + 手工指派 + 云元数据 + 按 IP 自动划分；攻击面按暴露级别 × 端口风险 × 重要程度排序，
  列出公网访问证据与未纳管盲区；攻击面以图展示访问路径。
- 端口表认不出的服务由 AI 凭进程识别命名，可一键交给 AI 上机调查并写回结论，人工标注优先级最高。

### 响应与通知

- 结束进程（校验进程 GUID 与创建时间）、隔离与解除隔离主机（Linux nftables / Windows WFP）。
- 全局开关与隔离放行清单两道闸门；自动响应需单独开启。
- Webhook 通知（generic / 钉钉 / 飞书 / 企业微信），主机失联与恢复通知。

### 平台

- 三档全局角色 + 组内角色，会话 cookie 认证，登录与处置审计；cookie 按外部协议加 Secure。
- 控制台下发 CSP、X-Frame-Options、Referrer-Policy 等安全头，对外 HTTPS 发 HSTS；exec 只能经命令门判权、名单与审批下发。
- mTLS 与按主机绑定证书；NATS JetStream 按资产分片队列，多节点 server。
- 跨宿主机高可用部署（Patroni + 三节点 JetStream + Keepalived VIP）与滚动发布脚本。
- Web 控制台：中英双语，AI 助手为主入口，命令面板。

[0.4.0]: https://github.com/yaklang/OpenXDR/releases/tag/v0.4.0
[0.3.0]: https://github.com/yaklang/OpenXDR/releases/tag/v0.3.0
[0.2.1]: https://github.com/yaklang/OpenXDR/releases/tag/v0.2.1
[0.2.0]: https://github.com/yaklang/OpenXDR/releases/tag/v0.2.0
[0.1.0]: https://github.com/yaklang/OpenXDR/releases/tag/v0.1.0
