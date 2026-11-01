# 检测与降噪链路

本文是 server 检测管线的完整参考，逐包对照代码核实并标注源码位置。
事件字段 schema 见 [events.md](events.md)，采集行为见
[collection.md](collection.md)。

## 处理链总览

三条接入路径先生成统一版本化信封；启用 JetStream 时持久入队，单机直连时直接
调用同一个 `ingest.Processor`：

```
稳定 event_id + partition_key（按资产分片）
  → JetStream durable consumer（处理成功才 ACK）
  → 事件主键幂等落库
  → ① sigma 规则求值 + 情报碰撞（合并成同一命中序列）
  → ② 抑制检查（被压掉的命中不占去重槽位）
  → ③ 去重（窗口内同指纹只留一行，count 累加）
  → ④ 告警落库
```

之后是集群单活的**异步**后台循环；PostgreSQL advisory lease 保证同名任务
只有一个节点执行，leader 失联后其他节点接管：

```
correlate：未归属告警 → incident（10s 一批）
triage：   新 incident / 待重研判 → LLM 研判 → verdict（30s 一批，需 AI_MODEL；节奏见「研判节奏」）
notify：   研判后事件 → webhook（30s 一批，benign 不推，高危 benign 照推待复核）
ueba：     扫进程事件维护基线，首次出现合成 low 告警进同一管线（30s 一批）
beacon：   增量读出站连接，新出现的规律公网外联合成 medium 告警（300s 一批）
janitor：  过期事件/会话清理（60min 一批，告警引用的证据不删）
```

另有两个**合成告警**源在 ingest 侧直接进管线（都走去重、可被抑制）：

- `xdr:bruteforce-success`（critical）：爆破得手升级，见下文
- `xdr:new-process`（low）：UEBA 首次出现，见下文
- `xdr:beacon`（medium）：新出现的外联心跳，见下文

sensor 与 syslog 路径结构相同，仅去重指纹与资产归属不同
（sensor 按源 IP 归属资产，`sensor.go:67-98`；syslog 按主机名→源 IP 两级，
`syslog/server.go:221-243`）。

## Sigma 规则引擎（`server/internal/sigma`）

**设计原则：拿不准就拒绝加载，绝不降级匹配。** 用了未实现修饰符的规则如果
被当成普通字符串匹配，`condition: not selection` 这类规则会对每个事件误报
（`engine.go:699-701`）。

### 能力边界

| 维度 | 支持 | 不支持（拒绝加载） |
|---|---|---|
| 修饰符 | `contains / startswith / endswith / re / all / cidr / windash`，正则标志 `i / m / s` | `base64`、`base64offset`、`fieldref` 等其余一切 |
| 条件 | `not/and/or`、括号、优先级 not>and>or；`1/all/any of them/pattern*`（`condition.go:9,176-217`） | 统计型条件 `count/min/max/avg/sum/near`（`engine.go:537-539`） |
| product | `windows / linux / macos`（`engine.go:153-155`） | 其余 product；既无 category 又无 product 的规则（`engine.go:595-606`） |
| category | 见下方映射表 | 未知 category（报"数据源未覆盖"，`engine.go:588-592`） |

修饰符语义：`re` 强制 `(?i)`（`m`、`s` 标志照常生效）；无通配符走 strings 精确/包含/前后缀（小写
比较）；有 `*?` 通配符 QuoteMeta 后转正则；值列表默认 OR，`|all` 转 AND；
值为 `null` 表示字段必须缺失；`cidr` 按网段匹配地址（含 v4 映射的 v6）；`windash` 把参数前缀的 `-`
展开成 `-`、`/` 与几种长破折号写法。

字段对齐：除了字段名映射（`fieldMap`），取值约定也要对上——`Initiated: true/false` 翻译成事件里的
`outbound/inbound`；`User` 取 `actor.user.name`，求值前由信封上的用户名补进去（入库的原始事件不改）；
父进程字段（`ParentImage`、`ParentCommandLine`）由 agent 在进程启动事件里直接带上。

### category → class_uid 映射（`engine.go:78-111`）

| Sigma category | class_uid | 现有采集来源 |
|---|---|---|
| process_creation / process_access / process_tampering / create_remote_thread | 1007 | ✅ agent |
| file_event / file_change / file_delete / file_access / file_rename / create_stream_hash | 1001 | ✅ agent（Linux fanotify/inotify + Windows RDCW/Startup/计划任务快照） |
| registry_set / registry_add / registry_event / registry_delete | 201002 | ✅ agent（Windows 快照 diff） |
| network_connection | 4001 | ✅ agent（eBPF）/ sensor |
| dns_query / dns | 4003 | ✅ sensor |
| authentication | 3002 | ✅ agent |
| application / antivirus | 100001 | ✅ syslog |
| image_load / driver_load | 1005 | ✅ Linux 内核模块快照 diff |
| proxy / webserver | 4002 | ❌ 无采集来源 |

`fieldMap`（`engine.go:31-74`）把 Sigma 标准字段名映射到 OCSF dot path；
未映射的字段名直接按 dot path 使用（`engine.go:675-678`）——写规则时字段
路径以 [events.md](events.md) 为准。

### 求值与热重载

- **OS 过滤**：`product` 与资产 OS 不一致则跳过（Windows 规则不在 Linux
  资产上求值）；资产 OS 未知（空串）时不过滤（`engine.go:466-486`）
- **规则索引**：按 class_uid 分桶 + anyClass 桶（`engine.go:325-337`）
- **字段缓存**：同一事件跨规则复用字段解析与小写结果；求值缓冲按规则快照复用，
  并发调用各自独占，结束后清除原始事件、字段值与全文缓存，不跨事件沿用证据。
- **热重载**：周期扫描（`RULES_RELOAD_SECONDS` 默认 30s，0 关闭），指纹=
  全部 yml 文件的路径+内容 SHA-256，变化则整体重载、`atomic.Pointer` 原子
  切换；编译失败的规则只跳过该条，不影响旧规则集（`engine.go:399-439`）
- **严重度**：informational1/low2/medium3/high4/critical5，默认 3
  （`engine.go:130-132`）
- **ATT&CK 标签**：解析 Sigma `tags` 的 `attack.` 前缀，技术匹配
  `^t\d{4}(\.\d{3})?$`，14 个战术按杀伤链排序（`attack.go:11-79`）

### 规则校验工具

- `go run ./cmd/sigmacheck --strict ../rules`：自带规则必须全部可加载
- `go run ./cmd/detectcheck --strict`：`validation/` 语料回放过引擎，
  命中规则的 ATT&CK 标注必须与技术一致（检测能力回归的核心防线）；用例可写 `level`，
  要求命中规则里的最高级别正好是它——降噪后的维护动作停在 low、劫持仍是 high，靠这个守住分级
- `DATABASE_URL=<只读副本> go run ./cmd/backtest -days 3 <规则目录>`：用近 N 天的真实事件回放规则，
  按规则报告每天命中次数、涉及主机与样本。新规则上线前必须回测：一天响几百次的不是检测能力，是噪音。
  按小时分段读取（只读副本上的长查询会和 WAL 回放冲突被取消），平台指令拉起的事件不计
- `DATABASE_URL=<只读副本> TEMPORAL_RULES_PATH=<时序规则目录> go run ./cmd/backtest -from <RFC3339> -to <RFC3339> <基础规则目录>`：
  时序规则回测，按事件时间顺序回放基础匹配与时序求值（纯内存，只读事务），输出每条时序规则的命中次数、
  按资产 / 账号的分布与样例证据事件 ID，以及未参与求值的覆盖缺口计数，见 [时序检测](temporal-detection.md#回测)
- 信号规则：`rules/signals/` 下带 `openxdr_signal: true`（级别必须 informational）的规则只作时序规则的输入，
  命中不单独告警、不进去重 / 关联 / 研判 / 通知，未启用时序检测时不生效；detectcheck 用 `expect: signal` 表达，
  回测单列其命中量与候选量，见 [时序检测 · 信号规则](temporal-detection.md#信号规则)
- SigmaHQ 社区规则：`rules/sigmahq/` 收录 Linux 进程 / 文件 / 网络与 DNS 规则（131 条，DRL 1.1），
  引入前在生产数据上回测，低价值高频与误报的列在 `excluded.txt` 不引入；同步方式见该目录 README。
  社区规则的许可要求基于命中的消息保留作者：告警、事件、报告、通知、规则页都带规则作者
- 对 SigmaHQ 全库实测（2026-10）：Linux 211 条可加载 211 条；Windows 2420 条可加载 2180 条，
  其余是 PowerShell 脚本 / 模块、命名管道等未接的数据源

## 威胁情报（`server/internal/intel`）

外部网络检测告警可通过 [Suricata EVE 接入](suricata.md)进入同一条处理链。
`ingest` 在事务内核对来源组和资产，将外部签名转为 `suricata:<gid>:<sid>` 命中，
随后复用下述抑制、持久去重与事件关联；不要求先写一条 Sigma 规则重新匹配告警文本。
原始 EVE 留在 `events.raw.suricata`，签名与修订号写入告警依据并进入 AI 研判上下文。

- **IOC 类型**：`ip / domain / hash` 三类（`ent/schema/intel.go:23`）。
  无独立 JA3 类型，但事件提取时 `ja3_hash` 键归入 hash 碰撞，JA3 实际
  走 hash 通道（`store.go:208`）
- **事件侧提取**：不枚举字段路径，按键名递归收集——`ip`→IP（含 DNS 应答
  `answers[].ip`）；`hostname`/`sni`→域名（小写、去尾点）；
  `sha256/sha1/md5/hashes/hash/ja3_hash/ja3s_hash`→哈希（`store.go:189-211`）
- **匹配**：内存索引 `kind:value`；域名**逐级后缀碰撞**
  （`a.b.evil.com` 依次试 `a.b.evil.com / b.evil.com / evil.com`），
  所以 `evil.com` 能撞上 `c2.evil.com` 的 DNS 查询、TLS SNI、HTTP Host
  （`store.go:137-147`）
- **命中产物**：`rule_id = "intel:<kind>:<value>"`，严重度取 IOC 的
  severity，与规则命中**走同一条**抑制/去重/关联/研判链路——没有第二套
  告警逻辑，抑制规则也能压情报误报（`store.go:23-29,131-135`）
- **有效期与计数**：`expires_at` 过期即跳过；命中计数内存攒批回写
  `matched_count`/`last_matched_at`；周期 reload（`INTEL_RELOAD_SECONDS`
  默认 30s），API 增删后立即 reload（`store.go:127,154-180`）
- **导入**：`detectKind` 自动识别——IP 字面量→ip；32/40/64 位十六进制
  →hash；其余→domain；重复条目跳过（`api/intel.go:205-214`）
- **订阅**（`intel/feeds.go`）：内置 `Catalog` 四个公开源（Feodo / ThreatFox /
  URLhaus / ET compromised）；ThreatFox 与 URLhaus 使用认证导出，前者读取单 CSV 的 ZIP，
  压缩包与解压内容各限 50 MiB，拒绝多文件或损坏包。密钥来自外部情报配置或 `ABUSE_CH_AUTH_KEY`。开关存 `settings.intel_feeds`（从未保存过时全开），
  同步结果存 `settings.intel_feed_status`。仅配置记录不存在时采用默认值；读取失败、`null`、缺少 `enabled` 数组、字段类型损坏或存在未知源 ID 时终止同步，
  不请求外部源、不删除旧情报，列表接口明确返回错误。`RunLeader("intel-feeds")` 启动即同步、之后
  每 `INTEL_FEED_INTERVAL_HOURS`（默认 6）小时一次；控制台改开关或「立即同步」走同一
  `Sync`，以 `WithLock("intel-feeds-sync")` 串行。条目以 `source=feed:<id>` 一条
  `INSERT … ON CONFLICT (kind,value) DO UPDATE … WHERE source LIKE 'feed:%'` 批量写入，
  手工情报不被覆盖；有效期为周期的 8 倍，源里撤下的条目到期失效、拉取暂时失败不断情报；
  关掉的源立即删除，过期订阅条目每次同步清理。外部数据不可信：内网/保留地址剔除，域名与
  哈希逐条校验，解析时按类型和值去重并保留首次备注，唯一 IOC 达到 10 万条后只接受重复项，新增唯一项立即拒绝；
  纯文本源在超限时停止读取，CSV 仍先做最多 50 MiB 的文本预处理。单源下载与解压大小各限 50 MiB；断流、解析失败或超限均拒绝本次更新，不续期旧条目；
  源返回零条视为异常而非全部撤销。
  离线测试覆盖认证请求构造、ZIP/CSV 解析与失败保留，不代表已接通外部源。实际导出路径、账户权限及数据量是否落在上限内，
  仍需有效 Auth-Key 验收；URLhaus 的完整 hostfile 下载说明仅登录后可见（[官方文档](https://urlhaus.abuse.ch/api/)）。
  ThreatFox 的 `url` 只取主机为 IP 的，避免公共平台主机名误伤。情报列表接口默认不含
  订阅条目，订阅状态与命中过的订阅情报走 `/api/intel/feeds`；`syncedAt` 仅记录最近成功，
  `attemptedAt` 记录最近尝试，失败不会刷新成功时间。旧版失败记录的成功时间无法还原时留空。

### 情报订阅离线验证

以下命令在仓库根目录执行，使用本地样例与临时 HTTP 服务，不需要 Auth-Key。
模糊测试验证文本与 ZIP 输入不能导致崩溃、重复 IOC、越过条目上限或在失败时返回部分情报。

```bash
go -C server test -race ./internal/intel
go -C server test ./internal/intel -run '^$' -fuzz '^FuzzFeedText$' -fuzztime=30s -parallel=2
go -C server test ./internal/intel -run '^$' -fuzz '^FuzzThreatFoxZIP$' -fuzztime=30s -parallel=2
```

配置 `INTEGRATION_DATABASE_URL` 指向专用测试库后，可运行订阅配置损坏、失败保留与 API 回归。
测试会清理数据库，不能指向业务库：

```bash
go -C server test -tags integration -p 1 ./internal/intel ./internal/api -run 'TestFeeds|TestFeedStatus|TestIntelFeedsAPI'
```

控制台的密钥输入、清空、恢复默认值及同步失败显示由[离线浏览器回归](../validation/web/README.md)覆盖。

## 持久去重（`server/internal/ingest`）

- 状态表 `alert_dedup_state(fingerprint, alert_id, first_ts, last_ts)` 由所有
  worker 共享；不再随 agent 重连或 server 重启丢失。
- 窗口 `ALERT_DEDUP_WINDOW_MINUTES` 默认 5 分钟，以**首条命中时间**为锚，
  窗口不滑动续期。
- **指纹构成**（按接入路径不同）：
  - agent：`ruleID`；文件事件（1001）追加 `|file.path`；爆破合成告警
    `xdr:bruteforce-success|username`（`agent.go:218-232,257`）
  - sensor：`ruleID|assetID`，无资产时 `ruleID|srcIP`（`sensor.go:104-106`）
  - syslog：`ruleID|origin`（`syslog/server.go:203`）
- 同一 fingerprint 先取得 PostgreSQL transaction advisory lock；窗内重复
  原子 `count+1` 并推进 `last_ts`，新窗口新建告警并替换状态指针。
- 事件插入、规则/情报告警和去重状态在同一事务提交。队列重投先被事件主键
  拦住，不会重复增加告警计数。

## 抑制（`server/internal/suppress`）

- 维度：(rule_id, asset_id?) 加可选的**字段条件**（最多 3 条、AND）；asset_id 为空=全局。
  条件按事件体 dot path 取值比较（equals / contains / endswith，不区分大小写），只压掉字段对得上的命中，
  比如 DNS 服务器上只压某个域名，而不是把管着全网查询的整条规则压掉（`suppress/conditions.go`）
- 命中检查有效期 + 资产限定；`expiresInDays` 0=长期（`store.go:86-106`）
- **从不静默**：被压次数持续累计（内存攒批回写 `matched_count`），
  清单里可见、随时可撤销；新建/删除立即 reload 生效
  （`store.go:108-137`、`api/suppressions.go:86-113`）
- 适用点：三条接入路径建告警前，以及 UEBA 与爆破合成告警
  （`ueba/engine.go:159`、`agent.go:256`）
- 抑制先于去重——被压掉的命中不占去重槽位（`agent.go:228-235`）
- **AI 提议、人批准**：AI 用 `suppress` 工具提交抑制草案（状态 `proposed`，不进索引）。只能针对本组单台主机、
  这台主机近 30 天真实命中过的规则（平台指令触发的不算），**必须带字段条件**且要对得上其中至少一次命中的事件，
  理由必填，有效期 1–90 天；条件相同的生效或待批抑制不重复提，30 天内被拒过的同样条件不再接受。主机所在组的管理员在抑制页批准（有效期从批准时重新算，立即生效）或拒绝，
  与命令审批同一档权限，写审计；侧栏显示待批数量
- **误报统计 → 抑制草案**（`server/internal/fpstats`，单活租约 `fp-stats`，默认每 6 小时一轮）：把人反复下的「误报」结论回喂到规则层。
  - 统计口径：近 `FP_SUPPRESS_WINDOW_DAYS`（30）天有告警（平台指令触发的除外）的 incident，按（规则、主机）计数，主机决定所属组；
    一个 incident 含多条规则时对每条规则各算一次。**计入**的误报是人下的结论——有结案人、不是系统自动结案、
    不是原样采纳 AI 结案建议（`resolution_source=ai_proposal`）；人选了误报、说明沿用 AI 研判的（`ai_verdict`）计入，
    结论是人下的，接口只在与 AI 研判一致时才允许不写理由。`ai_proposal` 与系统自动结案（`resolved_by=system`）结论和理由都出自 AI，
    计入就成了 AI 提议结案 → 统计 → 提议抑制的自我强化，单独计数写进依据、不进分子也不进分母；早期没记结案人的不算。
  - 门槛：计入的误报 ≥ `FP_SUPPRESS_MIN_COUNT`（5），误报率 = 误报 /（误报 + 属实 + 未结案）≥ `FP_SUPPRESS_MIN_RATIO`（90%），
    窗口内**没有任何**属实结论（`closed`，不论谁判的）。未结案的进分母：大部分还没人看过时不出草案。
    命中级别达到高危（≥4）的（规则、主机）不出草案：与研判复核同一口径，高危被统计吞掉代价太大，要压由人手写条件。
  - 窄优先：按 `query.hostname`、`dst_endpoint.ip`、`file.path`、`reg_key.path`、`module.file.path`、`process.file.path`、
    `src_endpoint.ip` 的顺序（先看规则作用的对象，最后才是发起进程）对每个取值单独过门槛，第一个有取值过门槛的字段出草案
    （每个取值一条 `equals` 条件，同一（规则、主机）一轮最多 5 条）；这些命中都出自同一个进程映像时再加一条 `process.file.path` 条件。
    shell、脚本解释器与 cmd / powershell / mshta / rundll32 等通用映像不算实体（攻击同样经由它们执行，按它们压等于压整条规则）。
    事件体已过保留期的命中不知道是哪个值：属实与未结案的从严算进每个取值，误报的不算。
    **没有任何取值单独够数**（实体分散）且整条规则过门槛时才出不带条件的整条规则草案，理由与依据里标明「整条规则」。平台合成规则（`xdr:` 开头，如首次出现检测）不出整条规则草案：它们的每条命中本来就是不同实体，整条压掉等于关掉这台主机上的这项检测。
  - 草案即 `status=proposed` 的抑制（`created_by=fp-stats`），挂进上面同一个组管理员审批流程，批准前不进索引；
    带依据（计入的事件、谁判的、比例、未计入的数量）与建议有效期 `FP_SUPPRESS_DAYS`（30，1–90）。
  - 不重复：同（规则、主机或全局）已有生效且范围不比草案窄的抑制、或与草案互相包含的待批草案时不生成；
    `FP_SUPPRESS_COOLDOWN_DAYS`（30）天内被拒过的，范围不比它窄的草案不再生成（拒了窄的，宽的更不提；更窄的可以再问）。

## 爆破得手升级（`internal/ingest/processor.go` 与旧接入路径 `internal/grpcsvc/bruteforce.go`）

- 每条 class 3002 且 `status_id=1` 的成功登录事件触发回查：同资产同用户
  前 **10 分钟**内失败（status_id=2）≥ **5 次**则合成 critical 告警。窗口按事件时间为
  `[成功时间−10分钟, 成功时间)`；同一时间戳不证明先后顺序，成功之后的失败不参与计数。
- 合成告警 `rule_id = "xdr:bruteforce-success"`，severity=5，指纹按
  username 去重，可抑制（`agent.go:250-269`）
- 设计取舍：成功登录稀少，回查一次库即可，无需引擎状态；Linux/Windows
  通用（两侧 3002 同构）。生产事务处理器在失败日志迟到时，还会回看该失败之后十分钟内已入库的成功登录；
  命中仍绑定成功事件及其原始时间，按同资产、同用户名隔离。旧的无事件总线 gRPC 路径仅在成功时回查。
- 生产路径在写入认证事件前获取同资产/用户名的 PostgreSQL 事务锁，避免并发事件互相不可见。
  `temporal_matches` 以规则和成功事件 ID 唯一记录已消费命中，和事件、告警在同一事务提交；
  后续补传不会再次增加同一成功事件的告警计数。被抑制的命中同样记录为已消费。
- 回看依赖数据库仍保留的事件；清理过的失败证据不能恢复。命中记录随成功事件删除级联清理，不能单独清空。
  旧版已合并告警没有保存全部成功事件 ID，升级前历史告警的命中记录迁移仍待补齐，不能据此承诺跨旧版升级完全去重。
  此实现仍是固定爆破检测，不代表已有通用计数/序列规则引擎。

## 平台指令触发的告警（`server/internal/cmdorigin`）

平台自己下发的指令（人工或 AI 的 exec）在主机上跑巡检、取证命令，常常命中侦察、端口探测之类的规则——
上线初期近一半告警来自这里。这类告警来源已知，单独处理：

- agent 拉起指令时设置环境变量 `OPENXDR_COMMAND_ID`，进程采集只认 **agent 直接子进程**上的这个变量
  （别的进程自己设没用），后代沿进程血缘继承；进程、网络、DNS 事件带 `platform_command.uid`。Windows 读不到
  别的进程的环境变量，暂不打标
- server 不盲信标记：指令必须是发给这台资产的 exec，事件发生在指令执行期间（结束后再给后代进程 1 小时）。
  核对不上的标记当没有，照常告警
- 核对通过的告警带 `command_id`、单独去重（不和同规则的真实命中合并），不进关联与研判、不计入态势统计；
  在资产详情的指令列表里按规则汇总显示。查询视图 `alerts` 带 `command_id`，AI 统计威胁时排除
- 指令拉起的进程不进 UEBA：既不学进基线，也不报首次出现——AI 跑过一个新程序，不该让以后别人再跑它时变成「见过的」

## 已知自动化（`server/internal/automation`）

平台指令之外，运维脚本与第三方 AI 运维插件（如 Termix 的 AI 运维）也经 SSH 登录主机跑 `uname`、读 `os-release`、
用 `/dev/tcp` 探端口，命中反弹 shell 特征、Linux 侦察、端口探测等规则。它们的命令行每次不同（`bash -lc '<脚本>'`、
`setsid sh -c 'exec 3<&0 …'`），复发归并合不上；反弹 shell 特征是 critical，误报统计也不会出草案。
已知自动化（代码与接口里仍叫 trusted source）按**登录身份**认出这类自动化，平台自动识别为主、组管理员可手动添加，处理口径与平台指令一致：

- **识别依据只有登录事实**。agent 把 sshd 认证成功日志里的用户、来源地址、公钥指纹挂到这次登录会话的所有进程上，
  事件顶层带 `login_session`（见 [事件模型](events.md)）。组管理员登记时按公钥指纹（`SHA256:…`）、来源网段、登录用户
  三项组合（全部满足才算命中），**至少要有指纹或网段之一**；不填指纹时网段不能宽于 /24（IPv6 /64）。
  **不提供按命令行或进程名放行**：命令行与进程名攻击者可以随意构造，拿它当可信依据等于给攻击者留了后门
- **防伪造**：
  - 认证日志的出处按 journald 记下的内核凭据核对（`_UID=0` 且 `_COMM` 为 `sshd` / `sshd-session`），
    `logger -t sshd` 之类的伪造日志不会被拿来绑定会话；伪造需要 root
  - 会话归属按内核审计会话号（`/proc/<pid>/sessionid`，pam_loginuid 打开会话时分配，本次开机内单调递增不复用）。
    非 root 改不了；root 重写 loginuid 只会拿到新号，挤不进已有会话。setsid、nohup、sudo 都不改变会话号
  - 认证日志的 pid 是 sshd 特权监控进程，按它的启动时刻核对，pid 复用不会把别人的会话认成这次登录
  - 公钥指纹只认 `publickey` 认证（hostbased 的是客户端主机密钥）；用户名由对端控制，解析从右边切，塞不进假来源与假指纹
  - 剩下的风险：同 uid 能 ptrace 会话里的进程（`kernel.yama.ptrace_scope=0` 时）就能借会话的身份执行；
    私钥被盗则攻击者就是「可信来源」——这正是下面高危例外要兜的
- **高危例外仍进研判**：即使来自可信来源，规则属于凭据窃取（`credential-access` 战术、T1003）、指标清除（T1070，含清日志、清历史）、
  削弱防御（`defense-impairment`、T1562）、破坏（`impact`、T1485/T1486/T1490）或是情报命中，告警照常进关联、研判与推送，
  标成 `automation_watch`。**不按 severity 阈值**：运维脚本最常误中的反弹 shell 特征本身就是 critical，按阈值等于白登记；
  按行为类别划分则是运维自动化几乎不需要做、做了也值得人看一眼的事
- 命中的告警带 `automation_id`、单独去重（不和同规则的真实命中合并），照常入库可查；不进关联与研判、不计入态势统计。
  事件页、incident 告警列表标注「已知自动化：<名称>」，研判上下文对高危例外注明来源。查询视图 `alerts` /
  `alert_events` 带 `automation_id`、`automation_watch`，另有 `trusted_sources` 视图
- **治理与抑制同等**：按组生效（别组主机上的同一登录不认），有效期必填（1–365 天），可停用、删除（删除只是隐藏，保留记录，
  已挂上的告警仍说得清来源），命中次数与最近命中时间持续累计，增删改都落审计（`trusted_source_created` / `_updated` /
  `_enabled` / `_revoked` / `_deleted`，自动识别的见下）。手动添加与调整只有组管理员能做；这是降低检测的操作，
  **Pi 没有对应工具**，AI 觉得该加时只能向用户说明依据
- 平台指令优先：指令拉起的进程也在某次登录会话里，两者都对得上时挂在指令上
- **覆盖范围**：只认 agent 上报的进程事件（启动与退出）上的规则 / 情报命中与 UEBA 首次出现（新程序照常学进基线）；
  网络、DNS、文件事件不带登录归属；时序规则、爆破得手、外联心跳等合成告警不走这条路径。
  只支持 Linux 主机上直接登录的 SSH 会话：容器里的 sshd 写的是容器自己的 journal，宿主机 agent 读不到，非特权 LXC
  也没有审计会话号；没有 pam_loginuid 的系统会话号一直未设置；Windows 的 OpenSSH 会话暂不做。
  认不出就不标，告警照常——失败方向是多告警，不是漏告警
- 已知时序缺口：sshd 先写认证日志、再打开 PAM 会话、最后拉起命令，agent 通常先读到日志；
  极端负载下会话的首个进程若早于日志到达，这一个进程不会被标注

### 自动识别

后台单活任务（`cluster.RunLeader`，名 `automation`，默认每 5 分钟）从核对过出处的 SSH 登录里自动认出运维自动化，
满足条件就**直接生效**，不等人登记；生效、停用都推送通知（复用 Webhook 通道），全程以 `system` 落审计。

- **登录台账**：每轮增量扫新到的、带 `login_session` 的 3002 事件（游标存在 `settings` 的 `automation.login_cursor`，
  每次往回多看 10 分钟，按事件 ID 去重），收进 `ssh_logins`，只留窗口内的。直接按天扫 events 在生产 7 天要 29 秒，台账让每轮只看新事件。
  晚于游标 10 分钟以上才到的登录（agent 离线攒批）不进台账——只会少算，方向是保守的
- **识别单位**：组 + 登录用户 + 公钥指纹。非公钥登录按（用户、来源地址）列出来解释，但永远不自动识别
- **条件全部满足才生效**（判断顺序即「近期 SSH 登录」里给出的原因）：
  1. 公钥登录（有指纹）
  2. 来源全是内网地址（私有、回环、100.64.0.0/10）。**公网来源一律不自动识别**：同一出口后面可能是任何人，
     密钥一旦泄露，攻击者从公网登录就直接被放过；需要的话人工添加
  3. 来源地址固定：按「用户 + 钥匙 + 来源地址」逐个判断，条目只写单个地址（/32，IPv6 /128）。同一把钥匙从工作站和脚本机都登录时
     分开判断，人手动的会话不会跟着脚本一起被认成自动化
  4. 回看期（窗口与有效期取大，默认 30 天）内该身份没有任何告警被判可疑以上：人工结案「属实」，或 AI 判 malicious / suspicious
  5. 登录有规律：窗口（默认 7 天）内至少 3 天有登录、共至少 20 次。交互式登录的管理员一周很少用同一把钥匙登 20 次，
     脚本与运维插件每跑一条命令就是一次登录
  6. 窗口内触发过告警——没有告警的来源本来就不产生噪声，不需要识别
  7. 告警全部已有结论：没进事件的、事件未研判的、重开待重新研判的都算「待研判」，有就先不识别。
     **高危事件（最高级别 ≥ 4）的 AI 良性结论不作数**，与通知、待复核同一个「需人工复核」口径（`review.Severity`）
  8. 良性结论够数（按事件计）：人工判误报的事件 1 个即可；只有 AI 结论时要 3 个。系统自动结案、人直接采纳 AI 结论结案的都按 AI 结论算——
     那不是人的独立判断
- **生效**：条目标 `origin=auto`、名字为 `用户@地址`、带依据（`evidence`：窗口天数、登录天数与次数、主机数、地址、人工误报与 AI 良性事件数），
  有效期默认 30 天。已有生效的人工条目覆盖全部来源地址、或人停用 / 删除过覆盖它的人工条目时不建
- **续期与过期**：登录仍有规律、没被判可疑以上就续期（一天最多一次，落审计 `trusted_source_auto_renewed`）。
  生效后它的告警不再研判，良性结论会随窗口滑走，所以续期不再要求新的结论。不再规律登录就不续，到期自然失效；
  过期后重新满足全部条件（包括新的良性结论）会复用同一条重新生效并再通知（`trusted_source_auto_revived`）
- **自动停用**：生效中的自动条目，只要它的告警（生效前同一身份的，或生效后挂在它上面的高危例外）被判可疑以上，下一轮立即停用
  （`revoked_by=system`、`revoke_cause=verdict`、记下事件），通知并落审计 `trusted_source_auto_revoked`；窗口内被它放过、
  还没进事件的告警改成 `automation_watch`，重新进关联与研判。**固定的条目同样会被停用**：固定是「别再自动改它」，
  不是「被判恶意也别管」。**人工登记的条目同样会被停用**，只看登记之后的告警结论（登记前的结论人是看过之后才登记的）；
  人工条目不会被自动续期或改动
- **人说了算**：人停用、删除过的自动条目永远不会被自动加回（不设冷却期：系统隔一阵再加回来等于无视人的否决；
  想恢复可以在页面上启用）。人重新启用被系统停用的条目时自动固定，并记下确认时刻（`confirmed_at`），
  此前告警上的结论不再触发停用，之后的新结论照常生效。固定的条目不续期、不改网段与依据
- **通知**：生效、停用分别合成一条推送（标题「认出 N 个日常自动化，已加入「已知自动化」」/「N 个已知自动化已自动停用」），
  说明依据、影响与怎么撤回；推送失败不清待发标记（`notice`），下轮重试，生效不因推送失败而推迟。未配置推送目标时只落审计
- **总开关**：`AUTOMATION_AUTO_ENABLED=false` 时不识别、不续期，但照常收登录、照常按结论停用已有的自动条目并通知。参数见
  [部署手册](deployment.md#配置)
- 控制台「已知自动化」页的「近期 SSH 登录」用同一套判断解释每个登录身份为什么（没）被认出来，可从那里手动添加

## 关联（`server/internal/correlate`）

周期批处理：`CORRELATE_INTERVAL_SECONDS` 默认 10s，每批最多 500 条未归属
告警按 ts 升序（`engine.go:53-63`）。

**归属判定优先级**（`engine.go:83-94`）：

1. **进程血缘**：沿 `parent_process_guid` 上溯最多 16 层，找祖先进程触发的、
   已归属 open/triaged incident 的告警——最强信号，能跨时间窗
   （`engine.go:23,149-182`）
2. **批内同资产缓存**
3. **同资产时间窗**：`CORRELATE_WINDOW_MINUTES` 默认 30 分钟，含"无资产"
   桶（`engine.go:71-77,216-237`）
4. **复发**：超出时间窗后，同资产、同规则、同实体的告警并回仍未结案
   （open/triaged）的 incident——周期扫描、轮询外联是同一件事反复发生，
   每次新开 incident 等于让研判与人把同一件事看 N 遍（`recur.go`）。
   实体键：情报规则的 rule_id 自带 IOC；其余按事件取 DNS 域名（不分大小写）、
   网络对端 IP（入站取 src，出站与 sensor 取 dst）、文件路径、进程（执行用户 + 父进程映像 +
   映像 + 完整命令行，映像路径按 merged-usr 归一、Windows 路径不分大小写）；
   容器（LXC / docker）入键，同机不同容器不并。取不到实体（登录、合成告警等）不做复发归并。
   进程类再有一档**粗键**（`CORRELATE_RECUR_COARSE`，默认开）：去掉命令行，同用户、同父进程映像、
   同映像的告警也并——同一程序被同一种父进程反复拉起，参数不同仍是同一类事。两个例外：
   映像是解释器或命令包装器（sh/bash/python/perl/powershell/cmd/rundll32/timeout/sudo/xargs/ssh 等，
   名单见 `recur.go`）时没有粗键，仍按完整命令行认——`bash -c` 后面跟什么都行，映像相同说明不了行为相同；
   首次出现（`xdr:new-process`）按（资产, 映像）建基线、同一映像只告警一次，它的粗键去掉映像，
   即同主机同用户同父进程下陆续冒出的新程序并成一件。
   跨度上限 `CORRELATE_RECUR_HOURS` 默认 24 小时，从 incident 创建起算，超出就新开；
   已结案的不重开，复发另起 incident。每次最多比对 100 条候选，比不到按新建处理
5. **横向移动**：只在本机没有归属故事时才查——时间窗内别的主机有
   conn_tuple 目的端是本机 IP 的会话事件，归并进对端 incident（每 IP 取
   最近 5 条），避免把巧合的网络连接当成攻击路径（`engine.go:184-214`）

其他行为：

- **无按用户维度的关联**（无此实现）
- **事件图**：存 incidents.graph JSONB；节点类型 asset/alert/process/
  connection，边 rel：hosts/triggered/spawned/lateral；上限
  `CORRELATE_MAX_GRAPH_NODES` 默认 500，触顶只累 overflow
  （`graph.go:5-25`、`engine.go:121-126,239-319`）
- **新证据**：incident 收到新证据时不改状态，记 `evidence_at`，研判引擎按「研判节奏」决定何时重研判。
  incident 里已有同资产同规则同实体（精确键）的告警时，再来一条不算新证据（否则周期扫描每来一次就重判一次）；
  按粗键并进来的是同类的另一件事（命令行不同、新冒出的程序），照常算新证据，但同级不清推送标记；
  研判上下文按规则汇总全部告警条数与累计命中，明细只列前 50 条时也能看到同类重复了多少次。
  **升级类**另记 `urgent_at`、立即重研判：级别高于 incident 现有最高级别（同时清掉推送标记，重新研判后按新级别与
  新结论再决定是否推送，升级信号不会被旧的「良性」吞掉），或 incident 里头一回出现的高危例外规则——与可信来源的高危例外
  同一口径（`automation.Watch`：情报命中、凭据窃取、指标清除、削弱防御、破坏；规则库里查不到的按高危）。同一条高危规则
  再来只算普通新证据，免得它自己成风暴。先归属告警再记时刻，研判按「证据时刻晚于取上下文的时刻」认没看过的证据
- incident 标题：`"<规则标题> @ <hostname>"`（`engine.go:96-108`）

## UEBA 首次出现（`server/internal/ueba`）

- **只做"新进程首次出现"一种**（包注释 `engine.go:1-6`）；外连侧的规律外联由下面的外联心跳检测负责
- 基线表 `process_baselines`：`(asset_id, exe_path)` 唯一
  （`ent/schema/processbaseline.go:18-27`）
- 扫描：只扫 class 1007 且有资产的事件，游标按 ts 推进每批 1000 条；
  空表从现在开始，**不回放历史**（`engine.go:24-88`）
- 学习期 `UEBA_LEARNING_DAYS` 默认 7 天，按资产从**该资产基线最早
  first_seen** 起算——新资产、新部署、重启都先安静学习，无需额外状态
  就避开告警风暴（`engine.go:126-158`）
- 合成告警 `xdr:new-process`，severity=2，进关联管道、可被抑制
  （`engine.go:159-168`）

## 外联心跳（`server/internal/beacon`）

C2 心跳的样子是同一进程隔着差不多的时间反复连同一个公网目的地。**只看规律会被淹没**：
生产两台主机一天就有一百七十多条规律的公网外联（grafana.com 每 10 分钟、NTP、tailscale、自家 git），
所以检测的是**新出现的**规律外联：

- **判定规律**（`beacon.go` 的 `Periodic`）：最近 `BEACON_WINDOW_HOURS`（默认 12）小时内至少 8 次连接、
  跨度至少 1 小时，间隔中位数在 50 秒到 90 分钟之间，四分位距 ÷ 中位数 ≤ 0.2。只看公网目的地，
  平台指令拉起的连接不算。agent 同一目标 60 秒只报一次连接（`netwatch.rs` 的 `ConnSampler`），
  比这更密的连接看起来都像每分钟一次；周期长于 90 分钟的在窗口里凑不够次数——这两头看不到。
- **身份是（资产, 容器, 进程, 目的端口）**，目的地址与域名只写进告警详情：中继服务换着地址连、
  同一目的地有时带域名有时不带，按地址认每天多出十几条「新心跳」，按进程与端口认只剩几条（生产 7 天数据离线模拟）。
  **已知缺口**：注入进本来就规律连同一端口的进程（比如往一直连 443 的 node 里塞 C2）看不出来；
  新落地的程序、老程序连新端口都能抓到。
- **基线** `beacon_baselines`：`(asset_id, flow)` 唯一，见过即不再报。学习期 `BEACON_LEARNING_DAYS`（默认 7）
  按**资产接入时间**（`assets.first_seen`）算，不按基线最早一条——平时没有规律外联的干净主机进不了基线，
  它冒出的第一条心跳恰恰最可疑。
- **首次启用**（基线为空）回放库里学习期内的历史，只学不报，有历史的资产上线即可检测；之后重启从一个窗口之前接着看，
  重复的由基线唯一索引挡住。单活运行（`cluster.RunLeader`），增量游标 `(ts, id)`，内存只留窗口内的连接时刻。
- 告警 `xdr:beacon`，severity=3，`count` 为窗口内连接次数，`detail` 写一行依据（谁、约多久一次、连哪、几次、离散度），
  研判上下文、事件页与 Pi 只读视图都看得到；可被抑制。`BEACON_ENABLED=0` 关闭。

## AI 研判（`server/internal/triage`）

未配置 `AI_MODEL` 则整个研判不启动（`engine.go:45-48`）。

### 研判流程

- 周期轮询 `AI_INTERVAL_SECONDS` 默认 30s，每批最多 5 个，取法见下节「研判节奏」
- **主动调查式**：模型可调用四个有边界的只读调查工具（`tools.go`）：
  | 工具 | 参数边界 |
  |---|---|
  | `query_events(keyword, hours, mode)` | 默认 indexed 搜索字段值（不保证纯 UUID/长哈希覆盖），查 UUID/哈希显式选 raw 搜索完整原文（返回正文仍会裁剪）；关键词转义 `% _ \`；hours 默认 24、超界回落；返回最近 15 条 |
  | `process_lineage(process_guid)` | GUID 必须合法 UUID；祖先上溯 10 层、子进程最多 10 条 |
  | `host_alerts(asset_id, days)` | UUID 校验；days 默认 7、>90 回落；最多 20 条，并附最近采集状态快照 |
  | `process_baseline(asset_id, exe_path)` | UUID 与完整路径校验；按资产匹配 UEBA 规范/旧版路径，返回已有基线首次记录；未命中为未知 |
- 历史结案参考仅使用有结案人、结案时间和非空独立备注的记录；排除系统结案、采纳 AI 研判/建议以及来源不完整的旧记录。
  上下文按 JSON 分开列出事件 ID、结案人、时间、状态、备注摘录与 `previous_ai_verdict`，注明备注是否截断。
  检索先按当前事件全部资产的现有归组限定范围（未分组资产单独处理），历史案例的全部告警都必须在范围内，防止同规则或混合组案例带入别组备注。资产归属未知则不检索，不能退回全局搜索；资产转组后重新计算范围，不使用被截断的明细推断归组。
  范围内再筛同规则或同主机、相关告警在近 90 天内、最多 8 条；空结果或查询失败均不表示不存在人工确认或工单。
- 四个调查工具均由服务端绑定本轮 incident ID，以完整事件资产的现有归组限制读取；模型参数不能覆盖绑定。
  `query_events` 两种模式及进程血缘的祖先、子进程查询均在 SQL 中过滤；主机告警和 UEBA 基线先检查资产范围。
  未绑定事件、无可确认资产归属或组外资产不退回全局搜索。范围内缺失仍为未知，不能外推到全局。
  每轮研判记录事件资产与归组快照，在后续模型调用、工具范围查询及落库前复核；发现变化则本轮失败，不保存旧结论、不触发结果回调。最终落库事务依次锁定事件、既有关联告警及其资产，再核对快照，使这些关联与归组在检查后至提交间保持稳定；模型推理期间不持锁。四个工具实际返回的资产，以及已提供历史案例的相关资产，也记录引用时的归组：转组或删除会中止本轮，最终事务一并锁定；不引用的同组资产不加入锁集合。仍不覆盖两次检查间转组后又转回、历史案例读出后新增或改挂告警，以及成功提交后的历史结论撤销；不能作为整个权限生命周期已闭环的证明。
- 服务端把查询覆盖、事件结构化标识、最近采集快照与 UEBA 基线查询结果写入 `query_evidence`。
  有工具证据时必须提交非空 `evidence_claims`，只能引用实际存在且值一致的字段，错误引用修正一次后仍不匹配则失败。
  事件正文裁剪与查询条数截断分开记录；父进程缺失保持未知；采集快照不回推历史；基线时间不是安装或实际首次执行时间。
  引用匹配只证明与存储记录一致，不保证自由文本推断正确。服务端根据已匹配引用生成 `evidence_observations`（evidence_id、field、text），覆盖模型伪造的同名字段；无引用时为空数组，同一字段重复引用只展示一次。
  前端在摘要前展示字段摘录及适用边界，完整台账仍可展开；摘要与攻击链明确标为模型判断。摘录不是完整调查结论，也不证明原始数据真实性。旧结论缺少该字段时不补造。
- 事件 raw 截断 300 字符；工具错误以 JSON 回给模型不中断
  （`tools.go:41-61,188-199`）
- **最多 6 轮**（`maxToolTurns`，`engine.go:100`）；模型返回无 tool_calls
  即出答案——不支持 tool calling 的模型天然退化为单轮，无需配置
  （`engine.go:109-128`）；轮数用尽收走工具强制收结论（`engine.go:129-135`）
- 上下文：事件图 + 按规则的全量汇总 + 最多 50 条告警（raw 截 500 字符）+ **误报反馈回流**
  （近 90 天同规则被判 false_positive 的案例）（`engine.go` buildContext）。重研判时另加一节：此前研判过几次、
  上次结论与摘要、上次之后新增的告警（按规则汇总加级别最高、最新的几条明细，不全量铺开；按告警主键 UUIDv7 的入库时间算，
  往前多算一分钟，上次取上下文时还没归属进来的也算新增）
- 新研判必须提交非空 `action_codes`，从服务端建议目录选择；不接受模型自写 `actions`。
  服务端拒绝未知、重复、对象参数及结论不匹配的代码，再生成原有 `actions` 字符串数组供展示和存档。
  结案审核只允许 benign，响应审核和关联排查只允许 malicious；建议代码不执行命令，也不替代响应权限、审批与审计。
  无效建议仅允许一次格式修正，仍无效则退避，不落结论也不触发 OnVerdict。旧存档仍按原格式读取。
- verdict 格式：`{verdict: malicious|suspicious|benign, confidence 0-100,
  summary, kill_chain[], actions[]}`；解析容错取首个 `{` 到末个 `}`，
  不合法存档 `{"error":"unparseable"}`；结论写 `ai_verdict` 并把状态推进
  triaged（`engine.go:20-32,85-90,146-159`）
- **模型输出视为不可信输入**：刻意不做 NL2SQL——工具参数空间受限且已
  转义，模型越不出边界

### 研判节奏（`triage/engine.go` queue，口径在 `review/retriage.go`）

执行时写入 `triage_started_at`，每 15 秒更新 `triage_heartbeat_at`。列表和详情 API 的
`triageStartedAt` 仅在执行心跳仍有效时返回；前端显示「正在研判」与本轮开始时间，
不把排队、冷却或失败退避当成执行中。成功、失败和取消都会清理状态；节点异常退出后心跳
超过 1 分钟即失效，下一次页面刷新不再显示运行中。旧执行不能清理新执行的状态。
详情每 5 秒刷新，列表每 10 秒刷新；正在重研判时保留上轮结论并标出正在研判。
轮询周期不是完成时间：每批依次处理，单个事件可能经过多轮模型调用和只读调查。

incident 状态：`open` 还没有可用结论（新事件、分析师重开），`triaged` 已有结论，`closed` / `false_positive` 是分析师终态。
研判之后再并入的证据不改状态，靠三个时刻判断：`triaged_at`（最近一次研判取上下文的时刻）、`evidence_at`、`urgent_at`
（关联引擎记，见上文「新证据」）。证据时刻晚于 `triaged_at` 即**待重研判**（控制台状态旁标「待重研判」，
升级类标「升级待重研判」；Pi 只读视图 `incidents.retriage` 为 `pending` / `urgent`；报告写「已研判（之后有新证据，待重研判）」）。
研判完成时 `triaged_at` 记成开始取上下文的时刻（再往前让 1 秒防节点间时钟差），研判期间并进来的证据晚于它，下一轮仍待重研判，
不会被这次结论吞掉；研判期间被分析师结案的不改回 triaged。

- **冷却**：普通新证据距上次研判满 `AI_RETRIAGE_COOLDOWN_MINUTES`（默认 30）才重研判，冷却期间进来的告警只累积，
  到期一次研判全部带上。升级类不等冷却。
- **每轮 5 个名额**：新事件（open）按创建先后占多数；重研判里升级类在前、普通的在后，各自按上次研判先后排（刚研判过的排到后面），
  至少留 1 个名额，新事件不满 4 个时补满。
- **防饿死**：新事件每轮至少 4 个名额、先来先研判，后来的新事件只会排在后面，第 k 个新事件最多等 ⌈k/4⌉ 轮；
  研判成功即离开新事件队列。重研判每轮保底 1 个，按上次研判先后轮转，研判完排到最后，每个待重研判的最多等它前面那几个各轮一次；
  每个 incident 的普通重研判至多每个冷却期一次，升级类每个 incident 有上限（级别最多升 4 次，加上不同高危规则各一次），
  所以噪声 incident 既挤不掉新事件，也不会被新事件永远压着。
- **失败退避**：一个 incident 研判失败（模型超时、端点报错、结论格式无效）只退避它自己，同批后面的照常研判：
  `triage_failures` 加一，`triage_retry_at` 推到 1、2、4…分钟后（封顶 1 小时），退避期内不进队列；
  重试时告警明细按失败次数减半（50→25→12…最少 5 条，汇总仍是全量）——超时多半是上下文太大，原样重试只会再超时。
  成功后清零。连续失败 3 次后通知不再等这个研判（见「通知」）。

生产估算（2026-10-21，离线重放 10-20 18:30 ~ 10-21 01:43 UTC 的告警流，单次研判按 250 秒）：Windows 测试机那个被系统
计划任务、服务配置变更反复并入的 incident 实际研判 43 次；按新口径冷却 30 分钟为 15 次（首次 1 次、高危规则首现 2 次、
冷却到期 12 次），冷却 60 分钟为 9 次。同期 pve1 DNS incident 复发后实际等了 40 分钟才重研判（队首超时反复中止整批），
pve2 侦察 incident 首次研判等了 40 分钟；按新口径分别约 4 分钟与即时，按生产当天 46% 的失败率随机注入也在 15 分钟内。

### LLM 客户端

OpenAI 兼容 chat completions；默认 `http://localhost:11434/v1`（Ollama），
temperature 0.1，超时 `AI_TIMEOUT_SECONDS` 默认 120s
（`llm.go:12-29,70-111`）。推理型模型的 `reasoning_content` 不影响解析，
引擎只取 `content` 里的 JSON。结论必须包含有效的 verdict、0–100 的 confidence 和非空 summary；
若 JSON 无效、字段不合规或 finish_reason 表示输出未完整结束，复用已有调查上下文，
撤掉工具后仅尝试一次完整格式修正。仍失败则进入退避重试，不增加成功研判次数、
不覆盖上一份有效结论，也不触发成功后的处置钩子。推理服务在内网时注意 `NO_PROXY`——Go 默认
读 `HTTP_PROXY`，内网端点可能被错误代理。

### 人工结案与批量结案（`server/internal/api`）

- 需人工复核的口径统一在 `server/internal/review`（`Needed`）：未结案，且 AI 没判良性、最高级别 ≥ 高危(4)
  或含人工提交的诱饵观察；低危良性放满 `AUTO_CLOSE_BENIGN_DAYS`（默认 7）天由 janitor 按误报自动结案（`resolved_by=system`）。
- 单个结案（`POST /api/incidents/{id}/status`）与批量结案（`POST /api/incidents/batch-status`）共用
  `resolutionOf`：结论与 AI 研判一致时理由可空（说明取研判摘要，记 `resolution_source=ai_verdict`），
  相反或没研判必须写；结案记结案人与时间、清掉 AI 结案建议、逐条写 `incident_status` 审计。
- 批量结案一次最多 200 个，一个事务内锁住这批事件，任一不可见、已结案或缺理由就整批拒绝，不做部分结案。
  AI 判恶意的事件按误报结案必须显式二次确认（`confirmMalicious`），不能被一批良性顺手带走；控制台默认把它们
  排除在批量误报之外，勾选确认才一起关。
- 事件页「按规则归并」视图（`GET /api/incidents/groups`）把同一规则（或同一情报目标）在同一主机上反复产生的
  未结案事件归成一组，显示事件数、首末时间与 AI 研判分布，可整组结案。归并只是视图，不合并 incident。
  组内有 AI 结案建议时说明默认预填建议文本；原样采纳记 `ai_proposal`。
- **人工案例回喂**：研判时 `appendCaseHistory` 取近 90 天同规则或同主机、人工结案的事件（排除系统自动结案与
  `resolution_source` 非空的采纳 AI），连同当时的 AI 结论与结案说明放进上下文。批量结案逐条写同样的字段，
  所以和单个结案一样回喂；同一说明批量关掉的事件会各自作为案例出现。
- **规则层回喂**：同一规则在同一主机上被人反复判误报，由误报统计生成待批准的抑制草案，见上文「抑制」。

### 准确度（`server/internal/api/accuracy.go`）

研判结论落库时记下当次用的模型（`ai_verdict.model`，`triage/engine.go` 的 `withModel`），
控制台「系统设置 → 研判准确度」拿已结案事件对照 AI 结论：

- **只有人写了理由的结案算独立复核**。一键采纳 AI 研判或结案建议（`resolution_source` 非空）、
  系统自动结案（`resolved_by=system`）的结论就是 AI 的结论，只计数、不进比例，否则准确率会被自己抬高。
  早期版本结案不记时间与结案人，那时只有人能结案，按独立复核算，时间取事件创建时间。
- **漏判率** = AI 判良性的事件里，人认定属实（closed）的比例——回答「AI 说良性时能不能信」，
  决定能否让 AI 结更多的案。**误判率** = AI 判可疑或恶意的事件里，人认定误报（false_positive）的比例。
- 按研判模型、按规则分别统计；一个事件带多条规则时每条规则各算一次。没记录模型的旧结论单独成组。
- 比例旁边同时给分子分母，独立复核少于 20 个时界面提示只作参考。

## 响应处置（`server/internal/response`）

**这是系统中唯一能影响被监控主机的功能。**

### 链路

```
POST /api/commands → Hub.Issue 落 command 行并发往 agent 指令通道
  → gRPC 双向流 Commands → agent 执行（respond/ 模块）
  → CommandResult 回传 → Hub.Complete 回写 succeeded/failed/unsupported
```

指令种类：`kill_process`、`isolate_host / unisolate_host`、`exec`，以及带目标（`target`）的三对：

| 动作 | 目标 | Linux | Windows |
|---|---|---|---|
| `block_network / unblock_network` | IP、网段或域名（域名在 agent 上解析） | nftables 独立表 `openxdr_block`，集合元素带原始目标注释，进出都丢 | 防火墙规则组「OpenXDR Block」，进出各一条；防火墙未启用时报失败 |
| `quarantine_file / restore_file` | 文件绝对路径 | 移进状态目录 `isolated-files/`（0700，文件去掉全部权限），记原路径、大小、SHA-256、权限与属主 | 同左，`ProgramData\OpenXDR\state\isolated-files` |
| `disable_account / enable_account` | 本机账号名 | `usermod -L -e 1`：锁密码并置过期，公钥登录经 PAM 账户检查同样被挡 | `Disable-LocalUser`（只管本地账号，域账号在域控处理） |

目标先经 server 的 `response.NormalizeTarget` 校验，agent 收到后再按同样的规则查一遍（`respond/netblock.rs`、
`quarantine.rs`、`account.rs`）：封锁拒绝覆盖 server 自己的地址（server 侧取 `ISOLATION_ALLOW`，agent 侧取
`OPENXDR_SERVER` 解析结果）、回环、未指定地址和过宽的网段（IPv4 宽于 /16、IPv6 宽于 /48）；隔离文件只处理普通文件，
拒绝伪文件系统、agent 自身与它的状态目录，恢复时原位置已有文件拒绝覆盖；锁定账号拒绝 root、Administrator、SYSTEM
这类内置账号、uid 0 与 agent 自身运行的账号。已有会话不随账号锁定断开，要断开用结束进程或隔离主机。
旧版 agent 不认识新动作，回执「未指定动作」失败，不会误执行（`hub.go`、`api/commands.go`、`grpcsvc/commands.go`）。

### 闸门与防护（改这块代码时全部不得绕过）

指令一律真执行，没有演练模式。两道闸门：

1. **全局开关** `RESPONSE_ENABLED`，否则一律拒绝下发（`hub.go:35-40,75-77`）
2. **隔离自保**：未配置 `ISOLATION_ALLOW` 时 agent 拒绝隔离——隔离后收不到
   解除指令只能人工上机；隔离指令自动附带放行清单
   （`main.go:203-211`、`api/commands.go:73-76`）

结构性防护：agent 不在线即失败不攒指令；每 agent 通道缓冲 32 条满即失败；
断线重连不自动重放任何旧指令，迟到回执仍可更新结果；指令流冒领防护 `verifyAgentID`；结果回写必须对上
库里的 command_id（`hub.go:25-215`、`grpcsvc/commands.go:29-44`）。

### 自动响应保险（`response/auto.go`）

挂 `OnVerdict` 钩子，verdict=malicious 且 confidence ≥
`AUTO_RESPONSE_MIN_CONFIDENCE`（默认 90）时触发：

1. `AUTO_RESPONSE_ENABLED=true` 才挂钩子，隔离真执行，仍受 `RESPONSE_ENABLED` 约束
2. `AUTO_RESPONSE_EXEMPT` 主机名白名单绝不隔离，跳过也记审计
3. 每次决策（含跳过）落审计

同一 incident 同一资产只自动隔离一次（查 issued_by="auto" 的 isolate_host），
重研判不重复隔离（`auto.go:28-104`）。

## 通知（`server/internal/notify`）

- 推送目标存 `settings` 表的 `notify` 键，控制台「系统设置 → 通知」可改并发送测试；
  从未保存过时用 `WEBHOOK_*` 环境变量（`notify/settings.go`）。未配置目标时通知器空转，
  配置后只推之后的事件
- 格式：generic 推 Message JSON；dingtalk/wecom 为 `{"msgtype":"text",...}`；
  feishu 为 `{"msg_type":"text",...}`；正文模板共用（`notify.go:144-227`）
- **投递语义**：AI 启用时等 verdict 再推；升级类证据待重研判时旧结论不作数，同样等新结论；
  普通新证据冷却中按旧结论照常决定，不卡在冷却上（重研判从良性翻成可疑或恶意时清推送标记重新推）；
  研判连续失败 3 次后不再等，不带结论照推并注明研判失败，AI 未启用时也不拿旧结论静默升级的事件；benign 静默跳过，但最高级别 ≥ 高危(4)
  的照推并标「良性，但级别高需人工复核」——AI 会看错，高危事件不能被一句良性吞掉；
  closed/false_positive 不推；目标启用前的历史事件不补发；失败下周期重试；
  每批 20 个（`notify.go:73-137`）
- 阈值 `WEBHOOK_MIN_SEVERITY`（默认 0=全推），按 incident 内告警最高
  severity 过滤（`notify.go:98-103,156-168`）
- 主机失联（`server/internal/liveness`）：agent 指令通道在线时每分钟刷新 `last_seen`；
  超过 `AGENT_SILENT_MINUTES`（默认 10）没有心跳推一次「N 台主机失联」，恢复推一次
  「N 台主机恢复」，同一次失联只推一次（`assets.silent_since`）。巡视器启动后先等满
  该时长再判定，避免 server 重启期间把整片主机报成失联

## 数据保留（`server/internal/janitor`）

- `RETENTION_DAYS` 默认 30 天，0=不清理；周期 `RETENTION_INTERVAL_MINUTES`
  默认 60 分钟（`janitor.go:28-30`）
- 只删**未被任何告警引用**的过期事件（`event.Not(event.HasAlerts())`）——
  证据跟着 incident 的生命周期走；每批 10000 条批间让出 100ms；同周期
  顺带清过期会话（`janitor.go:19,46-83`）
- events 是按天分区表时，过期日分区整体退役：被告警 / 时序证据引用的事件并进月归档分区，
  其余随分区删除；逐行清理只碰归档与默认分区（`eventpart.Retire`，见 [event-partitioning.md](event-partitioning.md)）

## 认证、RBAC 与审计

- **认证**：不透明随机 token，库中只存 SHA-256，cookie `openxdr_session`
  （HttpOnly、SameSite=Lax），TTL 7 天；删行即吊销
  （`auth/auth.go:27-32,116-186`）
- 登录 bcrypt 校验，用户不存在用 dummy hash 陪跑防时间侧信道；同 IP 失败
  5 次起 30s 指数退避、封顶约 64 分钟（`auth/throttle.go:12-59`）
- 初始 admin 密码取 `ADMIN_PASSWORD`，未配置则随机生成打印一次
  （`auth.go:60-87`）
- **RBAC 矩阵**（`minRole`，`auth.go:41-50`）：
  | 端点 | 最低角色 |
  |---|---|
  | `/api/users*`、`/api/audit` | admin |
  | 所有 GET | viewer |
  | 其余写操作（POST/PUT/DELETE） | analyst |
- **审计**字段：username/remote_addr/action/target/detail；写失败只记日志
  不阻断（`audit/audit.go:39-53`）。action 全清单：`login / login_failed /
  login_throttled / logout / incident_status / command_issued /
  suppression_created / suppression_deleted / intel_created /
  intel_imported / intel_deleted / intel_feeds_updated / intel_feeds_synced / agent_config_set / user_created /
  user_deleted / password_reset / auto_response / auto_response_skipped /
  auto_response_failed`

## server 环境变量全清单（`server/main.go`）

| 变量 | 默认值 | 用途 |
|---|---|---|
| `DATABASE_URL` | `postgres://openxdr:openxdr@localhost:5432/openxdr?sslmode=disable` | Postgres 连接 |
| `NATS_URL` | 空（单机直连） | NATS 集群地址；配置后启用 JetStream |
| `QUEUE_SHARDS` | `32` | 按 partition_key 一致性分片数 |
| `QUEUE_REPLICAS` | `1` | JetStream stream 副本数 |
| `QUEUE_MAX_BYTES_GB` / `QUEUE_MAX_AGE_HOURS` | `20` / `0` | 容量满时拒收新消息，时间必须为 0（不自动过期） |
| `LOG_FORMAT` / `LOG_LEVEL` | text / info | 结构化日志格式与等级 |
| `HTTP_ADDR` / `GRPC_ADDR` | `:8080` / `:8081` | REST / gRPC 监听 |
| `TLS_CA_FILE` / `TLS_CERT_FILE` / `TLS_KEY_FILE` | 空 | gRPC mTLS，三者必须同配否则启动报错；全空=明文（仅本机调试） |
| `ADMIN_PASSWORD` | 空（随机生成打印一次） | 初始 admin 密码 |
| `RULES_PATH` | `../rules` | Sigma 规则目录 |
| `RULES_RELOAD_SECONDS` | `30`（0 关闭） | 规则热重载扫描周期 |
| `ALERT_DEDUP_WINDOW_MINUTES` | `5` | 告警去重窗口 |
| `SUPPRESSION_RELOAD_SECONDS` | `30` | 抑制重载/计数回写周期 |
| `FP_SUPPRESS_MIN_COUNT` / `FP_SUPPRESS_MIN_RATIO` | `5` / `90` | 误报统计草案门槛：计入的人工误报次数与误报率（%）；次数 0 关闭 |
| `FP_SUPPRESS_WINDOW_DAYS` / `FP_SUPPRESS_DAYS` / `FP_SUPPRESS_COOLDOWN_DAYS` | `30` / `30` / `30` | 统计窗口、草案建议有效期（1–90）、被拒后冷却期 |
| `FP_SUPPRESS_INTERVAL_HOURS` | `6` | 误报统计周期 |
| `INTEL_RELOAD_SECONDS` | `30` | 情报重载/计数回写周期 |
| `CORRELATE_WINDOW_MINUTES` | `30` | 关联时间窗 |
| `CORRELATE_INTERVAL_SECONDS` | `10` | 关联批次周期 |
| `CORRELATE_MAX_GRAPH_NODES` | `500` | 事件图节点上限 |
| `CORRELATE_RECUR_HOURS` | `24`（0 关闭） | 复发归并跨度上限 |
| `CORRELATE_RECUR_COARSE` | `1` | 进程类告警按粗键（用户+父进程映像+映像）归并复发，0 只按完整命令行 |
| `UEBA_LEARNING_DAYS` | `7` | 首次出现检测学习期 |
| `UEBA_INTERVAL_SECONDS` | `30` | UEBA 批次周期 |
| `BEACON_ENABLED` | `1` | 外联心跳检测开关，0 关闭 |
| `BEACON_LEARNING_DAYS` | `7` | 外联心跳按资产接入时间的学习期 |
| `BEACON_WINDOW_HOURS` | `12` | 判定规律看的时间窗 |
| `BEACON_INTERVAL_SECONDS` | `300` | 外联心跳批次周期 |
| `RETENTION_DAYS` | `30`（0 不清） | 原始事件保留期 |
| `RETENTION_INTERVAL_MINUTES` | `60` | 清理周期 |
| `SYSLOG_ADDR` | 空（不启用） | syslog UDP+TCP 监听 |
| `AI_MODEL` | 空（不启用） | 研判模型名 |
| `AI_BASE_URL` | `http://localhost:11434/v1` | OpenAI 兼容端点 |
| `AI_API_KEY` | 空 | Bearer key |
| `AI_TIMEOUT_SECONDS` | `120` | LLM 超时 |
| `AI_INTERVAL_SECONDS` | `30` | 研判批次周期 |
| `AI_RETRIAGE_COOLDOWN_MINUTES` | `30` | 已研判 incident 又并入普通新证据时，距上次研判至少隔多久才重研判；升级类不等 |
| `RESPONSE_ENABLED` | `false` | 响应处置总开关 |
| `ISOLATION_ALLOW` | 空（隔离将被 agent 拒绝） | 隔离放行地址，逗号分隔 |
| `AUTO_RESPONSE_ENABLED` | `false` | 自动响应钩子，开启即真实隔离（依赖 RESPONSE_ENABLED） |
| `AUTO_RESPONSE_MIN_CONFIDENCE` | `90` | 自动隔离置信度门槛 |
| `AUTO_RESPONSE_EXEMPT` | 空 | 自动隔离主机白名单 |
| `WEBHOOK_URL` | 空（不启用） | 通知地址 |
| `WEBHOOK_FORMAT` | `generic` | generic / dingtalk / feishu / wecom |
| `WEBHOOK_INTERVAL_SECONDS` | `30` | 通知扫描周期 |
| `WEBHOOK_LINK_BASE` | 空 | 控制台链接前缀 |
| `WEBHOOK_MIN_SEVERITY` | `0`（全推） | 通知最低严重度（1 信息 ~ 5 严重） |

采集端环境变量见 [collection.md](collection.md)（agent 与 sensor 各一张表）。

### 研判证据边界与执行记录

调查工具会返回时间范围、返回上限及 `truncated`；事件原文摘要另带
`raw_truncated`，血缘另带 `missing_ancestor` 和祖先/子进程截断标记。
查询错误返回 `status=error`，不能当成“没有记录”。未发现只说明在已采集、
仍保留的数据及查询范围内未发现，不证明客户端无行为，也不证明外部入口没有请求。
AI 长期记忆明确标记为未经人工核实的线索，不允许当作人工确认或良性证明；
人工记录也只在它实际确认的主机、时间及行为范围内有效。
这些约束与回归用于减少不受证据支持的判断，不代表模型准确率保证。

事件详情的“研判执行记录”对应 `triage_runs`：从本版本起，每次抢到执行身份
就记录一条，成功、失败和取消分别留存。成功记录与结论同事务提交；进程崩溃
未能写退出结果时，旧记录在下一次接管时标为 `interrupted/lease_replaced`，
其真实停止时间与未保存的耗时不可恢复，不能拿接管时间当作执行耗时。
记录实际固定的模型、模型调用/工具调用次数与耗时、工具错误数、模型返回的 token
用量。未返回用量的失败请求可能仍被模型服务计费，不能据此推导账单。
`ready_at` 是可排队时刻，扣除了普通新证据冷却和已知失败退避；旧版重开事件缺少
准确时刻时为空。历史尝试不补造，失败率统计须明确起算版本与观测窗口。

调查工具单次最多 15 秒，超时作为查询失败返回而非无匹配；执行记录的 `tool_details`
按调用顺序记录工具名、耗时、失败标记，以及检索/告警工具的返回条数与截断状态。
不保存查询参数或工具返回原文。旧记录无工具明细时不回填。

DNS 事件摘要额外提供 query、requester、answers、进程与端点等结构化字段；单字段超过
2048 字节时省略并列在 `dns_omitted`，原文截断另标记 `raw_truncated`。
共享 CDN/IP、低频 DNS、固定前缀和长 TTL 不能替代应用归属证据，也不能据此建议
放行整个网段、域名族或抑制告警。需核实客户端归属的中高危事件应保留可疑结论。
