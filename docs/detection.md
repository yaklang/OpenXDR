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
triage：   open incident → LLM 研判 → verdict（30s 一批，需 AI_MODEL）
notify：   研判后事件 → webhook（30s 一批，benign 不推）
ueba：     扫进程事件维护基线，首次出现合成 low 告警进同一管线（30s 一批）
janitor：  过期事件/会话清理（60min 一批，告警引用的证据不删）
```

另有两个**合成告警**源在 ingest 侧直接进管线（都走去重、可被抑制）：

- `xdr:bruteforce-success`（critical）：爆破得手升级，见下文
- `xdr:new-process`（low）：UEBA 首次出现，见下文

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
| 修饰符 | `contains / startswith / endswith / re / all`（`engine.go:702-704`） | `cidr`、`base64` 等其余一切（`engine.go:668-671`） |
| 条件 | `not/and/or`、括号、优先级 not>and>or；`1/all/any of them/pattern*`（`condition.go:9,176-217`） | 统计型条件 `count/min/max/avg/sum/near`（`engine.go:537-539`） |
| product | `windows / linux / macos`（`engine.go:153-155`） | 其余 product；既无 category 又无 product 的规则（`engine.go:595-606`） |
| category | 见下方映射表 | 未知 category（报"数据源未覆盖"，`engine.go:588-592`） |

修饰符语义：`re` 强制 `(?i)`；无通配符走 strings 精确/包含/前后缀（小写
比较）；有 `*?` 通配符 QuoteMeta 后转正则；值列表默认 OR，`|all` 转 AND；
值为 `null` 表示字段必须缺失（`engine.go:681-741`）。

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
  命中规则的 ATT&CK 标注必须与技术一致（检测能力回归的核心防线）
- 对 SigmaHQ 3141 条规则实测：加载 2149 条（68.4%），其中 1393 条有现成
  数据源可命中

## 威胁情报（`server/internal/intel`）

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

- **维度只有 (rule_id, asset_id?)** 二元组；asset_id 为空=全局。
  无字段级/值级抑制（`store.go:19-23,94-105`）
- 命中检查有效期 + 资产限定；`expiresInDays` 0=长期（`store.go:86-106`）
- **从不静默**：被压次数持续累计（内存攒批回写 `matched_count`），
  清单里可见、随时可撤销；新建/删除立即 reload 生效
  （`store.go:108-137`、`api/suppressions.go:86-113`）
- 适用点：三条接入路径建告警前，以及 UEBA 与爆破合成告警
  （`ueba/engine.go:159`、`agent.go:256`）
- 抑制先于去重——被压掉的命中不占去重槽位（`agent.go:228-235`）

## 爆破得手升级（`server/internal/grpcsvc/bruteforce.go`）

- 每条 class 3002 且 `status_id=1` 的成功登录事件触发回查：同资产同用户
  前 **10 分钟**内失败（status_id=2）≥ **5 次**则合成 critical 告警
  （`bruteforce.go:18-54`；窗口/阈值常量 `bruteforce.go:27-28`）
- 合成告警 `rule_id = "xdr:bruteforce-success"`，severity=5，指纹按
  username 去重，可抑制（`agent.go:250-269`）
- 设计取舍：成功登录稀少，回查一次库即可，无需引擎状态；Linux/Windows
  通用（两侧 3002 同构）

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
4. **横向移动**：只在本机没有归属故事时才查——时间窗内别的主机有
   conn_tuple 目的端是本机 IP 的会话事件，归并进对端 incident（每 IP 取
   最近 5 条），避免把巧合的网络连接当成攻击路径（`engine.go:184-214`）

其他行为：

- **无按用户维度的关联**（无此实现）
- **事件图**：存 incidents.graph JSONB；节点类型 asset/alert/process/
  connection，边 rel：hosts/triggered/spawned/lateral；上限
  `CORRELATE_MAX_GRAPH_NODES` 默认 500，触顶只累 overflow
  （`graph.go:5-25`、`engine.go:121-126,239-319`）
- **重开**：triaged 的 incident 收到新告警重开为 open，等重新研判
  （`engine.go:110-137`）
- incident 标题：`"<规则标题> @ <hostname>"`（`engine.go:96-108`）

## UEBA 首次出现（`server/internal/ueba`）

- **只做"新进程首次出现"一种**（包注释 `engine.go:1-6`）；外连基线偏离
  刻意不做（信噪比不够）
- 基线表 `process_baselines`：`(asset_id, exe_path)` 唯一
  （`ent/schema/processbaseline.go:18-27`）
- 扫描：只扫 class 1007 且有资产的事件，游标按 ts 推进每批 1000 条；
  空表从现在开始，**不回放历史**（`engine.go:24-88`）
- 学习期 `UEBA_LEARNING_DAYS` 默认 7 天，按资产从**该资产基线最早
  first_seen** 起算——新资产、新部署、重启都先安静学习，无需额外状态
  就避开告警风暴（`engine.go:126-158`）
- 合成告警 `xdr:new-process`，severity=2，进关联管道、可被抑制
  （`engine.go:159-168`）

## AI 研判（`server/internal/triage`）

未配置 `AI_MODEL` 则整个研判不启动（`engine.go:45-48`）。

### 研判流程

- 周期轮询 `AI_INTERVAL_SECONDS` 默认 30s，每批最多 5 个 open incident
  （`engine.go:63-72`）
- **主动调查式**：模型可调用三个有边界的调查工具（与狩猎共用，
  `tools.go:21-39`）：
  | 工具 | 参数边界 |
  |---|---|
  | `query_events(keyword, hours)` | raw 全文 ILIKE，关键词转义 `% _ \`；hours 默认 24、超界回落；返回最近 15 条 |
  | `process_lineage(process_guid)` | GUID 必须合法 UUID；祖先上溯 10 层、子进程最多 10 条 |
  | `host_alerts(asset_id, days)` | UUID 校验；days 默认 7、>90 回落；最多 20 条 |
- 事件 raw 截断 300 字符；工具错误以 JSON 回给模型不中断
  （`tools.go:41-61,188-199`）
- **最多 6 轮**（`maxToolTurns`，`engine.go:100`）；模型返回无 tool_calls
  即出答案——不支持 tool calling 的模型天然退化为单轮，无需配置
  （`engine.go:109-128`）；轮数用尽收走工具强制收结论（`engine.go:129-135`）
- 上下文：事件图 + 最多 50 条告警（raw 截 500 字符）+ **误报反馈回流**
  （近 90 天同规则被判 false_positive 的案例）（`engine.go:161-252`）
- verdict 格式：`{verdict: malicious|suspicious|benign, confidence 0-100,
  summary, kill_chain[], actions[]}`；解析容错取首个 `{` 到末个 `}`，
  不合法存档 `{"error":"unparseable"}`；结论写 `ai_verdict` 并把状态推进
  triaged（`engine.go:20-32,85-90,146-159`）
- **模型输出视为不可信输入**：刻意不做 NL2SQL——工具参数空间受限且已
  转义，模型越不出边界

### 对话式狩猎与狩猎存规则

- `POST /api/hunt` 与研判共用 `toolLoop` 和同一工具集，仅 system prompt
  不同（`hunt.go:16-28`）
- **狩猎存为规则**两段式：`POST /api/hunt/rule` 让 LLM 起草 Sigma YAML，
  经 `sigma.Compile` 校验、错误回喂重试最多 3 次，**只起草不落盘**
  （`draftrule.go:30-58`）；分析师审阅后 `POST /api/rules` 落盘——再过
  一次 Compile、ID 查重、文件名清洗防路径穿越，写成 `hunt_<id>.yml`，
  热重载生效。**落盘前强制过引擎编译器，AI 不能直接改检测面**
  （`api/rules.go:59-95`）

### LLM 客户端

OpenAI 兼容 chat completions；默认 `http://localhost:11434/v1`（Ollama），
temperature 0.1，超时 `AI_TIMEOUT_SECONDS` 默认 120s
（`llm.go:12-29,70-111`）。推理型模型的 `reasoning_content` 不影响解析，
引擎只取 `content` 里的 JSON。推理服务在内网时注意 `NO_PROXY`——Go 默认
读 `HTTP_PROXY`，内网端点可能被错误代理。

## 响应处置（`server/internal/response`）

**这是系统中唯一能影响被监控主机的功能。**

### 链路

```
POST /api/commands → Hub.Issue 落 command 行并发往 agent 指令通道
  → gRPC 双向流 Commands → agent 执行（respond/ 模块）
  → CommandResult 回传 → Hub.Complete 回写 succeeded/failed/unsupported
```

指令种类仅 `kill_process / isolate_host / unisolate_host`
（`hub.go:140-144`、`api/commands.go:48-90`、`grpcsvc/commands.go:15-76`）。

### 闸门与防护（改这块代码时全部不得绕过）

三道闸门：

1. **全局开关** `RESPONSE_ENABLED`，否则一律拒绝下发（`hub.go:35-40,75-77`）
2. **dry-run 默认**：API 不显式传 `dryRun:false` 就只报告"将会做什么"
   （`api/commands.go:39-44,58-62`）
3. **隔离自保**：未配置 `ISOLATION_ALLOW` 时 agent 拒绝隔离——隔离后收不到
   解除指令只能人工上机；隔离指令自动附带放行清单
   （`main.go:203-211`、`api/commands.go:73-76`）

结构性防护：agent 不在线即失败不攒指令；每 agent 通道缓冲 32 条满即失败；
断线重连补发未回执指令；指令流冒领防护 `verifyAgentID`；结果回写必须对上
库里的 command_id（`hub.go:25-215`、`grpcsvc/commands.go:29-44`）。

### 自动响应四道保险（`response/auto.go`）

挂 `OnVerdict` 钩子，verdict=malicious 且 confidence ≥
`AUTO_RESPONSE_MIN_CONFIDENCE`（默认 90）时触发：

1. `AUTO_RESPONSE_ENABLED=true` 才挂钩子
2. `AUTO_RESPONSE_LIVE` 未 true 则全部 dry-run
3. `AUTO_RESPONSE_EXEMPT` 主机名白名单绝不隔离，跳过也记审计
4. 每次决策（含跳过）落审计

同一 incident 同一资产只自动隔离一次（查 issued_by="auto" 的 isolate_host），
重开重判不重复隔离（`auto.go:28-104`）。

## 通知（`server/internal/notify`）

- `WEBHOOK_URL` 未配置则整个通知器不启用（`notify.go:44-47`）
- 格式：generic 推 Message JSON；dingtalk/wecom 为 `{"msgtype":"text",...}`；
  feishu 为 `{"msg_type":"text",...}`；正文模板共用（`notify.go:144-227`）
- **投递语义**：AI 启用时等 verdict 再推；benign 静默跳过；
  closed/false_positive 不推；启动前历史事件不补发；失败下周期重试；
  每批 20 个（`notify.go:73-137`）
- 阈值 `WEBHOOK_MIN_SEVERITY`（默认 0=全推），按 incident 内告警最高
  severity 过滤（`notify.go:98-103,156-168`）

## 数据保留（`server/internal/janitor`）

- `RETENTION_DAYS` 默认 30 天，0=不清理；周期 `RETENTION_INTERVAL_MINUTES`
  默认 60 分钟（`janitor.go:28-30`）
- 只删**未被任何告警引用**的过期事件（`event.Not(event.HasAlerts())`）——
  证据跟着 incident 的生命周期走；每批 10000 条批间让出 100ms；同周期
  顺带清过期会话（`janitor.go:19,46-83`）

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
  login_throttled / logout / incident_status / command_issued / hunt /
  rule_create / suppression_created / suppression_deleted / intel_created /
  intel_imported / intel_deleted / agent_config_set / user_created /
  user_deleted / password_reset / auto_response / auto_response_skipped /
  auto_response_failed`

## server 环境变量全清单（`server/main.go`）

| 变量 | 默认值 | 用途 |
|---|---|---|
| `DATABASE_URL` | `postgres://openxdr:openxdr@localhost:5432/openxdr?sslmode=disable` | Postgres 连接 |
| `NATS_URL` | 空（单机直连） | NATS 集群地址；配置后启用 JetStream |
| `QUEUE_SHARDS` | `32` | 按 partition_key 一致性分片数 |
| `QUEUE_REPLICAS` | `1` | JetStream stream 副本数 |
| `QUEUE_MAX_BYTES_GB` / `QUEUE_MAX_AGE_HOURS` | `20` / `168` | 队列容量与未处理消息保留上限 |
| `LOG_FORMAT` / `LOG_LEVEL` | text / info | 结构化日志格式与等级 |
| `HTTP_ADDR` / `GRPC_ADDR` | `:8080` / `:8081` | REST / gRPC 监听 |
| `TLS_CA_FILE` / `TLS_CERT_FILE` / `TLS_KEY_FILE` | 空 | gRPC mTLS，三者必须同配否则启动报错；全空=明文（仅本机调试） |
| `ADMIN_PASSWORD` | 空（随机生成打印一次） | 初始 admin 密码 |
| `RULES_PATH` | `../rules` | Sigma 规则目录 |
| `RULES_RELOAD_SECONDS` | `30`（0 关闭） | 规则热重载扫描周期 |
| `ALERT_DEDUP_WINDOW_MINUTES` | `5` | 告警去重窗口 |
| `SUPPRESSION_RELOAD_SECONDS` | `30` | 抑制重载/计数回写周期 |
| `INTEL_RELOAD_SECONDS` | `30` | 情报重载/计数回写周期 |
| `CORRELATE_WINDOW_MINUTES` | `30` | 关联时间窗 |
| `CORRELATE_INTERVAL_SECONDS` | `10` | 关联批次周期 |
| `CORRELATE_MAX_GRAPH_NODES` | `500` | 事件图节点上限 |
| `UEBA_LEARNING_DAYS` | `7` | 首次出现检测学习期 |
| `UEBA_INTERVAL_SECONDS` | `30` | UEBA 批次周期 |
| `RETENTION_DAYS` | `30`（0 不清） | 原始事件保留期 |
| `RETENTION_INTERVAL_MINUTES` | `60` | 清理周期 |
| `SYSLOG_ADDR` | 空（不启用） | syslog UDP+TCP 监听 |
| `AI_MODEL` | 空（不启用） | 研判/狩猎模型名 |
| `AI_BASE_URL` | `http://localhost:11434/v1` | OpenAI 兼容端点 |
| `AI_API_KEY` | 空 | Bearer key |
| `AI_TIMEOUT_SECONDS` | `120` | LLM 超时 |
| `AI_INTERVAL_SECONDS` | `30` | 研判批次周期 |
| `RESPONSE_ENABLED` | `false` | 响应处置总开关 |
| `ISOLATION_ALLOW` | 空（隔离将被 agent 拒绝） | 隔离放行地址，逗号分隔 |
| `AUTO_RESPONSE_ENABLED` | `false` | 自动响应钩子（依赖 RESPONSE_ENABLED） |
| `AUTO_RESPONSE_LIVE` | `false`（默认 dry-run） | 自动响应真执行 |
| `AUTO_RESPONSE_MIN_CONFIDENCE` | `90` | 自动隔离置信度门槛 |
| `AUTO_RESPONSE_EXEMPT` | 空 | 自动隔离主机白名单 |
| `WEBHOOK_URL` | 空（不启用） | 通知地址 |
| `WEBHOOK_FORMAT` | `generic` | generic / dingtalk / feishu / wecom |
| `WEBHOOK_INTERVAL_SECONDS` | `30` | 通知扫描周期 |
| `WEBHOOK_LINK_BASE` | 空 | 控制台链接前缀 |
| `WEBHOOK_MIN_SEVERITY` | `0`（全推） | 通知最低严重度（1 信息 ~ 5 严重） |

采集端环境变量见 [collection.md](collection.md)（agent 与 sensor 各一张表）。
