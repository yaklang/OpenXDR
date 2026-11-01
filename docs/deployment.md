# 部署与使用手册

从单机试用到接入主机、开启检测与处置的完整操作说明。设计原理见 [architecture.md](architecture.md)，
跨宿主机高可用部署见 [deploy/ha](../deploy/ha/README.md)，AI 助手与巡检任务见 [pi-backend.md](pi-backend.md)。

## 启动与初始配置

```bash
# 启动 JetStream + Postgres + server + web
docker compose up -d
# 界面: http://localhost:5173   API: http://localhost:8080   gRPC 接入: 8081
```

数据库表由 server 启动时自动创建，无需手动迁移。

首次启动会创建 `admin` 账号：密码取 `ADMIN_PASSWORD` 环境变量，
未配置则随机生成并打印在 server 日志里（`docker compose logs server | grep admin`）。
登录后可在界面里建号，角色三档：admin（用户管理）/ analyst（研判与处置）/ viewer（只读）。
所有登录与处置操作都有审计日志，admin 可在界面查看。

启用告警通知：admin 在控制台「系统设置 → 通知」填入 IM 机器人地址，点「发送测试」确认收到后保存。
飞书、钉钉和企业微信还会检查 JSON 回执中的业务状态码，非零、缺失或坏回执均视为失败；
incident 通知失败不会标记已投递，下周期重试。generic Webhook 仅按 HTTP 2xx 确认接收，不能代替群内人工确认。
飞书回执字段参见[官方自定义机器人文档](https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot)。
研判后的事件、主机失联与恢复、巡检报告都推到这里。benign 判定不推（AI 说是噪声的不打扰人），
但高危及以上照推并标注「需人工复核」。格式支持 generic / dingtalk / feishu / wecom。
也可以用环境变量给出首次部署的默认值，控制台保存过之后以控制台为准：

```bash
WEBHOOK_URL=https://oapi.dingtalk.com/robot/send?access_token=... \
WEBHOOK_FORMAT=dingtalk \
WEBHOOK_LINK_BASE=http://<控制台地址>:5173 \
docker compose up -d
```

启用 AI 研判（不配置则只做规则告警和关联，不调用模型）：

```bash
AI_MODEL=qwen3 docker compose up -d   # 默认接本机 Ollama
```

研判是**主动调查**式的：模型可以调用工具检索原始事件、追进程血缘、
查主机告警前科，像分析师一样查证后再定性（最多 6 轮）。模型不支持
tool calling 时自动退化为单轮研判，无需配置。

刻意不做自然语言到 SQL 的翻译——工具的参数空间受限且已转义，模型再怎么发挥
也越不出这个边界。想用自然语言追问数据（「最近有没有主机连过这个 IP」）时用
「AI 助手」：它按组的只读视图查库、在主机上执行命令，高风险命令要组管理员批准。

也可以接任意 OpenAI 兼容端点，包括自建的私有化部署：

```bash
AI_BASE_URL=http://<推理服务>/v1 \
AI_MODEL=<模型名> \
AI_API_KEY=<密钥> \
AI_TIMEOUT_SECONDS=300 \
docker compose up -d
```

推理服务在内网时注意 `NO_PROXY`：Go 默认读取 `HTTP_PROXY` 环境变量，
若部署环境设了代理，内网端点的请求会被错误地转发出去。

实测接入自建 DeepSeek-V4-Flash（6× RTX 5090，vLLM）：单个 incident 研判
5–13 秒，模型能从事件图里读出父进程并给出可执行的处置建议。推理型模型返回的
`reasoning_content` 不影响解析，引擎只取 `content` 里的 JSON。

### 添加主机

已有运维文档时，可从资产页「从文档导入」识别主机地址、账号密码或私钥，预览确认后
按组保存资产和加密凭据，再单独发起 SSH 纳管。格式、权限和配置见
[文档导入与主机纳管](host-enrollment.md)。

在控制台「资产 → 添加主机」选好组，复制安装命令到被监控主机上执行：

```bash
# Linux（root）
curl -fsSL https://<控制台>/api/enroll/install.sh | sudo sh -s -- https://<控制台> <接入令牌>
# Windows（管理员 PowerShell）
& ([scriptblock]::Create((irm https://<控制台>/api/enroll/install.ps1))) https://<控制台> <接入令牌>
```

控制台必须是主机信任其证书的 HTTPS 地址：脚本、agent 与令牌都经它传输，明文会被中间人
篡改成任意代码以 root 执行。非 HTTPS 访问时控制台不给出安装命令，脚本也会拒绝运行。
失败时脚本原样打印 server 给出的原因（令牌无效、主机名已有在线 agent 等）；
新私钥在签发成功前只暂存，失败的重装不会破坏已安装主机的身份。

脚本会下载 agent、在本机生成私钥并由 server 签发主机绑定证书、写好配置、注册为
systemd 服务（Windows 为 SYSTEM 身份的开机计划任务）。主机自动进入令牌所属的组，
当晚就会出现在每日巡检报告里。令牌按组签发、默认 7 天有效
（最长 30 天）、有效期内可批量装机、随时可撤销。已有在线 agent 的主机名不能被
重复接入，令牌也不能把别组的主机改到本组。

之后不用再登录主机升级：把新版安装包放进 server 的 `AGENT_DIST_DIR`，在线 agent 下次重连
（server 滚动发布时就会重连）会经已认证的 gRPC 通道下载、校验哈希、自检能运行后替换自己并重启，
旧版保留为 `openxdr-agent.prev`。分发目录里放的是哪个版本，整片主机就收敛到哪个版本；
`AGENT_AUTO_UPGRADE=false` 关闭。资产详情里能看到每台主机的 agent 版本。

server 侧需要三样东西才会开放在线接入（缺哪样控制台会直接说明）：

- `ENROLL_GRPC_URL`：主机上能访问到的 gRPC 地址，如 `https://xdr.internal:8081`
- 开了 mTLS 时：`TLS_CA_KEY_FILE` 指向 CA 私钥（gencerts 生成的 `ca.key`），用于签发主机证书。
  `TLS_CA_FILE` 可以是多张 CA 的信任包，签发用其中与私钥配对的那张、下发给 agent 的是整个信任包——
  原 CA 私钥丢失时另起一张接入 CA 追加进信任包即可，已有证书不受影响
- `AGENT_DIST_DIR`（compose 已挂 `./dist`）里放采集端安装包：
  `openxdr-agent-linux-amd64`、`openxdr-agent-linux-arm64`、`openxdr-agent-windows-amd64.exe`，
  以及流量探针 `openxdr-sensor-linux-amd64`、`openxdr-sensor-linux-arm64`（官方镜像已内置以上全部）

流量探针（sensor）走同一套在线接入：平台管理员在「添加主机」切到「流量探针」签发令牌（组 admin 签不了——
探针的会话会按地址归到任何组的资产上），在探针主机上执行
`curl -fsSL <控制台>/api/enroll/sensor-install.sh | sudo sh -s -- <控制台> <令牌> <抓包网卡>`。
不带网卡只列出本机网卡后退出。证书 CN 为 `sensor:<主机名>`，只能进探针通道；同样按 `AGENT_DIST_DIR` 里的版本自动升级，
旧版保留为 `openxdr-sensor.prev`。抓包状态在资产详情的「流量探针」卡片里，异常走「主机采集异常」通知。
细节见 [采集端详解](collection.md#接入升级与抓包状态)，给 AI agent 的安装步骤见 [安装](install.md#放一台流量探针可选)。

也可以手工构建部署：

```bash
# 端点 agent（Linux 需 root 才能用 eBPF，否则自动回落轮询采集）
cd agent && cargo build --release
sudo OPENXDR_SERVER=http://<server>:8081 ./target/release/openxdr-agent

# 流量探针（需 root，网卡接核心交换机镜像口或反代网关的公网口；生产用上面的在线接入）
cd sensor && cargo build --release
sudo env SENSOR_IFACE=eth0 OPENXDR_SERVER=http://<server>:8081 ./target/release/openxdr-sensor
```

探针有两个抓包后端，用 `SENSOR_BACKEND` 切换：

| 后端 | 说明 |
|---|---|
| `afpacket`（默认） | AF_PACKET v3 零拷贝环 + FANOUT 按流哈希。任何 Linux 都能跑，不挑驱动，收发双向都能看到 |
| `afxdp` | 绕过协议栈，吞吐更高。需 `--features xdp` 构建、驱动支持，进程会在网卡上挂载 XDP 程序；**只能看到入向流量**，镜像口场景够用 |

`SENSOR_WORKERS` 决定并行度。afpacket 下多个 worker 共享 FANOUT 组；afxdp 下
worker 号即网卡队列号，数量不应超过网卡实际队列数。`SENSOR_GRPC_COMPRESSION=gzip`
让上行 gRPC 消息走 gzip（默认关闭，server 侧已注册编码器，清空该变量重启即回滚）。

### 按主机下发采集配置

采集范围不必编译期写死，可按主机调整：

```bash
curl -X PUT http://localhost:8080/api/assets/<asset-id>/config \
  -H 'Content-Type: application/json' -b cookie.txt \
  -d '{"fileWatchDirs": ["/srv/app", "/opt/secrets"], "collectAuth": false}'
```

配置随 agent 下次注册生效——agent 断线重连本就会重新注册，因此没有
单独的热更新通道。坏配置一律退回内置默认：让 agent 变瞎比配置不生效严重得多。

### 采集方式

内核态（零环）始终是可选项，用户态（三环）也能完整工作：

| 层次 | 方式 | 覆盖 | 前提 |
|---|---|---|---|
| 零环（可选） | Linux eBPF tracepoint | 全部 exec/exit，内核直接给出路径；TCP 出站连接 | `--features ebpf` + root |
| 三环（默认） | Linux netlink proc connector | 全部 exec/exit 通知，信息从 /proc 现补 | CAP_NET_ADMIN + 初始 pid 命名空间 |
| 三环 | Windows ETW | 进程启动与退出事件 | 管理员 |
| 三环（兜底） | 进程表轮询 | 每秒快照，漏短命进程 | 无 |
| 三环（并行） | Linux fanotify / inotify | 敏感文件变更（cron、sudoers、SSH 密钥、systemd 单元等），fanotify 路径带进程上下文 | 无（fanotify 需 CAP_SYS_ADMIN，不足自动退 inotify） |
| 三环（并行） | Windows ReadDirectoryChangesW | 敏感目录文件变更（drivers/etc、config 等） | 无 |
| 三环（并行） | Windows 快照 diff | 注册表自启动键（Run/RunOnce/Winlogon）、Startup 目录、服务与计划任务 | 无 |
| 三环（并行） | Linux wtmp/btmp | 登录成功与失败事件，认证可见性不依赖 syslog | 可读 /var/log/btmp |
| 三环（并行） | Windows Security 日志 | 4624/4625 登录成功与失败（含状态码） | 管理员或 Event Log Readers |

netlink 在**容器或 WSL2 里不可用**：proc connector 报的是初始 pid 命名空间的
pid，在嵌套命名空间中对不上本地 /proc，采出来全是错 pid、空进程名的垃圾。
agent 启动时会检测命名空间并主动退回轮询——宁可弱一点，也不产出假数据。

采集端默认构建**不依赖任何外部二进制**——protoc 随 crate 分发，`cargo build` 直接可用。
内核级采集是可选特性，开启后才需要 nightly 工具链：

```bash
rustup toolchain install nightly --component rust-src
cargo +nightly install bpf-linker

cargo build --release --features ebpf   # agent：Linux eBPF 采集
cargo build --release --features xdp    # sensor：AF_XDP 后端
```

不开这两个特性时，agent 走 netlink proc connector（失败再退轮询）、sensor 走 AF_PACKET，功能完整只是精度和吞吐低一些。

## 日志接入

server 内置 syslog 接收（同端口 UDP + TCP，RFC3164 与 RFC5424 都支持），
配置 `SYSLOG_ADDR` 启用：

```bash
SYSLOG_ADDR=:514 docker compose up -d

# 被监控主机把日志转发过来
echo '*.* @<server>:514' >> /etc/rsyslog.conf && systemctl restart rsyslog
```

日志按主机名归属资产，主机名对不上时退回源 IP 匹配，两者都对不上则归入
统一的未归属 incident。同一主机反复报同一条日志只留一行告警并计数。

规则里用 `logsource.category: application` 匹配这类事件，字段路径见
`rules/lnx_ssh_auth_failure.yml`。

## 威胁情报

内置 IOC 库：恶意 IP / 域名 / 文件哈希。三路事件（EDR / NTA / 日志）入库时
自动与情报碰撞，命中即产生告警，走与规则告警相同的去重、抑制与关联链路。
域名情报按后缀匹配，`evil.com` 能撞上 `c2.evil.com` 的 DNS 查询、TLS SNI 与 HTTP Host。
哈希情报撞的是 agent 随进程事件上报的 exe SHA-256（同一二进制只算一次，缓存按 mtime 失效）。

**情报订阅**：内置 abuse.ch Feodo Tracker（僵尸网络 C2 IP）、ThreatFox
（近期恶意软件 IP / 域名 / 哈希）、URLhaus（恶意软件分发域名）与 Emerging Threats
（失陷主机 IP）四个公开源，默认全部开启，server 单活每 `INTEL_FEED_INTERVAL_HOURS`
（默认 6）小时拉取一次。内网与保留地址不入库；ThreatFox 的 URL 只收主机是 IP 的，
挂在 GitHub 之类公共平台上的恶意 URL 若按主机名入库会误伤正常访问。手工录入的同值情报
优先；源里撤下的条目约两天后到期失效，关掉的源立即清空。在「威胁情报」页可逐个开关、
立即同步，并直接看到哪些订阅情报命中过。server 需要能访问这些源（可经 `HTTPS_PROXY`）。

ThreatFox 与 URLhaus 需要 abuse.ch Auth-Key。在「系统设置 → 外部情报查询」保存密钥，
或设置 `ABUSE_CH_AUTH_KEY`；控制台保存的值优先，清空后不再回退环境变量，点击恢复默认才重新使用环境变量。
密钥通过 `HOST_CREDENTIAL_KEY` 加密入库，接口只显示是否配置及末四位；认证下载地址不回显、不写入日志，且不跟随重定向。
未配置时明确提示配置密钥，不再请求已停用的匿名地址。Feodo 与 Emerging Threats 不需要这项密钥。
配置后在威胁情报页执行「立即同步」确认实际可用性；测试通过不代表账号具有源的下载权限。
官方说明：[ThreatFox 导出](https://threatfox.abuse.ch/export/) 与 [URLhaus API](https://urlhaus.abuse.ch/api/)。


界面上（威胁情报入口）还可直接粘贴清单批量导入：一行一条，类型自动识别，
重复条目跳过。每条情报持续累计命中次数——长期零命中的陈年 IOC 应当清理，
默认可设有效期到期自动失效。也可通过 API 对接情报源：

```bash
curl -X POST http://localhost:8080/api/intel/import \
  -H 'Content-Type: application/json' -b cookie.txt \
  -d '{"text": "6.6.6.6\nevil.example.com", "source": "feed-x", "expiresInDays": 30}'
```

## 误报抑制

分析师把事件标记为误报后，可以顺手把噪声源掐掉：抑制指定规则在指定主机
（或全部主机）上的告警。抑制后事件照常入库，只是不再产生告警——证据不丢，
只是不再打扰人。

抑制从不静默：每条抑制规则持续累计被压掉的次数，可在抑制清单里看到并随时撤销。
默认带有效期，避免抑制规则无限积累后悄悄吃掉真实告警。

## 响应处置

检测到攻击后可以直接下发处置指令：**结束进程**、**隔离主机**、**解除隔离**。
指令走 agent 主动连出的双向通道，被监控主机不需要开监听端口。

这是系统里唯一能对主机造成实际影响的功能。指令一律真执行，没有演练模式，闸门默认全开：

| 闸门 | 行为 |
|---|---|
| 全局开关 | `RESPONSE_ENABLED` 默认 false，不开则一律拒绝下发 |
| 隔离自保 | 未配置 `ISOLATION_ALLOW` 时 agent 拒绝隔离——隔离后收不到解除指令只能人工上机 |

```bash
RESPONSE_ENABLED=true ISOLATION_ALLOW=<server>:8081 docker compose up -d
```

每条指令连同下发者、执行结果一并落库，可在事件详情页查看。
隔离在 Linux 用 nftables 独立表实现（不触碰主机原有规则），Windows 使用独立 WFP 子层：管理端点许可优先于本子层的默认阻断，规则以事务原子更新并持久化。
Windows 放行地址必须为数字 IP 或 IP:端口（IPv6 为 `[地址]:端口`），最多 128 项；
解除隔离同时清理旧版 `OpenXDR-Isolation-*` 规则。部署前需在有本地控制台的 Windows 测试机
验证隔离、管理通道重连、解除隔离及 Agent 重启后的行为。

结束进程必须携带采集事件中的 `processGuid` 和 `pid`，Agent 同时校验 GUID 与创建时间，
通过 Linux pidfd（需内核支持）或 Windows 进程句柄执行，身份不明时拒绝，绝不退回裸 PID。
指令通道独立断开时会每 5 秒重连；所有动作均不自动重放，避免过期的隔离/解除意图再次生效。
跨节点确认丢失记录为 unknown；重新操作前需检查原指令记录与主机实际状态。
能证明没下发的瞬断（no responders、旧连接拒收）会在 server 内部有界重试约 5 秒，见 [集群](cluster.md#选主瞬断)。

## ATT&CK 覆盖

规则的 Sigma `tags` 会被解析成 ATT&CK 战术与技术，界面「检测规则 → ATT&CK 覆盖」标签按
杀伤链顺序出矩阵。空列就是检测缺口，不是排版问题。

矩阵还会标出**有规则但无数据源**的格子——纸面覆盖率与真实覆盖率的差额，
这是挂载大规则库后最容易自欺欺人的地方。

覆盖率不靠自我感觉：`validation/` 下是攻击手法的真实命令行语料，
`go run ./cmd/detectcheck` 回放过引擎，验证规则真能抓住 Atomic Red Team
实际执行的命令，且命中的规则标了对应技术。CI 每次都跑，规则改动
导致检测退化会直接失败。

## 导入社区规则

规则引擎兼容 Sigma，可直接挂载 [SigmaHQ](https://github.com/SigmaHQ/sigma) 规则库：

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma.git
RULES_PATH=sigma/rules docker compose up -d

# 导入前先看兼容情况
cd server && go run ./cmd/sigmacheck ../sigma/rules
```

对 SigmaHQ 3141 条规则的实测：**加载 2149 条（68.4%）**，其中 1393 条有现成数据源可命中，
其余等待对应遥测接入（文件、模块加载、HTTP）。未加载的主要是我们不采集的数据源
（注册表、PowerShell 脚本块、云平台审计日志）。

引擎对拿不准的规则一律拒绝加载而不是降级处理——用了未实现修饰符（如 `|cidr`）的规则
如果被当成普通字符串匹配，`condition: not selection` 这类规则会对每个事件误报。
同理，Windows 规则不会在 Linux 资产的事件上求值。

## 启用 mTLS

采集端与 server 之间默认是明文，仅适合本机调试。生产部署必须开双向认证：

```bash
cd server && go run ./cmd/gencerts ../certs <server 的域名或 IP>

# server
TLS_CA_FILE=certs/ca.crt TLS_CERT_FILE=certs/server.crt TLS_KEY_FILE=certs/server.key ...

# agent / sensor（注意地址是 https）
OPENXDR_SERVER=https://<server>:8081 \
OPENXDR_CA=certs/ca.crt OPENXDR_CERT=certs/client.crt OPENXDR_KEY=certs/client.key ...
```

三个变量必须同时配置，只配一部分会直接报错而不是悄悄降级成明文。
目录里已有 `ca.crt`/`ca.key` 时 gencerts 沿用这个 CA 只签新证书，不会让已发出的证书失效。

通用 client 证书所有采集端共用，持证者可以冒充任何主机上报。给 agent 逐台发
绑定证书可以消除这一点（sensor 用在线接入签发的 `sensor:<主机名>` 证书，同样只能以本机身份上报、进不了 agent 通道）：

```bash
# 在通用证书之外，为 web01、db01 各签一张身份绑定的证书
go run ./cmd/gencerts ../certs <server 地址> web01 db01

# web01 上的 agent 用自己的证书，server 会强制它只能以 web01 的身份注册、上报、接收指令
OPENXDR_CERT=certs/agent-web01.crt OPENXDR_KEY=certs/agent-web01.key ...
```

绑定是证书自身的属性（CN 前缀 `host:`），失陷主机拿自己的证书冒充不了别人。

## 配置

server 全部通过环境变量配置，均有默认值：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `DATABASE_URL` | `postgres://openxdr:openxdr@localhost:5432/openxdr?sslmode=disable` | 数据库连接串 |
| `NATS_URL` | 空（单机直连） | NATS 地址；配置后启用 JetStream 持久队列，多个地址用逗号分隔 |
| `QUEUE_SHARDS` | `32` | 事件一致性分片数；同一资产保持有序 |
| `QUEUE_BATCH_SIZE` | `1` | 同资产批消息最大事件数（1..64）；全部服务端升级到支持批消息的版本后可设为 64。仍保持每分片一条在途消息，整批原子提交；单个批消息不超过 256 KiB，超大单事件保持原格式。 |
| `QUEUE_REPLICAS` | `1` | JetStream stream 副本数；三节点生产集群设为 3 |
| `QUEUE_MAX_BYTES_GB` | `20` | 事件 stream 最大磁盘占用 |
| `QUEUE_MAX_AGE_HOURS` | `0` | 必须为 0；未处理消息不自动过期，容量满则拒收新消息 |
| `LOG_FORMAT` | 空（text） | 设为 `json` 输出结构化日志 |
| `LOG_LEVEL` | `info` | debug / info / warn / error |
| `RULES_PATH` | `../rules` | Sigma 规则目录 |
| `IDENTITY_RUN_RETENTION_DAYS` | `30` | 目录终态运行记录保留天数，0 关闭历史删除，范围 0–3650；每来源最新记录保留，过期运行回收不受此开关影响 |
| `IDENTITY_SOURCES_JSON` | 空（关闭） | 多目录只读账号同步（keycloak / entra / authentik / ad / ldap），严格 JSON 数组；凭据通过环境变量名引用，组须已存在，配置后重启生效。见 [身份来源配置](identity-correlation.md#启动配置与定时同步) |
| `TEMPORAL_RULES_PATH` | 空（关闭） | 时序规则独立目录；配置后与基础规则整批严格加载，共用 RULES_RELOAD_SECONDS 重载周期。生产建议指向版本目录的符号链接（`current → v-<版本>`，版本目录需带 `SHA256SUMS`），切换链接即原子发布；同时启用过期候选单活清理。容器使用容器内路径，需额外挂载；见 [时序检测](temporal-detection.md#不可变版本目录发布) |
| `RULES_RELOAD_SECONDS` | `30` | 规则目录变更检测周期，变更自动热重载；0 关闭 |
| `TASKS_PATH` | `../tasks` | 预设任务 YAML 目录；配置了 Pi 模型（`PI_MODEL` 或控制台）才运行，见 [Pi 后端](pi-backend.md#预设任务) |
| `SCHEDULE_INTERVAL_SECONDS` | `30` | 任务到期检查与 YAML 重载周期 |
| `SCHEDULE_SPREAD_MINUTES` | `15`（0 关闭） | 同一任务按组展开时的错峰窗口：每组在计划时间后固定偏移 hash(任务, 组) 秒开跑，窗口不超过任务周期的 1/4。15 分钟足够把十来个组拉开，每日巡检最晚 10:15 前开跑，仍在同一个上午；见 [Pi 后端](pi-backend.md#错峰与并发上限) |
| `SCHEDULE_MAX_RUNNING` | `1` | 全集群同一时刻运行中的定时任务会话上限，按库里 `kind=task` 的运行中会话计，人发起的对话不计入；超出的排队，排满一个周期仍没轮到就跳过并记 `skipped`。默认 1：两个巡检并行就曾把共用端点的每轮推理从 5–17 秒拖到平均 98 秒、双双超时；端点能并行推理再调大 |
| `CHROMIUM_PATH` | `chromium` | 报告 PDF 渲染用的 headless Chromium，server 镜像已内置 |
| `HTTP_ADDR` / `GRPC_ADDR` | `:8080` / `:8081` | 监听地址 |
| `ALERT_DEDUP_WINDOW_MINUTES` | `5` | 告警去重窗口 |
| `CORRELATE_WINDOW_MINUTES` | `30` | 关联时间窗 |
| `CORRELATE_MAX_GRAPH_NODES` | `500` | 单个事件图节点上限 |
| `CORRELATE_RECUR_HOURS` | `24`（0 关闭） | 同资产同规则同实体的复发并回未结案事件的最长跨度（从事件创建起算） |
| `CORRELATE_RECUR_COARSE` | `1` | 进程类告警的复发再按粗键归并：同用户、同父进程映像、同映像，命令行不同也并；解释器与命令包装器仍只按完整命令行，首次出现（`xdr:new-process`）按主机+用户+父进程并。0 关闭 |
| `AI_MODEL` | 空（不启用） | 事件研判与资产标注的模型名。**`AI_*`、`PI_MODEL`、`VT_API_KEY`、`IPINFO_PTR`、`VT_ALERT_MIN_ENGINES` 也能在控制台「系统设置 → AI 模型 / 外部情报」里改**，保存过的项以控制台为准、十几秒内全集群生效，环境变量只是首次部署的默认值；控制台保存的密钥用 `HOST_CREDENTIAL_KEY` 加密，没配这把钥匙时只能用环境变量提供密钥 |
| `AI_TEMPLATE_NO_THINKING` | `false` | 自部署 vLLM 使用无法识别的模型名（如 `/model`）时设为 `true`，对请求关闭思考的调用同时发送 `thinking=false` 与 `enable_thinking=false` 模板参数。已识别模型沿用原协议；不影响未请求关闭思考的调用。仅支持环境变量，修改后需重建 server 容器；单机、安装版、HA 与 cluster Compose 均透传 |
| `AI_BASE_URL` | `http://localhost:11434/v1` | OpenAI 兼容端点 |
| `AI_RETRIAGE_COOLDOWN_MINUTES` | `30` | 已研判的事件又并入普通新证据时，距上次研判至少隔这么久才重研判，冷却期内的新告警到期一次带上；级别升高或头一回出现情报命中、凭据窃取等高危类告警时不等。默认 30：生产上被系统例行变更反复并入的事件每几分钟来一批告警，不限流时一天能被重研判几十次、把慢模型的研判名额占满；30 分钟把它压到每小时至多两次，又不至于让真实攻击的后续动作晚太久才被重新定性（升级类本来就立即重判）。只认环境变量，控制台不可改 |
| `SYSLOG_ADDR` | 空（不启用） | syslog 监听地址，如 `:514`。UDP 与 TCP 同时监听 |
| `SUPPRESSION_RELOAD_SECONDS` | `30` | 抑制规则重载与命中计数回写周期 |
| `INTEL_RELOAD_SECONDS` | `30` | 威胁情报重载与命中计数回写周期 |
| `WEBHOOK_MIN_SEVERITY` | `0` | 低于该级别的事件不推送（1 信息 ~ 5 严重），0 表示全推。控制台保存过通知配置后以控制台为准 |
| `AGENT_SILENT_MINUTES` | `10` | agent 指令通道超过该时长没有心跳即判失联并通知，恢复时再通知一次 |
| `HOST_CREDENTIAL_KEY` | 空 | 文档导入凭据的 AES-256-GCM 密钥，base64 编码 32 字节；HA 节点必须一致。也是系统集成的前提：集成 API 游标密钥由它派生，Webhook 签名密钥用它加密 |
| `INTEGRATION_WEBHOOK_ALLOW` | 空（用控制台） | 可选锁定值：事件推送内网放行清单（逗号分隔的精确域名/CIDR）。配置后控制台「内网推送放行」只读，见[外部系统集成 API](#外部系统集成-api) |
| `ENROLL_SSH_ENABLED` | `false` | 允许组管理员使用保存凭据进行 SSH 纳管 |
| `DECOY_SSH_ENABLED` | `false` | 允许组管理员通过已保存凭据安装 Linux 专用诱饵；要求 systemd 250+、独立核对的 SSH 指纹、凭据加密密钥与 HTTPS `ENROLL_PUBLIC_URL` |
| `DECOY_DIST_DIR` | 镜像中 `/opt/openxdr/decoy-dist`，裸机为空 | 诱饵静态 ELF 安装包目录，固定文件名 `decoyhost-linux-amd64` / `decoyhost-linux-arm64`；不接受用户提供的下载地址 |
| `ENROLL_PUBLIC_URL` | 空 | 被纳管主机可访问的可信 HTTPS 控制台地址 |
| `ENROLL_GRPC_URL` | 空（不启用在线接入） | 写进 agent 配置的 gRPC 地址，主机上必须能访问 |
| `TLS_CA_KEY_FILE` | 空 | CA 私钥，开了 mTLS 时在线接入用它签发主机证书 |
| `AGENT_DIST_DIR` | 空 | agent 与 sensor 安装包目录，供安装脚本下载，也是在线 agent / sensor 自动升级的目标版本 |
| `AGENT_AUTO_UPGRADE` | `true` | 在线 agent / sensor 与安装包哈希不同时自动升级，`false` 同时关闭两者 |
| `SENSOR_GRPC_COMPRESSION` | 空（关闭） | 探针侧变量：设为 `gzip` 时 sensor 上行 gRPC 消息（注册、状态、会话批量上报）压缩，默认关闭，清空后重启即回滚；先升级 server 再开（server 始终能解压），只改线上字节，事件内容与身份不变 |
| `TRUSTED_PROXIES` | 空 | 可信反向代理的地址或网段（逗号分隔）。只有来自这些地址的请求才采信 `X-Forwarded-For`，从右往左取第一个不可信地址作为客户端，登录退避与审计按它记来源；留空不还原 |
| `ABUSE_CH_AUTH_KEY` | 空 | ThreatFox / URLhaus 认证导出密钥，可在「系统设置 → 外部情报查询」加密保存 |
| `INTEL_FEED_INTERVAL_HOURS` | `6` | 情报订阅同步周期（小时），订阅条目有效期为它的 8 倍 |
| `RESPONSE_ENABLED` | `false` | 是否允许下发响应指令；开启后人工处置、Pi 命令、定时任务与自动响应下发的指令都会真执行 |
| `ISOLATION_ALLOW` | 空 | 隔离主机时放行的地址，必须包含 server 的 gRPC 端点 |
| `AUTO_RESPONSE_ENABLED` | `false` | AI 研判高置信度 malicious 时真实隔离涉事主机（依赖 `RESPONSE_ENABLED`，每次决策落审计） |
| `AUTO_RESPONSE_MIN_CONFIDENCE` | `90` | 触发自动响应的置信度门槛 |
| `AUTO_RESPONSE_EXEMPT` | 空 | 逗号分隔的主机名，绝不自动隔离 |
| `UEBA_LEARNING_DAYS` | `7` | 首次出现检测的按资产学习期 |
| `BEACON_ENABLED` | `1` | 外联心跳检测（新出现的规律公网外联），0 关闭 |
| `COLLECTOR_DROP_ALERT` | `1000` | 一分钟内丢弃这么多事件就推「采集异常」，0 不看丢事件；采集器降级或缓存写不进去照常推送 |
| `PI_HISTORY_FOLD_KB` | `64` | Pi 会话历史超过这么多 KB 时折叠较早的工具结果再发给模型，0 不折叠 |
| `VULN_SYNC_HOURS` | `24` | 漏洞库（OSV）同步周期，0 关闭 |
| `VULN_OSV_URL` | `https://osv-vulnerabilities.storage.googleapis.com` | OSV 下载地址，可指向内网镜像 |
| `VULN_DIR` | 空 | 离线漏洞库目录（放 `Debian.zip`、`Ubuntu.zip`），设置后不联网 |
| `BEACON_LEARNING_DAYS` | `7` | 外联心跳学习期，按资产接入时间算；首次启用回放这段历史只学不报 |
| `RETENTION_DAYS` | `30` | 原始事件保留天数，0 表示不清理。被告警引用的证据事件不受影响。events 是分区表时按日分区整体退役（老库迁移见 [event-partitioning.md](event-partitioning.md)） |
| `TEMPORAL_GAP_RETENTION_DAYS` | `30` | 时序求值缺口（`temporal_evaluation_gaps`，诊断记录）按自身产生时间的保留天数，0 关闭，与 `RETENTION_DAYS` 相互独立。冷归档 swap 移出热表的事件的 gap 不随退役/删除清理，由 janitor 按此保留期清理（见 [event-archive.md](event-archive.md#105-派生状态决策表)） |
| `EVENT_ARCHIVE_READ` | 空（关闭） | 设为 `1` 时 `/api/events` 与 related/explain 调查入口读冷块（`event_archive_chunks`）并合流，冷查询按组权限过滤；响应体是对象契约 `{items, truncated, coverage}`，覆盖缺口（关键词不搜冷块、冷读关闭、扫描预算耗尽等）如实写进 `coverage.reason`，调试头 `X-Archive-Coverage` 只是摘要。开启时启动先确保冷归档表存在，建表失败只降级为「没有冷层」。生产归档仍要手工跑 `eventarchive` CLI（见 [event-archive.md](event-archive.md)）。**运营不变式：一旦用 `eventarchive swap` 切走分区，这个变量必须为 `1`**——已有切走数据的部署不能靠关闭读取变成「查询完整」，缺口还在，只是不再被声明 |
| `EVENT_ARCHIVE_DEDUP` | 空（关闭） | 设为 `1` 时接入路径在「事件时间不晚于归档边界」时按 ID 查冷层（`eventarchive.Exists`），命中就按重复处理：不入库、不重新检测、不产告警。归档边界有 60 秒缓存，逐条事件不查库；冷层故障时 fail-open（照常入库并继续检测），失败计入 `openxdr_archive_dedup_failopen_total{stage}` 并限流记日志。与 `EVENT_ARCHIVE_READ` 相互独立。**运营不变式：一旦用 `eventarchive swap` 切走分区，这个变量必须为 `1`**，否则迟到/重传的老事件会重新入库并重复告警（详见 [event-archive.md](event-archive.md#1010-重传判重接线event_archive_dedup)） |
| `EVENT_ARCHIVE_MIN_AGE_DAYS` | `14` | `eventarchive swap` 切换闸门的运营下限（天）：待切**日结束**必须早于 `现在 − 有效下限`。有效下限取各项最大：本值、temporal 安全边界（max(时序规则实际窗口, 24h) + 迟到余量 + 处理余量）、beacon 回读窗口（仅口径含 4001/agent）、assetmap 无游标回填 7 天（仅口径含 4001/5001/5020）。设了但不是合法非负天数时 swap 直接报错，不静默退默认；本值只是运营纪律，正确性来自有效下限与消费者追平证明（见 [event-archive.md](event-archive.md#103-p4-切换闸门min-age-有效下限与消费者追平)） |
| `IPDB_DIR` | 空（镜像内 `/opt/openxdr/ipdb`） | 离线 IP 归属库目录（DB-IP Lite 的 `dbip-asn-lite.mmdb`、`dbip-country-lite.mmdb`，CC BY 4.0），本地查 AS 与国家、不外发地址；发版镜像自带一份，缺库时归属留空并在启动日志说明。用 `openxdr-ipdb -dir <目录>` 更新，替换后自动加载，见 [资产图谱](asset-map.md#离线归属库) |
| `IPINFO_PTR` | `true` | 对资产连过的与告警里出现的公网地址做反向解析（PTR），结果缓存，供图谱展示与 AI 标注认地址；内网没有外部解析时可设 `false` |
| `VT_ALERT_MIN_ENGINES` | `3` | VirusTotal 判恶意的引擎数达到该值，就把地址加入威胁情报（来源 virustotal，随缓存期到期），之后再有主机连它即按情报命中告警；重查后不再达到即失效，人工录入的同一地址不动；0 关闭 |
| `VT_API_KEY` | 空 | VirusTotal API key。配置后查询公网地址的归属、国家、恶意判定与历史解析域名；**会把资产连过的、告警里出现的公网 IP 发给 VirusTotal**，不配置则不查 |
| `VT_PER_MINUTE` / `VT_PER_DAY` | `4` / `500` | VirusTotal 查询限额（默认按免费额度），撞到 429 自动等下一分钟 |
| `IPINFO_TTL_DAYS` | `7` | 公网地址信息的缓存期（天），到期重查 |
| `ASSET_ANNOTATE_REFRESH_HOURS` | `24` | 资产 AI 标注的定时刷新周期（小时），0 表示只在事实变化或人工要求时标注；需配置 `AI_MODEL`，见 [资产图谱与攻击面](asset-map.md) |
| `AUTO_CLOSE_BENIGN_DAYS` | `7` | 未结案事件 AI 判良性、最高级别低于 4（高危）且创建超过 N 天时，每小时由系统按 `false_positive` 自动结案并记审计；0 表示关闭 |
| `FP_SUPPRESS_MIN_COUNT` | `5` | 误报统计：近窗口内同一规则在同一主机上被人判误报至少这么多次（采纳 AI 结案建议与系统自动结案不计入），且满足误报率、期间无属实时，生成待组管理员批准的抑制草案；0 关闭。口径见 [detection.md](detection.md#抑制serverinternalsuppress) |
| `FP_SUPPRESS_MIN_RATIO` | `90` | 误报率下限（%）：误报 /（误报 + 属实 + 未结案） |
| `FP_SUPPRESS_WINDOW_DAYS` | `30` | 统计窗口（天） |
| `FP_SUPPRESS_DAYS` | `30` | 草案建议的有效期（天，1–90），批准时从批准那一刻起算 |
| `AUTOMATION_AUTO_ENABLED` | `true` | 已知自动化的自动识别总开关；`false` 时不新识别、不续期，但照常按结论停用已识别的条目并通知。条件见 [detection.md](detection.md#自动识别) |
| `AUTOMATION_AUTO_WINDOW_DAYS` | `7` | 统计登录规律与告警结论的窗口（天） |
| `AUTOMATION_AUTO_MIN_DAYS` / `AUTOMATION_AUTO_MIN_LOGINS` | `3` / `20` | 窗口内至少几天有登录、共至少几次登录（天数不超过窗口） |
| `AUTOMATION_AUTO_AI_BENIGN` | `3` | 没有人工误报结论时，至少要几个 AI 判良性的事件（人工误报 1 个即可） |
| `AUTOMATION_AUTO_TTL_DAYS` | `30` | 自动识别的有效期（天，1–365），持续满足时续期 |
| `AUTOMATION_AUTO_INTERVAL_SECONDS` | `300` | 识别、续期与按结论停用的周期（秒）；非正数等不合理值退回默认 |
| `FP_SUPPRESS_COOLDOWN_DAYS` | `30` | 组管理员拒绝后，同范围或更宽的草案多久内不再生成（天） |
| `FP_SUPPRESS_INTERVAL_HOURS` | `6` | 统计周期（小时），多节点只在持有租约的节点上跑 |

AI 助手相关的 `PI_*` 变量见 [pi-backend.md](pi-backend.md#配置)；按包整理的完整清单见 [detection.md](detection.md#server-环境变量全清单servermaingo)。

## 外部系统集成 API

无需额外环境变量，只要求已配置 `HOST_CREDENTIAL_KEY`（安装脚本默认生成）。分页游标的签名密钥由它按用途派生，
集群各节点自然一致；更换主密钥只会让 1 小时内的旧游标失效，Token 仍由数据库中的摘要和到期/吊销状态验证。
没有主密钥时集成 API 返回 503，控制台也不签发 Token、不建订阅。

闸门在控制台：只有全局管理员能在「系统集成」创建并启用集成、配置负责人、授权组和 scopes、签发 Token；
没有启用的集成和有效 Token 就没有任何外部访问。不要把 Token 放进 URL。
接口与限制见 [API 文档](api.md#外部系统只读-api)，机器契约见 [OpenAPI](openapi/integration-v1.yaml)。
事件推送与工单回写分别要求管理员显式创建订阅、开启回写。

事件推送默认只允许公网 HTTPS 目标。内网工单系统在「系统集成 → 内网推送放行」里填精确域名或 CIDR，
保存即生效、各节点一致并记审计；环回、链路本地和元数据地址始终拒绝。需要把清单固定在部署配置里时，
设置环境变量 `INTEGRATION_WEBHOOK_ALLOW`（逗号分隔），它作为锁定值，控制台只读。
目标 URL 不得带 userinfo、查询参数或片段，不跟随重定向、不继承 HTTP 代理，
DNS 校验与实际拨号使用同一地址，TLS 证书必须有效。
所有节点可运行投递 worker，由数据库租约协调；暂停订阅或停用集成不会撤回已经发出的 HTTP 请求。

暂停订阅的消息原地保留，恢复后继续投递；停用集成会取消其未发消息。暂停积压超过
24 小时会转为 dead，管理员可在清理前重放；终态记录保留 30 天，未分发消息不按普通
保留期删除。幂等结果保留 7 天。回退旧二进制会中断事件覆盖，恢复后需通过 API 对账。

指标包含 `openxdr_integration_deliveries`（各状态数量）、
`openxdr_integration_oldest_pending_seconds`、`openxdr_integration_attempts_retained`
以及集成 API 的 429 计数。队列指标是数据库全局快照，跨节点采集应取 max 而不是求和；
尝试数量是保留期内的 gauge，不是永久累计 counter。


## 独立欺骗引擎统一启动

在原安装目录的 `.env` 中追加 `COMPOSE_PROFILES=dygk`，继续使用主 `docker compose up -d`。原有 profile 以逗号保留。引擎版本和运行身份由平台与受限控制通道自动登记、签发；控制台选择平台托管后无需再配置独立启动参数。

| 配置 | 默认 | 用途 |
| --- | --- | --- |
| `COMPOSE_PROFILES` | 未启用 DYGK | 包含 `dygk` 时随主编排启用引擎 |
| `DYGK_VERSION` | 安装编排 `latest`，源码编排 `local` | 独立引擎镜像标签，生产宜锁定 |
| `DYGK_BIND_IP` | `127.0.0.1` | 主编排预留端口的宿主绑定地址 |
| `DYGK_PORT_RANGE` | `18080-18179` | 站点端口范围；登记应选择对应端口 |
| `DYGK_SOURCE` | `local` | 构建源码来源，`local` 使用提供的源码，`remote` 才从锁定的远端版本拉取 |
| `DYGK_LOCAL_SOURCE` | `local-source` | 相对 `integrations/dygk/` 的源码目录；云端构建需在自己的模块构建上下文内提供 |
| `DYGK_UPSTREAM_TOKEN` | 空 | 仅远端私有源码需要的读取令牌，经 BuildKit secret 提供；本地模式和预构建镜像运行时无需设置 |

控制 socket 和持久目录由主编排注入命名卷，不是开发机路径；不要将引擎控制卷挂给其他服务。独立镜像的发布授权、云端接入与回退步骤见 [运行包说明](../integrations/dygk/README.md)。

源码来源在同一 `.env` 配置，默认本地模式，不调用 Git 或自动回退远端。默认 `local-source/` 是被 Git 忽略的私有构建输入，Docker 构建会使用它；`.downloads/` 和 `.upstream/` 缓存则同时被 Docker 排除。云端本地模式需提供源码到自身构建上下文，远端模式需具备上游读取权限，两者都核验文件摘要。预构建镜像已包含运行核心，启动时无需源码来源参数或读取令牌。具体配置、目录与打包范围见 [源码来源配置](../integrations/dygk/README.md#源码来源配置)。
