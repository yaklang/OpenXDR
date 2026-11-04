# OpenXDR — AI 代理工作指南

开源 XDR 平台：EDR + SIEM + 全流量分析，AI 驱动降噪。核心理念："一万条告警进，三个真事件出"。

本文面向接手本仓库的 AI 编码代理，汇总架构、构建、约定与验证方式。更详细的设计见
`docs/deployment.md`（部署、使用与配置）、`docs/`（文档系统，从 `docs/README.md` 索引进入：
架构 / 采集端详解 / 事件模型 / 检测链路 / REST API / 路线图）。注意 `ARCH.md` 是**目标架构讨论稿**，描述的是演进方向
（如 Redis/MQ、多网关），不代表当前实现——当前实现以代码和 `docs/` 为准。

## 架构与运行时

数据通路：采集端 → gRPC 接入 → 归一化（OCSF 风格）→ PostgreSQL → 规则/情报/UEBA 检测 →
去重/抑制 → 关联成 incident → AI 研判 → Web 前端 / Webhook 通知。

- **agent/**（Rust，crate 名 `openxdr-agent`）：端点采集，支持 Linux / Windows。
  进程采集（启动+退出）按可用性自动降级：eBPF tracepoint（可选特性，
  `--features ebpf`）→ netlink proc connector → ETW（Windows）→ 进程表轮询
  （兜底），另有并行的文件监控（Linux fanotify 优先 / inotify 递归兜底、
  Windows ReadDirectoryChangesW）、持久化点快照（注册表自启动 / 服务 /
  计划任务 / Defender Exclusions / IFEO / AppInit_DLLs / CLSID COM 劫持 /
  WMI 事件订阅）、登录/安全日志采集（wtmp-btmp / Security 4624-4625 登录、
  4720/4726/4732 账户管理、1102 日志清空、4648 显式凭据、4719 审计策略，
  以及 PowerShell Operational 4104 脚本块）、网络采集（Linux eBPF TCP 出入站与 UDP 出站 /
  Windows ETW Kernel-Network TcpConnect，进程归属，与 sensor 同构 conn_tuple）、
  DNS 采集（Linux AF_PACKET + 经典 BPF 只收 UDP 53，按源端口归属进程，回填出站域名）、
  容器归属（按 cgroup 认 docker / LXC / QEMU 等，事件带 container）
  与内核模块加载监控（Linux /proc/modules diff，class_uid=1005），以及设备清单
  （监听端口与属主进程、云厂商元数据，class_uid=5001，供资产图谱与攻击面）。
  容器或 WSL2 中 netlink 不可用，agent 会主动退回轮询——宁可弱采集也不产假数据。
- **sensor/**（Rust，crate 名 `openxdr-sensor`）：全流量探针，只出会话元数据不存 PCAP。
  双抓包后端：AF_PACKET v3（默认）与 AF_XDP（`--features xdp`，需驱动支持，仅入向）。
  协议解析：DNS 查询/应答、TLS SNI/JA3/JA3S 与证书元数据（仅 TLS ≤1.2，
  有界重组 16KB，`x509.rs` 迷你 DER 解析）、HTTP 头。
- **server/**（Go 1.26，module `openxdr/server`）：可单机或多节点运行。Ent ORM + PostgreSQL；
  NATS JetStream 提供按资产分片的持久事件队列，PostgreSQL 提供幂等、持久去重
  与后台任务租约，跨节点响应指令走 NATS request/reply；
  HTTP REST（:8080，会话 cookie 认证）与 gRPC（:8081，agent/sensor 接入 + 控制信道）。
  启动时自动建表（`client.Schema.Create`），无手动迁移；唯独 events 是按天分区表，由 `eventpart` 维护、
  ent 迁移不碰它（所有 `Schema.Create` 都要带 `eventpart.SchemaOption`），老库用 `cmd/eventpartition` 在线迁移。
- **web/**（React 19 + TypeScript + Vite，antd 6 + react-router + TanStack Query）：管理控制台，
  AI 助手为主入口，按路由懒加载页面。nginx 容器部署，端口 5173→80；本地开发 8080 被占时用
  `OPENXDR_API=http://localhost:<端口> npm run dev` 指定后端。
- **pages/**（React + Vite + Tailwind）：项目主页，仅由 `.github/workflows/pages.yml`
  部署到 GitHub Pages，与产品代码无关，改产品时不要动它。主页中英文自动切换约定见
  `pages/README.md`；改可见文案或无障碍文案时必须同时维护两种语言。
- **proto/**：`agent.proto` / `sensor.proto`，gRPC 契约。Go 侧生成代码已提交在
  `server/pb/`；Rust 侧由 build.rs 在构建时用 `protoc-bin-vendored` 生成（无需装 protoc）。
- **rules/**：Sigma 兼容检测规则（YAML）。Sigma `tags` 解析成 ATT&CK 战术/技术。
  `rules/sigmahq/` 是引入的 SigmaHQ 社区规则（DRL 1.1，保留作者；同步与回测流程见其 README）。
- **validation/**：检测验证语料——真实攻击命令归一化成事件格式，回放过规则引擎对拍。
- **schema/**：`001_init.sql` 是设计参考 DDL；实际表结构以 `server/ent/schema/` 为准。

## 构建与测试命令

Server（Go，工作目录 `server/`）：

```bash
go build ./...                              # 构建
gofmt -l .                                  # 格式检查（必须无输出）
go vet ./...                                # 静态检查
go test ./...                               # 单元测试
INTEGRATION_DATABASE_URL=postgres://openxdr:openxdr@localhost:5432/openxdr_test?sslmode=disable \
  go test -tags integration -p 1 ./...      # 集成测试（共享测试库，必须 -p 1 串行）
go run ./cmd/sigmacheck --strict ../rules   # 自带规则必须全部可加载
go run ./cmd/detectcheck --strict           # 检测回归对拍（validation/ 语料）
go run ./cmd/gencerts ../certs <server地址> [主机名...]   # 生成 mTLS 证书
```

采集端（Rust，工作目录 `agent/` 或 `sensor/`）：

```bash
cargo fmt --check
cargo build --locked
cargo clippy --all-targets -- -D warnings
cargo test
# 内核级采集是可选特性，需要 nightly + bpf-linker：
rustup toolchain install nightly --component rust-src && cargo +nightly install bpf-linker
cargo build --release --features ebpf   # agent 的 eBPF 采集
cargo build --release --features xdp    # sensor 的 AF_XDP 后端
```

Web（工作目录 `web/`）：`npm ci && npm run build`（`tsc -b && vite build`），
`npm run lint`（oxlint）。pages 同构：`npm ci && npm run build`。

整体部署：`docker compose up -d`（postgres + server + web；server 镜像以仓库根为
构建上下文，见 `server/Dockerfile`）。

## CI 关卡（.github/workflows/ci.yml）

提交前确保本地能过这些检查，CI 完全一致：

- server：gofmt、build、vet、单测、集成测试（带 Postgres service）、
  `sigmacheck --strict`、`detectcheck --strict`。
- agent / sensor：默认特性下 fmt / build / clippy(-D warnings) / test，arm64 原生 runner 上再跑一遍 build / clippy / test；
  另有 ebpf/xdp 特性的单独构建项，以及 agent 交叉编译到
  `x86_64-pc-windows-gnu` 的 clippy（Windows 侧 ETW 代码平时编不到，改
  `windows.rs`、`registry.rs` 等文件时注意 cfg 分支别破编译）。
- web：`npm run build`。容器镜像：server 与 web 的 Dockerfile 都要能构建。

发版（.github/workflows/release.yml）：推 `v*` 标签即编 agent（Linux amd64 / arm64 musl 静态 + eBPF、Windows）与 sensor（amd64 / arm64；arm64 在原生 arm runner 上编），
把 agent 安装包、默认规则与预设任务打进 server 镜像，推 `ghcr.io/yaklang/openxdr-{server,web}`（amd64 / arm64），
再建 GitHub Release（附 `deploy/install/` 的一行安装脚本与编排文件，说明取 `deploy/install/RELEASE_NOTES.md`
加 CHANGELOG 对应版本）。改安装流程时同步 `docs/install.md`，它也是给用户 AI agent 的安装说明。

## 代码组织（server/internal）

每个包职责单一，按处理链顺序排列：

- `grpcsvc`：gRPC 接入（agent/sensor 注册、事件上报、指令下发、TLS/身份绑定）
- `sigma`：Sigma 兼容规则引擎（解析、修饰符、条件求值、热重载）
- `intel`：威胁情报碰撞（IP / 域名 / 文件哈希）
- `dedup` / `suppress`：告警去重与误报抑制
- `fpstats`：误报统计——同规则同主机被人反复判误报时生成抑制草案（单活），交 AI 审计员评审
- `suppressreview`：AI 审计员评审抑制草案——草案生成时当场评审、单活循环兜底积压；有会话用会话模型，否则用平台模型，都没配留给组管理员；模型调不通留待下一轮重试，回复不合格按拒绝
- `correlate`：按实体把告警关联成 incident 事件图
- `ueba`：首次出现检测（先学习后告警）
- `triage`：旧 AI 研判引擎（带只读调查工具逐个研判 incident）
- `piruntime` / `agentchat`：Pi 子进程（配置 `SANDBOX_URL` 时经 `cmd/sandboxd` 的隔离容器）、会话消息、exec/query/report 与后台运行、停止
- `commandgate`：人工与 AI exec 的组权限、命令名单、审批（人工发起的阻塞等组管理员，AI 发起的交 AI 审计员）、硬拒绝清单与审计
- `commandreview`：AI 审计员——AI 发起、命中名单的命令用会话自己的模型当场评审，结果记审批与审计
- `schedule` / `report`：`tasks/*.yml` 预设任务按组定时拉起 Pi 会话（系统身份），报告 HTML/PDF 渲染
- `response`：响应处置（结束进程 / 隔离与解封主机或容器 / 封禁与解封 IP / 隔离与恢复文件），含自动响应钩子
- `cmdsign`：响应指令端到端 Ed25519 签名（由 `HOST_CREDENTIAL_KEY` 派生，绑定指令 ID、目标 agent、签发时间与动作参数，agent 侧 TOFU 钉住公钥验签）
- `containment`：自主响应引擎（见 `docs/autonomous-response-design.md`）——快路径对确定性高危告警（横向喷洒、数据库进程拉起 shell、反弹 shell、高置信情报外联、爆破等）秒级下发容器/主机隔离、结束进程、封禁 IP 或文件隔离；慢路径按 AI 研判 `response_tier`（`observe` / `contain` / `isolate`）分级处置；所有自动处置带 TTL 租约到期自动解除、支持人工提前解除与全局熔断保护
- `natsretry`：NATS 选主瞬断的有界重试，只用于调用方能证明对端没收下的错误（事件发布、跨节点指令投递）
- `notify`：Webhook 通知（generic / dingtalk / feishu / wecom）
- `syslog`：syslog 接入（UDP+TCP，RFC3164/RFC5424）
- `api` / `auth` / `audit`：REST API、认证与 RBAC、审计日志
- `janitor`：原始事件保留期清理（分区表上整体退役日分区）、低危良性事件到期自动结案
- `eventpart`：events 按天分区——建表、ent diff hook、分区预建（单活）、退役、替代外键的触发器与在线迁移逻辑
- `assetmap`：资产图谱与攻击面——设备清单物化、依赖边聚合、区域与暴露判定、AI 标注（单活增量扫描事件）
- `cmdorigin`：核对事件上的平台指令标记（agent 给指令拉起的进程树打标），通过的告警挂到指令上、不进关联与研判
- `automation`：已知自动化（原可信自动化来源）——按 agent 打的 SSH 登录归属（公钥指纹、来源、用户）认出运维自动化：后台单活任务按登录规律与告警结论自动识别、续期、按结论停用，组管理员可调整或手动添加；告警挂到条目上、不进关联与研判，高危例外（凭据窃取、清痕迹、关防护、破坏、情报命中）照常研判
- `review`：需人工复核的统一口径（通知、总览计数、列表筛选与自动结案共用）
- `testdb`：集成测试共享的 Postgres 连接与清表（仅 `integration` tag 编译）
- `cmd/`：`detectcheck`（检测对拍）、`sigmacheck`（规则兼容检查）、`backtest`（用真实事件回测规则命中量）、`gencerts`（证书工具）、`sandboxd`（Pi 沙箱守护进程，见 `deploy/pi-sandbox`）、`eventpartition`（老库 events 在线迁移成分区表，见 `docs/event-partitioning.md`）

数据库实体定义在 `server/ent/schema/`（ent 代码生成，生成物已提交在 `server/ent/` 下）。

## 开发约定

- **语言**：代码注释、日志消息、文档均用简体中文；标识符与提交信息遵循各目录现状。
- **配置**：server 全部走环境变量（`getenv`/`getenvInt`，见 `main.go` 与 `docs/deployment.md` 配置表），
  均有默认值，不加配置文件。少数运营中常改的项（通知目标、AI 端点与模型、外部情报查询）可在控制台改，
  存在 `settings` 表里覆盖环境变量（`notify.Settings`、`aiconf.Store`），密钥用 `HOST_CREDENTIAL_KEY` 加密。
- **失败策略贯穿全项目**：拿不准就拒绝或降级，绝不静默产出错误数据——
  Sigma 规则用了未实现的修饰符直接拒绝加载而不是降级匹配；Windows 规则不在
  Linux 资产上求值；坏采集配置一律退回内置默认；TLS 三个变量（CA/证书/私钥）
  必须同时配置，否则报错而不是降级明文。
- **安全优先于便利**：危险能力默认关闭且多道闸门（`RESPONSE_ENABLED`、`ISOLATION_ALLOW` 隔离自保、
  AI exec 的组权限 + 命令名单 + AI 审计员评审 + 硬拒绝清单）；指令一律真执行，不提供演练模式；
  抑制与情报都可撤销、有有效期、持续累计命中计数；所有登录与处置操作落审计日志。
- **AI 边界**：旧 triage 仍使用受限调查工具与最多 6 轮研判；Pi 会话使用
  `agentchat` / `commandgate`：exec 绑定组、名单与审批，query 仅使用组专属只读视图身份，
  report、track（运维待办）、identify（服务调查结论）与 remember / forget（组内长期记忆，人工优先、AI 只能删自己写的）绑定会话归组；suppress 只提交抑制草案，AI 审计员（`suppressreview`）评审通过才生效，仍待批准的组管理员也可手动审批；propose_close 只写结案建议，结案由人采纳。Pi 不注册本机 shell/文件工具，模型不能改写身份或来源。
  AI 发起、命中名单的命令不等人：由 AI 审计员（`commandreview`）当场评审，批准或拒绝都留审批记录与审计，评审出错按拒绝；
  停 agent、关机重启、清日志审计、清防火墙、格式化磁盘在硬拒绝清单里，AI 发起的一律不执行、不送评审。
  定时任务里经 `commandgate.ReadOnly` 判定为只读的 Linux 命令仍直接自动批准，省一次模型调用。
  模型输出与工具结果视为不可信输入；配置和接口见 `docs/pi-backend.md`。
- **Rust 特性**：默认构建不依赖任何外部二进制（protoc 由 crate 分发）；
  `ebpf`/`xdp` 是可选特性，CI 单独构建。写采集端代码注意 `cfg(target_os)` 分支，
  Linux CI 上通过 Windows 交叉编译 clippy 来守 Windows 代码。
- **规则改动**：改 `rules/` 后必须跑 `sigmacheck --strict ../rules` 与
  `detectcheck --strict`；若检测能力变化，同步更新 `validation/` 语料
  （`expect: undetected` 用于显式记录已知缺口与良性对照）。新规则上线前用 `cmd/backtest`
  在真实数据上回测命中量。

## 测试策略

- Go：单元测试就近放在包内（`*_test.go`）；集成测试以 `//go:build integration`
  标记，依赖真实 Postgres，共享同一测试库且跑前清表，因此必须 `-p 1` 串行
  （见 `server/internal/testdb`）。跑集成测试需 `INTEGRATION_DATABASE_URL` 指向
  测试库（可用 `docker compose up -d postgres` 起一个）。
- Rust：`cargo test`（默认特性即可，CI 不跑内核特性的测试）。
- Web：无单测，靠 `tsc` 类型检查 + oxlint + 构建把关。
- 检测能力回归：`validation/` 语料 + `cmd/detectcheck` 是核心防线——验证规则
  能抓住 Atomic Red Team 实际执行的命令，且命中规则的 ATT&CK 标注必须与技术一致。
  它不验证采集端可见性——那是 `validation/replay/` 的实机回放（双语料脚本 +
  各系统×采集路径验证矩阵），改采集端或规则后应按矩阵补验对应格子。

## 安全注意事项

- 采集端与 server 默认明文 gRPC，仅限本机调试；生产必须 mTLS（`cmd/gencerts` 生成，
  agent 可签发 CN 前缀 `host:` 的主机绑定证书）。
- RBAC 三档角色：admin / analyst / viewer；REST 走 cookie 会话，敏感操作有审计。
- 响应处置（结束进程、隔离主机或容器、封禁 IP、隔离文件）是系统中唯一能影响被监控主机的功能：
  改 `response/`、`containment/`、`cmdsign/`、`grpcsvc/commands.go` 或 agent `respond/` 时，必须保持
  闸门（全局开关 `RESPONSE_ENABLED`、端到端指令签名 `cmdsign`、隔离放行清单 `ISOLATION_ALLOW`、自主响应保护与熔断、exec 的组权限 /
  命令名单 / 审批（AI 审计员或人工）/ 硬拒绝清单、审计落库）不被绕过。指令一律真执行，不要重新引入演练模式。
- 不要把密钥、证书提交进仓库；`certs/` 等产物只应存在于本地。
- 推理服务在内网时注意 `NO_PROXY`：Go 默认读 `HTTP_PROXY`，内网 LLM 端点可能被错误代理。
