# OpenXDR — AI 代理工作指南

开源 XDR 平台：EDR + SIEM + 全流量分析，AI 驱动降噪。核心理念："一万条告警进，三个真事件出"。

本文面向接手本仓库的 AI 编码代理，汇总架构、构建、约定与验证方式。更详细的设计见
`README.md`（使用与配置）、`docs/`（文档系统，从 `docs/README.md` 索引进入：
架构 / 采集端详解 / 事件模型 / 检测链路 / REST API / 路线图）。注意 `ARCH.md` 是**目标架构讨论稿**，描述的是演进方向
（如 Redis/MQ、多网关），不代表当前实现——当前实现以代码和 `README.md` 为准。

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
  以及 PowerShell Operational 4104 脚本块）、网络出站采集（Linux eBPF /
  Windows ETW Kernel-Network TcpConnect，进程归属，与 sensor 同构 conn_tuple）
  与内核模块加载监控（Linux /proc/modules diff，class_uid=1005）。
  容器或 WSL2 中 netlink 不可用，agent 会主动退回轮询——宁可弱采集也不产假数据。
- **sensor/**（Rust，crate 名 `openxdr-sensor`）：全流量探针，只出会话元数据不存 PCAP。
  双抓包后端：AF_PACKET v3（默认）与 AF_XDP（`--features xdp`，需驱动支持，仅入向）。
- **server/**（Go 1.25，module `openxdr/server`）：单体后端。Ent ORM + PostgreSQL；
  HTTP REST（:8080，会话 cookie 认证）与 gRPC（:8081，agent/sensor 接入 + 控制信道）。
  启动时自动建表（`client.Schema.Create`），无手动迁移。
- **web/**（React 19 + TypeScript + Vite）：管理控制台。nginx 容器部署，端口 5173→80。
- **pages/**（React + Vite + Tailwind）：项目主页，仅由 `.github/workflows/pages.yml`
  部署到 GitHub Pages，与产品代码无关，改产品时不要动它。主页中英文自动切换约定见
  `pages/README.md`；改可见文案或无障碍文案时必须同时维护两种语言。
- **proto/**：`agent.proto` / `sensor.proto`，gRPC 契约。Go 侧生成代码已提交在
  `server/pb/`；Rust 侧由 build.rs 在构建时用 `protoc-bin-vendored` 生成（无需装 protoc）。
- **rules/**：Sigma 兼容检测规则（YAML）。Sigma `tags` 解析成 ATT&CK 战术/技术。
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
- agent / sensor：默认特性下 fmt / build / clippy(-D warnings) / test；
  另有 ebpf/xdp 特性的单独构建项，以及 agent 交叉编译到
  `x86_64-pc-windows-gnu` 的 clippy（Windows 侧 ETW 代码平时编不到，改
  `windows.rs`、`registry.rs` 等文件时注意 cfg 分支别破编译）。
- web：`npm run build`。容器镜像：server 与 web 的 Dockerfile 都要能构建。

## 代码组织（server/internal）

每个包职责单一，按处理链顺序排列：

- `grpcsvc`：gRPC 接入（agent/sensor 注册、事件上报、指令下发、TLS/身份绑定）
- `sigma`：Sigma 兼容规则引擎（解析、修饰符、条件求值、热重载）
- `intel`：威胁情报碰撞（IP / 域名 / 文件哈希）
- `dedup` / `suppress`：告警去重与误报抑制
- `correlate`：按实体把告警关联成 incident 事件图
- `ueba`：首次出现检测（先学习后告警）
- `triage`：AI 研判引擎 + 对话式狩猎（共用同一套有边界的调查工具）
- `response`：响应处置（结束进程 / 主机隔离），含自动响应钩子
- `notify`：Webhook 通知（generic / dingtalk / feishu / wecom）
- `syslog`：syslog 接入（UDP+TCP，RFC3164/RFC5424）
- `api` / `auth` / `audit`：REST API、认证与 RBAC、审计日志
- `janitor`：原始事件保留期清理
- `testdb`：集成测试共享的 Postgres 连接与清表（仅 `integration` tag 编译）
- `cmd/`：`detectcheck`（检测对拍）、`sigmacheck`（规则兼容检查）、`gencerts`（证书工具）

数据库实体定义在 `server/ent/schema/`（ent 代码生成，生成物已提交在 `server/ent/` 下）。

## 开发约定

- **语言**：代码注释、日志消息、文档均用简体中文；标识符与提交信息遵循各目录现状。
- **配置**：server 全部走环境变量（`getenv`/`getenvInt`，见 `main.go` 与 README 配置表），
  均有默认值，不加配置文件。
- **失败策略贯穿全项目**：拿不准就拒绝或降级，绝不静默产出错误数据——
  Sigma 规则用了未实现的修饰符直接拒绝加载而不是降级匹配；Windows 规则不在
  Linux 资产上求值；坏采集配置一律退回内置默认；TLS 三个变量（CA/证书/私钥）
  必须同时配置，否则报错而不是降级明文。
- **安全优先于便利**：危险能力默认关闭且多道闸门（`RESPONSE_ENABLED`、dry-run 优先、
  `ISOLATION_ALLOW` 隔离自保）；抑制与情报都可撤销、有有效期、持续累计命中计数；
  所有登录与处置操作落审计日志。
- **AI 边界**：LLM 只能调用参数空间受限且已转义的调查工具，刻意不做 NL2SQL；
  研判最多 6 轮，模型不支持 tool calling 时自动退化单轮；模型输出视为不可信输入。
- **Rust 特性**：默认构建不依赖任何外部二进制（protoc 由 crate 分发）；
  `ebpf`/`xdp` 是可选特性，CI 单独构建。写采集端代码注意 `cfg(target_os)` 分支，
  Linux CI 上通过 Windows 交叉编译 clippy 来守 Windows 代码。
- **规则改动**：改 `rules/` 后必须跑 `sigmacheck --strict ../rules` 与
  `detectcheck --strict`；若检测能力变化，同步更新 `validation/` 语料
  （`expect: undetected` 用于显式记录已知缺口与良性对照）。

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
- 响应处置（结束进程、隔离主机）是系统中唯一能影响被监控主机的功能：
  改 `response/`、`grpcsvc/commands.go` 或 agent `respond/` 时，必须保持
  三道闸门（全局开关、dry-run 默认、隔离放行清单）不被绕过。
- 不要把密钥、证书提交进仓库；`certs/` 等产物只应存在于本地。
- 推理服务在内网时注意 `NO_PROXY`：Go 默认读 `HTTP_PROXY`，内网 LLM 端点可能被错误代理。
