# OpenXDR

开源 XDR 平台：EDR + SIEM + 全流量分析，AI 驱动降噪。

**核心理念：一万条告警进，三个真事件出。**

## 架构

```
┌─────────┐  ┌──────────┐  ┌────────────┐
│  Agent  │  │  Sensor  │  │  Syslog /  │
│ (Rust)  │  │  (Rust)  │  │  日志接入   │
│ 端点采集 │  │ 全流量探针│  │            │
└────┬────┘  └────┬─────┘  └─────┬──────┘
     │            │              │
     └────────────┼──────────────┘
                  ▼
        ┌──────────────────┐
        │   归一化 (OCSF)   │   统一实体：主机 ID / 进程 GUID / 用户 / 五元组
        └────────┬─────────┘
                 ▼
        ┌──────────────────┐
        │    PostgreSQL    │
        └────────┬─────────┘
                 ▼
        ┌──────────────────┐
        │  Server (Go)     │
        │  ├ 规则引擎 (Sigma)│   聚合去重，砍掉 80% 噪声
        │  ├ 关联引擎        │   按实体构建事件图：告警 → 攻击故事
        │  └ AI 研判 (LLM)  │   只研判聚合后的事件，输出置信度 + 攻击链描述
        └────────┬─────────┘
                 ▼
        ┌──────────────────┐
        │   Web (React)    │
        └──────────────────┘
```

## 目录

| 目录 | 说明 |
|---|---|
| `agent/` | Rust 端点采集 agent，支持 Linux / Windows。Linux 用 eBPF（tracepoint，需 root），Windows 用 ETW（Kernel-Process，需管理员），权限不足时自动回落轮询采集 |
| `sensor/` | Rust 全流量探针，部署在核心交换机镜像口。AF_PACKET v3 零拷贝抓包 + FANOUT 多核并行，出会话元数据（不存 PCAP） |
| `server/` | Go 后端（Ent + PostgreSQL）：接入、规则引擎、关联引擎、AI 研判 |
| `web/` | React 前端 |
| `schema/` | 统一事件 schema（基于 OCSF）与数据库 DDL |
| `rules/` | 检测规则（Sigma 兼容） |
| `docs/` | 设计文档 |

## 快速开始

```bash
# 启动 Postgres + server + web
docker compose up -d
# 界面: http://localhost:5173   API: http://localhost:8080   gRPC 接入: 8081
```

数据库表由 server 启动时自动创建，无需手动迁移。

启用 AI 研判（不配置则只做规则告警和关联，不调用模型）：

```bash
AI_MODEL=qwen3 docker compose up -d   # 默认接本机 Ollama
```

采集端各自构建部署到被监控主机：

```bash
# 端点 agent（Linux 需 root 才能用 eBPF，否则自动回落轮询采集）
cd agent && cargo build --release
sudo OPENXDR_SERVER=http://<server>:8081 ./target/release/openxdr-agent

# 流量探针（需 root，网卡接核心交换机镜像口）
cd sensor && cargo build --release
sudo env SENSOR_IFACE=eth0 OPENXDR_SERVER=http://<server>:8081 ./target/release/openxdr-sensor
```

探针有两个抓包后端，用 `SENSOR_BACKEND` 切换：

| 后端 | 说明 |
|---|---|
| `afpacket`（默认） | AF_PACKET v3 零拷贝环 + FANOUT 按流哈希。任何 Linux 都能跑，不挑驱动，收发双向都能看到 |
| `afxdp` | 绕过协议栈，吞吐更高。需 `--features xdp` 构建、驱动支持，进程会在网卡上挂载 XDP 程序；**只能看到入向流量**，镜像口场景够用 |

`SENSOR_WORKERS` 决定并行度。afpacket 下多个 worker 共享 FANOUT 组；afxdp 下
worker 号即网卡队列号，数量不应超过网卡实际队列数。

采集端默认构建**不依赖任何外部二进制**——protoc 随 crate 分发，`cargo build` 直接可用。
内核级采集是可选特性，开启后才需要 nightly 工具链：

```bash
rustup toolchain install nightly --component rust-src
cargo +nightly install bpf-linker

cargo build --release --features ebpf   # agent：Linux eBPF 采集
cargo build --release --features xdp    # sensor：AF_XDP 后端
```

不开这两个特性时，agent 走轮询采集、sensor 走 AF_PACKET，功能完整只是精度和吞吐低一些。

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

## 响应处置

检测到攻击后可以直接下发处置指令：**结束进程**、**隔离主机**、**解除隔离**。
指令走 agent 主动连出的双向通道，被监控主机不需要开监听端口。

这是系统里唯一能对主机造成实际影响的功能，三道闸门默认全开：

| 闸门 | 行为 |
|---|---|
| 全局开关 | `RESPONSE_ENABLED` 默认 false，不开则一律拒绝下发 |
| 演练优先 | 不显式传 `dryRun: false` 就只报告"将会做什么"，不产生任何影响 |
| 隔离自保 | 未配置 `ISOLATION_ALLOW` 时 agent 拒绝隔离——隔离后收不到解除指令只能人工上机 |

```bash
RESPONSE_ENABLED=true ISOLATION_ALLOW=<server>:8081 docker compose up -d
```

每条指令连同下发者、演练与否、执行结果一并落库，可在事件详情页查看。
隔离在 Linux 用 nftables 独立表实现（不触碰主机原有规则），Windows 用防火墙规则。

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

## 配置

server 全部通过环境变量配置，均有默认值：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `DATABASE_URL` | `postgres://openxdr:openxdr@localhost:5432/openxdr?sslmode=disable` | 数据库连接串 |
| `RULES_PATH` | `../rules` | Sigma 规则目录 |
| `HTTP_ADDR` / `GRPC_ADDR` | `:8080` / `:8081` | 监听地址 |
| `ALERT_DEDUP_WINDOW_MINUTES` | `5` | 告警去重窗口 |
| `CORRELATE_WINDOW_MINUTES` | `30` | 关联时间窗 |
| `CORRELATE_MAX_GRAPH_NODES` | `500` | 单个事件图节点上限 |
| `AI_MODEL` | 空（不启用） | 研判模型名 |
| `AI_BASE_URL` | `http://localhost:11434/v1` | OpenAI 兼容端点 |
| `SYSLOG_ADDR` | 空（不启用） | syslog 监听地址，如 `:514`。UDP 与 TCP 同时监听 |
| `RESPONSE_ENABLED` | `false` | 是否允许下发响应指令 |
| `ISOLATION_ALLOW` | 空 | 隔离主机时放行的地址，必须包含 server 的 gRPC 端点 |
| `RETENTION_DAYS` | `30` | 原始事件保留天数，0 表示不清理。被告警引用的证据事件不受影响 |

## 技术栈

- **Agent**: Rust（eBPF / ETW）
- **Sensor**: Rust（AF_PACKET v3 / AF_XDP 双后端）
- **Server**: Go + Ent
- **Web**: React + TypeScript (Vite)
- **存储**: PostgreSQL（大规模部署建议启用 TimescaleDB 扩展）
- **AI**: 兼容 OpenAI API 的任意 LLM，支持 Ollama 本地模型
