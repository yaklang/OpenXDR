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
| `afxdp` | 绕过协议栈，吞吐更高。需要驱动支持，进程会在网卡上挂载 XDP 程序；**只能看到入向流量**，镜像口场景够用 |

`SENSOR_WORKERS` 决定并行度。afpacket 下多个 worker 共享 FANOUT 组；afxdp 下
worker 号即网卡队列号，数量不应超过网卡实际队列数。

> agent 的 eBPF 字节码和 sensor 的 XDP 程序在构建时编译，需要
> `rustup toolchain install nightly --component rust-src` 和 `cargo +nightly install bpf-linker`。

## 启用 mTLS

采集端与 server 之间默认是明文，仅适合本机调试。生产部署必须开双向认证：

```bash
./scripts/gen-certs.sh certs <server 的域名或 IP>

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
| `RETENTION_DAYS` | `30` | 原始事件保留天数，0 表示不清理。被告警引用的证据事件不受影响 |

## 技术栈

- **Agent**: Rust（eBPF / ETW）
- **Sensor**: Rust（AF_PACKET v3 / AF_XDP 双后端）
- **Server**: Go + Ent
- **Web**: React + TypeScript (Vite)
- **存储**: PostgreSQL（大规模部署建议启用 TimescaleDB 扩展）
- **AI**: 兼容 OpenAI API 的任意 LLM，支持 Ollama 本地模型
