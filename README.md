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

## 技术栈

- **Agent**: Rust（eBPF / ETW）
- **Sensor**: Rust（AF_PACKET v3，二期可选 AF_XDP）
- **Server**: Go + Ent
- **Web**: React + TypeScript (Vite)
- **存储**: PostgreSQL（大规模部署建议启用 TimescaleDB 扩展）
- **AI**: 兼容 OpenAI API 的任意 LLM，支持 Ollama 本地模型
