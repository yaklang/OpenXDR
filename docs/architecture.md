# 架构设计

核心理念：**一万条告警进，三个真事件出**。所有设计决策都为这一句话服务。

本文是总体架构。各子系统的详细参考：[collection.md](collection.md)（采集端）、
[events.md](events.md)（事件模型）、[detection.md](detection.md)（检测与降噪
链路）、[api.md](api.md)（REST API）、[roadmap.md](roadmap.md)（规划）。

## 组件与端口

| 组件 | 技术 | 监听 | 职责 |
|---|---|---|---|
| agent | Rust | 不监听（主动连出） | 端点采集（Linux/Windows）+ 响应执行 |
| sensor | Rust | 不监听（主动连出） | 全流量会话元数据（仅 Linux） |
| server | Go 1.25 + Ent | `:8080` REST/健康/指标、`:8081` gRPC、syslog UDP+TCP（可选） | 可横向扩展的 gateway + worker；接入、检测、关联、研判、响应 |
| web | React 19 + Vite | nginx `:5173→80` | 管理控制台 |
| NATS JetStream | — | `:4222`，监控 `:8222` | 持久事件队列、按资产分片、故障重投、跨节点指令路由 |
| PostgreSQL | — | `:5432` | 事实存储、持久去重状态、后台任务租约 |

单机形态：`docker compose up -d`（JetStream + PostgreSQL + server + web）。
三节点形态见 [cluster.md](cluster.md) 与 `docker-compose.cluster.yml`。

## 数据流

```
agent (Rust)                    sensor (Rust)          syslog
进程/文件/认证/网络/注册表事件    全流量会话元数据         任意设备日志
（agent 侧完成 OCSF 归一化）                            │ UDP/TCP（默认关）
     │ gRPC stream                │ gRPC stream        │
     ▼                            ▼                    ▼
┌────────────── gateway server（可多节点）─────────────────────┐
│ 归一化（仅 sensor / syslog 两路在 server 侧做）：            │
│   统一成 OCSF 风格 JSON，实体对齐                            │
│   (主机 → asset，进程 → process_guid，会话 → 五元组)         │
│   稳定 event_id + partition_key → JetStream                │
└──────────────────────────┬─────────────────────────────────┘
                           ▼
┌────────────── ingest worker（durable consumer）─────────────┐
│ 每分片顺序消费，处理成功才 ACK；重投由 event_id 幂等          │
│ ① sigma 规则求值 + 威胁情报碰撞  →  合成同一命中序列          │
│ ② 抑制检查（分析师标记的噪声源，命中计数可见）                 │
│ ③ PostgreSQL 持久去重（跨节点/重启窗口不丢）                  │
│ ④ 告警落库                                                  │
│   合成告警源：xdr:bruteforce-success（爆破得手，ingest 侧）   │
│        │                                                   │
│        ▼  集群单活后台任务（PostgreSQL advisory lease）       │
│ correlate: 未归属告警 → incident                             │
│   血缘优先 → 同资产时间窗 → 横向移动（跨主机网络会话）          │
│ ueba: 新进程首次出现 → 合成 low 告警 xdr:new-process 进管线   │
│ triage: open incident → LLM 研判 → verdict                  │
│ notify: 研判后事件 → webhook（benign 不推，可设阈值）          │
│ response: 研判高置信度 malicious → 自动隔离（四道保险）        │
│ janitor: 过期事件/会话清理（告警引用的证据不删）               │
└─────────────────────────────────────────────────────────────┘
     ▼
web (React): 概览漏斗 / 事件列表+图 / 检索 / 情报 / 审计
```

> 注：旧版本图把"归一化"整体画在 server 框内——实际上 agent 事件的归一化
> 在 **agent 侧**完成（raw_json 已是 OCSF 风格，server 原样落库），server
> 只做 sensor 与 syslog 两路的归一化。且 agent 实际产出五类事件
> （1001/1007/3002/4001/201002），不止进程事件。详见
> [events.md](events.md)。

## 降噪的四道闸

| 层 | 机制 | 消掉什么 |
|---|---|---|
| 去重 | 窗口内同指纹告警合并计数 | 端口扫描、爆破造成的重复风暴 |
| 抑制 | 分析师标记的规则×资产组合不再告警 | 已知误报源。命中计数持续累加，绝不静默 |
| 关联 | 告警按实体归并成 incident | 碎片告警 → 攻击故事，研判对象从 N 条变 1 个 |
| 研判 | LLM 只看聚合后的 incident | benign 判定不推送通知 |

## 关键设计决策

**规则命中与情报命中走同一条管线。** IOC 碰撞的产物是 `intel:<kind>:<value>`
形式的 rule_id，与 sigma 告警共用去重、抑制、关联、研判全链路——没有第二套
告警逻辑，抑制规则也能压情报误报。

**匹配热路径在内存，幂等和去重在数据库事务。** 抑制规则、情报和 Sigma 在各
worker 内存求值；事件主键与告警指纹必须经过共享 PostgreSQL，才能保证节点切换、
重投和重连不改变语义。这里宁可支付一次事务成本，也不拿安全事件正确性换吞吐。

**规则与情报允许最终一致，事件处理不允许。** 各节点周期 reload 规则、抑制与
情报；事件ID、告警去重和后台任务租约使用共享强一致状态。

**关联优先级：血缘 > 同资产时间窗 > 横向移动。** 进程血缘是最强信号（能跨时间窗）；
横向移动只在本机没有归属故事时才查（时间窗内对端主机连过来且对端有 open incident），
避免把巧合的网络连接当成攻击路径。

**事件不可变，告警可变。** 原始事件只增不改；告警的 count/last_ts 随去重更新；
incident 的 status/graph 随关联与研判演进。janitor 只删无告警引用的过期事件——
证据跟着 incident 的生命周期走。

**采集端降级而非失败。** agent 内核态采集（eBPF/ETW）不可用时自动回落用户态
（netlink / 轮询）；上报堵塞时丢弃并计数，绝不反压采集——阻塞只会让内核缓冲区
溢出，丢得更多且无从知晓。

**拿不准就拒绝，绝不静默产出错误数据。** Sigma 规则用了未实现的修饰符直接
拒绝加载而不是降级匹配；Windows 规则不在 Linux 资产上求值；坏采集配置一律
退回内置默认；TLS 三个变量必须同时配置，否则报错而不是降级明文。netlink 在
容器/WSL2 里会因 pid 命名空间错位采出假数据，agent 检测到后主动退回轮询——
宁可弱采集也不产假数据。

**AI 只动手边界内的工具。** LLM 只能调用参数空间受限且已转义的调查工具，
刻意不做 NL2SQL；研判最多 6 轮，模型不支持 tool calling 时自动退化单轮；
模型输出视为不可信输入。狩猎产出的规则必须过引擎编译器才能落盘，
AI 不能直接改检测面。详见 [detection.md](detection.md)。

**危险能力默认关闭且多道闸门。** 响应处置（结束进程/主机隔离）有
`RESPONSE_ENABLED`、dry-run 默认、`ISOLATION_ALLOW` 隔离自保三道闸门；
自动响应另有四道保险（启用开关、dry-run 默认、主机白名单、全程审计）。

## 身份与安全

- 采集端 mTLS，agent 可按主机签发绑定证书（CN `host:<hostname>`），失陷主机
  冒充不了别人
- Web 三角色 RBAC（admin/analyst/viewer），集中式"路径→最低角色"表
- 会话是不透明 token，库里只存 SHA-256，删行即吊销
- 登录失败按源 IP 指数退避（5 次起 30s，封顶约 64 分钟）；用户不存在时
  dummy hash 陪跑防时间侧信道
- 所有登录与处置操作落审计日志

## 模块地图

| 路径 | 职责 |
|---|---|
| `server/internal/grpcsvc` | agent/sensor 接入，证书身份校验，指令下发，爆破得手升级检测 |
| `server/internal/ingest` | 稳定事件信封、数据库幂等、持久告警去重、统一检测处理器 |
| `server/internal/eventbus` | 单机直连 / JetStream 发布、分片 durable consumer、积压采集 |
| `server/internal/cluster` | PostgreSQL advisory lock 后台任务租约与迁移锁 |
| `server/internal/telemetry` | Prometheus 处理链指标 |
| `server/internal/syslog` | RFC3164/5424 解析与接入 |
| `server/internal/sigma` | Sigma 规则编译与求值（dot path 取值，class 分桶，热重载） |
| `server/internal/intel` | 威胁情报内存索引与碰撞 |
| `server/internal/dedup` | 告警去重 |
| `server/internal/suppress` | 误报抑制 |
| `server/internal/correlate` | 告警→incident 归并与实体图 |
| `server/internal/ueba` | 新进程首次出现检测（先学习后告警） |
| `server/internal/triage` | LLM 研判 + 对话式狩猎 + 狩猎存规则 |
| `server/internal/notify` | webhook 通知 |
| `server/internal/response` | 响应处置指令下发（结束进程/主机隔离）与自动响应 |
| `server/internal/janitor` | 数据保留与过期清理 |
| `server/internal/auth` | 会话、RBAC、登录限速 |
| `server/internal/audit` | 操作审计 |
| `agent/src/collector` | 端点采集（平台差异封死在模块内，对外一个 channel） |
| `agent/src/respond` | 响应指令执行（结束进程/主机隔离） |
| `sensor/src/capture` | 抓包后端（AF_PACKET v3 / AF_XDP） |
| `sensor/src/proto_id.rs` | 应用层协议识别与元数据提取（DNS 含应答/rcode、TLS 含证书元数据、HTTP、JA3/JA3S） |
| `sensor/src/flow.rs` | 五元组流聚合与老化 |
