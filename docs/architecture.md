# 架构设计

核心理念：**一万条告警进，三个真事件出**。所有设计决策都为这一句话服务。

## 数据流

```
agent (Rust)          sensor (Rust)         syslog
进程事件+exe哈希       全流量会话元数据        任意设备日志
     │ gRPC stream         │ gRPC stream        │ UDP/TCP 514
     ▼                     ▼                    ▼
┌──────────────────── server (Go) ────────────────────┐
│ 归一化: 统一成 OCSF 风格 JSON，实体对齐               │
│   (主机 → asset，进程 → process_guid，会话 → 五元组)  │
│        │                                            │
│        ▼  每条事件同步执行（三条接入路径共用一套逻辑）  │
│ ① sigma 规则求值 + 威胁情报碰撞  →  合成同一命中序列    │
│ ② 抑制检查（分析师标记的噪声源，命中计数可见）          │
│ ③ 去重（窗口内同指纹只留一行，count 累加）             │
│ ④ 告警落库                                          │
│        │                                            │
│        ▼  异步循环（各自独立的后台 goroutine）         │
│ correlate: 未归属告警 → incident                     │
│   血缘优先 → 同资产时间窗 → 横向移动（跨主机网络会话）  │
│ triage: open incident → LLM 研判 → verdict          │
│ notify: 研判后事件 → webhook（benign 不推，可设阈值）  │
│ janitor: 过期事件/会话清理（告警引用的证据不删）        │
└─────────────────────────────────────────────────────┘
     ▼
web (React): 概览漏斗 / 事件列表+图 / 检索 / 情报 / 审计
```

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

**热路径不查库。** 抑制规则与情报库整表进内存索引，周期 reload（写操作后立即
reload 一次）；命中计数在内存攒批回写。每秒上万事件的匹配开销是纯内存查表。

**内存索引 + 定期 reload 优于消息通知。** server 单体，30 秒的生效延迟对这两类
数据无关紧要，换来的是零分布式状态。

**关联优先级：血缘 > 同资产时间窗 > 横向移动。** 进程血缘是最强信号（能跨时间窗）；
横向移动只在本机没有归属故事时才查（时间窗内对端主机连过来且对端有 open incident），
避免把巧合的网络连接当成攻击路径。

**事件不可变，告警可变。** 原始事件只增不改；告警的 count/last_ts 随去重更新；
incident 的 status/graph 随关联与研判演进。janitor 只删无告警引用的过期事件——
证据跟着 incident 的生命周期走。

**采集端降级而非失败。** agent 内核态采集（eBPF/ETW）不可用时自动回落用户态
（netlink / 轮询）；上报堵塞时丢弃并计数，绝不反压采集——阻塞只会让内核缓冲区
溢出，丢得更多且无从知晓。

## 身份与安全

- 采集端 mTLS，agent 可按主机签发绑定证书（CN `host:<hostname>`），失陷主机
  冒充不了别人
- Web 三角色 RBAC（admin/analyst/viewer），集中式"路径→最低角色"表
- 会话是不透明 token，库里只存 SHA-256，删行即吊销
- 登录失败按源 IP 指数退避
- 所有登录与处置操作落审计日志

## 模块地图

| 路径 | 职责 |
|---|---|
| `server/internal/grpcsvc` | agent/sensor 接入，证书身份校验 |
| `server/internal/syslog` | RFC3164/5424 解析与接入 |
| `server/internal/sigma` | Sigma 规则编译与求值（dot path 取值，class 分桶） |
| `server/internal/intel` | 威胁情报内存索引与碰撞 |
| `server/internal/dedup` | 告警去重 |
| `server/internal/suppress` | 误报抑制 |
| `server/internal/correlate` | 告警→incident 归并与实体图 |
| `server/internal/triage` | LLM 研判 |
| `server/internal/notify` | webhook 通知 |
| `server/internal/response` | 响应处置指令下发（结束进程/主机隔离） |
| `server/internal/janitor` | 数据保留与过期清理 |
| `server/internal/auth` | 会话、RBAC、登录限速 |
| `server/internal/audit` | 操作审计 |
