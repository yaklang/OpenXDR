# OpenXDR 文档

本目录是项目的设计与参考文档，面向使用者和接手开发的（人或 AI）工程师。
使用与部署操作见 [deployment.md](deployment.md)；AI 代理工作指南见
[AGENTS.md](../AGENTS.md)。

**写作约定**：文档内容以代码实现为准并标注源码位置（`文件:行号`），
实现变更时同步更新文档；拿不准的行为写"未验证"而不是猜测。
`ARCH.md`（仓库根目录）是目标架构讨论稿，描述演进方向，不代表当前实现。

## 文档地图

| 文档 | 内容 | 什么时候读 |
|---|---|---|
| [install.md](install.md) | 一行安装：准备、安装、核对、接上 AI 与主机、升级备份、常见问题，附给 AI agent 的说明 | 第一次装、升级 |
| [deployment.md](deployment.md) | 部署与使用：启动、接入主机、日志与情报、抑制与处置、mTLS、配置项全表 | 部署、接入主机、查配置项 |
| [architecture.md](architecture.md) | 总体架构：数据通路、降噪四道闸、关键设计决策、身份与安全、模块地图 | 第一次了解系统；做任何跨模块改动前 |
| [collection.md](collection.md) | 采集端详解：agent（Linux/Windows 各采集路径与降级链）、sensor（抓包后端与协议解析）、配置下发 | 改 `agent/`、`sensor/`；评估采集覆盖面 |
| [events.md](events.md) | 事件模型参考：class_uid 总表、每类事件的字段 schema、实体标识约定、gRPC 契约 | 写/改检测规则；改事件格式；写查询 |
| [suricata.md](suricata.md) | Suricata EVE alert 接入：来源密钥、资产归属、重传、导入与验证 | 接入外部网络检测告警 |
| [detection.md](detection.md) | 检测与降噪链路：Sigma 引擎、情报、去重、抑制、爆破升级、关联、UEBA、AI 研判、响应处置、通知、清理 | 改 `server/internal/` 任何检测相关包 |
| [api.md](api.md) | REST API 参考：端点、参数、权限约定、对接示例 | 对接外部系统；改 `server/internal/api` |
| [open-integrations-design.md](open-integrations-design.md) | 资产导出与系统联动详细设计（待实施）：集成身份、API、事件订阅、工单回写及验收 | 实施导出、CMDB 对接或工单联动前 |
| [roadmap.md](roadmap.md) | 路线图：2026-10-30 运行修复与各方向实现/部署/验收状态、当前 P0/P1/P2 与完成条件、历史记录 | 决定"接下来做什么"之前 |
| [ingestion-capacity.md](ingestion-capacity.md) | 入库容量验证：有界 mTLS 合成流量、逐轮停止阈值与实际落库对账 | 扩大纳管或验证吞吐前 |
| [pi-backend.md](pi-backend.md) | AI 助手后端：会话与后台运行、命令名单与审批、只读查询、运维待办、预设任务 | 配置 AI 助手与巡检；改 `agentchat`、`commandgate` |
| [vulns.md](vulns.md) | 软件漏洞：dpkg / RPM 软件清单、OSV 漏洞库同步、版本比较与暴露服务标注、已知限制 | 看主机漏洞；改 `vuln` 或 agent 软件清单 |
| [temporal-detection.md](temporal-detection.md) | 时序检测（开发中）：计数与序列规则格式、加载约束、求值与存储 | 写时序规则；改 `temporal` |
| [identity-correlation.md](identity-correlation.md) | 身份关联（开发中）：Linux / Windows 登录归一化、本地账号、Keycloak / Entra ID / Authentik / AD-LDAP 目录同步 | 接入身份来源；改 `identity` |
| [asset-map.md](asset-map.md) | 资产图谱与攻击面：设备清单、依赖边、区域与暴露级别、风险分、AI 标注 | 看资产关系与暴露面；改 `assetmap` 或 agent inventory |
| [host-enrollment.md](host-enrollment.md) | 运维文档导入、凭据加密存储、按组授权与 SSH 纳管 | 导入含主机密码或私钥的文档；配置远程安装 |
| [ai-native.md](ai-native.md) | AI 原生架构设计稿（M1 已实现，当前接口以 pi-backend.md 为准）：agent 执行器、平台托管 Pi、定时巡检、对话页、组与审批 | 参与 AI 原生改造之前 |
| [ssh-decoy.md](ssh-decoy.md) | 独立 SSH 诱饵靶场原型：固定 Banner、标记核实、事件与验证边界 | 进行授权诱骗实验；不用于生产部署 |
| [multi-carrier-decoys.md](multi-carrier-decoys.md) | 多载体登记、HTTP/HTML、文件打开监视、模拟 Shell 与认证事件回传 | 布放与验收通用诱饵 |
| [../integrations/dygk/README.md](../integrations/dygk/README.md) | 独立欺骗引擎：统一启动、源码缓存与 Git 管理、镜像范围、上游更新和回退 | 部署或更新 DYGK 与原生诱饵运行包 |
| [deception-engine-design.md](deception-engine-design.md) | OpenXDR 与 DYGK 独立引擎接入设计：运行逻辑抽离、版本化协议、迁移清单与升级验收 | 实施欺骗引擎抽离或接入 DYGK 前 |
| [decoy-defense.md](decoy-defense.md) | 诱饵、暂停注入、输出填充的运行策略、事件契约和平台接入边界 | 开发和验收三层诱饵防御 |
| [event-partitioning.md](event-partitioning.md) | events 按天分区：主键与引用处理、ent 共存、预建与退役、老库在线迁移与回滚 | 改 events 表结构或保留期；执行分区迁移 |
| [event-archive.md](event-archive.md) | 冷归档：冷块格式、影子归档、冷热读取、按 ID 定位、单日切换与恢复、闸门与生命周期、CLI 速查 | 归档/切换/恢复操作；容量与保留规划；改冷归档代码 |
| [archive-rehearsal-2026-10-30.md](archive-rehearsal-2026-10-30.md) | 冷归档等规模演练记录（260 万行单日）：全链路耗时、Exists 延迟、空间账、Guard 反向验证 | 容量规划取数；换环境后对照重测 |
| [cluster.md](cluster.md) | JetStream 队列、server 集群、幂等语义、故障恢复与 Prometheus/Grafana | 部署多节点；排查积压、重投与节点故障 |
| [../deploy/ha/README.md](../deploy/ha/README.md) | 跨宿主机高可用：Patroni + 三节点 JetStream + Keepalived VIP，初始化与切换验收 | 部署两故障域 HA；升级或排查 VIP、主备切换 |

## 推荐阅读顺序

1. **新人上手**：README → deployment.md → architecture.md → events.md
2. **改采集端**：collection.md → events.md（确认事件契约）→ 改完跑
   `sigmacheck` / `detectcheck`
3. **改检测逻辑**：detection.md → events.md → roadmap.md（确认不与规划冲突）
4. **写规则**：events.md（字段路径）→ detection.md（Sigma 引擎能力边界）

## 文档与代码的对应关系

| 主题 | 文档 | 代码 |
|---|---|---|
| 端点采集 | collection.md | `agent/src/collector/` |
| 流量探针 | collection.md | `sensor/src/` |
| 事件 schema | events.md | `proto/`、`agent/src/collector/mod.rs`、`server/internal/grpcsvc/` |
| 检测管线 | detection.md | `server/internal/{sigma,intel,dedup,suppress,fpstats,correlate,ueba,triage}` |
| 响应处置 | detection.md | `server/internal/response`、`agent/src/respond/` |
| 配置项 | deployment.md 配置表 + detection.md | `server/main.go` |
