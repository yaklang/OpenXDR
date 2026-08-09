# OpenXDR 文档

本目录是项目的设计与参考文档，面向使用者和接手开发的（人或 AI）工程师。
使用与部署操作见根目录 [README.md](../README.md)；AI 代理工作指南见
[AGENTS.md](../AGENTS.md)。

**写作约定**：文档内容以代码实现为准并标注源码位置（`文件:行号`），
实现变更时同步更新文档；拿不准的行为写"未验证"而不是猜测。
`ARCH.md`（仓库根目录）是目标架构讨论稿，描述演进方向，不代表当前实现。

## 文档地图

| 文档 | 内容 | 什么时候读 |
|---|---|---|
| [architecture.md](architecture.md) | 总体架构：数据通路、降噪四道闸、关键设计决策、身份与安全、模块地图 | 第一次了解系统；做任何跨模块改动前 |
| [collection.md](collection.md) | 采集端详解：agent（Linux/Windows 各采集路径与降级链）、sensor（抓包后端与协议解析）、配置下发 | 改 `agent/`、`sensor/`；评估采集覆盖面 |
| [events.md](events.md) | 事件模型参考：class_uid 总表、每类事件的字段 schema、实体标识约定、gRPC 契约 | 写/改检测规则；改事件格式；写查询 |
| [detection.md](detection.md) | 检测与降噪链路：Sigma 引擎、情报、去重、抑制、爆破升级、关联、UEBA、AI 研判、响应处置、通知、清理 | 改 `server/internal/` 任何检测相关包 |
| [api.md](api.md) | REST API 参考：端点、参数、权限约定、对接示例 | 对接外部系统；改 `server/internal/api` |
| [roadmap.md](roadmap.md) | 路线图：现状快照、已完成项的教训、后续工作详细规划（P0/P1/P2）、不做清单 | 决定"接下来做什么"之前 |
| [pilot.md](pilot.md) | 内网长期试运行部署、验收与指标口径 | 验证真实事件量、降噪效果和存储增长时 |

## 推荐阅读顺序

1. **新人上手**：README（快速开始）→ architecture.md → events.md
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
| 检测管线 | detection.md | `server/internal/{sigma,intel,dedup,suppress,correlate,ueba,triage}` |
| 响应处置 | detection.md | `server/internal/response`、`agent/src/respond/` |
| 配置项 | README 配置表 + detection.md | `server/main.go` |
