# OpenXDR

[![CI](https://github.com/yaklang/OpenXDR/actions/workflows/ci.yml/badge.svg)](https://github.com/yaklang/OpenXDR/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

中文 | [English](README.en.md)

开源、AI 原生的 XDR 平台：EDR + SIEM + 全流量分析。
**检测、研判、处置自己闭环，人在事后审计、随时推翻。**

- **一万条告警进，三个真事件出。** 规则、情报、去重、抑制、关联层层收敛，再由带调查工具的 AI 逐个研判。
- **真攻击来了，平台先动手。** 内网横向、爆破得手、数据库被拿来执行命令，几秒内自动隔离攻击容器、封锁来源、结束进程，不等研判、不等人。
- **纳管即运维，纳管即安全。** 主机装上 agent、划进组，就有持续采集、检测、每日巡检和可以对话的 AI 运维助手。

## 能做什么

### 接入与采集

- **一条命令接入**：控制台按组签发接入令牌，Linux（x86_64 / arm64）、Windows 一行命令装好 agent；本机生成私钥，server 签发主机绑定证书。
  新版放进分发目录，在线 agent 自动升级。已有运维文档可直接导入，凭据加密保存，按组授权 SSH 纳管。
- **采集不挑环境**：进程、文件、持久化点、登录与安全日志、网络连接与 DNS、内核模块、监听端口与软件清单，
  并按 cgroup 认出容器归属。eBPF / ETW 可选，不可用时自动降级到 netlink、fanotify、轮询——宁可弱采集，也不产假数据。
- **全流量探针**：只出会话元数据（DNS、TLS JA3 与证书、HTTP），不存 PCAP；另有 syslog 接入。

### 检测与降噪

- **规则与情报**：200 多条 Sigma 兼容规则（热重载、ATT&CK 矩阵标出「有规则无数据源」的缺口），时序检测（计数与序列），
  威胁情报碰撞（内置 abuse.ch 等公开订阅），UEBA 首次出现与外联心跳检测。
- **降噪链**：持久去重、可撤销且有有效期的误报抑制、已知自动化识别（运维脚本、容器健康检查不再刷屏）、
  按实体关联成事件图，低危良性事件到期自动结案。
- **跨主机攻击不再被切碎**：按资产 + 容器分桶，受害方的登录失败直接认出横向来源，跨组也成立；
  一台纳管主机对多台主机喷洒时合成 5 级告警、立即重研判。
- **验收在 CI 里**：真实攻击命令回放过规则引擎对拍，真实攻击事件的完整时间线回放过入库、关联与自主响应。

### AI 研判、助手与巡检

- **主动研判**：AI 带只读调查工具逐个研判事件，给出结论、置信度与依据；重研判有冷却与公平调度，不被噪声拖垮。
- **对话即运维**：AI 可以在组内主机上执行命令、按组只读视图查库、登记运维待办、提交报告；事件与待办可多选「交给 AI」接着处理。
- **定时巡检**：预设任务按 cron 拉起 AI 巡检全组主机，产出 HTML / PDF 报告。
- **AI 审计员**：AI 发起的高风险命令、生成的抑制草案，由 AI 审计员当场评审，不再整夜等人点批准；
  停 agent、清日志、关防火墙、格式化磁盘在硬拒绝清单里，AI 发起的一律不执行。

### 自主响应

确定性的攻击信号命中后，平台按「谁是攻击来源、谁是受害方」和每台主机的处置等级直接遏制：

| 信号 | 平台自动做什么 |
|---|---|
| 内网横向喷洒 | 认出发起攻击的容器就只隔离那个容器；实验机才隔离整机；所有受害方封锁来源地址 |
| 爆破得手 | 封锁登录来源，锁定被攻破的账号（内置账号与核心主机不锁） |
| 数据库拉起 shell（`COPY FROM PROGRAM`、UDF） | 结束这个进程，在数据库主机上封锁发起命令的客户端 |
| 高级别情报命中 | 封锁地址；主动外连的恶意进程直接结束，命中哈希的文件移入隔离区 |

- **处置等级**：每台资产由 AI 定为实验 / 生产 / 核心三档（人可改可锁）。实验机可以断网，生产机不隔离整机，核心只做最轻的处置，平台节点之间绝不互封。
- **可撤回、有边界**：封锁与隔离按租约生效，到期由 AI 复核解除还是续期；熔断限制每小时处置次数与每组隔离比例；
  每个决定（包括没执行的）都有记录，控制台「自主响应」页一键撤回。
- 默认关闭，建议先只对实验等级开启，观察后再放开。

### 平台自身防护

能自主动手的安全平台，本身就是攻击者最想拿下的目标。OpenXDR 默认按这个假设设计：

- **指令签名**：每条处置指令都用签名信封绑定目标主机与有效期，agent 只执行验签通过的。数据库或消息总线被人摸到，也伪造不出指令。
- **安装包签名**：agent 只接受离线发布私钥签过名的升级包，拿下 server 节点也推不了恶意 agent。
- **审计防篡改**：审计日志封存成 HMAC 链，密钥不在数据库里；改一条、删一条都会告警，删掉最新记录由集群外的监控发现。
- **自我监控**：数据库高可用的控制面配置一被改、平台节点的 agent 一掉线就告警；控制面端口只对固定对端开放。

### 资产、攻击面与漏洞

- **资产图谱**：监听端口与连接关系聚合成依赖图，AI 标注每台资产的角色、功能、重要程度与处置等级。
- **攻击面**：资产按网段、云环境自动分区，每个对外服务按暴露级别 × 端口风险 × 重要程度排序，连过却没纳管的机器列为盲区。
- **软件漏洞**：按 OSV 漏洞库比对 dpkg 软件清单，标出可升级修复的漏洞与受影响的对外服务（目前覆盖 Debian / Ubuntu）。
- **身份关联**（开发中）：归一化登录与本地账号，可从 Keycloak、Entra ID、AD / LDAP 同步目录账号。

### 能上生产

mTLS 与按主机绑定证书、三档 RBAC 与组权限、NATS JetStream 按资产分片队列、多节点 server，
以及 Patroni + 三节点 JetStream + Keepalived 的跨宿主机高可用部署与滚动发布。

## 界面一览

以下截图来自虚构的演示环境，主机、地址与域名均为示例。

**态势总览**：一天上百万条原始事件、上万条告警，最后只剩 3 件需要人看。

![态势总览](docs/images/screenshots/overview-zh.png)

**AI 助手处理事件**：把事件交给 AI，它上机取证、查平台数据、在审批后处置，最后给出结论和结案建议。

![AI 助手](docs/images/screenshots/ai-assistant-zh.png)

**安全事件**：每个事件都带 AI 研判结论，良性的写明理由，真正可疑的排在最前。

![安全事件](docs/images/screenshots/incidents-zh.png)

**事件详情**：研判结论、攻击链与处置建议在上，进程树与外联关系一张图看清。

![事件详情](docs/images/screenshots/incident-detail-zh.png)

**资产图谱**：按实际观测到的连接画出依赖关系，AI 标注每台机器的角色与重要程度。

![资产图谱](docs/images/screenshots/asset-map-zh.png)

**攻击面**：哪些服务对公网开放、谁在访问、风险多高，按区域一目了然。

![攻击面](docs/images/screenshots/attack-surface-zh.png)

**每日巡检报告**：AI 每天巡检全组主机，只把需要人处理的事写在前面。

![巡检报告](docs/images/screenshots/reports-zh.png)

**定时任务**：每个任务像一位排班上岗的 AI 员工，上一班做了什么、交了什么报告都看得到。

![定时任务](docs/images/screenshots/scheduled-tasks-zh.png)

**资产详情**：采集链路是否健康、流量探针状态、角色画像与相关事件集中在一页。

![资产详情](docs/images/screenshots/asset-detail-zh.png)

## 架构

```
┌─────────┐  ┌──────────┐  ┌──────────┐
│  Agent  │  │  Sensor  │  │  Syslog  │
│ 端点采集 │  │ 全流量探针│  │ 日志接入  │
└────┬────┘  └────┬─────┘  └────┬─────┘
     │  ▲         │             │
     │  │ 签名指令 │             │   gRPC (mTLS)，agent 主动连出
     ▼  │         ▼             ▼
   ┌──────────────────────────────────┐
   │ Server (Go，多节点)              │
   │  归一化 → JetStream 分片队列      │
   │  规则 / 情报 / UEBA / 时序检测    │
   │  去重 → 抑制 → 跨主机关联         │
   │  AI 研判 · 助手 · 定时巡检        │
   │  自主响应（租约 · 熔断 · AI 复核） │──→ Webhook（钉钉 / 飞书 / 企微）
   │  自我监控 · 审计链                │
   └────────────────┬─────────────────┘
                    ▼
   PostgreSQL（Patroni 高可用）←→ Web 控制台（React）
```

详见 [架构文档](docs/architecture.md)。

## 安装

一台装了 Docker 的 Linux 服务器，一行命令：

```bash
curl -fsSL https://github.com/yaklang/OpenXDR/releases/latest/download/install.sh | sudo sh -s -- <控制台域名或 IP>
```

脚本生成口令与密钥、签发 mTLS 证书、配好 HTTPS（解析到公网的域名自动申请 Let's Encrypt，内网地址用自建 CA），
拉起后打印控制台地址与 admin 口令。登录后在「系统设置 → AI 模型」接上任意 OpenAI 兼容端点，
再到「资产 → 添加主机」复制安装命令到被监控主机上执行即可。再执行一遍就是升级。

**或者交给你的 AI agent**（Claude Code、Codex、Cursor 等，在目标服务器上运行），把这句话发给它：

```text
请在这台服务器上安装 OpenXDR，严格按照 https://github.com/yaklang/OpenXDR/blob/master/docs/install.md 操作：
先检查环境并问我控制台用哪个域名或 IP，再执行安装，最后把控制台地址、admin 口令，以及被纳管主机信任 CA 的命令告诉我。
```

详细步骤、核对、升级备份与常见问题见 [安装](docs/install.md)。从源码构建开发：

```bash
docker compose up -d
# 控制台 http://localhost:5173   API :8080   gRPC 接入 :8081
docker compose logs server | grep admin   # 首次启动生成的 admin 密码
```

## 文档

| 文档 | 内容 |
|---|---|
| [安装](docs/install.md) | 一行安装、核对、升级备份、常见问题，也是给 AI agent 的安装说明 |
| [部署与使用手册](docs/deployment.md) | 启动、接入主机、日志与情报、抑制与处置、mTLS、配置项全表 |
| [高可用部署](deploy/ha/README.md) | Patroni + 三节点 JetStream + Keepalived VIP，滚动发布 |
| [资产图谱与攻击面](docs/asset-map.md) | 设备清单、依赖边、区域划分、风险分与 AI 标注 |
| [自主响应与自身防护](docs/autonomous-response-design.md) | 信号与处置、处置等级、租约与熔断、容器隔离、指令签名、审计链、自我监控 |
| [跨主机攻击的关联与升级](docs/attack-campaign-design.md) | 一次真实内网跳板攻击的复盘，按实体分桶、受害方横向、喷洒合成告警 |
| [AI 助手与巡检](docs/pi-backend.md) | 会话、命令名单与 AI 审计员、只读查询、运维待办、预设任务 |
| [文档导入与主机纳管](docs/host-enrollment.md) | 运维文档导入、凭据加密、SSH 纳管、安装包发布签名 |
| [软件漏洞](docs/vulns.md) | dpkg 软件清单、OSV 漏洞库同步、版本比较、已知限制 |
| [时序检测](docs/temporal-detection.md) · [身份关联](docs/identity-correlation.md) | 计数与序列规则；登录归一化与目录同步（均开发中） |
| [架构](docs/architecture.md) · [采集端](docs/collection.md) · [事件模型](docs/events.md) · [检测链路](docs/detection.md) | 设计与实现细节 |
| [REST API](docs/api.md) · [集群与可观测性](docs/cluster.md) · [路线图](docs/roadmap.md) | 对接、运维与规划 |

完整索引见 [docs/README.md](docs/README.md)。

## 目录

| 目录 | 说明 |
|---|---|
| `agent/` | Rust 端点 agent（Linux / Windows），含响应处置 |
| `sensor/` | Rust 全流量探针，AF_PACKET v3 / AF_XDP 双后端 |
| `server/` | Go 后端：接入、检测、关联、AI 研判与助手、REST / gRPC |
| `web/` | React 管理控制台 |
| `rules/` | Sigma 兼容检测规则 |
| `temporal-rules/` | 时序检测规则（计数 / 序列），与 Sigma 规则分开存放 |
| `tasks/` | 预设巡检任务（YAML） |
| `validation/` | [检测验证语料](validation/README.md)：真实攻击命令回放过规则引擎，CI 守住检测能力 |
| `deploy/` | 集群与高可用部署 |
| `proto/` | gRPC 契约 |
| `schema/` | 设计参考 DDL，实际表结构以 `server/ent/schema/` 为准 |
| `pages/` | 项目主页（GitHub Pages），与产品代码无关 |

## 当前状态

当前版本 v0.4.0。OpenXDR 在维护团队自己的内网以双节点高可用部署持续运行，纳管二十多台 Linux 与 Windows 主机，
自主响应、自我监控与审计链都在生产上开着。

- **Linux**：采集、检测、研判与巡检从 10 月起在生产上持续运行，自主响应从 v0.4.0 起在生产开启；eBPF 网络与 DNS 采集、容器归属已在多个发行版实机验证。
- **Windows**：ETW 进程、网络、DNS 与安全日志采集已在 Windows 10 实机上逐项验证（见 [实机回放](validation/replay/README.md)），覆盖面仍不如 Linux。
- **自主响应**：默认关闭。处置引擎只认确定性的合成检测与高级别情报，不凭 AI 结论直接动手（AI 只参与定级与到期复核）；建议先只对实验等级开启。
- **AI**：效果取决于所接模型的 tool calling 能力，模型越弱越容易在长上下文里跑偏。平台保证它越不过权限、名单与硬拒绝的边界，
  但不保证结论正确——研判结论供参考，事件仍由人结案。

已知缺口与后续计划见 [路线图](docs/roadmap.md)，每个版本的变化与升级须知见 [CHANGELOG](CHANGELOG.md)。

## 参与

欢迎 Issue 与 PR，提交前请读 [CONTRIBUTING.md](CONTRIBUTING.md)；安全问题请按
[SECURITY.md](SECURITY.md) 私下报告。

## 许可证

[Apache License 2.0](LICENSE)

第三方数据：`rules/sigmahq/` 为 SigmaHQ 社区规则（DRL 1.1，见其 README）；发版镜像自带的离线 IP 归属库为
[DB-IP Lite](https://db-ip.com)（IP Geolocation by DB-IP，CC BY 4.0），见 [资产图谱](docs/asset-map.md#离线归属库)。
