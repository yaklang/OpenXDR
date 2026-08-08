# 路线图

原则先行：**解决真实存在的问题，不为臆想的需求写代码。**
每一项都要回答"谁会因为没有它而受伤"。回答不了的，进"不做"清单。

## 现状快照（2026-08）

- **采集**：Linux 进程（eBPF/netlink/轮询三级降级 + exe SHA-256）、敏感文件
  （inotify）；Windows 进程（ETW）；全流量探针（DNS/TLS/HTTP 元数据 + JA3）；syslog
- **检测**：Sigma 引擎（热重载）16 条规则、四类 IOC 情报碰撞
- **降噪**：去重 → 抑制 → 关联（血缘/时间窗/横向移动）→ AI 研判 → 通知阈值
- **响应**：结束进程、主机隔离（mTLS + 按主机绑定证书）
- **运营**：概览漏斗、事件检索、规则/情报/抑制/资产/审计页、三角色 RBAC

## P0 —— 下一步就做

**1. ~~Windows 采集对称性~~ ✅ 已完成。** 注册表 Run/RunOnce/Winlogon 与
Startup 目录快照 diff。仍缺：服务与计划任务持久化点。

**2. ~~登录事件采集~~ ✅ 已完成。** Linux：wtmp/btmp 增量读；Windows：
Security 日志 4624/4625 订阅（Security-Auditing 的 ETW provider 是受保护
通道，Event Log API 是正路），滤掉机器账号与服务会话。两侧同出 OCSF 3002。
**✅ 爆破得手升级已完成**："窗口内 N 次失败后一次成功"在 ingest 侧检测
（成功登录稀少，回查一次库即可，无需引擎状态），合成 critical 告警
`xdr:bruteforce-success`，按用户维度隔离，Linux/Windows 通用。

**3. ~~事件检索规模化~~ ✅ 索引已完成**（pg_trgm GIN）。
待评估：events 表按时间分区（原生分区即可，TimescaleDB 作为可选增强），
等真实数据量说话再动。

**4. 检测面对拍验证 —— 合成回放 ✅ 已完成，实机待环境。**

`validation/` 语料 + `cmd/detectcheck`：50 个用例取自 Atomic Red Team 的真实
命令行，回放过引擎，判定标准是"命中的规则必须标了该技术"。已进 CI。

第一次跑出 14 个问题，全部修完，其中值得记住的三类：

| 类别 | 实例 | 教训 |
|---|---|---|
| 规则匹配不到真实命令 | `vssadmin delete shadows` 漏了 `.exe` 变体，一条 critical 勒索规则形同虚设 | 规则里别写命令名，写动作 |
| 完全没有规则 | LSASS 内存转储、`/etc/shadow` 读取 | 凭据窃取这么核心的手法之前是空的 |
| 抓到了但没标 | python 反弹 shell 命中却未标 T1059.006 | 覆盖矩阵会因此少算，与"标了抓不到"同样有害 |

**仍需实机**：合成回放绕过了采集层，验证不了"ETW/inotify 是否真的报了这个
动作"。需要 Linux + Windows 各一台可跑攻击模拟的测试机。

## P1 —— 看得见的价值

**5. ~~MITRE ATT&CK 映射~~ ✅ 已完成。** 引擎解析 Sigma tags，21 条规则
全部打标，`/api/attack` 出覆盖矩阵（含"有规则但无数据源"的差额）。

矩阵第一次跑出来就暴露了缺口，已补三条（删卷影 T1490、远程执行 T1021.002、
数据打包 T1560.001）。**仍然全空的战术**：initial-access、reconnaissance、
resource-development、exfiltration（仅间接覆盖）。前两个本质上需要边界设备
日志（邮件网关、WAF、VPN），属于接入面而非规则问题——等有真实环境再说，
不为假想数据源写规则。

**6. ~~incident 报告导出~~ ✅ 已完成。** `GET /api/incidents/{id}/report`
输出 Markdown，界面一键下载。渲染是纯函数，脱库单测。

**7. ~~AI 研判升级为工具调用~~ ✅ 已完成。** 研判可调用 query_events /
process_lineage / host_alerts 主动查证；误报反馈已回流进上下文；
同一套工具开放为对话式狩猎。**✅ 狩猎存为规则已完成**：AI 起草 Sigma
草稿（编译不过就回喂重试），分析师审阅修改后落盘规则目录，热重载生效。
落盘前强制过引擎编译器，AI 不能直接改检测面。

**8. ~~agent 配置下发~~ ✅ 已完成。** 配置存在资产上，随 `Register` 响应下发，
agent 断线重连本就会重新注册，因此不需要热更新通道也不需要新 RPC。
可调：文件监控目录、三个采集开关。坏配置一律退回内置默认——
让 agent 变瞎比配置不生效严重得多。

## P2 —— 时机到了再做

**9. ~~UEBA 首次出现~~ ✅ 已完成。** (资产, 可执行文件) 基线表，首次入表即
首次出现，合成 low 告警 `xdr:new-process` 进关联管道。学习期按资产从基线
最早记录起算（默认 7 天）——新资产、新部署、重启都先安静学习，无需额外
状态就避开告警风暴。断点存在基线表里，重启不回放历史。
外连基线偏离仍不做：信噪比不够，等首次出现在真实环境里证明自己再说。

**10. ~~自动响应~~ ✅ 已完成。** 研判钩子：verdict 为 malicious 且置信度
达标（默认 90）→ 对 incident 涉事资产下发隔离。四道保险：显式开启
（`AUTO_RESPONSE_ENABLED`）、默认 dry-run（真执行要 `AUTO_RESPONSE_LIVE`）、
主机白名单（`AUTO_RESPONSE_EXEMPT`）、每次决策含跳过都进审计。
同一 incident 同一资产只动一次，重开重判不重复隔离。

- **agent 独立网络采集**（无 sensor 的小部署盲区；eBPF tcp_connect 采样）
- **macOS agent**（Endpoint Security Framework）

## 不做

- **多租户 / SaaS 化**——目标用户是自建 SOC 的团队，租户隔离用"每客户一套"解决。
  为不存在的 SaaS 生意把每张表加 tenant_id，是给所有查询上税。
- **微服务拆分 / server 水平扩展**——单机 Go + Postgres 能撑到远超目标规模；
  dedup/correlate 状态外置换来的是分布式债。垂直扩容 + 读写分离足够。
- **存 PCAP 全包**——磁盘无底洞，会话元数据 + 按需取证是行业共识。
- **自研规则 DSL**——Sigma 生态就是护城河，兼容它而不是发明方言。

## 工程债（随手清）

- sensor 侧尚无 JA3S / 服务端指纹
- Windows ETW 采集无文件哈希（进程事件里补 exe SHA-256 需处理镜像路径转换）
- 前端无移动端适配（SOC 大屏优先，低优）
