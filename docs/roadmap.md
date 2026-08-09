# 路线图

原则先行：**解决真实存在的问题，不为臆想的需求写代码。**
每一项都要回答"谁会因为没有它而受伤"。回答不了的，进"不做"清单。

## 现状快照（2026-08-09 更新）

- **采集**：Linux 进程启停（eBPF/netlink/轮询三级降级 + username + exe SHA-256）、
  敏感文件（fanotify FID 优先 / inotify 递归兜底，fanotify 路径带进程上下文）、
  持久化点目录（systemd unit / cron / .ssh）、登录（wtmp/btmp）；Windows 进程启停
  （ETW + Win7 PEB cmdline 兜底 + exe SHA-256）、文件监控（RDCW）、持久化点
  （注册表 Run/Startup/服务/计划任务，删除带旧值）、登录（4624/4625 含失败原因码）；
  全流量探针（DNS 含应答与 rcode、TLS、HTTP 元数据 + JA3/JA3S）；syslog
- **检测**：Sigma 引擎（热重载）29 条规则、三类 IOC 情报碰撞（IP/域名/哈希；
  TLS 指纹 JA3/JA3S 走哈希通道）
- **降噪**：去重 → 抑制 → 关联（血缘/时间窗/横向移动）→ AI 研判 → 通知阈值
- **响应**：结束进程、主机隔离（mTLS + 按主机绑定证书）
- **运营**：概览漏斗、事件检索、规则/情报/抑制/资产/审计页、三角色 RBAC

## P0 —— 下一步就做

**1. ~~Windows 采集对称性~~ ✅ 已完成。** 注册表 Run/RunOnce/Winlogon 与
Startup 目录快照 diff。~~仍缺：服务与计划任务持久化点~~ ✅ 已补齐（见附录 P1-6）。

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

**11. ~~agent 独立网络采集~~ ✅ 已完成（eBPF 模式）。** tracepoint
`sock:inet_sock_set_state` 抓 TCP 进 SYN_SENT（本机主动出站，必然在发起
进程上下文里），带 pid → 进程 GUID，网络事件直接挂进血缘。同目标 60s
采样去重，loopback 不报。conn_tuple 与 sensor 同格式，横向移动关联与
现有网络规则零改动复用。仅 eBPF 模式提供；netlink 模式不做——
proc connector 没有网络事件，为它单开轮询不值。

- **macOS agent**（Endpoint Security Framework，需 Mac 开发环境）

## 不做

- **多租户 / SaaS 化**——目标用户是自建 SOC 的团队，租户隔离用"每客户一套"解决。
  为不存在的 SaaS 生意把每张表加 tenant_id，是给所有查询上税。
- **微服务拆分 / server 水平扩展**——单机 Go + Postgres 能撑到远超目标规模；
  dedup/correlate 状态外置换来的是分布式债。垂直扩容 + 读写分离足够。
- **存 PCAP 全包**——磁盘无底洞，会话元数据 + 按需取证是行业共识。
- **自研规则 DSL**——Sigma 生态就是护城河，兼容它而不是发明方言。

## 工程债（随手清）

- ~~sensor 侧尚无 JA3S / 服务端指纹~~ ✅ 已完成（ServerHello→JA3S，入情报碰撞）
- ~~Windows ETW 采集无文件哈希~~ ✅ 已完成（设备路径→Win32 路径转换后哈希生效）
- 前端无移动端适配（SOC 大屏优先，低优）

---

## 附：后续工作详细规划（2026-08 代码核实版）

以下规划基于对采集端与 server 全量代码的逐项核实（结论与证据见
[docs/collection.md](collection.md) 与 [docs/events.md](events.md)），
按"缺口严重度 × 工程成本"排序。**P0 与 P1 已全部完成**（2026-08-09，
验证：cargo fmt/clippy/test、go build/vet/test、sigmacheck、detectcheck 全过）。

### P0 —— 修正确性缺陷 ✅ 全部完成

1. ~~补 Linux 进程事件 username~~ ✅ `mod.rs:185` `username_of`：/proc status
   读 uid → /etc/passwd 解析（带缓存），eBPF/netlink 路径已接入。
2. ~~修 eBPF 降级链~~ ✅ eBPF 失败 → netlink → 轮询逐级回落
   （`linux.rs:39-51`）；`agent/Cargo.toml` 错误注释已修正。
3. ~~Windows ETW 哈希路径转换~~ ✅ `windows.rs:95` `to_win32_path`
   （QueryDosDeviceW 映射），exe SHA-256 真正生效。
4. ~~persistwatch 删除告警~~ ✅ 注册表值与 Startup 文件删除均上报，
   删除事件带旧值内容。
5. ~~文档对齐代码~~ ✅ docs 文档系统重建（见 docs/README.md）。

### P1 —— 补采集面缺口 ✅ 全部完成

6. ~~Windows 服务与计划任务持久化点~~ ✅ `persistwatch.rs:130,179`：
   服务快照（ImagePath+启动类型）与 Tasks 目录递归快照，增/改/删全报。
7. ~~进程退出事件（双平台）~~ ✅ netlink `PROC_EVENT_EXIT`（含 exit_code）、
   ETW Stop（ID 2）、轮询消失 pid、eBPF `sched_process_exit`；退出事件
   复用启动 GUID（`mod.rs:230-251`）。
8. ~~Windows 文件监控~~ ✅ 新模块 `fswatch_win.rs`（ReadDirectoryChangesW），
   与 Linux fswatch 事件格式对齐，`collectFiles`/`fileWatchDirs` 在
   Windows 侧有了消费者。
9. ~~4625 字段补全~~ ✅ `authwatch_win.rs` 解析 Status/SubStatus →
   `status_code`/`status_detail`。
10. ~~sensor DNS 应答解析 + JA3S~~ ✅ `proto_id.rs`：压缩指针安全解析、
    rcode、A/AAAA 应答（至多 4 个）、ServerHello→JA3S；proto 新增
    `dns_rcode/dns_answers/ja3s`；应答 IP 与 JA3S 自动入情报碰撞。

### P2 —— 结构性增强

11. ~~Linux 持久化点扩展~~ ✅ fswatch 默认目录增加
    `/etc/systemd/system`、`/var/spool/cron`、各用户 `.ssh`；inotify
    递归化（限深 4 层，运行中动态补挂）。
12. ~~文件事件带进程上下文~~ ✅ fanotify（FID 模式）优先路径：事件自带
    pid → exe/comm/属主，无权限时干净回落 inotify（`fswatch.rs:70`）。
13. **实机攻击验证环境（部分完成）**。2026-08-09 已在 Windows 开发机上
    完成首轮实机冒烟（便携 PostgreSQL + server + release agent 全链路）：
    进程启动/退出（含 cmdline、DOMAIN\user、sha256、退出复用启动 GUID）、
    RDCW 文件增删改、Run 键/服务/计划任务的增删（删除带旧值）、4625
    失败登录（status_code/status_detail）均按预期上事件，且 5 条新规则
    在真实数据流上全部命中。**仍待做**：Linux 实机（fanotify/netlink EXIT/
    eBPF 全路径）、Win7/2008R2 实机（PEB cmdline 兜底）、Atomic Red Team
    脚本化回放为可重复的端到端验证。

### 兼容性备忘（本轮顺带解决/确认）

- Win7/2008R2：ETW cmdline 信息类要求 Win 8.1+，已加 PEB 读取兜底
  （`windows.rs:235`）；Rust  MSVC 目标对 Win7 的运行支持需实机确认。
- musl/32 位 Linux：authwatch 解析的 utmp 字段（type/line/user/host）偏移
  在时间字段之前，musl 与 32 位布局相同，实际兼容（此前"会解析错误"的
  担心不成立）。
- CentOS 7 级老内核（3.10）：无 inet_sock_set_state（eBPF 网络采集降级）、
  无 nftables（主机隔离失败）——维持现状，不为过老内核写兼容层。

### 当前迭代收尾计划（2026-08-09 起，按序执行）

P0/P1/P2 代码改动共 43 个文件尚未提交，收尾顺序：

1. **Linux 编译验证（进行中）**：本轮 Linux-only 改动（netlink EXIT、
   fswatch 804 行重写、linux.rs 降级链、eBPF exit 程序）尚未过编译器。
   在 WSL2 Ubuntu 中装 Rust 工具链，跑 agent/sensor 的
   `cargo build --locked && clippy -D warnings && test`，sensor 整 crate
   一并验证（此前只跑过脚手架 crate）。
2. **粗粒度分组提交 + CI 全绿**：按"proto+pb / 采集端 / server / 规则+语料 /
   文档"粗分组提交（不拆碎）。CI 重点盯：Linux 构建、eBPF/xdp 特性构建、
   Windows 交叉编译 clippy、集成测试。
3. **实机验证收尾**：Linux 实机冒烟（fanotify 进程上下文 / netlink EXIT /
   eBPF 全路径，断言清单对齐 Windows 冒烟）；Win7/2008R2 实机（PEB cmdline
   兜底 + MSVC 二进制兼容性）；Atomic Red Team 脚本化回放（把 validation/
   语料对应技术实机执行，验证采集可见性——detectcheck 只验证规则层）。

### 维持"不做"的判断

macOS agent（无 Mac 开发/CI 环境，写了也守不住编译）、Windows 端点网络采集
（sensor 已覆盖，避免重复建设）、多租户、微服务拆分、存 PCAP、自研规则 DSL。
