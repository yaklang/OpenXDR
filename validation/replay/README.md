# 实机回放验证

`validation/` 根目录的语料 + `cmd/detectcheck` 是**合成对拍**：验证规则引擎对
真实攻击命令的判定，但不经过采集端。本目录是另一半：**实机端到端回放**——
在装了 agent 的真实系统上执行攻击命令，断言"事件上来了 + 规则命中了"。
它验证的是 detectcheck 覆盖不了的东西：采集可见性、事件字段完整性、
以及"规则模式是否匹配实机命令行形态"。

## 运行方法

前置：server 与 agent 在线（agent 注册成功、采集器日志正常）。

- Windows（管理员 PowerShell）：`powershell -NoProfile -ExecutionPolicy Bypass -File validation/replay/windows.ps1`
- Linux（root）：`bash validation/replay/linux.sh`

两个脚本都只跑**安全子集**：不删卷影、不转储凭据（杀毒必拦，拦了测不出采集）、
不清系统日志。所有动作可逆，持久化点当场建当场删。

断言（PostgreSQL 直查最可靠）：

```sql
-- 进程事件（启动应有 cmd_line；退出复用启动 GUID）
select raw->'process'->>'name', raw->>'activity_id', raw->'process'->>'cmd_line'
from events where class_uid=1007 and ts > now() - interval '15 minutes';
-- 文件事件（建=1/改=3/删=4，fanotify 路径带肇事进程）
select raw->'file'->>'path', raw->>'activity_id', raw->'process'->>'name'
from events where class_uid=1001 and ts > now() - interval '15 minutes';
-- 规则命中
select rule_id, sum(count) from alerts
where ts > now() - interval '15 minutes' group by 1;
```

## 各系统 × 采集路径验证矩阵

| 采集路径 | Windows 11 本机 | WSL2 Ubuntu（6.18 内核） | Win7/2008R2 | 真 Linux |
|---|---|---|---|---|
| 进程启动（ETW / netlink / eBPF / 轮询） | ✅ ETW | ⚠️ 轮询兜底（命名空间设计降级） | 未验证（PEB 兜底） | ✅ netlink（PVE 7.0 内核） |
| 进程退出 | ✅ ETW Stop，复用启动 GUID | ⚠️ 轮询消失检测 | 未验证 | ✅ netlink EXIT，复用启动 GUID |
| 短命进程 cmdline | ✅（极快进程有竞争，见下注） | ❌ 多为空（轮询固有） | 未验证 | ✅ uname/whoami/cat/sh/timeout 完整 |
| 文件监控（RDCW / fanotify / inotify） | ✅ RDCW 增改删 | ✅ fanotify 全生命周期+肇事进程 | — | ✅ fanotify 增改删+肇事进程 |
| 持久化点（注册表/Startup/服务/计划任务） | ✅ 增删，删除带旧值；Win10 测试机：交互用户（非 SYSTEM）自己 HKCU 的 Run 与 CLSID 增删带属主 SID，登录/登出不报增删（第六轮） | ✅（经 fanotify 覆盖 systemd/cron/.ssh） | — | — |
| 网络（ETW / eBPF 出站） | ✅ ETW TcpConnect + 进程 GUID | ✅ eBPF 捕获 10.0.0.1:4444 | — | ✅ eBPF 完整五元组+进程 GUID |
| 网络入站 / UDP 出站（eBPF SYN_RECV→ESTABLISHED、kprobe udp_sendmsg；ETW TcpAccept / UDP 发送） | ✅ Win10 测试机：入站归属到监听进程、UDP 出站带进程、nslookup 直发 UDP 53 按进程上报（第五轮） | ✅ 入站归属到监听进程（python3 :8000）、UDP 出站 1.1.1.1:123 带进程（docker 特权容器 `--pid=host --cgroupns=host`，6.6 内核，2026-10-18） | — | ✅ Debian 12 测试机（6.1 内核）：TCP 入站归属监听进程、UDP 出站带进程（第七轮） |
| DNS（AF_PACKET + 经典 BPF；Windows ETW DNS-Client 3008） | ✅ Win10 测试机：问答、NXDOMAIN（rcode 3 + SOA）、CNAME 链入库，按发起进程归属，出站连接回填域名（curl → www.baidu.com）（第五轮） | ✅ 问答配对、rcode / 应答入库，按源端口归属到发起 pid，出站连接回填域名（curl → example.org） | — | ✅ Debian 12 测试机：问答配对、NXDOMAIN（rcode 3）、按源端口归属进程、出站 TCP 连接回填域名（curl → example.com）（第七轮） |
| 采集活性检测（静默降级、自检不外发） | ✅ Win10 测试机：外部停掉 `OpenXDR-Process` 会话，5 分钟后进程能力降为 degraded 并带原因（第五轮） | — | — | 见第五轮 |
| 退出码与运行时长（eBPF exit_group / ETW ProcessStop） | ✅ Win10 测试机：ETW `ProcessStop` `ExitCode` 解析（`exit 7` → `exit_code=7, duration_ms=2767`）（第七轮） | ✅ `sh -c "sleep 2; exit 7"` → 退出码 7、2001 ms | — | ✅ Debian 12 测试机（eBPF `exit_group`）：`sh -c "sleep 2; exit 7"` → `exit_code=7, duration_ms=2001`（第七轮） |
| 平凡退出抑制（exit 0 且 <2s 不发 Terminate） | ✅ Win10 测试机：`exit /b 0`（<2s）抑制 Terminate，`exit /b 9`（<2s）与 `sleep 3; exit 0` 照常发 Terminate 并复用启动 GUID（第七轮） | 未验证 | — | ✅ Debian 12 测试机（eBPF）：`exit 0`（<2s）抑制 Terminate，`exit 9`（<2s）与 `sleep 3; exit 0` 照常发 Terminate 并复用启动 GUID（第七轮） |
| 容器归属（cgroup） | — | ✅ docker 容器 ID（需 `--cgroupns=host`，否则看到相对路径） | — | ✅ Docker 容器 ID + 容器名，PVE `lxc` / `qemu` VMID + 名称（第七轮） |
| 登录（4624/4625 / wtmp-btmp） | ✅ 4625 含失败原因码 | 不适用（WSL 无 wtmp 写入） | 未验证 | ✅ wtmp SSH 登录 |
| sensor TLS 证书元数据（跨段重组 + x509 解析） | —（sensor 仅 Linux） | ✅ lo 抓自签 TLS1.2 握手，`tls.cert` 全字段入库并触发自签证书告警 | — | ✅ Debian 12 测试机 eth0 在线接入（2026-10-21）：证书主体/签发者、JA3/JA3S、DNS 问答入库 |
| sensor 只握手标注（`tls.handshake_only`） | — | — | — | ✅ 同机实测：TLS1.3、TLS1.2 只握手不发请求均标注，正常 HTTPS 请求不标；会话归到资产 |

注：Windows 上秒退进程（如 `reg add`）的 cmdline 靠 ETW 事件触发后回读，
进程已退场则读不到（cmd_line 为空）——已知竞态，注册表/文件类事件不受影响。

注：「平凡退出抑制」为有意行为（`suppressTrivialExit`，默认开）：退出码为 0 且存活
不到 2 秒的进程不再单独上报 Terminate（启动事件照发）；非零退出码、退出码未知
（被信号杀）、启动时间未知、存活 ≥2 秒的照常上报；关闭开关恢复逐条上报。实机回放
应选取明显低于/高于 2s 阈值的进程，避免把调度抖动当失败；精确 2s 边界由受控单测
覆盖（`collector::tests` 判定矩阵）。轮询路径本就不上报秒退进程，不能作为抑制生效
的证据。登记时记录 agent 版本、`suppressTrivialExit` 配置、实际采集后端与关联 GUID。

## 实机规则命中记录（2026-08-09）

- Windows：Windows Recon（systeminfo）、LOLBin Download（certutil/bitsadmin/mshta）、
  Suspicious PowerShell、Autostart Registry Write via CLI、Remote Execution Lateral
  （wmic /node:）、Service Installed、Autostart Entry Deleted、Run Key Persistence
- Linux（WSL2）：Sensitive File Modified、Systemd Service Unit File、
  Suspicious Outbound（eBPF 捕获 4444 出站）
- sensor（WSL2 lo 抓包）：TLS Self-Signed Certificate（自签 TLS1.2 握手，
  证书跨段重组解析 → `tls.cert` 入库 → 告警，2026-08-09）
- 良性对照零误报：`tasklist|findstr lsass`、`sh -c 'echo hello'`、`tar czf /tmp/build.tar.gz`

## 回放抓到的真实缺陷（全部当天修复）

1. **fanotify 路径还原全灭**（WSL2 6.18）：O_PATH 挂载 fd 的 `open_by_handle_at`
   一律 EBADF → 改 O_RDONLY（`fswatch.rs` `mount_fd_for`）。
2. **fanotify 只报改不报建删**：解析器只认 `FAN_EVENT_INFO_TYPE_FID`，
   建/删/移动事件内核发的是 DFID/DFID_NAME → 统一解析（`fswatch.rs` `fa_parse`）。
3. **一条带 NUL 的脏事件毒化整个事件管道**：Windows
   `ProcessCommandLineInformation` 长度计入结尾 NUL → jsonb 拒收（22P05）→
   批量插入失败 → agent 重连重放同批再失败，死循环。双侧修：agent 剥结尾
   NUL（`windows.rs` `command_line`）+ server ingest 递归剥 NUL
   （`grpcsvc/sanitize.go`，纵深防御）。
4. **规则裸命令名匹配不到实机命令行**：实机 ETW 命令行是带引号全路径
   （`"C:\...\WMIC.exe" /node:...`），`wmic /node:`、`schtasks /create /s `、
   `reg add` 这类裸名模式全部落空 → 规则改为动作形态匹配
   （`win_remote_exec_lateral`、`win_reg_add_autostart`），语料补实机形态用例。
   教训与 vssadmin 一脉相承：**规则里写动作，别写命令名**。

## 第二轮：AB 档采集扩充实机回放（2026-08-09）

A/B 档 15 个采集项全部实机回放，验证环境同上（Win11 本机 + WSL2 Ubuntu）。

**实机验证通过**：账户管理（4720/4726/4732）、审计策略变更（4719）、
PowerShell 4104 脚本块（FromBase64String 内容进 cmd_line）、IFEO 劫持
（建/删）、COM 劫持（建/删）、WMI 订阅持久化（建/删/系统项改）、ETW
Kernel-Network 网络进程归属（curl 出站 4001 带 GUID）、at 任务文件、
shell rc 文件、内核模块加载/卸载（1005）。

**实机命中规则（8 条）**：At Job Persistence、IFEO Debugger Hijack、
Shell RC File Persistence、WMI Event Subscription Persistence、Linux Kernel
Module Loaded、Windows Service Installed or Tampered、Windows Account
Management、Suspicious PowerShell Script Block。

**本机不可触发（环境限制，非代码问题）**：4648 显式凭据（本机 Server 服务
未运行，net use 到不了认证层）、1102 日志清空（破坏性，不在开发机做）、
Defender 排除项（第三方杀毒在管，Defender 未运行，Add-MpPreference 不落
注册表）、EventLog 服务停止（受保护服务）。

**这轮回放的三条教训**：
1. Remove-WmiObject 没有 -Filter 参数——删除要写
   `Get-WmiObject ... | Remove-WmiObject`，回放脚本里写错会留下残留实例
   污染后续快照基线。
2. 快照类采集（persistwatch 30s / kmodwatch 30s）回放时建删之间必须留
   ≥35s，否则中间态被跳过（与第一轮 persistwatch 教训同型）。
3. 监控目录在 agent 启动后新建的（如 /var/spool/at）曾经不会被补盯；现已增加
   5 秒周期补扫，fanotify/inotify 两条路径都会自动补挂。

## 第三轮：真 Linux 双机回放（2026-08-09）

环境：两台 Debian 13 / Proxmox VE 9.2.2 宿主机，内核均为
`7.0.2-6-pve`。当前 HEAD 的默认特性 agent 同时接入临时隔离 server，响应处置
保持关闭。

- 两台均选择 netlink proc connector，未降级轮询；短命进程的 name/cmdline
  完整，EXIT 事件复用启动 GUID 且带 `exit_code=0`。
- 两台均选择 fanotify，systemd unit 与 cron 文件的建/改/删共 12 条事件全部
  上报，带实际写入进程（bash/rm）。
- 两次新 SSH 会话均由 wtmp 采集为 3002 登录事件，用户名与源 IP 正确。
- 两台均实机命中 Credential Dumping、Linux Recon、Linux Reverse Shell、
  Systemd Service Unit、Sensitive File Modified；pve2 额外验证 dummy 模块加载，
  1005 事件和 Linux Kernel Module Loaded 规则均命中。
- 回放结束后 agent/server/数据库、测试文件和内核模块全部撤销，无常驻产物。

## 第四轮：PVE 测试机回放（2026-10-20）

环境：pve2 上的 Debian 12 云镜像 VM（内核 6.1，eBPF + AF_PACKET + fanotify）、pve1 上的 Windows 10 Pro 22H2 VM
（无人值守安装，Defender 实时防护回放期间临时关闭、结束后恢复），均由生产 HA 控制台的「采集验证测试」组接入，
agent 为 v0.2.0 musl 静态 / mingw 构建。

- Linux：14 条规则实机命中，含两条新时序规则（读影子口令库后打包 `linux-shadow-read-archive`、
  凭据读取后外联 4444 `credential-dump-suspicious-outbound`）；1001 / 1005 / 1007 / 4001 事件齐全。
- Linux 缺口：脚本里的 `curl … | bash` 没命中 Download and Pipe to Shell——管道两端是同一父进程下的两个兄弟进程，
  两条命令行里都没有 `|`，规则按命令行匹配看不到。交互 shell 与 `sh -c 'curl … | sh'` 形态不受影响。
  仍未覆盖：规则侧没有可用的写法，原因见 [temporal-rules/README.md](../../temporal-rules/README.md#当前格式做不到留待引擎扩展的链路)，
  语料以已知缺口记录。
- Windows：17 条规则实机命中（含 Windows Recon、Suspicious PowerShell Invocation、IFEO、Defender 排除项、WMI 订阅、
  账户管理），两条新时序规则（LOLBin 下载后写自启动 / 建计划任务）同样命中；临时关闭 Defender 也被 Security Service Stopped 报出。
- Windows 缺口：COM 劫持（HKCU CLSID InprocServer32）与审计策略变更（4719，activity_id 15）**已采集、没有规则**；
  网络只有 TCP 出站（`etw-tcp-out` 报 degraded 是设计如此），DNS 未采集。
  前两项已补规则 `User-Level COM Hijack (HKCU CLSID Server)`、`Windows Audit Policy Disabled`，
  语料直接取本轮入库的原始事件（4719 的 `policy_changes` 是 `%%8448, %%8450` 这类消息 ID，不是文字）。
- 本轮抓到的真实缺陷：
  1. **Windows 进程采集静默停止**：ETW 会话随机命名，agent 被强杀或升级退出时会话泄漏；Kernel-Process provider 可挂的会话数有限，
     测试机漏到 7 个后新会话收不到任何进程事件，健康状态却仍报 `etw/active`。改为固定会话名并在启动前停掉同名旧会话（894bbc7）。
  2. 分发目录里的 Linux agent 是 glibc 动态链接（在 Debian 12 上报 `GLIBC_2.39` 弱符号警告），换成与发版一致的 musl 静态构建。
  3. 回放脚本：Linux 版会覆盖 `/root/.ssh/id_rsa`、删 `authorized_keys`，与「全部可逆」不符，改为先备份、退出时还原；
     Windows 版 Defender 排除路径里混进了响铃字符（`\a` 被转义），排除项写的是乱码路径，改回 `C:\atomic-test`。
  4. 生产 JetStream 的一个消费者（`ingest-0a`）leader 漂到公网 witness 且其流副本落后，该分片停止投递约 10 分钟、积压 2 万条；
     挪回内网节点后几分钟内追平。中心 Grafana 的队列积压告警覆盖了这种情况。

## 第五轮：采集活性检测与 Windows 网络 / DNS 补全（2026-10-20）

环境：同第四轮的 pve1 Windows 10 22H2 测试机与 pve2 Debian 12 测试机，接入生产 HA 控制台。测试版 agent 为当前分支构建，
临时去掉了二进制哈希上报（否则注册时会被生产分发目录自动升级回去），测完换回原版。

- Windows DNS（ETW DNS-Client 3008）：`Resolve-DnsName`、.NET 解析、curl 的查询均以 4003 入库并归属到发起进程；
  NXDOMAIN 报 rcode 3 带回 SOA，CNAME 链与 IPv4 映射地址还原正确；只查缓存的试探、getaddrinfo 取消的一路、localhost 不报。
- Windows 网络：TcpAccept 入站归属到监听的 powershell 进程，`conn_tuple` 发起方在前；UDP 出站带进程；
  nslookup 绕过系统解析器直发的 UDP 53 按进程上报，不再被 Dnscache 服务对同一服务器的查询压掉；
  curl 的出站连接回填了 DNS 采集见过的域名。
- 抓到的缺陷：Windows 的进程、网络、DNS 是三个 ETW 会话，短命进程（nslookup、curl）的连接与查询比它的启动事件早到
  约 1.5 秒，网络侧现场登记的 GUID 随后被启动事件换掉，血缘断开、事件没有进程名。改为先到的事件占位、10 秒内到达的
  启动事件沿用占位 GUID，实机确认 curl 的连接、DNS、启动、退出四条事件同一 GUID。
- 活性检测：外部 `logman stop OpenXDR-Process -ets` 模拟第四轮的「会话在、事件无」——之前健康状态会一直报
  `etw/active`；新 agent 5 分钟后报「持续 5 分钟收不到进程事件，自检进程也没被看到」。生产 server 尚是旧版，
  按设计拒收带 `reason` 的快照（`采集状态上报失败：InvalidArgument`），印证了先升 server 后升 agent 的顺序要求。
  agent 重启后会话重建，能力回到 active。
- 测试机上 persistwatch 每 30 秒拉起一次 WMI 查询的 powershell，进程通道在 Windows 上不会静默到触发自检；
  自检进程不外发由单测与 Linux 测试机验证。

## 第六轮：用户配置单元的持久化点（2026-10-21）

环境：pve1 Windows 10 22H2 测试机（本地管理员 kei 自动登录），接入生产 HA 控制台。测试版 agent 为当前分支构建，
同第五轮临时去掉二进制哈希上报，测完换回生产分发版。

前几轮的 HKCU 回放之所以命中，是因为回放脚本经 qemu-ga 以 SYSTEM 执行、写进了 SYSTEM 自己的 HKCU（S-1-5-18）；
agent 也以 SYSTEM 运行，读的正是这一份，真实用户自己 HKCU 下的写入它一直看不到。本轮改为枚举 `HKEY_USERS` 下已加载的
用户配置单元后实测：

- 以 kei 交互身份（一次性计划任务，`LogonType Interactive`）写 HKCU Run 值与 `CLSID\{…}\InprocServer32` 默认值，
  确认写进 `HKU\<kei 的 SID>` 而 SYSTEM 的配置单元没有；下一轮快照报出两条 201002 Create，路径 `HKCU\...`、
  `user` 为 kei 的 SID 与 `OPENXDR-TESTWIN\kei`，实机命中 Registry Run Key Persistence 与 User-Level COM Hijack；
  删除后两条 Delete，命中 Autostart Registry Entry or Service Deleted。
- `logoff` 注销 kei（配置单元卸载，其 Run 下的 OneDrive 与 22 个 CLSID 从快照里整组消失）：不产生任何 HKCU 删除事件。
- 抓到的缺陷：注销时系统删掉每用户服务实例（`CDPUserSvc_33fa3` 等 20 个，Type 带 0x80），旧版服务快照把它们报成
  一批「服务被删除」并命中 Autostart Registry Entry or Service Deleted，登录时又报一批新增。改为实例不进快照
  （须有带用户服务位的同名模板、ImagePath 展开后一致），模板仍在快照里；复测注销不再有服务删除事件。
- 测试机上注销控制台会话后，ACPI 关机与 `shutdown /r` 都卡在「系统正在关机」，agent 等进程已退出仍不前进，
  只能 `qm reset`；卡住时 agent 进程已退出，未见与 agent 相关的迹象，但没查到根因，记在这里供以后在这台机上做注销测试时参考。

## 第七轮：Linux eBPF 网络/DNS/退出码与双平台平凡退出抑制补验（2026-11-02）

环境：pve2 Debian 12 测试机 `openxdr-test-linux`（`10.1.1.137`，内核 `6.1.0-54-cloud-amd64`，采集后端 `ebpf` + `AF_PACKET` + `fanotify`，`suppressTrivialExit=true`，agent 哈希 `4bf965743c44...`）、pve1 Windows 10 Pro 22H2 测试机 `OPENXDR-TESTWIN`（build 19045，采集后端 `etw` + `RDCW`，`suppressTrivialExit=true`，agent 哈希 `653999b7af63...`）以及生产 PVE/Docker 宿主机群，均接入生产 HA 控制台。

- **Linux 平凡退出抑制与 eBPF `exit_group` 退出码/时长**：
  - `sh -c "echo p1-trivial-exit-0; exit 0"`（pid 6899，`process_guid = bef0f832-eded-4bf7-b14f-826d4732a6fc`）：仅上报 Launch（`activity_id=1`，事件 `edc1c0b8-001a-8914-bb1c-5d4e941becf3`），Terminate（`activity_id=2`）被抑制（0 条）。
  - `sh -c "echo p1-fast-exit-9; exit 9"`（pid 6900，`process_guid = a406bb70-ad16-4d43-8a4d-77045fd93238`）：非零退出码不抑制，Launch（`3ecec8eb-9d85-86d0-94cf-e5cb897aeb4d`）与 Terminate（`51f16bc4-96bf-8467-a22a-03de0bb9e8a2`，`exit_code=9, duration_ms=0`）均入库且复用同一 GUID。
  - `sh -c "echo p1-long-exit-0; sleep 3; exit 0"`（pid 6901，`process_guid = 076e7f35-4f83-48f2-bfb0-d57b5fbcb874`）：存活 ≥2s 不抑制，Launch（`8acbc3f4-8b25-8303-a14a-00f5ef414f5e`）与 Terminate（`81c2be4c-c680-8307-a726-2848610d8bd6`，`exit_code=0, duration_ms=3001`）均入库且复用同一 GUID。
  - `sh -c "echo p1-long-exit-7; sleep 2; exit 7"`（pid 6903，`process_guid = 77e414bb-3a36-4b56-b3e9-e23f6082d80e`）：Launch（`8e7b223d-3fdb-8aa8-a6a6-251021bbd7d4`）与 Terminate（`26596e55-eca7-85bd-8ec0-36ee4097525c`，`exit_code=7, duration_ms=2001`）均入库。
- **Linux eBPF 网络入站 / UDP 出站与 DNS 问答/回填**：
  - UDP 出站（`kprobe udp_sendmsg`）：`python3` 向 `1.1.1.1:123` 发包，入库 `4001`（`b80db656-9190-8f17-991d-fd9b18328ec9`，`conn_tuple="udp:10.1.1.137:37856>1.1.1.1:123"`，`direction="outbound"`），归属到 `python3`（pid 6905，`process_guid = 1fe58d2a-7fc6-48ac-b536-34ff0d721b24`）。
  - TCP 入站（`SYN_RECV→ESTABLISHED`）：宿主机连接测试机 `:18124`，入库 `4001`（`9f580c2b-90df-82c8-ac53-bdc4cc923a91`，`conn_tuple="tcp:10.1.1.3:60328>10.1.1.137:18124"`，`direction="inbound"`），归属到监听进程 `python3`（pid 6912，`process_guid = 9013098f-3acb-4a15-ba8d-1b775fed97a9`）。（注：若用户态测试脚本在 `accept()` 后 `<1ms` 内立即 `close` 并退出进程，`/proc/<pid>/fd` 在 socket inode 反查前已消失，`4001` 仍入库但无 `process` 字段；正常常驻监听服务不受影响。）
  - DNS 问答配对与出站回填：`curl --noproxy "*" http://example.com` 触发 `4003`（`46ac9ac7-ecc5-8007-9a59-8e9b13b68e9a`，`rcode_id=0`，`answers` 含 `172.66.147.243` / `104.20.23.154`，按源端口 `50952` 归属到 `curl` pid 6913），紧随的 TCP 出站 `4001`（`514a2022-9431-8f22-a5b4-bb4cbb631206`，`tcp:10.1.1.137:36114>172.66.147.243:80`）`dst_endpoint.hostname` 回填为 `"example.com"`；NXDOMAIN 查询 `nonexistent-p1-replay-check.invalid` 入库 `4003`（`ff4d9cb3-6707-8a65-bda2-def0b64c3f0b`，`rcode_id=3`，按源端口 `48399` 归属到 `python3` pid 6906）。
- **Linux 容器归属（`cgroup`）**：
  - Docker 宿主机（`docker` 等）上容器内进程事件携带 `container: {"runtime":"docker","uid":"<12位容器ID>","name":"<容器名>"}`（如 `blue-server`、`SoulStream-server`、`cache`）。
  - Proxmox VE 宿主机（`pve1` / `pve2`）上 LXC 与 QEMU 子进程事件携带 `container: {"runtime":"lxc"|"qemu","uid":"<VMID>","name":"<CT/VM名称>"}`（如 `lxc` 201 `dns-primary`、202 `dns-secondary`、203 `gateway`、204 `monitor`；`qemu` 103 `zachary-dev`、9001 `secrux-verify-amd64`）。
- **本轮抓到的真实缺陷与 Windows 实机补验**：
  - **缺陷：Windows ETW `EVENT_PROCESS_STOP` 漏解 `ExitCode` 导致退出码恒为空且平凡退出抑制在 Windows 上完全失效**。`Microsoft-Windows-Kernel-Process` 事件 ID 2（`ProcessStop`）载荷自带 `ExitCode`（`UInt32`），但 `agent/src/collector/windows.rs` 原先未解析该字段（`exit_code: None`）。由于 `ProcessRegistry::trivial_exit` 对 `exit_code == None` 采取保守放行（视作未知退出码，不抑制），Windows 上所有 `<2s` 且 `exit 0` 的短命进程（包括 agent 自身 `persistwatch` 每 30 秒拉起的 4 个 `<1s` `powershell.exe` / `conhost.exe` 子进程）均被逐条上报 Terminate。
  - **修复与实机验证**：在 `windows.rs` `EVENT_PROCESS_STOP` 分支补上 `parser.try_parse("ExitCode").ok()`，通过在线自动升级（退出码 75 原子替换）推送至 `OPENXDR-TESTWIN` 后实测四组对照：
    1. `cmd.exe /c "echo win-p1-trivial-exit-0 & exit /b 0"`（`process_guid = f2b28910-5763-4c39-aa70-a8df01718a5f`）：仅上报 Launch（`c799e421-0366-8521-8cde-aa57ca6bee2b`），Terminate 被抑制（0 条）；同周期 `persistwatch` 的 `<1s` `powershell.exe` 子进程 Terminate 亦同步被抑制。
    2. `cmd.exe /c "echo win-p1-fast-exit-9 & exit /b 9"`（`process_guid = 5a5007e4-8b84-4943-a0be-18b2c2cf6a16`）：Launch（`dbbe1b2a-2836-8cdc-908c-e86816ea1d76`）与 Terminate（`eb33e4b4-7f75-80f6-b049-3ea68d584918`，`exit_code=9, duration_ms=0`）均入库且复用同一 GUID。
    3. `powershell.exe -NoProfile -Command "Write-Output win-p1-long-exit-0; Start-Sleep -Seconds 3; exit 0"`（`process_guid = 5fced765-f676-44c1-8513-f3fc05911c3b`）：Launch（`b36dc8e8-a128-8dff-9047-0736bc9e23e3`）与 Terminate（`27a8944e-9027-8ae0-a6dd-9afbd2596ac6`，`exit_code=0, duration_ms=3265`）均入库且复用同一 GUID。
    4. `powershell.exe -NoProfile -Command "Write-Output win-p1-long-exit-7; Start-Sleep -Seconds 2; exit 7"`（`process_guid = 1bc190b6-f4a9-4804-8443-d63734e29aed`）：Launch（`57d1c3fd-b815-8d47-b16f-5812ac7649d5`）与 Terminate（`8aeadc19-6476-836d-98e3-cdddaa9cb7de`，`exit_code=7, duration_ms=2767`）均入库且复用同一 GUID。

## 已知边界

- ~~agent 异常退出会泄漏 ETW 会话~~：已修（2026-10-20），会话改用固定名 `OpenXDR-Process` / `OpenXDR-Network`（后加的 DNS 采集同样固定为 `OpenXDR-DNS`），
  启动前先停同名旧会话。旧版本漏下的 `n4r1b-trace-*` 要重启一次主机或手动 `logman stop <name> -ets` 清掉——
  不自动清，因为那是 ferrisetw 的默认命名，别的软件也可能在用。
- 用户配置单元只覆盖已加载的：未登录用户的 NTUSER.DAT 不去挂载，离线期间对其配置单元的篡改看不到，
  登录加载后以那时为基线。
- WSL2 不能验证：netlink proc connector（命名空间，agent 正确降级）、wtmp
  登录（无写入）、短命进程 cmdline（轮询固有）；这些格子已由真 Linux 双机补验。
- ~~server 热重载偶现不及时~~：已确认元数据指纹与 watcher 启动竞态两个根因，
  改为内容 SHA-256 指纹并从 Engine 已加载指纹起步，等大小/等 mtime 覆盖写回归通过。
