# 采集端详解

本文是 agent（端点采集）与 sensor（全流量探针）的完整参考，内容逐一对照代码核实，
每条结论标注源码位置。事件字段的完整 schema 见 [events.md](events.md)，
syslog 接入的服务端行为见 [detection.md](detection.md)。

## 总览：三条数据源

| 数据源 | 部署位置 | 产出 | 传输 |
|---|---|---|---|
| agent（Rust） | 每台被监控主机（Linux / Windows） | 进程（启动+退出）、文件、认证、网络、注册表五类事件 | gRPC 双向流 :8081 |
| sensor（Rust） | 核心交换机镜像口（仅 Linux） | 会话元数据（DNS 查询/应答、TLS SNI/JA3/JA3S/证书元数据、HTTP），不存 PCAP | gRPC 客户端流 :8081 |
| syslog | 任意网络设备/主机 | 非结构化日志 | UDP+TCP 同端口（默认不启用） |

agent 事件的 OCSF 归一化在 **agent 侧**完成（raw_json 已是 OCSF 风格 JSON，
server 原样落库）；sensor 与 syslog 的归一化在 **server 侧**完成。

## agent 通用机制

### 注册与配置下发

- 启动参数：**无命令行参数**，全部走环境变量（`agent/src/main.rs`）：
  - `OPENXDR_SERVER`：server 地址，默认 `http://127.0.0.1:8081`（`main.rs:17`）
  - `OPENXDR_CA` / `OPENXDR_CERT` / `OPENXDR_KEY`：mTLS 三件套，必须同时配置；
    全不配=明文，配一半=报错（`agent/src/tls.rs:10-26`）
- 注册时上报 hostname、os、非回环 IP 列表、版本（`main.rs:31-36`）
- 采集配置由 server 在 `Register` 响应的 `config_json` 下发（`main.rs:39`）。
  **无热更新通道**：agent 断线固定 5 秒重连并重新注册（`main.rs:21-23`），
  配置随重注册生效
- 配置解析失败或为空一律回退内置默认（`collector/config.rs:34-46`）——
  让 agent 变瞎比配置不生效严重得多

### 事件出口（EventSink）

上报侧堵塞时**丢弃并计数**（`dropped_events` 字段携带累计值），绝不反压采集——
阻塞采集只会让内核缓冲区溢出，丢得更多且无从知晓
（`collector/mod.rs:123-144`）。channel 容量 1024。

### 进程血缘注册表（ProcessRegistry）

- pid → UUID v4 GUID 映射，父 GUID 由 ppid 查表得到；父早于 agent 启动则为空
  （`collector/registry.rs:24-38`）
- 上限 65536 条，超出按序号淘汰最旧一半（`registry.rs:9,33-36`）
- pid 复用语义：新登记直接覆盖旧条目（`registry.rs:30-31`）
- 启动时用 /proc（Linux）或 sysinfo（Windows）快照 seed 预登记现有进程
  （`collector/mod.rs`、`windows.rs` `seeded_registry`）
- **退出事件复用启动时的 GUID**：Terminate 分支优先 `guid_of(pid)` 查已有映射，
  退出与启动事件共享 `process_guid`，血缘不断（`mod.rs:230-251`）

### exe SHA-256

- 各进程采集路径共用 `process_event()` 组装，哈希在此统一计算
  （`collector/mod.rs:233` 起）
- 实现：文件可读且 ≤128MB 才算；缓存键 (path, mtime, size)，上限 4096 条，
  满则整体清空（`collector/hash.rs:20-46`）
- Windows ETW 的 ImageName 先经设备路径→Win32 路径转换再进哈希
  （`collector/windows.rs:95` `to_win32_path`），否则按设备路径读文件必失败

## Linux 采集路径

### 进程采集三级降级

```
--features ebpf 构建：  eBPF tracepoint → netlink proc connector → 轮询
默认构建：              netlink proc connector → 轮询
```

| 路径 | 机制 | 前提 | 证据 |
|---|---|---|---|
| eBPF | tracepoint `sched_process_exec`（启动）+ `sched_process_exit`（退出），内核直接给路径 | `--features ebpf` + root | `collector/linux.rs`、`agent/ebpf/src/main.rs` |
| netlink | proc connector，订阅 `PROC_EVENT_FORK`/`EXEC`/`EXIT`；fork 仅用于血缘登记不上报 | CAP_NET_ADMIN + 初始 pid 命名空间 | `collector/netlink.rs:20-24` |
| 轮询 | 每秒进程表快照 diff，新 pid 报启动、消失 pid 报退出 | 无 | `collector/poll.rs` |

关键行为：

- **逐级降级不跳档**：eBPF 启动失败先试 netlink，netlink 不可用才退轮询
  （`linux.rs:39-51`），与默认构建同一条链
- **命名空间检测**：netlink 启动前检查 `/proc/self/ns/pid` inode 是否为初始
  pid ns（4026531836），容器/WSL2 中直接拒绝启动并回落轮询——宁可弱采集
  也不产假数据（`netlink.rs:32-58`）。eBPF 路径**无**此检测
- **短命进程**：eBPF/netlink 在事件路径上从 /proc 补全 cmdline/ppid，进程已退场
  就只报 pid、字段留空，事件本身不丢（`linux.rs`、`netlink.rs:148-167`）；
  轮询路径明确会漏 1 秒内启动又退出的进程（`poll.rs`），且 WSL2 实测
  捕到的短命进程多为空 cmdline"鬼影"（扫描间隔内进程已退场，/proc 读不到）——
  轮询兜底下进程类规则基本无法命中，这是环境性降级，不是规则问题
- **进程退出事件**（activity_id=2 Terminate）：netlink 解析 `PROC_EVENT_EXIT`
  （含 exit_code，`netlink.rs:24,139`）；轮询 diff 消失的 pid；eBPF 挂
  `sched_process_exit`。退出事件复用启动时的进程 GUID（见上节）
- **username**：eBPF/netlink 路径从 `/proc/<pid>/status` 读 real uid，
  再查 `/etc/passwd` 解析成用户名（结果带缓存）；passwd 查不到退化为
  uid 数字串，与轮询路径一致（`mod.rs:185` `username_of`）

### 敏感文件监控（fswatch：fanotify 优先，inotify 兜底）

- **fanotify 路径**（有 CAP_SYS_ADMIN 时）：FID 模式
  （`FAN_REPORT_FID|FAN_REPORT_DIR_FID|FAN_REPORT_NAME`）递归打标，
  覆盖建/删/改/移动；**事件自带 pid**——读 `/proc/<pid>/exe`、`/proc/<pid>/comm`
  与 `username_of(pid)`，文件事件带进程上下文（"谁改的"）。路径经
  mountinfo + `open_by_handle_at` 解析（`fswatch.rs:70` `spawn`）。
  两个实机勘定（2026-08-09 WSL2 回放）：挂载 fd 必须 O_RDONLY 打开
  （O_PATH 在 WSL2 6.18 内核下 open_by_handle_at 一律 EBADF，
  `fswatch.rs` `mount_fd_for`）；建/删/移动事件内核发的是
  DFID/DFID_NAME 信息记录（父目录句柄+目录项名），与 FID 同布局，
  `fa_parse` 三种类型统一解析
- **inotify 路径**（fanotify 不可用时干净回落）：启动时递归 add_watch
  （限深 `MAX_DEPTH=4`，防大目录 watch 爆炸），运行中 `IN_CREATE|IN_ISDIR`
  动态补挂新子目录；无进程上下文（inotify 不提供）（`fswatch.rs:31,164`）
- 两条路径产出格式一致：class_uid=1001，activity_id 增 1/删 4/改 3，
  `file.path`；fanotify 路径额外带 `process.*` 与 `username`
- 默认目录（`fswatch.rs:93` `default_targets`）：`/etc`、`/etc/cron.d`、
  `/etc/cron.daily`、`/etc/sudoers.d`、`/etc/ssh`、`/root/.ssh`、
  `/etc/systemd/system`、`/var/spool/cron`、`/var/spool/at`，以及启动时枚举
  `/home` 一层补进各用户 `.ssh`。server 下发 `fileWatchDirs` 非空时
  **整体覆盖**默认清单
- **单文件目标**：除目录外还支持盯单个文件——用户 shell rc
  （`/etc/profile`、`/etc/bash.bashrc` + /root 与 /home 各用户存在的
  `.bashrc`/`.bash_profile`/`.profile`，T1546.004）。inotify 用
  `IN_DELETE_SELF/IN_MOVE_SELF` 系掩码，fanotify 不带目录专属标记；
  已被目录 watch 覆盖的文件自动去重，不会双报
- 启动日志标明实际走哪条路：`fanotify 递归盯 N 个目录（含进程上下文）` 或
  `fanotify 不可用（原因），回落 inotify 递归监控`

### 登录事件（authwatch，wtmp/btmp）

- 每 5 秒轮询 `/var/log/wtmp`（成功）与 `/var/log/btmp`（失败）
  （`authwatch.rs:17,35-46`）
- 增量：启动 offset 置为文件末尾（历史不重放），之后按 384 字节完整记录消费，
  残缺尾部留到下一轮；logrotate 截断时 offset 归零重读（`authwatch.rs:47-91`）
- 只收 `ut_type==USER_PROCESS(7)` 且用户名非空的记录；登出跳过
  （`authwatch.rs:100-113`）
- 成功/失败完全靠**文件名**区分（btmp→`status_id:2`），记录本身无失败标志
  （`authwatch.rs:29-31,124`）
- 字段：`user.name`、`src_endpoint.ip`（ut_host）、`service.name`（ut_line）
  （`authwatch.rs:105-128`）

### 网络采集（netwatch，仅 eBPF 构建）

- tracepoint `sock:inet_sock_set_state`，内核侧只收
  `newstate==TCP_SYN_SENT && protocol==TCP`——本机主动发起的 TCP 出站
  （`agent/ebpf/src/main.rs`）
- 用户侧丢 loopback；按 (目的IP, 目的端口) 60 秒去重，表满 4096 清过期
  （`linux.rs`、`netwatch.rs:17-43`）
- 带 pid → 进程 GUID，网络事件直接挂进血缘；`conn_tuple` 与 sensor 同格式，
  横向移动关联与网络规则零改动复用（`netwatch.rs:57-81`）
- 默认构建（netlink 模式）**无网络采集**——proc connector 没有网络事件，
  `collect_network` 开关在非 eBPF 构建下无任何效果

### 内核模块监控（kmodwatch）

- 每 30s 读 /proc/modules 做 diff：新模块报加载（class_uid=1005，
  activity_id=1）、消失报卸载（4）；首轮基线静默（`kmodwatch.rs`）
- 路径按 /lib/modules/$(uname -r)/ 解析，解析失败只报名字不编造路径；
  /proc/modules 拿不到加载者——进程与 username 留空（那是 audit/eBPF 的领域）

## Windows 采集路径

### 进程采集（ETW）

- 订阅 `Microsoft-Windows-Kernel-Process`（GUID `22fb2cd6-...`），
  处理 **event ID 1（启动）与 2（停止）**（`windows.rs:19,30`）。
  Stop 事件产 Terminate（activity_id=2），pid + ImageName（转 Win32 路径），
  cmdline/username 留空（进程已退场，句柄多半开不到）
- ETW 事件本身只有 pid/ppid/ImageName；cmdline 与 username 现场补
  （`OpenProcessToken`→`LookupAccountSidW` 得 `DOMAIN\user`）
- cmdline 补全双路径：`NtQueryInformationProcess(ProcessCommandLineInformation)`
  （Win 8.1+）；失败时回落 **PEB 读取**（ProcessBasicInformation 拿 PEB 地址 →
  ReadProcessMemory 读 RTL_USER_PROCESS_PARAMETERS → CommandLine），
  **Win7/2008R2 由此获得命令行**（`windows.rs:235` `command_line_peb`）
- ImageName 常是设备路径（`\Device\HarddiskVolumeN\...`），直接用会让
  exe SHA-256 落空；采集时经 `QueryDosDeviceW` 映射翻成 Win32 路径
  （`windows.rs:95` `to_win32_path`）
- 需要管理员权限；失败回落**轮询**（`windows.rs:5`）。轮询路径下
  username 是 SID 字符串而非用户名（`poll.rs`）

### 网络采集（netwatch_win，ETW Kernel-Network）

- 订阅 `Microsoft-Windows-Kernel-Network`（GUID `7dd42a49-...`），只取
  **event ID 12（TcpConnect）**——本机主动 connect 才触发；端口字段是网络
  字节序，已换算（`netwatch_win.rs`，实机勘定）
- 归一化与 Linux eBPF 路径完全同构：共用 `netwatch::conn_event` 组装
  （class_uid=4001、conn_tuple 同格式、60s 同目标采样去重、loopback/
  未指定地址不报）；UDP 不做（该 provider 的 UDP 只有逐报文事件，无连接语义）
- **与进程采集共享同一张 GUID 注册表**——网络事件的 process_guid 与进程
  血缘严格一致（`mod.rs` 把 Arc<Mutex<ProcessRegistry>> 同时交给
  netwatch_win 与 windows::run）
- 独立 trace session，订阅失败只打日志降级，不影响进程采集主路

### 持久化点快照（persistwatch）

七类持久化点，30 秒一轮快照 diff，各自独立基线、首轮静默、单类读取失败
只跳过自己这一轮（`persistwatch.rs`）：

| 监控对象 | 事件类别 | 说明 |
|---|---|---|
| 注册表 Run/RunOnce/Winlogon（HKLM+HKCU） | 201002 | 增(1)/改(3)/删(4)，删除带旧值内容 |
| Startup 目录（全局+每用户） | 1001 | 增(1)/删(4)，修改不报 |
| **Windows 服务**（`HKLM\SYSTEM\CurrentControlSet\Services`） | 201002 | `services_snapshot`：ImagePath+启动类型+**运行状态**（SCM 枚举，EventLog 等安全服务被停止产生 Modify；枚举失败整轮跳过防误报） |
| **计划任务**（`C:\Windows\System32\Tasks` 递归） | 1001 | `tasks_snapshot`：快照 路径→(mtime,size)，增/改/删全报 |
| **Defender Exclusions / AppInit_DLLs / IFEO Debugger / HKCU CLSID** | 201002 | `WATCH_TREES` 递归枚举（键不存在静默跳过）：T1562.001 排除项篡改、T1546.010/012、T1546.015 COM 劫持 |
| **WMI 事件订阅**（`root\subscription` 的 __EventFilter/__EventConsumer） | 1001 | powershell 子进程查询快照（30s），file.path 用 `wmi:...` 伪路径；T1546.003 |

- 事件无进程上下文（快照 diff 不知道谁写的），设计上不用注册表通知
  （`persistwatch.rs:3-6`）
- 非 REG_SZ/REG_EXPAND_SZ 的注册表值记为 `<type N, M bytes>` 占位

### 文件监控（fswatch_win，ReadDirectoryChangesW）

- 每个监控目录一个线程：`CreateFileW`（`FILE_FLAG_BACKUP_SEMANTICS`）打开目录，
  循环阻塞 `ReadDirectoryChangesW`，不递归（`fswatch_win.rs:46`）
- 事件映射：Added/RenamedNew→1、Removed/RenamedOld→4、Modified→3
  （改名天然拆成删+增两条）（`fswatch_win.rs:160` `rdcw_activity`）
- 默认目录：`C:\Windows\System32\drivers\etc`、`C:\Windows\System32\config`；
  `fileWatchDirs` 下发非空时覆盖；失败目录静默跳过
- 缓冲溢出（`ERROR_NOTIFY_ENUM_DIR`）打日志继续；事件格式与 Linux 侧完全一致
  （1001 + activity_id + `file.path`，无进程上下文——RDCW 不提供）

### 登录与安全日志事件（authwatch_win）

- `EvtSubscribe` 订阅 Security 日志，只订未来事件：
  **4624/4625**（登录成功/失败）、**4720/4726**（创建/删除用户）、
  **4732**（成员加入本地组）、**1102**（Security 日志被清空）、
  **4648**（显式凭据登录）、**4719**（审计策略变更），统一归一化成 OCSF 3002
- 4624/4625 过滤：机器账号（`$` 结尾）、SYSTEM、空用户丢弃；成功事件额外丢弃
  LogonType 0/5；失败事件保留所有类型
- 4624/4625 解析字段：`TargetUserName`、`LogonType`、`IpAddress`、`Status`、
  `SubStatus`——后两个有值才写成 `status_code`/`status_detail`
  （4625 可区分"密码错"0xC000006A 与"账号锁定"0xC0000234 等）
- 新事件类型用平台自定义 `activity_id`（OCSF 3002 未定义，从 10 起）：
  10=创建用户、11=删除用户、12=加入本地组（组名在 `group_name`，
  是否管理员组由规则判定）、13=日志清空（另带 `log_cleared: true` 显式标记）、
  14=显式凭据登录、15=审计策略变更；机器账号同样过滤
- 另订阅 `Microsoft-Windows-PowerShell/Operational` 的 **4104**（Script Block
  Logging），归一化成 OCSF 1007 进程事件：`process.name=powershell.exe`、
  pid 取事件 Execution ProcessID、脚本体放 `process.cmd_line`（Sigma 的
  CommandLine 匹配因此直接作用于脚本内容）。分片不拼接：单片直接发，
  分片各发一条并标注 `message_number`/`message_total`。4104 依赖组策略开启，
  订阅失败只打日志，不影响 Security 主路
- 需要管理员或 Event Log Readers 权限；订阅失败只告警不影响其他采集

## 采集配置开关全表

配置存于资产上，随 Register 下发（`collector/config.rs:10-28`）：

| 开关 | 默认 | Linux | Windows |
|---|---|---|---|
| `collectFiles` | true | 控制 fswatch | 控制 fswatch_win |
| `collectAuth` | true | 控制 authwatch | 控制 authwatch_win |
| `collectPersist` | true | 无消费者 | 控制 persistwatch |
| `collectNetwork` | true | 仅 eBPF 构建有效 | 无消费者 |
| `fileWatchDirs` | []（内置清单） | 覆盖 fswatch 默认目录 | 覆盖 fswatch_win 默认目录 |
| （进程采集） | — | 无开关，按降级链选择 | 无开关，无条件启动 |

## sensor（全流量探针，仅 Linux）

### 抓包后端

| 后端 | 机制 | 前提 | 证据 |
|---|---|---|---|
| `afpacket`（默认） | AF_PACKET v3 mmap 零拷贝环（2MiB×64 块），`PACKET_FANOUT_HASH` 按流哈希多 worker，内核重组分片 | 任意 Linux | `capture/afpacket.rs:12-19,81-89,150-158` |
| `afxdp` | XDP 程序按 rx_queue redirect 到 XSKMAP，**仅入向（RX）** | `--features xdp` + 驱动支持 | `capture/afxdp.rs:19,185`、`sensor/ebpf/src/main.rs:19-24` |

- `SENSOR_BACKEND` 选择后端，`SENSOR_WORKERS` 决定并行度（afxdp 下
  worker 号=网卡队列号）（`main.rs:48,114-117`）
- mTLS 变量与 agent 相同（`OPENXDR_CA/CERT/KEY`，`sensor/src/tls.rs:14-26`）

### 协议解析（按方向各探测一次）

| 协议 | 触发 | 提取字段 | 不解析 |
|---|---|---|---|
| DNS | sport/dport=53，按报文 QR 位区分查询/应答 | 查询名、**rcode、A/AAAA 应答 IP（至多 4 个）**；域名解析支持 RFC 1035 压缩指针（限跳 16 次防循环，越界即畸形） | TXT 等其他记录类型 |
| TLS | record 0x16；ClientHello（0x01）与 ServerHello（0x02）**各探一次** | SNI、JA3（客户端）、**JA3S（服务端）**，均为 md5 且 GREASE 按 RFC 8701 剔除；**证书元数据**：叶证书 subject/issuer CN、自签标志（subject/issuer 原始 DER 相等的启发式，非签名验证）、有效期（unix 秒） | TLS 1.3 证书（加密传输，协议上不可见）、证书链与签名验证 |
| HTTP | HTTP/1.x 请求行（9 种方法白名单） | URI、Host、User-Agent（首包前 4KB，无跨包重组） | 方法/状态码不进上报结构 |

TLS 证书跨 TCP 分段是常态（叶证书+链一般 1.5–4KB），服务端方向做**有界重组**：
每条流一个握手缓冲（上限 16KB），按 record → handshake 增量解析，不完整等下一个包；
ServerHello 扩展 supported_versions=0x0304 判定 TLS 1.3 后立即停止等证书，
看到应用数据 record（0x17）或缓冲超限同样停止。X.509 解析是自研迷你 DER walker
（`sensor/src/x509.rs`），不引新 crate，畸形一律返回 None。

证据：`sensor/src/proto_id.rs`（`read_name`、`parse_dns_response`、`parse_server_hello`、
握手重组与 Certificate 提取）、`sensor/src/x509.rs`（DER/有效期/CN 解析）。
其他协议（SSH/SMTP/ICMP 等）无实现。
DNS/JA3S/证书字段经 proto `FlowRecord` 的 `dns_rcode=19` / `dns_answers=20` /
`ja3s=21` / `tls_cert_*=22-26` 上报（`proto/sensor.proto`）。

### 流聚合与上报

- 五元组"小端在前"归一化，双向并入同一条流；方向判定：纯 SYN 发送方为客户端，
  SYN+ACK 为服务端，UDP/中途观察以首包发送方为客户端（`flow.rs:21-43,136-142`）
- 逐方向累计包数/字节数、TCP 标志位并集（`flow.rs:159-167`）
- 导出条件：TCP 见 FIN/RST、空闲 30s、最长生存 300s；每 5s 扫描；
  每 worker 上限 100 万条流（`flow.rs:101-110,173-191`）
- **无采样、无逐事件去重**——聚合本身就是"五元组归并成会话"
- 上报攒批：满 256 条或 2 秒一批，断线 5s 重连（`report.rs:12-13,92-117`）；
  上报队列（65536）满丢会话并计数；内核丢包经 `PACKET_STATISTICS` 统计上报
- server 侧归一化与 class_uid 判定（4001/4003）见 [events.md](events.md)

## 响应面（与采集同进程）

agent 的 `respond/` 模块执行 server 下发的指令：结束进程、主机隔离
（Linux nftables 独立表 / Windows netsh 防火墙规则）。三道闸门：
`RESPONSE_ENABLED` 全局开关、dry-run 默认、未配置 `ISOLATION_ALLOW` 拒绝隔离。
详见 [detection.md](detection.md) 响应处置一节。
