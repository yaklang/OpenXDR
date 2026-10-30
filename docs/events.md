# 事件模型参考

OpenXDR 采用 OCSF 风格事件模型。本文列出所有事件类别、字段 schema 与实体标识，
是写规则、改采集、查事件的基准参考。字段以代码实现为准（标注源码位置）。

## 事件类别总表

| class_uid | 类别 | 来源 | 产生位置 |
|---|---|---|---|
| 1001 | 文件活动（File System Activity） | agent | Linux fswatch（fanotify/inotify）、Windows fswatch_win、persistwatch 文件/计划任务部分 |
| 1007 | 进程活动（Process Activity） | agent | Linux eBPF/netlink/轮询、Windows ETW/轮询（启动+退出） |
| 2004 | 检测告警（Detection Finding，OCSF 风格） | suricata | EVE alert 专用 HTTP 接入，保留外部检测证据，见 [suricata.md](suricata.md) |
| 3002 | 认证（Authentication） | agent | Linux wtmp/btmp；Windows Security 4624/4625/4720/4726/4732/1102/4648/4719 |
| 4001 | 网络活动（Network Activity） | agent / sensor | agent netwatch 连接（Linux eBPF、Windows ETW Kernel-Network：TCP 出入站、UDP 出站）；sensor 非 DNS 会话 |
| 4003 | DNS 活动（DNS Activity） | agent / sensor | agent dnswatch 本机与容器的 DNS 问答（Linux AF_PACKET）、dnswatch_win 系统解析器的查询（Windows ETW DNS-Client）；sensor 会话带 dns_query 时判定 |
| 1005 | 模块活动（Module Activity） | agent | Linux kmodwatch（/proc/modules diff） |
| 5001 | 设备清单（Device Inventory Info） | agent | inventory：监听端口（含服务进程所属的包）与云环境快照，供资产图谱与攻击面 |
| 5020 | 软件清单（Software Inventory Info） | agent | software：发行版与 dpkg / RPM 已装包（包名、版本、源码包、源码版本）；漏洞匹配目前仅支持 Debian / Ubuntu 的 dpkg 包，见 [vulns.md](vulns.md) |
| 201002 | 注册表值活动（Registry Value Activity） | agent | Windows persistwatch 注册表键/服务快照 |
| 100001 | 应用日志（OCSF 私有段） | syslog | server syslog 接入 |

events 表公共列：`ts`、`class_uid`、`source`（agent/sensor/syslog/suricata）、
`asset_id`、`process_guid`、`parent_process_guid`、`username`、`conn_tuple`、
`raw`（OCSF 风格 JSON）。server 对 agent 事件**不做字段级归一化**，raw_json
原样落库；解析失败替换为 `{}`（`server/internal/grpcsvc/agent.go:186-214`）。
攒批落库：500 条或 2 秒 flush（`agent.go:71-74`）。

## 1007 进程活动

agent 侧组装（`agent/src/collector/mod.rs:233` `process_event`）。
**启动（activity_id=1 Launch）与退出（2 Terminate）**两种：

```json
{
  "activity_id": 1,
  "process": {
    "pid": 1234,
    "uid": "<进程 GUID>",
    "name": "bash",
    "file": { "path": "/bin/bash", "sha256": "<exe SHA-256 或 null>" },
    "cmd_line": "-c whoami",
    "exit_code": null,
    "parent_process": { "pid": 1000, "uid": "<父进程 GUID 或 null>" }
  }
}
```

- 顶层 protobuf 另带 `process_guid` / `parent_process_guid` / `username`
- 进程在容器或 Proxmox 虚拟机里时（Linux 按 cgroup 识别），顶层加
  `"container": { "runtime": "docker|podman|containerd|cri-o|lxc|qemu|nspawn", "uid": "<容器 ID 前 12 位或 VMID>", "name": "<名字，读不到省略>" }`
- 平台下发的指令拉起的进程（及其后代）顶层带 `"platform_command": { "uid": "<指令 ID>" }`，网络与 DNS 事件同样带，
  见 [检测链路 · 平台指令触发的告警](detection.md#平台指令触发的告警servercmdorigin)
- Linux 上属于某次 SSH 登录会话的进程（按内核审计会话号认）顶层带
  `"login_session": { "uid": "<审计会话号>", "user", "src_ip", "src_port", "auth_method", "key_type", "key_fp": "SHA256:…" }`；
  对应的认证成功事件（3002）也带同一对象（无 `uid`）。只在认证日志出处核对通过（root 身份的 sshd）时才有，
  见 [检测链路 · 已知自动化](detection.md#已知自动化serverinternalautomation)
- **退出事件复用启动时的进程 GUID**（注册表查得到就填同一个），血缘不断；
  eBPF（exit_group）与 netlink 路径的退出事件带 `exit_code`（被信号杀掉的为 null）；
  知道启动时间的（启动事件或启动快照里见过）带 `process.created_time`（毫秒）与顶层 `duration_ms`；
  ETW Stop 与轮询消失 pid 的退出事件只有 pid 等少量字段（进程已退场，补不到细节）
- **短命且成功退出的进程不再产生 Terminate 事件**：退出码为 0、存活不到 2 秒的（采集开关
  `suppressTrivialExit`，默认开，见 [采集端详解](collection.md#进程采集三级降级)）只留启动事件。
  退出码非零或未知（被信号杀、内核/ETW 拿不到）、启动时间读不到、存活 ≥ 2 秒的照旧上报——
  判不准就不抑制，宁可多报
- 字段质量随采集路径变化，写规则时注意：
  - Linux eBPF/netlink：username 由 /proc status 的 uid 查 /etc/passwd 解析
    （passwd 查不到退化为 uid 数字串）；exe 路径来自内核或
    `/proc/<pid>/exe`，cmdline/ppid 从 /proc 现场补，短命进程补不到则留空
  - Linux/Windows 轮询：漏 1 秒内短命进程；username 是 uid/SID 数字串
  - Windows ETW：cmdline、username（`DOMAIN\user`）现场补；ImageName 经
    设备路径→Win32 路径转换后 sha256 正常产出；Win7/2008R2 走 PEB 读取
    兜底拿 cmdline

## 1001 文件活动

```json
{ "activity_id": 1, "file": { "path": "/etc/cron.d/evil" } }
```

- activity_id：1=Create、3=Update、4=Delete（各采集器映射见
  [collection.md](collection.md)）
- **进程上下文取决于采集路径**：
  - Linux fanotify 路径：**带** `process.pid/name/file.path` 与 `username`
    （"谁改的"可见）
  - Linux inotify 路径 / Windows fswatch_win / persistwatch：无进程上下文
    （机制本身不提供）
- 产生位置：Linux fswatch（fanotify 优先、inotify 兜底）、Windows
  fswatch_win（ReadDirectoryChangesW）、persistwatch 的 Startup 目录与
  计划任务快照（增/删/改语义见 collection.md）
- persistwatch 的计划任务事件另带 `task.actions`：任务 XML 里的动作，一行一个，Exec 为「命令 参数」、
  ComHandler 为 `com:{CLSID}`（删除事件为旧动作，任务文件读不到时省略）；修改事件里动作变了才带
  `task.prev_actions`（旧动作）。动作不变的修改是系统维护改触发器与状态

## 3002 认证

Linux（`authwatch.rs:122-128`）与 Windows（`authwatch_win.rs`）同构：

```json
{
  "activity_id": 1,
  "status_id": 2,
  "status_code": "0xC000006A",
  "status_detail": "0x0",
  "user": { "name": "root" },
  "src_endpoint": { "ip": "10.0.0.5" },
  "service": { "name": "sshd" }
}
```

- `status_id`：1=成功、2=失败。Linux 靠 wtmp/btmp 文件名区分；Windows 靠
  事件 ID（4624/4625）
- `status_code`/`status_detail`：仅 Windows 侧、有值才写（来自 4625 的
  Status/SubStatus，可区分"密码错"0xC000006A 与"账号锁定"0xC0000234）
- Linux `service.name` 是 ut_line（如 `sshd`、`pts/0`）；Windows 是
  `logon-type-N`（如 `logon-type-3` 网络登录、`logon-type-10` 远程交互）
- 认证成功事件会触发 server 侧"爆破得手"跨事件检测，见
  [detection.md](detection.md)

### Windows 安全日志扩展事件（activity_id 10-15，平台自定义段）

OCSF 3002 未覆盖这些语义，activity_id 从 10 起自定义（`authwatch_win.rs` 注释
逐条说明），`status_id` 恒为 1：

| activity_id | 事件 ID | 含义 | 关键字段 |
|---|---|---|---|
| 10 | 4720 | 创建用户 | user.name=新账号、actor_user=操作者 |
| 11 | 4726 | 删除用户 | 同上 |
| 12 | 4732 | 加入本地组 | user.name=成员、group_name=组名 |
| 13 | 1102 | Security 日志被清空 | user.name=操作者、log_cleared=true |
| 14 | 4648 | 显式凭据登录 | user.name、src_endpoint.ip、target_server、process_name |
| 15 | 4719 | 审计策略变更 | policy_category/subcategory/changes，原样是 `%%` 消息 ID（changes：8448 成功移除、8449 成功添加、8450 失败移除、8451 失败添加） |

### PowerShell 脚本块（4104 → 1007）

订阅 `Microsoft-Windows-PowerShell/Operational` 的 4104 事件，以进程类事件
发出（`authwatch_win.rs`）：process.name="powershell.exe"、process.pid 取事件
的 Execution ProcessID、**cmd_line 放 ScriptBlockText**——Sigma 规则的
CommandLine 匹配因此可以直接作用于脚本内容。分片（MessageTotal>1）按片
各发一条并标注 message_number/message_total，不做跨片重组；有脚本路径时
加 script_path。该通道依赖组策略开启 Script Block Logging，订阅失败只打
日志不影响 4624/4625 主路。

## 4001 网络活动

两个来源，字段不同：

**agent netwatch**（Linux eBPF 构建 `netwatch.rs:57-81`；Windows ETW
Kernel-Network `netwatch_win.rs`，TcpConnect 12/28、TcpAccept 15/31、UDP 发送 42/58，端口为网络字节序
已换算）——两路归一化完全同构（共用 `netwatch::conn_event` 组装与 60s
同目标采样去重），带进程血缘。Windows 侧与进程采集共享同一张 GUID 注册表，
网络事件的 process_guid 与进程血缘一致；loopback/未指定地址不报。两个平台都有 TCP 出站、TCP 入站与 UDP 出站：

```json
{
  "activity_id": 1,
  "connection_info": { "direction": "outbound", "protocol_name": "tcp" },
  "src_endpoint": { "ip": "...", "port": 51234 },
  "dst_endpoint": { "ip": "...", "port": 443, "hostname": "github.com" },
  "process": { "pid": 1234, "uid": "<进程 GUID>", "name": "curl", "file": { "path": "/usr/bin/curl" } },
  "container": { "runtime": "docker", "uid": "4f1c2a3b5d6e", "name": "termix" }
}
```

- `direction`：`outbound` 时 src 是本机、进程是发起方；`inbound` 时 src 是对端、dst 是本机服务，
  进程是监听该端口的服务进程（Linux 按监听表查，查不到省略；Windows 取 TcpAccept 事件的 PID 字段）
- Windows 发往 UDP 53 的出站按进程采样：绕过系统解析器自己发 DNS 报文的程序（nslookup 等）在这里出现，
  系统解析器（Dnscache 服务）的查询见 4003
- `protocol_name`：`tcp` / `udp`，与 `conn_tuple` 前缀一致；UDP 的源端口可能是 0（首个数据报才绑定端口）
- UDP 出站的源地址：未连接套接字按路由查出口地址；查不到时**省略** `src_endpoint.ip`，`conn_tuple` 源地址留空
  （`udp::41641>110.42.47.158:41641`），不报 0.0.0.0 / ::——未指定地址不是一台主机。
  旧版 agent 会照报未指定地址，server 侧资产图谱两种都按上报资产自己的地址处理
- `dst_endpoint.hostname`：目的地址最近被本机解析过时的域名（agent 自己看到的 DNS 应答），没见过就省略；
  参与域名情报碰撞
- `container`：同 1007

`process.name` / `process.file.path` 取自进程注册表（Linux 注册表没有名字时现读
`/proc/<pid>/comm`），拿不到就省略。早于 agent 启动的长驻进程没有启动事件可回查，
资产图谱的依赖边靠这两个字段知道是哪个进程发起的连接；容器里的进程在依赖边上记成「容器/进程」。
入站只给资产图谱补发起方未纳管的依赖（发起方纳管时它自己的出站已经记过）。

**sensor 会话**（server 侧归一化，`grpcsvc/sensor.go:168-214`）——带流量统计：

```json
{
  "activity_id": 6,
  "duration_ms": 1230,
  "connection_info": { "protocol_num": 6, "tcp_flags": "..." },
  "src_endpoint": { "ip": "...", "port": 51234 },
  "dst_endpoint": { "ip": "...", "port": 443 },
  "traffic": { "packets": 10, "bytes": 2048, "packets_in": 6, "bytes_in": 1200, "packets_out": 4, "bytes_out": 848 },
  "tls": { "sni": "example.com", "ja3_hash": "...", "ja3s_hash": "...", "handshake_only": true,
           "cert": { "subject": "example.com", "issuer": "DigiCert CA",
                     "self_signed": false, "not_before": 1754000000, "not_after": 1786000000 } },
  "http_request": { "hostname": "...", "url": { "path": "/x" }, "user_agent": "..." }
}
```

- `tls` 对象在 SNI/JA3/JA3S/证书/只握手任一非空时出现；`ja3s_hash` 是服务端指纹，
  与 `ja3_hash` 一样参与哈希情报碰撞
- `tls.cert` 在解析到服务端 Certificate 消息时出现（仅 **TLS ≤1.2**——TLS 1.3 的
  证书加密传输，被动嗅探看不到）：subject/issuer 是叶证书 CN，
  `self_signed` 是 subject 与 issuer 原始 DER 相等的启发式（非签名验证），
  `not_before`/`not_after` 是 unix 秒。sensor 侧做有界重组（16KB 上限）应对
  证书跨 TCP 分段
- sensor 上报前把 src 摆正为客户端方向（`sensor/src/report.rs:19-49`）
- `tls.handshake_only` 只在为真时出现：客户端发完 ClientHello（或握完手）就结束会话、没发任何请求，
  扫描与证书探测的典型形态。只陈述事实，不单独告警，留给研判；sensor 跟丢 record 或中途才看到会话时不标，
  所以没有这个字段不等于发了请求（判定见 [collection.md](collection.md#流聚合与上报)）
- sensor 无进程信息；资产归属先按**源 IP** 反查 asset，源地址不是纳管资产时按**目的 IP**——公网打进反代网关的会话
  归到网关上，组视图与研判才看得见，与 agent 记录入站连接同一口径（`sensor.go` `flowAsset`）。
  资产图谱据此把这类会话按入站记，发起方是对端地址、不挂网关资产
- `conn_tuple` 格式统一为 `tcp:src:sport>dst:dport`，agent 与 sensor 同格式，
  横向移动关联直接复用；源地址未知时留空（只有 agent 的 UDP 出站会出现），目的端总是有的

## 4003 DNS 活动

**agent dnswatch**（Linux，`agent/src/collector/dnswatch.rs`）——一问一答一条事件，带发起进程与容器：

```json
{
  "activity_id": 6,
  "query": { "hostname": "github.com", "type": "A", "rcode_id": 0 },
  "answers": [ { "type": "CNAME", "rdata": "x.github.com", "ttl": 60 }, { "type": "A", "ip": "20.205.243.166", "ttl": 30 } ],
  "src_endpoint": { "ip": "10.1.1.10", "port": 40445 },
  "dst_endpoint": { "ip": "10.1.1.1", "port": 53 },
  "process": { "pid": 1234, "uid": "<进程 GUID>", "name": "curl" },
  "container": { "runtime": "lxc", "uid": "203", "name": "dns" }
}
```

- `activity_id`：6 一问一答，1 只有查询（5 秒没等到应答），此时没有 `rcode_id` 与 `answers`
- 只收本机与本机容器发起的查询；同一 (客户端, 域名, 类型) 60 秒内只报一次
- `requester.ip`：容器里的解析器（AdGuard、dnsmasq）转发上游时，5 秒内送进同一容器的同名同类型查询的客户端地址，即真正问的一方；没有就省略
- `process` 只在 eBPF 构建里有（按源端口取 UDP 发送事件的进程）；`conn_tuple` 为 `udp:客户端>服务器:53`

**agent dnswatch_win**（Windows，`agent/src/collector/dnswatch_win.rs`，ETW DNS-Client 3008）——字段同上，差别：

```json
{
  "activity_id": 6,
  "query": { "hostname": "www.baidu.com", "type": "A", "rcode_id": 0 },
  "answers": [ { "type": "CNAME", "rdata": "www.a.shifen.com" }, { "type": "A", "ip": "183.2.172.177" } ],
  "process": { "pid": 3868, "uid": "<进程 GUID>", "name": "powershell.exe", "file": { "path": "C:\\...\\powershell.exe" } }
}
```

- 看的是系统解析器 API 层的解析（含缓存命中），发起进程取自事件本身，必有 `process`
- 拿不到 DNS 服务器地址、源端口与 TTL：不写 `src_endpoint` / `dst_endpoint`、`answers[].ttl`，`conn_tuple` 为空
- `answers[].type` 按地址族给（A / AAAA）：getaddrinfo 的双栈查询会把 IPv4 结果放在 AAAA 查询里返回，
  `query.type` 保留原查询类型
- 同一进程对同一 (域名, 类型) 60 秒只报一次；只查缓存的试探、getaddrinfo 内部取消的一路不报

**sensor 会话**中 `dns_query` 非空时判定为 4003（`sensor.go:24-28,79-82`），
在 4001 字段基础上加：

```json
{
  "query": { "hostname": "evil.example.com", "rcode_id": 3 },
  "answers": [ { "ip": "6.6.6.6" } ]
}
```

- `query.rcode_id`：DNS 应答码（NXDOMAIN=3 等）。注意 0 的歧义：可能是
  NOERROR 也可能是没抓到应答（proto3 uint32 无零值区分）
- `answers`：A/AAAA 应答 IP（至多 4 个），键名 `ip` 使应答地址**自动参与
  IP 情报碰撞**；无应答则不写该键

## 1005 模块活动

Linux kmodwatch（`kmodwatch.rs`）：每 30s 读 /proc/modules 做 diff，
新出现的模块报加载（activity_id=1）、消失的报卸载（4）；首次快照为基线
不报存量。/proc/modules 拿不到加载者，进程与 username 字段留空
（那是 audit/eBPF 的领域）：

```json
{ "activity_id": 1, "module": { "file": { "path": "/lib/modules/.../e1000e.ko.xz", "name": "e1000e.ko.xz" } } }
```

路径按 /lib/modules/$(uname -r)/ 解析，解析失败只有 name 不编造 path。
`module.file.path` 与 Sigma 引擎的 ImageLoaded 字段映射对齐
（`server/internal/sigma/engine.go:50`）。

## 5001 设备清单

agent inventory（`collector/inventory.rs`）：启动时报一次全量，之后每 60 秒比对监听表，
（协议、地址、端口、进程名）有变化或满 6 小时才再报。不产告警，由 server `assetmap`
物化到资产上，见 [资产图谱与攻击面](asset-map.md)：

```json
{
  "activity_id": 2,
  "device": {
    "os": "Ubuntu 24.04.1 LTS",
    "listening": [
      { "proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": { "pid": 812, "name": "sshd", "file": { "path": "/usr/sbin/sshd" } } },
      { "proto": "udp", "addr": "::", "port": 53 }
    ],
    "cloud": { "provider": "aliyun", "instance_id": "i-bp1...", "region": "cn-hangzhou", "public_ip": "47.1.2.3" }
  }
}
```

属主进程拿不到时整个 `process` 省略；不在云上时省略 `cloud`；识别不到系统时省略 `os`
（Linux 读 os-release 的 `PRETTY_NAME`，麒麟、统信同规范；Windows 读注册表
ProductName / DisplayVersion / build，如 `"Windows Server 2022 Standard (build 20348)"`）。
`listening` 按 (proto, addr, port) 去重排序，最多 512 条。`os` 由 assetmap 物化到资产的
`os_display`，覆盖文档导入时声明的值；注册请求仍只报 linux / windows family。

## 201002 注册表值活动

Windows persistwatch（`persistwatch.rs`）：

```json
{
  "activity_id": 1,
  "reg_key": { "path": "HKCU\\SOFTWARE\\...\\Run\\Updater" },
  "reg_value": { "data": "C:\\evil.exe" },
  "user": { "uid": "S-1-5-21-…-1001", "name": "HOST\\alice" }
}
```

- activity_id：1=Create、3=Modify、4=Delete（删除事件带旧值内容）
- 覆盖：Run/RunOnce/Winlogon 自启动键（HKLM + 每个已加载的用户配置单元）、**Windows 服务快照**
  （`HKLM\SYSTEM\CurrentControlSet\Services`，值形如
  `ImagePath=…; ServiceDll=…; FailureCommand=…; Start=2; State=Running`，空字段省略；
  EventLog 等安全服务被停止会产生 Modify。服务的修改事件另带 `reg_value.prev_data`（旧值）与
  `reg_value.changed`（变了的字段名，逗号分隔，如 `Start,State`），规则据此区分系统翻启动类型 / 运行状态
  与换执行目标）、`CurrentVersion\Windows`
  （AppInit_DLLs）、Defender Exclusions、IFEO 各子键 Debugger 值、
  用户的 `HKCU\Software\Classes\CLSID`（InprocServer32/LocalServer32）
- 用户配置单元的路径统一写 `HKCU\...`，`user` 记配置单元属主：`uid` 为 SID，`name` 为 `DOMAIN\user`（解析不到省略）；
  HKLM 事件没有 `user`。属主不等于写入者（管理员也能写已加载的别人的配置单元），所以不放 `actor.user`
- 无进程上下文

## 100001 应用日志（syslog）

server 侧归一化（`server/internal/syslog/server.go:167-184`）：

```json
{
  "activity_id": 1,
  "severity_id": 3,
  "message": "<正文原文>",
  "metadata": { "product": { "name": "<AppName>" }, "log_name": "<MsgID>" },
  "actor": { "process": { "pid": 123 } },
  "device": { "hostname": "web01" },
  "facility": 4
}
```

- RFC3164 / RFC5424 双支持（PRI 后首字符区分）；RFC5424 的 STRUCTURED-DATA
  **只剥离不解析**（`parse.go:74-81`）
- 正文 message 不做进一步结构化提取
- 资产归属：先主机名匹配，退回源 IP，都对不上留空（`server.go:221-243`）

## 实体标识约定

- **进程 GUID**：agent 侧 UUID v4，pid 复用直接覆盖；父 GUID 查不到为空；
  退出事件复用启动 GUID。server 只接受合法 UUID 才写入列（`agent.go:193-214`）
- **conn_tuple**：`tcp:src:sport>dst:dport`，网络类关联与规则的统一键
- **资产归属**：agent 事件按 agent_id 直查；sensor 按源 IP，源地址未纳管时按目的 IP；syslog 按
  主机名→源 IP 两级
- **事件不可变**：原始事件只增不改；告警的 count/last_ts 随去重更新；
  incident 的 status/graph 随关联与研判演进。janitor 只删无告警引用的
  过期事件

## gRPC 契约

- `proto/agent.proto`：`AgentEvent{agent_id, ts_unix_ns, class_uid,
  process_guid, parent_process_guid, username, conn_tuple, raw_json,
  dropped_events}`；另有注册、指令下发（Command/CommandResult）消息
- `proto/sensor.proto`：`FlowRecord{start/end_unix_ns, 五元组, protocol,
  双向 packets/bytes, tcp_flags, dns_query, dns_rcode, dns_answers,
  tls_sni, ja3, ja3s, http_host, http_uri, http_user_agent}`；
  `FlowBatch` 携带 `dropped_packets` 计数
- Go 侧生成代码已提交在 `server/pb/`（改动 proto 后需用 protoc +
  protoc-gen-go 重新生成）；Rust 侧由 build.rs 用 `protoc-bin-vendored`
  构建时生成，无需安装 protoc
