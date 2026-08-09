# 事件模型参考

OpenXDR 采用 OCSF 风格事件模型。本文列出所有事件类别、字段 schema 与实体标识，
是写规则、改采集、查事件的基准参考。字段以代码实现为准（标注源码位置）。

## 事件类别总表

| class_uid | 类别 | 来源 | 产生位置 |
|---|---|---|---|
| 1001 | 文件活动（File System Activity） | agent | Linux fswatch（fanotify/inotify）、Windows fswatch_win、persistwatch 文件/计划任务部分 |
| 1007 | 进程活动（Process Activity） | agent | Linux eBPF/netlink/轮询、Windows ETW/轮询（启动+退出） |
| 3002 | 认证（Authentication） | agent | Linux wtmp/btmp、Windows Security 4624/4625 |
| 4001 | 网络活动（Network Activity） | agent（仅 eBPF）/ sensor | agent netwatch 出站连接；sensor 非 DNS 会话 |
| 4003 | DNS 活动（DNS Activity） | sensor | 会话带 dns_query 时判定 |
| 201002 | 注册表值活动（Registry Value Activity） | agent | Windows persistwatch 注册表键/服务快照 |
| 100001 | 应用日志（OCSF 私有段） | syslog | server syslog 接入 |

events 表公共列：`ts`、`class_uid`、`source`（agent/sensor/syslog）、
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
- **退出事件复用启动时的进程 GUID**（注册表查得到就填同一个），血缘不断；
  netlink 路径的退出事件带 `exit_code`；ETW Stop 与轮询消失 pid 的退出事件
  只有 pid 等少量字段（进程已退场，补不到细节）
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

## 4001 网络活动

两个来源，字段不同：

**agent netwatch**（仅 eBPF 构建，`netwatch.rs:57-81`）——带进程血缘：

```json
{
  "activity_id": 1,
  "connection_info": { "direction": "outbound", "protocol_name": "tcp" },
  "src_endpoint": { "ip": "...", "port": 51234 },
  "dst_endpoint": { "ip": "...", "port": 443 },
  "process": { "pid": 1234, "uid": "<进程 GUID>" }
}
```

**sensor 会话**（server 侧归一化，`grpcsvc/sensor.go:168-214`）——带流量统计：

```json
{
  "activity_id": 6,
  "duration_ms": 1230,
  "connection_info": { "protocol_num": 6, "tcp_flags": "..." },
  "src_endpoint": { "ip": "...", "port": 51234 },
  "dst_endpoint": { "ip": "...", "port": 443 },
  "traffic": { "packets": 10, "bytes": 2048, "packets_in": 6, "bytes_in": 1200, "packets_out": 4, "bytes_out": 848 },
  "tls": { "sni": "example.com", "ja3_hash": "...", "ja3s_hash": "..." },
  "http_request": { "hostname": "...", "url": { "path": "/x" }, "user_agent": "..." }
}
```

- `tls` 对象在 SNI/JA3/JA3S 任一非空时出现；`ja3s_hash` 是服务端指纹，
  与 `ja3_hash` 一样参与哈希情报碰撞
- sensor 上报前把 src 摆正为客户端方向（`sensor/src/report.rs:19-49`）
- sensor 无进程信息；资产归属按**源 IP** 反查 asset（`sensor.go:67-98`）
- `conn_tuple` 格式统一为 `tcp:src:sport>dst:dport`，agent 与 sensor 同格式，
  横向移动关联直接复用

## 4003 DNS 活动

sensor 会话中 `dns_query` 非空时判定为 4003（`sensor.go:24-28,79-82`），
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

## 201002 注册表值活动

Windows persistwatch（`persistwatch.rs`）：

```json
{
  "activity_id": 1,
  "reg_key": { "path": "HKLM\\SOFTWARE\\...\\Run" },
  "reg_value": { "data": "C:\\evil.exe" }
}
```

- activity_id：1=Create、3=Modify、4=Delete（删除事件带旧值内容）
- 覆盖：Run/RunOnce/Winlogon 自启动键（HKLM+HKCU）+ **Windows 服务快照**
  （`HKLM\SYSTEM\CurrentControlSet\Services`，值为 ImagePath+启动类型）
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
- **资产归属**：agent 事件按 agent_id 直查；sensor 按源 IP；syslog 按
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
