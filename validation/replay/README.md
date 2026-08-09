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
| 持久化点（注册表/Startup/服务/计划任务） | ✅ 增删，删除带旧值 | ✅（经 fanotify 覆盖 systemd/cron/.ssh） | — | — |
| 网络（ETW / eBPF 出站） | ✅ ETW TcpConnect + 进程 GUID | ✅ eBPF 捕获 10.0.0.1:4444 | — | ✅ eBPF 完整五元组+进程 GUID |
| 登录（4624/4625 / wtmp-btmp） | ✅ 4625 含失败原因码 | 不适用（WSL 无 wtmp 写入） | 未验证 | ✅ wtmp SSH 登录 |

注：Windows 上秒退进程（如 `reg add`）的 cmdline 靠 ETW 事件触发后回读，
进程已退场则读不到（cmd_line 为空）——已知竞态，注册表/文件类事件不受影响。

## 实机规则命中记录（2026-08-09）

- Windows：Windows Recon（systeminfo）、LOLBin Download（certutil/bitsadmin/mshta）、
  Suspicious PowerShell、Autostart Registry Write via CLI、Remote Execution Lateral
  （wmic /node:）、Service Installed、Autostart Entry Deleted、Run Key Persistence
- Linux（WSL2）：Sensitive File Modified、Systemd Service Unit File、
  Suspicious Outbound（eBPF 捕获 4444 出站）
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

## 第四轮：eBPF 双机长期试运行（2026-08-09）

在 pve2 创建独立 `openxdr-lab`（`192.0.2.10`），server 强制 mTLS，pve1/pve2
使用按主机绑定证书常驻接入。两台均成功加载 eBPF 进程与
`inet_sock_set_state` 网络采集。

首轮实测发现 SYN_SENT tracepoint 的 `sport` 在 PVE 7.0 内核确实为 0。内核侧
改为用 `skaddr` 暂存 SYN_SENT 的发起 PID，在 ESTABLISHED/CLOSE 再读取真实端口
并上报；复测得到完整 `src_ip:ephemeral_port > dst_ip:port` 和进程 GUID。启动后
创建 `/var/spool/at`，5 秒补扫后文件建/改/删均被 fanotify 捕获。

pilot 每小时记录事件、告警、incident、活跃资产和数据库体积，作为是否需要时间
分区及降噪效果的真实依据，详见 [pilot.md](../../docs/pilot.md)。

## 已知边界

- agent 异常退出会泄漏 ETW 会话（`logman query -ets` 里的 `n4r1b-trace-*`），
  攒多了新会话创建报"系统资源不足"→ 手动 `logman stop <name> -ets` 清理。
- WSL2 不能验证：netlink proc connector（命名空间，agent 正确降级）、wtmp
  登录（无写入）、短命进程 cmdline（轮询固有）；这些格子已由真 Linux 双机补验。
- ~~server 热重载偶现不及时~~：已确认元数据指纹与 watcher 启动竞态两个根因，
  改为内容 SHA-256 指纹并从 Engine 已加载指纹起步，等大小/等 mtime 覆盖写回归通过。
