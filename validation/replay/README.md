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
| 进程启动（ETW / netlink / eBPF / 轮询） | ✅ ETW | ⚠️ 轮询兜底（命名空间设计降级） | 未验证（PEB 兜底） | 未验证 |
| 进程退出 | ✅ ETW Stop，复用启动 GUID | ⚠️ 轮询消失检测 | 未验证 | 未验证 |
| 短命进程 cmdline | ✅（极快进程有竞争，见下注） | ❌ 多为空（轮询固有） | 未验证 | 未验证 |
| 文件监控（RDCW / fanotify / inotify） | ✅ RDCW 增改删 | ✅ fanotify 全生命周期+肇事进程 | — | 未验证 |
| 持久化点（注册表/Startup/服务/计划任务） | ✅ 增删，删除带旧值 | ✅（经 fanotify 覆盖 systemd/cron/.ssh） | — | — |
| 网络（eBPF 出站） | 不采集（设计：交给 sensor） | ✅ 捕获 10.0.0.1:4444 出站 | — | 未验证 |
| 登录（4624/4625 / wtmp-btmp） | ✅ 4625 含失败原因码 | 不适用（WSL 无 wtmp 写入） | 未验证 | 未验证 |

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

## 已知边界

- agent 异常退出会泄漏 ETW 会话（`logman query -ets` 里的 `n4r1b-trace-*`），
  攒多了新会话创建报"系统资源不足"→ 手动 `logman stop <name> -ets` 清理。
- WSL2 不能验证：netlink proc connector（命名空间，agent 正确降级）、wtmp
  登录（无写入）、短命进程 cmdline（轮询固有）。进程类规则的实机命中
  需要真 Linux 机器。
- server 热重载偶现不及时（一次未定位），重启 server 后规则立即生效。
