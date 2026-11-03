# 补充检测规则与证据采集

这组规则补充 Linux/Windows 安全事件的具体检测场景，同时完善来源 IP 关联和可选 Windows 证据采集。规则中的 ATT&CK 标签只表示关联技术，不代表完整覆盖该技术，也不证明告警行为一定是攻击。

## 规则与数据前提

规则按现有命名放在 `rules/`（告警）与 `rules/signals/`（时序信号，`openxdr_signal: true`，不单独告警），参照 Wazuh 规则族的场景、按 OpenXDR 字段模型重写：

| 规则文件 | 级别 | 说明 |
|---|---|---|
| `win_office_verclsid` | high | Office 拉起 verclsid（T1218.012 / T1559.001） |
| `win_sysmon_image_replaced` | high | Sysmon 25 映像被替换（T1055.012） |
| `win_browser_credential_copy` | high | 命令行复制浏览器凭据库（T1555.003） |
| `win_firewall_disable` | high | netsh / PowerShell 关闭防火墙（T1562.004） |
| `win_fodhelper_shell` | high | fodhelper 拉起 shell，UAC 绕过（T1548.002） |
| `win_pth_command` | high | `sekurlsa::pth /ntlm:`（T1550.002） |
| `win_regsvr32_scriptlet` | high | regsvr32 加载远程 scriptlet（T1218.010） |
| `win_rundll32_script` | high | rundll32 内嵌 javascript / vbscript（T1218.011） |
| `win_sam_export` | high | `reg save HKLM\SAM`（T1003.002） |
| `win_wevtutil_clear` | high | wevtutil 清日志（T1070.001） |
| `win_sysmon_lsass_access` | medium | Sysmon 10 读 LSASS 内存（T1003.001） |
| `win_sysmon_remote_thread` | medium | Sysmon 8 向系统进程创建远程线程（T1055） |
| `win_powershell_screen_capture` | medium | PowerShell CopyFromScreen（T1113） |
| `win_admin_share_copy` | medium | 向 ADMIN$ / C$ 复制文件（T1570 / T1021.002） |
| `win_script_userdir` | medium | wscript / cscript 跑下载或临时目录脚本（T1059.005 / .007） |
| `win_winrm_exec` | medium | PowerShell Remoting 远程执行（T1021.006） |
| `app_web_path_traversal` | medium | Web 日志里的路径穿越取敏感文件（T1190） |
| `win_ad_discovery` | low | Get-ADUser / Get-NetUser（T1087.002） |
| `signals/lnx_signal_group_db` | 信号 | /etc/group、gshadow 变更（T1098） |
| `signals/lnx_signal_init_scripts` | 信号 | rc.local、init.d、rc*.d 变更（T1037.004） |
| `signals/lnx_signal_systemd_timer` | 信号 | systemd .timer 变更（T1053.006） |
| `signals/lnx_signal_systemd_override` | 信号 | systemd drop-in 覆盖配置变更（T1543.002） |
| `signals/lnx_signal_systemd_unit_deleted` | 信号 | systemd .service 单元删除（T1070） |
| `signals/lnx_signal_audit_config` | 信号 | auditd 配置变更（T1562.012） |
| `signals/lnx_signal_account_create` | 信号 | useradd / adduser（T1136.001） |
| `signals/win_signal_ntlm_network_logon` | 信号 | NTLM 网络登录（T1078） |
| `signals/win_signal_login_success` | 信号 | Windows 登录成功，RDP 除外（T1078） |
| `signals/win_signal_rdp_success` | 信号 | Windows RDP 登录成功（T1021.001） |
| `signals/app_signal_mysql_auth_failure` | 信号 | MySQL 认证失败（T1110.001） |
| `signals/app_signal_postgres_auth_failure` | 信号 | PostgreSQL 认证失败（T1110.001） |

另有 6 条时序规则 `temporal-rules/wazuh-gap-*.yml`（SSH / Windows 同源失败计数、MySQL / PostgreSQL 失败计数、
Windows 失败后成功 / RDP 成功），清单与重叠说明见 [temporal-rules/README.md](../temporal-rules/README.md#认证与侦察)；
时序规则仍需配置 `TEMPORAL_RULES_PATH` 才加载。标有 `openxdr_signal: true` 的规则只提供关联候选，不能把它们的标签计作独立检测覆盖。

取舍：

- **Linux 文件类改成信号**。agent 的 fanotify 递归监控整个 `/etc`，apt、systemctl、useradd 会持续改 group、init.d、
  systemd 与 audit 配置，单发告警全是运维噪声，所以只作时序输入；这些信号目前还没有时序规则引用，引用前不产生任何效果。
  `lnx_signal_systemd_unit_deleted` 排除 `.wants/` / `.requires/` 下的符号链接；agent 把「移出」记作删除，编辑器改名备份时原路径也会报一次删除。
  agent 默认只监控 `/etc/systemd/system`，`/usr/lib/systemd/system`、`/lib/systemd/system` 需在采集配置 `fileWatchDirs` 里显式加上才看得到。
  `lnx_signal_account_create` 的帮助 / 版本排除按独立参数匹配；引擎正则不区分大小写，`-D` 与 `-d` 分不开，所以不排除 `useradd -D`。
- **与 SigmaHQ 重复的不再收**：用户 crontab 变更由 SigmaHQ `file_event_lnx_susp_cron_file_created` 覆盖（只认
  `/var/spool/cron/crontabs/` 与 `/var/spool/cron/root`，RHEL 上非 root 用户的 `/var/spool/cron/<用户>` 不覆盖）；
  清空审计规则由 SigmaHQ `proc_creation_lnx_auditctl_clear_rules`（`auditctl -D`）覆盖。auditd `CONFIG_CHANGE remove_rule`
  每次 auditd 重载都按规则条数各报一次，不再单独告警，在 `validation/detection_evidence.yml` 里记为已知缺口。
- **NTLM 网络登录降为信号**，不标 T1550.002：域内访问共享、打印同样走 NTLM，单凭它认不出 Pass-the-Hash。
- **Sysmon LSASS 访问与远程线程降为 medium**，按固定完整路径排除 Defender（MsMpEng）、MDE（MsSense / SenseIR）、
  WmiPrvSE，LSASS 另排除任务管理器与系统 svchost，远程线程另排除 csrss / wininit / winlogon / services。
  按完整路径而非文件名排除，放在别处的同名程序照常命中；第三方 EDR、备份、监控与调试器不在排除里，上线前按回测结果按主机窄抑制。
- 没有时序规则引用的信号（sudo 成功、WinRM 端口连接、auditd 普通身份 root 执行）不收。

正常维护、安全软件、软件安装及经授权的自动化都可能触发这些 experimental 规则。部署前应在自己的历史事件上回测。

## 按来源 IP 关联

新增时序维度 `group_by: asset_source_ip`，按组、目标资产和规范化后的来源 IP 分桶，避免多个不同来源各自的少量失败登录累加成同源暴破。

- 来源使用认证事件的 `src_endpoint.ip`；IPv4、IPv4-mapped IPv6 与 IPv6 按统一口径规范化。
- 缺失或无效来源不进入这一关联维度，不用 syslog 传输对端地址冒充攻击来源。
- SSH syslog 在识别的失败登录格式中提取来源 IP，转发代理的地址不会覆盖日志内来源。
- 候选表增加可空 `source_entity` 和部分索引，只读历史回测采用同一维度。
- 来源维度只决定计数口径；告警按主机合并，同一主机被多个来源各自打满阈值只出一条告警、计数累加，说明里记首个来源 IP。
- 跨来源、跨资产、跨组、缺来源与重复投递均有反例测试。

## Windows Sysmon：显式开启

更新 Windows Agent 后，在资产详情的“采集配置”中启用“Sysmon 注入与内存访问”，对应 `collectSysmon: true`。默认关闭，下次 Agent 注册时应用。

目标主机必须预先安装可信 Sysmon，并配置以下事件。该开关只订阅日志，不会安装 Sysmon 或改动其策略。

| 事件 | 证据 | 检测边界 |
|---|---|---|
| 8 CreateRemoteThread | 源/目标映像、PID、进程 GUID、起始函数等 | 向指定系统进程创建远程线程；不单凭此事件断言线程劫持或镂空 |
| 10 ProcessAccess | 源/目标映像和规范化的 GrantedAccess | 访问 LSASS 的指定敏感权限掩码；不证明凭据已被导出，安全软件也可能命中 |
| 25 ProcessTampering | 映像和 Type | 仅对明确的 `Image is replaced` 匹配进程映像替换规则 |

证据位于 `raw.sysmon`，使用独立活动编号，不伪装为新进程启动，不编造进程 GUID 归属。订阅成功只说明日志订阅建立，仍需通过原始事件验证实际送达；未安装或无读取权限会报告 unavailable。

已有的 Windows 登录采集补充认证包、登录进程、工作站、NTLM 包及密钥长度字段。NTLM 网络登录只作时序信号，正常认证也会命中，不能单凭它确认 Pass-the-Hash 或域账号被盗。

## Linux auditd：单记录归一化

服务端 syslog 对 auditd/audit/audispd/audisp-syslog 的 `SYSCALL` 和 `CONFIG_CHANGE` 单记录提取 `audit` 对象，保留 auid、uid/euid、syscall、结果、exe、时间和审计序号，同时保留原始消息。重复键、截断引号、非法片段和超长记录被拒绝。

需要自己配置可信 auditd 日志转发和接入来源。启用 Agent 文件监控并不会自动产生这些审计字段。此实现尚未关联 SYSCALL/EXECVE/PATH 多条记录；`audit.record_scope=single_record` 明确标示这一边界。目前仓库里没有规则消费 `audit.*` 字段，解析先为后续规则与研判保留原文结构。

## 验证与实机验收

`validation/exact-rule-cases.json` 按规则 ID 对拍正反例（`go test ./internal/sigma -run TestExactRuleCorpus`）；`validation/detection_evidence.yml` 进 `detectcheck` 技术对拍；`validation/temporal/auth-burst-cases.json` 验证来源维度与序列边界（单元回放与数据库持久回放）。Go 集成测试检查 syslog 入队、资产归属、持久候选和告警行为。Windows 解析测试不依赖真实攻击命令。

```sh
cd server
go run ./cmd/sigmacheck --strict ../rules
go run ./cmd/detectcheck --strict
go test ./...
# INTEGRATION_DATABASE_URL 必须指向独立测试库；测试会清表。
go test -tags integration -p 1 ./...
```

编译与合成事件测试不等同于端点可见性验收。部署后还需验证：

1. Windows Agent 已更新、Sysmon 通道已配置，8/10/25 的原始字段及主机归属真实送达。
2. NTLM 日志上下文字段、PowerShell 4104 内容及父子进程路径真实可见。
3. auditd 转发没有把中继主机当成源主机，且 auid/uid/euid 与原文一致。
4. 在真实历史日志上核查命中量和时序候选上限；无历史样本不能视为零误报证明。

这些规则不会自动启用响应处置，也不更改命令审批策略。
