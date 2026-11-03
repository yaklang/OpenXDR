# 实验性时序规则

此目录独立于单事件 `rules/`，默认不启用。配置 `TEMPORAL_RULES_PATH` 指向本目录才能加载，
容器需要只读挂载；同时保持 `RULES_PATH` 指向配套基础规则。基础规则和时序规则必须成套发布。

规则字段见 [时序检测实现约定](../docs/temporal-detection.md#规则格式)，`group_by` 可选 `asset`（默认）、`account` 或 `asset_source_ip`（同主机同来源 IP 计数，告警仍按主机合并），未知取值拒绝加载。
生产按不可变版本目录发布时，每个版本目录需带 `SHA256SUMS`，见同文档「不可变版本目录发布」。

告警类基础规则仍会各自产生单事件告警；时序告警是在它们之上补的一条「链路」告警，不自动触发任何额外处置。
`rules/signals/` 下的**信号规则**（`openxdr_signal: true`，级别 informational）例外：只作时序规则的输入，命中不单独告警，
用于「只在链路里才有意义、单独看全是噪声」的步骤，见 [时序检测 · 信号规则](../docs/temporal-detection.md#信号规则)。
所有规则只证明**同组同实体内的时间先后**，不证明同一进程或同一会话的因果关系，需结合原始证据复核。
单元回放与数据库持久回放见 `validation/temporal/README.md`；尚未做生产误报率评估。
上线前用 `cmd/backtest` 的时序模式在生产只读副本上逐条回测命中量，见 [时序检测 · 回测](../docs/temporal-detection.md#回测)，
命中量不可接受的规则从发布目录里拿掉即可，规则之间互不依赖。

## 取值原则

- **窗口都不超过 15 分钟**。生产 Observe 按快照内**最大窗口**回查 `[t − 最大窗口, t + 最大窗口]` 的同资产候选，
  超过 10000 条记 `candidate_limit` 缺口、不求值；窗口拉长会让被公网扫描的主机更早触顶。需要更长窗口的链路先评估候选量。
- **序列优先于计数**。单一基础规则的计数只看次数，运维脚本循环调用就能凑够；序列要求两类不同动作按先后出现。
- **第二步选运维少做的动作**。「关防火墙 / 关 SELinux 后 `curl | sh`」正是 k3s 等安装文档的标准步骤，
  所以安全防护削弱之后只认从 `/dev/shm` 执行；清历史、清审计规则、清 syslog 在安装前出现的情况少见，才接下载执行。
- **同时间戳不算先后**（引擎语义）。同一条命令行同时命中两步（如 `sh -c "unset HISTFILE; curl … | sh"`）不构成序列。
- **先后不可信时用 `temporal`（不论先后的共现）**。兄弟进程几乎同时 exec，采集到的先后不保证，严格序列会随机漏报。
- **信号规则只被引用才落候选**。新信号先用单事件回测估每天命中量、再看时序回测的候选峰值，确认不会撑出 `candidate_limit`。

## 规则清单

下表「基础规则」列出文件名，ID 见对应 YAML。级别除侦察计数为 medium 外均为 high。

### 认证与侦察

| ID | 类型 / 实体 | 窗口 / 阈值 | 基础规则 |
|---|---|---|---|
| `temporal:linux-auth-burst` | 计数 / 主机 | 5 分钟 ≥ 5 | `lnx_login_failure` |
| `temporal:linux-account-auth-burst` | 计数 / 账号，`min_assets: 2` | 10 分钟 ≥ 5 | `lnx_login_failure` |
| `temporal:linux-bruteforce-then-recon` | 序列 / 账号 | 10 分钟，失败 ×5 → 侦察 | `lnx_login_failure` ×5、`lin_recon_commands` |
| `temporal:linux-bruteforce-success-recon` | 序列 / 账号 | 10 分钟，失败 ×5 → 成功 → 侦察 | `lnx_login_failure` ×5、信号 `lnx_signal_login_success`、`lin_recon_commands` |
| `temporal:windows-recon-burst` | 计数 / 主机 | 2 分钟 ≥ 6 | `win_recon_commands` |
| `temporal:wazuh-gap-sshd-fail-burst` | 计数 / 主机+来源 IP | 2 分钟 ≥ 10 | `lnx_ssh_auth_failure`（syslog） |
| `temporal:wazuh-gap-windows-fail-burst` | 计数 / 主机+来源 IP | 2 分钟 ≥ 10 | `win_login_failure` |
| `temporal:wazuh-gap-mysql-fail-burst` | 计数 / 主机 | 2 分钟 ≥ 10 | 信号 `app_signal_mysql_auth_failure` |
| `temporal:wazuh-gap-postgres-fail-burst` | 计数 / 主机 | 2 分钟 ≥ 10 | 信号 `app_signal_postgres_auth_failure` |
| `temporal:wazuh-gap-windows-fail-success` | 序列 / 账号 | 10 分钟，失败 ×5 → 成功（RDP 除外） | `win_login_failure` ×5、信号 `win_signal_login_success` |
| `temporal:wazuh-gap-windows-fail-rdp` | 序列 / 账号 | 10 分钟，失败 ×5 → RDP 成功 | `win_login_failure` ×5、信号 `win_signal_rdp_success` |

- `linux-auth-burst`：同组同主机 5 分钟内至少 5 次 Linux 失败认证。不按账号或源 IP 分组，不同用户的失败也会累计。
  它是集中失败线索，不能直接断言账号遭到暴力破解。
- `linux-account-auth-burst`：同组同账号 10 分钟内至少 5 次失败、来自至少两台主机。单机 5 次只命中上一条，不重复告警。
  账号取事件 `username` 列，去首尾空白、转小写后比较，不做域前缀/UPN 互认；没有用户名的失败记 `no_account` 缺口。
  不同组的同名账号互不累计；资产换组后其此前的失败不再计入。
- `linux-bruteforce-then-recon`：同组同账号 10 分钟内先有 5 次失败登录，再由**同一账号**执行侦察命令
  （`whoami` / `uname -a` / `cat /etc/passwd`）。账号维度：失败登录的用户名与执行侦察的进程属主相同才关联，
  公网扫描爆破 root、运维用自己的账号排查不会连起来。10 分钟与固定的爆破得手升级（`xdr:bruteforce-success`）一致。
  中间不要求成功登录，严格形态见下一条。
  已知误报：被公网持续扫描 root 的主机上，root 的 cron / 监控脚本恰好在窗口内调用 `whoami` 或 `uname -a`；
  自己反复输错密码 5 次后登录执行 `whoami`。前者回测命中多时，按主机对 root 账号窄抑制。
- `linux-bruteforce-success-recon`：上一条的严格形态，「失败 ×5 → 同账号成功登录 → 同账号侦察」，同一个 10 分钟窗口内严格先后。
  成功登录一步引用信号规则 `rules/signals/lnx_signal_login_success.yml`（wtmp / sshd 日志的成功登录，不单独告警）。
  比上一条少了「爆破 root 失败后、root 自己的 cron 调 `whoami`」这类误报，但要求成功登录可见：agent 读不到 sshd journal、
  只剩 wtmp 时，不开 pty 的 `ssh host cmd` 不落成功记录，这条会漏，上一条仍能兜住，所以两条并存；
  真实爆破得手两条会同时在侦察事件上命中。生产 7 天回测（1615 万条事件，2026-10-13 17:00 至 10-20 17:00 UTC）期间
  全网没有一次失败登录，两条都是 0 次，误报率没有可用的数据，只证明了候选量（成功登录信号每天约 100 次，全是 root）。
- `windows-recon-burst`：同主机 2 分钟内至少 6 次侦察命令。Linux 版同口径的 `linux-recon-burst` 在生产 7 天数据上回测命中 12 次，
  全是运维自动化（AI 运维插件成批跑 `uname` / `cat /etc/os-release`），没有上线；要重新加，得先有能排除自动化来源的信号。引擎只能数事件、不能数「不同命令种类」，
  所以阈值定在手工排查（三五条）之上，只抓脚本化的密集侦察；手工侦察会漏，这是刻意取舍。
  已知误报：每分钟多次调用 `whoami` 判断身份的 cron 脚本（Linux 规则按子串匹配 `whoami`，`sh -c "whoami; …"` 父子进程各算一次）；
  RMM / 资产盘点代理成批跑 `ipconfig`、`systeminfo`、`netstat`（Windows）；平台 Pi 运维会话已按平台指令归属另行处理，
  但第三方 AI 运维插件（如 DNS 容器里的 termix-ops）不带平台标记，会被计入。
- `wazuh-gap-*` 六条来自 [补充检测规则](../docs/detection-evidence.md)。两条「主机+来源 IP」计数只数同一来源的失败，
  多个来源各凑几次不会累加成一次爆破；但告警按主机合并，同一主机被多个来源各自打满阈值只出一条告警、计数累加。
  `sshd-fail-burst` 数的是 syslog 接入的 sshd 日志，`linux-auth-burst` 数的是 agent 的登录事件（btmp / journald），
  两者不是同一批事件；主机同时装 agent 又转发 sshd syslog 时，同一次爆破两条都会命中。
  Windows 失败后成功的两条按登录类型分开（成功信号排除 RDP 类型 10），同一次登录只命中其中一条；
  但同主机同账号「5 次失败后成功」还会命中内置的 `xdr:bruteforce-success`（critical），两者并存，
  时序规则多出的是同组跨主机（在 A 失败、在 B 成功）的情形。

### 下载执行后建立持久化

| ID | 类型 / 实体 | 窗口 | 基础规则 |
|---|---|---|---|
| `temporal:linux-download-sensitive-file` | 序列 / 主机 | 10 分钟 | `lnx_download_exec` → `lnx_sensitive_file_change` |
| `temporal:linux-download-systemd-unit` | 序列 / 主机 | 10 分钟 | `lnx_download_exec` → `lnx_systemd_service_file` |
| `temporal:linux-download-shell-rc` | 序列 / 主机 | 10 分钟 | `lnx_download_exec` → `lnx_shell_rc_persistence` |
| `temporal:windows-lolbin-download-autostart` | 序列 / 主机 | 15 分钟 | `win_lolbin_download` → `win_registry_persistence` |
| `temporal:windows-lolbin-download-scheduled-task` | 序列 / 主机 | 15 分钟 | `win_lolbin_download` → `win_scheduled_task_file` |

- Linux 三条覆盖一句话植入后的常见落脚点：cron、authorized_keys、sudoers、ld.so.preload（敏感文件变更）、
  `/etc/systemd/system/*.service`、shell 启动文件。authorized_keys 已被文件监控覆盖（默认盯 `/root/.ssh` 与各用户 `.ssh`），
  不再另用命令行规则重复关联。10 分钟足够落地脚本跑完，短于常规运维批次间隔。
- 已知误报：`curl | sh` 形式的官方安装脚本本身就会落持久化——k3s / rancher 写 `/etc/systemd/system/*.service`，
  nvm、rustup、sdkman、oh-my-zsh、bun 改 `~/.bashrc` / `~/.profile`。包管理器装服务不经管道执行，不会命中。
  这类安装一台机器一般只发生一次，需要时按主机与时间窗临时抑制，不建议整条关闭。
- Windows 两条：certutil / bitsadmin / mshta 下载后写 Run / Winlogon 或新建/修改计划任务。注册表与计划任务来自
  persistwatch 30 秒一轮的快照，事件时间晚于真实写入，持久化在后、顺序不会反，15 分钟留出快照延迟。
  `win_scheduled_task_file` 不含系统自带任务（`Tasks\Microsoft\Windows\`）的修改——Windows 维护每十几分钟就改一次，
  会和任何下载凑成链；自带任务的动作被劫持由单事件规则 `win_scheduled_task_hijack` 报 high。
  已知误报：用 bitsadmin / certutil 分发软件的老式登录脚本随后写入自启动；正常软件安装写 Run 键不经 LOLBin，不会命中。

### 管道下载执行（兄弟进程）

| ID | 类型 / 实体 | 窗口 | 基础规则 |
|---|---|---|---|
| `temporal:linux-download-pipe-shell` | 共现（不论先后）/ 主机 | 5 秒 | 信号 `lnx_signal_download_tool`、信号 `lnx_signal_shell_stdin` |

- `curl … | bash` 在脚本或交互式 shell 里由 shell fork 出两个兄弟进程，`curl URL` 与无参数 / `-s` 的 `bash` 各一条命令行，
  都不含 `|`，单事件 `lnx_download_exec` 只看得到 `sh -c "curl … | sh"` 这种整条进命令行的形态。两端各写一条信号规则：
  curl / wget 启动；不带脚本参数的 shell（`bash`、`sh -s`、`sh -s - server`，不含登录 shell `-bash`、`bash -c`、`bash x.sh`）。
  两者单独看都是运维噪声，只作信号。兄弟进程几乎同时 exec，采集到的先后不保证 curl 在前，所以用 `temporal` 不论先后，
  5 秒窗口给轮询 / netlink 采集的时间戳抖动留余量。
- 生产 7 天回测（同上）：两条信号分别每天约 137 次与 28 次（监控探活 curl、`timeout 5 sh` 等运维插件），链路命中 2 次，
  都在测试机：一次是实机回放（两者同父进程 `bash /tmp/linux.sh`，相隔 0.4 毫秒），一次是用平台的一行命令安装流量探针
  （`curl -fsSL …/sensor-install.sh | sh -s -- …`，同一安装的父进程 `bash -c "curl … | sh"` 已被 `lnx_download_exec` 单独告警）。
- 已知误报：交互式或脚本里用 `curl | sh` 装软件——本平台 agent / sensor 一行安装、k3s、docker、rustup 等官方安装脚本；
  监控脚本恰好在交互式子 shell（`bash`）、`docker exec … sh` 前后 5 秒内 curl 探活。轮询采集兜底时短命的 curl 可能采不到，会漏。
- 按父进程分组（`group_by: parent`）仍不做：信号规则解决了基础规则的告警噪声，而资产维度 5 秒窗口的命中都是真正的管道
  （安装脚本也是同一个父进程拉起的兄弟进程，按父进程分组同样命中），精度不是瓶颈；候选量也不是（见下文「候选量」），
  加一维只多出候选表列、锁顺序与清理口径的复杂度。

### 凭据读取后打包、外传或外联

| ID | 类型 / 实体 | 窗口 | 基础规则 |
|---|---|---|---|
| `temporal:linux-shadow-read-archive` | 序列 / 主机 | 15 分钟 | `cred_credential_dumping` → `lnx_archive_collection` |
| `temporal:linux-shadow-read-upload` | 序列 / 主机 | 15 分钟 | `cred_credential_dumping` → SigmaHQ `proc_creation_lnx_susp_curl_fileupload` |
| `temporal:linux-ssh-key-read-archive` | 序列 / 主机 | 15 分钟 | `lnx_ssh_private_key_access` → `lnx_archive_collection` |
| `temporal:linux-ssh-key-read-upload` | 序列 / 主机 | 15 分钟 | `lnx_ssh_private_key_access` → SigmaHQ `proc_creation_lnx_susp_curl_fileupload` |
| `temporal:linux-ssh-key-read-suspicious-outbound` | 序列 / 主机 | 15 分钟 | `lnx_ssh_private_key_access` → `net_suspicious_outbound` |
| `temporal:credential-dump-suspicious-outbound` | 序列 / 主机 | 15 分钟 | `cred_credential_dumping` → `net_suspicious_outbound` |

- 读取影子库（`cat` / `cp /etc/shadow`、`unshadow`）或 SSH 私钥（新增基础规则 `lnx_ssh_private_key_access`，
  只认读取/拷贝/编码工具与 `find -name id_*`，`ssh -i`、公钥、`ssh-keygen` 不算）之后，出现打包敏感目录、
  `curl` 表单/数据上传或连 4444 / 5555 / 6667 / 31337 端口。15 分钟给手工操作留余量，仍在快照最大窗口内。
- `credential-dump-suspicious-outbound` 不限 OS：`cred_credential_dumping` 同时覆盖 Windows lsass 转储，
  `net_suspicious_outbound` 两侧都有采集；Windows 出站只有 TCP。
- 已知误报：备份脚本先 `cp /etc/shadow` 留底、15 分钟内又 `tar` 打包 `/etc`；改密码前留底影子库后马上用 `curl -d` 推送通知或调用接口
  （SigmaHQ 上传规则的 `-d` / `-F` / `-T` 判定按引擎强制不区分大小写，`curl -f` 也会命中）；
  运维用 `cat` 查看私钥后打包家目录做迁移；adb（5555）、IRC（6667）等合法业务端口外联。
  例行备份只打包、不单独读影子库或私钥，不会命中。

### 防御削弱后可疑执行

| ID | 类型 / 实体 | 窗口 | 基础规则 |
|---|---|---|---|
| `temporal:linux-history-tamper-download-exec` | 序列 / 主机 | 15 分钟 | `lnx_history_tampering` → `lnx_download_exec` |
| `temporal:linux-audit-rules-cleared-download-exec` | 序列 / 主机 | 15 分钟 | SigmaHQ `proc_creation_lnx_auditctl_clear_rules` → `lnx_download_exec` |
| `temporal:linux-syslog-cleared-download-exec` | 序列 / 主机 | 15 分钟 | SigmaHQ `proc_creation_lnx_clear_syslog` → `lnx_download_exec` |
| `temporal:linux-security-disabled-shm-exec` | 序列 / 主机 | 15 分钟 | SigmaHQ `proc_creation_lnx_security_tools_disabling` → SigmaHQ `proc_creation_lnx_susp_exec_from_dev_shm` |
| `temporal:windows-defender-exclusion-lolbin-download` | 序列 / 主机 | 15 分钟 | `win_defender_exclusion_tamper` → `win_lolbin_download` |

- 攻击者落地后先关掉记录与防护再拉载荷。运维也会清历史、清日志，但通常在安装**之后**收尾（镜像构建脚本最后 `history -c`、
  装完 `journalctl --vacuum` 腾磁盘），顺序反过来不命中。
- 防火墙 / SELinux / EDR 停用之后不接下载执行而接 `/dev/shm` 执行：关 SELinux、停 firewalld 后 `curl | sh` 是 k3s 等安装文档的原样步骤。
- `unset HISTFILE`、`history -c` 是 shell 内建命令，交互式会话里不产生进程事件；只有经 `sh -c` / `bash -c` 执行时可见
  （webshell、漏洞利用载荷常见），交互式攻击者的这一步会漏。
- Windows：先加 Defender 排除项再用 certutil 等下载。排除项来自 30 秒快照，若下载紧跟在排除项之后（30 秒内），
  快照上报时间可能晚于下载、顺序反转而漏报（回放语料以「已知缺口」用例显式记录）。
- 已知误报：清理 syslog / journal 后立刻用 `curl | sh` 装软件（如磁盘满了先腾空间再装 agent）；
  排障时 `auditctl -D` 后装软件；备份或数据库软件安装器先加排除项、再用 certutil / bitsadmin 拉组件；
  从 `/dev/shm` 运行程序的容器 / IPC 框架恰好遇到停防火墙。

## 候选量

信号规则可能高频，只有被时序规则引用时才落候选。生产 7 天回测（同上）全部 22 条规则的候选 2339 条，其中三条信号 1854 条
（curl / wget 957、成功登录 699、读 stdin 的 shell 198）；单实体 15 分钟窗口峰值资产维度 104 条（pve2，敏感文件变更，非信号）、
账号维度 122 条（root，成功登录信号加侦察）。线上回查前后各一个最大窗口，最坏约翻倍，离 10000 的 `candidate_limit` 还有两个数量级，
回测期内没有任何覆盖缺口。

## 当前格式做不到、留待引擎扩展的链路

以下方向需要时序引擎新能力，本目录没有用变通写法硬凑：

- **新进程首次出现 → 外联新目的**：首次出现是 UEBA 异步合成的 `xdr:new-process` 告警（学习期内不报，30 秒一批），
  不是 Sigma 基础规则，不进时序候选；外联「新目的」同样没有单事件基础规则。需要让时序规则引用合成信号并定义学习期内的语义。
- **单步「任一基础规则」**：现在每一步只能引用一条基础规则，「读取凭据 →（打包 | 上传 | 外联）」只能拆成多条规则。
- **按不同取值计数**（如 2 分钟内至少 4 种不同侦察命令）：现在只能数事件次数。
