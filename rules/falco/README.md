# Falco 移植规则

移植自 [falcosecurity/rules](https://github.com/falcosecurity/rules)（`e7b066b`，2026-10-22）里 `maturity_stable` 的规则，
按 [Apache License 2.0](LICENSE) 授权。Falco 规则写在系统调用事件上，本平台的引擎不认它的条件语言，
所以这里是逐条改写成 Sigma 格式，不是原样引入；每条规则的 `description` 写明对应的 Falco 规则名和与原规则的差异。

## 已移植

只取本平台现有采集（进程路径、命令行、父进程、容器归属）能判断的部分：

| 规则 | Falco 原规则 | 与原规则的差异 |
|---|---|---|
| `netcat_rce_in_container` | Netcat Remote Code Execution in Container | 无 |
| `shell_script_from_dev_shm` | Execution from /dev/shm | 只取 shell 执行 /dev/shm 下脚本的部分；可执行文件本身在 /dev/shm 的已由 SigmaHQ 规则覆盖；按工作目录判断的分支没有数据源 |
| `find_aws_credentials` | Find AWS Credentials | 无 |
| `remove_bulk_data` | Remove Bulk Data from Disk | 无 |
| `service_spawns_shell` | Run shell untrusted | 只看直接父进程（原规则看全部祖先）；数据库拉起 shell 已由 `lnx_database_spawns_shell` 覆盖 |
| `debugfs_in_container` | Debugfs Launched in Privileged Container | 容器信息没有特权标记，对所有容器生效 |
| `link_over_sensitive_files` | Create Symlink / Hardlink Over Sensitive Files | 按 `ln` 命令行判断，原规则看系统调用参数 |
| `release_agent_container_escape` | Detect release_agent File Container Escapes | 按容器内命令行提到 release_agent 判断，原规则看写打开与进程能力；容器内读取它也会命中 |

## 待采集补齐后移植

这些要先给 agent 加数据源：`Terminal shell in container` 与 `System user interactive`（进程的 tty、用户）、
`Redirect STDOUT/STDIN to Network Connection in Container`（dup 系统调用）、`Drop and execute new binary in container`
（可执行文件是否来自 overlay 上层）、`PTRACE attached to process` / `PTRACE anti-debug attempt`、
`Packet socket created in container`、`Fileless execution via memfd_create`（经 fexecve 执行时记下的路径是 `/dev/fd/N`，
runc、systemd-executor 每天成千上万次这样执行，要 agent 解析 `/proc/<pid>/exe` 的真实目标才分得出 memfd 载荷）、`Read sensitive file untrusted` 等文件读取类。

## 更新

上游规则变化时对照改写，跑 `sigmacheck --strict`、`go test ./internal/sigma`（正反例在 `validation/exact-rule-cases.json`），
再用 `cmd/backtest` 在生产只读副本上回测。
