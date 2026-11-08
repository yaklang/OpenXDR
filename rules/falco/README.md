# Falco 移植规则

移植自 [falcosecurity/rules](https://github.com/falcosecurity/rules)（`e7b066b`，2026-10-22）里 `maturity_stable` 的规则，
按 [Apache License 2.0](LICENSE) 授权。Falco 规则写在系统调用事件上，本平台的引擎不认它的条件语言，
所以这里是逐条改写成 Sigma 格式，不是原样引入；每条规则的 `description` 写明对应的 Falco 规则名和与原规则的差异。

## 已移植

只取本平台采集能判断的部分（进程路径、命令行、父进程、容器归属，以及 agent 补的 tty、真实可执行文件、overlay 来源、stdio 套接字）：

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
| `terminal_shell_in_container` | Terminal shell in container | 依赖 agent 采集的 `process.tty`；父进程按 container_entrypoint 判断 |
| `system_user_interactive` | System user interactive | 按进程有控制终端判断交互，原规则看祖先是否 sshd / login |
| `fileless_memfd_exec` | Fileless execution via memfd_create | agent 把 fd 执行路径解析成 `/memfd:…`；除 runc 外还排除 PVE `pct exec` 的 lxc-attach（生产实测只有这两类） |
| `drop_and_execute_in_container` | Drop and execute new binary in container | 依赖 `process.file.upper_layer`；排除 go test 编出的 `/tmp/go-build*/` 测试程序（生产实测） |
| `redirect_stdio_to_network_in_container` | Redirect STDOUT/STDIN to Network Connection in Container | 依赖 agent 的 `stdio_socket` 事件；排除容器里 sshd 接受连接（生产实测 LXC 容器） |

## 尚未移植

`PTRACE attached to process` / `PTRACE anti-debug attempt`、`Packet socket created in container` 要再给 agent 加系统调用钩子；
`Read sensitive file untrusted` 等文件读取类要文件打开事件。

新采集上线后的规则，用上线以来的生产数据回测：2026-11-08 起 12 小时、约 2600 条带新字段的事件，排除上面实测到的正常行为后命中为零。

## 更新

上游规则变化时对照改写，跑 `sigmacheck --strict`、`go test ./internal/sigma`（正反例在 `validation/exact-rule-cases.json`），
再用 `cmd/backtest` 在生产只读副本上回测。
