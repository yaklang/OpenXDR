# 软件漏洞（`server/internal/vuln`）

回答「这台主机有哪些已知漏洞、升级能修掉哪些、暴露在外的服务有没有」。

## 数据从哪来

- **软件清单**：agent 每 30 分钟查询一次本机软件包数据库；dpkg 主机运行 `dpkg-query`，上报已装（状态 `ii`）的二进制包、版本、源码包与源码版本，
  以及 `/etc/os-release` 的发行版与版本号（OCSF 5020，`agent/src/collector/software.rs`）。清单变了才报，最长 24 小时补报一次。
  监听端口清单里，每个服务进程顺带标上它的可执行文件属于哪个包（`dpkg -S` 或 `rpm -qf`，按路径缓存）。
  server 由资产图谱的批处理物化到 `assets.software`（`assetmap/inventory.go` 的 `software`，字段逐个清洗）。
- **RPM 清单**：没有 dpkg-query 时使用 `rpm -qa`，保留二进制包完整 epoch:version-release；源码名称与版本来自 SOURCERPM，不推测源码 epoch。没有源码信息时两项留空；gpg-pubkey 密钥条目不算软件包。健康路径显示 rpm，UOS 的清单可入库，但尚无对应漏洞公告与 RPM 版本比较支持。
- **漏洞库**：OSV 按生态打包的公告（`<VULN_OSV_URL>/Debian/all.zip`、`Ubuntu/all.zip`），每 `VULN_SYNC_HOURS`（默认 24）
  小时同步一次，只同步资产实际用到的生态（Debian:13、Ubuntu:22.04……），同一生态在一个事务里整批替换，
  失败保留旧数据并在资产页提示，一小时后重试（`sync.go`，状态存 settings 表 `vuln_sync`）。下载按 HTTP Range 每段 8 MB、
每段限时 90 秒，超时换新连接重下这一段（最多 4 次）：生产实测同一线路上单个连接时快时慢，一条连接走到底会被慢的拖死。撤回的公告跳过；Ubuntu 只认普通仓库，
  Pro / FIPS 是另一套包。**离线部署**把 zip 放进 `VULN_DIR`（文件名 `Debian.zip`、`Ubuntu.zip`），不再联网。

## 怎么比

- 发行版的公告按**源码包**发布，所以用源码包名与源码版本比（同一个源码包编出的多个二进制包一起算）。
- 版本比较按 dpkg 规则（`version.go` 的 `CompareDeb`：epoch、`~` 最小、数字段按数值），
  与 `dpkg --compare-versions` 在 pve2 真实清单 × OSV 版本的 3000 对上逐一一致。
- 已装版本落在某个受影响区间（`introduced` ≤ 版本 < `fixed`）即命中；有 `fixed` 的归「可升级修复」，
  升到 `fixedIn`（可修漏洞里最高的修复版本）就能一次修掉；没有 `fixed` 的归「暂无修复」（发行版还没出补丁，多数被标为低危或不重要）。
- 分数由 CVSS 3.x 向量算出（`cvss.go`），没有 v3 向量记 0；Debian 自己的紧急度几乎都是「未评定」，不用于排序。
- 「对外服务」：某个监听在非回环地址上的服务进程属于这个源码包，排在最前，攻击面页面对应服务那一行标出漏洞数与最高分。

匹配在查询时算（单台主机约 15 毫秒），不落表：漏洞库一更新，结果立刻跟着变。

## 已知限制

- 漏洞匹配只支持 dpkg 系（Debian、Ubuntu）。RPM 支持软件清单采集，但不参与 dpkg 版本比较；Alpine 等没有 dpkg/RPM 的主机仍标记软件采集不可用。
- 看的是宿主机自己的包；容器、LXC 里的软件不在清单里。
- Proxmox 这类在 Debian 之上自带同名包的发行版，自带包的版本号与 Debian 不同（如 `-pve`），比较结果只作参考。
- Windows 不采集软件清单（缺少可对的漏洞生态）。
