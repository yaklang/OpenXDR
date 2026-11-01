# 2026-10-30 生产业务数据修复

## 已实施的主机配置修复

- **UOS 采集**：旧服务 `LimitMEMLOCK=65536` 导致 eBPF map 创建失败。
  增加 `/etc/systemd/system/openxdr-agent.service.d/memlock.conf`，将上限设为 134217728 后重启 Agent。
  控制台状态确认 process/network/DNS 均 active；修复后真实网络事件 3 条、DNS 2 条均含 process GUID。
  安装脚本与 pilot service 同步补上该上限，避免新安装重现；已有安装需按安装文档更新 service。
  4.19 内核不支持当前 fanotify 名字报告，文件监控仍为 inotify/degraded，未伪装成完整采集。
- **gym SSH**：独立 nftables 表 `inet openxdr_ssh_guard`，仅允许管理网段 `10.1.1.0/24`、
  `tailscale0`、本机及已建立连接；阻断其他来源的新 SSH 连接。
  `/etc/systemd/system/openxdr-ssh-guard.service` 持久加载 `/etc/nftables.d/openxdr-ssh-guard.nft`，
  没有改 Docker 管理的表。独立新管理连接成功；临时 netns 内的非管理来源连接超时且命中 DROP 计数。
  测试 netns/veth 已清理，验证后取消三分钟自动回滚 timer。回退可停止并禁用该独立 service。
- **Registry 写入面**：保留 SoulRaid 现有匿名拉取依赖，启用 `storage.maintenance.readonly.enabled=true`。
  配置文件 `/etc/openxdr-registry-readonly.yml` 只读挂载，原数据目录 `/opt/registry` 不变。
  首次环境变量方式因当前 Registry 版本解析不兼容失败，自动恢复旧容器；改用配置文件，先隔离容器验证，再应用生产。
  实测 `/v2/` 为 200、上传初始化为 405；192 依赖端读取 worker manifest 为 200。
  测试容器及其匿名 volume 已删除。旧容器 `registry-pre-openxdr-20261030` 停止且 restart=no，保留回退依据；
  原容器元数据/配置备份位于该主机 `/root/registry-pre-openxdr-20261030.*`（仅 root 可读）。
  **匿名读取和访问来源隔离仍未完成，不将只读化描述成完整鉴权。**

## 待办数据修正

通过平台 API 将 `agent-unbound`、`ssh-bruteforce-public` 两项标记 resolved，写明实机验证证据，留下 `finding_status` 审计。
node2 核对的是原待办绑定的同一个 asset_id，并非仅比较同名资产。

Registry 待办仍 open，标题/详情更新为已禁写但匿名读取边界待收口；Windows 邻居待办仍 open，
删除“node1/node2 未纳管”的过期表述，保留其他未逐个复核的地址问题。
这两次证据更正使用单个数据库事务更新并写 `finding_evidence_update`，保留前后标题/详情，
没有修改其余待办，也没有把不完整证据当成已修复。Windows 项没有刷新 last_seen 冒充重新扫描全部邻居。

## 总览统计代码修复

原总览把 24 小时原始事件、24 小时去重告警、全部未结案待复核存量当作同一时间范围计算降噪百分比。
现在分别标出时间范围，移除不成立的百分比，并明确原始事件包含正常活动与测试采集，不等于攻击次数。
中英文文案同步。没有因客户端自报测试标记而跳过检测或隐藏原始事件，也没有增加大表 JSON 全扫描计数。

## 验证与边界

- 安装脚本 `sh -n`、enroll PostgreSQL 集成测试通过；Web 类型检查、生产构建与 lint 通过（保留既有 Fast Refresh 警告）。
- UOS 从启动日志、采集能力和实际归属事件三层验证；SSH 包含管理连接正例和非管理来源反例；Registry 包含依赖读取与写入拒绝。
- 30 个待人工复核事件并不等于研判卡死，不因“清零”而批量结案；两条重研判还涉及冷却窗口。
- 历史模型失败记录保留，不能靠删除记录或修改 verdict 假装成功；仍需分别处理确有重现的模型/超时问题。
- 400/s 持续入库、独立备份、其他未复核主机风险等原路线图事项不因本轮修复而宣告完成。

补充复核：最近 24 小时的 6 次失败研判均已有后续成功结论，当前无首次研判积压。
留存业务日志显示最近一组为上游 LLM HTTP 503 和一次读取超时，已有退避重试恢复；
这批记录不能认定为当前结果解析器故障，因此没有无证据地修改解析逻辑或缩减调查范围。

## Registry 访问来源收口（后续已完成）

用户授权按最优方案处理后，进一步核实 193 的 Dispatcher 正在运行，且配置同样引用该仓库。
最终采用**已确认消费者的网络白名单 + 仓库只读**，保留现有客户端兼容性；没有冒充已配置应用层认证。

- 允许 189 本机、192 和 193；其他来源访问宿主接口的 TCP 5000 被拒绝，IPv6 没有隐式放行。
- 独立 `inet openxdr_registry_guard` 表在 Docker DNAT 前检查原始目的地址和端口，未改 Docker 自管规则。
  现有 Docker raw 表另有禁止外部接口直达 Registry 容器 IP 的规则；本次未删除或放宽它。
- 配置对应 [registry-access.nft](../deploy/operations/registry-access.nft) 与
  [registry-access.service](../deploy/operations/registry-access.service)，是本环境专用配置，不自动应用到其他安装。
  实机路径为 `/etc/nftables.d/openxdr-registry-guard.nft` 和
  `/etc/systemd/system/openxdr-registry-guard.service`，服务 active/enabled。
- 192、193 的 `/v2/`、worker manifest 均为 200；进一步读取 linux/amd64 镜像层首 1024 字节，均返回 206。
  没有拉取或执行整个镜像。上传初始化仍为 405。
- 197 非授权内网来源连接超时；临时网络命名空间中的非授权 IPv4/IPv6 同样被拒绝，DROP 计数增长。
  测试 netns/veth 和三分钟回滚 timer 已清理；未改 SSH 或其他业务端口。
- 首次 Python urllib 验证因环境代理不支持 Docker 使用的 CIDR 免代理规则而返回代理 502；
  显式直连复测成功。两个 Docker daemon 的 NO_PROXY 已含 10.0.0.0/8，无需重启或修改消费者。
- Registry 待办通过平台 API resolved，说明保留匿名只读的允许源信任边界，写入 `finding_status` 审计。
  后续新增消费者必须先确认用途，再更新白名单并验证读取/拒绝；不能整段开放回退。

应急回退：停止并禁用 `openxdr-registry-guard.service` 仅撤销本次独立表，会重新暴露匿名读取，
不得把它当常态；仓库只读配置保持生效。若出现合法消费者遗漏，优先补充经核实的精确地址。
