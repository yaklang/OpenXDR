# 跨宿主机高可用部署

该部署面向两个 PVE 故障域：`node1=10.1.1.198`、`node2=10.1.1.197`，入口 VIP
为 `10.1.1.199`。独立 witness 运行 etcd DCS 和第三个 JetStream 节点，只通过
mTLS 接受连接。任一 PVE 整机失联后，剩余 PostgreSQL 副本可晋升，JetStream
仍保有 2/3 quorum，VIP 漂移到存活节点。

组件边界：

- Patroni 管理两个 PostgreSQL 16 数据节点，同步复制降低自动切换的数据损失窗口；
- 每个应用节点的 HAProxy 在 `127.0.0.1:15432` 只转发 Patroni primary；
- 三节点 NATS JetStream 使用 mTLS route，应用仅访问本机 `127.0.0.1:4222`；
- Keepalived 以 `/readyz` 为依据持有 `10.1.1.199`；
- 两个 Prometheus 各自抓取两端 OpenXDR、Patroni 和本机 NATS exporter。

## 初始化

证书与 `.env` 不能提交。先生成 HA PKI，再分别渲染节点配置：

```bash
deploy/ha/generate-certs.sh runtime/pki <witness-address>
export OPENXDR_PASSWORD=... POSTGRES_PASSWORD=... REPLICATION_PASSWORD=...
export NATS_ROUTE_PASSWORD=... VRRP_PASSWORD=... ADMIN_PASSWORD=...
export GRAFANA_ADMIN_PASSWORD=...                 # VRRP 密码最多 8 字符
deploy/ha/render.py --node node1 --witness <witness-address>
sudo deploy/ha/prepare-runtime.sh runtime
docker compose -f docker-compose.ha-node.yml config --quiet
docker compose -f docker-compose.ha-node.yml up -d --build
```

`OPENXDR_PASSWORD` 与 `NATS_ROUTE_PASSWORD` 只允许 URL-safe 字符
`A-Z a-z 0-9 . _ ~ -`；`VRRP_PASSWORD` 只允许 1-8 位字母或数字。渲染器会拒绝
不安全值，避免 YAML、连接 URL 或 Keepalived 静默误解析。

节点 `runtime/secrets` 只放 HA CA、对应 NATS 证书和 etcd client 证书；
`runtime/app-certs` 放 agent gRPC 使用的原有 CA 及包含 VIP SAN 的 server 证书。
Witness 使用 [witness-compose.yml](witness-compose.yml) 和渲染后的
`witness-nats.conf`，只接收 `2379/tcp` 与 `6222/tcp`。如果 witness 上已有不能
重启的 Docker 工作负载，可安装固定版本的 etcd、NATS 二进制，并使用
[`systemd/`](systemd/) 中的受限服务单元；部署前按实际地址调整 etcd 的
`--advertise-client-urls`。公网端口即使有 mTLS，也应在上游防火墙限制来源地址。

`runtime/` 已被 Git 忽略。CA 私钥不能留在应用 VM；签发完成后应复制到至少两个
受控的离线备份位置，再从节点删除。应用节点只保留运行所需的叶子证书。

## 升级

用 [`release.sh`](release.sh) 从当前提交滚动发布：

```bash
SSH="ssh -F <ssh 配置>" GOPROXY=https://goproxy.cn,direct deploy/ha/release.sh <节点1> <节点2>
```

脚本在本地构建 server / web 镜像（标签为提交短哈希），连同 `rules/`、`tasks/` 推到节点，
先升不持有 VIP 的节点，`readyz` 通过后再升另一个；任一步失败立即停下。
每个节点切换前把旧镜像标成 `pre-<标签>`，回滚方式见脚本头部注释。
agent 不走这个脚本：把新版本放进节点的 `dist/` 目录，agent 下次注册时自动升级——agent 重启、事件上报中断，
或 server 重启导致指令通道断开（重连前会重报注册）都会触发；server 端按文件大小与修改时间重算哈希，不用重启 server。

独立 DYGK 引擎的单节点配置、升级和恢复边界见 [dygk.md](dygk.md)。节点存在
`docker-compose.dygk.yml` 时，发布脚本自动合并它以保留 server 控制通道；不会自动
部署或升级引擎镜像，也不会把单实例引擎变成 HA。

时序规则（`temporal-rules/`）按内容哈希发布成节点上的不可变版本目录 `temporal-rules/v-<哈希>/`（带 `SHA256SUMS`），
再原子切换 `temporal-rules/current` 链接，保留最近 5 个版本；compose 只读挂载整个 `temporal-rules/` 到容器 `/temporal-rules`。
开启时在节点 `.env` 设 `TEMPORAL_RULES_PATH=/temporal-rules/current`，server 每 `RULES_RELOAD_SECONDS` 整批重载；
不设则保持单事件检测。回滚规则：把 `current` 链接切回旧版本目录（`ln -sfn v-<旧> current.tmp && mv -T current.tmp current`）。

## 业务日志

[持久日志与集中查询](logs/README.md) 使用 journald 和受限 SSH 归档，容器重建后仍可查询旧日志。
节点存在 `docker-compose.logs.yml` 时，滚动发布自动合并日志驱动配置。

Patroni 探测使用 `HEAD /primary`，保留主库 200、从库 503 判定，避免 GET 正文在探测端提前
关闭连接时产生重复的 ConnectionResetError。部署时先校验配置，再平滑重载 HAProxy。

## 备份与恢复

节点外逻辑备份、隔离恢复验收和容量处理顺序见 [backup-recovery.md](backup-recovery.md)。
同步副本不能替代独立备份，切换演练也不能替代恢复验收。

## 验收

1. `patronictl list` 必须是一主一同步副本；
2. JetStream stream 必须 `replicas=3` 且三个 peer current；
3. `curl http://10.1.1.199:8080/readyz` 与实际 agent 上报均成功；
4. 依次停止 node1、node2（一次只停一个），确认 VIP 漂移、PostgreSQL 晋升、事件持续增长；
5. 恢复节点后确认 Patroni 自动追平、JetStream replica current、Prometheus targets 全绿。

本环境在 2026-08-10 完成两轮整机切换：关闭 node2 后 node1 晋升到 timeline 5；
关闭 node1 后 node2 晋升到 timeline 6。两轮均保持 JetStream quorum 且事件计数
持续增长。Keepalived 的实测入口恢复窗口约 30 秒，因此客户端必须重连，不能把它
描述为零中断。

这套架构容忍一个 PVE 故障，不容忍 PVE 与独立 witness 同时故障。Witness 不保存
PostgreSQL 业务数据，但第三个 JetStream replica 会保存加密传输后的事件队列副本。


### 事件队列 Leader 回迁

独立 witness 也是 JetStream 的数据副本，可能当选事件流或消费者 Leader。
如果它位于异地，每条同步发布、逐条消费确认都可能叠加 WAN 往返延迟。
不要为提高吞吐减少副本、清空持久队列，或直接提高 `MaxAckPending` 破坏同资产处理顺序。

从两个本地节点都恢复健康的状态开始，用 `server/cmd/queueleader` 预览回迁。
在仓库的 `server/` 下构建，然后把二进制放到能通过本机客户端端口连接 NATS 的节点：

```sh
go build -o openxdr-queueleader ./cmd/queueleader
# 在 NATS 节点上执行；默认不做变更
./openxdr-queueleader -from openxdr-witness -to openxdr-node2
# 复核计划后执行
./openxdr-queueleader -from openxdr-witness -to openxdr-node2 -apply
```

工具只迁移指定来源持有的事件流和 ingest 消费者 Leader，先校验全部目标副本
已同步且在线，再逐个迁移、确认新的 Leader；请求超时不自动重发。
这不会改变副本数量、消息、消费者游标或保留策略，也不会禁止故障后的重新选举。
目标节点故障后应先恢复多数派，再决定是否回迁；不要把本工具做成无条件重选循环。

验收同时检查：真实 Leader、Agent 本地缓存、服务端 pending、消费速率、最新入库事件时间、
采集丢弃计数。迁移后端侧集中补传可能暂时抬高服务端 pending，不能只据这一项判定回退。
应用每 10 秒先通过 JetStream API 查询流副本健康，再查询各分片待办；整轮共用 5 秒时限。
流查询失败按配置的全部副本不健康计；分片查询失败或本轮超时则保留上次待办值，不能将其视为实时零积压。
`openxdr_queue_sample_timestamp_seconds{shard}` 记录各分片最近一次成功采样时间（0 表示尚未成功）；
用 `time() - openxdr_queue_sample_timestamp_seconds` 检查指标年龄。超时后下一轮从未采样的分片继续，避免后面的分片长期得不到更新。

HTTP `/jsz` 的本地副本视图可能不同于 Leader 状态，排障需结合 JetStream API 与实际 Leader
的监控输出，不能直接用某个从节点的本地视图判定整个集群失去同步。


### 事件批消息的两阶段启用与回退

`QUEUE_BATCH_SIZE` 默认 `1`，发布旧的单事件格式；消费者兼容单事件和批消息。
批消息只包含相邻的同资产事件，最多 64 条、256 KiB（按编码后大小拆分），
每分片仍保持 `MaxAckPending=1`，一个事务提交整批事件与检测派生状态。
Agent 在满批、原有 2 秒定时刷新或上报流结束时发布；只有消息持久化成功后才返回上报 ACK。

1. 保持 `QUEUE_BATCH_SIZE=1`，按滚动发布流程升级所有接入/消费节点，核对运行镜像并验收就绪状态。
2. 确认旧消费者全部退出后，在所有 server 容器配置 `QUEUE_BATCH_SIZE=64`，再滚动重建服务端。
3. 验收实际事件入库速度、最新事件延迟、队列积压和 Agent 缓存。队列指标计数的是消息，启用后一条消息可能包含多个事件，不能直接拿消息消费速率当事件吞吐。

需要停止批量发送时，将配置改回 `1`，保留新消费者即可继续处理已有批消息。
若需要回退到不认识批消息的旧服务端，必须先让所有发布节点恢复 `1`，
再等待所有分片 `num_pending=0` 且 `num_ack_pending=0`，确认没有在途批消息后才允许回退。
不要直接回滚旧镜像：旧消费者会把批消息当成非法信封终止处理。
不要删除或重建 stream/consumer，不要改变分片数或通过缩减副本提速。

### 生产数据库缓存配置记录

2026-10-30 生产通过 Patroni DCS 将 `postgresql.parameters.shared_buffers` 调为 `1GB`，
两节点已滚动生效；当时 node1 为主库、node2 为同步备库（角色随故障切换变化，操作前重新查 `patronictl list`）。
此值针对已核实的生产内存余量，不作为所有安装环境的默认值。仅修改 `bootstrap.dcs` 不会更新现有集群。
容量数据及未完成项见 [本次入库验证](../../validation/ingest/2026-10-30-capacity/README.md)。

更改缓存应先核实 VM balloon 后实际可用内存、容器限制和同步副本状态，再以 `patronictl edit-config --pg`
修改对应参数；共享缓存需要 PostgreSQL 重启。先重启备库并确认追平，再做受控主库切换。
降级过程可能已重启原主库并应用参数，必须查询实际值和 `pending_restart`，避免重复重启。
若需回退，本次旧值是 `128MB`，通过同样的 DCS 与逐节点生效流程恢复，不能只改本地配置文件。
切换后同步更新运维查询使用的主库地址，确认队列恢复、复制状态和真实业务；不要把就绪检查当完整业务验收。
