# 队列、集群与可观测性

OpenXDR 支持两种模式：未设置 `NATS_URL` 时，事件信封在进程内直接交给处理器；
设置后，gateway 将事件持久写入 NATS JetStream，多台 server 以同一 durable
consumer group 消费。两种模式共用 `ingest.Processor`，检测语义不会因部署形态改变。

## 一致性语义

- gateway 为 agent、sensor、syslog 事件计算稳定 UUID；JetStream 重投和来源重试
  不会产生第二条数据库事件。
- 按 `asset_id` 分片；没有资产时使用 agent ID、源 IP 或 syslog origin。
  每个分片 `MaxAckPending=1`，同一分片处理完成后才投下一条。
- 投递是 **at-least-once**。数据库 `events.id` 主键实现事件幂等，不伪称
  exactly-once。
- 告警去重状态在 PostgreSQL `alert_dedup_state`，事务 advisory lock 保证多个
  worker 对同一指纹串行更新；server 重启或 agent 重连不再清空窗口。
- 处理成功才 ACK；失败 NAK 并延迟重投。JetStream 使用 WorkQueue retention，
  已 ACK 消息删除，长期证据源仍是 PostgreSQL。
- correlate、UEBA、triage、notify、janitor 用 PostgreSQL advisory lease 单活运行；
  租约连接断开时取消任务，其他节点接管。
- agent 指令通过 NATS request/reply 路由到持有其 gRPC 长连接的 server；
  在线判断同样跨节点，响应结果仍落共享数据库审计。

## 选主瞬断

JetStream 流换 leader 的一两秒里，server 内部有界重试（首次 100ms、翻倍到 1s 封顶、
从首次尝试起总计约 5 秒，`internal/natsretry`），不把错误抛给 agent/sensor 让上报连接断开，
也不把指令立刻判成 unknown。只重试能证明对端**肯定没收下**的错误：

| 路径 | 重试的错误 | 依据 |
|---|---|---|
| 事件发布 | no responders（`ErrNoStreamResponse`） | 流 leader 当选后才订阅主题，选主空档没有订阅者，NATS 直接回 no responders，消息没进任何副本 |
| 事件发布 | 503 `raft: not leader`、10009 集群非 leader | 旧 leader 已卸任，raft 提案被拒，没有写入日志 |
| 指令投递 | no responders | 服务端查不到订阅才回这个状态，没有交给任何节点（agent 重连换节点的空档） |
| 指令投递 | 持有订阅的节点回「agent 指令连接已失效」 | 同一队列组只投一个成员，它没把指令放进通道（旧连接还没退订） |

其它错误照原样处理：事件发布超时等直接报错（即便重发，Nats-Msg-Id 去重与事件稳定 ID 主键
也保证不重复）；指令投递超时、连接中断等**可能已下发**的失败不重试，记 unknown、禁止自动重发；
「队列已满」等确定的拒绝重试改变不了结果，维持原口径。重试超限后返回最后一次错误，口径与重试前相同。

## 三节点启动

```bash
export POSTGRES_PASSWORD='...'
export ADMIN_PASSWORD='...'
export GRAFANA_ADMIN_PASSWORD='...'
docker compose -f docker-compose.cluster.yml up -d --build
```

组件：3×NATS JetStream、3×server、HAProxy、web、Prometheus、Grafana、
NATS exporter。入口：Web `:5173`、REST `:8080`、gRPC `:8081`、
Prometheus `:9090`、Grafana `:3000`。示例 Compose 的 PostgreSQL 是单节点，
用于本机验收；生产必须把 `DATABASE_URL` 指向 Patroni、CloudNativePG 或云厂商
高可用 PostgreSQL，不能把示例数据库冒充完整 HA。

syslog 示例只在 `server1:5514` 暴露 UDP/TCP。生产应在外部四层负载均衡上配置
UDP/TCP 健康检查，或者部署独立 syslog gateway；HAProxy 只承载 HTTP/gRPC。

## 健康与指标

- `GET /healthz`：进程存活。
- `GET /readyz`：PostgreSQL 可用、NATS 已连接且全部分片 consumer 有效。
- `GET /metrics`：Prometheus 指标；集群 HAProxy 明确拒绝外部访问，Prometheus
  直接抓取各 server。

关键指标：

| 指标 | 含义 |
|---|---|
| `openxdr_events_published_total` | gateway 成功发布事件 |
| `openxdr_events_processed_total{duplicate}` | 处理完成与幂等丢弃数 |
| `openxdr_queue_pending_messages{shard}` | 每个 durable consumer 的积压+待 ACK |
| `openxdr_queue_replicas_unhealthy` | 事件流不同步或离线的副本数；取不到流信息（没有 leader）时等于副本总数 |
| `openxdr_event_processing_seconds` | 单事件处理耗时直方图（只算这条事件自己的处理，不含等待同批其他事件与提交） |
| `openxdr_event_batch_seconds` / `openxdr_event_batch_size` | 整批入库事务耗时（含取锁与提交）与每批事件数 |
| `openxdr_pipeline_failures_total{stage}` | 发布、解码或处理失败 |
| `openxdr_alerts_created_total` | 新建告警数 |

Prometheus 预置节点离线、队列积压、副本不同步、处理失败和 P95 延迟规则（规则只负责判定，
模板没有配 Alertmanager，要把这些告警接到外部监控才有人收到）；Grafana 预置
“OpenXDR 集群处理链”面板。NATS 自身的 JetStream、存储、连接和路由状态由
`prometheus-nats-exporter` 提供。

## 故障验收

1. 连续写入事件时停止一台 server：HAProxy 应摘除节点，队列消息由其余节点消费。
2. 在 worker 事务提交前终止进程：消息重投，但同一稳定 ID 最终只落一条事件。
3. 重启 agent 或 server：同一告警指纹仍在原窗口累计 count。
4. 停止一台 NATS：三副本 stream 仍可发布消费；恢复后副本重新同步。
5. 停止后台任务 leader：日志应在其他节点出现“取得集群任务租约”。
6. agent 连到 server A，从 server B 的 API 下发 dry-run：指令必须经 NATS 路由成功。

任何一项失败都不能把集群标记为可用。

## 未处理事件的保留与升级

事件 stream 使用 `DiscardNew`：达到容量上限后拒绝发布，由新版 Agent 保留本地批次并重试；已确认的旧消息不为新消息腾空间。
`QUEUE_MAX_AGE_HOURS` 默认且必须为 0，未处理事件不自动过期。旧配置显式设为 168 等非零值时，新 server 拒绝启动并报告该变量。
队列容量必须为正；在线缩容会被拒绝，防止读取状态与更新配置之间有新发布而误删积压。缩容须在停止发布、核对并排空积压后由管理员维护。

升级时先更新全部 gateway/worker 的环境配置，再完成 server 版本切换；不能把新旧版本长期混跑，否则旧版可能在重启时写回原来的淘汰策略。stream 配置迁移不清空积压。
已被旧策略淘汰或过期的消息无法追回。本保证不覆盖操作员手工删除、磁盘损坏、旧采集端没有补传缓存等情况。

单机、三节点 Compose 和 HA 的 NATS 模板均设置 `sync_interval: 1s`：Agent 收到确认就删本地缓存，NATS 默认 2 分钟才落一次盘，
副本所在机器同时断电会丢掉这段已确认的事件；每秒落盘把这个窗口缩到 1 秒。没有用 `always`（每条确认前落盘）：
2026-10-19 在生产 HA 节点（PVE 虚拟盘，与 PostgreSQL 同盘）上用 1 KB 消息、逐条同步发布实测：

| 配置 | 1 并发 | 4 并发 | 16 并发 |
|---|---|---|---|
| 默认（2 分钟） | 3217 条/秒，p99 0.5 ms | 8515 条/秒 | 21075 条/秒，p99 1.6 ms |
| `always` | 959 条/秒，p99 2.3 ms | 1311 条/秒 | 1537 条/秒，p99 17 ms |
| `1s` | 3111 条/秒，p99 0.4 ms | 9326 条/秒 | 24931 条/秒，p99 1.3 ms |

生产平均每秒 16 条、单秒突发约 1700 条；`always` 让突发排空从约 0.5 秒拉长到数秒，还会与同盘 PostgreSQL 争抢 fsync，
`1s` 几乎没有代价。使用外部 NATS 时必须自行设置。
同时设置 `max_payload: 4MB`，覆盖新版 Agent 有界事件大小；外部 NATS 若仍采用默认 1 MiB 上限，大事件可能反复拒收。
此配置会增加磁盘同步开销，应以实际硬件测量吞吐，不能沿用默认异步同步策略下的容量数字。
[NATS 官方持久性说明](https://github.com/nats-io/nats.docs/blob/master/nats-concepts/jetstream/README.md)。
