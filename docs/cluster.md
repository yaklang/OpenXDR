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
| `openxdr_event_processing_seconds` | 单事件处理耗时直方图 |
| `openxdr_pipeline_failures_total{stage}` | 发布、解码或处理失败 |
| `openxdr_alerts_created_total` | 新建告警数 |

Prometheus 预置节点离线、队列积压、处理失败和 P95 延迟规则；Grafana 预置
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
