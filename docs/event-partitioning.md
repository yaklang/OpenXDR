# events 按天分区

生产 events 约 78 GB、7800 万行，保留 30 天。原来的保留期清理是逐行 `DELETE`
（每批 1 万行，`server/internal/janitor/janitor.go`），删出大量死元组，靠 autovacuum 追；
按时间查询要走全表的 `ts` 索引。本文是把 events 改成 PostgreSQL 原生范围分区（按 `ts`）的
设计、实现位置与生产迁移步骤。

代码：`server/internal/eventpart`（建表、ent 共存、预建、退役、迁移），
`server/cmd/eventpartition`（在线迁移命令），`server/internal/janitor`（保留期）。

## 1. 分区粒度：按 UTC 日

| | 按天 | 按周 |
|---|---|---|
| 单分区大小 | ~2.6 GB / 260 万行 | ~18 GB / 1800 万行 |
| 保留期精度 | 多留不到 1 天 | 多留最多 7 天（+23% 存储，约 18 GB） |
| 在用分区数 | 30 日分区 + 8 天预建 + 每月 1 个归档 | 5 + 2 + 归档 |
| 退役时复制证据 | 每次扫 2.6 GB | 每次扫 18 GB，`SHARE` 锁持有更久 |
| 按 id 查（无 ts）的代价 | 探 ~40–50 个分区索引 | 探 ~8 个 |

选按天：保留期是按天配置的（`RETENTION_DAYS`），按周会白存近一周数据；日分区 2–3 GB，
建索引、VACUUM、退役复制都在分钟以内；AI 查询与界面检索的时间窗多为小时到几天，日分区裁剪更细。
代价是不带 ts 的按 id 查询要探所有分区（见第 8 节），50 个上下的分区数在 PostgreSQL 16 下没有问题。
边界一律用 UTC 零点，与时区无关。

## 2. 表结构与主键

```
events (PARTITION BY RANGE (ts))
├── events_pYYYYMMDD   日分区 [当天, 次日)
├── events_aYYYYMM     月归档分区 [月初, 最老日分区下界)：只装已过保留期、仍被引用的证据
└── events_default     默认分区：没有对应日分区的时间戳
```

- **主键 `(id, ts)`**。分区表的唯一约束必须包含分区键，单列 `id` 主键建不起来。
  这不削弱幂等：事件 ID 由来源侧稳定字段算出，且都含时间戳（`grpcsvc/agent.go` 的 `ts_unix_ns`、
  `grpcsvc/sensor.go` 的 `start_unix_ns`、`syslog/server.go` 的 `msg.Ts`），同一 id 必然同一 ts，
  `(id, ts)` 唯一与 `id` 唯一等价。ent 新建事件用 UUIDv7，不会撞。
- 入库 `INSERT ... ON CONFLICT DO NOTHING` 不写冲突列（`ingest/processor.go`），
  老表（主键 id）与分区表（主键 id, ts）都适用，迁移前后同一份代码。
- 二级索引与 ent 定义同名同列：`event_ts`、`event_asset_id_ts`、`event_process_guid`、
  `event_process_guid_ts`、`event_process_creation_guid`、`event_parent_process_guid`、`event_conn_tuple_ts`，外加 server 启动时建的关键词检索索引 `events_search_trgm`（pg_trgm GIN，见下文；老库可能还是旧的 `events_raw_trgm`）。
  在父表上建的是分区索引，新分区自动带上。
- `events_assets_events` 外键（asset_id → assets，ON DELETE SET NULL）保留：分区表**引用**别的表没有限制。

`event_conn_tuple_ts` 是 `(conn_tuple, ts) WHERE conn_tuple IS NOT NULL` 部分索引，
用于日志关联中按连接取最早事件，避免按时间扫描整个历史库。已有普通表不由启动迁移补索引，
应在主库单独执行（事务外），先检查空间与复制状态：

```sql
SET lock_timeout = '5s';
CREATE INDEX CONCURRENTLY event_conn_tuple_ts
ON events (conn_tuple, ts) WHERE conn_tuple IS NOT NULL;
```

同一进程及父进程回溯按 `process_guid` 过滤、按 `ts` 取最早记录，使用
`event_process_guid_ts` 联合索引。单列 `process_guid` 索引不能同时提供时间顺序，
优化器可能误选全局时间索引，导致稀疏命中时扫描大量历史事件。已有普通表同样在线补建：

```sql
SET lock_timeout = '5s';
CREATE INDEX CONCURRENTLY event_process_guid_ts
ON events (process_guid, ts) WHERE process_guid IS NOT NULL;
```

进程字段通常覆盖绝大多数事件，此索引的空间不能按连接部分索引估算；
需同时预留索引、排序临时文件和 WAL 的空间，并监控主从复制。验收前保留原单列索引。

资产图谱按进程 GUID 查询 `class_uid=1007` 的进程名，使用 `event_process_creation_guid`。
普通 GUID 索引也包含该进程的大量网络事件；若启动记录已过保留期，查一个不存在的进程名
仍会扫描这些网络记录。专用部分索引让不存在的启动记录直接返回，不必读取无关事件：

```sql
SET lock_timeout = '5s';
CREATE INDEX CONCURRENTLY event_process_creation_guid
ON events (process_guid) WHERE class_uid = 1007 AND process_guid IS NOT NULL;
```

该索引只用于进程事件查询，不能替代跨事件类型的 GUID 回溯索引。
若进程事件占比很高，仍需按 GB 级估算空间；不要把“部分索引”理解为一定很小。

完成后检查 `pg_index.indisvalid` 与查询计划；中断可能留下无效索引，不能仅凭同名索引存在判断成功。
并发建索引完成前不要重启 server：启动时的全文索引 DDL 即使带 `IF NOT EXISTS`，
也可能等待表锁，并使后续写入排在锁队列中。应先完成索引校验，再滚动发布应用。
已有分区表不能直接在父表上使用 `CONCURRENTLY`：需在各子表并发建立同构索引，再挂到父索引；
新建库会直接带上该索引。不要为了补索引重新执行事件数据迁移。

### 关键词检索索引

检索不直接把关键词条件交给规划器：它估不准子串命中率，会只走 trgm 索引、把时间范围当事后过滤，
整个保留期的候选行都要重算检索函数。`eventsearch.Search` 按三档走：逐行过滤最近 1 万行 → trgm 索引限时 5 秒 →
逐行过滤最近 20 万行，总时限 20 秒，没覆盖整个时间窗口时标为截断。按天分区后时间范围能裁掉分区，索引那档会快得多。

控制台事件检索与研判工具 `query_events` 的关键词走 `events_search_trgm`：
`gin (openxdr_event_search_text(raw) gin_trgm_ops)`。函数把事件里的标量值拼成一串，去掉 UUID 与
32 位以上的十六进制串（进程 uid、文件哈希）。旧索引 `events_raw_trgm` 对整个 `raw::text` 切三元组，
字段名、JSON 标点与高熵哈希都进了索引；生产抽样每行三元组从 253 个降到 79 个，约少七成。
口径变化：字段名与 JSON 结构不再能搜到；关键词只由十六进制字符与连字符组成且含字母或连字符时
（UUID、哈希片段）回退 `raw::text` 匹配，结果不漏，只是不走索引、按时间范围扫；
纯数字关键词按值匹配，不再命中 UUID 与哈希内部的数字片段。

新库启动即建。已有 `events_raw_trgm` 的库启动时**不现建**（大表上要几小时且挡住写入），
server 仍按旧口径用旧索引，直到新索引建好且有效。先升级 server（启动时建出 `openxdr_event_search_text` 函数），再在主库事务外：

```sql
SET lock_timeout = '5s';
CREATE INDEX CONCURRENTLY events_search_trgm
ON events USING gin (openxdr_event_search_text(raw) gin_trgm_ops);
```

分区表不能在父表上 `CONCURRENTLY`：先 `CREATE INDEX events_search_trgm ON ONLY events USING gin (...)`，
再对每个子表 `CREATE INDEX CONCURRENTLY` 同构索引并 `ALTER INDEX events_search_trgm ATTACH PARTITION <子表索引>`，
全部挂上后父索引才有效。确认 `pg_index.indisvalid` 后滚动重启 server，日志出现
「events_search_trgm 已可用，可以删除旧检索索引」即已切换；再删旧索引（普通表用 `DROP INDEX CONCURRENTLY events_raw_trgm`，
分区表直接 `DROP INDEX`，带 `lock_timeout`）。别在新索引建好之前删旧索引：两个都没有时启动会在前台现建新索引。

## 3. 指向 events 的引用，逐个处理

分区表不能被单列外键引用（被引用端要有只含 `id` 的唯一约束）。老库共有 8 个外键指向 `events(id)`，
全部去掉，语义改由触发器（逐行删除时）与退役流程（删分区时）显式承担：

| 引用 | 原约束 | 现在 |
|---|---|---|
| `alerts.event_id`（ent 边） | ON DELETE SET NULL | 无外键。保留期**不删**被告警引用的事件（退役时钉住，见第 6 节），所以置空本来不会发生；手工删事件不会置空，悬空 id 与 NULL 对读侧等价（JOIN 不到）。ent 的 `WithEvent` / `HasAlerts` 仍按列 JOIN，不需要外键 |
| `temporal_evidence.event_id` | NO ACTION DEFERRABLE INITIALLY DEFERRED | 约束触发器 `openxdr_events_evidence`，同样延迟到提交时检查，仍是证据的事件拒绝删除；同一语句里随锚点级联掉证据的删除照常通过。退役时钉住 |
| `temporal_detections.anchor_id` | ON DELETE CASCADE | 触发器 `openxdr_events_release` 级联删除；退役时已出告警（`alert_id` 非空）的锚点钉住，其余随分区清理 |
| `temporal_matches.event_id` | CASCADE | 同上（触发器 / 退役显式清理） |
| `temporal_candidates.event_id` | CASCADE | 同上 |
| `temporal_evaluation_gaps.event_id` | CASCADE | 同上 |
| `identity_observations.event_id` | CASCADE | 同上；下游 `identity_login_matches` 仍经它自己的外键级联 |
| `identity_local_snapshots.event_id` | CASCADE | 同上；下游 `identity_local_accounts`、`identity_login_matches.snapshot_event_id` 仍经各自外键 |

没有外键的只读引用不受影响：AI 组视图 `alert_events`（按 `e.id = a.event_id` 回查）、
身份图与身份 API 的 `JOIN events e ON e.id = o.event_id`、`response/verification.go` 的按 id 读取。

触发器在 `eventpart/schema.go`（`releaseFunctions`），只挂在分区表上（老库的普通表仍由原外键管）；
行级触发器挂在父表上会自动克隆到所有现有与以后的分区。各模块 `EnsureSchema` 的建表语句去掉了
`REFERENCES events(id)`；老库上已有的外键不动，迁移切换时才去掉。

**钉住（pinned）的口径**与原 janitor 逐行清理完全一致：`alerts.event_id`、`temporal_evidence.event_id`、
`alert_id` 非空的 `temporal_detections.anchor_id`（`eventpart/schema.go` 的 `PinnedIDs`，冷归档复用同一常量）。

## 4. ent 自动迁移与分区表共存

server 每次启动 `client.Schema.Create`。直接交给 ent，它会按单列主键对 events 做 diff，
Atlas 直接报 `partition key cannot be dropped`，或者去补 `alerts_events_alerts` 外键。

- `eventpart.SchemaOption` 是 ent 的 diff hook：比对**之前**把 `events` 表和所有指向它的外键
  从「现状」与「目标」两边都拿掉。ent 从此不碰 events；老库上仍在的 `alerts_events_alerts`
  也因为两边都看不到而不会被当成多余删掉。
- `eventpart.Migrate` = 带 hook 的 `Schema.Create` + events 建表：库里没有 events（新部署）就直接建分区表；
  已是普通表（迁移前的老库）原样保留，各处走老路径；已是分区表就补齐触发器与预建分区。
  `main.go` 的 `migrateSchema` 与测试库 `testdb` 都走它。**所有** `Schema.Create` 调用都必须带 `SchemaOption`。
- 代价：给 ent 的 `Event` 加字段时，ent 不会再替你加列，要同步改 `eventpart/schema.go` 的
  `Columns` / `columnDDL` 并对已有库 `ALTER TABLE events ADD COLUMN`（作用于分区表会传到所有分区）。
  `eventpart/schema_test.go` 比对 ent 生成的列与索引，漏了就挂。

## 5. 预建分区与默认分区

- 单活后台任务 `event-partitions`（`cluster.RunLeader`，`eventpart/maintain.go`）启动即跑、之后每小时一次，
  确保今天起 `PremakeDays = 7` 天的日分区都在。events 还是普通表时什么都不做，迁移切换后下一轮自动接手。
- 建分区不用 `CREATE TABLE ... PARTITION OF`（对父表要 ACCESS EXCLUSIVE），而是建独立表 →
  把默认分区里该日的行搬过去 → `ATTACH PARTITION`（对父表只要 SHARE UPDATE EXCLUSIVE，不挡读写）。
  先锁默认分区再 ATTACH：写入方是先父表后叶子，两边锁不成环。`lock_timeout = 3s`，等不到下一轮重试。
- 默认分区兜底所有没有日分区的时间戳：采集端时钟错乱的未来/远古时间、server 停机超过 7 天期间的事件、
  已退役范围以前的远古迟到事件。数据不丢；预建到那一天时自动搬进日分区。近一天落进默认分区的行会打告警日志。
- 「搬分区」不是删除：搬运事务里 `SET LOCAL openxdr.moving_rows = 'on'`，级联、证据保护与迁移镜像触发器都跳过。

## 6. 保留期：退役分区

janitor 每轮（`RETENTION_INTERVAL_MINUTES`）对上界不晚于截止点的日分区逐个退役（`eventpart.Retire`）。
截止点 = `now - max(RETENTION_DAYS, 27h)`：时序证据只可能引用「最大窗口 24h + 迟到余量 2h」内的事件，
再留 1 小时处理耗时（`janitor.retireGuard`），保留期配得再短也不会退役仍可能被新证据引用的日子。

退役一个日分区 D（月份 M）在一个事务里（`eventpart/partitions.go` 的 `retireDay`）：

1. `LOCK D IN SHARE MODE`：读照常，迟到写入 D 的事务等待，钉住集合在删除前不再变化；
2. 新建暂存表，复制 D 中被钉住的行；按原级联口径删掉 D 中其余事件的派生状态；
3. 默认分区里落在 [M 月初, D 上界) 的行搬进暂存表；已有的 M 月归档分区整体并入；
4. 在暂存表上建好主键与父表同构的索引（ATTACH 时直接挂上，不在排他锁里现建）；
5. `DETACH` D 与旧归档 → `DROP` → 暂存表改名为 `events_aYYYYMM` → `ATTACH` 为 [M 月初, D 上界)。

对父表的 ACCESS EXCLUSIVE 只从第 5 步开始，到提交为止只有目录操作和对小表的校验，毫秒级。
默认分区存在时 PostgreSQL 不允许 `DETACH ... CONCURRENTLY`，所以这里是普通 DETACH，
`lock_timeout = 3s` 等不到就整体回滚、下一轮重来（排队期间会挡住新查询最多 3 秒）。
理论上与「正在往 D 写迟到事件的事务」可能互相等锁成环，PostgreSQL 死锁检测会中止其中一个：
入库事务失败后由 JetStream 重投，退役失败则下一轮重来，不产生错误数据。

之后 janitor 照旧做逐行清理，但截止点收紧到最老日分区的下界：只碰归档与默认分区里的少量行
（迟到写进已退役范围的事件、引用已解除的证据、远古时间戳），日分区里的过期行一律留给整体退役，不逐行删。

## 7. AI 视图（queryrole 与 deploy/pi-query/group-views.sql）

视图定义不用改：

- 视图按名字引用 `public.events`，分区表对查询透明；组视图是 `security_barrier`，但时间比较运算符
  （`timestamptz_ge` / `timestamptz_lt` 等）是 leakproof 的，外层 `ts` 条件可以下推进视图，照样裁剪分区。
  `queryrole` 集成测试 `TestGroupViewsPrunePartitions` 用组只读身份 `EXPLAIN` 验证只扫一个日分区。
- `alert_events` 按 `e.id = a.event_id` 回查，主键 `(id, ts)` 的前导列是 id，每个分区一次索引探查，
  50 个分区量级下仍是毫秒级。
- 视图在 PostgreSQL 里按表 OID 绑定，老表改名后视图仍指向老表。在线迁移的 switch 步骤会在同一事务里
  用原定义 `CREATE OR REPLACE` 依赖 events 的全部视图（保留 `security_barrier` 等选项和授权），
  server 重启时 `queryrole.Reconcile` 也会重建组视图。

## 8. 按 ts 查询的分区裁剪（审计结果）

带 ts 条件的路径都用参数化比较（`ent` 的 `TsGTE/TsLT` 或 SQL `ts >= $n`），计划期或执行器启动时裁剪：
事件检索 `api/events.go`、总览计数 `api/stats.go`、AI 研判工具 `triage/tools.go`、关联 `correlate`、UEBA、
资产图谱游标、爆破检测、响应核验、身份 API、`cmd/backtest`。连接里的 `e.ts <= login.ts` 一类条件按嵌套循环参数
执行期裁剪。

不带 ts、要探全部分区的路径（行为正确，代价随分区数线性）：入库事务里按 id 回读事件
（`temporal.Observe`、`identity.Observe*`）、`eventai` 按 process_guid / conn_tuple 查关联事件、
`alert_events` 视图。前两者每次只探几十个分区索引；如以后分区数显著增长，可给它们补上已知的事件时间。

## 9. 在线迁移（老库）

新部署直接是分区表，不需要迁移。老库用 `server/cmd/eventpartition`：

```
DATABASE_URL=... eventpartition [-pgdata 数据目录] [-confirm] <步骤>
```

| 步骤 | 只读 | 做什么 | 可中断 / 重跑 |
|---|---|---|---|
| `check` | 是 | 阶段、表大小、预计耗时、磁盘需求与余量、前置条件 | 随时 |
| `prepare` | | 一个事务：状态表、`events_next`（只带主键）、归档与日分区、老表上的镜像触发器 | 原子；失败无残留 |
| `copy` | | 按 `-chunk`（默认 1 小时）时间段 `INSERT ... SELECT ... ON CONFLICT DO NOTHING`，每段提交并推进游标；空段直接跳到下一条数据 | Ctrl-C 后重跑从游标续 |
| `index` | | 照老表的二级索引在每个分区上 `CREATE INDEX CONCURRENTLY`，再挂到父索引；最后 `ANALYZE` | 失败留下的无效索引重跑时删掉重建 |
| `verify` | 是（只写状态表） | 同一 REPEATABLE READ 快照里逐日比对行数与 id 摘要；一致才允许 switch | 随时 |
| `repair` | | 按日删除新表多出的行、补上缺的行（`-day` 只修一天）；之后必须重新 verify | 可重跑 |
| `switch` | | 一个事务（见下） | 锁等不到整体回滚，可重跑 |
| `rollback` | | 切回老表（见第 11 节） | |
| `finish` | | 删 `events_old` 与镜像，迁移结束，不可再回滚 | |
| `abort` | | 切换前放弃：摘镜像、删 `events_next` 与状态表 | |

会改库的步骤不加 `-confirm` 直接拒绝。没有演练模式：每步都是真执行，靠每步之后的只读核对把关。
同一时间只允许一个迁移进程（advisory lock）。

**追平新写入**：prepare 在老表上挂行级镜像触发器，老表的插入、更新（资产删除置空 asset_id）、删除
在同一事务里同步到 `events_next`。任何快照里两表一致，回填只需覆盖触发器生效前已有的行；
回填与镜像重复的行由主键去重。唯一的竞争是「回填读到一行、随即该行被 janitor 删除」留下残行，
verify 的逐日摘要必然发现，repair 修掉。

**switch 事务**（停写窗口就是它）：`lock_timeout`（默认 5s）内拿到两表 ACCESS EXCLUSIVE →
确认镜像触发器仍是 verify 时那一个且启用 → 核对最近一小时行数 → 记录并删除指向老表的外键 →
老表改名 `events_old`、索引加 `_old` 后缀 → `events_next` 改名 `events`、索引去掉 `_next` 恢复标准名 →
按原定义重建依赖视图 → 挂删除级联与证据保护触发器 → 在新表上挂反向镜像（新表 → `events_old`，供回滚）。
全是目录操作加一小时数据的计数，测试库实测 30 ms 以内；生产预计 1 秒内，最坏不超过 lock_timeout。

**磁盘**：迁移期间新旧两份并存，需要老表（含索引与 TOAST）× 1.2 的余量（新表一份，两成给 WAL 与临时文件）。
`prepare` / `copy` / `index` 开始前都用 `-pgdata` 指向的文件系统核对，不足直接拒绝；不给 `-pgdata` 也拒绝。
同步备库要有同样的余量：在备库容器里跑只读的 `check -pgdata ...` 核对。

## 10. 生产执行步骤（Patroni 一主一同步副本）

正式执行前，先在生产数据的副本（例如从备份恢复的库）上把全流程跑一遍，量出实际耗时。

1. **先升级全部 server 到本版本**并确认 `/readyz`。旧版本在切换后会因为 `ON CONFLICT (id)` 和不带 hook 的
   `Schema.Create` 失败，必须在 switch 之前全部换掉；之后也不能回退到旧版本。
2. 把 `eventpartition` 二进制拷进主库与备库容器（同 `cmd/backtest` 的做法），两边各跑
   `check -pgdata $PGDATA`：看老表数据与索引大小、需要的余量、预计耗时；余量不足先扩容。
3. 低峰期 `prepare -confirm -retention-days <与 RETENTION_DAYS 一致>`：只在挂触发器时短暂锁老表写入（≤ lock-timeout）。
   此后入库每条事件多一次写入，直到 finish。
4. `copy -confirm`，IO 紧张时加 `-pause 200ms`。按经验速率（30–80 MB/s，含同步复制）78 GB 约 0.5–1.5 小时，
   运行中每 10 秒打印游标、速率与预计剩余。期间关注复制延迟与 `pg_wal` 占用。可随时 Ctrl-C，重跑续传。
5. `index -confirm`：4 个 btree 各扫一遍新表，约 10–30 分钟/个；trgm GIN 最慢，约 2–5 小时（换成 `events_search_trgm` 后会快不少）。
6. 低峰期 `verify`：两表各全扫一遍，约 20–60 分钟，期间持有一个长快照（会推迟 VACUUM 回收）。
   有不一致就 `repair -confirm`，再 `verify`。
7. 低峰期 `switch -confirm`。拿不到锁（有长查询或长事务）会整体放弃，换个时间重跑即可。
8. 观察 1–3 天：server 日志应出现「预建事件分区」「退役过期事件分区」；`verify`（切换后只比对仍在日分区内的日子）
   应一致；检索、AI 查询、告警详情正常。
9. `finish -confirm`：删 `events_old`，释放约一倍空间。

## 11. 回滚

- **switch 之前**：`abort -confirm`，老表从头到尾没动过（只多过一个镜像触发器）。
- **switch 之后、finish 之前**：`rollback -confirm`。反向镜像让 `events_old` 一直与新表同步，回滚是同样的短事务：
  两表改名还原、索引名还原、外键以 `NOT VALID` 加回（事务外逐个 `VALIDATE`，不长时间锁表）、视图重绑、
  镜像改回老表 → `events_next`。退役期间整体删掉的日分区在老表里仍有完整数据（多出来的只是过期事件，
  老 janitor 会照常逐行清掉）。回滚后可以 `abort`，或 `verify` → `repair` → `switch` 再来。
- **finish 之后**：老表已删，没有工具化回滚；server 也不能回退到旧版本。只能从备份恢复。

## 12. 风险与限制

- 去掉外键后，引用完整性靠触发器和退役流程保证；绕过它们的操作（直接对分区 `TRUNCATE`、手工 `DROP` 分区、
  `session_replication_role = replica`）不会级联也不会保护证据。
- 默认分区存在时不能 `DETACH CONCURRENTLY`，退役要短暂拿父表 ACCESS EXCLUSIVE。它不排队等锁（排队时后来的读写全被堵在后面），
  而是在 SAVEPOINT 里 `LOCK ... NOWAIT` 每 100ms 试一次，碰上没有冲突持锁的瞬间拿到，最多试 30 秒；
  一直有超过 30 秒的读（或持续不断的长查询）时这一轮放弃，日志报「退役过期事件分区失败」，过期数据暂时多留。
- 退役事务持有日分区的 SHARE 锁复制证据（整分区扫一遍，约 2.6 GB）期间，迟到写进该日的事件要等；
  与写迟到事件的事务可能触发死锁检测、中止其中一方（重投 / 下一轮重来）。
- 月归档分区每次退役整体重建，大小取决于当月被告警引用的事件量；引用很多的月份重建更慢（仍不持父表排他锁）。
- 不带 ts 的按 id 查询代价随分区数增长（第 8 节）。
- 迁移期间写放大（镜像），verify 的长快照推迟 VACUUM；switch 要求全部 server 已是本版本。
- 同步备库的磁盘与 WAL：copy / index 产生的 WAL 与数据量同级，备库同样需要一倍余量，复制延迟会拖慢主库提交。

## 普通表的重复 GUID 索引清理

`event_process_guid_ts(process_guid, ts) WHERE process_guid IS NOT NULL` 已覆盖应用的非空 GUID 等值、
批量与时间排序查询。新库不再单独创建 `event_process_guid(process_guid)`，避免每条事件维护重复 B-tree。
`event_process_creation_guid` 和父进程索引仍保留，不属于这次清理范围。

旧表不会在服务启动时自动删索引。先升级全部服务节点，确认联合索引 valid/ready，保存查询计划与旧定义，
再由数据库管理员在**普通 events 表**执行 [受保护的清理脚本](../deploy/ha/drop-redundant-process-index.sql)。
脚本核对表类型及两个索引的列、谓词和有效性，使用 5 秒锁等待、2 分钟语句上限并发删除；不删除任何事件。
不要放进外层事务。分区父索引不支持 `DROP INDEX CONCURRENTLY`，脚本会拒绝，须单独安排分区维护。

完成后确认 `to_regclass('public.event_process_guid') IS NULL`，复核 GUID 查询结果、执行计划、写入队列和复制状态。
若并发删除被取消，先检查索引状态和阻塞者；索引可能已无效但尚未释放空间，不能仅凭命令退出判断完成。
迁移工具会保留旧表上的既有索引，因此需要清理的普通表应在分区迁移之前处理。

如出现查询回归，保持联合索引存在，并按保存的旧定义在线重建，例如：

```sql
CREATE INDEX CONCURRENTLY event_process_guid ON public.events(process_guid);
```

重建需要时间、磁盘和 WAL 余量；它不是瞬时回滚。清理前应核对非应用的自定义查询是否依赖空 GUID 检索性能。
