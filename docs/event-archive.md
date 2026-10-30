# 冷归档

events 保留期内的数据在日分区里，过期分区由 `eventpart.Retire` 整体退役（见
`docs/event-partitioning.md`）。退役之外还有一类需求：**把过期但仍有价值的事件压成冷块长期保留**，
查询时按需解压。本文是冷归档的格式、口径、生命周期与操作手册；阶段 A（影子归档）、B1（冷热读取）、
B2（定位与物化）、C（单日切换与恢复）及后续 P0–P6（基线反例、批量恢复、locator、原子切换、
消费者闸门、查询闭环、生命周期）已全部实现并通过等规模演练；C 仍**只在测试库验证**，
生产启用前按第 12 节顺序执行单日试点。等规模实测数字见
[archive-rehearsal-2026-10-30.md](archive-rehearsal-2026-10-30.md)（260 万行单日：shadow 25.7s、
swap 37.7s、restore 123s、Exists 未命中 p50=2.5ms，净节省 ≈934 MB/日）。

代码：`server/internal/eventarchive`（冷块编解码、影子构建、对拍、度量、定位、单日切换与还原、
状态汇总），`server/internal/eventpart`（分区 DDL：预建、退役、单日重写），
`server/cmd/eventarchive`（命令行）。

## 1. 阶段划分

| 阶段 | 做什么 | 状态 |
|---|---|---|
| **A 影子归档** | 只读 events，把候选事件编码成冷块写进新表，块 + locator 行 + run 计数同事务，逐事件对拍 | **已实现** |
| **B1 冷热读取** | `/api/events` 先查热表，再按同一组参数与同一个组权限查冷块，合流去重；覆盖缺口进响应体（`coverage`） | **已实现** |
| **B2 定位与物化** | locator 索引按事件 ID 定位（`Locate` / `Exists`）、证据物化（`Materialize`）、归档边界（`Boundary`） | **已实现** |
| B2 生命周期 | 按自动策略回收冷块（现按 run 手工删，见第 13 节容量口径） | 未实现（独立后续） |
| **C 单日切换与恢复** | `plan` → `swap` → `restore`：把已验证 run 覆盖的一天重建成只保留「钉住 + 非归档口径 + 无冷副本」的行，冷层继续可读、可整日还原；重传判重接进接入路径（`EVENT_ARCHIVE_DEDUP`，第 10.9 节） | **已实现（只在测试库验证）** |

阶段 A 的铁律：**不改动、删除或切换 events 的任何一行**。不改 `events` 与其索引，
不 `DETACH` / `ATTACH` / `DROP` 任何分区，不调用 `eventpart.Retire`，不给 events 加外键或触发器。
写入只发生在三张新建表上：`event_archive_chunks`、`event_archive_runs`、`event_archive_locator`。
正因为如此，阶段 A 无论跑多少轮都不影响线上读写路径，也不需要停写窗口。

阶段 B2 唯一的例外是 `Materialize`：它会往 `events` **插入**一条原本只在冷块里的事件
（`ON CONFLICT DO NOTHING`），插入缺失的证据是它的本意；仍然不修改、不删除既有行，也不碰分区。

阶段 C 是**唯一会删数据**的环节：它按天重建日分区，把已经进了冷块的行从热表移走。
第 10 节把它的集合定义、拒绝条件、闸门、事务边界与生命周期写清楚；任何一条不满足就拒绝执行，不猜。

## 2. 冷块格式

一块冷块 = 头部 + 载荷。头部在库里是 `event_archive_chunks` 的列；导出或单独存档时用
`Block.MarshalBinary` 拼回下面这套字节布局，读端 `DecodeBlock` 可独立解码：

```
magic(8) "OXDRARC1" | format(1) | codec(1) | count(4, BE) | plainLen(8, BE) | plainSHA256(32) | payload
```

| 字段 | 含义 |
|---|---|
| `magic` | 固定 `OXDRARC1`，用来把冷块与任意字节流区分开 |
| `format` | 格式版本，当前只有 `1`（`FormatV1`）；不能识别的版本直接拒绝 |
| `codec` | `0` = 原文；`1` = zstd（`klauspost/compress/zstd`，`EncodeAll`、并发 1、级别 1） |
| `count` | 块内事件条数 |
| `plainLen` | 解压后明文字节数 |
| `plainSHA256` | 明文的 SHA-256，用来发现载荷损坏 |
| `payload` | zstd frame，或未压缩的明文 |

**载荷**是逐行 JSON：`\n` 分隔，末行不带 `\n`；每行是一条事件，字段顺序由 `Event` 的声明顺序固定，
因此同样的输入两次编码字节完全一致。字段与 events 的公共列一一对应：

```json
{"id":"…","ts":"2026-09-01T00:00:00Z","class_uid":4001,"source":"agent",
 "asset_id":null,"process_guid":null,"parent_process_guid":null,
 "username":"root","conn_tuple":"10.0.0.1:50000>10.0.0.2:443","raw":{"…":"…"}}
```

- `ts` 用 RFC3339Nano、UTC；`raw` 用 `json.RawMessage`，**原样写入** events 里 jsonb 的文本表示。
  这里不能用 `encoding/json` 整体序列化：它会把 `json.RawMessage` 重新压紧并转义 `< > &`，
  jsonb 文本里本来就带空格，一过它就不再逐字节相同，对拍永远过不去。
- 可空列写 `null`，与 events 的 NULL 一一对应，不会把 NULL 折成空串。
- 能压小就用 zstd；压不小（已经压过的数据、太短的块）就退化 `codec=0` 存原文，读端按 `codec` 分辨。

头部布局是冻结的：ID Bloom filter 不进这套字节，它是块的一条**列**（`id_bloom`），
和 `first_ts` / `event_count` 一样属于「头部字段落在库里」的那部分。没有 filter 的块照旧能读、能查。

**读的硬上限**（都在解压之前判断，不按头部声明的大小分配内存）：

| 上限 | 值 | 行为 |
|---|---|---|
| `plainLen` | 16 MiB（`MaxPlainLen`） | 超出直接报错，解码器也设了同样的上限 |
| `count` | 8192（`MaxCount`） | 超出直接报错 |
| 单条事件 | 4 MiB（`MaxEventBytes`） | 构建时跳过并计数，不进冷块；swap 时该行留热（见 10.1） |

解压后核对 `sha256(明文)` 与 `plainLen`，再按 `\n` 切行、逐行反序列化并核对条数。
任何一项不符都返回错误、返回 `nil` 事件列表，**不返回部分结果**。空块（0 条）不允许写入。

## 3. 三张新表

`EnsureSchema` 建三张表（全部 `CREATE TABLE IF NOT EXISTS`，幂等）：

```
event_archive_chunks(id pk, run_id, seq, day, class_uid, source, first_ts, last_ts,
                     event_count, format, codec, plain_len, payload_len, plain_sha256,
                     payload, id_bloom, created_at, UNIQUE(run_id, seq))
  索引：(day, class_uid, source)、 (first_ts, last_ts)
event_archive_runs(id pk, started_at, finished_at, status, day_from, day_to, classes, sources,
                   scanned, archived, pinned_skipped, chunks, error, detail)
event_archive_locator(event_id, chunk_id → chunks.id ON DELETE CASCADE, PRIMARY KEY (event_id, chunk_id))
  索引：(chunk_id)
```

- **没有任何指向 events 的外键**，也没有触发器：冷归档与 events 之间只有「某一轮扫描时读到过」的
  关系，由 `run_id` + 对拍来证明，不靠数据库约束。
- `payload` 允许 TOAST，不给大字段建索引；`id_bloom` 是随行过滤元数据（P2 起读取路径走 locator，
  不再逐块过滤，详见第 8 节）。
- `status`：`building`（构建结束、等对拍）→ `verified`（对拍通过，`detail.verified_at` 记时间）；
  构建或对拍出错记 `failed`，原因写 `error`。`verified` 是**粘性资格**：对拍通过过一次就保持，
  之后冷块被改坏不会自动回退（当前健康度用 `status` 子命令的冷副本自校验看，见 10.8）。
- `detail` 记构建明细（`scanned`、首末 ts、`oversized` / `oversized_ids`、封块阈值）与
  swap 的逐日操作记录 `days.<UTC 日>`（见 10.6）。

## 4. 影子构建

```
DATABASE_URL=... eventarchive shadow -from 2026-09-01 -to 2026-09-14 [-classes 4001,4003] \
    [-sources agent,sensor] [-chunk-events 2048] [-chunk-bytes 1048576] -confirm
```

1. 不加 `-confirm` 直接拒绝（与 `eventpartition` 同一约定，没有演练模式）。
2. 建 run 行，`status=building`。
3. **只读**扫描 events：`ts >= from AND ts < to+1d`、`class_uid = ANY(classes)`、`source = ANY(sources)`，
   并**排除被钉住的事件**（`id NOT IN (eventpart.PinnedIDs)`）。
4. 按 `ChunkEvents`（默认 2048）或 `ChunkBytes`（默认 1 MiB 未压缩）封块；**每块一个事务**写
   `event_archive_chunks`、该块的 locator 行、并累加 run 的 `archived` / `chunks`——三者同生共死，
   崩在中途不会留下「有块没索引」或「计数对不上」的账（P2 原子性）。
5. 扫描结束写 `scanned` / `pinned_skipped` / `detail` / `finished_at`，`status` 保持 `building`，
   等 `verify` 置 `verified`。

**pin 排除先于归档判定**：被 `alerts.event_id`、`temporal_evidence.event_id`、
`temporal_detections.anchor_id`（`alert_id` 非空）引用的事件不归档，计入 `pinned_skipped`。
口径直接复用 `eventpart.PinnedIDs`（与保留期退役、janitor 逐行清理同一个常量），不另维护一份。

**分组的顺序与封块**：分块以 `(day, class_uid, source)` 为界——块上的这三列必须是同一个值。
扫描按 `(类别, 来源)` 分组，每组内 `ORDER BY ts, id` 用 keyset 分页流式读取：内存里只有一批事件
加正在封的块。组内 ts 递增，日边界天然连续到日界封块。

**超大事件**：单条编码后超过 `ChunkBytes` 时单独成块；单条超过 4 MiB 时跳过，计入
`detail.oversized` 并记 id（最多 20 个），不静默丢。这类事件没有冷副本，swap 时**留热**
（见 10.1），不再是切换的阻断条件。

**一致性与锁**：整个扫描固定在一个只读 `REPEATABLE READ` 事务的快照里，不给 events 加任何锁。
快照内的计数自洽，构建结束核对 `scanned == archived + pinned_skipped + oversized`，对不上就让这轮
`failed`。快照之外的并发写入由 `verify` 报成「候选集已变化」。

**口径固定**：没给 `-sources` 时，构建开始时把范围内的来源清单固定下来写进 run 行，
`verify` 用同一份清单重查。之后新增的来源不会被悄悄纳入。

**可以重复跑**：同一范围每次一个新 `run_id`，冷块叠加（重叠副本合法，locator 每 run 每块各一行）。
重叠副本计入存储成本、不重复计算节省量（见第 6 节口径）。

## 5. 对拍

```
DATABASE_URL=... eventarchive verify -run <uuid>
```

1. 先核 run 自己的账：`chunks` / `archived` 与 `event_archive_chunks` 实际行数、条数必须一致。
2. 按 run 的 `day_from/day_to/classes/sources` 只读重查候选集（同样排除 pin），
   与按 `seq` 顺序解码出的所有事件**逐事件全字段比对**：`id`、`ts`、`class_uid`、`source`、
   `asset_id`、`process_guid`、`parent_process_guid`、`username`、`conn_tuple`、`raw`（逐字节）。
3. 每块解出来后核块自洽：`event_count` 与解出条数、块内同属一个 (日, 类别, 来源)、
   `first_ts` / `last_ts` 与首末条一致、块内 ts 不回退。
4. **locator 成员集合校验（P2）**：每块解出的成员集合必须与 `event_archive_locator` 里该块的
   成员集合**精确相等**——缺行、多行、错指块都报错，不以条数相同代替集合相同。
5. 全部一致才把 run 置 `verified`（`detail.verified_at` 记时间）。

错误分三类，不混在一起：

| 情况 | 错误 |
|---|---|
| events 里多出候选（构建后新写入） | `候选集已变化，请重新运行` + 首个多出的事件 |
| 冷块里有、events 里已经没有（构建后被清理） | 同上 + 首个缺失的事件 |
| 字段不一致、`raw` 字节不同、SHA 不符、解压失败、locator 集合不符 | 字段级差异或「冷块已损坏 / 数据不一致」，**不**说是候选集变化 |

单条编码后超过 4 MiB 的事件在两边同规则跳过（它们本来就不在冷块里），不是遗漏。
老块（P2 之前写的、没有 locator 行）对拍会报错：它们必须先跑 `backfill-locator`（见 8.4）。

## 6. 空间度量

```
DATABASE_URL=... eventarchive report -run <uuid>
```

所有数字来自真实查询：归档前（被归档事件在 events 里的条数、整行字节、所在日分区大小）与
归档后（`sum(plain_len)`、`sum(payload_len)`、压缩比、chunks 表总大小，含 TOAST 与索引）。

口径注意：

- `sum(pg_column_size(t.*))` 是 jsonb 在库里的**二进制**行宽，`plain_len` 是 JSON **文本**字节数，
  两者不是同一个分母。压缩比只按 `plain_len/payload_len` 算。
- 日分区大小是**整分区口径**（含当天未归档类别与全部索引），与冷归档表不是同一批事件，只作量级参考。
- **重叠副本不重复计算节省**：同一事件被多个 run 归档时，热表只省一份空间，冷块却按份数付成本。
  `report` 按 run 各自报数（每个 run 都会数到这批事件）；跨 run 汇总节省时必须按事件 id 去重后
  只计一份，成本（块 + locator）照实相加。净节省口径见第 13 节。

## 7. 读取契约（阶段 B1）

冷读只读，不改冷块格式、不动 events，也不改变热表查询的参数语义。

**开关**：`EVENT_ARCHIVE_READ=1` 才把 `*sql.DB` 交给 `/api/events` 与 related/explain 调查入口，
默认关闭。开启时启动阶段先跑一次 `EnsureSchema`；建表失败只记警告并降级为「没有冷层」。
开关关着（连接为 nil）时 `/api/events` 与未接冷层时一致，不报冷层缺口：默认部署每次检索都提示
「冷层未搜索」只会是噪音。库里已有冷块却没开读属于部署配置错误，server 启动时在日志里告警；
**swap 之前必须在全部节点开启 `EVENT_ARCHIVE_READ=1`**（与 `EVENT_ARCHIVE_DEDUP=1` 同理）。

### 7.1 `eventarchive.Query`

```go
Query(ctx context.Context, db *sql.DB, f Filter) ([]Event, Coverage, error)
```

| 条件 | 含义 |
|---|---|
| `From` / `To` | 按 `ts`，左闭右开 |
| `AssetIDs` | **nil 表示不限**（全局 admin）；**非 nil 表示受限**：事件 `asset_id` 为 NULL 或不在集合里的一律丢弃，空切片表示「一无所见」。与热表 `AssetIDIn()` 的空集合口径一致 |
| `Classes` / `Sources` | 空表示不限 |
| `IDs` | 按事件 ID 精确定位，可与其它条件叠加 |
| `Limit` | `<=0` 用 1000 |

- 候选块按元数据收窄（`first_ts`/`last_ts` 与窗口相交、`class_uid`、`source`），解压后逐事件精确匹配；
  结果 `(ts, id)` 倒序、去重（多 run 重复归档只留一条），最多 `Limit` 条。
- **预算**：单次最多解压 200 块（`maxScannedChunks`）。`Coverage` 把两种缺口分开：
  `Truncated`（命中数超过 `Limit` 被挤掉，或预算没扫完）与 `ScanIncomplete`（还有候选块因预算没解压，
  「该范围没扫完」）。两者可同时为真。
- **块损坏**：头部/`sha256`/条数/块内自洽任一不符，`Query` **整体返回错误**并带块 id——
  「跳过坏块」等于把「查不到」伪装成「不存在」。
- **表不存在**：返回 `ErrNoSchema`（部署状态，不是数据错误）；**表在但没有块**：空结果、不报错。

### 7.2 `/api/events` 对象契约

响应体是对象（不是裸数组），三个字段：

| 字段 | 类型 | 含义 |
|---|---|---|
| `items` | 事件行数组 | 热表行与冷块事件合流去重后的结果，按 `(ts, id)` 倒序，最多 `limit` 条。行字段：`id` / `ts` / `classUid` / `source` / `assetId` / `username` / `connTuple` / `raw` / `automation`（可信自动化引用，可省略） |
| `truncated` | bool | **纯条数信号**：返回条数达到 `limit`，可能还有更早的；与扫描是否完整无关，可与 `coverage.scan_complete=true` 同时为真 |
| `coverage` | 对象 | 冷热两层的覆盖说明，字段见下 |

`coverage` 字段：

| 字段 | 含义 |
|---|---|
| `hot_searched` | 热表是否参与了查询（该入口恒为 `true`） |
| `cold_searched` | 冷层是否真的查了；`false` 时原因看 `reason` |
| `scan_complete` | 本次请求声明的范围（热 + 冷）是否扫完；`reason` 非空时必为 `false` |
| `reason` | 空串 = 无缺口；枚举见下 |

`reason` 枚举（与 `scan_complete` 互为表里）：

| 取值 | 含义 |
|---|---|
| `hot_keyword_degraded` | 热表关键词检索超出时限（见 [事件表分区](event-partitioning.md#关键词检索索引)），只覆盖了最近的数据；优先于其他原因 |
| `keyword_not_searched` | 关键词查询不搜冷块（冷块无关键词索引，逐块解压全文扫代价不可控） |
| `no_archive_schema` | 冷读开着但冷归档表未初始化（没跑过 ensure-schema） |
| `scan_incomplete` | 扫描预算（200 块）耗尽，还有候选块没解压；此时 `cold_searched=true`（查了，没查完） |
| `before_archive` | 查询窗口整体早于最早的冷块，该窗口不在冷层覆盖内 |

块损坏等真实读取错误**不走 reason**：直接 `500` 带块 id，不能用「缺口说明」掩盖错误。
归档表在、但一条冷块都没有时不报缺口（冷层不可能吞掉任何事件）。

调试头 `X-Archive-Coverage`（`chunks=N;matched=M;truncated=0|1` 或 `skipped=…`）与 `X-Truncated`
保留为摘要，**真源是响应体里的 `coverage`**；调试期结束后头会移除。

`matched` 是**冷层**的命中数（含与热表重复的事件），不是合流后的新增条数。合流规则：热表行优先
（它带着告警与自动化信息），冷块事件补进来，按 `(ts, id)` 去重、倒序、截到 `limit`。
冷块为空时原样返回热表结果，不重排、不截断。冷查询的时间窗给 `To` 补 1ns（热表 `ts <= to`，
冷查询左闭右开），直接调 `eventarchive.Query` 的调用方要自己处理这个边界差。

## 8. 按 ID 定位与证据物化（阶段 B2）

### 8.1 locator 索引

`event_archive_locator` 是「事件 id → 块」的索引表：主键 `(event_id, chunk_id)` 让按事件 id 定位
从「扫全部块元数据」变成一次 btree 探查；`chunk_id` 上的第二索引服务按块查成员
（对拍的集合校验与覆盖性推导）。

- **结构上刻意不冗余 `run_id`**：按 run/day 列块经 `event_archive_chunks` 取，主键已覆盖
  `event_id` 前缀探查。同一事件 id 跨 run 多副本合法（多次 shadow 重叠归档），每副本一行；
  同块内 `(event_id, chunk_id)` 唯一。
- locator 行与块 INSERT 在**同一事务**写入（`writeChunk`），块被删时 `ON DELETE CASCADE` 连带消失。
  「在 locator 里」=「有这个块的冷副本」——swap 的删除依据（keepSelect 第三条）用的就是这一点。
- 每块的 `id_bloom` 列继续随块写入（随行过滤元数据）；P2 起读取路径不再逐块过滤，老块（无
  locator 行）必须先回填才能获得「确定不存在」语义。

### 8.2 `Locate` / `Exists`

```go
Locate(ctx context.Context, db *sql.DB, id uuid.UUID) (Event, bool, error)
Exists(ctx context.Context, db *sql.DB, id uuid.UUID) (bool, error)
```

按 id 探查 locator 得到候选块，逐块 load/Decode/核对块自洽后**逐事件精确比对 ID**，命中即返回。
结论分三档，调用方必须分清：

| 情形 | 返回 |
|---|---|
| 命中 | `found=true` + 事件（跨 run 多副本内容一致——都从同一条热行编码，命中任一副本即可） |
| 索引未命中，且 locator 覆盖完整（没有缺行的块） | `found=false, err=nil`：**确定**冷层没有 |
| 索引未命中，但库里还有没回填的块 | `ErrLocatorIncomplete`：**无法确认**不存在，不得当 `false` 用 |
| 索引行指向的块解不出该 id | 错误（locator 与载荷不一致），**不返回** `found=false` |
| 块损坏 / 冷归档表不存在 | 错误（后者是 `ErrNoSchema`，部署状态） |

### 8.3 `Boundary` 与 `Materialize`

`Boundary` 返回冷层最晚事件时间（`max(last_ts)`）与「是否已有冷块」。它是接入判重**时间闸门**的
唯一依据：事件时间晚于边界就不可能在冷块里，连 `Exists` 都不用发。只读一条聚合，不缓存
（缓存是调用方的事，ingest 侧 60 秒 TTL）。

`Materialize` 把一条冷事件物化回 `events`（单事务 `INSERT … ON CONFLICT DO NOTHING`，幂等）：
不经过检测器、不产告警、不改派生表、不回写冷块。冷层没有返回 `(false, nil)`；索引覆盖不完整时
未命中返回 `ErrLocatorIncomplete`（拿不准就不动 events）。events 自己的约束照旧生效：
**`asset_id` 指向已删除资产时报外键错误，整块/整条回滚，不静默丢字段、不改写成 NULL**——
要恢复这类历史，先重建同 id 资产（或单独确定语义），再幂等重跑。

### 8.4 老块迁移：`backfill-locator`

P2 之前写的冷块没有 locator 行。迁移完成态不建新状态表，用**覆盖性推导**表达：

```
「没有缺 locator 行的块」 == 「迁移完成」
  即 chunks LEFT JOIN locator … WHERE l IS NULL 的数量为 0
```

它便宜（块表顺序扫 + locator 索引 probe，不碰 payload、不解 TOAST），并且**不存在「回填一半」的
中间态**：每块的回填是单事务，回滚后整块回到 0 行。该推导同时给 `Locate` / `Exists` 的
`ErrLocatorIncomplete` 判定使用（`LIMIT 1` 即可），不引入第二份账本。

流程与前提：

1. **前提一：并发新块写入必须已经走原子新路径**（`writeChunk` 同事务写 locator）——
   旧版本的写入进程必须**先全部退出**再回填，否则「回填完成」之后又出现无索引新块，
   覆盖性推导被新块打破（表现为 `Exists` 对新块未命中报 `ErrLocatorIncomplete`，
   属可观测的保守行为，不是静默丢判重）。
2. 不加 `-confirm` 时先只读报告缺口块数；加 `-confirm` 才逐块 load/Decode/check 后单事务回填。
3. 幂等：已回填的块不再出现在缺行清单里，重跑返回 0；中途失败（解码/校验/写入）该块一行不写，
   已完成的其他块保留，重跑只处理剩余的块。
4. **不要求热行存在**：块直接解码回填，已 swap（events 里已删）的旧块同样处理。
5. 收尾重新核对覆盖性推导成立；不成立（并发旧路径又写了新块）就如实报错，不宣布迁移完成。

## 9. 调查入口的冷层口径（阶段 P5）

「没查到」不再可能被当成「不存在」：五条调查路径全部如实表达冷归档造成的覆盖缺口。

- **`/api/events`**：见 7.2 的对象契约与 `reason` 枚举。
- **related / explain（`/api/events/{id}/related|explain`）**：热表查不到这条日志时按 id 经
  `Locate` 读冷事件，**只读**——不自动物化回热表、不自动 pin（把冷事件变成受保护证据要走
  restore + 人工/研判流程）。权限与热表同口径：复用 `/api/events` 冷查询的 `visibleAssets`
  （admin 不限；非 admin 要求资产可见；`asset_id` 为 NULL 的冷事件只有 admin 能看），越权与不存在
  同文案 `404`，不泄漏冷层里有没有这条事件。`ErrNoSchema` / `ErrLocatorIncomplete` 时 `404` 并在
  响应体说明「冷层状态未知」；块损坏如实 `500`。目标事件来自冷层时，响应体的
  `archive.target_from_archive=true`，同时声明 `archive.candidates_hot_only=true`：关联候选与解读
  输入仍然只查热表（冷层没有关键词与关联索引），「没有关联」不等于「没有相关事件」。
- **Pi 的 SQL query 工具**：每次结果都带**静态范围声明** `coverage{tables:["events","alert_events"],
  hot_only:true, note}`——任意 SQL 到底碰了哪些表靠解析说不清，说不清还硬给行级承诺比诚实的
  边界声明更危险。模型零额外调用即知「查不到 ≠ 没发生」。**外部 SQL 直查组视图同样只覆盖热表**
  （queryrole 的组视图不含冷数据），这是当前口径不是缺陷，扩大覆盖需独立设计。
- **旧 triage 的 query_events**：复用 `/api/events` 的 coverage 结构补归档缺口，不建平行结构。
- **前端**：事件页零结果且 `coverage.reason` 非空时展示 warning 级提示（说明这部分可能只是
  没查到冷层）与归档恢复指引；有结果但覆盖不完整时展示 info 级提示；AI 抽屉显示目标事件的
  冷层来源与边界。

## 10. 单日切换与恢复（阶段 C）

阶段 A/B 做完之后，同一批事件在 `events` 与冷块里各有一份；阶段 C 才把它们从热表移走，
空间真正释放。这是全项目唯一删数据的环节，先看计划（`plan`），再动数据（`swap`），可回滚（`restore`）。

```go
type SwapPlan struct {
    Day        time.Time // UTC 日
    Archived   int64     // 该日、本 run 覆盖的类别/来源、且未被 pin 的行数（事务外估计）
    KeepPinned int64     // 该日被 pin 保护的行数（无论类别/来源）
    KeepOther  int64     // 该日其它类别/来源的行数
    Total      int64     // 该日分区当前总行数
    Guard      *GuardReport // P4 切换闸门的只读评估（Plan 附带核对，Swap 据此拒绝）
    Kept       int64     // Swap 执行后事务内实测保留数（Plan 恒为零值）
    Dropped    int64     // Swap 执行后事务内实测移出数
}
Plan(ctx, db, runID, day) (SwapPlan, error)        // 只读
Swap(ctx, db, runID, day) (SwapPlan, error)        // 重建该日分区（会删行）
Restore(ctx, db, runID, day) (int64, error)        // 把该日冷事件批量物化回 events（幂等）
```

### 10.1 集合定义：删什么、留什么

```
H = 本次锁定的当日日分区热事件集合
C = 本 run/day 已验证冷块对应的原始事件集合（= 该日该 run 的 locator 成员）
S = 本 run 的类别、来源范围
P = 本次受保护的证据事件集合（PinnedIDs，事务内重读）

D = H ∩ C ∩ S − P      # 本次实际删除集
K = H − D              # 本次实际保留集
```

保留口径（`keepSelect`）与归档口径共用同一份谓词（`scopePredicate`），三条判定互补穷尽：

| 行 | 条件 | 去向 |
|---|---|---|
| 被 pin（`id IN (PinnedIDs)`，锁内重读） | 证据保护 | 留热 |
| 口径外（非本 run 的类别/来源） | 不属于本次归档 | 留热 |
| **没有本 run 的冷副本**（不在 locator 里） | shadow 之后到达、或单条超 4 MiB 没进冷块 | **留热**（不再要求整日计数相等） |
| 口径内 ∧ 未 pin ∧ 有本 run 冷副本 | D | 移出热表 |

由此：无冷副本的行（超大、shadow 后到达）自动留热，swap 不再被「冷块条数 == 待移出条数」的
整日门禁阻断；事务外的 `coldCount` 预检只把差额写进 `detail.days` 的 `note` 供运维解释
「计划移出 N、实际移出 M」的差。**plan 是观察值，不是冻结快照**；swap 输出事务内实测结果
（`Kept` / `Dropped`），不用旧计划冒充实际计数。事务内核对后没有可删行时明确报「无需切换」，
不反复重建分区。

### 10.2 拒绝条件（任一不满足就拒绝，一个字节都不动）

| 条件 | 为什么 |
|---|---|
| run 不存在，或 `status != verified` | 没对拍通过的归档不能当删除依据 |
| `day` 不在 run 的 `day_from..day_to` 内 | 范围外的一天没有「本 run 的归档」可言 |
| 该日没有独立日分区（行在 `events_default`） | 本流程**不**去默认分区搬行，报错要求先 `EnsureDays`；退役后同日再 swap 也因此明确拒绝 |
| `Plan.Archived == 0` | 口径内连一个候选都没有 |
| P4 切换闸门（Guard）不放行 | 见 10.3；拒绝信息带日结束、有效下限数值与各消费者原因 |
| 同日分区的重写已被另一个操作持有（advisory try 锁） | 见 10.4 的并发语义 |

### 10.3 P4 切换闸门：min-age 有效下限与消费者追平

swap 把一天移出热表前要过两道只读闸门（`Plan` 附带评估供人核对，`Swap` 据此拒绝）。

**有效下限（年龄项）**：`日结束 ≤ now − effective`，其中

```
effective = max(适用项取最大):
  min-age    EVENT_ARCHIVE_MIN_AGE_DAYS（默认 14 天），运营下限，总是适用
  temporal   max(规则目录实际最大窗口, 24h) + LateGrace(2h) + pruneSlack(10min)
             （规则目录读不到时退保守常量 24h + LateGrace + 1h，与 janitor retireGuard 同口径）
  beacon     max(BEACON_LEARNING_DAYS, BEACON_WINDOW_HOURS)（默认 7d / 12h），仅口径含 4001+agent
  assetmap   7 天无游标回填常量（assetmap.backfill），仅口径含 4001/5001/5020
```

年龄判定用**日结束**（次日零点），不是日开始；各项是否适用由它与 run 口径是否相交决定，
不相交的消费者不会无谓挡住无关口径的 run。配置值解析失败直接报错，不静默退默认。

**消费者追平（进度项）**：口径相交的消费者都要有越过待切日的**持久**进度（`ConsumedThrough`，
只读汇总）。每个进度证明什么、不证明什么，逐个写明：

| 消费者 | 进度 | 证明 | 不证明 |
|---|---|---|---|
| beacon | `beacon_baselines` 的 `min(first_seen)` | 外联检测至少在 first_seen 处理过出站连接并留下持久基线 | 当前游标位置（重启回退到 now−窗口）；[first_seen, now] 之间是否都已消费 |
| assetmap | `settings[assetmap.cursor]`（与事件同事务落库） | 4001/5001/5020 已物化进资产画像与依赖边到该时间 | 游标之后的事件；无 settings 行（unknown）时是否从未跑过还是回填没落 |
| ueba | `process_baselines` 的 `max(first_seen)` | 1007 至少被读到该时间（引擎从它恢复游标，只往前读） | 精确游标（批次无新组合时该值落后，按它拒绝是保守方向） |
| automation | `ssh_logins` 的 `max(ts)` | 近窗口内有登录被收进过 ssh_logins | 非登录的 3002 事件；窗口外的行已删 |

**unknown 的方向是拒绝**：任一相关消费者没有持久进度可读就拒绝切换——swap 是热表行的不可逆移出，
unknown 放行的失败模式是基线/检测缺口（静默、事后不可补），拒绝的失败模式只是晚切一天。

### 10.4 事务边界与并发

`Swap` 经 `eventpart.RewriteDayGuarded` 在**单个事务**里完成：

1. `SET LOCAL lock_timeout='3s'`；事务内先取 **advisory try 锁**
   （`pg_try_advisory_xact_lock(hashtext('openxdr:eventpart:rewrite:'||day))`，不等待）：
   同一分区的重写一次只允许一个，第二个并发操作**立即明确拒绝**，而不是靠后面的 DDL 锁超时兜底。
   `retire` 不取这把锁——它与 swap 的串行化由分区 DDL 的锁顺序保证。
2. 对日分区 `LOCK TABLE … IN SHARE MODE`（读照常，该日迟到写入等待）；
3. 建暂存表 → 复制保留行 → `cloneIndexes`（与 retire 共用，不在排他锁窗口建索引）；
4. **锁内集合校验（swapVerify，复制后与分区替换前各跑一次）**，同一条 SQL 取一致快照：
   a) 事务内重读 P（SHARE 锁挡得住该日 events 写入，挡不住 alerts 等引用表的并发 INSERT，
   pin 只能在锁内重读才作数）；b) 确定 D（口径 ∧ 未 pin ∧ 在本 run locator 里）；
   c) 核对暂存表 == H − D（差集非空报首个差异 id）；d) 断言 D ⊆ locator（要删的行全有冷副本）。
   任一步失败整体回滚，原分区一行不动。
5. 派生状态按 10.5 的决策表清理；`DETACH → DROP → RENAME → ATTACH` 同一事务；
6. **逐日记账与分区替换同一事务**（见 10.6），提交结果要么「分区已换 + 记录已写」，要么都没发生。

PostgreSQL 的 DDL 是事务性的：任何一步失败（索引建不起来、DROP 有依赖、ATTACH 校验不过、
客户端断开、提交失败）都整体回滚，原分区连同索引、触发器、分区边界原样保留。终检把并发 pin 的
竞态窗口压缩到 `[终检, commit]`；终检之后到达的引用最多指向删除集（已有冷副本）里的行。

### 10.5 派生状态决策表

重写的派生清理只删「随本次切换被移出热表」的事件对应的派生行；保留行的派生行一律不动。
swap 与 retire 的口径**不同**，逐表决策（V09）：

| 表 | swap 是否清 | 依据 |
|---|---|---|
| `temporal_matches` | 清 | 默认口径 4001/4003 不产生行（no-op）；扩到 3002 前重新评审 |
| `temporal_candidates` | 清 | Guard 的 temporal 项保证被删候选已超出所有在线版本的求值范围（安全条件是「已失效」，不依赖异步 Prune 已执行） |
| `temporal_evaluation_gaps` | **不清** | 诊断记录，有真实读者（`GET /api/temporal-gaps`）；swap 顺带删会让缺口清单在保留期前静默缩水。清理链路（R6）：retire 的「日分区 − 暂存」差集清理与逐行删除触发器都看不到已被 swap 移出热表的事件的 gap，这类 gap 由 janitor 按 gap 自身 `created_at` 的诊断保留期（`TEMPORAL_GAP_RETENTION_DAYS`，默认 30 天，0 关闭）清理，不 JOIN events；仍留在日分区里的事件的 gap 照旧随 retire 差集清理 |
| `temporal_detections` | 清 | 已出告警的检测锚点在 PinnedIDs 里被保留；能删到的只有被抑制的检测，与 retire 同口径 |
| `identity_observations` / `identity_local_snapshots` | 清 | 默认口径下 no-op；扩口径前重新评审（读者 JOIN events） |

### 10.6 逐日记录：`detail.days` 与对账

每个 run 的 `detail.days.<UTC 日>` 记**那一天**的实际切换结果：

```json
{"swapped_at":"…RFC3339…","kept":N,"dropped":M,"run_day_verified":true,"note":"预检差额说明（可省略）"}
```

- 写入用 `jsonb_set` 合并进 `{days}` 对象：**同 run 多日互不覆盖**，重复切换同一日覆盖该日自己的记录；
- 与分区替换**同一事务**提交，不存在「分区已切成功、成功记录单独写失败」的窗口；
- 预检发现「口径内未钉住 N 行、冷块 M 行」的差额时写进 `note`，解释计划与实测的差。

对账方法：`eventarchive status -run <uuid>` 直接把逐日记录排出来（见 10.8）；手工对账用
`detail.days.<day>.kept + dropped` 对照该日分区切换前后的行数，`dropped` 对照该日该 run 的
`sum(event_count)`（冷块条数），`kept` 对照分区现存行数。

### 10.7 restore：批量物化，不是精确撤销

`Restore(run, day)` 的目标是该 run/day 的 **C 集合**（该日该 run 的全部冷块成员），不是某次 swap
的 D：

```
swap 后：     H − D
restore 后：  (H − D) ∪ C
```

- **按块批量物化**：每块只 load/Decode/check 一次，随后在**单事务**里用一条 typed unnest 的
  `INSERT … ON CONFLICT DO NOTHING` 写回整块（10 列，参数个数与块内条数无关）。
  已在热表的行被跳过并如实计数——「后来被 pin、从未删除的事件」被遍历到时跳过是正常幂等。
- **块级原子**：当前块解码、校验或写入失败只回滚该块，此前已提交的块保留；返回
  `(已插入数, 错误)` 两者同时有效（部分完成）。错误带块 id 与原因。重跑靠主键幂等继续，
  不需要进度账本。
- 幂等：同一稳定环境下第二次 restore 插入 0 行；若 janitor 在两次调用之间删了行，不适用该断言。
  swap 删除数与 restore 插入数**无需相等**（物化 C，不是撤销 D）。
- 不经过检测器：不产规则命中、不产告警、不改任何派生表；不回写冷块。
- **资产外键显式失败**：冷事件 `asset_id` 指向已删除资产时，该块整块回滚，错误含外键
  （`events_assets_events`）与块 id，**不静默改写 asset_id、不跳坏块**；其余已完成块保留。
  修复原因（如重建同 id 资产）后幂等重跑补齐。若要恢复这类历史资产的语义，单独确定，不在
  restore 里猜。
- **规模实测**（一次性环境，外推需重测）：45 万行单次 restore 18.4s ≈ 24,457 行/s，
  环境 PostgreSQL 16 / arm64 容器。等规模（单日 260 万行、1143 块）已在演练中实测——
  restore 123.1s、swap 37.7s、Exists 未命中 p50=2.5ms，见
  [archive-rehearsal-2026-10-30.md](archive-rehearsal-2026-10-30.md)；换环境后重测。

### 10.8 三类校验分开 + `status`

对一个 run 有三种时间点不同、含义不同的「状态」，不能塞进一个值：

1. **构建期对拍**（`verify`）：`run.status == verified`，粘性资格——证明「对拍那一刻冷块与热表
   逐字段一致」，不证明此后仍一致；
2. **冷副本自校验**（现在时刻）：逐块 Decode + 头部/摘要核对 + locator 成员集合核对。证明「此刻
   块自洽、索引对得上块」，不证明与热表一致（swap 后热行已删，对拍口径本来就不成立）；
3. **操作记录**（`detail.days`）：证明「那一天真的切过、事务内实测多少」，不证明冷块当前健康。

`eventarchive.RunState(ctx, db, runID)`（只读）把三者各自汇总；CLI `eventarchive status -run <id>`
打印。典型组合的读法：

| 组合 | 含义 |
|---|---|
| verified + 自校验通过 + 已操作 | 正常 |
| verified + **自校验失败** + 已操作 | 对拍之后冷块被改坏（如 payload 损坏）——按块 id 定位原因，评估影响；`status` 不会回退，避免把「曾经合格」误读成「现在合格」 |
| verified + 自校验通过 + 无操作 | 可切还没切 |
| building + 自校验通过 | 还没对拍，不能作为删除依据 |

自校验要解压整个 run，代价与归档条数成正比（同 `report`），大 run 低峰期跑。

### 10.9 生命周期：swap → retire → restore 的规范顺序

```
日分区仍存在：
  shadow → verify → plan → swap → 可选 restore
                                   ↓
热保留期到期：                    retire（eventpart.Retire，janitor 同一入口）
                                   ↓
日分区已不存在：             可选 restore（按当前分区路由）
```

不变量（P6 逐条验证，`p6_lifecycle_integration_test.go`）：

- **同一天要 swap 必须在 retire 前完成**；retire 不无限等待 shadow/swap，继续执行既有保留策略。
- 没赶上 retire 的热行不能再靠 shadow 恢复（shadow 按 events 扫描，行已随分区消失就扫不到）；
  已有冷副本仍可读。
- **退役后同日再 swap 明确拒绝**（没有独立日分区可重写）。
- **retire 后 restore 仍允许**：恢复行按当前分区路由——覆盖该日的月归档分区
  （`events_aYYYYMM`，退役时由 pin 行带出）优先；该日无覆盖分区（如该日从无日分区、退役也没
  推进到它）时落默认分区 `events_default`。用 `tableoid` 断言过（T21/T22）。
- **restore 不撤销退役**：不重新创建与月归档重叠的日分区；**不重置热保留期**：恢复行带着原始
  `ts` 回来，对保留期立即再次到期——janitor 再跑一轮保留期清理时，非 pin 的恢复行会被再次删除，
  被 pin（告警/时序证据引用）的行保留。
- **swap 后该日再次 shadow 不会重复归档**：shadow 只扫 events，已移出的行天然扫不到；
  两个 run 主动覆盖同一天形成的**重叠副本**合法（Locate 任一命中），但重叠副本计入成本、
  节省不重复计算（第 6 节）。
- 删除冷块前须确认它不是所需原始事件的**唯一副本**；locator 随块 `CASCADE`。restore 成功
  不是删除冷块的理由。

### 10.10 重传判重接线（`EVENT_ARCHIVE_DEDUP`）

`swap` 把行移出热表之后，`INSERT ... ON CONFLICT DO NOTHING` 再也看不到它们：迟到或重传的
老事件会被当成新事件重新入库、重新检测。`EVENT_ARCHIVE_DEDUP=1` 才把冷层的存在性判断接进
接入路径（`ingest.Processor.Archive`，默认 `nil`，不设时接入路径一行都不多跑）。

**依赖方向**：`ingest` 不 import `eventarchive`，只定义最小接口 `ingest.ArchiveDedup`
（`Archived` + `ArchiveBoundary`），适配器在 `main.go`；`eventarchive` 不知道自己在被谁调用。

**时间闸门 + 60 秒缓存**：只有 `envelope.Timestamp <= 归档中最晚的 last_ts` 时才查冷层；边界走
`ingest.CachedArchive` 的 60 秒 TTL。缓存放 `ingest` 侧：一份会过期的边界不能被冷读、覆盖度统计
或证据物化复用。

**插入点：先查后插，紧接在 `INSERT ... ON CONFLICT` 之前**。命中冷层就按重复处理（`stored=false`，
不入库、不检测、不产告警）。不选「插入后再删」：检测副作用已经发生，删掉事件行回滚不了它们。

**失败策略：fail-open**。`Archived` 返回错误（块损坏、库不可用）或边界读不到时照常入库并继续
检测：把「无法确认」当成「已归档」会**永久丢掉一条真实事件**；重复告警最多被告警侧去重窗口吸收。
每次 fail-open 计入 `openxdr_archive_dedup_failopen_total{stage}` 并限流记日志。冷归档表不存在
同样 fail-open。多节点各自缓存边界，切换后最多 60 秒的窗口内重放刚切走的事件会重新入库
（不会丢事件）；低峰手工切换后等一个缓存周期即可。

**这条判重实际覆盖哪些事件**：被 `alerts` / 时序证据钉住的事件不进冷块、也不被 swap 移走，
它们的重放仍由 `ON CONFLICT` 挡住。真正依赖冷层判重的是「归档时没有告警」的旧事件。

**运营不变式**：

1. **一旦开始用 `eventarchive swap` 切走分区，server 的 `EVENT_ARCHIVE_DEDUP` 必须为 `1`**，
   否则重放会重复入库、重复告警。
2. **`EVENT_ARCHIVE_READ` 同样必须有效**：已有切走数据的部署不能通过关闭读取悄悄变成
   「查询完整」——缺口还在，只是不再被如实声明（CLI 的 swap 成功输出会提醒，但 CLI 读不到
   server 的环境变量）。
3. 两者相互独立：一个管 `/api/events` 与调查入口的冷读，一个管接入判重，各开各的。

## 11. 命令行速查

```
DATABASE_URL=... eventarchive <子命令>

  ensure-schema                                     建三张冷归档表（幂等）
  shadow -from YYYY-MM-DD -to YYYY-MM-DD [选项] -confirm
                                                    影子归档：只读 events 写冷块（会写库）
       -classes 4001,4003     归档类别（默认 4001,4003）
       -sources agent,sensor  来源（默认范围内全部）
       -chunk-events 2048     单块事件条数上限
       -chunk-bytes 1048576   单块未压缩明文字节上限
  verify -run <uuid>                               重扫对拍，通过后置 verified
  status -run <uuid>                               三类状态分层：对拍资格 / 当前自校验 / 逐日记录
                                                   （只读；自校验要解压全部块，大 run 低峰跑）
  backfill-locator [-confirm]                      报告缺口块数；-confirm 才逐块回填 locator 行
                                                   （一次性迁移，幂等；前提见 8.4）
  report -run <uuid>                               归档前后大小、压缩比与含索引对比
  locate -id <uuid>                                按事件 ID 找一条冷事件（只读）
  materialize -id <uuid> -confirm                  把一条冷事件物化回 events（幂等，不产告警）
  plan -run <uuid> -day YYYY-MM-DD                 单日切换计划（只读估计，实际以事务内实测为准）
  swap -run <uuid> -day YYYY-MM-DD -confirm        重建该日分区：只保留钉住的、非归档口径的、
                                                   没有冷副本的行（唯一删数据的环节）
  restore -run <uuid> -day YYYY-MM-DD -confirm     把该日冷事件批量物化回 events（幂等，块级事务）
```

`shadow` / `materialize` / `swap` / `restore` / `backfill-locator` 会写库，不加 `-confirm` 直接拒绝
（没有演练模式）；`verify` 只改 run 的状态列；`ensure-schema` 只建表；`locate` / `plan` / `status`
只读。失败一律非零退出码。与其他运维命令（`cmd/eventpartition`、`cmd/backtest`）一样，二进制要放进
能连到主库的环境里跑。

## 12. 已验证的内容

单元测试（无 DB）：

- 冷块编解码（`chunk_test.go`）：全字段往返（NULL 可空列、Unicode/转义 raw、微秒精度）、空块拒绝、
  头部逐项篡改必报错、载荷截断、超上限先拒绝后解码、不可压数据退化 `codec=0`、两次编码字节一致。
- 冷查询（`query_test.go`，内存块）：过滤边界、`AssetIDs` 的 nil/空集合语义、去重倒序、`Limit`、
  坏块整体报错、200 块预算、`Truncated` 与 `ScanIncomplete` 两种缺口的区分。
- Bloom（`lookup_test.go`）：零漏报（n=1..5000 全量断言）、假阳性实测 ≈1.55%、非 8 字节对齐按
  「没有过滤器」处理。

集成测试（专用库，`-tags integration -p 1`）按阶段：

- **P0 基线**（`p0_baseline/p0_counterexamples`）：字段保真、restore 目标基线、超大事件留热、
  retire 后路由现状；T01/T02 反例（计数抵消与检查后写入在旧实现下静默丢行——P3 修复的依据）。
- **P1 批量恢复**：整块批量保真（NULL vs 空串、260 KiB raw、同 ts 不同 id）、最大块
  （8192 条一事务）、**块级失败与重跑**（第 2 块改坏 → 第 1 块保留 + 错误带块 id → 修复后补齐 →
  再跑 0 行）。
- **P2 locator**：块/locator/计数三者原子（注入点回滚）、缺行/多行/错指块的集合校验、老块回填
  （幂等、中断重跑、空库）、跨 run 多副本定位、执行计划走索引。
- **P3 原子切换**：pin 竞态三时点（锁内重读挡住 → 整体回滚）、swap/swap、swap/restore、swap/retire
  的并发串行化、复制/建索引/替换前失败的原子回滚、提交未知、无 TODO 窗口的逐日记录。
- **P4 闸门**：min-age 有效下限（日结束判定、0 时 temporal 边界仍生效）、消费者 unknown 拒绝与
  追平放行、beacon/assetmap 的 swap vs 全热对照（基线与依赖边集合一致）、temporal 候选与
  派生表逐项按决策表。
- **P5 覆盖度与调查入口**：关键词跨归档天、冷读关闭、预算耗尽时 `truncated` 与 `scan_complete`
  双真且相互独立、冷事件调查权限三视角（admin/组内/无组）与零物化、热冷同时间排序去重。
- **P6 生命周期**（`p6_lifecycle_integration_test.go`）：T21 完整链
  （swap → retire → restore → janitor 真实入口再清理 → 再 shadow 不重复归档）、T22 多日逐日记录
  互不覆盖、退役后再 swap 拒绝、restore 的月归档/default 双路由、重叠 run、部分恢复 + 资产外键
  显式失败与重跑、RunState 三态区分（verified → payload 改坏 → 已操作）。
- 读取与判重（`query_*` / `swap_integration` / ingest 的 `archive_*`）：合流与组权限、覆盖度头、
  坏块 500、冷层不可用时行为不变、切走后重放不重复入库不产告警、fail-open 可观测。

## 13. 已知限制与后续

- **冷块不是 WORM**：摘要与载荷同库同行，有写权限的攻击者可以同时改掉两者而不被发现；块
  SHA256 只覆盖意外损坏，不提供防篡改证明。取证级防篡改（WORM/签名链/跨块哈希链）是独立后续。
- **冷保留与容量预算没有自动化**：没有自动清理器；试点必须先明确冷数据保留范围、最大占用与
  到达上限停止新增归档的操作规则，不能无预算长期积累。按 run 手工删块（`DELETE FROM
  event_archive_chunks WHERE run_id=…`，locator 随块 CASCADE）前须确认不是唯一副本。
  等规模的空间/延迟/锁已在演练中实测（260 万行单日，见
  [archive-rehearsal-2026-10-30.md](archive-rehearsal-2026-10-30.md)），但**空载容器、无并发业务负载**；
  生产锁等待与并发延迟须在试点时重测。
- **审计缺失**：冷读、物化、切换、还原都没有独立审计事件；操作结果记录（run.detail / detail.days）
  与正确性证明有，但「谁在什么时候做了什么」没有。审计产品化是独立后续。
- **外部 SQL 直查组视图只覆盖热表**：Pi 的 query 与 queryrole 组视图都不含冷数据（每次结果带
  静态声明）；关键词检索同样不进冷层（`reason=keyword_not_searched`）。扩大覆盖需独立设计
  （冷层关键词索引 / 组视图扩展），当前如实声明缺口。
- **`temporal_evaluation_gaps` 按 `TEMPORAL_GAP_RETENTION_DAYS` 清理（R6）**：swap 不清（诊断记录
  有读者）；retire 只能清仍留在日分区里的事件的 gap，swap 已移出热表的事件的 gap 由 janitor 按
  gap 自身 `created_at` 的诊断保留期清理（默认 30 天，0 关闭）——依据诊断时间而非事件时间
  （旧事件迟到新产生的 gap 不因事件过期），不 JOIN events。
- **阶段 C 只在测试库验证过**：切换是分区 DDL（父表排他锁的窗口在 `DETACH`/`ATTACH` 期间），
  需要低峰窗口、需要先 `verify`、需要消费者追平；生产试点前按 `COLD_ARCHIVE` 方案的部署顺序执行。
- **同一条事件多轮 run 归档时**，`Locate` 返回先解到的那份副本，不比较副本差异；每个 run 的副本
  一致性由该 run 的对拍负责。节省量不得按 run 相加（第 6 节）。
- **`report` / `status` 要解码全部冷块**：耗时与归档条数成正比，大 run 低峰期跑。
- **`X-Archive-Coverage` / `X-Truncated` 头是调试摘要**：真源是响应体 `coverage`；调试期结束后
  头会移除。
- **边界缓存 60 秒**：各节点独立；切换/新归档后最多 60 秒内重放仍可能被判成新事件（不会丢事件）。
  按 run 删块会让边界回退，也落在缓存滞后窗口里。
