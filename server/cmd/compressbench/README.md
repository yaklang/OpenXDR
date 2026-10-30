# compressbench

测量 OpenXDR 事件批次在不同压缩算法下的字节成本与吞吐，作为日志压缩优化的
「优化前后对比」基线。纯离线工具：只读事件或合成数据，不连接数据库、不写生产路径。

## 用法

```bash
cd server
go run ./cmd/compressbench --source agent --n 20000
go run ./cmd/compressbench --source sensor --n 20000
go run ./cmd/compressbench --source agent --input events.ndjson --batch 128,500 --out result.csv
```

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--source` | `agent` | `agent` 或 `sensor`；决定合成画像与 protobuf 消息类型 |
| `--input` | 空 | NDJSON 文件，每行一个 `events.raw` JSON 对象；提供时用真实数据并忽略 `--n` |
| `--n` | `50000` | 无 `--input` 时合成的事件数 |
| `--batch` | `128,500` | 逗号分隔的批大小（事件数）；最后一批可以更小，重复项只保留一次。500 对应 agent 本地 spool 的 `MAX_BATCH_EVENTS` |
| `--out` | 空 | 可选 CSV 输出路径 |
| `--seed` | `1` | 合成数据随机种子，同一 seed 逐字节复现 |

## 未压缩表示

| source | representation | 内容 |
|---|---|---|
| agent | `raw_json` | 一批事件的 `raw_json` 以换行连接（末尾不加换行），镜像落库/Envelope 形态 |
| agent | `protobuf` | 每条事件 marshal 成 `pb.AgentEvent`，按 `StoredBatch.events`（字段 1）的 length-delimited 形式拼接 |
| sensor | `protobuf` | 每条会话 marshal 成 `pb.FlowRecord`，按 `FlowBatch.flows`（字段 2）的 length-delimited 形式拼接 |

sensor 没有 `raw_json`，因此只测 protobuf 表示。

每条 protobuf 记录的批内编码为 `field tag + varint 长度 + 消息体`，与 agent 本地
`StoredBatch` / sensor 线上 `FlowBatch` 的 repeated 字段同形，包含真实的 tag 开销。

## codec

| 表内名称 | 实现 | 级别 |
|---|---|---|
| `none` | 恒等拷贝 | 基线，压缩前后字节相同 |
| `gzip` | 标准库 `compress/gzip` | 默认级（`gzip.DefaultCompression`） |
| `zstd-1` | `github.com/klauspost/compress/zstd` | zstd level 1（`SpeedFastest`） |
| `zstd-3` | 同上 | zstd level 3（`SpeedDefault`） |
| `lz4` | `github.com/pierrec/lz4/v4` | frame 格式，默认参数 |

## 指标口径

- **ratio = 未压缩表示字节 / 压缩后字节**。分母是压缩后字节；`none` 恒为 `1.0`，
  且 `compressed_bytes == uncompressed_bytes`。
- `compress_mbps` / `decompress_mbps` = 总未压缩字节 / 墙钟时间 / 1,000,000
  （MB 按 10^6 字节计）。吞吐是单次墙钟计时，适合同机前后对比，不作为跨机绝对性能结论。
  单批只有几百字节的极小输入会受时钟分辨率限制；那种规模只用于功能验证，不用于比较吞吐。
- `lossless`：每批都断言 `decompress(compress(x)) == x`。任一批不一致立即报错并以非零码退出，
  不会静默跳过或放宽。
- `batches` 是实际批数（含最后一批不足 `batch_events` 的情况）。
  由于 `raw_json` 只在批内加换行，不同批大小的 `uncompressed_bytes` 会相差少量换行字节。

## 合成数据

**合成数据只是指示性的，不能代表生产负载；权威数字必须用 `--input` 喂真实数据。**

agent 画像按 `docs/events.md` 的字段形态生成，类别比例约为：

| class_uid | 类别 | 比例 |
|---|---|---|
| 1007 | 进程启动/退出 | 55% |
| 4001 | 网络活动 | 25% |
| 4003 | DNS 活动 | 12% |
| 1001 | 文件活动 | 4% |
| 3002 | 认证 | 2% |
| 1005 / 5001 | 模块 / 设备清单 | 各 1% |

字段包含固定 `agent_id`、轮转复用的 pid、重复的可执行路径
（`/usr/bin/bash`、`/usr/sbin/sshd` 等）、按路径确定的高熵 SHA-256、随机进程 GUID、
变化的 `cmd_line`，以及 1007/4001/4003/1001/3002/1005/5001 各自的 OCSF 形态。
`pb.AgentEvent` 同时带 `ts_unix_ns`、`class_uid`、`process_guid`、`parent_process_guid`、
`username`、`conn_tuple`、`raw_json`。

sensor 画像生成 `pb.FlowRecord`：双向 packets/bytes、TCP flags、重复的内网/公网 IP 与端口、
部分 TLS SNI/JA3/JA3S/证书、HTTP host/uri/user_agent、DNS query/answers。

同一 `--seed` 生成完全相同的字节序列，便于优化前后用同一份数据回放。

## 用真实数据

`--input` 每行是一个 `events.raw` JSON 对象。用 PostgreSQL 导出（示例为最近一天）：

```bash
psql "$DATABASE_URL" -c "\copy (SELECT raw FROM events WHERE ts > now()-interval '1 day') TO STDOUT" > events.ndjson
go run ./cmd/compressbench --source agent --input events.ndjson
```

sensor 数据用 `WHERE source = 'sensor'` 过滤，并加 `--source sensor`。

COPY 文本格式会转义反斜杠（Windows 路径常见），导出的行字节会比库内多。需要严格对齐
库内字节时改用不转义的对齐模式输出（`events.raw` 是单行 JSON，不会破坏 NDJSON）：

```bash
psql "$DATABASE_URL" -At -c "SELECT raw FROM events WHERE ts > now()-interval '1 day'" > events.ndjson
```

已知边界（因为 `events.raw` 本身不含 events 表的独立列）：

- agent 输入：工具只在行内存在时读取 `agent_id` / `ts_unix_ns` / `class_uid` 等信封字段，
  并由事件体回填可证明的 `process_guid`、`parent_process_guid`、认证用户名与 `conn_tuple`。
  生产 raw 通常没有这些信封列，所以 protobuf 表示会少算少量信封字节。
- sensor 输入：`events.raw` 里有 `duration_ms` 但没有会话起止时间，工具令
  `start_unix_ns=0`、`end_unix_ns=duration_ms`，因此 protobuf 字节数略低于线上原始记录。
- `--source` 必须与数据来源一致；把 agent raw 喂给 sensor 会因缺少
  `connection_info.protocol_num` 直接报错，不会产出假数据。

## 输出

标准输出是人类可读表格，`--out` 另写一份 CSV。列：

```
source, representation, batch_events, codec, batches, uncompressed_bytes,
compressed_bytes, ratio, compress_mbps, decompress_mbps, lossless
```

## 测试

```bash
cd server
gofmt -l ./cmd/compressbench
go vet ./cmd/compressbench/...
go test ./cmd/compressbench/...
```

测试覆盖每种 codec 在 agent/sensor 合成批上的无损往返、ratio 的字节口径、
`none` 的 ratio==1.0 与字节相等、`--seed` 可复现，以及两种 `--input` 行的解析。
