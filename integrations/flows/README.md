# ntopng / nProbe 流量接入

接收标签式 JSON 流量，归一化为 `class_uid=4001`，进入现有规则、情报、降噪与落库链路。
这不是 NetFlow / IPFIX / sFlow 二进制监听器，也不连接 ZMQ；已有 nProbe 可先把这些协议转为 JSON。

## 配置和导入

1. 在控制台「系统集成」创建并启用集成，授权 `flows:write`，绑定且仅绑定一个组。
2. 签发包含 `flows:write` 的 Token。Token 只显示一次，保存在转发端的密钥配置中。
3. 准备每行一个 JSON 对象的文件。ntopng 日志可以带 Syslog 头；脚本取第一个 `{` 开始的 JSON。
4. 使用 Python 3 标准库工具导入：

```bash
# 用环境变量提供 Token，不放进命令行或仓库
export OPENXDR_INTEGRATION_TOKEN='替换为控制台签发的 Token'
python3 integrations/flows/import.py --server https://xdr.example.com --source ntopng flows.jsonl
# nProbe 对应 --source nprobe
```

导入工具逐行确认；失败时返回非零、指出行号并停止，不改输入文件。修正后可整文件重传。
工具要求 HTTPS，使用系统 CA 验证服务端，不跟随重定向。大量实时接入时可由现有转发器调用下方 HTTP 接口，
并持久保存尚未得到确认的记录；此脚本用于文件导入，不提供实时 tail 或后台守护。

## HTTP 契约

`POST /api/integration/v1/flows/ntopng/events` 或 `/api/integration/v1/flows/nprobe/events`，
使用 `Authorization: Bearer <Token>` 和 `Content-Type: application/json`，body 为一条原生 JSON。
最多 256 KiB；持久队列确认后返回 202，尚未完成最终落库。503 应保留原报文重试，400 应修正字段，403 应检查授权。
不同来源、组、集成或内容不会合并；相同 JSON 仅空白和顶层键顺序变化仍是幂等重传。

必需字段：

| 字段 | 含义 |
|---|---|
| `IPV4_SRC_ADDR` / `IPV6_SRC_ADDR` | 源地址；IPv4 缺失或 0.0.0.0 时取 IPv6 |
| `IPV4_DST_ADDR` / `IPV6_DST_ADDR` | 目的地址；同上 |
| `PROTOCOL` | IP 协议号 0..255；6 TCP、17 UDP、1 ICMP、58 ICMPv6 |
| `L4_SRC_PORT` / `L4_DST_PORT` | TCP / UDP 必需，0..65535；其他协议缺失时记 0 |
| `FLOW_START_SEC` | 首包 epoch 秒；可用 `FLOW_START_MILLISECONDS` 的 epoch 毫秒替代，毫秒优先 |

ntopng Syslog JSON 可使用 `FIRST_SWITCHED` 的 epoch 秒作为首包时间。
**nProbe 不接受 `FIRST_SWITCHED` 作为绝对时间**，该字段在其协议定义中是 uptime。
请在 nProbe 模板中导出 `%FLOW_START_SEC` 或 `%FLOW_START_MILLISECONDS`，并启用标签式 JSON。
不同版本的导出命令以安装版本的 `nprobe -h` 为准。

可选 `IN_BYTES` / `OUT_BYTES` / `IN_PKTS` / `OUT_PKTS` 为无符号 64 位整数，
分别归一化为 `traffic.bytes_out` / `bytes_in` / `packets_out` / `packets_in`；不猜缺失计数。
完整原始字段保留在 `raw.flow` 中，包括未归一化的应用协议、接口与导出器字段，大整数不经过浮点转换。

示例（时间需按实际流量填写）：

```json
{"IPV4_SRC_ADDR":"192.0.2.1","IPV4_DST_ADDR":"198.51.100.2","L4_SRC_PORT":12345,"L4_DST_PORT":443,"PROTOCOL":6,"FLOW_START_SEC":1794000000,"IN_BYTES":1024,"OUT_BYTES":2048}
```

## 归属与检索边界

来源组、observer 只取集成授权。仅当接收时间距首包时间不超过五分钟，且授权组内对应 IP 恰好属于一台当时在线资产，
才归属该资产。优先源端，未匹配时再看目的端；重复 IP 不猜具体资产，不生成进程归属。
消费时再次核对组，避免排队期间资产转组造成越权归属。未匹配与历史导入的流量只允许全局管理员检索。
当前不拆分双端资产证据、不按原始流量字段自动生成设备资产。

控制台「日志检索」选 `ntopng` / `nprobe` 来源，支持 IP、端口与时间范围过滤。

官方格式参考：[ntopng Syslog JSON](https://www.ntop.org/guides/ntopng/flow_dump/syslog/index.html)、
[nProbe Information Elements](https://www.ntop.org/guides/nprobe/flow_information_elements.html)。

## 已验证的原生导出

官方 ntopng 7.0.261106 镜像处理 10 包离线 PCAP，实际导出 HTTP / DNS 两条会话。
原始 JSON 已保存在 [原生样本](../../server/internal/flowinput/testdata/README.md)，并作为 Go 回归用例使用。
该样本经 HTTPS 导入工具落库，重复导入和带 Syslog 头导入后仍只有两条记录；
另验证了错误行停止、拒绝重定向、拒绝明文 HTTP 与撤销 Token 后拒绝写入。

官方 nProbe 11.2.261106 镜像在没有许可证时拒绝执行。当前 nProbe 接口有协议、权限、
归属和幂等测试，原生设备导出联调需要合法许可证，不能用构造 JSON 代替这项验收。
