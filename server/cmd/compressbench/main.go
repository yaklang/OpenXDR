// compressbench 测量 OpenXDR 事件批次在不同压缩算法下的字节成本与吞吐。
//
// 纯离线工具：读 NDJSON（events.raw）或按 --seed 合成事件，按 --batch 分组，
// 对 raw_json / protobuf 两种未压缩表示分别跑 none / gzip / zstd-1 / zstd-3 / lz4，
// 输出字节数、压缩比与压缩/解压吞吐。每批都做无损往返校验，不一致立即失败。
//
// 用法: go run ./cmd/compressbench [--source agent|sensor] [--input events.ndjson] [--n 50000] [--batch 128,500] [--out result.csv] [--seed 1]
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"openxdr/server/pb"
)

var tableHeaders = []string{
	"source", "representation", "batch_events", "codec", "batches",
	"uncompressed_bytes", "compressed_bytes", "ratio",
	"compress_mbps", "decompress_mbps", "lossless",
}

func main() {
	source := flag.String("source", "agent", "数据画像：agent 或 sensor（同时决定 protobuf 消息类型）")
	input := flag.String("input", "", "NDJSON 文件，每行一个 events.raw JSON 对象；提供时用真实数据，忽略合成")
	n := flag.Int("n", 50000, "无 --input 时合成的事件数")
	batchList := flag.String("batch", "128,500", "逗号分隔的批大小（事件数）；最后一批可以更小")
	out := flag.String("out", "", "可选的 CSV 输出路径")
	seed := flag.Int64("seed", 1, "合成数据随机种子，保证可复现")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "compressbench: 不接受位置参数: %s\n", strings.Join(flag.Args(), " "))
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*source, *input, *n, *batchList, *out, *seed); err != nil {
		fmt.Fprintln(os.Stderr, "compressbench:", err)
		os.Exit(1)
	}
}

func usage() {
	w := flag.CommandLine.Output()
	fmt.Fprint(w, `compressbench 测量事件批次在不同压缩算法下的字节成本与吞吐。

表示：
  agent   同时测 raw_json 与 protobuf 两种未压缩表示
  sensor  只测 protobuf（sensor 没有 raw_json）
  raw_json 表示：一批事件的 raw JSON 以换行连接
  protobuf 表示：逐事件 marshal 后按批次消息的 repeated 字段编码
                 （agent 为 StoredBatch.events 字段 1，sensor 为 FlowBatch.flows 字段 2）

指标口径：
  ratio = 未压缩表示字节 / 压缩后字节（分母是压缩后字节；none 恒为 1.0）
  compress_mbps / decompress_mbps = 总未压缩字节 / 墙钟时间 / 1,000,000
  无损校验是硬门槛：任一批 decompress(compress(x)) != x 立即报错退出，不静默跳过。

合成数据只是指示性的，权威数字请用 --input 喂真实数据（每行一个 events.raw JSON 对象）：
  psql -c "\copy (SELECT raw FROM events WHERE ts > now()-interval '1 day') TO STDOUT"
--source 必须与数据来源一致；一个 seed 对应一份完全可复现的合成数据。

参数：
`)
	flag.PrintDefaults()
}

func run(source, input string, n int, batchList, out string, seed int64) error {
	if source != "agent" && source != "sensor" {
		return fmt.Errorf("--source 只能是 agent 或 sensor，收到 %q", source)
	}
	sizes, err := parseBatchSizes(batchList)
	if err != nil {
		return err
	}

	var (
		agentEvents []*pb.AgentEvent
		sensorFlows []*pb.FlowRecord
	)
	switch source {
	case "agent":
		if input != "" {
			agentEvents, err = loadAgentInput(input)
		} else {
			agentEvents, err = synthesizeAgent(n, seed)
		}
	case "sensor":
		if input != "" {
			sensorFlows, err = loadSensorInput(input)
		} else {
			sensorFlows, err = synthesizeSensor(n, seed)
		}
	}
	if err != nil {
		return err
	}

	var payloads [][]byte
	if source == "agent" {
		payloads, err = marshalMessages(agentEvents)
	} else {
		payloads, err = marshalMessages(sensorFlows)
	}
	if err != nil {
		return err
	}

	protoField := protowire.Number(1) // StoredBatch.events
	if source == "sensor" {
		protoField = 2 // FlowBatch.flows
	}

	var rows []row
	for _, size := range sizes {
		if source == "agent" {
			part, err := measureBatches(source, "raw_json", size, buildRawBatches(agentEvents, size), codecNames)
			if err != nil {
				return err
			}
			rows = append(rows, part...)
		}
		part, err := measureBatches(source, "protobuf", size, buildProtoBatches(payloads, size, protoField), codecNames)
		if err != nil {
			return err
		}
		rows = append(rows, part...)
	}

	if err := printTable(os.Stdout, rows); err != nil {
		return err
	}
	if out != "" {
		if err := writeCSV(out, rows); err != nil {
			return err
		}
	}
	return nil
}

func parseBatchSizes(s string) ([]int, error) {
	fields := strings.Split(s, ",")
	sizes := make([]int, 0, len(fields))
	seen := map[int]bool{}
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			return nil, fmt.Errorf("--batch 里有空项: %q", s)
		}
		v, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("--batch 项 %q 不是整数", f)
		}
		if v <= 0 {
			return nil, fmt.Errorf("--batch 项必须大于 0，收到 %d", v)
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		sizes = append(sizes, v)
	}
	return sizes, nil
}

func marshalMessages[T proto.Message](msgs []T) ([][]byte, error) {
	out := make([][]byte, len(msgs))
	for i, m := range msgs {
		b, err := proto.Marshal(m)
		if err != nil {
			return nil, fmt.Errorf("序列化第 %d 条事件: %w", i+1, err)
		}
		out[i] = b
	}
	return out, nil
}

func batchCount(n, size int) int {
	if n == 0 {
		return 0
	}
	return (n-1)/size + 1
}

// buildRawBatches 镜像 events.raw 的落库形态：批内 JSON 以换行连接，末尾不加换行。
func buildRawBatches(events []*pb.AgentEvent, size int) [][]byte {
	batches := make([][]byte, 0, batchCount(len(events), size))
	for start := 0; start < len(events); start += size {
		end := min(start+size, len(events))
		need := end - start - 1
		for _, ev := range events[start:end] {
			need += len(ev.RawJson)
		}
		buf := make([]byte, 0, need)
		for i, ev := range events[start:end] {
			if i > 0 {
				buf = append(buf, '\n')
			}
			buf = append(buf, ev.RawJson...)
		}
		batches = append(batches, buf)
	}
	return batches
}

// buildProtoBatches 把逐事件 protobuf 消息按批次消息的 repeated 字段拼接：
// 每条 = field tag (wire type 2) + varint 长度 + 消息体，与 agent 本地 StoredBatch 同形。
func buildProtoBatches(payloads [][]byte, size int, field protowire.Number) [][]byte {
	batches := make([][]byte, 0, batchCount(len(payloads), size))
	for start := 0; start < len(payloads); start += size {
		end := min(start+size, len(payloads))
		need := 0
		for _, p := range payloads[start:end] {
			need += len(p) + 2
		}
		buf := make([]byte, 0, need)
		for _, p := range payloads[start:end] {
			buf = protowire.AppendTag(buf, field, protowire.BytesType)
			buf = protowire.AppendBytes(buf, p)
		}
		batches = append(batches, buf)
	}
	return batches
}

func printTable(w io.Writer, rows []row) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, strings.Join(tableHeaders, "\t")); err != nil {
		return fmt.Errorf("写表头: %w", err)
	}
	for _, r := range rows {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%d\t%d\t%d\t%.4f\t%.2f\t%.2f\t%t\n",
			r.Source, r.Representation, r.BatchEvents, r.Codec, r.Batches,
			r.UncompressedBytes, r.CompressedBytes, r.Ratio,
			r.CompressMBps, r.DecompressMBps, r.Lossless); err != nil {
			return fmt.Errorf("写结果行: %w", err)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("刷新输出: %w", err)
	}
	return nil
}

func writeCSV(path string, rows []row) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("创建 %s: %w", path, err)
	}
	w := csv.NewWriter(f)
	if err := w.Write(tableHeaders); err != nil {
		f.Close()
		return fmt.Errorf("写 %s 表头: %w", path, err)
	}
	for _, r := range rows {
		record := []string{
			r.Source,
			r.Representation,
			strconv.Itoa(r.BatchEvents),
			r.Codec,
			strconv.Itoa(r.Batches),
			strconv.Itoa(r.UncompressedBytes),
			strconv.Itoa(r.CompressedBytes),
			strconv.FormatFloat(r.Ratio, 'f', 4, 64),
			strconv.FormatFloat(r.CompressMBps, 'f', 2, 64),
			strconv.FormatFloat(r.DecompressMBps, 'f', 2, 64),
			strconv.FormatBool(r.Lossless),
		}
		if err := w.Write(record); err != nil {
			f.Close()
			return fmt.Errorf("写 %s: %w", path, err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		f.Close()
		return fmt.Errorf("写 %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("关闭 %s: %w", path, err)
	}
	return nil
}
