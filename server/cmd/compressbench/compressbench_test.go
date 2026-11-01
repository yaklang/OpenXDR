package main

import (
	"bytes"
	"math"
	"testing"

	"google.golang.org/protobuf/proto"

	"openxdr/server/pb"
)

// 要求 (a)：每种 codec 对合成批做无损往返；none 还必须与原文逐字节相等。
func TestCodecLosslessRoundTrip(t *testing.T) {
	agentEvents, err := synthesizeAgent(300, 1)
	if err != nil {
		t.Fatal(err)
	}
	agentPayloads, err := marshalMessages(agentEvents)
	if err != nil {
		t.Fatal(err)
	}
	agentBatch := buildProtoBatches(agentPayloads, 300, 1)[0]

	sensorFlows, err := synthesizeSensor(300, 1)
	if err != nil {
		t.Fatal(err)
	}
	sensorPayloads, err := marshalMessages(sensorFlows)
	if err != nil {
		t.Fatal(err)
	}
	sensorBatch := buildProtoBatches(sensorPayloads, 300, 2)[0]

	for _, corpus := range []struct {
		name  string
		batch []byte
	}{
		{name: "agent", batch: agentBatch},
		{name: "sensor", batch: sensorBatch},
	} {
		for _, name := range codecNames {
			t.Run(corpus.name+"/"+name, func(t *testing.T) {
				c, err := newCodec(name)
				if err != nil {
					t.Fatal(err)
				}
				defer c.close()
				compressed, err := c.compress(corpus.batch)
				if err != nil {
					t.Fatal(err)
				}
				if name == "none" && !bytes.Equal(compressed, corpus.batch) {
					t.Fatalf("none 压缩结果与原文不一致：%d != %d 字节", len(compressed), len(corpus.batch))
				}
				decoded, err := c.decompress(compressed)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(decoded, corpus.batch) {
					t.Fatalf("无损校验失败：解压结果 %d 字节，原文 %d 字节", len(decoded), len(corpus.batch))
				}
			})
		}
	}
}

// 要求 (b)：ratio 的分子是未压缩表示字节，分母是压缩后字节。
func TestMeasureRatioMatchesByteTotals(t *testing.T) {
	events, err := synthesizeAgent(400, 3)
	if err != nil {
		t.Fatal(err)
	}
	payloads, err := marshalMessages(events)
	if err != nil {
		t.Fatal(err)
	}
	batches := buildProtoBatches(payloads, 128, 1)
	rows, err := measureBatches("agent", "protobuf", 128, batches, codecNames)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(codecNames) {
		t.Fatalf("行数 = %d，期望 %d", len(rows), len(codecNames))
	}
	total := 0
	for _, b := range batches {
		total += len(b)
	}
	for _, r := range rows {
		if r.Batches != len(batches) || r.BatchEvents != 128 {
			t.Fatalf("%s 的批次统计不对: batches=%d batch_events=%d", r.Codec, r.Batches, r.BatchEvents)
		}
		if r.UncompressedBytes != total {
			t.Fatalf("%s 的未压缩字节 = %d，期望 %d", r.Codec, r.UncompressedBytes, total)
		}
		want := float64(r.UncompressedBytes) / float64(r.CompressedBytes)
		if math.Abs(r.Ratio-want) > 1e-12 {
			t.Fatalf("%s 的 ratio = %v，期望 %v（未压缩/压缩后）", r.Codec, r.Ratio, want)
		}
		if !r.Lossless {
			t.Fatalf("%s 未通过无损校验", r.Codec)
		}
	}
}

// 要求 (c)：none 的 ratio 恰为 1.0，且压缩前后字节一致。
func TestNoneCodecRatioIsOne(t *testing.T) {
	batch := []byte(`{"activity_id":1,"process":{"pid":1234,"name":"bash","file":{"path":"/usr/bin/bash","sha256":"abc"}}}`)
	rows, err := measureBatches("agent", "raw_json", 1, [][]byte{batch}, []string{"none"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("行数 = %d，期望 1", len(rows))
	}
	r := rows[0]
	if r.UncompressedBytes != len(batch) || r.CompressedBytes != len(batch) {
		t.Fatalf("none 字节数不一致: uncompressed=%d compressed=%d batch=%d", r.UncompressedBytes, r.CompressedBytes, len(batch))
	}
	if r.Ratio != 1.0 {
		t.Fatalf("none 的 ratio = %v，必须恰为 1.0", r.Ratio)
	}
	if !r.Lossless {
		t.Fatal("none 未通过无损校验")
	}
}

func TestSyntheticSeedReproducible(t *testing.T) {
	a1, err := synthesizeAgent(200, 7)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := synthesizeAgent(200, 7)
	if err != nil {
		t.Fatal(err)
	}
	a3, err := synthesizeAgent(200, 8)
	if err != nil {
		t.Fatal(err)
	}
	agentDiffers := false
	for i := range a1 {
		if !proto.Equal(a1[i], a2[i]) {
			t.Fatalf("agent 第 %d 条事件在同一 seed 下不一致", i)
		}
		if !proto.Equal(a1[i], a3[i]) {
			agentDiffers = true
		}
	}
	if !agentDiffers {
		t.Fatal("agent 换了 seed 后事件仍完全相同")
	}

	s1, err := synthesizeSensor(100, 7)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := synthesizeSensor(100, 7)
	if err != nil {
		t.Fatal(err)
	}
	s3, err := synthesizeSensor(100, 8)
	if err != nil {
		t.Fatal(err)
	}
	sensorDiffers := false
	for i := range s1 {
		if !proto.Equal(s1[i], s2[i]) {
			t.Fatalf("sensor 第 %d 条会话在同一 seed 下不一致", i)
		}
		if !proto.Equal(s1[i], s3[i]) {
			sensorDiffers = true
		}
	}
	if !sensorDiffers {
		t.Fatal("sensor 换了 seed 后会话仍完全相同")
	}
}

func TestBuildRawBatchesJoinsWithNewline(t *testing.T) {
	events := []*pb.AgentEvent{{RawJson: `{"a":1}`}, {RawJson: `{"b":2}`}, {RawJson: `{"c":3}`}}
	batches := buildRawBatches(events, 2)
	if len(batches) != 2 {
		t.Fatalf("批数 = %d，期望 2", len(batches))
	}
	if got, want := string(batches[0]), "{\"a\":1}\n{\"b\":2}"; got != want {
		t.Fatalf("第 1 批 = %q，期望 %q", got, want)
	}
	if got, want := string(batches[1]), `{"c":3}`; got != want {
		t.Fatalf("第 2 批 = %q，期望 %q", got, want)
	}
}

func TestParseBatchSizes(t *testing.T) {
	got, err := parseBatchSizes("128, 500,128")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 128 || got[1] != 500 {
		t.Fatalf("parseBatchSizes = %v，期望 [128 500]", got)
	}
	for _, bad := range []string{"", "0", "-1", "12,", "x", "128,,500"} {
		if _, err := parseBatchSizes(bad); err == nil {
			t.Fatalf("parseBatchSizes(%q) 应当报错", bad)
		}
	}
}

func TestParseAgentLineDerivesEnvelope(t *testing.T) {
	line := []byte(`{"activity_id":1,"process":{"pid":1234,"uid":"11111111-1111-4111-8111-111111111111","name":"bash","file":{"path":"/usr/bin/bash","sha256":"abc"},"cmd_line":"-c id","parent_process":{"pid":1000,"uid":"22222222-2222-4222-8222-222222222222"}}}`)
	ev, err := parseAgentLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if ev.ProcessGuid != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("process_guid = %q", ev.ProcessGuid)
	}
	if ev.ParentProcessGuid != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("parent_process_guid = %q", ev.ParentProcessGuid)
	}
	if ev.RawJson != string(line) {
		t.Fatal("raw_json 必须与输入行完全一致")
	}

	network := []byte(`{"activity_id":1,"connection_info":{"direction":"outbound","protocol_name":"tcp"},"src_endpoint":{"ip":"10.0.0.5","port":51234},"dst_endpoint":{"ip":"93.184.216.34","port":443},"process":{"pid":7,"uid":"33333333-3333-4333-8333-333333333333","name":"curl","file":{"path":"/usr/bin/curl"}}}`)
	ev, err = parseAgentLine(network)
	if err != nil {
		t.Fatal(err)
	}
	if want := "tcp:10.0.0.5:51234>93.184.216.34:443"; ev.ConnTuple != want {
		t.Fatalf("conn_tuple = %q，期望 %q", ev.ConnTuple, want)
	}
}

func TestParseSensorLine(t *testing.T) {
	line := []byte(`{"activity_id":6,"duration_ms":1230,"connection_info":{"protocol_num":6,"tcp_flags":24},"src_endpoint":{"ip":"10.0.0.5","port":51234},"dst_endpoint":{"ip":"93.184.216.34","port":443},"traffic":{"packets":10,"bytes":2048,"packets_in":6,"bytes_in":1200,"packets_out":4,"bytes_out":848},"tls":{"sni":"example.com","ja3_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ja3s_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","handshake_only":true},"http_request":{"hostname":"example.com","url":{"path":"/x"},"user_agent":"curl/8.5.0"}}`)
	f, err := parseSensorLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if f.SrcIp != "10.0.0.5" || f.SrcPort != 51234 || f.DstIp != "93.184.216.34" || f.DstPort != 443 {
		t.Fatalf("五元组还原错误: %+v", f)
	}
	if f.Protocol != 6 || f.TcpFlags != 24 {
		t.Fatalf("protocol/tcp_flags = %d/%d", f.Protocol, f.TcpFlags)
	}
	if f.SrcPackets != 4 || f.SrcBytes != 848 || f.DstPackets != 6 || f.DstBytes != 1200 {
		t.Fatalf("双向流量还原错误: %+v", f)
	}
	if f.EndUnixNs != 1230*1e6 {
		t.Fatalf("end_unix_ns = %d", f.EndUnixNs)
	}
	if f.TlsSni != "example.com" || f.Ja3 == "" || f.Ja3S == "" || !f.TlsHandshakeOnly {
		t.Fatalf("tls 字段还原错误: %+v", f)
	}
	if f.HttpHost != "example.com" || f.HttpUri != "/x" || f.HttpUserAgent != "curl/8.5.0" {
		t.Fatalf("http_request 还原错误: %+v", f)
	}

	if _, err := parseSensorLine([]byte(`{"activity_id":1,"process":{"pid":1}}`)); err == nil {
		t.Fatal("缺少 sensor 会话字段的 JSON 应当报错")
	}
}
