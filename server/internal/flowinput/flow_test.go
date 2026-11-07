package flowinput

import (
	"os"
	"strings"
	"testing"
)

const flowJSON = `{"IPV4_SRC_ADDR":"192.0.2.1","IPV4_DST_ADDR":"198.51.100.2","L4_SRC_PORT":12345,"L4_DST_PORT":443,"PROTOCOL":6,"FIRST_SWITCHED":1794000000,"FLOW_ID":18446744073709551615}`

func TestFlowFormats(t *testing.T) {
	e, err := Parse("ntopng", []byte(flowJSON))
	if err != nil {
		t.Fatal(err)
	}
	if e.Time.Unix() != 1794000000 || e.ConnTuple() != "tcp:192.0.2.1:12345>198.51.100.2:443" || !strings.Contains(string(e.Raw), "18446744073709551615") {
		t.Fatalf("归一化错误: %+v", e)
	}
	if _, err := Parse("nprobe", []byte(flowJSON)); err == nil {
		t.Fatal("nProbe uptime 不能当绝对时间")
	}
	nprobe := strings.Replace(flowJSON, "FIRST_SWITCHED", "FLOW_START_SEC", 1)
	if _, err := Parse("nprobe", []byte(nprobe)); err != nil {
		t.Fatal(err)
	}
	millis := strings.Replace(strings.Replace(nprobe, "FLOW_START_SEC", "FLOW_START_MILLISECONDS", 1), "1794000000", "1794000000123", 1)
	e, err = Parse("nprobe", []byte(millis))
	if err != nil || e.Time.UnixMilli() != 1794000000123 {
		t.Fatalf("毫秒时间错误: %v %+v", err, e)
	}
	ipv6 := strings.ReplaceAll(strings.ReplaceAll(flowJSON, "IPV4_", "IPV6_"), "192.0.2.1", "2001:db8::1")
	e, err = Parse("ntopng", []byte(ipv6))
	if err != nil || !strings.Contains(e.ConnTuple(), "[2001:db8::1]:12345") {
		t.Fatalf("IPv6: %v %+v", err, e)
	}
}

func TestInvalidFlow(t *testing.T) {
	for _, raw := range []string{"null", "[]", `{}`, strings.Replace(flowJSON, "12345", "65536", 1), strings.Replace(flowJSON, "192.0.2.1", "invalid", 1), strings.Replace(flowJSON, "1794000000", "100", 1), strings.Replace(flowJSON, `"PROTOCOL":6`, `"PROTOCOL":256`, 1)} {
		if _, err := Parse("ntopng", []byte(raw)); err == nil {
			t.Errorf("非法报文不应接收: %s", raw)
		}
	}
	if _, err := Parse("other", []byte(flowJSON)); err == nil {
		t.Fatal("未知来源应拒绝")
	}
}

func TestNativeNtopngExport(t *testing.T) {
	data, err := os.ReadFile("testdata/ntopng-7.0.261106.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("应有 HTTP 和 DNS 两条原生会话，实际 %d", len(lines))
	}
	for _, line := range lines {
		event, err := Parse("ntopng", []byte(line))
		if err != nil {
			t.Fatal(err)
		}
		switch event.ProtocolNum {
		case 6:
			if event.DstPort != 80 || event.Traffic["bytes_out"] != 345 || event.Traffic["bytes_in"] != 221 || event.Traffic["packets_out"] != 5 || event.Traffic["packets_in"] != 3 {
				t.Fatalf("HTTP 原生计数失真: %+v", event)
			}
		case 17:
			if event.DstPort != 53 || event.Traffic["bytes_out"] != 72 || event.Traffic["bytes_in"] != 100 || event.Traffic["packets_out"] != 1 || event.Traffic["packets_in"] != 1 {
				t.Fatalf("DNS 原生计数失真: %+v", event)
			}
		default:
			t.Fatalf("非预期协议: %d", event.ProtocolNum)
		}
	}
}
