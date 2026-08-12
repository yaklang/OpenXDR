package grpcsvc

import (
	"encoding/json"
	"testing"

	"openxdr/server/pb"
)

func rawToMap(t *testing.T, f *pb.FlowRecord) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(flowRaw(f), &m); err != nil {
		t.Fatalf("flowRaw 产物应为合法 JSON：%v", err)
	}
	return m
}

func TestFlowRawDNSRcodeAndAnswers(t *testing.T) {
	m := rawToMap(t, &pb.FlowRecord{
		Protocol:   17,
		SrcIp:      "10.0.0.1",
		DstIp:      "8.8.8.8",
		DnsQuery:   "cdn.example.com",
		DnsRcode:   3,
		DnsAnswers: []string{"93.184.216.34", "2001:db8::1"},
	})
	query, ok := m["query"].(map[string]any)
	if !ok {
		t.Fatalf("DNS 会话应有 query 对象：%v", m)
	}
	if query["hostname"] != "cdn.example.com" {
		t.Fatalf("query.hostname 不对：%v", query)
	}
	// JSON 数字解出来是 float64
	if query["rcode_id"] != float64(3) {
		t.Fatalf("query.rcode_id 应为 3：%v", query)
	}
	answers, ok := m["answers"].([]any)
	if !ok || len(answers) != 2 {
		t.Fatalf("answers 应为两个元素：%v", m["answers"])
	}
	// 键名必须是 ip，intel 按键名递归收集才能撞上情报
	first, ok := answers[0].(map[string]any)
	if !ok || first["ip"] != "93.184.216.34" {
		t.Fatalf("answers[0].ip 不对：%v", answers[0])
	}
	second, ok := answers[1].(map[string]any)
	if !ok || second["ip"] != "2001:db8::1" {
		t.Fatalf("answers[1].ip 不对：%v", answers[1])
	}
}

func TestFlowRawDNSNoAnswers(t *testing.T) {
	m := rawToMap(t, &pb.FlowRecord{Protocol: 17, DnsQuery: "nx.example"})
	if _, ok := m["answers"]; ok {
		t.Fatalf("无应答 IP 不应写 answers 键：%v", m)
	}
	// rcode_id 对 DNS 会话恒存在（0 = NOERROR 或未抓到应答）
	query := m["query"].(map[string]any)
	if query["rcode_id"] != float64(0) {
		t.Fatalf("rcode_id 缺省应为 0：%v", query)
	}
}

func TestFlowRawTLSJA3S(t *testing.T) {
	m := rawToMap(t, &pb.FlowRecord{
		Protocol: 6,
		TlsSni:   "c2.example",
		Ja3:      "ja3-hash",
		Ja3S:     "ja3s-hash",
	})
	tls, ok := m["tls"].(map[string]any)
	if !ok {
		t.Fatalf("应有 tls 对象：%v", m)
	}
	if tls["sni"] != "c2.example" || tls["ja3_hash"] != "ja3-hash" || tls["ja3s_hash"] != "ja3s-hash" {
		t.Fatalf("tls 对象字段不对：%v", tls)
	}
}

func TestFlowRawJA3SAlone(t *testing.T) {
	// 只抓到 ServerHello 的流也要出 tls.ja3s_hash
	m := rawToMap(t, &pb.FlowRecord{Protocol: 6, Ja3S: "ja3s-hash"})
	tls, ok := m["tls"].(map[string]any)
	if !ok {
		t.Fatalf("仅 JA3S 也应有 tls 对象：%v", m)
	}
	if tls["ja3s_hash"] != "ja3s-hash" {
		t.Fatalf("ja3s_hash 不对：%v", tls)
	}
	if _, ok := tls["sni"]; ok {
		t.Fatalf("无 SNI 不应写 sni 键：%v", tls)
	}
}

func TestFlowRawTLSCert(t *testing.T) {
	m := rawToMap(t, &pb.FlowRecord{
		Protocol:          6,
		TlsSni:            "c2.example",
		TlsCertSubject:    "evil.selfsigned",
		TlsCertIssuer:     "evil.selfsigned",
		TlsCertSelfSigned: true,
		TlsCertNotBefore:  1754000000,
		TlsCertNotAfter:   1786000000,
	})
	tls, ok := m["tls"].(map[string]any)
	if !ok {
		t.Fatalf("应有 tls 对象：%v", m)
	}
	cert, ok := tls["cert"].(map[string]any)
	if !ok {
		t.Fatalf("应有 tls.cert 对象：%v", tls)
	}
	if cert["subject"] != "evil.selfsigned" || cert["issuer"] != "evil.selfsigned" {
		t.Fatalf("cert subject/issuer 不对：%v", cert)
	}
	if cert["self_signed"] != true {
		t.Fatalf("cert self_signed 应为 true：%v", cert)
	}
	if cert["not_before"] != float64(1754000000) || cert["not_after"] != float64(1786000000) {
		t.Fatalf("cert 有效期不对：%v", cert)
	}
}

func TestFlowRawNoCertNoCertKey(t *testing.T) {
	// 证书字段为空（TLS 1.3 或没抓到 Certificate）时不应写 tls.cert
	m := rawToMap(t, &pb.FlowRecord{Protocol: 6, TlsSni: "a.example"})
	tls, ok := m["tls"].(map[string]any)
	if !ok {
		t.Fatalf("应有 tls 对象：%v", m)
	}
	if _, ok := tls["cert"]; ok {
		t.Fatalf("无证书不应写 cert 键：%v", tls)
	}
}

func TestConnTuple(t *testing.T) {
	tcp := &pb.FlowRecord{Protocol: protoTCP, SrcIp: "1.2.3.4", SrcPort: 443, DstIp: "5.6.7.8", DstPort: 52432}
	if got := connTuple(tcp); got != "tcp:1.2.3.4:443>5.6.7.8:52432" {
		t.Errorf("tcp 连接元组 = %q，期望 tcp:1.2.3.4:443>5.6.7.8:52432", got)
	}
	udp := &pb.FlowRecord{Protocol: 17, SrcIp: "10.0.0.1", SrcPort: 53, DstIp: "10.0.0.2", DstPort: 5353}
	if got := connTuple(udp); got != "udp:10.0.0.1:53>10.0.0.2:5353" {
		t.Errorf("udp 连接元组 = %q，期望 udp:10.0.0.1:53>10.0.0.2:5353", got)
	}
	// 未知协议按 udp 处理，保证去重键不随协议字段漂移
	other := &pb.FlowRecord{Protocol: 0, SrcIp: "1.1.1.1", SrcPort: 1, DstIp: "2.2.2.2", DstPort: 2}
	if got := connTuple(other); got != "udp:1.1.1.1:1>2.2.2.2:2" {
		t.Errorf("未知协议连接元组 = %q，期望按 udp 处理", got)
	}
}
