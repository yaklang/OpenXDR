package intel

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/sigma"
)

func storeWith(keys map[string]entry) *Store {
	return &Store{byKey: keys, counters: map[uuid.UUID]*counter{}}
}

func e(sev int16, expires *time.Time) entry {
	return entry{id: uuid.Must(uuid.NewV7()), severity: sev, expires: expires}
}

func TestMatchIPAndDomainAndHash(t *testing.T) {
	s := storeWith(map[string]entry{
		"ip:6.6.6.6":       e(5, nil),
		"domain:evil.com":  e(4, nil),
		"hash:" + sha256of: e(5, nil),
	})
	raw := map[string]any{
		"dst_endpoint": map[string]any{"ip": "6.6.6.6", "port": 443},
		"query":        map[string]any{"hostname": "C2.Evil.com."},
		"file":         map[string]any{"sha256": sha256of},
	}
	hits := s.Match(raw, time.Now())
	if len(hits) != 3 {
		t.Fatalf("期望 3 次命中，得到 %d：%v", len(hits), hits)
	}
	want := map[string]bool{
		"intel:ip:6.6.6.6":       true,
		"intel:domain:evil.com":  true, // 子域命中根域情报，大小写与尾点已归一
		"intel:hash:" + sha256of: true,
	}
	for _, h := range hits {
		if !want[h.RuleID] {
			t.Errorf("意外命中 %s", h.RuleID)
		}
	}
}

const sha256of = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestMatchJA3(t *testing.T) {
	const ja3 = "e7d705a3286e19ea42f587b344ee6865"
	s := storeWith(map[string]entry{"hash:" + ja3: e(4, nil)})
	raw := map[string]any{"tls": map[string]any{"ja3_hash": ja3, "sni": "ok.example.com"}}
	hits := s.Match(raw, time.Now())
	if len(hits) != 1 || hits[0].RuleID != "intel:hash:"+ja3 {
		t.Fatalf("JA3 指纹应作为 hash 情报命中：%v", hits)
	}
}

func TestMatchJA3S(t *testing.T) {
	const ja3s = "a4e5f0e0b0a4e5f0e0b0a4e5f0e0b0a4"
	s := storeWith(map[string]entry{"hash:" + ja3s: e(4, nil)})
	raw := map[string]any{"tls": map[string]any{"ja3s_hash": ja3s}}
	hits := s.Match(raw, time.Now())
	if len(hits) != 1 || hits[0].RuleID != "intel:hash:"+ja3s {
		t.Fatalf("JA3S 服务端指纹应作为 hash 情报命中：%v", hits)
	}
}

func TestMatchDNSAnswerIP(t *testing.T) {
	// sensor 的 DNS 应答写成 "answers":[{"ip":...}]，靠键名 ip 撞上情报
	s := storeWith(map[string]entry{"ip:93.184.216.34": e(5, nil)})
	raw := map[string]any{
		"query":   map[string]any{"hostname": "cdn.example.com", "rcode_id": 0},
		"answers": []any{map[string]any{"ip": "93.184.216.34"}},
	}
	hits := s.Match(raw, time.Now())
	if len(hits) != 1 || hits[0].RuleID != "intel:ip:93.184.216.34" {
		t.Fatalf("DNS 应答 IP 应命中 IP 情报：%v", hits)
	}
}

func TestMatchExpiredAndMiss(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	s := storeWith(map[string]entry{
		"ip:6.6.6.6": e(5, &past),
	})
	raw := map[string]any{
		"src_endpoint": map[string]any{"ip": "10.0.0.1"},
		"dst_endpoint": map[string]any{"ip": "6.6.6.6"},
	}
	if hits := s.Match(raw, time.Now()); len(hits) != 0 {
		t.Fatalf("过期情报不该命中：%v", hits)
	}
}

func TestMatchDedupWithinEvent(t *testing.T) {
	s := storeWith(map[string]entry{"ip:6.6.6.6": e(5, nil)})
	raw := map[string]any{
		"src_endpoint": map[string]any{"ip": "6.6.6.6"},
		"dst_endpoint": map[string]any{"ip": "6.6.6.6"},
	}
	if hits := s.Match(raw, time.Now()); len(hits) != 1 {
		t.Fatalf("同一事件里重复出现的值只算一次：%v", hits)
	}
}

func TestMatchEmptyIndexSkipsWalk(t *testing.T) {
	s := storeWith(map[string]entry{})
	if hits := s.Match(map[string]any{"dst_endpoint": map[string]any{"ip": "6.6.6.6"}}, time.Now()); hits != nil {
		t.Fatalf("空情报库不该有命中：%v", hits)
	}
}

func TestDetectionsMerge(t *testing.T) {
	rules := []*sigma.Rule{{ID: "r1", Severity: 3}}
	iocs := []Hit{{RuleID: "intel:ip:6.6.6.6", Severity: 5}}
	got := Detections(rules, iocs)
	if len(got) != 2 || got[0].RuleID != "r1" || got[1].RuleID != "intel:ip:6.6.6.6" {
		t.Fatalf("合并结果不对：%v", got)
	}
}
