package selfwatch

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestConfigEvidenceRedactsSecretsAndRetainsRisk(t *testing.T) {
	before := json.RawMessage(`{"ttl":30,"postgresql":{"pg_hba":["host all secretuser 10.1.1.197/32 scram-sha-256"],"parameters":{"ssl":"on","archive_command":"SECRET-OLD-COMMAND"}},"SECRET-KEY":"SECRET-OLD-VALUE"}`)
	after := json.RawMessage(`{"ttl":60,"postgresql":{"pg_hba":["host all secretuser 0.0.0.0/0 trust ldapbindpasswd=SECRET-HBA","host all secretuser ::/0 trust"],"parameters":{"ssl":"off","archive_command":"SECRET-NEW-COMMAND"}},"SECRET-KEY":"SECRET-NEW-VALUE"}`)
	now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.FixedZone("CST", 8*3600))
	e := changeEvidence(before, after, now)
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "secretuser") {
		t.Fatalf("脱敏失败：%s", raw)
	}
	if e.Actor != "unknown" || e.Source != "platform_selfwatch" || !e.ObservedAt.Equal(now) || e.BeforeSHA256 == e.AfterSHA256 {
		t.Fatalf("观察来源不完整：%+v", e)
	}
	var hba *configChange
	for i := range e.Changes {
		if e.Changes[i].Path == "postgresql.pg_hba" {
			hba = &e.Changes[i]
		}
	}
	if hba == nil || !hba.Dangerous || len(hba.After.HBA) != 2 || hba.After.HBA[0].Method != "trust" || hba.After.HBA[0].Address != "0.0.0.0/0" || hba.After.HBA[1].Address != "::/0" {
		t.Fatalf("缺失危险语义：%s", raw)
	}
	if hba.Before.HBA[0].Method != "scram-sha-256" || hba.Before.SHA256 == hba.After.SHA256 {
		t.Fatalf("缺失前后差异：%+v", hba)
	}
}

func TestConfigEvidenceBoundedAndFailClosed(t *testing.T) {
	before, after := map[string]any{}, map[string]any{}
	for i := range 100 {
		before[fmt.Sprintf("a%03d", i)] = "before"
		after[fmt.Sprintf("a%03d", i)] = "after"
	}
	before["postgresql"] = map[string]any{"pg_hba": []string{"local all all peer"}}
	after["postgresql"] = map[string]any{"pg_hba": []string{"local all all trust"}}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	e := changeEvidence(a, b, time.Now())
	if len(e.Changes) != maxEvidenceChanges || e.Dropped != 101-maxEvidenceChanges {
		t.Fatalf("未限制差异大小：%+v", e)
	}
	var dangerous bool
	for _, c := range e.Changes {
		dangerous = dangerous || c.Path == "postgresql.pg_hba"
	}
	if !dangerous {
		t.Fatal("危险字段被普通字段挤出截断摘要")
	}
	for _, v := range []any{map[string]any{"password": "secret"}, []any{"secret"}, "secret", 123456.0} {
		s := summarize("postgresql.parameters.ssl", v, true)
		if !s.Redacted || s.Value != nil {
			t.Fatalf("未知 ssl 值被放行：%+v", s)
		}
	}
	for _, line := range []string{`host all all 0.0.0.0/0 "SECRET"`, `host all all 0.0.0.0/0 SECRET`, `SECRET all all 0.0.0.0/0 trust`} {
		if s := summarizeHBA(line); s.Type != "unparsed" {
			t.Fatalf("无法解析时不得猜测：%+v", s)
		}
	}
}

func TestConfigEvidenceNewSecurityObject(t *testing.T) {
	before := json.RawMessage(`{"ttl":30}`)
	after := json.RawMessage(`{"ttl":30,"postgresql":{"pg_hba":["host all all ::/0 trust"]}}`)
	paths := diff(before, after)
	if len(paths) != 1 || paths[0] != "postgresql.pg_hba" || !dangerous(paths[0]) {
		t.Fatalf("新加父对象不能掩盖安全字段：%v", paths)
	}
	e := changeEvidence(before, after, time.Now())
	if len(e.Changes) != 1 || e.Changes[0].Before.Present || e.Changes[0].After.HBA[0].Method != "trust" {
		t.Fatalf("新字段缺失摘要：%+v", e)
	}
}

func TestHBASummaryTruncationRetainsTailRisk(t *testing.T) {
	lines := make([]any, 12)
	for i := range lines {
		lines[i] = "host all all 127.0.0.1/32 scram-sha-256"
	}
	lines[11] = "host all all 0.0.0.0/0 trust"
	s := summarize("postgresql.pg_hba", lines, true)
	if len(s.HBA) != 8 || s.OmittedHBA != 4 || s.TrustRules != 1 || s.WorldRules != 1 {
		t.Fatalf("截断隐藏了尾部风险：%+v", s)
	}
}
