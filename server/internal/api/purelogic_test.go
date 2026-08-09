package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entintel "openxdr/server/ent/intel"
)

func TestEscapeLike(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"100%", "100\\%"},
		{"a_b", "a\\_b"},
		{`path\file`, `path\\file`},
		{`%_\`, `\%\_\\`},
		{"", ""},
	}
	for _, c := range cases {
		if got := escapeLike(c.in); got != c.want {
			t.Errorf("escapeLike(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSummarize(t *testing.T) {
	title := "反弹 shell"
	raw := json.RawMessage(`{"verdict":"malicious"}`)
	inc := &ent.Incident{
		ID: uuid.New(), CreatedAt: time.Unix(1000, 0), Status: "triaged",
		Title: &title, AiVerdict: raw,
	}
	s := summarize(inc, 5, 9)

	if s.ID != inc.ID || s.Status != "triaged" || s.Title != &title {
		t.Errorf("基础字段映射错误: %+v", s)
	}
	if s.AiVerdict != nil && string(s.AiVerdict) != `{"verdict":"malicious"}` {
		t.Errorf("AiVerdict = %s", s.AiVerdict)
	}
	// AiVerdict 是 RawMessage，非 nil 判断用 len
	if len(s.AiVerdict) == 0 {
		t.Error("AiVerdict 应保留原始 JSON")
	}
	if s.AlertCount != 5 || s.Severity != 9 {
		t.Errorf("派生字段错误: alertCount=%d severity=%d", s.AlertCount, s.Severity)
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, map[string]int{"n": 3})

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if strings.TrimSpace(w.Body.String()) != `{"n":3}` {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestToRow(t *testing.T) {
	id := uuid.New()
	inc := uuid.New()
	detail := "已隔离"
	now := time.Now()
	c := &ent.Command{
		ID: id, CreatedAt: now, Kind: "isolate_host", Status: "succeeded",
		DryRun: true, AssetID: uuid.New(), IncidentID: &inc,
		IssuedBy: "kei", Detail: &detail, CompletedAt: &now,
	}
	r := toRow(c)
	if r.ID != id || r.Kind != "isolate_host" || r.Status != "succeeded" {
		t.Errorf("基础字段映射错误: %+v", r)
	}
	if !r.DryRun || r.IssuedBy != "kei" {
		t.Errorf("dry-run/issuer 映射错误: %+v", r)
	}
	if r.IncidentID != &inc || r.Detail != &detail || r.CompletedAt != &now {
		t.Errorf("指针字段映射错误: %+v", r)
	}
}

func TestToIntelRow(t *testing.T) {
	id := uuid.New()
	note := "存疑"
	exp := time.Now()
	i := &ent.Intel{
		ID: id, CreatedAt: exp, Kind: entintel.KindIP, Value: "1.2.3.4",
		Source: "manual", Severity: 4, Note: &note, ExpiresAt: &exp,
		MatchedCount: 7, LastMatchedAt: &exp,
	}
	r := toIntelRow(i)
	if r.ID != id || r.Kind != string(entintel.KindIP) || r.Value != "1.2.3.4" {
		t.Errorf("基础字段映射错误: %+v", r)
	}
	if r.Severity != 4 || r.MatchedCount != 7 || r.Source != "manual" {
		t.Errorf("数值字段映射错误: %+v", r)
	}
	if r.Note != &note || r.ExpiresAt != &exp || r.LastMatchedAt != &exp {
		t.Errorf("指针字段映射错误: %+v", r)
	}
}
