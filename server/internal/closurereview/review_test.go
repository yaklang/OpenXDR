package closurereview

import (
	"encoding/json"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"testing"
)

func TestStrictDecision(t *testing.T) {
	for _, raw := range []string{`{"approve":true,"reason":"充分肯定证据"}`, `{"approve":false,"reason":"保持事件等待更多可核验正面证据","cmd":"true"}`, `{"approve":false,"reason":"保持事件等待更多可核验正面证据"} {}`, `null`} {
		if _, err := ParseDecision(raw); err == nil {
			t.Fatalf("应拒绝 %s", raw)
		}
	}
	id := uuid.New()
	raw := `{"approve":true,"reason":"构建记录与命令精确匹配，属于已授权构建", "positive_evidence":"签名构建清单给出本次完整命令及资产、工件哈希，逐项与事件匹配", "event_ids":["` + id.String() + `"],"claims":[{"event_id":"` + id.String() + `","field":"process.cmd_line","value":"/bin/build"}]}`
	d, err := ParseDecision(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rejection(d, &material{Basis: []positiveBasis{{Type: "verified_platform_readonly", EventID: id}}, Events: []*ent.Event{{ID: id, Raw: json.RawMessage(`{"process":{"cmd_line":"/bin/build"}}`)}}}) != "" {
		t.Fatal("应接受相同事件引用")
	}
	if rejection(d, &material{Events: []*ent.Event{{ID: uuid.New()}}}) == "" {
		t.Fatal("禁止伪造引用")
	}
}
func TestVerdictHash(t *testing.T) {
	if VerdictHash(json.RawMessage(`{ "verdict": "benign" }`)) != VerdictHash(json.RawMessage(`{"verdict":"benign"}`)) {
		t.Fatal("空白不影响hash")
	}
	if VerdictHash(json.RawMessage(`bad`)) != "" {
		t.Fatal("拒绝无效JSON")
	}
}

func TestParseDecisionStripsCodeFence(t *testing.T) {
	body := `{"approve":false,"reason":"命令行不足以说明良性行为","positive_evidence":"","event_ids":[],"claims":[]}`
	for _, text := range []string{body, "```json\n" + body + "\n```", "```\n" + body + "\n```"} {
		if d, err := ParseDecision(text); err != nil || d.Approve {
			t.Fatalf("%q: %v", text, err)
		}
	}
	if _, err := ParseDecision("```json\n" + body); err == nil {
		t.Fatal("围栏不完整应拒绝")
	}
}

func TestMissingFactsOnlyOnRejection(t *testing.T) {
	gap := `{"kind":"authorization","subject_kind":"domain","subject":"gzmpc.com"}`
	reject := `{"approve":false,"reason":"扫描目标不在已登记的授权范围内","missing_facts":[` + gap + `]}`
	if d, err := ParseDecision(reject); err != nil || len(d.MissingFacts) != 1 || d.MissingFacts[0].Subject != "gzmpc.com" {
		t.Fatalf("拒绝可带缺口：%v %+v", err, d)
	}
	for _, raw := range []string{
		`{"approve":false,"reason":"扫描目标不在已登记的授权范围内","missing_facts":[` + gap + `,` + gap + `,` + gap + `,` + gap + `]}`,
		`{"approve":false,"reason":"扫描目标不在已登记的授权范围内","missing_facts":[{"kind":"authorization","subject_kind":"domain","subject":"x","why":"y"}]}`,
	} {
		if _, err := ParseDecision(raw); err == nil {
			t.Fatalf("应拒绝 %s", raw)
		}
	}
	m := &material{Benign: &benignEvidence{Hosts: []benignHost{{ID: uuid.New(), Hostname: "raid"}}}}
	if s, ok := missingSubject(MissingFact{Kind: "owner", SubjectKind: "asset", Subject: "raid"}, m, ""); !ok || s != m.Benign.Hosts[0].ID.String() {
		t.Fatal("主机名换成资产 ID")
	}
	for _, mf := range []MissingFact{{Kind: "permission", SubjectKind: "domain", Subject: "gzmpc.com"}, {Kind: "owner", SubjectKind: "rule", Subject: "x"}, {Kind: "owner", SubjectKind: "domain", Subject: "evil.example"}} {
		if _, ok := missingSubject(mf, m, `{"cmd":"nmap gzmpc.com"}`); ok {
			t.Fatalf("应丢弃 %+v", mf)
		}
	}
}
