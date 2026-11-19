package closurereview

import (
	"encoding/json"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"strings"
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

// 审计员把服务端列写成原文路径、或把事件级字段挂到 process 下时仍能核对；原路径存在就不再换路径
func TestClaimValuePathSlips(t *testing.T) {
	user := "postgres"
	ev := &ent.Event{ID: uuid.New(), Username: &user, Raw: json.RawMessage(`{"process":{"cmd_line":"bash -c initdb","name":"bash"},"container":{"name":"scutum-test-pg-1"},"name":"other"}`)}
	for field, want := range map[string]string{
		"username":                   "postgres",
		"raw.username":               "postgres",
		"raw.process.username":       "postgres",
		"raw.process.container.name": "scutum-test-pg-1",
		"process.cmd_line":           "bash -c initdb",
		"raw.process.name":           "bash",
	} {
		if got, ok := claimValue(ev, field); !ok || got != want {
			t.Errorf("%s = %q %v，应为 %q", field, got, ok, want)
		}
	}
	if _, ok := claimValue(ev, "raw.process.parent_process.cmd_line"); ok {
		t.Error("不存在的字段不应凑出取值")
	}
}

// 材料原样给审计员：< > & 不转义，照抄出来的引用才能与原值逐字对上
func TestEncodeKeepsShellMetachars(t *testing.T) {
	cmd := `timeout 3 bash -c '</dev/tcp/127.0.0.1/18080' && echo ok`
	id := uuid.New()
	// 库里的原文是 jsonb 文本，本来就不转义；截断处理过一遍也不能转义
	raw, ok := truncateRaw(json.RawMessage(`{"process":{"cmd_line":"` + cmd + `"}}`))
	if !ok {
		t.Fatal("原文应能处理")
	}
	m := &material{Benign: &benignEvidence{}, Events: []*ent.Event{{ID: id, Raw: raw}}}
	b, err := encode(m)
	if err != nil || !strings.Contains(string(b), `'</dev/tcp/127.0.0.1/18080' && echo`) {
		t.Fatal("材料不应转义 shell 元字符", string(b), err)
	}
	// 事件里没有的字段只是不计入覆盖；别的引用覆盖了就照常通过
	d := Decision{Approve: true, Reason: "本机端口探测脚本", PositiveEvidence: "命令行只探测本机回环端口，是健康检查",
		EventIDs: []uuid.UUID{id}, Claims: []Claim{{EventID: id, Field: "raw.answers.0.ip", Value: "1.2.3.4"}, {EventID: id, Field: "process.cmd_line", Value: cmd}}}
	if why := rejection(d, m); why != "" {
		t.Fatal(why)
	}
	d.Claims = d.Claims[:1]
	if why := rejection(d, m); !strings.Contains(why, "没有字段级引用") {
		t.Fatal("只有不存在字段的引用不算覆盖", why)
	}
	m.Benign.Severe = []severeHost{{Hostname: "yuesheng-gpu", Facts: []string{"F-8867eeac"}}}
	if why := rejection(d, m); !strings.Contains(why, "F-8867eeac") {
		t.Fatal("驳回原因应列出可引用的事实编号", why)
	}
}
