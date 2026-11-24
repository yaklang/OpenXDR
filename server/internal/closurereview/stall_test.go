package closurereview

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

func benignMaterial(ids ...uuid.UUID) *material {
	m := &material{Benign: &benignEvidence{}}
	for _, id := range ids {
		m.Events = append(m.Events, &ent.Event{ID: id, Raw: json.RawMessage(`{"process":{"name":"rm","cmd_line":"rm -f /var/log/sa/sa01"}}`)})
	}
	return m
}

func approve(ids []uuid.UUID, claims ...Claim) Decision {
	return Decision{Approve: true, Reason: "sysstat 归档轮转删除旧文件", PositiveEvidence: "命令行是 sa2 汇总脚本删除过期 sa 归档", EventIDs: ids, Claims: claims}
}

// 审计员的可纠正失误不再整份作废：多写的 event_ids、过短或落在截断字段上的引用只是不计入
func TestRejectionTolerance(t *testing.T) {
	a, b, lineage := uuid.New(), uuid.New(), uuid.New()
	m := benignMaterial(a, b)
	good := func(id uuid.UUID) Claim {
		return Claim{EventID: id, Field: "raw.process.cmd_line", Value: "rm -f /var/log/sa/sa01"}
	}
	cases := map[string]struct {
		d    Decision
		want string
	}{
		"多写祖先事件":     {approve([]uuid.UUID{a, b, lineage}, good(a), good(b)), ""},
		"漏写事件":       {approve([]uuid.UUID{a}, good(a), good(b)), "event_ids 漏了原始事件 " + b.String()},
		"短值不计入":      {approve([]uuid.UUID{a, b}, Claim{EventID: a, Field: "raw.process.name", Value: "rm"}, good(a), good(b)), ""},
		"只有短值":       {approve([]uuid.UUID{a, b}, Claim{EventID: a, Field: "raw.process.name", Value: "rm"}, good(b)), "事件 " + a.String() + " 没有字段级引用"},
		"截断字段不计入":    {approve([]uuid.UUID{a, b}, Claim{EventID: a, Field: "raw.process.cmd_line", Value: "cc …" + truncMark + "原长 1]…"}, good(b)), "事件 " + a.String() + " 没有字段级引用"},
		"引用材料外事件不计入": {approve([]uuid.UUID{a, b}, good(lineage), good(a), good(b)), ""},
		"材料内事件值不符":   {approve([]uuid.UUID{a, b}, Claim{EventID: a, Field: "raw.process.cmd_line", Value: "rm -rf /"}, good(b)), "引用的字段 raw.process.cmd_line 与事件 " + a.String() + " 的原值不符"},
	}
	for name, c := range cases {
		if got := rejection(c.d, m); got != c.want {
			t.Errorf("%s: %q，应为 %q", name, got, c.want)
		}
	}
}

func TestTruncateRaw(t *testing.T) {
	long := strings.Repeat("目标文件.o ", 4000)
	raw, _ := json.Marshal(map[string]any{"process": map[string]any{"cmd_line": long, "file": map[string]any{"path": "/usr/bin/cc"}}})
	out, ok := truncateRaw(raw)
	if !ok || len(out) > 8192 {
		t.Fatalf("截断后应在上限内：ok=%v len=%d", ok, len(out))
	}
	var doc map[string]map[string]any
	if json.Unmarshal(out, &doc) != nil {
		t.Fatal("截断后必须仍是合法 JSON")
	}
	cmd := doc["process"]["cmd_line"].(string)
	if !strings.Contains(cmd, truncMark) || !strings.Contains(cmd, "原长 ") || !utf8.ValidString(cmd) || !strings.HasPrefix(long, strings.Split(cmd, "…")[0]) {
		t.Fatalf("截断标记或首尾不对：%.80q", cmd)
	}
	if doc["process"]["file"].(map[string]any)["path"] != "/usr/bin/cc" {
		t.Fatal("短字段必须原样保留")
	}
	if _, ok := truncateRaw(json.RawMessage(`[1,2]`)); ok {
		t.Fatal("原文不是对象应判失败")
	}
}

func TestAuditVerdictDropsQueryExcerpts(t *testing.T) {
	out := auditVerdict(json.RawMessage(`{"verdict":"benign","summary":"良性","query_evidence":[{"raw_truncated":true}]}`))
	if strings.Contains(string(out), "raw_truncated") || !strings.Contains(string(out), `"summary":"良性"`) {
		t.Fatalf("%s", out)
	}
}

func TestAuditDetailParsing(t *testing.T) {
	overruled := `snapshot=x approved=false mechanism=ai_review model=m decision={"approve":true,"reason":"apt 校验"} rejected=event_ids 漏了原始事件 1`
	refused := `snapshot=x approved=false mechanism=ai_review model=m decision={"approve":false,"reason":"下载后执行","positive_evidence":""} rejected=审计员未批准`
	invalid := `snapshot=x approved=false mechanism=ai_review model=m decision={"approve":false,"reason":"` + invalidDecision().Reason + `"} rejected=审计员未批准`
	if !retryable(overruled) || retryable(refused) || !retryable(invalid) {
		t.Fatal("只有服务端驳回批准与回复不合格可以重审")
	}
	if got := auditReason(overruled); got != "event_ids 漏了原始事件 1" {
		t.Fatalf("%q", got)
	}
	if got := auditReason(refused); got != "下载后执行" {
		t.Fatalf("%q", got)
	}
	if !strings.Contains(serverFeedback(overruled), "event_ids 漏了原始事件 1") {
		t.Fatal("重审要带上驳回原因")
	}
}

// 字段在材料里被截断过，审计员引用了其中一段：不计入覆盖，不整份驳回
func TestClaimOnTruncatedFieldIsSkipped(t *testing.T) {
	id := uuid.New()
	long := "rustc --crate-name scutum " + strings.Repeat("-C link-arg=/opt/runner/_work/target/debug/deps/x.o ", 200)
	raw, _ := json.Marshal(map[string]any{"process": map[string]any{"name": "cc", "cmd_line": "cc -m64", "parent_process": map[string]any{"cmd_line": long}}})
	cut, _ := truncateRaw(raw)
	m := &material{Benign: &benignEvidence{}, Events: []*ent.Event{{ID: id, Raw: cut}}}
	head := Claim{EventID: id, Field: "raw.process.parent_process.cmd_line", Value: long[:120]}
	good := Claim{EventID: id, Field: "raw.process.cmd_line", Value: "cc -m64"}
	if got := rejection(approve([]uuid.UUID{id}, head, good), m); got != "" {
		t.Fatalf("截断字段上的引用应不计入而不是驳回：%q", got)
	}
	if got := rejection(approve([]uuid.UUID{id}, head), m); got != "事件 "+id.String()+" 没有字段级引用" {
		t.Fatalf("只有截断字段上的引用应判为缺引用：%q", got)
	}
}

func TestAlertStallSyntheticWithoutEvent(t *testing.T) {
	aid := uuid.New()
	a := &ent.Alert{
		RuleID:   "xdr:new-ssh-key",
		Severity: 4,
		AssetID:  &aid,
		Edges:    ent.AlertEdges{Asset: &ent.Asset{ID: aid, Hostname: "gateway"}},
	}
	err := alertStall(a)
	if err == nil || !strings.Contains(err.Error(), "含平台合成检测（xdr:new-ssh-key）") {
		t.Fatalf("无原始事件的平台合成告警应给出合成检测原因而非缺事件，实际：%v", err)
	}
}
