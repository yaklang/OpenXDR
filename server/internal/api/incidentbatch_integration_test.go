//go:build integration

package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// 归并视图按主告警的规则 + 主机分组，带研判分布；批量结案整批事务、逐条审计，
// 恶意按误报须二次确认，组内 viewer 与组外事件整批拒绝。
func TestAPIIncidentGroupsAndBatchResolve(t *testing.T) {
	ctx, db := testdb.New(t)
	gA := db.Group.Create().SetName("A").SaveX(ctx)
	gB := db.Group.Create().SetName("B").SaveX(ctx)
	web := db.Asset.Create().SetHostname("web01").SetGroupID(gA.ID).SaveX(ctx)
	dbHost := db.Asset.Create().SetHostname("db01").SetGroupID(gA.ID).SaveX(ctx)
	other := db.Asset.Create().SetHostname("b01").SetGroupID(gB.ID).SaveX(ctx)

	now := time.Now()
	mk := func(verdict string, created time.Time, asset *ent.Asset, rules ...string) *ent.Incident {
		c := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetCreatedAt(created)
		if verdict != "" {
			c.SetAiVerdict(json.RawMessage(`{"verdict":"` + verdict + `","summary":"s"}`))
		}
		inc := c.SaveX(ctx)
		for i, rule := range rules {
			// 第一条规则级别最高，作为主告警
			db.Alert.Create().SetTs(created).SetRuleID(rule).SetSeverity(int16(3 - i)).
				SetAssetID(asset.ID).SetIncidentID(inc.ID).ExecX(ctx)
		}
		return inc
	}
	ben1 := mk("benign", now.Add(-72*time.Hour), web, "r1", "r-low")
	ben2 := mk("", now.Add(-24*time.Hour), web, "r1")
	mal := mk("malicious", now, web, "r1")
	onDB := mk("suspicious", now, dbHost, "r1")
	ip1 := mk("", now, web, "intel:ip:1.2.3.4")
	ip2 := mk("benign", now.Add(-time.Hour), web, "intel:ip:1.2.3.4")
	foreign := mk("", now, other, "r1")

	h := Handler(db, nil, loadRules(t), response.NewHub(db, false), suppress.New(db, time.Hour), intel.New(db, time.Hour), nil)
	admin := httptest.NewServer(asAdmin(h))
	t.Cleanup(admin.Close)

	resp, raw := get(t, admin, "/api/incidents/groups?status=unresolved")
	if resp.StatusCode != 200 {
		t.Fatalf("归并视图 %d %s", resp.StatusCode, raw)
	}
	var groups []incidentGroup
	if err := json.Unmarshal(raw, &groups); err != nil {
		t.Fatal(err)
	}
	type shape struct {
		host  string
		count int
		dist  string
	}
	got := map[string]shape{}
	for _, g := range groups {
		dist := fmt.Sprintf("b%d s%d m%d n%d", g.Verdicts["benign"], g.Verdicts["suspicious"], g.Verdicts["malicious"], g.Verdicts["none"])
		got[g.RuleID+"@"+*g.Hostname] = shape{*g.Hostname, g.Count, dist}
		if g.Count != len(g.Incidents) {
			t.Errorf("%s 事件数与明细不符", g.Key)
		}
	}
	want := map[string]shape{
		"r1@web01":               {"web01", 3, "b1 s0 m1 n1"},
		"r1@db01":                {"db01", 1, "b0 s1 m0 n0"},
		"r1@b01":                 {"b01", 1, "b0 s0 m0 n1"},
		"intel:ip:1.2.3.4@web01": {"web01", 2, "b1 s0 m0 n1"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("归并结果\n got  %v\n want %v", got, want)
	}
	if groups[0].RuleID != "r1" || *groups[0].Hostname != "web01" || !groups[0].FirstAt.Equal(db.Incident.GetX(ctx, ben1.ID).CreatedAt) {
		t.Errorf("事件最多的组应排第一、最早时间取组内最早：%+v", groups[0])
	}
	if r, _ := get(t, admin, "/api/incidents/groups?status=closed"); r.StatusCode != 400 {
		t.Errorf("已结案不参与归并，应 400，得到 %d", r.StatusCode)
	}

	post := func(ts *httptest.Server, ids []uuid.UUID, status, note string, confirm bool) (int, string) {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"ids": ids, "status": status, "note": note, "confirmMalicious": confirm})
		r, err := postJSON(ts, "/api/incidents/batch-status", string(b))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		msg, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(msg)
	}
	statusOf := func(id uuid.UUID) string { return db.Incident.GetX(ctx, id).Status }
	group := []uuid.UUID{ben1.ID, ben2.ID, mal.ID}

	// 组里有 AI 判恶意的：不确认就整批不动
	if code, msg := post(admin, group, "false_positive", "运维批量脚本", false); code != 409 || !strings.Contains(msg, "恶意") {
		t.Errorf("恶意未确认应 409，得到 %d %s", code, msg)
	}
	// 没写理由且 ben2 没研判：整批拒绝，不做部分结案
	if code, _ := post(admin, []uuid.UUID{ben1.ID, ben2.ID}, "false_positive", "", false); code != 400 {
		t.Errorf("缺理由应 400，得到 %d", code)
	}
	for _, id := range group {
		if s := statusOf(id); s != "open" {
			t.Fatalf("被拒的批量不应改动任何事件，%s 已是 %s", id, s)
		}
	}
	tooMany := make([]uuid.UUID, batchResolveMax+1)
	for i := range tooMany {
		tooMany[i] = uuid.New()
	}
	if code, _ := post(admin, tooMany, "closed", "x", false); code != 400 {
		t.Errorf("超过上限应 400，得到 %d", code)
	}
	if code, _ := post(admin, []uuid.UUID{ben1.ID, uuid.New()}, "closed", "x", false); code != 404 {
		t.Errorf("含不存在的事件应 404，得到 %d", code)
	}

	// 组内只是 viewer：整批拒绝；analyst 碰到组外事件也整批拒绝
	member := func(name, role string) *httptest.Server {
		u := db.User.Create().SetUsername(name).SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
		db.GroupMember.Create().SetGroupID(gA.ID).SetUserID(u.ID).SetRole(role).SaveX(ctx)
		ts := httptest.NewServer(as(u, h))
		t.Cleanup(ts.Close)
		return ts
	}
	viewer, analyst := member("vic", "viewer"), member("ann", "analyst")
	if code, _ := post(viewer, []uuid.UUID{ip1.ID}, "closed", "x", false); code != 403 {
		t.Errorf("viewer 批量结案应 403，得到 %d", code)
	}
	if code, _ := post(analyst, []uuid.UUID{ip1.ID, foreign.ID}, "closed", "x", false); code != 403 {
		t.Errorf("含组外事件应 403，得到 %d", code)
	}
	if _, raw := get(t, analyst, "/api/incidents/groups?status=unresolved"); strings.Contains(string(raw), `"hostname":"b01"`) {
		t.Errorf("归并视图不应露出组外主机：%s", raw)
	}

	// 二次确认后整组按误报关：逐条记结案人与审计，作为人工案例（resolution_source 为空）
	if code, msg := post(analyst, append(group, ben1.ID), "false_positive", "确认是备份任务", true); code != 200 || !strings.Contains(msg, `"resolved":3`) {
		t.Fatalf("确认后批量结案应成功，得到 %d %s", code, msg)
	}
	for _, id := range group {
		inc := db.Incident.GetX(ctx, id)
		if inc.Status != "false_positive" || inc.ResolvedBy == nil || *inc.ResolvedBy != "ann" || inc.Resolution == nil || *inc.Resolution != "确认是备份任务" || inc.ResolutionSource != nil {
			t.Errorf("结案信息不符：%+v", inc)
		}
		if n := db.AuditLog.Query().Where(auditlog.TargetEQ(id.String()), auditlog.ActionEQ("incident_status")).CountX(ctx); n != 1 {
			t.Errorf("%s 审计应 1 条，得到 %d", id, n)
		}
	}
	// 已结案的再进批量：冲突，不覆盖别人的结论
	if code, _ := post(analyst, []uuid.UUID{ben1.ID, onDB.ID}, "closed", "x", false); code != 409 || statusOf(onDB.ID) != "open" {
		t.Errorf("含已结案事件应 409 且不动其余，得到 %d", code)
	}

	// 原样用了组内某个事件的 AI 结案建议：整批都记为 ai_proposal，不当人工案例回喂
	proposal := &schema.ClosureProposal{Status: "false_positive", Note: "扫描器探测，已加白", SessionID: uuid.New(), At: now}
	db.Incident.UpdateOneID(ip1.ID).SetClosureProposal(proposal).ExecX(ctx)
	if code, msg := post(analyst, []uuid.UUID{ip1.ID, ip2.ID}, "false_positive", " 扫描器探测，已加白 ", false); code != 200 {
		t.Fatalf("采纳建议批量结案应成功，得到 %d %s", code, msg)
	}
	for _, id := range []uuid.UUID{ip1.ID, ip2.ID} {
		inc := db.Incident.GetX(ctx, id)
		if inc.ResolutionSource == nil || *inc.ResolutionSource != "ai_proposal" || inc.ClosureProposal != nil {
			t.Errorf("采纳建议应记 ai_proposal 并清掉建议：%+v", inc)
		}
	}
}
