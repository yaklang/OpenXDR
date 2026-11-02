//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/schema"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// 记忆按组可见；组内 viewer 只能看，analyst 以上可增删改，人改过的变成人工记忆；主机必须属于该组
func TestAPIMemories(t *testing.T) {
	ctx, client := testdb.New(t)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	hA := client.Asset.Create().SetHostname("pve1").SetGroupID(gA.ID).SaveX(ctx)
	hB := client.Asset.Create().SetHostname("pve2").SetGroupID(gB.ID).SaveX(ctx)
	ai := client.Memory.Create().SetGroupID(gA.ID).SetAssetID(hA.ID).SetContent("AI 记的").SetSource("ai").SetAuthor("s").SaveX(ctx)
	client.Memory.Create().SetGroupID(gB.ID).SetContent("B组秘密").SetSource("human").SetAuthor("b").SaveX(ctx)
	alice := client.User.Create().SetUsername("alice").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(alice.ID).SetRole("viewer").SaveX(ctx)

	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	admin := httptest.NewServer(asAdmin(h))
	t.Cleanup(admin.Close)
	viewer := httptest.NewServer(as(alice, h))
	t.Cleanup(viewer.Close)

	_, body := get(t, viewer, "/api/memories")
	var rows []memoryRow
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) != 1 || rows[0].Hostname != "pve1" || strings.Contains(string(body), "B组秘密") {
		t.Fatalf("记忆越组或缺主机名：%s", body)
	}
	send := func(ts *httptest.Server, method, path, body string) int {
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := send(viewer, "POST", "/api/memories", `{"groupId":"`+gA.ID.String()+`","content":"x"}`); code != http.StatusForbidden {
		t.Errorf("组内 viewer 不能写记忆，得到 %d", code)
	}
	if code := send(admin, "POST", "/api/memories", `{"groupId":"`+gA.ID.String()+`","assetId":"`+hB.ID.String()+`","content":"x"}`); code != http.StatusBadRequest {
		t.Errorf("别组主机应 400，得到 %d", code)
	}
	if code := send(admin, "POST", "/api/memories", `{"groupId":"`+gA.ID.String()+`","content":"10.1.1.100 是网关容器"}`); code != http.StatusOK {
		t.Fatalf("新增应 200，得到 %d", code)
	}
	if code := send(admin, "PATCH", "/api/memories/"+ai.ID.String(), `{"content":"人改过"}`); code != http.StatusNoContent {
		t.Fatalf("修改应 204，得到 %d", code)
	}
	if m := client.Memory.GetX(ctx, ai.ID); m.Source != "human" || m.Content != "人改过" || m.Author != "admin" {
		t.Errorf("人改过的应变成人工记忆：%+v", m)
	}
	if code := send(admin, "DELETE", "/api/memories/"+ai.ID.String(), ""); code != http.StatusNoContent {
		t.Fatalf("删除应 204，得到 %d", code)
	}
	if n := client.AuditLog.Query().CountX(ctx); n != 3 {
		t.Errorf("增删改都要写审计，得到 %d 条", n)
	}
}

// 采纳（人结案）与忽略都会清掉 AI 的结案建议；结案记在人名下
func TestClosureProposalLifecycle(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("A").SaveX(ctx)
	host := client.Asset.Create().SetHostname("pve1").SetGroupID(g.ID).SaveX(ctx)
	proposal := &schema.ClosureProposal{Status: "false_positive", Note: "良性", SessionID: uuid.New(), At: time.Now()}
	mk := func() uuid.UUID {
		inc := client.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetClosureProposal(proposal).SaveX(ctx)
		client.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(3).SetAssetID(host.ID).SetIncidentID(inc.ID).SaveX(ctx)
		return inc.ID
	}
	adopted, dismissed := mk(), mk()
	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	admin := httptest.NewServer(asAdmin(h))
	t.Cleanup(admin.Close)
	_, body := get(t, admin, "/api/incidents/"+adopted.String())
	if !strings.Contains(string(body), `"closureProposal":{"status":"false_positive"`) {
		t.Fatalf("详情应带结案建议: %s", body)
	}
	resp, err := http.Post(admin.URL+"/api/incidents/"+adopted.String()+"/status", "application/json", strings.NewReader(`{"status":"false_positive","note":"良性"}`))
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("结案: %v %v", err, resp)
	}
	if inc := client.Incident.GetX(ctx, adopted); inc.ClosureProposal != nil || inc.ResolvedBy == nil || *inc.ResolvedBy != "admin" {
		t.Fatalf("采纳后建议应清掉、结案记在人名下: %+v", inc)
	}
	req, _ := http.NewRequest("DELETE", admin.URL+"/api/incidents/"+dismissed.String()+"/closure-proposal", nil)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("忽略: %v %v", err, resp)
	}
	if inc := client.Incident.GetX(ctx, dismissed); inc.ClosureProposal != nil || inc.Status != "open" {
		t.Fatalf("忽略后建议应清掉、状态不变: %+v", inc)
	}
}

// 结论与 AI 研判一致时可以不写理由（说明取研判摘要、记为 ai_verdict）；相反或没研判时必须写；
// 原样采纳 AI 结案建议记为 ai_proposal。这两种都不当人工案例
func TestCloseWithoutNote(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("A").SaveX(ctx)
	host := client.Asset.Create().SetHostname("pve1").SetGroupID(g.ID).SaveX(ctx)
	mk := func(verdict string) uuid.UUID {
		c := client.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetStatus("triaged")
		if verdict != "" {
			c.SetAiVerdict(json.RawMessage(`{"verdict":"` + verdict + `","confidence":80,"summary":"Termix 面板 SSH 健康检查"}`))
		}
		inc := c.SaveX(ctx)
		client.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(3).SetAssetID(host.ID).SetIncidentID(inc.ID).SaveX(ctx)
		return inc.ID
	}
	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	ts := httptest.NewServer(asAdmin(h))
	t.Cleanup(ts.Close)
	status := func(id uuid.UUID, body string) int {
		resp, err := http.Post(ts.URL+"/api/incidents/"+id.String()+"/status", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	benign := mk("benign")
	if code := status(benign, `{"status":"closed"}`); code != http.StatusBadRequest {
		t.Errorf("AI 判良性却按属实关、不写理由应 400，得到 %d", code)
	}
	if code := status(benign, `{"status":"false_positive"}`); code != http.StatusNoContent {
		t.Fatalf("与研判一致可以不写理由，得到 %d", code)
	}
	if inc := client.Incident.GetX(ctx, benign); inc.ResolutionSource == nil || *inc.ResolutionSource != "ai_verdict" ||
		inc.Resolution == nil || !strings.Contains(*inc.Resolution, "Termix 面板 SSH 健康检查") {
		t.Errorf("说明应取研判摘要并标来源: %+v", inc)
	}
	if code := status(mk(""), `{"status":"false_positive"}`); code != http.StatusBadRequest {
		t.Errorf("没有研判时不写理由应 400，得到 %d", code)
	}
	proposed := mk("benign")
	client.Incident.UpdateOneID(proposed).SetClosureProposal(&schema.ClosureProposal{Status: "false_positive", Note: "AI 写的结案说明", SessionID: uuid.New(), At: time.Now()}).ExecX(ctx)
	if code := status(proposed, `{"status":"false_positive","note":"AI 写的结案说明"}`); code != http.StatusNoContent {
		t.Fatalf("采纳建议应 204，得到 %d", code)
	}
	if inc := client.Incident.GetX(ctx, proposed); inc.ResolutionSource == nil || *inc.ResolutionSource != "ai_proposal" {
		t.Errorf("原样采纳 AI 建议应记为 ai_proposal: %+v", inc.ResolutionSource)
	}
	human := mk("benign")
	if code := status(human, `{"status":"false_positive","note":"我看过了，是运维脚本"}`); code != http.StatusNoContent || client.Incident.GetX(ctx, human).ResolutionSource != nil {
		t.Errorf("人自己写的理由不标来源")
	}
}
