//go:build integration

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// AI 提议的抑制：批准前不生效；组内 analyst 不能批，组管理员能；批准后立即生效，有效期从批准时重新算
func TestSuppressionReview(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("A").SaveX(ctx)
	host := client.Asset.Create().SetHostname("pve1").SetGroupID(g.ID).SaveX(ctx)
	created := time.Now().Add(-10 * 24 * time.Hour)
	p := client.Suppression.Create().SetRuleID("probe").SetAssetID(host.ID).SetStatus("proposed").SetReason("例行巡检").
		SetCreatedBy("ai:x").SetCreatedAt(created).SetExpiresAt(created.Add(30 * 24 * time.Hour)).SaveX(ctx)
	analyst := client.User.Create().SetUsername("ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(analyst.ID).SetRole("analyst").SaveX(ctx)
	lead := client.User.Create().SetUsername("lead").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(lead.ID).SetRole("admin").SaveX(ctx)

	store := suppress.New(client, time.Hour)
	store.Reload(ctx)
	if store.Suppressed("probe", &host.ID, nil, time.Now()) {
		t.Fatal("提议在批准前不能生效")
	}
	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), store, intel.New(client, time.Hour), nil)
	review := func(ts *httptest.Server, decision string) int {
		resp, err := http.Post(ts.URL+"/api/suppressions/"+p.ID.String()+"/review", "application/json", strings.NewReader(`{"decision":"`+decision+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	asAnalyst := httptest.NewServer(as(analyst, h))
	t.Cleanup(asAnalyst.Close)
	asLead := httptest.NewServer(as(lead, h))
	t.Cleanup(asLead.Close)
	if code := review(asAnalyst, "approve"); code != http.StatusForbidden {
		t.Fatalf("组内 analyst 不能批准，得到 %d", code)
	}
	if code := review(asLead, "approve"); code != http.StatusNoContent {
		t.Fatalf("组管理员批准应 204，得到 %d", code)
	}
	got := client.Suppression.GetX(ctx, p.ID)
	if got.Status != "active" || got.ReviewedBy == nil || got.ExpiresAt.Before(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("批准后应生效、有效期从批准时重新算: %+v", got)
	}
	if !store.Suppressed("probe", &host.ID, nil, time.Now()) {
		t.Fatal("批准后应立即生效")
	}
	if code := review(asLead, "reject"); code != http.StatusConflict {
		t.Fatalf("已处理的提议不能再审，得到 %d", code)
	}
}

// 内置良性链 API 权限与保护：viewer 可见；仅全局 admin 可启停（PATCH）；禁止硬删除（DELETE）与人工创建通配规则
func TestBuiltinSuppressionToggleAndProtection(t *testing.T) {
	ctx, client := testdb.New(t)
	rules := sigma.LoadDir("../../../rules")
	if _, err := suppress.SyncBuiltins(ctx, client, rules, "../../../rules/benign-chains"); err != nil {
		t.Fatalf("SyncBuiltins: %v", err)
	}
	store := suppress.New(client, time.Hour)
	store.SetRules(rules)
	store.Reload(ctx)

	admin := client.User.Create().SetUsername("root-admin").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	analyst := client.User.Create().SetUsername("sec-ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)

	h := Handler(client, nil, rules, response.NewHub(client, false), store, intel.New(client, time.Hour), nil)
	asAdmin := httptest.NewServer(as(admin, h))
	t.Cleanup(asAdmin.Close)
	asAnalyst := httptest.NewServer(as(analyst, h))
	t.Cleanup(asAnalyst.Close)

	// analyst GET /api/suppressions 能看到内置良性链
	resp, err := http.Get(asAnalyst.URL + "/api/suppressions")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/suppressions: %v %v", resp, err)
	}
	resp.Body.Close()

	var targetID string
	for _, s := range client.Suppression.Query().AllX(ctx) {
		if s.BuiltinKey != nil && *s.BuiltinKey == "kafka-tool-uname" {
			targetID = s.ID.String()
		}
	}
	if targetID == "" {
		t.Fatal("未找到 kafka-tool-uname 内置链")
	}

	req := func(ts *httptest.Server, method, path, body string) int {
		r, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}

	if code := req(asAnalyst, http.MethodPatch, "/api/suppressions/"+targetID, `{"enabled":false}`); code != http.StatusForbidden {
		t.Fatalf("非 admin 不能启停内置链，得到 %d", code)
	}
	if code := req(asAdmin, http.MethodDelete, "/api/suppressions/"+targetID, ""); code != http.StatusBadRequest {
		t.Fatalf("内置链禁止 DELETE，得到 %d", code)
	}
	if code := req(asAdmin, http.MethodPost, "/api/suppressions", `{"ruleId":"*"}`); code != http.StatusBadRequest {
		t.Fatalf("人工接口禁止创建通配 * 抑制，得到 %d", code)
	}
	if code := req(asAdmin, http.MethodPatch, "/api/suppressions/"+targetID, `{"enabled":false}`); code != http.StatusOK {
		t.Fatalf("admin 停用内置链应 200，得到 %d", code)
	}
	raw := map[string]any{
		"process": map[string]any{
			"file":     map[string]any{"path": "/bin/uname"},
			"cmd_line": "/bin/uname -a",
			"parent_process": map[string]any{
				"file":     map[string]any{"path": "/bin/bash"},
				"cmd_line": "/bin/bash /opt/kafka/bin/kafka-run-class.sh kafka.admin.TopicCommand --list",
			},
		},
	}
	if store.Suppressed(sigma.RuleNewProcess, nil, raw, time.Now()) {
		t.Fatal("停用后不应再抑制")
	}
	if code := req(asAdmin, http.MethodPatch, "/api/suppressions/"+targetID, `{"enabled":true}`); code != http.StatusOK {
		t.Fatalf("admin 重新启用内置链应 200，得到 %d", code)
	}
	if !store.Suppressed(sigma.RuleNewProcess, nil, raw, time.Now()) {
		t.Fatal("重新启用后应立即抑制")
	}
}
