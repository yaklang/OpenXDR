//go:build integration

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// 可信来源只有组管理员能登记与撤销，校验识别条件与有效期，全程落审计；
// 组外看不到；候选列表来自组内核对过出处的 SSH 登录；事件列表标注来源
func TestTrustedSourcesAPI(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("ops").SaveX(ctx)
	other := client.Group.Create().SetName("other").SaveX(ctx)
	host := client.Asset.Create().SetHostname("pve1").SetGroupID(g.ID).SaveX(ctx)
	analyst := client.User.Create().SetUsername("ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(analyst.ID).SetRole("analyst").SaveX(ctx)
	lead := client.User.Create().SetUsername("lead").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(lead.ID).SetRole("admin").SaveX(ctx)
	outsider := client.User.Create().SetUsername("out").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(other.ID).SetUserID(outsider.ID).SetRole("admin").SaveX(ctx)

	// 组内一次核对过出处的登录、一次没带登录归属的登录
	const fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	client.Event.Create().SetTs(time.Now().Add(-time.Hour)).SetClassUID(3002).SetSource("agent").SetAssetID(host.ID).
		SetRaw(json.RawMessage(`{"status_id":1,"login_session":{"user":"root","src_ip":"10.1.1.35","auth_method":"publickey","key_type":"ED25519","key_fp":"` + fp + `"}}`)).SaveX(ctx)
	client.Event.Create().SetTs(time.Now().Add(-time.Hour)).SetClassUID(3002).SetSource("agent").SetAssetID(host.ID).
		SetRaw(json.RawMessage(`{"status_id":1}`)).SaveX(ctx)

	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	asAnalyst := httptest.NewServer(as(analyst, h))
	t.Cleanup(asAnalyst.Close)
	asLead := httptest.NewServer(as(lead, h))
	t.Cleanup(asLead.Close)
	asOutsider := httptest.NewServer(as(outsider, h))
	t.Cleanup(asOutsider.Close)

	post := func(s *httptest.Server, path, body string) *http.Response {
		t.Helper()
		resp, err := http.Post(s.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	body := `{"groupId":"` + g.ID.String() + `","name":"Termix","reason":"AI 运维插件","keyFingerprint":"` + fp + `","sourceCidr":"10.1.1.35","expiresInDays":90}`

	if resp := post(asAnalyst, "/api/trusted-sources", body); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("组内 analyst 不能登记，得到 %d", resp.StatusCode)
	}
	if resp := post(asOutsider, "/api/trusted-sources", body); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("别组管理员不能登记，得到 %d", resp.StatusCode)
	}
	for _, bad := range []string{
		`{"groupId":"` + g.ID.String() + `","name":"x","loginUser":"root","expiresInDays":30}`,
		`{"groupId":"` + g.ID.String() + `","name":"x","keyFingerprint":"` + fp + `","expiresInDays":0}`,
		`{"groupId":"` + g.ID.String() + `","name":"x","keyFingerprint":"` + fp + `","expiresInDays":400}`,
		`{"groupId":"` + g.ID.String() + `","name":"x","sourceCidr":"10.0.0.0/8","expiresInDays":30}`,
		`{"groupId":"` + g.ID.String() + `","name":"","keyFingerprint":"` + fp + `","expiresInDays":30}`,
	} {
		if resp := post(asLead, "/api/trusted-sources", bad); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s 应被拒绝，得到 %d", bad, resp.StatusCode)
		}
	}
	resp := post(asLead, "/api/trusted-sources", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("组管理员登记应 201，得到 %d", resp.StatusCode)
	}
	var created trustedSourceRow
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.SourceCIDR == nil || *created.SourceCIDR != "10.1.1.35/32" || created.CreatedBy != "lead" ||
		created.ExpiresAt.Before(time.Now().Add(89*24*time.Hour)) {
		t.Fatalf("登记结果不对: %+v", created)
	}
	if n := client.AuditLog.Query().Where(auditlog.ActionEQ("trusted_source_created"), auditlog.TargetEQ(created.ID.String())).CountX(ctx); n != 1 {
		t.Fatalf("登记应落审计，实际 %d 条", n)
	}

	list := func(s *httptest.Server) []trustedSourceRow {
		t.Helper()
		resp, err := http.Get(s.URL + "/api/trusted-sources")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var rows []trustedSourceRow
		if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	if rows := list(asAnalyst); len(rows) != 1 {
		t.Fatalf("组内成员应能看到，实际 %d 条", len(rows))
	}
	if rows := list(asOutsider); len(rows) != 0 {
		t.Fatalf("组外看不到，实际 %d 条", len(rows))
	}

	// 候选：来自后台收进 ssh_logins 的核对过出处的登录，标出已被刚登记的来源覆盖
	client.SSHLogin.Create().SetID(uuid.New()).SetTs(time.Now().Add(-time.Hour)).SetGroupID(g.ID).SetAssetID(host.ID).
		SetLoginUser("root").SetSrcIP("10.1.1.35").SetAuthMethod("publickey").SetKeyFp(fp).SetKeyType("ED25519").ExecX(ctx)
	raw, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	candidates := httptest.NewServer(as(lead, TrustedCandidates(client, raw)))
	t.Cleanup(candidates.Close)
	cresp, err := http.Get(candidates.URL + "/api/trusted-sources/candidates?groupId=" + g.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	defer cresp.Body.Close()
	var cands []trustedCandidate
	if err := json.NewDecoder(cresp.Body).Decode(&cands); err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 || cands[0].KeyFP == nil || *cands[0].KeyFP != fp || cands[0].Logins != 1 || cands[0].Reason != "covered" ||
		len(cands[0].SourceIDs) != 1 || cands[0].SourceIDs[0] != created.ID.String() {
		t.Fatalf("候选不对: %+v", cands)
	}

	// 事件列表标注来源
	ev := client.Event.Create().SetTs(time.Now().Add(-time.Minute)).SetClassUID(1007).SetSource("agent").SetAssetID(host.ID).
		SetRaw(json.RawMessage(`{"process":{"cmd_line":"uname -a"}}`)).SaveX(ctx)
	client.Alert.Create().SetTs(ev.Ts).SetRuleID("r").SetSeverity(3).SetEventID(ev.ID).SetAssetID(host.ID).
		SetAutomationID(created.ID).SaveX(ctx)
	eresp, err := http.Get(asAnalyst.URL + "/api/events?classUid=1007")
	if err != nil {
		t.Fatal(err)
	}
	defer eresp.Body.Close()
	// /api/events 是对象契约 {items, truncated, coverage}：取 items 再断言标注
	var events struct {
		Items []eventRow `json:"items"`
	}
	if err := json.NewDecoder(eresp.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	if len(events.Items) != 1 || events.Items[0].Automation == nil || events.Items[0].Automation.Name != "Termix" {
		t.Fatalf("事件应标注可信来源: %+v", events.Items)
	}

	revoke := "/api/trusted-sources/" + created.ID.String() + "/revoke"
	if resp := post(asAnalyst, revoke, ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("组内 analyst 不能撤销，得到 %d", resp.StatusCode)
	}
	if resp := post(asLead, revoke, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("组管理员撤销应 204，得到 %d", resp.StatusCode)
	}
	if resp := post(asLead, revoke, ""); resp.StatusCode != http.StatusConflict {
		t.Fatalf("重复撤销应 409，得到 %d", resp.StatusCode)
	}
	got := client.TrustedSource.GetX(ctx, created.ID)
	if got.RevokedAt == nil || got.RevokedBy == nil || *got.RevokedBy != "lead" {
		t.Fatalf("撤销应留下时间与操作人: %+v", got)
	}
	if n := client.AuditLog.Query().Where(auditlog.ActionEQ("trusted_source_revoked"), auditlog.TargetEQ(created.ID.String())).CountX(ctx); n != 1 {
		t.Fatalf("撤销应落审计，实际 %d 条", n)
	}

	// 调整：改名、固定、改有效期、启用；删除后隐藏，再改 409
	do := func(s *httptest.Server, method, path, body string) int {
		t.Helper()
		req, _ := http.NewRequest(method, s.URL+path, strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	item := "/api/trusted-sources/" + created.ID.String()
	if code := do(asAnalyst, http.MethodPatch, item, `{"enabled":true}`); code != http.StatusForbidden {
		t.Fatalf("组内 analyst 不能调整，得到 %d", code)
	}
	for _, bad := range []string{`{}`, `{"name":" "}`, `{"expiresInDays":0}`} {
		if code := do(asLead, http.MethodPatch, item, bad); code != http.StatusBadRequest {
			t.Fatalf("%s 应 400，得到 %d", bad, code)
		}
	}
	if code := do(asLead, http.MethodPatch, item, `{"enabled":true,"name":"Termix AI","pinned":true,"expiresInDays":30}`); code != http.StatusOK {
		t.Fatalf("启用并调整应 200，得到 %d", code)
	}
	got = client.TrustedSource.GetX(ctx, created.ID)
	if got.RevokedAt != nil || got.Name != "Termix AI" || !got.Pinned || got.ConfirmedAt == nil || got.ExpiresAt.After(time.Now().AddDate(0, 0, 31)) {
		t.Fatalf("调整结果不对: %+v", got)
	}
	if n := client.AuditLog.Query().Where(auditlog.ActionEQ("trusted_source_enabled"), auditlog.TargetEQ(created.ID.String())).CountX(ctx); n != 1 {
		t.Fatalf("启用应落审计，实际 %d 条", n)
	}
	if code := do(asLead, http.MethodPatch, item, `{"enabled":false}`); code != http.StatusOK {
		t.Fatalf("停用应 200，得到 %d", code)
	}
	if code := do(asLead, http.MethodDelete, item, ``); code != http.StatusNoContent {
		t.Fatalf("删除应 204，得到 %d", code)
	}
	if code := do(asLead, http.MethodDelete, item, ``); code != http.StatusConflict {
		t.Fatalf("重复删除应 409，得到 %d", code)
	}
	if code := do(asLead, http.MethodPatch, item, `{"name":"x"}`); code != http.StatusConflict {
		t.Fatalf("删除后不能再改，得到 %d", code)
	}
	if rows := list(asLead); len(rows) != 0 {
		t.Fatalf("删除后列表不再显示，实际 %d 条", len(rows))
	}
	if n := client.AuditLog.Query().Where(auditlog.ActionEQ("trusted_source_deleted"), auditlog.TargetEQ(created.ID.String())).CountX(ctx); n != 1 {
		t.Fatalf("删除应落审计，实际 %d 条", n)
	}
}
