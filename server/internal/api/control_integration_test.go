//go:build integration

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/testdb"
)

// 权威事实只有平台管理员能写；意图只能由持有人为自己名下的通道登记，组外主机不行；登记推送通知、落审计
func TestControlAPI(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("ops").SaveX(ctx)
	other := client.Group.Create().SetName("other").SaveX(ctx)
	host := client.Asset.Create().SetHostname("dd").SetGroupID(g.ID).SaveX(ctx)
	outside := client.Asset.Create().SetHostname("x").SetGroupID(other.ID).SaveX(ctx)
	admin := client.User.Create().SetUsername("root").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	ana := client.User.Create().SetUsername("ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(ana.ID).SetRole("analyst").SaveX(ctx)

	var notes []string
	h := Control(client, func(_ context.Context, title, body, _ string) error {
		notes = append(notes, title+"："+body)
		return nil
	})
	asAdmin := httptest.NewServer(as(admin, h))
	t.Cleanup(asAdmin.Close)
	asAna := httptest.NewServer(as(ana, h))
	t.Cleanup(asAna.Close)
	post := func(s *httptest.Server, path, body string) int {
		t.Helper()
		resp, err := http.Post(s.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	const fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	key := `{"kind":"key","subject":"` + fp + `","holder":"user:ana","content":"ana 的工作机钥匙"}`
	if code := post(asAna, "/api/facts", key); code != http.StatusForbidden {
		t.Fatalf("分析员不能写事实：%d", code)
	}
	if code := post(asAdmin, "/api/facts", `{"kind":"key","subject":"md5","content":"x"}`); code != http.StatusBadRequest {
		t.Fatalf("指纹格式不对应拒绝：%d", code)
	}
	if code := post(asAdmin, "/api/facts", key); code != http.StatusCreated {
		t.Fatalf("管理员录入钥匙：%d", code)
	}
	if code := post(asAdmin, "/api/facts", `{"kind":"channel","subject":"10.1.1.161","holder":"user:ana","content":"ana 的办公机"}`); code != http.StatusCreated {
		t.Fatalf("管理员录入通道：%d", code)
	}
	intent := func(asset fmt.Stringer, src string) string {
		return `{"keyFingerprint":"` + fp + `","sourceAddr":"` + src + `","assetIds":["` + asset.String() + `"],"category":"troubleshoot","durationMinutes":60,"note":"排查 manage-backend"}`
	}
	if code := post(asAna, "/api/intents", intent(outside.ID, "10.1.1.161")); code != http.StatusForbidden {
		t.Fatalf("组外主机不能登记：%d", code)
	}
	if code := post(asAna, "/api/intents", intent(host.ID, "10.1.1.3")); code != http.StatusForbidden {
		t.Fatalf("不在名下的来源不能登记：%d", code)
	}
	if code := post(asAdmin, "/api/intents", intent(host.ID, "10.1.1.161")); code != http.StatusForbidden {
		t.Fatalf("管理员也不能替别人的通道登记：%d", code)
	}
	if code := post(asAna, "/api/intents", intent(host.ID, "10.1.1.161")); code != http.StatusCreated {
		t.Fatalf("持有人登记：%d", code)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "user:ana") || !strings.Contains(notes[0], "dd") {
		t.Fatalf("登记应实时推送：%v", notes)
	}
	resp, err := http.Get(asAna.URL + "/api/intents?active=1")
	if err != nil {
		t.Fatal(err)
	}
	var rows []intentRow
	_ = json.NewDecoder(resp.Body).Decode(&rows)
	resp.Body.Close()
	if len(rows) != 1 || !rows[0].Active || rows[0].Hostnames[0] != "dd" {
		t.Fatalf("列表：%+v", rows)
	}
	if code := post(asAna, "/api/intents/"+rows[0].ID.String()+"/end", ""); code != http.StatusNoContent {
		t.Fatalf("登记人可以提前结束：%d", code)
	}
	for _, action := range []string{"fact_created", "intent_registered", "intent_ended"} {
		if !client.AuditLog.Query().Where(auditlog.ActionEQ(action)).ExistX(ctx) {
			t.Errorf("缺审计 %s", action)
		}
	}
}
