//go:build integration

package integration

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/flowinput"
	"openxdr/server/internal/testdb"
)

// 流量写入走集成 Token：需要 flows:write 且恰好一个授权组，来源组与探针身份只取自集成本身。
func TestFlowEventsEndpoint(t *testing.T) {
	ctx, db := testdb.New(t)
	owner := db.User.Create().SetUsername("owner").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	g := db.Group.Create().SetName("A").SaveX(ctx)
	i := db.Integration.Create().SetName("edge-a").SetPurpose("test").SetOwnerID(owner.ID).SetEnabled(true).SetScopes([]string{"flows:write", "assets:read"}).SaveX(ctx)
	db.IntegrationGroup.Create().SetIntegrationID(i.ID).SetGroupID(g.ID).SaveX(ctx)
	token := func(name string, scopes ...string) string {
		plain := "oxi_" + name + strings.Repeat("x", 40)
		db.IntegrationToken.Create().SetIntegrationID(i.ID).SetPrefix("oxi_" + name).SetTokenHash(TokenHash(plain)).SetScopes(scopes).SetExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)
		return plain
	}
	writer, reader := token("w", "flows:write"), token("r", "assets:read")
	var got []flowinput.Origin
	h := (&Service{DB: db, CursorKey: []byte(strings.Repeat("s", 32)), Flows: func(_ context.Context, origin flowinput.Origin, _ flowinput.Event) error {
		got = append(got, origin)
		return nil
	}}).Handler()
	alert := `{"IPV4_SRC_ADDR":"192.0.2.1","IPV4_DST_ADDR":"198.51.100.2","L4_SRC_PORT":1,"L4_DST_PORT":443,"PROTOCOL":6,"FIRST_SWITCHED":1794000000,"group_id":"` + uuid.NewString() + `"}`
	post := func(plain string) int {
		r := httptest.NewRequest("POST", "/api/integration/v1/flows/ntopng/events", strings.NewReader(alert))
		r.Header.Set("Authorization", "Bearer "+plain)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := post(reader); code != 403 {
		t.Fatalf("缺 flows:write 的令牌不能写入: %d", code)
	}
	// 持续流量不受人工调用的限流约束
	for n := range 50 {
		if code := post(writer); code != 202 {
			t.Fatalf("第 %d 条写入失败: %d", n, code)
		}
	}
	if len(got) != 50 || got[0].GroupID != g.ID || got[0].Observer != i.ID.String() {
		t.Fatalf("来源不是集成本身: %+v", got[0])
	}
	db.IntegrationGroup.Create().SetIntegrationID(i.ID).SetGroupID(db.Group.Create().SetName("B").SaveX(ctx).ID).SaveX(ctx)
	if code := post(writer); code != 403 {
		t.Fatalf("多组授权时无从判断归属，应拒绝: %d", code)
	}
}
