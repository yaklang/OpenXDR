//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/deception/native"
	"openxdr/server/deception/sdk"
	"openxdr/server/ent"
	"openxdr/server/ent/decoydeployment"
	"openxdr/server/ent/decoyobservation"
	"openxdr/server/internal/decoy"
	"openxdr/server/internal/testdb"
)

func TestDecoyRuntimeEndToEnd(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("runtime").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	host := db.Asset.Create().SetHostname("host").SetGroupID(group.ID).SaveX(ctx)
	management := http.NewServeMux()
	mapSSHDecoys(management, db)
	root := http.NewServeMux()
	root.Handle("/api/decoy-runtime/", DecoyRuntime(db))
	root.Handle("/", as(&ent.User{Username: "admin", Role: "admin"}, management))
	request := func(method, path, token string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(b))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		root.ServeHTTP(w, r)
		return w
	}
	create := func(kind, resource string, port int) ent.DecoyDeployment {
		t.Helper()
		w := request("POST", "/api/decoys", "", map[string]any{"assetId": host.ID, "profile": "decoy", "kind": kind, "resource": resource, "port": port})
		if w.Code != 201 {
			t.Fatalf("登记 %s: %d %s", kind, w.Code, w.Body)
		}
		var row ent.DecoyDeployment
		if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	row := create("http", "", 8088)
	create("file", "README.md", 0)
	create("file", "notes.md", 0)
	create("shell", "simulated-shell", 0)
	issue := func(id uuid.UUID) string {
		t.Helper()
		w := request("POST", "/api/decoys/"+id.String()+"/token", "", nil)
		if w.Code != 200 {
			t.Fatalf("令牌: %d %s", w.Code, w.Body)
		}
		var data struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		return data.Token
	}
	token := issue(row.ID)
	base := "/api/decoy-runtime/" + row.ID.String()
	if w := request("GET", base+"/config", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request("GET", "/api/decoys?groupId="+group.ID.String(), "", nil); bytes.Contains(w.Body.Bytes(), []byte(token)) || bytes.Contains(w.Body.Bytes(), []byte("token_hash")) || bytes.Contains(w.Body.Bytes(), []byte(`"marker"`)) {
		t.Fatal("列表泄露凭据或标记")
	}
	ts := httptest.NewServer(root)
	defer ts.Close()
	client, err := sdk.NewClient(ts.URL, row.ID.String(), token)
	if err != nil {
		t.Fatal(err)
	}
	m, err := client.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := native.HTTPHandler(m, func(kind string) error { return client.Record(ctx, kind) })
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/decoy/" + m.ID, "/decoy/" + m.ID + "/verify/" + m.Marker} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatalf("诱饵: %d %s", w.Code, w.Body)
		}
	}
	// 标记命中自动开单，页面访问不开。
	if db.Incident.Query().CountX(ctx) != 1 || db.Alert.Query().OnlyX(ctx).RuleID != decoy.ObservationRulePrefix+"marker_used" {
		t.Fatal("标记命中未自动进入复核")
	}
	if n := db.DecoyObservation.Query().CountX(ctx); n != 2 {
		t.Fatal(n)
	}
	event := decoy.Observation{ID: uuid.NewString(), Kind: "http_page"}
	for range 2 {
		if w := request("POST", base+"/events", token, event); w.Code != 204 {
			t.Fatal(w.Code, w.Body)
		}
	}
	if n := db.DecoyObservation.Query().CountX(ctx); n != 3 {
		t.Fatalf("重放重复入库: %d", n)
	}
	event.Kind = "marker_used"
	if w := request("POST", base+"/events", token, event); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if w := request("POST", base+"/events", token, map[string]any{"id": uuid.NewString(), "kind": "http_page", "assetId": uuid.NewString()}); w.Code != 400 {
		t.Fatal("接受伪造资产", w.Code)
	}
	event.ID = uuid.NewString()
	event.Kind = "file_opened"
	if w := request("POST", base+"/events", token, event); w.Code != 400 {
		t.Fatal("接受其他载体事件", w.Code)
	}
	// 新实例或不同事件 ID 不能重放同一代标记。
	event.ID = uuid.NewString()
	event.Kind = "marker_used"
	if w := request("POST", base+"/events", token, event); w.Code != 409 {
		t.Fatal("标记跨实例重放", w.Code, w.Body)
	}
	old := token
	token = issue(row.ID)
	if w := request("GET", base+"/config", old, nil); w.Code != 401 {
		t.Fatal("旧令牌仍可用", w.Code)
	}
	db.Asset.UpdateOneID(host.ID).SetGroupID(other.ID).ExecX(ctx)
	if w := request("GET", base+"/config", token, nil); w.Code != 401 {
		t.Fatal("迁组未失效", w.Code)
	}
	token = issue(row.ID)
	db.DecoyDeployment.UpdateOneID(row.ID).SetTokenExpiresAt(time.Now().Add(-time.Second)).ExecX(ctx)
	if w := request("GET", base+"/config", token, nil); w.Code != 401 {
		t.Fatal("过期未失效", w.Code)
	}
	token = issue(row.ID)
	if w := request("POST", "/api/decoys/"+row.ID.String()+"/revoke", "", nil); w.Code != 204 {
		t.Fatal(w.Code, w.Body)
	}
	if w := request("POST", base+"/events", token, decoy.Observation{ID: uuid.NewString(), Kind: "http_page"}); w.Code != 401 {
		t.Fatal("撤销未失效", w.Code)
	}
	if db.DecoyDeployment.GetX(ctx, row.ID).TokenHash != "" {
		t.Fatal("撤销未清令牌")
	}
}
func TestDecoyRuntimeQuota(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("quota").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	token := strings.Repeat("a", 64)
	row := db.DecoyDeployment.Create().SetAssetID(a.ID).SetKind(decoydeployment.KindHTTP).SetPort(8088).SetProfile("decoy").SetTemplate("http-decoy-v1").SetCreatedBy("admin").SetTokenHash(decoyTokenHash(token)).SetTokenGroupID(g.ID).SetTokenExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)
	bulk := make([]*ent.DecoyObservationCreate, 1000)
	for i := range bulk {
		bulk[i] = db.DecoyObservation.Create().SetID(uuid.New()).SetDeploymentID(row.ID).SetKind("http_page")
	}
	db.DecoyObservation.CreateBulk(bulk...).ExecX(ctx)
	r := httptest.NewRequest("POST", "/api/decoy-runtime/"+row.ID.String()+"/events", strings.NewReader(fmt.Sprintf(`{"id":%q,"kind":"http_page"}`, uuid.NewString())))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	DecoyRuntime(db).ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatal(w.Code, w.Body)
	}
	if n := db.DecoyObservation.Query().Where(decoyobservation.DeploymentIDEQ(row.ID)).CountX(context.Background()); n != 1000 {
		t.Fatal(n)
	}
}
