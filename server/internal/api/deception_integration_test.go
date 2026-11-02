//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/deception/contract"
	"openxdr/server/ent"
	"openxdr/server/ent/decoyobservation"
	"openxdr/server/internal/testdb"
)

func TestDeceptionRevisionAndReliableObservations(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("deception").SaveX(ctx)
	host := db.Asset.Create().SetHostname("web").SetGroupID(group.ID).SaveX(ctx)
	management := http.NewServeMux()
	mapSSHDecoys(management, db)
	root := http.NewServeMux()
	root.Handle("/api/deception-runtime/", DeceptionRuntime(db))
	root.Handle("/api/decoy-runtime/", DecoyRuntime(db))
	root.Handle("/", as(&ent.User{Username: "admin", Role: "admin"}, management))
	token, instance, revision := "", uuid.NewString(), ""
	request := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-Decoy-Instance", instance)
		r.Header.Set("X-Decoy-Revision", revision)
		w := httptest.NewRecorder()
		root.ServeHTTP(w, r)
		return w
	}
	must := func(method, path string, body any, status int, out any) {
		t.Helper()
		w := request(method, path, body)
		if w.Code != status {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body)
		}
		if out != nil {
			if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
				t.Fatal(err)
			}
		}
	}
	var deployment ent.DecoyDeployment
	must("POST", "/api/decoys", map[string]any{"assetId": host.ID, "kind": "http", "profile": "decoy", "port": 8088}, 201, &deployment)
	release := contract.Release{Engine: "dygk", Version: "test-1", Digest: "sha256:" + strings.Repeat("a", 64), Protocol: 1, StateSchema: "dygk-sqlite-v1"}
	var admitted ent.DecoyEngineRelease
	must("POST", "/api/deception/releases", release, 201, &admitted)
	var rev ent.DecoyRevision
	must("POST", "/api/decoys/"+deployment.ID.String()+"/revisions", map[string]any{"releaseId": admitted.ID, "config": contract.DefaultConfig()}, 201, &rev)
	revision = rev.ID.String()
	var issued struct {
		Token string `json:"token"`
	}
	must("POST", "/api/decoys/"+deployment.ID.String()+"/token", nil, 200, &issued)
	token = issued.Token
	base := "/api/deception-runtime/v1/deployments/" + deployment.ID.String()
	must("GET", "/api/decoy-runtime/"+deployment.ID.String()+"/config", nil, 409, nil)
	must("GET", base+"/config", nil, 200, new(contract.RuntimeConfig))
	bad := release
	bad.Digest = "sha256:" + strings.Repeat("b", 64)
	must("POST", base+"/handshake", contract.Handshake{Instance: instance, Revision: revision, Release: bad}, 409, nil)
	must("POST", base+"/handshake", contract.Handshake{Instance: instance, Revision: revision, Release: release}, 204, nil)
	must("POST", base+"/lease", map[string]string{"instance": instance, "state": "running"}, 204, nil)
	must("POST", base+"/lease", map[string]any{"instance": instance, "state": "running", "pending": 3, "errorCode": "delivery_failed"}, 204, nil)
	current := db.DecoyDeployment.GetX(ctx, deployment.ID)
	if current.RuntimePending == nil || *current.RuntimePending != 3 || current.RuntimeError != "delivery_failed" {
		t.Fatal("健康状态未保存")
	}
	must("POST", base+"/lease", map[string]any{"instance": instance, "state": "running", "pending": -1}, 400, nil)
	must("POST", base+"/lease", map[string]any{"instance": instance, "state": "running", "pending": 0, "errorCode": "raw secret"}, 400, nil)
	must("POST", base+"/lease", map[string]any{"instance": instance, "state": "running", "pending": 0}, 204, nil)
	if db.DecoyDeployment.GetX(ctx, deployment.ID).RuntimeError != "" {
		t.Fatal("恢复后错误未清除")
	}
	session := strings.Repeat("c", 64)
	epoch := uuid.NewString()
	fact := contract.Fact{ID: uuid.NewString(), Epoch: epoch, Sequence: 1, Time: time.Now().UTC().Truncate(time.Millisecond), Session: session, Kind: "honeypot_triggered", Count: 1}
	batch := map[string]any{"items": []contract.Fact{fact}}
	must("POST", base+"/observations", batch, 200, nil)
	must("POST", base+"/observations", batch, 200, nil)
	second := fact
	second.ID = uuid.NewString()
	second.Sequence = 2
	must("POST", base+"/observations", map[string]any{"items": []contract.Fact{second}}, 200, nil)
	if n := db.Incident.Query().CountX(ctx); n != 1 {
		t.Fatalf("同会话重复开单: %d", n)
	}
	fact.Count = 2
	must("POST", base+"/observations", map[string]any{"items": []contract.Fact{fact}}, 409, nil)
	fact.ID = uuid.NewString()
	fact.Kind = "ip_banned"
	must("POST", base+"/observations", map[string]any{"items": []contract.Fact{fact}}, 400, nil)
	must("POST", base+"/observations", map[string]any{"items": []map[string]any{{"eventId": uuid.NewString(), "ip": "1.2.3.4"}}}, 400, nil)
	must("POST", "/api/decoys/"+deployment.ID.String()+"/revisions", map[string]any{"releaseId": admitted.ID, "config": contract.DefaultConfig(), "expectedRevision": rev.ID}, 409, nil)
	must("POST", "/api/decoys/"+deployment.ID.String()+"/stop", nil, 202, nil)
	must("POST", base+"/lease", map[string]string{"instance": instance, "state": "stopped"}, 204, nil)
	var next ent.DecoyRevision
	must("POST", "/api/decoys/"+deployment.ID.String()+"/revisions", map[string]any{"releaseId": admitted.ID, "config": contract.DefaultConfig(), "expectedRevision": rev.ID}, 201, &next)
	must("GET", base+"/config", nil, 401, nil)
	if n := db.DecoyObservation.Query().Where(decoyobservation.DeploymentIDEQ(deployment.ID)).CountX(ctx); n != 2 {
		t.Fatalf("幂等观察数量错误: %d", n)
	}
	var manager struct {
		Online bool `json:"online"`
	}
	must("GET", "/api/deception/hosted-status", nil, 200, &manager)
	if manager.Online {
		t.Fatal("未连接管理器不能显示在线")
	}
	value, _ := json.Marshal(map[string]any{"seenAt": time.Now()})
	db.Setting.Create().SetID("deception.hosted").SetValue(value).SaveX(ctx)
	must("GET", "/api/deception/hosted-status", nil, 200, &manager)
	if !manager.Online {
		t.Fatal("新心跳未显示在线")
	}
	value, _ = json.Marshal(map[string]any{"seenAt": time.Now().Add(-time.Minute)})
	db.Setting.UpdateOneID("deception.hosted").SetValue(value).ExecX(ctx)
	must("GET", "/api/deception/hosted-status", nil, 200, &manager)
	if manager.Online {
		t.Fatal("过期心跳仍显示在线")
	}

}
