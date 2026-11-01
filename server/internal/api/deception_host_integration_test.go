//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openxdr/server/deception/contract"
	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func TestDeceptionHostedAssignmentsAndGroupBoundary(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("hosted").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	host := db.Asset.Create().SetHostname("web").SetGroupID(group.ID).SaveX(ctx)
	management := http.NewServeMux()
	mapSSHDecoys(management, db)
	admin := as(&ent.User{Username: "admin", Role: "admin"}, management)
	broker := HostedDeception(db)
	request := func(handler http.Handler, path string, body any, out any, status int) {
		t.Helper()
		raw, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(raw)))
		if w.Code != status {
			t.Fatalf("%s %d %s", path, w.Code, w.Body)
		}
		if out != nil {
			if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
				t.Fatal(err)
			}
		}
	}
	release := contract.Release{Engine: "dygk", Version: "hosted-1", Digest: "sha256:" + strings.Repeat("e", 64), Protocol: 1, StateSchema: "dygk-sqlite-v1"}
	type assignment struct {
		ID       string `json:"id"`
		Revision string `json:"revision"`
		Instance string `json:"instance"`
		Token    string `json:"token"`
		Stop     bool   `json:"stop"`
	}
	var result struct {
		Jobs []assignment `json:"jobs"`
	}
	request(broker, "/engine/poll", map[string]any{"release": release, "instances": []any{}}, &result, 200)
	admitted, err := hostedRelease(db, ctx)
	if err != nil || admitted == nil {
		t.Fatalf("托管版本未自动登记: %v", err)
	}
	var deployment ent.DecoyDeployment
	request(admin, "/api/decoys", map[string]any{"assetId": host.ID, "kind": "http", "profile": "decoy", "port": 18080}, &deployment, 201)
	cfg := contract.DefaultConfig()
	// 非托管登记不能挤占当前引擎的托管容量。
	for i := 0; i < 100; i++ {
		var remote ent.DecoyDeployment
		request(admin, "/api/decoys", map[string]any{"assetId": host.ID, "kind": "http", "profile": "decoy", "port": 20000 + i}, &remote, 201)
		request(admin, fmt.Sprintf("/api/decoys/%s/revisions", remote.ID), map[string]any{"releaseId": admitted.ID, "config": cfg}, nil, 201)
	}
	cfg.Hosted = true
	otherRelease := db.DecoyEngineRelease.Create().SetEngine("dygk").SetVersion("hosted-other").SetDigest("sha256:" + strings.Repeat("f", 64)).SetProtocol(1).SetStateSchema("dygk-sqlite-v1").SetCreatedBy("admin").SaveX(ctx)
	for i := 0; i < 100; i++ {
		var remote ent.DecoyDeployment
		request(admin, "/api/decoys", map[string]any{"assetId": host.ID, "kind": "http", "profile": "decoy", "port": 21000 + i}, &remote, 201)
		request(admin, fmt.Sprintf("/api/decoys/%s/revisions", remote.ID), map[string]any{"releaseId": otherRelease.ID, "config": cfg}, nil, 201)
	}
	request(admin, "/api/decoys/"+deployment.ID.String()+"/revisions", map[string]any{"releaseId": admitted.ID, "config": cfg}, nil, 201)
	request(broker, "/engine/poll", map[string]any{"release": release, "instances": []any{}}, &result, 200)
	if len(result.Jobs) != 1 || len(result.Jobs[0].Token) != 64 {
		t.Fatal("平台未自动签发运行身份")
	}
	job := result.Jobs[0]
	request(broker, "/engine/poll", map[string]any{"release": release, "instances": []any{}}, &result, 200)
	if len(result.Jobs) != 0 {
		t.Fatal("同一租约被重复分配")
	}
	instances := []map[string]string{{"id": job.ID, "revision": job.Revision, "instance": job.Instance}}
	request(broker, "/engine/poll", map[string]any{"release": release, "instances": instances}, &result, 200)
	if len(result.Jobs) != 1 || result.Jobs[0].Token != "" || result.Jobs[0].Stop {
		t.Fatal("已运行实例不应重新签发令牌")
	}
	db.Asset.UpdateOne(host).SetGroupID(other.ID).SaveX(ctx)
	request(broker, "/engine/poll", map[string]any{"release": release, "instances": instances}, &result, 200)
	if len(result.Jobs) != 1 || !result.Jobs[0].Stop {
		t.Fatal("资产迁组后没有停止旧实例")
	}
	request(broker, "/engine/finished", map[string]any{"release": release, "instances": []map[string]string{{"id": job.ID, "instance": job.Instance, "revision": job.Revision, "state": "stopped"}}}, nil, 200)
	if current := db.DecoyDeployment.GetX(ctx, deployment.ID); current.RuntimeState != "stopped" {
		t.Fatal("迁组后的内部退出确认未保存")
	}
	request(broker, "/engine/poll", map[string]any{"release": release, "instances": []any{}}, &result, 200)
	if len(result.Jobs) != 0 {
		t.Fatal("迁组后未经新组授权自动重签")
	}
	db.DecoyEngineRelease.UpdateOne(admitted).SetEnabled(false).SaveX(ctx)
	request(broker, "/engine/poll", map[string]any{"release": release, "instances": instances}, nil, 403)
	// 当前版本确实超过 100 个托管登记时仍须拒绝，不能截断任务导致误停实例。
	db.DecoyEngineRelease.UpdateOne(admitted).SetEnabled(true).SaveX(ctx)
	for i := 0; i < 100; i++ {
		var extra ent.DecoyDeployment
		request(admin, "/api/decoys", map[string]any{"assetId": host.ID, "kind": "http", "profile": "decoy", "port": 22000 + i}, &extra, 201)
		request(admin, fmt.Sprintf("/api/decoys/%s/revisions", extra.ID), map[string]any{"releaseId": admitted.ID, "config": cfg}, nil, 201)
	}
	request(broker, "/engine/poll", map[string]any{"release": release, "instances": instances}, nil, 422)
}
