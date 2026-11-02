//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openxdr/server/deception/contract"
	"openxdr/server/deception/native"
	"openxdr/server/deception/sdk"
	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func TestDeceptionNativeManagedProtocol(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("native-protocol").SaveX(ctx)
	host := db.Asset.Create().SetHostname("host").SetGroupID(group.ID).SaveX(ctx)
	management := http.NewServeMux()
	mapSSHDecoys(management, db)
	root := http.NewServeMux()
	root.Handle("/api/deception-runtime/", DeceptionRuntime(db))
	root.Handle("/", as(&ent.User{Username: "admin", Role: "admin"}, management))
	server := httptest.NewServer(root)
	defer server.Close()
	request := func(path string, body any, out any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		root.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(raw)))
		if w.Code < 200 || w.Code >= 300 {
			t.Fatalf("%s %d %s", path, w.Code, w.Body)
		}
		if out != nil {
			if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
				t.Fatal(err)
			}
		}
	}
	var deployment ent.DecoyDeployment
	request("/api/decoys", map[string]any{"assetId": host.ID, "kind": "http", "profile": "decoy", "port": 18081}, &deployment)
	release := contract.Release{Engine: "native", Version: contract.Version, Digest: "sha256:" + strings.Repeat("f", 64), Protocol: 1, StateSchema: "native-v1"}
	var admitted ent.DecoyEngineRelease
	request("/api/deception/releases", release, &admitted)
	request("/api/decoys/"+deployment.ID.String()+"/revisions", map[string]any{"releaseId": admitted.ID, "config": contract.DefaultConfig()}, nil)
	var issued struct {
		Token string `json:"token"`
	}
	request("/api/decoys/"+deployment.ID.String()+"/token", nil, &issued)
	client, err := sdk.NewManagedClient(server.URL, deployment.ID.String(), issued.Token, release)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := client.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if err = client.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	handler, err := native.HTTPHandler(manifest, func(kind string) error { return client.Record(ctx, kind) })
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/verify/" + manifest.Marker} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	if n := db.Incident.Query().CountX(ctx); n != 1 {
		t.Fatalf("原生标记未通过新协议开单: %d", n)
	}
	request("/api/decoys/"+deployment.ID.String()+"/stop", nil, nil)
	if _, err = client.Manifest(ctx); !errors.Is(err, sdk.ErrStopRequested) {
		t.Fatal("未识别停止请求", err)
	}
	if err = client.Finish(ctx, false); err != nil {
		t.Fatal(err)
	}
}
