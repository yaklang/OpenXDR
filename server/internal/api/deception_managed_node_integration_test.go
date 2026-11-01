//go:build integration

package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"openxdr/server/deception/contract"
	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func TestDeceptionManagedNodeStartsFromPlatformConfiguration(t *testing.T) {
	node := os.Getenv("DECEPTION_NODE")
	if node == "" || runtime.GOOS != "linux" {
		t.Skip("托管进程与 Unix 权限在 Linux 引擎 CI 验证")
	}
	ctx, db := testdb.New(t)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	socket := filepath.Join(t.TempDir(), "control.sock")
	if err := StartDeceptionHost(ctx, db, socket); err != nil {
		t.Fatal(err)
	}
	module, err := filepath.Abs(filepath.Join("..", "..", "..", "integrations", "dygk"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, node, filepath.Join(module, "web", "manager.mjs"))
	cmd.Env = append(os.Environ(), "DYGK_CONTROL_SOCKET="+socket, "DYGK_STATE_DIR="+t.TempDir(), "DYGK_LISTEN_HOST=127.0.0.1")
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	wait := func(check func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if check() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("托管引擎未完成平台启动流程")
	}
	var release *ent.DecoyEngineRelease
	wait(func() bool { release, _ = hostedRelease(db, ctx); return release != nil })
	group := db.Group.Create().SetName("managed-node").SaveX(ctx)
	host := db.Asset.Create().SetHostname("site").SetGroupID(group.ID).SaveX(ctx)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	management := http.NewServeMux()
	mapSSHDecoys(management, db)
	admin := as(&ent.User{Username: "admin", Role: "admin"}, management)
	request := func(path string, body any, out any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		admin.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(string(raw))))
		if w.Code < 200 || w.Code >= 300 {
			t.Fatalf("%s %d %s", path, w.Code, w.Body)
		}
		if out != nil {
			if e := json.Unmarshal(w.Body.Bytes(), out); e != nil {
				t.Fatal(e)
			}
		}
	}
	var deployment ent.DecoyDeployment
	request("/api/decoys", map[string]any{"assetId": host.ID, "kind": "http", "profile": "decoy", "port": port}, &deployment)
	cfg := contract.DefaultConfig()
	cfg.Hosted = true
	request("/api/decoys/"+deployment.ID.String()+"/revisions", map[string]any{"releaseId": release.ID, "config": cfg}, nil)
	wait(func() bool {
		row, _ := db.DecoyDeployment.Get(ctx, deployment.ID)
		return row != nil && row.RuntimeState == "running"
	})
	response, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || !strings.Contains(string(body), "data-dygk") {
		t.Fatal("托管站点未实际提供诱饵")
	}
	previous := db.DecoyDeployment.GetX(ctx, deployment.ID).RuntimeInstanceID
	env := cmd.Env
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	// 模拟故障实例的租约过期，保留同一磁盘状态目录。
	db.DecoyDeployment.UpdateOneID(deployment.ID).SetRuntimeSeenAt(time.Now().Add(-2 * time.Minute)).ExecX(ctx)
	cmd = exec.CommandContext(ctx, node, filepath.Join(module, "web", "manager.mjs"))
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	wait(func() bool {
		row := db.DecoyDeployment.GetX(ctx, deployment.ID)
		return row.RuntimeState == "running" && row.RuntimeInstanceID != nil && *row.RuntimeInstanceID != *previous
	})
	response, err = http.Get("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("重启后站点不可用")
	}
	request("/api/decoys/"+deployment.ID.String()+"/stop", nil, nil)
	wait(func() bool {
		row, _ := db.DecoyDeployment.Get(ctx, deployment.ID)
		return row != nil && row.RuntimeState == "stopped"
	})
	occupied, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	row := db.DecoyDeployment.GetX(ctx, deployment.ID)
	request("/api/decoys/"+deployment.ID.String()+"/revisions", map[string]any{"releaseId": release.ID, "config": cfg, "expectedRevision": row.ActiveRevisionID}, nil)
	wait(func() bool {
		row := db.DecoyDeployment.GetX(ctx, deployment.ID)
		return row.RuntimeState == "failed" && row.RuntimeError == "startup_failed"
	})
	occupied.Close()
	row = db.DecoyDeployment.GetX(ctx, deployment.ID)
	request("/api/decoys/"+deployment.ID.String()+"/revisions", map[string]any{"releaseId": release.ID, "config": cfg, "expectedRevision": row.ActiveRevisionID}, nil)
	wait(func() bool {
		row := db.DecoyDeployment.GetX(ctx, deployment.ID)
		return row.RuntimeState == "running" && row.RuntimeError == ""
	})
	request("/api/decoys/"+deployment.ID.String()+"/stop", nil, nil)
	wait(func() bool { return db.DecoyDeployment.GetX(ctx, deployment.ID).RuntimeState == "stopped" })

}
