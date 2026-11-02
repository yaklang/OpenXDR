//go:build integration

package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"openxdr/server/deception/contract"
	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func TestDeceptionNodeRuntimeEndToEnd(t *testing.T) {
	node := os.Getenv("DECEPTION_NODE")
	if node == "" {
		t.Skip("DECEPTION_NODE 未配置，Node 24 运行包端到端由引擎 CI 验证")
	}
	ctx, db := testdb.New(t)
	module, err := filepath.Abs(filepath.Join("..", "..", "..", "integrations", "dygk"))
	if err != nil {
		t.Fatal(err)
	}
	info := exec.Command(node, filepath.Join(module, "web", "main.mjs"), "--print-release")
	raw, err := info.Output()
	if err != nil {
		t.Fatal(err)
	}
	var release contract.Release
	if json.Unmarshal(raw, &release) != nil {
		t.Fatal("版本信息无效")
	}
	group := db.Group.Create().SetName("node-e2e").SaveX(ctx)
	host := db.Asset.Create().SetHostname("node").SetGroupID(group.ID).SaveX(ctx)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	management := http.NewServeMux()
	mapSSHDecoys(management, db)
	root := http.NewServeMux()
	root.Handle("/api/deception-runtime/", DeceptionRuntime(db))
	root.Handle("/", as(&ent.User{Username: "admin", Role: "admin"}, management))
	platform := httptest.NewServer(root)
	defer platform.Close()
	request := func(path string, body any, out any) {
		t.Helper()
		b, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		root.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(b)))
		if w.Code < 200 || w.Code >= 300 {
			t.Fatalf("%s %d %s", path, w.Code, w.Body)
		}
		if out != nil {
			if e := json.Unmarshal(w.Body.Bytes(), out); e != nil {
				t.Fatal(e)
			}
		}
	}
	var deployed ent.DecoyDeployment
	request("/api/decoys", map[string]any{"assetId": host.ID, "kind": "http", "profile": "decoy", "port": port}, &deployed)
	var admitted ent.DecoyEngineRelease
	request("/api/deception/releases", release, &admitted)
	request("/api/decoys/"+deployed.ID.String()+"/revisions", map[string]any{"releaseId": admitted.ID, "config": contract.DefaultConfig()}, nil)
	var token struct {
		Token string `json:"token"`
	}
	request("/api/decoys/"+deployed.ID.String()+"/token", nil, &token)
	procCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(procCtx, node, filepath.Join(module, "tests", "runtime-probe.mjs"))
	cmd.Env = append(os.Environ(), "DECOY_PLATFORM_URL="+platform.URL, "DECOY_DEPLOYMENT="+deployed.ID.String(), "DECOY_RUNTIME_TOKEN="+token.Token, "DYGK_STATE_DIR="+t.TempDir())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	lines := bufio.NewScanner(stdout)
	wait := func(expected string) {
		t.Helper()
		if !lines.Scan() || lines.Text() != expected {
			t.Fatalf("运行端未返回 %s: %s", expected, stderr.String())
		}
	}
	wait("ready")
	origin := "http://127.0.0.1:" + strconv.Itoa(port)
	get := func(path string) string {
		t.Helper()
		res, e := http.Get(origin + path)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != 200 {
			t.Fatalf("%s %d %s", path, res.StatusCode, body)
		}
		return string(body)
	}
	entry := get("/_dygk/entry/0")
	sessionMatch := regexp.MustCompile(`\?s=([a-f0-9]+)`).FindStringSubmatch(entry)
	if len(sessionMatch) != 2 {
		t.Fatal("未发现会话归档")
	}
	session := sessionMatch[1]
	get("/_dygk/archive/0?s=" + session)
	verify := get("/_dygk/verify?s=" + session)
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(verify)
	if len(csrf) != 2 {
		t.Fatal("未发现验证表单")
	}
	res, err := http.PostForm(origin+"/_dygk/profile?s="+session, url.Values{"csrf": {csrf[1]}, "access_key": {"compat-" + session[:12]}, "framework": {"integration"}, "version": {"1"}})
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	io.WriteString(stdin, "pump\n")
	wait("flushed")
	if n := db.Incident.Query().CountX(ctx); n != 1 {
		t.Fatalf("实际引擎未进入复核闭环: %d", n)
	}
	observations := db.DecoyObservation.Query().AllX(ctx)
	b, _ := json.Marshal(observations)
	if strings.Contains(string(b), session) || strings.Contains(string(b), "127.0.0.1") {
		t.Fatal("源会话或地址进入平台事实")
	}
	io.WriteString(stdin, "stop\n")
	wait("stopped")
	stdin.Close()
	if err = cmd.Wait(); err != nil {
		t.Fatalf("运行端退出: %v %s", err, stderr.String())
	}
	current := db.DecoyDeployment.GetX(ctx, deployed.ID)
	if current.RuntimeState != "stopped" {
		t.Fatal(current.RuntimeState)
	}
}
