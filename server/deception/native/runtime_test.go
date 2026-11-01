package native

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"openxdr/server/deception/sdk"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func manifest(kind, profile string) Manifest {
	p, _ := Lookup(kind, profile)
	return Manifest{ID: uuid.NewString(), Kind: kind, Profile: profile, Template: p.Template, Marker: strings.Repeat("a", 64), Resource: "README.md"}
}
func TestHTTPIsolationAndMarker(t *testing.T) {
	m := manifest("http", "decoy")
	var events []string
	h, err := HTTPHandler(m, func(kind string) error { events = append(events, kind); return nil })
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	base := "/decoy/" + m.ID
	if w := request("GET", "/business"); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w := request("POST", base); w.Code != 405 {
		t.Fatal(w.Code)
	}
	if w := request("HEAD", base); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal(w.Code)
	}
	if len(events) != 0 {
		t.Fatal(events)
	}
	w := request("GET", base)
	if w.Code != 200 || !strings.Contains(w.Body.String(), base+"/verify/"+m.Marker) || w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal(w.Body.String())
	}
	if w := request("GET", base+"/verify/"+strings.Repeat("b", 64)); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w := request("GET", base+"/verify/"+m.Marker); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request("GET", base+"/verify/"+m.Marker); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if strings.Join(events, ",") != "http_page,marker_used" {
		t.Fatal(events)
	}
	if w := request("GET", "/"); w.Code != 200 || !strings.Contains(w.Body.String(), `href="/archive"`) || strings.Contains(w.Body.String(), base) {
		t.Fatal("根路径未提供诱饵页", w.Body.String())
	}
	if w := request("GET", "/status"); w.Code != 200 {
		t.Fatal(w.Code)
	}
}
func TestHTTPRecordFailureClosesCarrier(t *testing.T) {
	m := manifest("http", "padding")
	calls := 0
	h, _ := HTTPHandler(m, func(string) error { calls++; return errors.New("离线") })
	for range 2 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/decoy/"+m.ID, nil))
		if w.Code != 503 {
			t.Fatal(w.Code)
		}
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}

// adminRoot 模拟只有管理员可写的父目录；t.TempDir 跟随 umask，可能属组可写。
func adminRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	return root
}
func TestFileNeverOverwritesAndPreservesChanges(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux 文件权限与清理验收")
	}
	root := adminRoot(t)
	m := manifest("file", "decoy")
	if err := os.Chmod(root, 0775); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallFile(root, m); err == nil {
		t.Fatal("接受了属组可写的父目录")
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	f, err := InstallFile(root, m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InstallFile(root, m); err == nil {
		t.Fatal("覆盖已有目录")
	}
	if err := os.WriteFile(f.Path, []byte("人工修改"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.Remove(); err == nil {
		t.Fatal("删除已变更内容")
	}
	if data, err := os.ReadFile(f.Path); err != nil || string(data) != "人工修改" {
		t.Fatal(string(data), err)
	}
	m.ID = uuid.NewString()
	m.Resource = "../business.md"
	if _, err := InstallFile(root, m); err == nil {
		t.Fatal("路径穿越未拒绝")
	}
	m.Resource = "README.md"
	f, err = InstallFile(root, m)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(f.Path); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
func TestFileCleanupRejectsSymlink(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux 文件权限与清理验收")
	}
	root := adminRoot(t)
	m := manifest("file", "padding")
	f, err := InstallFile(root, m)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "important")
	if err = os.WriteFile(outside, []byte("真实内容"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(f.Path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, f.Path); err != nil {
		t.Skip(err)
	}
	if err = f.Remove(); err == nil {
		t.Fatal("接受替换符号链接")
	}
	data, _ := os.ReadFile(outside)
	if string(data) != "真实内容" {
		t.Fatal("修改业务文件")
	}
}
func TestShellDoesNotExecute(t *testing.T) {
	m := manifest("shell", "decoy")
	target := filepath.Join(t.TempDir(), "must-not-exist")
	input := "touch " + target + "\ncat /etc/passwd\n$(id)\ncat README.md\nverify " + m.Marker + "\nverify " + m.Marker + "\nexit\n"
	var output bytes.Buffer
	markers := 0
	err := Shell(strings.NewReader(input), &output, m, func(kind string) error {
		if kind == "marker_used" {
			markers++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("执行了宿主命令")
	}
	if markers != 1 || strings.Contains(output.String(), "root:") {
		t.Fatal(output.String())
	}
	output.Reset()
	err = Shell(strings.NewReader(strings.Repeat("x", 2048)), &output, m, func(string) error { return nil })
	if err == nil {
		t.Fatal("超长输入未拒绝")
	}
}
func TestClientRejectsRedirectAndInsecureOrigin(t *testing.T) {
	id, token := uuid.NewString(), strings.Repeat("a", 64)
	for _, origin := range []string{"http://example.test", "https://user:pass@example.test", "https://example.test/?token=x", "https://example.test/api"} {
		if _, err := sdk.NewClient(origin, id, token); err == nil {
			t.Fatal(origin)
		}
	}
	leaked := false
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer source.Close()
	c, err := sdk.NewClient(source.URL, id, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Manifest(context.Background()); err == nil || leaked {
		t.Fatal("令牌跟随重定向")
	}
}
