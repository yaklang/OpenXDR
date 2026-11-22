package main

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const key = "0123456789abcdef0123456789abcdef"

// fakeDocker 代替 docker：run 时读一行请求、回一行结果后再等输入结束；rm 时记下被删的容器名
func fakeDocker(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "docker")
	script := `#!/bin/sh
if [ "$1" = rm ]; then echo "$3" >> "` + dir + `/removed"; kill "$(cat ` + dir + `/pid)" 2>/dev/null; exit 0; fi
echo $$ > "` + dir + `/pid"
read line
echo '{"type":"result","response":"ok","stop_reason":"stop"}'
cat >/dev/null
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func server(t *testing.T, maxRuns int) (*httptest.Server, string) {
	dir := t.TempDir()
	c := config{key: key, docker: fakeDocker(t, dir), image: "img", network: "net", memory: "1g", cpus: "1", pids: "64", tmpfs: "64m", maxRuns: maxRuns, maxRun: time.Minute}
	return httptest.NewServer(runHandler(c)), dir
}

func open(t *testing.T, url, token string) (io.WriteCloser, *http.Response, error) {
	in, out := io.Pipe()
	req, _ := http.NewRequest(http.MethodPost, url, in)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	return out, resp, err
}

func TestRunPipesAndCleansUp(t *testing.T) {
	srv, dir := server(t, 1)
	defer srv.Close()

	// 错误密钥立即拒绝，不能卡在读请求体上
	done := make(chan struct{})
	go func() {
		in, resp, err := open(t, srv.URL, strings.Repeat("x", 32))
		if err != nil || resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("错误密钥应 401: %v", err)
		} else {
			resp.Body.Close()
		}
		_ = in.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("错误密钥时卡住了")
	}

	stdin, resp, err := open(t, srv.URL, key)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("正常运行: %v", err)
	}
	_, _ = io.WriteString(stdin, `{"type":"run"}`+"\n")
	line, _ := bufio.NewReader(resp.Body).ReadString('\n')
	if !strings.Contains(line, `"stop_reason":"stop"`) {
		t.Fatalf("容器输出应原样回传: %q", line)
	}

	// 唯一的名额被占着，再来一个应 503
	busyIn, busy, err := open(t, srv.URL, key)
	if err != nil || busy.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("并发满应 503: %v %v", err, busy.Status)
	}
	busy.Body.Close()
	_ = busyIn.Close()

	// 平台半路断开：容器必须被删
	resp.Body.Close()
	_ = stdin.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, _ := os.ReadFile(filepath.Join(dir, "removed")); strings.HasPrefix(string(b), "openxdr-sbx-") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("断开后应 docker rm -f 容器")
}

func TestLoadValidates(t *testing.T) {
	for _, env := range []map[string]string{
		{"SANDBOXD_KEY": "short"},
		{"SANDBOXD_KEY": key, "SANDBOXD_TLS_CERT": "/a.pem"},
		{"SANDBOXD_KEY": key, "SANDBOX_MAX_RUNS": "0"},
	} {
		for _, k := range []string{"SANDBOXD_KEY", "SANDBOXD_TLS_CERT", "SANDBOXD_TLS_KEY", "SANDBOX_MAX_RUNS"} {
			t.Setenv(k, env[k])
		}
		if _, err := load(); err == nil {
			t.Errorf("应拒绝配置 %v", env)
		}
	}
}

func TestArgsHardening(t *testing.T) {
	c := config{image: "img", network: "net", memory: "1g", cpus: "1.5", pids: "256", tmpfs: "512m"}
	got := c.args("openxdr-sbx-test")
	var tmpfs []string
	for i := 0; i < len(got)-1; i++ {
		if got[i] == "--tmpfs" {
			tmpfs = append(tmpfs, got[i+1])
		}
	}
	if len(tmpfs) != 2 {
		t.Fatalf("应配置两个 tmpfs 挂载，实际 %v", tmpfs)
	}
	want := []string{"/tmp:size=256m,noexec,nosuid,nodev", "/home/agent:size=512m,uid=10010,gid=10010,noexec,nosuid,nodev"}
	for i := range want {
		if tmpfs[i] != want[i] {
			t.Errorf("tmpfs[%d] = %q，期望 %q", i, tmpfs[i], want[i])
		}
	}
}
