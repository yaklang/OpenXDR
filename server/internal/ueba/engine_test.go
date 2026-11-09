package ueba

import (
	"encoding/json"
	"testing"
)

// ueba 的纯逻辑单测不带 integration tag：首次出现检测的判定依赖 DB（见
// engine_integration_test.go），但 exePath 只是从 JSON 里取路径，先锤炼它。

func TestExePath(t *testing.T) {
	raw := json.RawMessage(`{"process":{"file":{"path":"/usr/bin/ls"}}}`)
	if got := exePath(raw); got != "/usr/bin/ls" {
		t.Errorf("exePath 应提取出 /usr/bin/ls，实际 %q", got)
	}

	// 缺失、结构不符、非法 JSON 一律返回空串，不 panic
	if got := exePath(json.RawMessage(`{}`)); got != "" {
		t.Errorf("空文档应返回空串，实际 %q", got)
	}
	if got := exePath(json.RawMessage(`{"process":123}`)); got != "" {
		t.Errorf("process 非对象应返回空串，实际 %q", got)
	}
	if got := exePath(json.RawMessage(`not-json`)); got != "" {
		t.Errorf("非法 JSON 应返回空串，实际 %q", got)
	}
}

func TestCanonicalPath(t *testing.T) {
	cases := []struct{ in, canon, legacy string }{
		{"/bin/rm", "/usr/bin/rm", "/bin/rm"},
		{"/sbin/zpool", "/usr/sbin/zpool", "/sbin/zpool"},
		{"/lib/systemd/systemd-hostnamed", "/usr/lib/systemd/systemd-hostnamed", "/lib/systemd/systemd-hostnamed"},
		{"/usr/bin/rm", "/usr/bin/rm", "/bin/rm"},
		{"/usr/local/bin/x", "/usr/local/bin/x", "/usr/local/bin/x"},
		{"/binx/y", "/binx/y", "/binx/y"},
		{"/opt/app/server", "/opt/app/server", "/opt/app/server"},
		{`C:\Windows\System32\cmd.exe`, `C:\Windows\System32\cmd.exe`, `C:\Windows\System32\cmd.exe`},
		{"/tmp/go-build10312128/b361/config.test", "/tmp/go-buildN/bN/config.test", "/tmp/go-buildN/bN/config.test"},
		{"/tmp/TestHostedCodeOutputLimit1401744958/001/docker-fixture", "/tmp/TestHostedCodeOutputLimitN/N/docker-fixture", "/tmp/TestHostedCodeOutputLimitN/N/docker-fixture"},
		{"/tmp/pytest-of-runner/pytest-150/x/bin/awk", "/tmp/pytest-of-runner/pytest-N/x/bin/awk", "/tmp/pytest-of-runner/pytest-N/x/bin/awk"},
		{"/var/tmp/d-20261108T024043Z-a6b8ed8f6f9a/run", "/var/tmp/d-NTNZ-N/run", "/var/tmp/d-NTNZ-N/run"},
		{"/tmp/x12345678", "/tmp/x12345678", "/tmp/x12345678"},
		{"/opt/build123/app", "/opt/build123/app", "/opt/build123/app"},
	}
	for _, c := range cases {
		if got := canonicalPath(c.in); got != c.canon {
			t.Errorf("canonicalPath(%q) = %q, want %q", c.in, got, c.canon)
		}
		if got := legacyPath(canonicalPath(c.in)); got != c.legacy {
			t.Errorf("legacyPath(%q) = %q, want %q", canonicalPath(c.in), got, c.legacy)
		}
	}
}
