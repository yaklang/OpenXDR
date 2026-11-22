package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDetectKind(t *testing.T) {
	cases := []struct{ in, kind, value string }{
		{"1.2.3.4", "ip", "1.2.3.4"},
		{"2001:db8::1", "ip", "2001:db8::1"},
		{"Evil.COM.", "domain", "evil.com"},
		{"d41d8cd98f00b204e9800998ecf8427e", "hash", "d41d8cd98f00b204e9800998ecf8427e"},
		{"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", "hash", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		// 长度对但含非十六进制字符，是域名不是哈希
		{"this-is-a-32-char-long-hostname!", "domain", "this-is-a-32-char-long-hostname!"},
	}
	for _, c := range cases {
		kind, value := detectKind(c.in)
		if kind != c.kind || value != c.value {
			t.Errorf("detectKind(%q) = %s,%s，期望 %s,%s", c.in, kind, value, c.kind, c.value)
		}
	}
}

func TestIsHex(t *testing.T) {
	for _, s := range []string{"deadbeef", "0123456789abcdef", "a1b2c3"} {
		if !isHex(s) {
			t.Errorf("isHex(%q) 应为 true", s)
		}
	}
	// isHex 只认小写：detectKind 在调用前已 ToLower，大写在这里本就该拒绝
	for _, s := range []string{"ABCDEF", "deadx", "0x1f", "12G4", "abc def", "-ff"} {
		if isHex(s) {
			t.Errorf("isHex(%q) 应为 false", s)
		}
	}
	// 空串无字符可否定：按实现返回 true，detectKind 靠长度限制不会走到这里
	if !isHex("") {
		t.Errorf("isHex 空串按实现应为 true")
	}
}

func TestValidIntelIP(t *testing.T) {
	accepted := []struct {
		in   string
		want string
	}{
		{"1.2.3.4", "1.2.3.4"},
		{"5.6.7.8", "5.6.7.8"},
		{"::ffff:8.8.8.8", "8.8.8.8"},
		{"2001:4860:4860::8888", "2001:4860:4860::8888"},
	}
	for _, tc := range accepted {
		got, ok := validIntelIP(tc.in)
		if !ok || got != tc.want {
			t.Errorf("validIntelIP(%q) = (%q, %v), want (%q, true)", tc.in, got, ok, tc.want)
		}
	}

	rejected := []string{
		"",
		"not-an-ip",
		"127.0.0.1",
		"::1",
		"::ffff:127.0.0.1",
		"10.1.1.1",
		"172.16.0.5",
		"192.168.1.1",
		"169.254.169.254",
		"fe80::1",
		"fc00::1",
		"100.64.0.1",
		"0.0.0.0",
		"::",
		"224.0.0.1",
		"255.255.255.255",
		"240.0.0.1",
	}
	for _, raw := range rejected {
		if got, ok := validIntelIP(raw); ok {
			t.Errorf("私网/回环/保留/非法 IP %q 不应放行，got %q", raw, got)
		}
	}
}

func TestIntelHandlerRejectsInvalidInputsAndOversizedBody(t *testing.T) {
	mux := http.NewServeMux()
	mapIntel(mux, nil, nil)

	cases := []struct {
		name   string
		path   string
		body   string
		status int
	}{
		{"单条私网 IP 拒绝", "/api/intel", `{"kind":"ip","value":"10.1.1.36"}`, http.StatusBadRequest},
		{"单条回环 IP 拒绝", "/api/intel", `{"kind":"ip","value":"127.0.0.1"}`, http.StatusBadRequest},
		{"单条链路本地 IP 拒绝", "/api/intel", `{"kind":"ip","value":"169.254.169.254"}`, http.StatusBadRequest},
		{"单条保留 IP 拒绝", "/api/intel", `{"kind":"ip","value":"240.0.0.1"}`, http.StatusBadRequest},
		{"单条 severity 越界(低)", "/api/intel", `{"kind":"ip","value":"1.2.3.4","severity":-1}`, http.StatusBadRequest},
		{"单条 severity 越界(高)", "/api/intel", `{"kind":"ip","value":"1.2.3.4","severity":6}`, http.StatusBadRequest},
		{"导入 severity 越界", "/api/intel/import", `{"text":"1.2.3.4","severity":9}`, http.StatusBadRequest},
		{"单条超 1 MiB 拒绝", "/api/intel", `{"kind":"domain","value":"` + strings.Repeat("a", maxIntelBodyBytes+16) + `"}`, http.StatusRequestEntityTooLarge},
		{"导入超 10 MiB 拒绝", "/api/intel/import", `{"text":"` + strings.Repeat("a", maxIntelImportBytes+16) + `"}`, http.StatusRequestEntityTooLarge},
	}

	for _, tc := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
		mux.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Errorf("%s: status = %d, want %d (%s)", tc.name, rec.Code, tc.status, rec.Body.String())
		}
	}
}
