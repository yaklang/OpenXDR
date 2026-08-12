package api

import "testing"

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
