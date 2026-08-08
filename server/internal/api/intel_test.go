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
