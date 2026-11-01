package eventsearch

import "testing"

func TestEscapeLike(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"100%", `100\%`},
		{"a_b", `a\_b`},
		{`path\file`, `path\\file`},
		{`%_\`, `\%\_\\`},
		{"", ""},
	}
	for _, c := range cases {
		if got := escapeLike(c.in); got != c.want {
			t.Errorf("escapeLike(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// 可能落在被排除的 UUID / 哈希里的关键词才回退全文；纯数字按值匹配（端口、pid 不该被迫全表扫）。
func TestHexish(t *testing.T) {
	cases := map[string]bool{
		"43b8d2d0":                             true,
		"5000508E-C623":                        true,
		"5000508e-c623-4ea9-b9d2-4bbb2dcc5eee": true,
		"cafe":                                 true,
		"-":                                    true,
		"4444":                                 false,
		"10.1.1.35":                            false,
		"curl":                                 false,
		"/usr/bin/ps":                          false,
		"SHA256:EUsd":                          false,
	}
	for in, want := range cases {
		if got := hexish.MatchString(in); got != want {
			t.Errorf("hexish(%q) = %v, want %v", in, got, want)
		}
	}
}
