package triage

import "testing"

func TestStripFence(t *testing.T) {
	cases := map[string]string{
		"title: x":                     "title: x",
		"```yaml\ntitle: x\n```":       "title: x",
		"```\ntitle: x\n```":           "title: x",
		"  ```yaml\ntitle: x\n```\n  ": "title: x",
	}
	for in, want := range cases {
		if got := stripFence(in); got != want {
			t.Errorf("stripFence(%q) = %q, 期望 %q", in, got, want)
		}
	}
}
