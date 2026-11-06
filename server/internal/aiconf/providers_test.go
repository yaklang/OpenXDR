package aiconf

import "testing"

func TestProviderBoundaries(t *testing.T) {
	for _, base := range []string{"https://user:secret@host/v1", "https://host/v1?key=secret", "https://host/v1#x", "file:///tmp/model"} {
		p := []ProviderPatch{{ID: "a", Name: "a", BaseURL: base}}
		if (Patch{Providers: &p}).Check() == nil {
			t.Fatal("应拒绝不安全服务地址")
		}
	}
	p := []ProviderPatch{{ID: "a", Name: "a", BaseURL: "http://host/v1", Enabled: true}}
	if (Patch{Providers: &p}).Check() == nil {
		t.Fatal("不能启用无用途的服务")
	}
	p[0].Enabled = false
	p = append(p, p[0])
	if (Patch{Providers: &p}).Check() == nil {
		t.Fatal("标识重复应拒绝")
	}
}
