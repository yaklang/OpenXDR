package facts

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

func TestValidateShared(t *testing.T) {
	if err := ValidateShared("key", true); err != nil {
		t.Fatalf("key 事实应允许标记 shared: %v", err)
	}
	if err := ValidateShared("key", false); err != nil {
		t.Fatalf("key 事实不标记 shared 应通过: %v", err)
	}
	for _, kind := range []string{"channel", "asset_role", "decision", "change"} {
		if err := ValidateShared(kind, true); err == nil {
			t.Fatalf("%s 事实不应允许标记 shared=true", kind)
		}
		if err := ValidateShared(kind, false); err != nil {
			t.Fatalf("%s 事实 shared=false 应通过: %v", kind, err)
		}
	}
}

func TestRenderSharedKeyFact(t *testing.T) {
	const fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	dedicated := &ent.Fact{
		ID:      uuid.MustParse("01930000-0000-7000-8000-000000000001"),
		Kind:    "key",
		Subject: fp,
		Holder:  "user:zachary",
		Shared:  false,
		Content: "Bifrost WSL 专用钥匙",
	}
	shared := &ent.Fact{
		ID:      uuid.MustParse("01930000-0000-7000-8000-000000000002"),
		Kind:    "key",
		Subject: fp,
		Holder:  "user:zachary",
		Shared:  true,
		Content: "过渡期管理钥匙",
	}
	outDedicated := Render(&Brief{Facts: []*ent.Fact{dedicated}}, nil)
	if strings.Contains(outDedicated, "共享钥匙") {
		t.Fatalf("非共享钥匙不应渲染共享标记: %s", outDedicated)
	}
	outShared := Render(&Brief{Facts: []*ent.Fact{shared}}, nil)
	if !strings.Contains(outShared, "（共享钥匙）") {
		t.Fatalf("共享钥匙应渲染共享标记: %s", outShared)
	}
}

func TestHostCoverageSQLExcludesSingleChange(t *testing.T) {
	got := HostCoverageSQL("f")
	want := "f.kind IN ('asset_role', 'change') AND f.subject NOT LIKE 'authorization:change:%' AND f.subject NOT LIKE 'permission:change:%'"
	if got != want {
		t.Fatalf("手写 SQL 与 HostCoverage 口径一致：\n%s\n%s", got, want)
	}
}
