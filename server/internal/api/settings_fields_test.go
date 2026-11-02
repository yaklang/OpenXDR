package api

import (
	"openxdr/server/internal/aiconf"
	"strings"
	"testing"
)

func TestAbuseCHKeyAuditRedaction(t *testing.T) {
	key := "abuse-secret-12345678"
	got := changedFields(aiconf.Patch{AbuseCHKey: &key})
	if got != "abuseCHKey（设置）" || strings.Contains(got, key) {
		t.Fatalf("审计只能记录设置动作: %q", got)
	}
	key = ""
	if got := changedFields(aiconf.Patch{AbuseCHKey: &key}); got != "abuseCHKey（清空）" {
		t.Fatalf("清空审计不正确: %q", got)
	}
}
