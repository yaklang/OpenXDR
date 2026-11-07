package commandreview

import (
	"strings"
	"testing"
)

func TestReviewEvidenceRedactsSecretsWithoutHidingHealth(t *testing.T) {
	raw := "ActiveState=active\nPASSWORD=private-value\nAuthorization: Bearer credential-value\n-----BEGIN OPENSSH PRIVATE KEY-----\nkey-material\n-----END OPENSSH PRIVATE KEY-----\nNRestarts=0"
	got := reviewText(raw)
	for _, secret := range []string{"private-value", "credential-value", "key-material"} {
		if strings.Contains(got, secret) {
			t.Fatal("凭据进入审计材料", got)
		}
	}
	for _, fact := range []string{"ActiveState=active", "NRestarts=0"} {
		if !strings.Contains(got, fact) {
			t.Fatal("健康事实被抹去", got)
		}
	}
}
