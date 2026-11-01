package vuln

import (
	"context"
	"openxdr/server/internal/assetmap"
	"testing"
)

func TestRPMNeverUsesDebianVersionMatching(t *testing.T) {
	// 即使事件错误地携带 debian，RPM 也不得进入 dpkg 公告查询与比较。
	sw := &assetmap.Software{OS: "debian", Version: "13", Manager: "rpm", Packages: [][4]string{{"pkg", "1:2-3", "pkg", "2-3"}}}
	rep, err := Match(context.Background(), nil, sw, nil)
	if err != nil || rep.Ecosystem != "" || rep.Packages != 1 {
		t.Fatalf("RPM 被送入 dpkg 匹配: %+v %v", rep, err)
	}
}
