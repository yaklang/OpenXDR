//go:build integration

package syslog

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"openxdr/server/internal/dedup"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

const sshRule = `
id: b1e7a4f0-2c93-4d58-9a16-5f0d3e8c7b24
title: SSH Auth Failure
logsource:
  category: application
  product: linux
detection:
  selection:
    metadata.product.name: 'sshd'
    message|contains:
      - 'Failed password'
      - 'Invalid user'
  condition: selection
`

func loadSSHRule(t *testing.T) *sigma.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh.yml"), []byte(sshRule), 0o644); err != nil {
		t.Fatal(err)
	}
	return sigma.LoadDir(dir)
}

// 端到端：RFC3164 报文 → 归类到 linux 资产、命中 ssh 规则 → 生成一条告警；
// 同主机重复命中走 dedup 不再建新告警。
func TestSyslogBuildLifecycle(t *testing.T) {
	ctx, client := testdb.New(t)
	asset, err := client.Asset.Create().
		SetHostname("web01").SetOs("linux").SetIPAddrs([]string{"10.0.0.5"}).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{DB: client, Rules: loadSSHRule(t), Suppress: suppress.New(client, time.Hour), Intel: intel.New(client, time.Hour)}
	ded := dedup.New(time.Hour)
	line := `<34>Oct 11 22:14:15 web01 sshd[123]: Failed password for root from 1.2.3.4`

	// 第一次：命中规则 → 1 条告警
	ec, first := s.build(ctx, incoming{line: line}, ded)
	if len(first) != 1 {
		t.Fatalf("首次应生成 1 条告警，实际 %d", len(first))
	}

	evt, err := ec.Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if evt.ClassUID != ClassApplicationActivity || evt.Source != "syslog" {
		t.Errorf("事件 class/source = %d/%s", evt.ClassUID, evt.Source)
	}
	if evt.AssetID == nil || *evt.AssetID != asset.ID {
		t.Errorf("应归属到 web01 资产，得到 %v", evt.AssetID)
	}
	var raw struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(evt.Raw, &raw); err != nil || raw.Message == "" {
		t.Errorf("raw 应含 message，得到 %v", string(evt.Raw))
	}

	// 第二次：同主机同指纹 → 去重，无新告警
	_, second := s.build(ctx, incoming{line: line}, ded)
	if len(second) != 0 {
		t.Errorf("窗口内重复命中应去重，实际新建 %d 条", len(second))
	}
}

// 归属先按主机名、再退回来源 IP。
func TestSyslogResolveAsset(t *testing.T) {
	ctx, client := testdb.New(t)
	byHost, _ := client.Asset.Create().SetHostname("web01").SetOs("linux").Save(ctx)
	byIP, _ := client.Asset.Create().SetHostname("nms").SetIPAddrs([]string{"10.9.9.9"}).Save(ctx)

	s := &Server{DB: client}

	// 主机名命中
	id, os_ := s.resolveAsset(ctx, "web01", nil)
	if id == nil || *id != byHost.ID || os_ != "linux" {
		t.Errorf("主机名归属失败: id=%v os=%q", id, os_)
	}
	// 来源 IP 退回命中
	id2, _ := s.resolveAsset(ctx, "", net.ParseIP("10.9.9.9"))
	if id2 == nil || *id2 != byIP.ID {
		t.Errorf("IP 归属失败: id=%v", id2)
	}
	// 都对不上 → nil
	if id3, _ := s.resolveAsset(ctx, "ghost", nil); id3 != nil {
		t.Errorf("未知主机/IP 应返回 nil，得到 %v", id3)
	}
}
