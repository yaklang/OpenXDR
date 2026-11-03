//go:build integration

package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/alert"
	"openxdr/server/internal/sigma"
)

// 内部横向喷洒：60 分钟内同一台纳管主机的地址在 ≥3 台其他纳管主机上登录失败，告警落在源主机上，
// 去重成一条、重投不多计；共用地址、窗口外、源主机自己都不算
func TestLateralSpray(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	asset := func(name string, ips ...string) uuid.UUID {
		return client.Asset.Create().SetHostname(name).SetGroupID(uuid.New()).SetIPAddrs(ips).SaveX(ctx).ID
	}
	src := asset("uos-server", "10.1.1.170", "172.17.0.1")
	var victims []uuid.UUID
	for i := range 4 {
		victims = append(victims, asset(fmt.Sprintf("victim-%d", i), fmt.Sprintf("10.1.1.%d", 190+i), "172.17.0.1"))
	}
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	n := 0
	failure := func(victim uuid.UUID, at time.Duration, from string) Envelope {
		n++
		return Envelope{Version: EnvelopeVersion, ID: StableID(t.Name(), fmt.Sprint(n)), PartitionKey: victim.String(),
			Timestamp: base.Add(at), ClassUID: 3002, Source: "agent", AssetID: &victim, AssetOS: "linux", Username: "postgres",
			Raw: json.RawMessage(`{"status_id":2,"activity_id":1,"user":{"name":"postgres"},"service":{"name":"sshd"},"src_endpoint":{"ip":"` + from + `"}}`)}
	}
	sprays := func() []int {
		var counts []int
		for _, a := range client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleLateralSpray)).AllX(ctx) {
			counts = append(counts, a.Count)
		}
		return counts
	}
	var sent []Envelope
	process := func(es ...Envelope) {
		t.Helper()
		sent = append(sent, es...)
		if err := p.ProcessBatch(ctx, es); err != nil {
			t.Fatal(err)
		}
	}

	// 共用地址（docker 网桥）认不出来源；源主机登自己不算；两台还不够
	process(failure(victims[0], 0, "172.17.0.1"), failure(victims[1], 0, "172.17.0.1"), failure(victims[2], 0, "172.17.0.1"))
	process(failure(src, time.Second, "10.1.1.170"), failure(victims[0], 2*time.Second, "10.1.1.170"), failure(victims[1], 3*time.Second, "10.1.1.170"))
	if got := sprays(); len(got) != 0 {
		t.Fatalf("不该出喷洒告警：%v", got)
	}
	// 第三台受害主机：出一条；第四台并进同一条
	process(failure(victims[2], 70*time.Second, "10.1.1.170"))
	process(failure(victims[3], 80*time.Second, "10.1.1.170"))
	// 重投全部事件：不多计
	if err := p.ProcessBatch(ctx, sent); err != nil {
		t.Fatal(err)
	}
	got := client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleLateralSpray)).AllX(ctx)
	if len(got) != 1 || got[0].Count != 2 {
		t.Fatalf("应只有一条 count=2 的喷洒告警，实际 %v", sprays())
	}
	a := got[0]
	if a.AssetID == nil || *a.AssetID != src || a.Severity != 5 || a.EventID != nil || !a.Ts.Equal(base.Add(70*time.Second)) {
		t.Errorf("喷洒告警应落在源主机、级别 5、不挂事件、时间取第三台：%+v", a)
	}
	if a.Detail == nil || !strings.Contains(*a.Detail, "共波及 4 台") || !strings.Contains(*a.Detail, "10.1.1.193 ×1") || strings.Contains(*a.Detail, "victim-") {
		t.Errorf("detail 应列出全部受害主机地址与次数、不带主机名：%v", a.Detail)
	}

	// 窗口外：另一台源主机隔 35 分钟各打一台，任一 60 分钟回看里都凑不齐三台
	other := asset("range", "10.1.1.171")
	process(failure(victims[0], 0, "10.1.1.171"), failure(victims[1], 35*time.Minute, "10.1.1.171"), failure(victims[2], 70*time.Minute, "10.1.1.171"))
	if client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleLateralSpray), alert.AssetIDEQ(other)).ExistX(ctx) {
		t.Error("60 分钟内不足三台受害主机不该告警")
	}
}
