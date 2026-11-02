//go:build integration

package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"openxdr/server/internal/temporal"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

const sourceRule = "id: by-source\nkind: event_count\ngroup_by: asset_source_ip\nwithin: 1m\nrules: [base]\nthreshold: 3\nlevel: high\n"

// 真实仓库 Linux 认证规则走处理器，确认不是只有测试用 marker 规则可用。
func TestNativeLinuxSourceIPRule(t *testing.T) {
	for _, split := range []bool{false, true} {
		t.Run(fmt.Sprintf("split=%v", split), func(t *testing.T) {
			f := sourceFixture(t)
			a := f.asset(uuid.New())
			store := &temporal.Store{}
			root := filepath.Join("..", "..", "..")
			if err := store.Reload(filepath.Join(root, "rules"), filepath.Join(root, "temporal-rules")); err != nil {
				t.Fatal(err)
			}
			f.p.Temporal = store
			f.p.Rules = store
			for i := 0; i < 10; i++ {
				ip := "192.0.2.6"
				if split && i%2 == 1 {
					ip = "192.0.2.7"
				}
				e := sourceEvent(f, a, i, ip)
				e.ClassUID = 3002
				e.AssetOS = "linux"
				e.Raw = json.RawMessage(fmt.Sprintf(`{"activity_id":1,"status_id":2,"src_endpoint":{"ip":%q}}`, ip))
				f.process(e)
			}
			want := 1
			if split {
				want = 0
			}
			if f.detections("temporal:linux-auth-source-burst") != want {
				t.Fatal("真实 Linux 登录规则同源阈值错误")
			}
		})
	}
}

func sourceFixture(t *testing.T) *accountFixture {
	f := newAccountFixture(t)
	f.p.Temporal = temporalStoreFixtureWithRule(t, sourceRule)
	return f
}
func sourceEvent(f *accountFixture, asset uuid.UUID, seconds int, ip string) Envelope {
	e := f.event(asset, seconds, "same-user")
	e.Raw = json.RawMessage(fmt.Sprintf(`{"marker":"yes","src_endpoint":{"ip":%q}}`, ip))
	return e
}

func TestSourceIPIsolationAndLateReplay(t *testing.T) {
	f := sourceFixture(t)
	group := uuid.New()
	a, b := f.asset(group), f.asset(group)
	e1, e2, e3 := sourceEvent(f, a, 0, "192.0.2.10"), sourceEvent(f, a, 1, "::ffff:192.0.2.10"), sourceEvent(f, a, 2, "192.0.2.10")
	// 两个来源、两台目标各自未到三次，不得相加。
	f.process(e1, e2, sourceEvent(f, a, 0, "198.51.100.1"), sourceEvent(f, b, 0, "192.0.2.10"))
	if f.detections("by-source") != 0 {
		t.Fatal("不同来源或目标被混合")
	}
	f.process(e3, e1, e2, e3)
	if f.detections("by-source") != 1 {
		t.Fatal("同源阈值或幂等错误")
	}
	var entity string
	var count int
	var asset uuid.UUID
	if err := f.p.DB.QueryRow(`SELECT d.entity,a.count,a.asset_id FROM temporal_detections d JOIN alerts a ON a.id=d.alert_id WHERE d.rule_id='by-source'`).Scan(&entity, &count, &asset); err != nil {
		t.Fatal(err)
	}
	if entity != temporal.AssetSourceIPEntity(a, "192.0.2.10") || count != 1 || asset != a {
		t.Fatal("告警归因错误")
	}
	// 终点先到、前序迟到补齐；另一来源应形成独立告警实体。
	f.process(sourceEvent(f, a, 12, "2001:db8::5"), sourceEvent(f, a, 11, "2001:db8::5"), sourceEvent(f, a, 10, "2001:db8::5"))
	if f.detections("by-source") != 2 {
		t.Fatal("迟到回放未补齐")
	}
	var alerts int
	if err := f.p.DB.QueryRow(`SELECT count(DISTINCT alert_id) FROM temporal_detections WHERE rule_id='by-source'`).Scan(&alerts); err != nil || alerts != 2 {
		t.Fatalf("不同攻击源告警被错误去重: %d %v", alerts, err)
	}
}

func TestSourceIPMissingAndMovedGroup(t *testing.T) {
	f := sourceFixture(t)
	a := f.asset(uuid.New())
	for i, ip := range []string{"", "-", "0.0.0.0", "host.invalid"} {
		f.process(sourceEvent(f, a, i, ip))
	}
	if f.detections("by-source") != 0 || len(f.metrics.reasons) != 4 || slices.ContainsFunc(f.metrics.reasons, func(r string) bool { return r != "no_source_ip" }) {
		t.Fatalf("来源缺口错误: %v", f.metrics.reasons)
	}
	f.process(sourceEvent(f, a, 10, "192.0.2.9"), sourceEvent(f, a, 11, "192.0.2.9"))
	f.client.Asset.UpdateOneID(a).SetGroupID(uuid.New()).SaveX(context.Background())
	f.process(sourceEvent(f, a, 12, "192.0.2.9"))
	if f.detections("by-source") != 0 {
		t.Fatal("资产换组后复用旧候选")
	}
}

func TestSourceIPConcurrentThreshold(t *testing.T) {
	f := sourceFixture(t)
	a := f.asset(uuid.New())
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		e := sourceEvent(f, a, i, fmt.Sprintf("192.0.2.%d", 10+i%2))
		wg.Add(1)
		go func() { defer wg.Done(); errs <- f.p.Process(context.Background(), e) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.detections("by-source") != 2 {
		t.Fatal("并发来源计数丢失或串扰")
	}
}
