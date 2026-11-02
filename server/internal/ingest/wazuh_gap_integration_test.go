//go:build integration

package ingest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/temporal"
)

// 独立测试库中走真实入库处理器：验证新增规则的证据、幂等和隔离。
func TestWazuhGapPersistentReplay(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	data, err := os.ReadFile(filepath.Join(root, "validation", "wazuh-gap-temporal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name   string `json:"name"`
		Events []struct {
			ID       string         `json:"id"`
			Seconds  int            `json:"seconds"`
			Group    string         `json:"group"`
			Asset    string         `json:"asset"`
			Username string         `json:"username"`
			OS       string         `json:"os"`
			ClassUID int            `json:"classUid"`
			Raw      map[string]any `json:"raw"`
		} `json:"events"`
		Matches []struct {
			Rule     string   `json:"rule"`
			Anchor   string   `json:"anchor"`
			Evidence []string `json:"evidence"`
		} `json:"matches"`
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			p, c, db := testProcessor(t)
			defer c.Close()
			defer db.Close()
			ctx := context.Background()
			store := &temporal.Store{}
			if err := store.Reload(filepath.Join(root, "rules"), filepath.Join(root, "temporal-rules")); err != nil {
				t.Fatal(err)
			}
			p = &Processor{DB: db, Temporal: store, Rules: store, Suppress: p.Suppress, Intel: p.Intel, DedupWindow: p.DedupWindow}
			id := func(s string) uuid.UUID { return uuid.NewSHA1(uuid.NameSpaceOID, []byte(tc.Name+"/"+s)) }
			assets := map[string]uuid.UUID{}
			now := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
			var events []Envelope
			for _, input := range tc.Events {
				key := input.Group + "/" + input.Asset
				asset, exists := assets[key]
				if !exists {
					asset = c.Asset.Create().SetHostname(key).SetOs(input.OS).SetGroupID(id(input.Group)).SaveX(ctx).ID
					assets[key] = asset
				}
				raw, err := json.Marshal(input.Raw)
				if err != nil {
					t.Fatal(err)
				}
				source := "agent"
				if input.ClassUID == 100001 {
					source = "syslog"
				}
				e := Envelope{Version: EnvelopeVersion, ID: id(input.ID), PartitionKey: asset.String(), Timestamp: now.Add(time.Duration(input.Seconds) * time.Second), ClassUID: input.ClassUID, Source: source, AssetID: &asset, AssetOS: input.OS, Username: input.Username, Raw: raw}
				if err := p.Process(ctx, e); err != nil {
					t.Fatal(err)
				}
				events = append(events, e)
			}
			// 重建处理器并重投，不能多出告警或多计一次阈值。
			p = &Processor{DB: db, Temporal: store, Rules: store, Suppress: p.Suppress, Intel: p.Intel, DedupWindow: p.DedupWindow}
			for _, e := range events {
				if err := p.Process(ctx, e); err != nil {
					t.Fatal(err)
				}
			}
			rows, err := db.Query(`SELECT d.rule_id,d.anchor_id,d.evidence,a.count FROM temporal_detections d JOIN alerts a ON a.id=d.alert_id WHERE d.rule_id LIKE 'temporal:wazuh-gap-%'`)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string][]uuid.UUID{}
			for rows.Next() {
				var rule string
				var anchor uuid.UUID
				var raw []byte
				var count int
				if err = rows.Scan(&rule, &anchor, &raw, &count); err != nil {
					t.Fatal(err)
				}
				if count != 1 {
					t.Fatalf("重复计数 %s: %d", rule, count)
				}
				var evidence []uuid.UUID
				if err = json.Unmarshal(raw, &evidence); err != nil {
					t.Fatal(err)
				}
				got[rule+"/"+anchor.String()] = evidence
			}
			if err = rows.Err(); err != nil {
				t.Fatal(err)
			}
			rows.Close()
			want := map[string][]uuid.UUID{}
			for _, m := range tc.Matches {
				var ev []uuid.UUID
				for _, e := range m.Evidence {
					ev = append(ev, id(e))
				}
				want[m.Rule+"/"+id(m.Anchor).String()] = ev
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("持久回放不符合预期: 实际=%v 预期=%v", got, want)
			}
		})
	}
}
