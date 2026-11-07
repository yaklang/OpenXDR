//go:build integration

package ingest

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"openxdr/server/internal/flowinput"
	"testing"
	"time"
)

func TestFlowIngestScopeAndReplay(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	group := uuid.New()
	asset := client.Asset.Create().SetHostname("flow-source").SetGroupID(group).SetIPAddrs([]string{"10.0.0.1"}).SetFirstSeen(now.Add(-time.Hour)).SetLastSeen(now).SaveX(ctx)
	client.Asset.Create().SetHostname("other-group").SetGroupID(uuid.New()).SetIPAddrs([]string{"10.0.0.1"}).SetFirstSeen(now.Add(-time.Hour)).SetLastSeen(now).SaveX(ctx)
	event, err := flowinput.Parse("nprobe", []byte(fmt.Sprintf(`{"IPV4_SRC_ADDR":"10.0.0.1","IPV4_DST_ADDR":"198.51.100.2","L4_SRC_PORT":12345,"L4_DST_PORT":443,"PROTOCOL":6,"FLOW_START_SEC":%d,"IN_BYTES":18446744073709551615}`, now.Unix())))
	if err != nil {
		t.Fatal(err)
	}
	e := FlowEnvelope(flowinput.Origin{GroupID: group, Observer: "edge", Received: now}, event)
	if err := p.Process(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(ctx, e); err != nil {
		t.Fatal(err)
	}
	got := client.Event.Query().OnlyX(ctx)
	if got.AssetID == nil || *got.AssetID != asset.ID || got.Source != "nprobe" || got.ClassUID != 4001 {
		t.Fatalf("流量归属错误: %+v", got)
	}
	var count string
	if err := db.QueryRow(`SELECT raw->'traffic'->>'bytes_out' FROM events WHERE id=$1`, e.ID).Scan(&count); err != nil || count != "18446744073709551615" {
		t.Fatalf("流量计数失真: %q %v", count, err)
	}
	// 资产在队列处理前转组，重放新的事件不能继续沿用旧授权。
	asset.Update().SetGroupID(uuid.New()).SaveX(ctx)
	event.Time = event.Time.Add(time.Second)
	raw := fmt.Sprintf(`{"IPV4_SRC_ADDR":"10.0.0.1","IPV4_DST_ADDR":"198.51.100.2","L4_SRC_PORT":12345,"L4_DST_PORT":443,"PROTOCOL":6,"FLOW_START_SEC":%d}`, event.Time.Unix())
	event, err = flowinput.Parse("nprobe", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	e = FlowEnvelope(flowinput.Origin{GroupID: group, Observer: "edge", Received: now}, event)
	if err := p.Process(ctx, e); err != nil {
		t.Fatal(err)
	}
	got = client.Event.GetX(ctx, e.ID)
	if got.AssetID != nil {
		t.Fatal("转组后的资产不应被旧集成归属")
	}
}
