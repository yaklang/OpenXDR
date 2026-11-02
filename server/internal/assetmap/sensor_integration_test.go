//go:build integration

package assetmap

import (
	"database/sql"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

// sensor 会话归到目的端（公网打进网关）时按入站记：发起方是对端地址、不挂网关资产；
// 源地址是资产自己的会话照旧按出站记在资产名下。
func TestEngineSensorInboundAttribution(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	gw := client.Asset.Create().SetHostname("gw01").SetIPAddrs([]string{"203.0.113.10", "10.0.0.1"}).SaveX(ctx)
	flow := func(src, dst string, port int) {
		client.Event.Create().SetTs(time.Now().Add(-time.Minute)).SetClassUID(classNetwork).SetSource("sensor").SetAssetID(gw.ID).
			SetRaw(json.RawMessage(`{"src_endpoint":{"ip":"` + src + `","port":40000},"dst_endpoint":{"ip":"` + dst + `","port":` + strconv.Itoa(port) + `}}`)).
			SaveX(ctx)
	}
	flow("198.51.100.7", "203.0.113.10", 443)
	flow("10.0.0.1", "10.0.0.2", 5432)
	e := &Engine{DB: client, SQL: db, Interval: time.Second}
	e.cursor, e.cursorID = e.loadCursor(ctx)
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	links := client.AssetLink.Query().AllX(ctx)
	if len(links) != 2 {
		t.Fatalf("应有两条依赖边：%+v", links)
	}
	for _, l := range links {
		switch l.SrcIP {
		case "198.51.100.7":
			if l.SrcAssetID != nil || l.DstIP != "203.0.113.10" {
				t.Errorf("入站边不应挂网关资产：%+v", l)
			}
		case "10.0.0.1":
			if l.SrcAssetID == nil || *l.SrcAssetID != gw.ID {
				t.Errorf("出站边应挂网关资产：%+v", l)
			}
		default:
			t.Errorf("多出的边：%+v", l)
		}
	}
}
