//go:build integration

package grpcsvc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

// LXC 里的进程事件归到同名资产，宿主机记在 observed_by；正文的大整数原样保留。
// Docker 容器、没有同名资产、同名资产已下线的都留在宿主机名下
func TestLXCEventsBelongToTheGuestAsset(t *testing.T) {
	ctx, client := testdb.New(t)
	host := client.Asset.Create().SetHostname("pve1").SaveX(ctx)
	guest := client.Asset.Create().SetHostname("gateway").SetOs("linux").SaveX(ctx)
	client.Asset.Create().SetHostname("old-ct").SetRetiredAt(time.Now()).SaveX(ctx)
	st := &agentStream{ctx: ctx, s: &Server{DB: client}, assetID: &host.ID, assetOS: "linux"}
	attr := func(raw string) (string, string) {
		var m map[string]any
		_ = json.Unmarshal([]byte(raw), &m)
		id, _, out := st.attribute(json.RawMessage(raw), m)
		return id.String(), string(out)
	}
	id, out := attr(`{"process":{"pid":7,"created_time":9007199254740993},"container":{"runtime":"lxc","uid":"203","name":"gateway"}}`)
	if id != guest.ID.String() {
		t.Fatalf("应归到 gateway：%s", id)
	}
	if !strings.Contains(out, `"observed_by":{"asset_id":"`+host.ID.String()+`"}`) || !strings.Contains(out, "9007199254740993") {
		t.Fatalf("要记下宿主机、保留原始正文：%s", out)
	}
	if !json.Valid([]byte(out)) {
		t.Fatalf("改写后不是合法 JSON：%s", out)
	}
	for _, raw := range []string{
		`{"container":{"runtime":"docker","uid":"abc","name":"gateway"}}`,
		`{"container":{"runtime":"lxc","uid":"201","name":"dns-primary"}}`,
		`{"container":{"runtime":"lxc","uid":"205","name":"old-ct"}}`,
		`{"process":{"pid":1}}`,
	} {
		if id, out := attr(raw); id != host.ID.String() || out != raw {
			t.Fatalf("不该改归属：%s → %s %s", raw, id, out)
		}
	}
}
