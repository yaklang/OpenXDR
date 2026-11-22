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
// 未在宿主机 containers 清单登记、跨组、Docker 容器、没有同名资产、同名资产已下线的都留在宿主机名下
func TestLXCEventsBelongToTheGuestAsset(t *testing.T) {
	ctx, client := testdb.New(t)
	containers := json.RawMessage(`[{"runtime":"lxc","uid":"203","name":"gateway","addrs":["10.1.1.100"]},{"runtime":"lxc","uid":"205","name":"old-ct","addrs":["10.1.1.105"]},{"runtime":"docker","uid":"d1","name":"docker-only","addrs":["172.17.0.2"]}]`)
	host := client.Asset.Create().SetHostname("pve1").SetContainers(containers).SaveX(ctx)
	guest := client.Asset.Create().SetHostname("gateway").SetOs("linux").SaveX(ctx)
	client.Asset.Create().SetHostname("docker-only").SetOs("linux").SaveX(ctx)
	client.Asset.Create().SetHostname("old-ct").SetRetiredAt(time.Now()).SaveX(ctx)
	srv := &Server{DB: client}
	st := &agentStream{ctx: ctx, s: srv, assetID: &host.ID, assetOS: "linux"}
	attr := func(stream *agentStream, raw string) (string, string) {
		var m map[string]any
		_ = json.Unmarshal([]byte(raw), &m)
		id, _, out := stream.attribute(json.RawMessage(raw), m)
		return id.String(), string(out)
	}
	id, out := attr(st, `{"process":{"pid":7,"created_time":9007199254740993},"container":{"runtime":"lxc","uid":"203","name":"gateway"}}`)
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
		`{"container":{"runtime":"lxc","uid":"206","name":"docker-only"}}`,
		`{"process":{"pid":1}}`,
	} {
		if id, out := attr(st, raw); id != host.ID.String() || out != raw {
			t.Fatalf("不该改归属：%s → %s %s", raw, id, out)
		}
	}

	// 非宿主机（containers 中未登记 gateway）伪造 LXC 上报：不得改写归属
	spoofHost := client.Asset.Create().SetHostname("random-vm").SaveX(ctx)
	spoofStream := &agentStream{ctx: ctx, s: srv, assetID: &spoofHost.ID, assetOS: "linux"}
	spoofRaw := `{"process":{"pid":9},"container":{"runtime":"lxc","uid":"203","name":"gateway"}}`
	if id, out := attr(spoofStream, spoofRaw); id != spoofHost.ID.String() || out != spoofRaw {
		t.Fatalf("未登记该 LXC 的主机不能伪造归属：%s %s", id, out)
	}

	// 跨组宿主机即使 containers 写了同名 LXC，也不能跨组改写目标资产归属
	gA := client.Group.Create().SetName("group-a").SaveX(ctx)
	gB := client.Group.Create().SetName("group-b").SaveX(ctx)
	hostA := client.Asset.Create().SetHostname("pve-a").SetGroupID(gA.ID).
		SetContainers(json.RawMessage(`[{"runtime":"lxc","uid":"301","name":"ct-b","addrs":["10.2.0.10"]},{"runtime":"lxc","uid":"302","name":"ct-a","addrs":["10.2.0.11"]}]`)).SaveX(ctx)
	ctA := client.Asset.Create().SetHostname("ct-a").SetGroupID(gA.ID).SetOs("linux").SaveX(ctx)
	client.Asset.Create().SetHostname("ct-b").SetGroupID(gB.ID).SetOs("linux").SaveX(ctx)
	streamA := &agentStream{ctx: ctx, s: srv, assetID: &hostA.ID, assetOS: "linux"}
	if id, _ := attr(streamA, `{"container":{"runtime":"lxc","uid":"302","name":"ct-a"}}`); id != ctA.ID.String() {
		t.Fatalf("同组且已登记的 LXC 应归到 ct-a：%s", id)
	}
	crossRaw := `{"container":{"runtime":"lxc","uid":"301","name":"ct-b"}}`
	if id, out := attr(streamA, crossRaw); id != hostA.ID.String() || out != crossRaw {
		t.Fatalf("跨组宿主机不能归属到其他组的 LXC：%s %s", id, out)
	}
}
