//go:build integration

package commandreview

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
)

func TestMaterialIncludesFreshReceiptsAndCurrentDecision(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	foreign := db.Group.Create().SetName("secret").SaveX(ctx)
	a := db.Asset.Create().SetHostname("target").SetGroupID(g.ID).SaveX(ctx)
	b := db.Asset.Create().SetHostname("secret").SetGroupID(foreign.ID).SaveX(ctx)
	u := db.User.Create().SetUsername("admin").SetRole("admin").SetPasswordHash("x").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("retire").SetTitle("退役").SaveX(ctx)
	d, _, err := findings.Delegate(ctx, db, f.ID, u, uuid.New(), "确认退役旧服务，必须保留替代者", "m", "local", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s := db.AgentSession.GetX(ctx, d.SessionID)
	db.SessionMessage.Create().SetSessionID(s.ID).SetSeq(1).SetRole("user").SetContent(json.RawMessage(`{"content":"核实后退役旧服务"}`)).SaveX(ctx)
	db.SessionMessage.Create().SetSessionID(s.ID).SetSeq(2).SetRole("assistant").SetContent(json.RawMessage(`{"content":[{"type":"text","text":"旧说明：替代者tick failed，健康未确认"}]}`)).SaveX(ctx)
	probe := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCreatedAt(s.CreatedAt.Add(time.Microsecond)).SetCmd("systemctl show metis-dispatcher.service").SetStatus("succeeded").SetExitCode(0).SetCompletedAt(time.Now()).SetStdout("ActiveState=active\nNRestarts=0\nnew-positive-evidence").SaveX(ctx)
	db.Command.Create().SetAssetID(b.ID).SetKind("exec").SetCmd("systemctl status secret").SetStatus("succeeded").SetExitCode(0).SetCompletedAt(time.Now()).SetStdout("must-not-leak").SaveX(ctx)
	db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("systemctl status old").SetCreatedAt(time.Now().Add(-time.Hour)).SetStatus("succeeded").SetExitCode(0).SetCompletedAt(time.Now().Add(-time.Hour)).SetStdout("stale-probe").SaveX(ctx)
	db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("systemctl status partial").SetStatus("succeeded").SetExitCode(0).SetCompletedAt(time.Now()).SetTruncated(true).SetStdout("partial").SaveX(ctx)
	cmd := "systemctl disable --now old.service"
	req := commandgate.Request{SessionID: &s.ID, Command: response.Request{AssetID: a.ID, Cmd: &cmd}}
	r := &Reviewer{DB: db}
	material, err := r.material(ctx, s, req)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{d.RequestID.String(), d.Instruction, probe.ID.String(), "new-positive-evidence", `"complete_fresh_probe":true`, `"complete_fresh_probe":false`} {
		if !strings.Contains(material, want) {
			t.Fatalf("缺少实时材料 %s: %s", want, material)
		}
	}
	for _, bad := range []string{"must-not-leak", "stale-probe"} {
		if strings.Contains(material, bad) {
			t.Fatal("泄露或用了过时证据", bad)
		}
	}
	if err = findings.RevokeDecision(ctx, db, f.ID, "admin", "local"); err != nil {
		t.Fatal(err)
	}
	if _, err = r.material(ctx, s, req); err == nil {
		t.Fatal("审计材料接受了撤销的决定")
	}
}
