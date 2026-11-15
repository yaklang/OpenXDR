//go:build integration

package commandreview

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/clockskew"
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
	now, err := clockskew.DBNow(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	db.SessionMessage.Create().SetSessionID(s.ID).SetSeq(1).SetRole("user").SetContent(json.RawMessage(`{"content":"核实后退役旧服务"}`)).SaveX(ctx)
	db.SessionMessage.Create().SetSessionID(s.ID).SetSeq(2).SetRole("assistant").SetContent(json.RawMessage(`{"content":[{"type":"text","text":"旧说明：替代者tick failed，健康未确认"}]}`)).SaveX(ctx)
	// 容差内（s.CreatedAt - 2s, now + 2s）纳入本轮且标为 complete_fresh_probe=true；
	// 超出下界（s.CreatedAt - 10s）排除；超出上界（now + 10s）标为 complete_fresh_probe=false。
	probe := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCreatedAt(s.CreatedAt.Add(-2 * time.Second)).SetCmd("systemctl show metis-dispatcher.service").SetStatus("succeeded").SetExitCode(0).SetCompletedAt(now.Add(2 * time.Second)).SetStdout("ActiveState=active\nNRestarts=0\nnew-positive-evidence").SaveX(ctx)
	db.Command.Create().SetAssetID(b.ID).SetKind("exec").SetCreatedAt(s.CreatedAt.Add(time.Millisecond)).SetCmd("systemctl status secret").SetStatus("succeeded").SetExitCode(0).SetCompletedAt(s.CreatedAt.Add(2 * time.Millisecond)).SetStdout("must-not-leak").SaveX(ctx)
	db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("systemctl status old").SetCreatedAt(s.CreatedAt.Add(-clockskew.Max - 5*time.Second)).SetStatus("succeeded").SetExitCode(0).SetCompletedAt(s.CreatedAt.Add(-clockskew.Max - 4*time.Second)).SetStdout("stale-probe").SaveX(ctx)
	futureDone := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCreatedAt(s.CreatedAt.Add(time.Millisecond)).SetCmd("systemctl status future-skew").SetStatus("succeeded").SetExitCode(0).SetCompletedAt(now.Add(clockskew.Max + 5*time.Second)).SetStdout("beyond-future-skew").SaveX(ctx)
	db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCreatedAt(s.CreatedAt.Add(time.Millisecond)).SetCmd("systemctl status partial").SetStatus("succeeded").SetExitCode(0).SetCompletedAt(s.CreatedAt.Add(2 * time.Millisecond)).SetTruncated(true).SetStdout("partial").SaveX(ctx)
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
	// 核对回执 JSON 中 probe 为 complete_fresh_probe=true，而 futureDone 为 complete_fresh_probe=false。
	const receiptHeader = "平台实时读取的目标资产最近30分钟真实指令回执（新到旧；complete_fresh_probe=false不得作为完整健康证明；没有回执不等于健康）：\n"
	_, afterHeader, ok := strings.Cut(material, receiptHeader)
	if !ok {
		t.Fatalf("未找到回执列表标题: %s", material)
	}
	jsonLine, _, _ := strings.Cut(afterHeader, "\n")
	var receipts []struct {
		ID                 uuid.UUID `json:"id"`
		CompleteFreshProbe bool      `json:"complete_fresh_probe"`
	}
	if err := json.Unmarshal([]byte(jsonLine), &receipts); err != nil {
		t.Fatalf("解析回执 JSON 失败: %v (%s)", err, jsonLine)
	}
	seenProbe, seenFuture := false, false
	for _, row := range receipts {
		if row.ID == probe.ID {
			seenProbe = true
			if !row.CompleteFreshProbe {
				t.Fatalf("容差内探针应标为 complete_fresh_probe=true: %+v", row)
			}
		}
		if row.ID == futureDone.ID {
			seenFuture = true
			if row.CompleteFreshProbe {
				t.Fatalf("超出上界容差的未来完成探针不应标为 complete_fresh_probe=true: %+v", row)
			}
		}
	}
	if !seenProbe || !seenFuture {
		t.Fatalf("回执列表不完整: seenProbe=%v seenFuture=%v", seenProbe, seenFuture)
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
