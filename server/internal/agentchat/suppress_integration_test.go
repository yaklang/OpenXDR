//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/testdb"
)

// AI 只能对本组主机上真实命中过的规则提议抑制；提议不生效、不重复，被拒绝过的不再接受
func TestSuppressProposal(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("o").SaveX(ctx)
	host := db.Asset.Create().SetHostname("pve1").SetGroupID(group.ID).SaveX(ctx)
	stranger := db.Asset.Create().SetHostname("x").SetGroupID(other.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("a").SetModel("m").SetStatus("running").SaveX(ctx)
	ev := db.Event.Create().SetTs(time.Now()).SetClassUID(4003).SetSource("agent").SetAssetID(host.ID).
		SetRaw(json.RawMessage(`{"query":{"hostname":"4mrf9fwf.doggygo.top"}}`)).SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetRuleID("probe").SetSeverity(2).SetAssetID(host.ID).SetEventID(ev.ID).SaveX(ctx)
	cmd := db.Command.Create().SetKind("exec").SetAssetID(host.ID).SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetRuleID("own").SetSeverity(2).SetAssetID(host.ID).SetCommandID(cmd.ID).SaveX(ctx)
	s := &Service{DB: db}
	proposeWith := func(host, rule, conds string) (string, error) {
		return s.tool(ctx, session, commandgate.Request{}, "suppress", json.RawMessage(
			`{"host":"`+host+`","rule_id":"`+rule+`","reason":"vpn-proxy 每天 10:58 解析订阅域名，例行业务","days":30,"conditions":`+conds+`}`))
	}
	domain := `[{"field":"query.hostname","op":"endswith","value":".doggygo.top"}]`
	propose := func(host, rule string) (string, error) { return proposeWith(host, rule, domain) }
	if _, err := proposeWith(host.ID.String(), "probe", `[]`); err == nil {
		t.Fatal("不带条件应拒绝：不能整条规则压掉")
	}
	// 对不上时把真实值带回去，字段路径写错也要说清楚，模型不用再猜
	_, err := proposeWith(host.ID.String(), "probe", `[{"field":"query.hostname","op":"equals","value":"made-up.top"},{"field":"query.name","op":"equals","value":"x"}]`)
	if err == nil || !strings.Contains(err.Error(), `query.hostname = "4mrf9fwf.doggygo.top"`) || !strings.Contains(err.Error(), "query.name 在这些事件里不存在") {
		t.Fatalf("对不上任何真实命中的条件应拒绝并给出实际值：%v", err)
	}
	if _, err := propose(stranger.ID.String(), "probe"); err == nil {
		t.Fatal("别组主机应拒绝")
	}
	if _, err := propose(host.ID.String(), "never-hit"); err == nil {
		t.Fatal("没命中过的规则应拒绝")
	}
	if _, err := propose(host.ID.String(), "own"); err == nil {
		t.Fatal("只有平台指令触发过的规则不需要抑制")
	}
	out, err := propose(host.ID.String(), "probe")
	if err != nil || !strings.Contains(out, "proposed") {
		t.Fatalf("应提交提议: %s %v", out, err)
	}
	p := db.Suppression.Query().OnlyX(ctx)
	if p.Status != "proposed" || p.SessionID == nil || *p.SessionID != session.ID || p.AssetID == nil || *p.AssetID != host.ID {
		t.Fatalf("提议应待批准、记下会话与主机: %+v", p)
	}
	if out, _ := propose(host.ID.String(), "probe"); !strings.Contains(out, "pending") {
		t.Fatalf("已有待批准的不重复提: %s", out)
	}
	if len(p.Conditions) != 1 || p.Conditions[0].Value != ".doggygo.top" {
		t.Fatalf("条件应落库: %+v", p.Conditions)
	}
	db.Suppression.UpdateOne(p).SetStatus("rejected").SetReviewedAt(time.Now()).ExecX(ctx)
	if out, _ := propose(host.ID.String(), "probe"); !strings.Contains(out, "rejected") {
		t.Fatalf("30 天内拒绝过的不再接受: %s", out)
	}
	// 被拒的是别的条件时，更窄的新提议照常接受
	if out, err := proposeWith(host.ID.String(), "probe", `[{"field":"query.hostname","op":"equals","value":"4mrf9fwf.doggygo.top"}]`); err != nil || !strings.Contains(out, "proposed") {
		t.Fatalf("条件不同的提议应接受: %s %v", out, err)
	}
}

// 提议落库后当场交审计员评审，结论与理由直接回给模型
func TestSuppressReviewedOnSpot(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	host := db.Asset.Create().SetHostname("pve1").SetGroupID(group.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("a").SetModel("m").SetStatus("running").SaveX(ctx)
	ev := db.Event.Create().SetTs(time.Now()).SetClassUID(4003).SetSource("agent").SetAssetID(host.ID).
		SetRaw(json.RawMessage(`{"query":{"hostname":"a.example.com"}}`)).SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetRuleID("probe").SetSeverity(2).SetAssetID(host.ID).SetEventID(ev.ID).SaveX(ctx)
	var reviewed []uuid.UUID
	s := &Service{DB: db, ReviewSuppression: func(_ context.Context, id uuid.UUID) (string, string, error) {
		reviewed = append(reviewed, id)
		return "rejected", "条件太宽", nil
	}}
	out, err := s.tool(ctx, session, commandgate.Request{}, "suppress", json.RawMessage(
		`{"host":"`+host.ID.String()+`","rule_id":"probe","reason":"例行解析更新域名，每天一次","conditions":[{"field":"query.hostname","op":"equals","value":"a.example.com"}]}`))
	if err != nil || !strings.Contains(out, `"status":"rejected"`) || !strings.Contains(out, "条件太宽") {
		t.Fatalf("应回给模型审计员的结论: %s %v", out, err)
	}
	if p := db.Suppression.Query().OnlyX(ctx); len(reviewed) != 1 || reviewed[0] != p.ID {
		t.Fatalf("应评审刚落库的草案: %v", reviewed)
	}
}
