//go:build integration

package triage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func TestHistoryCannotBorrowAnotherGroupsHumanConfirmation(t *testing.T) {
	ctx, db := testdb.New(t)
	ga := db.Group.Create().SetName("当前组").SaveX(ctx)
	gb := db.Group.Create().SetName("另一组").SaveX(ctx)
	a := db.Asset.Create().SetHostname("current").SetGroupID(ga.ID).SaveX(ctx)
	peer := db.Asset.Create().SetHostname("peer").SetGroupID(ga.ID).SaveX(ctx)
	b := db.Asset.Create().SetHostname("outside").SetGroupID(gb.ID).SaveX(ctx)
	unassigned := db.Asset.Create().SetHostname("unassigned").SaveX(ctx)
	now := time.Now()
	current := db.Incident.Create().SetTitle("当前事件").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	add := func(inc *ent.Incident, host *ent.Asset, rule string, at time.Time) *ent.Alert {
		q := db.Alert.Create().SetIncidentID(inc.ID).SetRuleID(rule).SetSeverity(3).SetTs(at)
		if host != nil {
			q.SetAssetID(host.ID)
		}
		return q.SaveX(ctx)
	}
	al := add(current, a, "same-rule", now)
	history := func(title string, hosts ...*ent.Asset) {
		inc := db.Incident.Create().SetTitle(title).SetGraph(json.RawMessage(`{}`)).SetStatus("false_positive").SetResolvedBy("analyst").SetResolvedAt(now).SetResolution("仅适用于该案例的人工确认").SaveX(ctx)
		for i, host := range hosts {
			rule, at := "same-rule", now
			if i > 0 {
				rule = "unrelated-rule"
				at = now.AddDate(0, 0, -100)
			}
			add(inc, host, rule, at)
		}
	}
	history("同组参考", peer)
	history("组外秘密", b)
	history("混合组秘密", peer, b)
	history("未分组秘密", unassigned)
	history("未知归属秘密", nil)
	history("混合未知秘密", peer, nil)
	var out strings.Builder
	(&Engine{DB: db}).appendCaseHistory(ctx, &out, current, []*ent.Alert{al})
	if !strings.Contains(out.String(), `"title":"同组参考"`) {
		t.Fatalf("同组参考丢失: %s", out.String())
	}
	for _, secret := range []string{"组外秘密", "混合组秘密", "未分组秘密", "未知归属秘密", "混合未知秘密"} {
		if strings.Contains(out.String(), secret) {
			t.Errorf("历史人工案例跨组泄漏: %s", secret)
		}
	}
	// 资产转组后重新取当前归属，不沿用旧范围。
	db.Asset.UpdateOne(a).SetGroupID(gb.ID).ExecX(ctx)
	out.Reset()
	(&Engine{DB: db}).appendCaseHistory(ctx, &out, current, []*ent.Alert{al})
	if strings.Contains(out.String(), `"title":"同组参考"`) || !strings.Contains(out.String(), `"title":"组外秘密"`) {
		t.Fatalf("未按当前资产归属刷新参考范围: %s", out.String())
	}
	// 范围取完整事件，而非调用方已截断的告警明细。
	db.Asset.UpdateOne(a).SetGroupID(ga.ID).ExecX(ctx)
	add(current, b, "not-in-detail", now)
	out.Reset()
	(&Engine{DB: db}).appendCaseHistory(ctx, &out, current, []*ent.Alert{al})
	for _, title := range []string{"同组参考", "组外秘密", "混合组秘密"} {
		if !strings.Contains(out.String(), `"title":"`+title+`"`) {
			t.Fatalf("完整事件范围被明细截断: %s", out.String())
		}
	}

	unknown := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	unknownAlert := add(unknown, nil, "same-rule", now)
	out.Reset()
	(&Engine{DB: db}).appendCaseHistory(ctx, &out, unknown, []*ent.Alert{unknownAlert})
	if !strings.Contains(out.String(), "缺少可确认的资产归属，未检索历史案例") || strings.Contains(out.String(), `"source":"human"`) {
		t.Fatalf("未知资产归属不能退回全局案例: %s", out.String())
	}

}
