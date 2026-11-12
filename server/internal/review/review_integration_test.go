//go:build integration

package review

import (
	"encoding/json"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/predicate"
	"openxdr/server/internal/decoy"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/testdb"
)

// 三个口径在同一批事件上的判定：哪些要人看、哪些是可以自动结案的良性噪声、哪些只有诱饵观察
func TestPredicates(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	cutoff := now.Add(-24 * time.Hour)

	names := map[uuid.UUID]string{}
	type al struct {
		rule string
		sev  int16
	}
	mk := func(name, status, verdict string, created time.Time, alerts ...al) {
		c := db.Incident.Create().SetStatus(status).SetGraph(json.RawMessage(`{}`)).SetCreatedAt(created)
		if status == "triaged" {
			c.SetTriagedAt(created)
		}
		if verdict != "" {
			c.SetAiVerdict(json.RawMessage(verdict))
		}
		inc := c.SaveX(ctx)
		names[inc.ID] = name
		for _, a := range alerts {
			db.Alert.Create().SetTs(created).SetRuleID(a.rule).SetSeverity(a.sev).SetIncidentID(inc.ID).ExecX(ctx)
		}
	}
	benign := `{"verdict":"benign","summary":"运维脚本"}`
	suspicious := `{"verdict":"suspicious","summary":"未知来源"}`
	suspiciousResp := `{"verdict":"suspicious","action_codes":["review_response"]}`
	malicious := `{"verdict":"malicious"}`
	dec := decoy.ObservationRulePrefix + "honeyfile"

	mk("未研判", "open", "", old)
	mk("判恶意", "open", malicious, old, al{"r1", 2})
	mk("判良性低危旧", "triaged", benign, old, al{"r1", 2}, al{"r2", 3})
	// 良性结论没看过的证据：分析师重开的、之后又并入新证据待重研判的，都不能拿旧结论自动结案
	mk("重开良性低危旧", "open", benign, old, al{"r1", 2})
	mk("待重研判良性低危旧", "triaged", benign, old, al{"r1", 2})
	for id, name := range names {
		if name == "待重研判良性低危旧" {
			db.Incident.UpdateOneID(id).SetTriagedAt(old).SetEvidenceAt(now).ExecX(ctx)
		}
	}
	mk("判良性低危新", "triaged", benign, now, al{"r1", 1})
	mk("判良性高危旧", "triaged", benign, old, al{"r1", 2}, al{"r2", 4})
	mk("判良性严重旧", "triaged", benign, old, al{"r1", 5})
	// 高危告警所在主机有写明业务的资产角色事实：良性结论有人写过的依据兜底，照常静默、到期交审计
	covered := db.Asset.Create().SetHostname("ci").SaveX(ctx)
	db.Fact.Create().SetKind("asset_role").SetAssetID(covered.ID).SetContent("CI 构建机").SetCreatedBy("admin").ExecX(ctx)
	mk("判良性高危有事实", "triaged", benign, old)
	for id, name := range names {
		if name == "判良性高危有事实" {
			db.Alert.Create().SetTs(old).SetRuleID("r2").SetSeverity(4).SetIncidentID(id).SetAssetID(covered.ID).ExecX(ctx)
		}
	}
	mk("判可疑低危旧", "triaged", suspicious, old, al{"r1", 3})
	mk("判可疑高危", "triaged", suspicious, old, al{"r1", 4})
	mk("判可疑低危需响应", "triaged", suspiciousResp, old, al{"r1", 3})
	mk("判良性含诱饵与真实告警", "open", benign, old, al{"r1", 1}, al{dec, 1})
	mk("判良性仅诱饵", "open", benign, old, al{dec, 1})
	mk("未研判仅诱饵", "open", "", old, al{dec, 2})
	mk("结论缺 verdict 字段", "open", `{"summary":"x"}`, old, al{"r1", 1})
	mk("结论大小写不符", "open", `{"verdict":"Benign"}`, old, al{"r1", 1})
	mk("已结案恶意高危", "closed", malicious, old, al{"r1", 5})
	mk("误报良性", "false_positive", benign, old, al{"r1", 1})
	mk("已结案含诱饵", "closed", "", old, al{dec, 1})

	if err := incidentwork.Reconcile(ctx, db, now); err != nil {
		t.Fatal(err)
	}

	query := func(p predicate.Incident) []string {
		var out []string
		for _, inc := range db.Incident.Query().Where(p).AllX(ctx) {
			out = append(out, names[inc.ID])
		}
		sort.Strings(out)
		return out
	}
	expect := func(label string, got []string, want ...string) {
		t.Helper()
		sort.Strings(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s\n got  %v\n want %v", label, got, want)
		}
	}

	expect("Needed", query(Needed()),
		"未研判", "判恶意", "重开良性低危旧", "判良性高危旧", "判良性严重旧", "判可疑高危", "判可疑低危需响应", "判良性含诱饵与真实告警", "判良性仅诱饵", "未研判仅诱饵", "结论缺 verdict 字段", "结论大小写不符")
	expect("StaleBenign", query(StaleBenign(cutoff)), "判良性低危旧", "判良性高危有事实")
	expect("SevereBenign", query(SevereBenign()), "判良性高危旧", "判良性严重旧")
	// 截止时间放到未来，新创建的良性低危事件也算过期；未核实的可疑事件（判可疑低危旧）虽静默不通知，但绝不自动按误报结案
	expect("StaleBenign(未来)", query(StaleBenign(now.Add(time.Hour))), "判良性低危旧", "判良性高危有事实", "判良性低危新")
	expect("DecoyOnly", query(DecoyOnly()), "判良性仅诱饵", "未研判仅诱饵", "已结案含诱饵")

	// 自动结案与人工复核互斥：任何事件都不能同时属于两边
	for _, n := range query(StaleBenign(now.Add(time.Hour))) {
		if slices.Contains(query(Needed()), n) {
			t.Errorf("%s 同时需要复核又可自动结案", n)
		}
	}
}
