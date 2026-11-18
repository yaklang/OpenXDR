//go:build integration

package closurereview

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/fpstats"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/suppressclose"
)

const staleRuleID = "11111111-2222-4333-8444-555555555555"

func ruleSet(t *testing.T, contains string) []*sigma.Rule {
	t.Helper()
	dir := t.TempDir()
	rule := `title: Test
id: ` + staleRuleID + `
status: test
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: ` + contains + `
  condition: selection
level: medium
`
	if err := os.WriteFile(filepath.Join(dir, "rule.yml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	return sigma.LoadDir(dir).Rules()
}

// 规则修订后不再命中的旧告警是噪声：事件告警全是噪声、研判良性就按抑制口径直接结案，不调模型；
// 规则仍命中的照常交审计员
func TestStaleRuleAlertsAreNoise(t *testing.T) {
	t.Run("规则已不再命中", func(t *testing.T) {
		f := setupBenign(t)
		f.db.Alert.UpdateOneID(f.al.ID).SetRuleID(staleRuleID).ExecX(f.ctx)
		rules := ruleSet(t, "evil-marker")
		f.r.Rules = func() []*sigma.Rule { return rules }
		if ok, err := f.r.Review(f.ctx, f.inc.ID); !ok || err != nil || f.calls != 0 {
			t.Fatal(ok, err, f.calls)
		}
		inc := f.db.Incident.GetX(f.ctx, f.inc.ID)
		if inc.Status != "false_positive" || inc.ResolutionSource == nil || *inc.ResolutionSource != suppressclose.Source || !strings.Contains(*inc.Resolution, "规则已修订") {
			t.Fatalf("应按抑制口径结案并写明原因：%+v", inc)
		}
		if !f.db.AuditLog.Query().Where(auditlog.ActionEQ("incident_status"), auditlog.TargetEQ(inc.ID.String())).ExistX(f.ctx) {
			t.Fatal("结案要落审计")
		}
	})
	t.Run("规则仍命中", func(t *testing.T) {
		f := setupBenign(t)
		f.db.Alert.UpdateOneID(f.al.ID).SetRuleID(staleRuleID).ExecX(f.ctx)
		rules := ruleSet(t, "apt-get")
		f.r.Rules = func() []*sigma.Rule { return rules }
		if ok, err := f.r.Review(f.ctx, f.inc.ID); !ok || err != nil || f.calls != 1 {
			t.Fatal("仍命中的告警应照常交审计员", ok, err, f.calls)
		}
		if src := f.db.Incident.GetX(f.ctx, f.inc.ID).ResolutionSource; src == nil || *src != "ai_review" {
			t.Fatal("应由审计员结案")
		}
	})
}

// 被生效抑制覆盖的告警不计入条数：原本超过上限的事件剔掉噪声后照常送审，材料里列明剔掉了什么
func TestSuppressedAlertsExcludedFromReview(t *testing.T) {
	f := setupBenign(t)
	for range maxBenignAlerts + 5 {
		ev := f.db.Event.Create().SetTs(f.ev.Ts).SetAssetID(f.asset.ID).SetSource("agent").SetClassUID(1007).
			SetRaw([]byte(`{"activity_id":1,"process":{"cmd_line":"/usr/sbin/update-grub noise","pid":7}}`)).SaveX(f.ctx)
		f.db.Alert.Create().SetTs(f.al.Ts).SetAssetID(f.asset.ID).SetEventID(ev.ID).SetIncidentID(f.inc.ID).SetSeverity(2).SetRuleID("noise-rule").ExecX(f.ctx)
	}
	f.db.Suppression.Create().SetRuleID("noise-rule").SetAssetID(f.asset.ID).SetStatus("active").SetCreatedBy(fpstats.CreatedByAI).
		SetConditions([]suppress.Condition{{Field: "process.cmd_line", Op: "contains", Value: "update-grub"}}).SaveX(f.ctx)
	store := suppress.New(f.db, time.Minute)
	store.Reload(f.ctx)
	f.r.Suppress = store
	var seen string
	judge := f.r.Judge
	f.r.Judge = func(ctx context.Context, model, material string) (Decision, error) {
		seen = material
		return judge(ctx, model, material)
	}
	if ok, err := f.r.Review(f.ctx, f.inc.ID); !ok || err != nil || f.calls != 1 {
		t.Fatal("剔掉噪声后应照常送审并结案", ok, err, f.calls)
	}
	if strings.Count(seen, `"rule_id":"noise-rule"`) != maxBenignAlerts+5 || !strings.Contains(seen, "已被生效的抑制或内置良性链覆盖") {
		t.Fatal("材料应列明剔掉的噪声告警")
	}
}
