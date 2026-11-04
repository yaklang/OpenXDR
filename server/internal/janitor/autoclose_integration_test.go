//go:build integration

package janitor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/testdb"
)

// 只关 AI 判良性且放够天数的事件；未核实的可疑事件（不论级别）、恶意、新事件、结论后又有新证据待重研判的都不按误报自动关掉，N=0 关闭。
func TestAutoCloseBenign(t *testing.T) {
	ctx, client := testdb.New(t)
	old := time.Now().AddDate(0, 0, -8)
	create := func(verdict string, severity int16, at time.Time) string {
		inc := client.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).
			SetAiVerdict(json.RawMessage(`{"verdict":"` + verdict + `"}`)).SetCreatedAt(at).SaveX(ctx)
		client.Alert.Create().SetTs(at).SetRuleID("r").SetSeverity(severity).SetIncidentID(inc.ID).SaveX(ctx)
		return inc.ID.String()
	}
	lowOld := create("benign", 3, old)
	highBenignOld := create("benign", 4, old)
	suspiciousLowOld := create("suspicious", 2, old)
	suspiciousHighOld := create("suspicious", 4, old)
	maliciousOld := create("malicious", 2, old)
	lowNew := create("benign", 1, time.Now())
	pending := create("benign", 2, old)
	client.Incident.UpdateOneID(uuid.MustParse(pending)).SetTriagedAt(old).SetEvidenceAt(time.Now()).ExecX(ctx)

	if n, err := (&AutoClose{DB: client, Days: 0}).sweep(ctx); err != nil || n != 0 {
		t.Fatalf("N=0 应关闭自动结案，得到 %d %v", n, err)
	}
	a := &AutoClose{DB: client, Days: 7}
	if n, err := a.sweep(ctx); err != nil || n != 2 {
		t.Fatalf("应关 2 个（良性低危、良性高危），得到 %d %v", n, err)
	}
	// 重复执行（如两个节点先后跑）不再动已结案的
	if n, err := a.sweep(ctx); err != nil || n != 0 {
		t.Fatalf("重复执行应为空操作，得到 %d %v", n, err)
	}
	for _, inc := range client.Incident.Query().AllX(ctx) {
		switch inc.ID.String() {
		case lowOld, highBenignOld:
			if inc.Status != "false_positive" || inc.ResolvedBy == nil || *inc.ResolvedBy != "system" || inc.ResolvedAt == nil ||
				inc.Resolution == nil || *inc.Resolution != "AI 判良性、7 天无人处理，系统自动结案" {
				t.Errorf("良性旧事件应自动结案且说明准确：%+v", inc)
			}
		case suspiciousLowOld, suspiciousHighOld, maliciousOld, lowNew, pending:
			if inc.Status != "triaged" || inc.ResolvedBy != nil {
				t.Errorf("%s 不该被结案：%+v", inc.ID, inc)
			}
		}
	}
	row := client.AuditLog.Query().Where(auditlog.ActionEQ("incident_auto_closed")).OnlyX(ctx)
	if row.Detail == nil || !strings.Contains(*row.Detail, "AI 判良性事件") || strings.Contains(*row.Detail, "低危良性") {
		t.Errorf("审计明细应如实描述 AI 判良性事件，得到 %v", row.Detail)
	}
}
