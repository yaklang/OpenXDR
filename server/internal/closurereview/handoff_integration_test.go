//go:build integration

package closurereview

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/question"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/review"
)

// aiOwned 按研判落库时的口径生成工作计划：良性低危事件归 AI 静默跟进
func aiOwned(t *testing.T, f *fixture) {
	t.Helper()
	inc := f.db.Incident.GetX(f.ctx, f.inc.ID)
	if err := incidentwork.Refresh(f.ctx, f.db, inc, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.inc = f.db.Incident.GetX(f.ctx, f.inc.ID)
	if w := f.inc.Work; w == nil || w.Owner != "ai" || w.Stage != "monitoring" {
		t.Fatalf("前提：事件应归 AI 静默跟进，实际 %+v", w)
	}
}

func handedOff(t *testing.T, f *fixture, want string) {
	t.Helper()
	inc := f.db.Incident.GetX(f.ctx, f.inc.ID)
	if inc.Status != "triaged" || inc.Work == nil || inc.Work.Owner != "human" || inc.Work.Stage != "escalated" ||
		!strings.HasPrefix(inc.Work.Reason, review.HandoffPrefix) || !strings.Contains(inc.Work.Reason, want) {
		t.Fatalf("应转人工并写明「%s」，实际 status=%s work=%+v", want, inc.Status, inc.Work)
	}
	if !f.db.Incident.Query().Where(incident.IDEQ(inc.ID), review.Needed(), review.HandedOff()).ExistX(f.ctx) {
		t.Fatal("转人工的事件必须进待复核与每日汇总口径")
	}
	if !f.db.AuditLog.Query().Where(auditlog.ActionEQ("incident_closure_handoff"), auditlog.TargetEQ(inc.ID.String())).ExistX(f.ctx) {
		t.Fatal("转人工要落审计")
	}
}

func verdict(f *fixture, v string) {
	f.db.Incident.UpdateOneID(f.inc.ID).SetAiVerdict(json.RawMessage(v)).ExecX(f.ctx)
}

// 结案审计确定结不掉的事件不能静默挂着：带原因转人工
func TestStalledIncidentsHandOffToHuman(t *testing.T) {
	cases := map[string]struct {
		edit func(*fixture)
		want string
	}{
		"告警超限": {func(f *fixture) {
			// 原文各不相同，归并不了
			distinctAlerts(f, maxBenignAlerts*maxBenignBatches)
		}, "超过分批审计上限"},
		"可疑结论": {func(f *fixture) { verdict(f, `{"verdict":"suspicious","action_codes":["monitor"]}`) }, "研判结论为可疑"},
		"后续动作无人执行": {func(f *fixture) {
			verdict(f, `{"verdict":"benign","action_codes":["review_closure","hunt_related"]}`)
		}, "hunt_related"},
		"审计员实质拒绝": {func(f *fixture) {
			f.r.Judge = func(context.Context, string, string) (Decision, error) {
				f.calls++
				return Decision{Reason: "下载后执行的形态，必须拒绝"}, nil
			}
		}, "下载后执行的形态"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := setupBenign(t)
			c.edit(f)
			aiOwned(t, f)
			if ok, err := f.r.Review(f.ctx, f.inc.ID); ok || err != nil {
				t.Fatal(ok, err)
			}
			handedOff(t, f, c.want)
			// 已交人后再扫不重复审、不重复落审计
			calls := f.calls
			if _, err := f.r.Review(f.ctx, f.inc.ID); err != nil || f.calls != calls {
				t.Fatal("交人后不应再调模型", err, f.calls)
			}
			if n := f.db.AuditLog.Query().Where(auditlog.ActionEQ("incident_closure_handoff")).CountX(f.ctx); n != 1 {
				t.Fatal("转人工只记一次", n)
			}
		})
	}
}

// 等待类原因（安静期未满、研判后出现研判没看过的新告警）不能转人工
func TestWaitingIncidentsStayWithAI(t *testing.T) {
	cases := map[string]func(*fixture){
		"安静期未满": func(f *fixture) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			f.db.Event.UpdateOneID(f.ev.ID).SetTs(now.Add(-10 * time.Minute)).ExecX(f.ctx)
			f.db.Alert.UpdateOneID(f.al.ID).SetTs(now.Add(-10 * time.Minute)).SetLastTs(now.Add(-10 * time.Minute)).ExecX(f.ctx)
			f.db.Incident.UpdateOneID(f.inc.ID).SetTriagedAt(now.Add(-time.Minute)).ExecX(f.ctx)
		},
		"研判后的新规则告警": func(f *fixture) {
			ts := f.inc.TriagedAt.Add(time.Minute)
			ev := f.db.Event.Create().SetTs(ts).SetAssetID(f.asset.ID).SetSource("agent").SetClassUID(1007).SetRaw(f.ev.Raw).SaveX(f.ctx)
			f.db.Alert.Create().SetTs(ts).SetAssetID(f.asset.ID).SetEventID(ev.ID).SetIncidentID(f.inc.ID).SetSeverity(3).SetRuleID("other-rule").ExecX(f.ctx)
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := setupBenign(t)
			edit(f)
			aiOwned(t, f)
			if ok, err := f.r.Review(f.ctx, f.inc.ID); ok || err != nil || f.calls != 0 {
				t.Fatal(ok, err, f.calls)
			}
			if w := f.db.Incident.GetX(f.ctx, f.inc.ID).Work; w.Owner != "ai" || w.Stage != "monitoring" {
				t.Fatalf("等待中的事件不应转人工：%+v", w)
			}
		})
	}
}

// 服务端驳回批准后，同一快照带着驳回原因重审一次，纠正后照常结案
func TestRetryAfterServerOverruleCloses(t *testing.T) {
	f := setupBenign(t)
	aiOwned(t, f)
	var second string
	f.r.Judge = func(_ context.Context, _ string, material string) (Decision, error) {
		f.calls++
		d := benignApproval(f.ev.ID, benignCmd)
		if f.calls == 1 {
			d.Claims = []Claim{{EventID: f.ev.ID, Field: "process.cmd_line", Value: "/usr/bin/apt-get upgrade"}}
		} else {
			second = material
		}
		return d, nil
	}
	if ok, err := f.r.Review(f.ctx, f.inc.ID); ok || err != nil {
		t.Fatal("第一次引用对不上应被驳回", ok, err)
	}
	if w := f.db.Incident.GetX(f.ctx, f.inc.ID).Work; w.Owner != "ai" {
		t.Fatal("可纠正的驳回不应立刻转人工")
	}
	if ok, err := f.r.Review(f.ctx, f.inc.ID); !ok || err != nil || f.calls != 2 {
		t.Fatal("重审纠正后应结案", ok, err, f.calls)
	}
	if !strings.Contains(second, `"server_feedback"`) || !strings.Contains(second, "原值不符") {
		t.Fatal("重审材料要带上驳回原因")
	}
}

// 核心资产上的低危例行告警照常交审计员结案
func TestCoreAssetLowSeverityCloses(t *testing.T) {
	f := setupBenign(t)
	f.db.Asset.UpdateOneID(f.asset.ID).SetResponseTier("core").ExecX(f.ctx)
	if ok, err := f.r.Review(f.ctx, f.inc.ID); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if f.db.Incident.GetX(f.ctx, f.inc.ID).Status != "false_positive" {
		t.Fatal("核心资产上的低危良性事件应可结案")
	}
}

// 几十 KB 的命令行保留首尾交审计员，引用其他完整字段即可结案
func TestOversizeEventTruncatedThenCloses(t *testing.T) {
	f := setupBenign(t)
	long := "cc -m64 " + strings.Repeat("/opt/runner/_work/app/target/debug/deps/lib-0123456789abcdef.rlib ", 500)
	raw, _ := json.Marshal(map[string]any{"activity_id": 1, "process": map[string]any{"cmd_line": long, "pid": 42, "file": map[string]any{"path": "/usr/bin/cc"}}})
	f.db.Event.UpdateOneID(f.ev.ID).SetRaw(raw).ExecX(f.ctx)
	var seen string
	f.r.Judge = func(_ context.Context, _ string, material string) (Decision, error) {
		f.calls++
		seen = material
		d := benignApproval(f.ev.ID, "")
		d.Claims = []Claim{{EventID: f.ev.ID, Field: "raw.process.file.path", Value: "/usr/bin/cc"}}
		return d, nil
	}
	if ok, err := f.r.Review(f.ctx, f.inc.ID); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if !strings.Contains(seen, truncMark) || strings.Contains(seen, long) {
		t.Fatal("交审计员的材料应是截断后的原文")
	}
}

// 高危告警所在主机没有业务事实：转人工，并向总控问这台主机的业务
func TestSevereHostWithoutFactsAsksQuestion(t *testing.T) {
	f := setupBenign(t)
	f.db.Alert.UpdateOneID(f.al.ID).SetSeverity(4).ExecX(f.ctx)
	aiOwned(t, f)
	if ok, err := f.r.Review(f.ctx, f.inc.ID); ok || err != nil || f.calls != 0 {
		t.Fatal(ok, err, f.calls)
	}
	handedOff(t, f, "没有写明业务的资产角色或授权事实")
	if !f.db.Question.Query().Where(question.SubjectKindEQ("asset"), question.SubjectEQ(f.asset.ID.String()), question.StatusEQ("open")).ExistX(f.ctx) {
		t.Fatal("应向总控提问这台主机的业务")
	}
}

// 早先转人工的事件每轮照样重审：结不掉的原因变了就改写，原因不变不重复写；人工接管的不动
func TestHandoffReasonRefreshes(t *testing.T) {
	f := setupBenign(t)
	verdict(f, `{"verdict":"benign","action_codes":["review_closure","hunt_related"]}`)
	aiOwned(t, f)
	if _, err := f.r.Review(f.ctx, f.inc.ID); err != nil {
		t.Fatal(err)
	}
	handedOff(t, f, "hunt_related")
	verdict(f, `{"verdict":"suspicious","action_codes":["monitor"]}`)
	for range 2 {
		if _, err := f.r.Review(f.ctx, f.inc.ID); err != nil {
			t.Fatal(err)
		}
	}
	handedOff(t, f, "研判结论为可疑")
	if n := f.db.AuditLog.Query().Where(auditlog.ActionEQ("incident_closure_handoff")).CountX(f.ctx); n != 2 {
		t.Fatal("原因变一次记一次", n)
	}
	w := *f.db.Incident.GetX(f.ctx, f.inc.ID).Work
	w.ManualOwner = "analyst"
	f.db.Incident.UpdateOneID(f.inc.ID).SetWork(&w).ExecX(f.ctx)
	verdict(f, `{"verdict":"benign","action_codes":["review_closure","hunt_related"]}`)
	if _, err := f.r.Review(f.ctx, f.inc.ID); err != nil {
		t.Fatal(err)
	}
	if r := f.db.Incident.GetX(f.ctx, f.inc.ID).Work.Reason; !strings.Contains(r, "研判结论为可疑") {
		t.Fatal("人工接管的事件不改写", r)
	}
}

// distinctAlerts 补 n 条原文各不相同的低危告警，时间与夹具一致（已安静、研判前）
func distinctAlerts(f *fixture, n int) {
	evs := make([]*ent.EventCreate, n)
	for i := range n {
		raw, _ := json.Marshal(map[string]any{"activity_id": 1, "process": map[string]any{"cmd_line": benignCmd + " " + strconv.Itoa(i)}})
		evs[i] = f.db.Event.Create().SetTs(f.inc.CreatedAt).SetAssetID(f.asset.ID).SetSource("agent").SetClassUID(1007).SetRaw(raw)
	}
	saved := f.db.Event.CreateBulk(evs...).SaveX(f.ctx)
	als := make([]*ent.AlertCreate, n)
	for i, ev := range saved {
		als[i] = f.db.Alert.Create().SetTs(f.inc.CreatedAt).SetAssetID(f.asset.ID).SetEventID(ev.ID).SetIncidentID(f.inc.ID).SetSeverity(3).SetRuleID(f.al.RuleID)
	}
	f.db.Alert.CreateBulk(als...).ExecX(f.ctx)
}

// batchJudge 按材料里的事件逐条引用 cmd_line 批准；reject 指定的批次拒绝
func batchJudge(f *fixture, reject string, seen *[]string) {
	f.r.Judge = func(_ context.Context, _, raw string) (Decision, error) {
		f.calls++
		var m material
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return Decision{}, err
		}
		*seen = append(*seen, m.Batch)
		if m.Batch == reject {
			return Decision{Reason: "这一批里有下载后执行的形态"}, nil
		}
		d := Decision{Approve: true, Reason: "批 " + m.Batch + " 都是包管理器刷新软件源", PositiveEvidence: "process.cmd_line 均为 apt-get update 的正常软件源更新"}
		for _, ev := range m.Events {
			var r struct {
				Process struct {
					Cmd string `json:"cmd_line"`
				} `json:"process"`
			}
			_ = json.Unmarshal(ev.Raw, &r)
			d.EventIDs = append(d.EventIDs, ev.ID)
			d.Claims = append(d.Claims, Claim{EventID: ev.ID, Field: "process.cmd_line", Value: r.Process.Cmd})
		}
		return d, nil
	}
}

// 组数超过单次上限按组分批：每批单独送审，全部批准才结案
func TestBenignBatchedReview(t *testing.T) {
	f := setupBenign(t)
	distinctAlerts(f, maxBenignAlerts*2)
	var seen []string
	batchJudge(f, "", &seen)
	if ok, err := f.r.Review(f.ctx, f.inc.ID); !ok || err != nil {
		t.Fatal(ok, err, seen)
	}
	if strings.Join(seen, ",") != "1/3,2/3,3/3" {
		t.Fatal("41 组应分三批依次送审", seen)
	}
	inc := f.db.Incident.GetX(f.ctx, f.inc.ID)
	if inc.Status != "false_positive" || inc.Resolution == nil || !strings.Contains(*inc.Resolution, "分 3 批审计全部批准") {
		t.Fatalf("%+v", inc.Resolution)
	}
}

// 任一批不批就停，整件转人工并写明哪一批、为什么
func TestBenignBatchRejectHandsOff(t *testing.T) {
	f := setupBenign(t)
	distinctAlerts(f, maxBenignAlerts*2)
	aiOwned(t, f)
	var seen []string
	batchJudge(f, "2/3", &seen)
	if ok, err := f.r.Review(f.ctx, f.inc.ID); ok || err != nil {
		t.Fatal(ok, err)
	}
	if strings.Join(seen, ",") != "1/3,2/3" {
		t.Fatal("第二批不过就不再审第三批", seen)
	}
	handedOff(t, f, "第 2/3 批：这一批里有下载后执行的形态")
}
