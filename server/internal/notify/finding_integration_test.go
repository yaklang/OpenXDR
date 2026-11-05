//go:build integration

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/testdb"
)

type findingNoticeFixture struct {
	ctx context.Context
	db  *ent.Client
	now time.Time
	f   *ent.Finding
	w   findings.Work
	cmd *ent.Command
}

func newFindingNotice(t *testing.T) findingNoticeFixture {
	t.Helper()
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	group := db.Group.Create().SetName("notice-" + uuid.NewString()).SaveX(ctx)
	a := db.Asset.Create().SetHostname("risk-host").SetGroupID(group.ID).SaveX(ctx)
	observed := now.Add(-time.Minute)
	since := observed.Add(-11 * time.Minute)
	evidence := now.Add(-30 * time.Second)
	cmd := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetStatus("succeeded").SetCmd("df -P /").SetCreatedAt(now.Add(-2 * time.Minute)).SetCompletedAt(observed).SetExitCode(0).SetStdout("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1000 960 40 96% /\n").SaveX(ctx)
	w := findings.Work{Version: 2, Stage: "blocked", Blocker: "policy_required", Plan: "保持自治复查", RepairAttempts: 1, EvidenceCommands: []uuid.UUID{cmd.ID}, EvidenceAt: &evidence, RiskSince: &since, RiskObservedAt: &observed, RiskKind: "disk_pressure", RiskTarget: &findings.RiskTarget{Kind: "disk_root", Mount: "/", AssetID: a.ID}, EscalatedAt: &observed}
	f := db.Finding.Create().SetAssetID(a.ID).SetGroupID(group.ID).SetKey("risk").SetTitle("模型标题不决定是否通知").SetSeverity("low").SetWorkOwner("ai").SetWork(findings.EncodeWork(w)).SaveX(ctx)
	return findingNoticeFixture{ctx, db, now, f, w, cmd}
}

func (f findingNoticeFixture) work(t *testing.T) findings.Work {
	t.Helper()
	var w findings.Work
	if err := json.Unmarshal(f.db.Finding.GetX(f.ctx, f.f.ID).Work, &w); err != nil {
		t.Fatal(err)
	}
	return w
}
func (f findingNoticeFixture) notifier(url string) *Notifier {
	return &Notifier{DB: f.db, Settings: &Settings{DB: f.db, Default: Target{URL: url, Format: "generic", LinkBase: "https://console.invalid"}}, Client: &http.Client{Timeout: time.Second}, start: f.now.Add(-time.Hour)}
}

func TestFindingNoticeOffAndOrdinaryPolicyRequired(t *testing.T) {
	f := newFindingNotice(t)
	var sent atomic.Int64
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent.Add(1) }))
	defer hook.Close()
	n := f.notifier("")
	if err := n.sweepFindings(f.ctx); err != nil {
		t.Fatal(err)
	}
	if sent.Load() != 0 || f.work(t).EscalationNotifiedAt != nil {
		t.Fatal("关闭目标不能算成功通知")
	}
	n = f.notifier(hook.URL)
	work := f.w
	work.RiskKind = ""
	work.EscalatedAt = nil
	f.db.Finding.UpdateOneID(f.f.ID).SetSeverity("high").SetWork(findings.EncodeWork(work)).ExecX(f.ctx)
	if err := n.sweepFindings(f.ctx); err != nil {
		t.Fatal(err)
	}
	if sent.Load() != 0 || f.work(t).EscalationNotifiedAt != nil {
		t.Fatal("模型high/普通policy_required不能升级通知")
	}
}

func TestFindingNoticeRetriesAndDoesNotRepeat(t *testing.T) {
	f := newFindingNotice(t)
	var sent atomic.Int64
	var fail atomic.Bool
	fail.Store(true)
	captured := make(chan Text, 3)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
		var body Text
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		captured <- body
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer hook.Close()
	n := f.notifier(hook.URL)
	if err := n.sweepFindings(f.ctx); err == nil {
		t.Fatal("失败须返回错误并等待重试")
	}
	if f.work(t).EscalationNotifiedAt != nil {
		t.Fatal("失败回执被写成已通知")
	}
	fail.Store(false)
	if err := n.sweepFindings(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := n.sweepFindings(f.ctx); err != nil {
		t.Fatal(err)
	}
	work := f.work(t)
	if sent.Load() != 2 || work.EscalationNotifiedAt == nil || work.RepairAttempts != 1 || f.db.Finding.GetX(f.ctx, f.f.ID).WorkOwner != "ai" {
		t.Fatal("重试/重复抑制或AI持续归属错误", sent.Load(), work)
	}
	body := <-captured
	if !strings.Contains(body.Title, "紧急") || !strings.Contains(body.Body, f.cmd.ID.String()) || !strings.Contains(body.Body, "继续自治跟进") || !strings.Contains(body.Body, "risk-host") {
		t.Fatal("通知缺少真实证据引用与跟进状态", body)
	}
}

func TestFindingNoticeDoesNotBackfillOrStarveNewEscalation(t *testing.T) {
	f := newFindingNotice(t)
	var sent atomic.Int64
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent.Add(1) }))
	defer hook.Close()
	n := f.notifier(hook.URL)
	n.start = f.now.Add(-2 * time.Minute)
	historic := f.w
	old := f.now.Add(-3 * time.Minute)
	historic.EscalatedAt = &old
	for i := range 25 {
		f.db.Finding.Create().SetAssetID(f.f.AssetID).SetGroupID(f.f.GroupID).SetKey(fmt.Sprintf("historical-%d", i)).SetTitle("旧升级").SetLastSeen(f.now.Add(-time.Hour)).SetWork(findings.EncodeWork(historic)).ExecX(f.ctx)
	}
	stale := f.w
	oldObserved := f.now.Add(-11 * time.Minute)
	stale.RiskObservedAt = &oldObserved
	for i := range 25 {
		f.db.Finding.Create().SetAssetID(f.f.AssetID).SetGroupID(f.f.GroupID).SetKey(fmt.Sprintf("stale-%d", i)).SetTitle("过期风险观测").SetLastSeen(f.now.Add(-time.Hour)).SetWork(findings.EncodeWork(stale)).ExecX(f.ctx)
	}

	if err := n.sweepFindings(f.ctx); err != nil {
		t.Fatal(err)
	}
	if sent.Load() != 1 {
		t.Fatal("旧历史不应补发或堵住新风险", sent.Load())
	}
	for _, row := range f.db.Finding.Query().AllX(f.ctx) {
		if row.ID != f.f.ID {
			var work findings.Work
			_ = json.Unmarshal(row.Work, &work)
			if work.EscalationNotifiedAt != nil {
				t.Fatal("旧历史伪记通知成功")
			}
		}
	}
}

func TestFindingNoticeRejectsStaleInvalidAndMovedEvidence(t *testing.T) {
	for _, bad := range []string{"stale_probe", "stale_evidence", "short_duration", "wrong_target", "wrong_mount", "unknown_command", "truncated_command", "missing_command", "wrong_probe", "changed_group", "future_probe", "version1", "mismatched_observation", "empty_output"} {
		t.Run(bad, func(t *testing.T) {
			f := newFindingNotice(t)
			work := f.w
			var sent atomic.Int64
			hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent.Add(1) }))
			defer hook.Close()
			switch bad {
			case "stale_probe":
				old := f.now.Add(-11 * time.Minute)
				work.RiskObservedAt = &old
				work.EscalatedAt = &old
			case "stale_evidence":
				old := f.now.Add(-11 * time.Minute)
				work.EvidenceAt = &old
			case "short_duration":
				short := work.RiskObservedAt.Add(-9 * time.Minute)
				work.RiskSince = &short
			case "wrong_target":
				target := *work.RiskTarget
				target.AssetID = uuid.New()
				work.RiskTarget = &target
			case "wrong_mount":
				target := *work.RiskTarget
				target.Mount = "/data"
				work.RiskTarget = &target
			case "unknown_command":
				f.db.Command.UpdateOneID(f.cmd.ID).SetStatus("unknown").ExecX(f.ctx)
			case "truncated_command":
				f.db.Command.UpdateOneID(f.cmd.ID).SetTruncated(true).ExecX(f.ctx)
			case "missing_command":
				work.EvidenceCommands = []uuid.UUID{uuid.New()}
			case "wrong_probe":
				f.db.Command.UpdateOneID(f.cmd.ID).SetCmd("df -P /data").ExecX(f.ctx)
			case "changed_group":
				other := f.db.Group.Create().SetName("other").SaveX(f.ctx)
				f.db.Asset.UpdateOneID(f.f.AssetID).SetGroupID(other.ID).ExecX(f.ctx)
			case "future_probe":
				future := f.now.Add(time.Minute)
				work.RiskObservedAt = &future
				work.EscalatedAt = &future
				work.EvidenceAt = &future
			case "version1":
				work.Version = 1
			case "mismatched_observation":
				earlier := work.RiskObservedAt.Add(-time.Microsecond)
				work.RiskObservedAt = &earlier
				work.EscalatedAt = &earlier
			case "empty_output":
				f.db.Command.UpdateOneID(f.cmd.ID).SetStdout("").ExecX(f.ctx)
			}
			f.db.Finding.UpdateOneID(f.f.ID).SetWork(findings.EncodeWork(work)).ExecX(f.ctx)
			if err := f.notifier(hook.URL).sweepFindings(f.ctx); err != nil {
				t.Fatal(err)
			}
			if sent.Load() != 0 || f.work(t).EscalationNotifiedAt != nil {
				t.Fatal("不满足新鲜真实风险证据却通知", bad)
			}
		})
	}
}

func TestFindingNoticeDoesNotOverwriteConcurrentPlanOrHumanTerminal(t *testing.T) {
	for _, change := range []string{"plan", "resolved", "group"} {
		t.Run(change, func(t *testing.T) {
			f := newFindingNotice(t)
			var sent atomic.Int64
			hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sent.Add(1)
				switch change {
				case "plan":
					work := f.work(t)
					work.RepairAttempts++
					work.Plan = "并发修复已预留"
					f.db.Finding.UpdateOneID(f.f.ID).SetWork(findings.EncodeWork(work)).ExecX(f.ctx)
				case "resolved":
					f.db.Finding.UpdateOneID(f.f.ID).SetStatus("resolved").SetResolvedBy("analyst").ExecX(f.ctx)
				case "group":
					other := f.db.Group.Create().SetName("moved").SaveX(f.ctx)
					f.db.Asset.UpdateOneID(f.f.AssetID).SetGroupID(other.ID).ExecX(f.ctx)
				}
			}))
			defer hook.Close()
			if err := f.notifier(hook.URL).sweepFindings(f.ctx); err != nil {
				t.Fatal(err)
			}
			work := f.work(t)
			if sent.Load() != 1 || work.EscalationNotifiedAt != nil {
				t.Fatal("旧发送快照不得给并发状态落成功标记")
			}
			if change == "plan" && (work.RepairAttempts != 2 || work.Plan != "并发修复已预留") {
				t.Fatal("覆盖了新计划或修复次数")
			}
			if change == "resolved" && f.db.Finding.GetX(f.ctx, f.f.ID).Status != "resolved" {
				t.Fatal("覆盖了人工终态")
			}
		})
	}
}

func TestFindingNoticeWaitsForNewerExactProbe(t *testing.T) {
	for _, status := range []string{"succeeded", "failed", "unknown", "pending", "sent"} {
		t.Run(status, func(t *testing.T) {
			f := newFindingNotice(t)
			var sent atomic.Int64
			hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent.Add(1) }))
			defer hook.Close()
			newer := f.db.Command.Create().SetAssetID(f.f.AssetID).SetKind("exec").SetCmd("df -P /").SetStatus(status).SetCreatedAt(f.now.Add(-40 * time.Second))
			if status == "succeeded" {
				newer.SetCompletedAt(f.now.Add(-30 * time.Second)).SetExitCode(0).SetStdout("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1000 500 500 50% /\n")
			}
			if status == "failed" {
				newer.SetCompletedAt(f.now.Add(-30 * time.Second)).SetExitCode(1)
			}
			newer.ExecX(f.ctx)
			if err := f.notifier(hook.URL).sweepFindings(f.ctx); err != nil {
				t.Fatal(err)
			}
			if sent.Load() != 0 || f.work(t).EscalationNotifiedAt != nil {
				t.Fatal("选择性引用旧critical忽略更新探针", status)
			}
		})
	}
}

func TestFindingNoticeHonorsSeverityGateAndExactProbe(t *testing.T) {
	f := newFindingNotice(t)
	var sent atomic.Int64
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent.Add(1) }))
	defer hook.Close()
	f.db.Command.Create().SetAssetID(f.f.AssetID).SetKind("exec").SetCmd("df -P /data").SetStatus("unknown").SetCreatedAt(f.now.Add(-30 * time.Second)).ExecX(f.ctx)
	n := f.notifier(hook.URL)
	n.Settings.Default.MinSeverity = 6
	if err := n.sweepFindings(f.ctx); err != nil {
		t.Fatal(err)
	}
	if sent.Load() != 0 || f.work(t).EscalationNotifiedAt != nil {
		t.Fatal("门槛外不应推送或记成功")
	}
	n.Settings.Default.MinSeverity = 5
	if err := n.sweepFindings(f.ctx); err != nil {
		t.Fatal(err)
	}
	if sent.Load() != 1 {
		t.Fatal("不同挂载探针不应覆盖根磁盘风险")
	}
}

func TestFindingNoticeMemoryPressureContinuesAIOwnership(t *testing.T) {
	f := newFindingNotice(t)
	var sent atomic.Int64
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent.Add(1) }))
	defer hook.Close()
	work := f.w
	work.RiskKind = "memory_pressure"
	work.RiskTarget = &findings.RiskTarget{Kind: "memory", AssetID: f.f.AssetID}
	f.db.Command.UpdateOneID(f.cmd.ID).SetCmd("free -b").SetStdout("total used free shared buff/cache available\nMem: 16000000000 15000000000 500000000 0 500000000 1000000000\nSwap: 16000000000 15500000000 500000000\n").ExecX(f.ctx)
	f.db.Finding.UpdateOneID(f.f.ID).SetWork(findings.EncodeWork(work)).ExecX(f.ctx)
	if err := f.notifier(hook.URL).sweepFindings(f.ctx); err != nil {
		t.Fatal(err)
	}
	got := f.db.Finding.GetX(f.ctx, f.f.ID)
	if sent.Load() != 1 || got.WorkOwner != "ai" || got.Status != "open" || f.work(t).EscalationNotifiedAt == nil {
		t.Fatal("资源紧急通知不能停止AI跟进或假结案")
	}
}

func TestFindingNoticePersistedActivationSurvivesHATakeover(t *testing.T) {
	f := newFindingNotice(t)
	var sent atomic.Int64
	var fail atomic.Bool
	fail.Store(true)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer hook.Close()
	first := f.notifier(hook.URL)
	if err := first.Settings.Save(f.ctx, Target{URL: hook.URL, Format: "generic"}); err != nil {
		t.Fatal(err)
	}
	activation := f.now.Add(-time.Hour)
	f.db.Setting.UpdateOneID(settingKey).SetUpdatedAt(activation).ExecX(f.ctx)
	// 新leader的进程起点晚于尚未发送的升级，但同一渠道已在此前持续启用。
	first.start = f.now
	if err := first.sweepFindings(f.ctx); err == nil {
		t.Fatal("第一次渠道失败应保留待通知状态")
	}
	if sent.Load() != 1 || f.work(t).EscalationNotifiedAt != nil {
		t.Fatal("接管把合法旧升级吞掉，或失败被标成功")
	}
	fail.Store(false)
	takeover := f.notifier("http://fallback.invalid")
	takeover.start = time.Now()
	if err := takeover.sweepFindings(f.ctx); err != nil {
		t.Fatal(err)
	}
	if sent.Load() != 2 || f.work(t).EscalationNotifiedAt == nil {
		t.Fatal("新leader未重试同一持久渠道的合法升级")
	}
}

func TestFindingNoticeSavingNewChannelDoesNotBackfill(t *testing.T) {
	f := newFindingNotice(t)
	var oldSent, newSent atomic.Int64
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { oldSent.Add(1) }))
	defer old.Close()
	fresh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { newSent.Add(1) }))
	defer fresh.Close()
	n := f.notifier(old.URL)
	if err := n.Settings.Save(f.ctx, Target{URL: old.URL, Format: "generic"}); err != nil {
		t.Fatal(err)
	}
	f.db.Setting.UpdateOneID(settingKey).SetUpdatedAt(f.now.Add(-time.Hour)).ExecX(f.ctx)
	if err := n.Settings.Save(f.ctx, Target{URL: fresh.URL, Format: "generic"}); err != nil {
		t.Fatal(err)
	}
	if !f.db.Setting.GetX(f.ctx, settingKey).UpdatedAt.After(*f.w.EscalatedAt) {
		t.Fatal("测试未建立新渠道激活边界")
	}
	if err := n.sweepFindings(f.ctx); err != nil {
		t.Fatal(err)
	}
	if oldSent.Load() != 0 || newSent.Load() != 0 || f.work(t).EscalationNotifiedAt != nil {
		t.Fatal("新渠道不得补发旧升级或记成功")
	}
}

func TestFindingNoticePersistedOffOrCorruptDoesNotUseFallback(t *testing.T) {
	for _, mode := range []string{"off", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			f := newFindingNotice(t)
			var sent atomic.Int64
			hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent.Add(1) }))
			defer hook.Close()
			n := f.notifier(hook.URL)
			if err := n.Settings.Save(f.ctx, Target{}); err != nil {
				t.Fatal(err)
			}
			if mode == "corrupt" {
				f.db.Setting.UpdateOneID(settingKey).SetValue(json.RawMessage(`[]`)).ExecX(f.ctx)
			}
			err := n.sweepFindings(f.ctx)
			if mode == "corrupt" && err == nil {
				t.Fatal("持久配置损坏应返回错误并拒绝发送")
			}
			if mode == "off" && err != nil {
				t.Fatal(err)
			}
			if sent.Load() != 0 || f.work(t).EscalationNotifiedAt != nil {
				t.Fatal("持久off/坏配置不能回退到环境目标或伪记成功")
			}
		})
	}
}

func TestFindingNoticeConfigurationReadFailureDoesNotUseFallback(t *testing.T) {
	f := newFindingNotice(t)
	var sent atomic.Int64
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent.Add(1) }))
	defer hook.Close()
	n := f.notifier(hook.URL)
	unavailable := errors.New("settings unavailable")
	f.db.Setting.Intercept(ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, q ent.Query) (ent.Value, error) { return nil, unavailable })
	}))
	if err := n.sweepFindings(f.ctx); !errors.Is(err, unavailable) {
		t.Fatal("配置读取错误必须原样拒绝，不能切换环境目标", err)
	}
	if sent.Load() != 0 || f.work(t).EscalationNotifiedAt != nil {
		t.Fatal("配置读取失败却回退发出或记成功")
	}
}
