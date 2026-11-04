//go:build integration

package schedule

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
	"openxdr/server/ent/taskrun"
	"openxdr/server/internal/testdb"
)

type fakeRunner struct {
	mu    sync.Mutex
	db    *ent.Client
	jobs  []Job
	fail  string // 该组的会话总是失败，其余组交一份报告
	flaky string // 该组只有第一次失败
	tried bool
}

func (f *fakeRunner) RunTask(_ context.Context, job Job) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs = append(f.jobs, job)
	if job.Session.GroupID.String() == f.fail {
		return errors.New("输出被截断")
	}
	if job.Session.GroupID.String() == f.flaky && !f.tried {
		f.tried = true
		return errors.New("会话结束但没有提交报告")
	}
	return f.db.Report.Create().SetSessionID(job.Session.ID).SetGroupID(job.Session.GroupID).
		SetTitle("日报").SetMarkdown("# 发现紧急风险").SetLevel("urgent").Exec(context.Background())
}

func TestSchedulerTick(t *testing.T) {
	ctx, client := testdb.New(t)
	withSpread(t, 0)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	client.Group.Create().SetName("empty").SaveX(ctx)
	client.Asset.Create().SetHostname("a1").SetGroupID(gA.ID).SaveX(ctx)
	client.Asset.Create().SetHostname("b1").SetGroupID(gB.ID).SaveX(ctx)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "t.yml"), []byte(
		"id: t\nname: 巡检\nschedule: '*/5 * * * *'\napproval_timeout: 2m\nprompt: 看看\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{db: client, fail: gB.ID.String()}
	var mu sync.Mutex
	notes := map[string]string{}
	s := &Scheduler{
		DB: client, Runner: runner, Dir: dir, DefaultModel: func() string { return "m" }, Timeout: time.Minute, MaxRunning: 10,
		Notify: func(_ context.Context, title, text, path string) error {
			mu.Lock()
			defer mu.Unlock()
			notes[title] = text + "\n" + path
			return nil
		},
		start: time.Now().Add(-10 * time.Minute),
	}

	if err := Sync(ctx, client, LoadDir(dir)); err != nil {
		t.Fatal(err)
	}
	client.Task.UpdateOneID("t").SetCreatedAt(s.start).ExecX(ctx)
	if err := s.tick(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	// A 一次成功；B 失败后重试一次仍失败
	if len(runner.jobs) != 3 {
		t.Fatalf("应 A 跑一次、B 跑两次，得到 %d", len(runner.jobs))
	}
	for _, j := range runner.jobs {
		if j.Session.Kind != "task" || j.Session.Initiator != Initiator || j.Session.Model != "m" ||
			j.Prompt != "看看" || j.ApprovalTimeout != 2*time.Minute {
			t.Errorf("任务会话参数不符：%+v %+v", j, j.Session)
		}
	}
	runs := client.TaskRun.Query().AllX(ctx)
	status := map[string]string{}
	for _, r := range runs {
		status[r.GroupID.String()] = r.Status
	}
	if status[gA.ID.String()] != "succeeded" || status[gB.ID.String()] != "failed" {
		t.Errorf("运行终态不符：%v", status)
	}
	// A 推紧急报告（带摘要与链接），B 推失败
	if len(notes) != 2 || !strings.Contains(notes["【紧急】日报"], "发现紧急风险") ||
		!strings.Contains(notes["【紧急】日报"], "/api/agent-reports/") || notes["任务失败：巡检"] == "" {
		t.Errorf("通知不符：%v", notes)
	}

	// 刚跑过，同一时刻不会再触发
	if err := s.tick(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if len(runner.jobs) != 3 {
		t.Errorf("未到下个周期不应再跑，累计 %d", len(runner.jobs))
	}

	// 下个周期：A 上一轮仍在跑则跳过，只跑 B
	client.TaskRun.Update().Where(taskrun.GroupIDEQ(gA.ID)).SetStatus("running").ExecX(ctx)
	if err := s.tick(ctx, time.Now().Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if len(runner.jobs) != 5 || runner.jobs[3].Session.GroupID != gB.ID || runner.jobs[4].Session.GroupID != gB.ID {
		t.Errorf("A 在跑应只补 B（含一次重试），累计 %d", len(runner.jobs))
	}

	// 界面停用后不再调度；YAML 删除后标记 removed
	client.Task.UpdateOneID("t").SetEnabled(false).ExecX(ctx)
	if err := s.tick(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if len(runner.jobs) != 5 {
		t.Errorf("停用后不应再跑，累计 %d", len(runner.jobs))
	}
	if client.Task.GetX(ctx, "t").Enabled {
		t.Error("同步不应覆盖界面的启停")
	}
	_ = os.Remove(filepath.Join(dir, "t.yml"))
	if err := s.tick(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if task := client.Task.GetX(ctx, "t"); !task.Removed {
		t.Error("YAML 删除后应标记 removed")
	}
}

// 第一次失败、重试成功：同一行运行记录换成重试会话，只推报告不报失败。
func TestSchedulerRetriesOnce(t *testing.T) {
	ctx, client := testdb.New(t)
	withSpread(t, 0)
	g := client.Group.Create().SetName("A").SaveX(ctx)
	client.Asset.Create().SetHostname("a1").SetGroupID(g.ID).SaveX(ctx)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "t.yml"), []byte("id: t\nname: 巡检\nschedule: '*/5 * * * *'\nprompt: 看看\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{db: client, flaky: g.ID.String()}
	var titles []string
	s := &Scheduler{DB: client, Runner: runner, Dir: dir, DefaultModel: func() string { return "m" }, Timeout: time.Minute, MaxRunning: 10,
		Notify: func(_ context.Context, title, _, _ string) error { titles = append(titles, title); return nil }}
	if err := Sync(ctx, client, LoadDir(dir)); err != nil {
		t.Fatal(err)
	}
	client.Task.UpdateOneID("t").SetCreatedAt(time.Now().Add(-10 * time.Minute)).ExecX(ctx)
	if err := s.tick(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	runs := client.TaskRun.Query().AllX(ctx)
	if len(runner.jobs) != 2 || len(runs) != 1 || runs[0].Status != "succeeded" || runs[0].Error != nil ||
		*runs[0].SessionID != runner.jobs[1].Session.ID {
		t.Fatalf("应重试一次并以重试会话成功收场：%d 次 %+v", len(runner.jobs), runs)
	}
	if !client.AgentSession.Query().Where(agentsession.IDEQ(runner.jobs[0].Session.ID)).ExistX(ctx) {
		t.Error("失败那次的会话应保留")
	}
	if len(titles) != 1 || titles[0] != "【紧急】日报" {
		t.Errorf("重试成功只应推报告：%v", titles)
	}
}

// 立即运行：请求晚于上次运行就跑一轮，跑完不再重复。
func TestSchedulerRunRequested(t *testing.T) {
	ctx, client := testdb.New(t)
	withSpread(t, 0)
	g := client.Group.Create().SetName("A").SaveX(ctx)
	client.Asset.Create().SetHostname("a1").SetGroupID(g.ID).SaveX(ctx)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "t.yml"), []byte("id: t\nname: 巡检\nschedule: '0 2 * * *'\nprompt: 看看\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{db: client}
	s := &Scheduler{DB: client, Runner: runner, Dir: dir, DefaultModel: func() string { return "m" }, Timeout: time.Minute, MaxRunning: 10}
	if err := Sync(ctx, client, LoadDir(dir)); err != nil {
		t.Fatal(err)
	}
	tick := func() {
		if err := s.tick(ctx, time.Now()); err != nil {
			t.Fatal(err)
		}
		s.wg.Wait()
	}
	tick()
	if len(runner.jobs) != 0 {
		t.Fatal("没到点也没请求，不应运行")
	}
	client.Task.UpdateOneID("t").SetRunRequestedAt(time.Now()).ExecX(ctx)
	tick()
	tick()
	if len(runner.jobs) != 1 {
		t.Fatalf("一次请求应只跑一轮，得到 %d", len(runner.jobs))
	}
}

type blockedRunner struct {
	started chan struct{}
	release chan struct{}
}

func (r *blockedRunner) RunTask(ctx context.Context, _ Job) error {
	r.started <- struct{}{}
	select {
	case <-r.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Pi 模型没配（控制台或环境变量都空）时到期任务不运行；配上后下一轮即运行
func TestSchedulerWaitsForPiModel(t *testing.T) {
	ctx, db := testdb.New(t)
	withSpread(t, 0)
	g := db.Group.Create().SetName("a").SaveX(ctx)
	db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	task := db.Task.Create().SetID("wait").SetCreatedAt(time.Now().Add(-time.Minute)).SetName("巡检").SetSchedule("* * * * *").SetPrompt("检查").SaveX(ctx)
	runner := &blockedRunner{make(chan struct{}, 1), make(chan struct{})}
	model := ""
	s := &Scheduler{DB: db, Runner: runner, DefaultModel: func() string { return model }, Timeout: time.Minute, MaxRunning: 10}
	s.fire(ctx, []*ent.Task{task}, time.Now())
	if n := db.TaskRun.Query().CountX(ctx); n != 0 {
		t.Fatalf("没配 Pi 模型不应运行，得到 %d 次", n)
	}
	model = "m"
	s.fire(ctx, []*ent.Task{task}, time.Now())
	<-runner.started
	close(runner.release)
	s.wg.Wait()
	if n := db.TaskRun.Query().CountX(ctx); n != 1 {
		t.Fatalf("配上模型后应运行一次，得到 %d 次", n)
	}
}

// 停机打断的一轮记为 interrupted、不发失败通知；接手的调度器用新会话重跑同一轮，跑完不再补
func TestSchedulerRerunsInterrupted(t *testing.T) {
	ctx, client := testdb.New(t)
	withSpread(t, 0)
	g := client.Group.Create().SetName("A").SaveX(ctx)
	client.Asset.Create().SetHostname("a1").SetGroupID(g.ID).SaveX(ctx)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "t.yml"), []byte("id: t\nname: 巡检\nschedule: '0 2 * * *'\nprompt: 看看\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Sync(ctx, client, LoadDir(dir)); err != nil {
		t.Fatal(err)
	}
	client.Task.UpdateOneID("t").SetRunRequestedAt(time.Now()).ExecX(ctx)
	var notes []string
	notify := func(_ context.Context, title, _, _ string) error { notes = append(notes, title); return nil }

	blocked := &blockedRunner{started: make(chan struct{}, 1), release: make(chan struct{})}
	old := &Scheduler{DB: client, Runner: blocked, Dir: dir, DefaultModel: func() string { return "m" }, Timeout: time.Minute, MaxRunning: 10, Notify: notify}
	stop, cancel := context.WithCancel(ctx)
	if err := old.tick(stop, time.Now()); err != nil {
		t.Fatal(err)
	}
	<-blocked.started
	cancel()
	old.wg.Wait()
	run := client.TaskRun.Query().OnlyX(ctx)
	if run.Status != StatusInterrupted || len(notes) != 0 {
		t.Fatalf("停机打断应记 interrupted 且不通知：%s %v", run.Status, notes)
	}
	first := *run.SessionID

	runner := &fakeRunner{db: client}
	next := &Scheduler{DB: client, Runner: runner, Dir: dir, DefaultModel: func() string { return "m" }, Timeout: time.Minute, MaxRunning: 10, Notify: notify}
	for range 2 {
		if err := next.tick(ctx, time.Now()); err != nil {
			t.Fatal(err)
		}
		next.wg.Wait()
	}
	runs := client.TaskRun.Query().Where(taskrun.TaskIDEQ("t")).AllX(ctx)
	if len(runner.jobs) != 1 || len(runs) != 1 || runs[0].Status != "succeeded" || *runs[0].SessionID == first {
		t.Fatalf("应换新会话重跑同一轮一次：%d 次 %+v", len(runner.jobs), runs)
	}
}

// levelRunner 按组交指定级别的报告
type levelRunner struct {
	mu     sync.Mutex
	db     *ent.Client
	levels map[string]string
	ran    []string
}

func (f *levelRunner) RunTask(_ context.Context, job Job) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := job.Session.GroupID.String()
	f.ran = append(f.ran, g)
	return f.db.Report.Create().SetSessionID(job.Session.ID).SetGroupID(job.Session.GroupID).
		SetTitle("证书检查").SetMarkdown("# 结果").SetLevel(f.levels[g]).Exec(context.Background())
}

// 默认关闭的任务只在单独开启的组上跑；ok 级报告只存档不推送，urgent 标题加前缀；
// YAML 里的 enabled 只决定首次入库，之后界面改过的开关不被覆盖
func TestGroupEnabledAndQuietReports(t *testing.T) {
	ctx, client := testdb.New(t)
	withSpread(t, 0)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	gC := client.Group.Create().SetName("C").SaveX(ctx)
	for _, g := range []*ent.Group{gA, gB, gC} {
		client.Asset.Create().SetHostname("h-" + g.Name).SetGroupID(g.ID).SaveX(ctx)
	}
	dir := t.TempDir()
	write := func(enabled string) {
		if err := os.WriteFile(filepath.Join(dir, "t.yml"), []byte(
			"id: t\nname: 证书\nenabled: "+enabled+"\nschedule: '*/5 * * * *'\nprompt: 看看\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("false")
	runner := &levelRunner{db: client, levels: map[string]string{gA.ID.String(): "attention", gB.ID.String(): "urgent"}}
	var mu sync.Mutex
	var titles []string
	s := &Scheduler{
		DB: client, Runner: runner, Dir: dir, DefaultModel: func() string { return "m" }, Timeout: time.Minute, MaxRunning: 10,
		Notify: func(_ context.Context, title, _, _ string) error {
			mu.Lock()
			defer mu.Unlock()
			titles = append(titles, title)
			return nil
		},
		start: time.Now().Add(-10 * time.Minute),
	}
	if err := Sync(ctx, client, LoadDir(dir)); err != nil {
		t.Fatal(err)
	}
	task := client.Task.UpdateOneID("t").SetCreatedAt(s.start).SaveX(ctx)
	if task.Enabled {
		t.Fatal("enabled: false 的任务首次入库应为关闭")
	}
	if err := s.tick(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if len(runner.ran) != 0 {
		t.Fatalf("全局关闭且没有按组开启时不应运行：%v", runner.ran)
	}

	client.Task.UpdateOneID("t").SetGroupEnabled(map[string]bool{gA.ID.String(): true, gB.ID.String(): true}).ExecX(ctx)
	if err := s.tick(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	s.wg.Wait()
	if len(runner.ran) != 2 || strings.Contains(strings.Join(runner.ran, ","), gC.ID.String()) {
		t.Fatalf("只应在 A、B 上运行：%v", runner.ran)
	}
	if len(titles) != 1 || titles[0] != "【紧急】证书检查" {
		t.Fatalf("ok 级不推送、urgent 加前缀，得到 %q", titles)
	}

	// YAML 改成 enabled: true 也不覆盖界面上的开关
	write("true")
	if err := Sync(ctx, client, LoadDir(dir)); err != nil {
		t.Fatal(err)
	}
	if client.Task.GetX(ctx, "t").Enabled {
		t.Fatal("同步不应覆盖已入库任务的开关")
	}
}
