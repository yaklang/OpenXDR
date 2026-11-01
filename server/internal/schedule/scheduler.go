package schedule

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
	entasset "openxdr/server/ent/asset"
	entgroup "openxdr/server/ent/group"
	"openxdr/server/ent/report"
	enttask "openxdr/server/ent/task"
	"openxdr/server/ent/taskrun"
	"openxdr/server/internal/commandgate"
)

// StatusInterrupted 运行被停机或失去租约打断：结果不算数，接手的 leader 用新会话重跑
const StatusInterrupted = "interrupted"

// StatusSkipped 并发上限已满、排队超过一个周期仍没轮到，这一轮没有运行
const StatusSkipped = "skipped"

// Initiator 定时任务会话的发起人，即审批闸门的系统身份。
const Initiator = commandgate.SystemActor

// Job 一次任务运行：会话已建好（kind=task、initiator=system、绑定组与模型）。
type Job struct {
	Session         *ent.AgentSession
	Prompt          string
	ApprovalTimeout time.Duration
}

// Runner 以系统身份跑完一次任务会话。会话状态由 Runner 落库；
// 输出截断、轮数耗尽等未完整结束的情况必须返回错误，不能算成功。
type Runner interface {
	RunTask(ctx context.Context, job Job) error
}

// Notifier 任务结果外发，nil 表示不外发。
// Notifier 推送一条通知；path 是控制台内的相对链接，由推送端拼前缀。
type Notifier func(ctx context.Context, title, text, path string) error

type Scheduler struct {
	DB     *ent.Client
	Runner Runner
	Dir    string
	// 检查到期与重载 YAML 的周期
	Interval time.Duration
	// 任务未指定模型时使用（控制台可改，每轮取）；为空表示 Pi 未启用，任务照常同步但不运行
	DefaultModel func() string
	Notify       Notifier
	// 单次运行上限，含模型、工具与审批等待
	Timeout time.Duration
	// 全集群同一时刻运行中的定时任务会话上限，<= 0 用 DefaultMaxRunning
	MaxRunning int

	start time.Time
	wg    sync.WaitGroup
	// 本节点在跑的任务数（含失败重试换会话的间隙）
	active atomic.Int32
	// 排队项 → 开始排队的时刻，只在 leader 内存里
	queued map[string]time.Time
}

// Run 集群单活；遗留会话由执行期限清理器处理，接管时不修改其他节点的活跃运行。
func (s *Scheduler) Run(ctx context.Context) {
	s.start = time.Now()
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	defer s.wg.Wait()
	for {
		if err := s.tick(ctx, time.Now()); err != nil {
			slog.Error("任务调度批次失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Scheduler) tick(ctx context.Context, now time.Time) error {
	if err := Sync(ctx, s.DB, LoadDir(s.Dir)); err != nil {
		return err
	}
	tasks, err := s.DB.Task.Query().Where(enttask.Removed(false)).All(ctx)
	if err != nil {
		return err
	}
	s.fire(ctx, tasks, now)
	return nil
}

// EnabledFor 任务在某个组上跑不跑：按组设置优先，没设置的组跟全局默认
func EnabledFor(t *ent.Task, group uuid.UUID) bool {
	if on, ok := t.GroupEnabled[group.String()]; ok {
		return on
	}
	return t.Enabled
}

// AnyEnabled 至少有一个组会跑
func AnyEnabled(t *ent.Task) bool {
	if t.Enabled {
		return true
	}
	for _, on := range t.GroupEnabled {
		if on {
			return true
		}
	}
	return false
}

// slot 一个组上到期的一轮。plan 是计划时间（cron 时刻，或立即运行的请求时刻），写进 scheduled_at；
// fire 是可以开跑的时刻：定时触发加错峰偏移，立即运行不偏移；period 是排队上限，排满一个周期就跳过。
type slot struct {
	plan, fire time.Time
	period     time.Duration
	manual     bool
}

// due 按组从上次运行起算；从未运行的组使用任务的持久创建时间。
// 停机或停用期间错过的多个周期只补跑一次。
func (s *Scheduler) due(ctx context.Context, t *ent.Task, groupID uuid.UUID, now time.Time) (slot, error) {
	expr := t.Schedule
	if t.CustomSchedule != nil {
		expr = *t.CustomSchedule
	}
	sched, err := ParseSchedule(expr)
	if err != nil {
		return slot{}, err
	}
	base := t.CreatedAt
	last, err := s.DB.TaskRun.Query().Where(taskrun.TaskIDEQ(t.ID), taskrun.GroupIDEQ(groupID)).
		Order(ent.Desc(taskrun.FieldStartedAt)).First(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return slot{}, err
	}
	if last != nil {
		base = last.StartedAt
	}
	// 手动请求晚于上次运行就立即跑、不错峰；计划时间记请求时刻，集群内同一请求只跑一轮
	if r := t.RunRequestedAt; r != nil && r.After(base) && !r.After(now) {
		return slot{plan: *r, fire: *r, period: Period(sched, sched.Next(*r)), manual: true}, nil
	}
	next := sched.Next(base)
	if next.IsZero() {
		return slot{}, nil
	}
	fire := next.Add(Offset(t.ID, groupID, sched, next))
	if fire.After(now) {
		return slot{}, nil
	}
	return slot{plan: next, fire: fire, period: Period(sched, next)}, nil
}

// candidate 到期待拉起的一轮；retry 非空表示重跑被打断的那一轮
type candidate struct {
	task  *ent.Task
	group *ent.Group
	model string
	retry *ent.TaskRun
	slot
}

// rank 拉起顺序：立即运行（人在等）> 被打断的重跑 > 定时触发；同类按开跑时刻先来后到
func (c candidate) rank() int {
	switch {
	case c.manual:
		return 0
	case c.retry != nil:
		return 1
	}
	return 2
}

// key 排队登记用：同一任务同一组同一轮是同一个排队项
func (c candidate) key() string {
	round := c.plan
	if c.retry != nil {
		round = c.retry.StartedAt
	}
	return c.task.ID + "/" + c.group.ID.String() + "/" + round.UTC().Format(time.RFC3339Nano)
}

// fire 收集所有任务所有组到期的一轮，在并发上限内按优先级拉起，其余排队
func (s *Scheduler) fire(ctx context.Context, tasks []*ent.Task, now time.Time) {
	// 任务自带模型也得在 Pi 启用时才跑：端点与密钥跟着平台配置走
	def := s.DefaultModel()
	if def == "" {
		return
	}
	var queue []candidate
	for _, t := range tasks {
		if AnyEnabled(t) {
			queue = append(queue, s.collect(ctx, t, def, now)...)
		}
	}
	s.launch(ctx, queue, now)
}

// collect 一个任务每个目标组到期的一轮。空组不跑；上一轮还在跑的组跳过本轮，不叠加。
func (s *Scheduler) collect(ctx context.Context, t *ent.Task, def string, now time.Time) []candidate {
	q := s.DB.Group.Query()
	if t.TargetGroup != "*" {
		q = q.Where(entgroup.NameEQ(t.TargetGroup))
	}
	groups, err := q.All(ctx)
	if err != nil {
		slog.Error("查询任务目标组失败", "task", t.ID, "err", err)
		return nil
	}
	if len(groups) == 0 {
		slog.Warn("任务没有可用的目标组", "task", t.ID, "group", t.TargetGroup)
	}
	model := t.Model
	if model == "" {
		model = def
	}
	var out []candidate
	for _, g := range groups {
		if !EnabledFor(t, g.ID) {
			continue
		}
		c := candidate{task: t, group: g, model: model}
		// 上一轮被停机打断的先接着重跑，不等下一个周期，也不再错峰（当初开跑时已错过峰）
		if c.retry, err = s.interrupted(ctx, t, g.ID, now); err != nil {
			slog.Error("查询被打断的任务运行失败", "task", t.ID, "group", g.ID, "err", err)
			continue
		}
		if c.retry != nil {
			c.fire = c.retry.StartedAt
		} else {
			if c.slot, err = s.due(ctx, t, g.ID, now); err != nil {
				slog.Error("任务到期判断失败", "task", t.ID, "group", g.ID, "err", err)
				continue
			}
			if c.plan.IsZero() {
				continue
			}
		}
		n, err := s.DB.Asset.Query().Where(entasset.GroupIDEQ(g.ID)).Count(ctx)
		if err != nil || n == 0 {
			continue
		}
		busy, err := s.DB.TaskRun.Query().
			Where(taskrun.TaskIDEQ(t.ID), taskrun.GroupIDEQ(g.ID), taskrun.StatusEQ("running")).
			Exist(ctx)
		if err != nil || busy {
			if busy {
				slog.Warn("上一轮仍在运行，跳过本轮", "task", t.ID, "group", g.Name)
			}
			continue
		}
		out = append(out, c)
	}
	return out
}

// launch 并发上限内按优先级拉起，拉不起的排队，下一次检查再看。排队满一个周期仍没轮到就跳过并留一条
// skipped 记录，不无限积压；被打断的重跑不在这里跳过，超过 interruptedWithin 自然不再重跑。
// 排队起点只记在 leader 内存里：leader 切换后重新起算，最多多等一个周期，不会因此超发。
func (s *Scheduler) launch(ctx context.Context, queue []candidate, now time.Time) {
	sort.SliceStable(queue, func(i, j int) bool {
		a, b := queue[i], queue[j]
		if a.rank() != b.rank() {
			return a.rank() < b.rank()
		}
		return a.fire.Before(b.fire)
	})
	free, err := s.free(ctx)
	if err != nil {
		slog.Error("统计运行中的任务会话失败", "err", err)
		return
	}
	waiting := map[string]time.Time{}
	for _, c := range queue {
		if free > 0 {
			if s.spawn(ctx, c) {
				free--
			}
			continue
		}
		key := c.key()
		since, ok := s.queued[key]
		if !ok {
			since = now
			slog.Info("定时任务会话已达并发上限，排队", "task", c.task.ID, "group", c.group.Name, "limit", s.maxRunning())
		}
		if c.retry == nil && now.Sub(since) >= c.period {
			s.skip(ctx, c, since, now)
			continue
		}
		waiting[key] = since
	}
	// 已拉起、已跳过、或不再到期（停用、改周期）的排队项一并清掉
	s.queued = waiting
}

// free 还能拉起几个任务会话。以库里运行中的任务会话为准，覆盖其他节点（如上一任 leader）尚未收尾的；
// 本节点在跑的另算一份取较大者——失败重试换会话的间隙里库里会少算一个。人发起的对话会话不计入。
func (s *Scheduler) free(ctx context.Context) (int, error) {
	n, err := s.DB.AgentSession.Query().Where(agentsession.KindEQ("task"), agentsession.StatusEQ("running")).Count(ctx)
	if err != nil {
		return 0, err
	}
	return s.maxRunning() - max(n, int(s.active.Load())), nil
}

// spawn 建运行记录与会话并在后台跑；建不起来返回 false
func (s *Scheduler) spawn(ctx context.Context, c candidate) bool {
	run, session := c.retry, (*ent.AgentSession)(nil)
	var err error
	if c.retry != nil {
		slog.Info("重跑被停机打断的任务", "task", c.task.ID, "group", c.group.Name, "run", c.retry.ID)
		session, err = s.rerun(ctx, c.task, c.group, c.retry, c.model)
	} else {
		run, session, err = s.begin(ctx, c.task, c.group, c.model, c.plan)
	}
	if err != nil {
		slog.Error("创建任务运行失败", "task", c.task.ID, "group", c.group.Name, "err", err)
		return false
	}
	s.active.Add(1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.active.Add(-1)
		s.execute(ctx, c.task, c.group, run, session)
	}()
	return true
}

// SkipReason 排队超时跳过时写进运行记录的原因
const SkipReason = "定时任务并发上限已满，排队超过一个周期仍没轮到，跳过本轮"

// skip 记一条 skipped 运行。开始时间记跳过时刻，下一轮从这里起算：排队期间又到期的周期一并跳过，
// 免得过载时补跑一轮接一轮地排下去。
func (s *Scheduler) skip(ctx context.Context, c candidate, since, now time.Time) {
	slog.Warn("定时任务排队超过一个周期，跳过本轮", "task", c.task.ID, "group", c.group.Name,
		"plan", c.plan, "queued_since", since, "limit", s.maxRunning())
	err := s.DB.TaskRun.Create().SetTaskID(c.task.ID).SetGroupID(c.group.ID).SetScheduledAt(c.plan).
		SetStartedAt(now).SetFinishedAt(now).SetStatus(StatusSkipped).SetError(SkipReason).Exec(ctx)
	if err != nil {
		slog.Error("保存跳过记录失败", "task", c.task.ID, "group", c.group.Name, "err", err)
	}
}

// interruptedWithin 多久以内被打断的运行才重跑：再早的那一轮已经过时，等下一个周期
const interruptedWithin = 12 * time.Hour

// interrupted 这个组上一轮是否被停机打断、还值得重跑。只看最近一轮：之后已经跑过就不补
func (s *Scheduler) interrupted(ctx context.Context, t *ent.Task, groupID uuid.UUID, now time.Time) (*ent.TaskRun, error) {
	last, err := s.DB.TaskRun.Query().Where(taskrun.TaskIDEQ(t.ID), taskrun.GroupIDEQ(groupID)).
		Order(ent.Desc(taskrun.FieldStartedAt)).First(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if last.Status != StatusInterrupted || last.StartedAt.Before(now.Add(-interruptedWithin)) {
		return nil, nil
	}
	return last, nil
}

func (s *Scheduler) begin(ctx context.Context, t *ent.Task, g *ent.Group, model string, scheduled time.Time) (*ent.TaskRun, *ent.AgentSession, error) {
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return nil, nil, err
	}
	session, err := s.newSession(ctx, tx, t, g, model)
	if err != nil {
		_ = tx.Rollback()
		return nil, nil, err
	}
	run, err := tx.TaskRun.Create().
		SetTaskID(t.ID).SetGroupID(g.ID).SetSessionID(session.ID).SetScheduledAt(scheduled).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return nil, nil, err
	}
	return run, session, tx.Commit()
}

// rerun 同一轮运行换一个新会话重跑：一个计划时间只占一行运行记录（唯一索引），
// 失败那次的会话与错误仍留在 agent_sessions 里可查。
func (s *Scheduler) rerun(ctx context.Context, t *ent.Task, g *ent.Group, run *ent.TaskRun, model string) (*ent.AgentSession, error) {
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return nil, err
	}
	session, err := s.newSession(ctx, tx, t, g, model)
	if err == nil {
		err = tx.TaskRun.UpdateOneID(run.ID).SetSessionID(session.ID).SetStatus("running").
			ClearFinishedAt().ClearError().Exec(ctx)
	}
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return session, tx.Commit()
}

func (s *Scheduler) newSession(ctx context.Context, tx *ent.Tx, t *ent.Task, g *ent.Group, model string) (*ent.AgentSession, error) {
	return tx.AgentSession.Create().
		SetKind("task").SetGroupID(g.ID).SetInitiator(Initiator).SetModel(model).
		SetTitle(t.Name).SetRunExpiresAt(time.Now().Add(s.runTimeout() + time.Minute)).
		Save(ctx)
}

func (s *Scheduler) execute(ctx context.Context, t *ent.Task, g *ent.Group, run *ent.TaskRun, session *ent.AgentSession) {
	err := s.attempt(ctx, t, g, run, session)
	// 停机或失去租约打断的：已记为 interrupted，由接手的 leader 重跑，不算失败也不通知
	if err != nil && ctx.Err() != nil {
		return
	}
	// 模型偶尔乱写、漏交报告，换个新会话重跑一次通常就好；超时与失去租约不重跑
	if err != nil && ctx.Err() == nil && !errors.Is(err, context.DeadlineExceeded) {
		slog.Warn("任务失败，新开会话重试一次", "task", t.ID, "group", g.Name, "err", err)
		if next, rerr := s.rerun(ctx, t, g, run, session.Model); rerr != nil {
			slog.Error("创建重试会话失败", "task", t.ID, "group", g.Name, "err", rerr)
		} else {
			session = next
			err = s.attempt(ctx, t, g, run, session)
		}
	}

	done, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err == nil {
		s.pushReports(done, g, session)
		return
	}
	// 巡检失败不能悄无声息：没人看控制台时，Webhook 是唯一的信号
	if s.Notify != nil {
		text := fmt.Sprintf("❌ 资产组：「%s」\n⚠️ 任务重试后仍失败：%v", g.Name, err)
		if nerr := s.Notify(done, "任务失败："+t.Name, text, "/?session="+session.ID.String()); nerr != nil {
			slog.Error("任务失败通知发送失败", "run", run.ID, "err", nerr)
		}
	}
}

// attempt 跑一次会话并落终态。
func (s *Scheduler) attempt(ctx context.Context, t *ent.Task, g *ent.Group, run *ent.TaskRun, session *ent.AgentSession) error {
	runCtx, cancel := context.WithTimeout(ctx, s.runTimeout())
	defer cancel()
	slog.Info("任务开始", "task", t.ID, "group", g.Name, "session", session.ID)
	err := s.Runner.RunTask(runCtx, Job{
		Session:         session,
		Prompt:          t.Prompt,
		ApprovalTimeout: time.Duration(t.ApprovalTimeoutSeconds) * time.Second,
	})

	// 节点失去租约时 ctx 已取消，终态仍要落库
	done, cancelDone := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancelDone()
	update := s.DB.TaskRun.UpdateOneID(run.ID).Where(taskrun.StatusEQ("running")).SetFinishedAt(time.Now()).SetStatus("succeeded")
	if err != nil {
		status := "failed"
		if ctx.Err() != nil {
			status = StatusInterrupted
		}
		update.SetStatus(status).SetError(err.Error())
	}
	if uerr := update.Exec(done); uerr != nil {
		slog.Error("保存任务运行终态失败", "run", run.ID, "err", uerr)
	}
	if err != nil {
		slog.Error("任务失败", "task", t.ID, "group", g.Name, "err", err)
		return err
	}
	slog.Info("任务完成", "task", t.ID, "group", g.Name)
	return nil
}

// pushReports 把会话提交的报告推出去：标题、摘要与控制台里的 HTML 链接。
// 推送失败只记日志，报告本身已在库里。
func (s *Scheduler) pushReports(ctx context.Context, g *ent.Group, session *ent.AgentSession) {
	if s.Notify == nil {
		return
	}
	reports, err := s.DB.Report.Query().Where(report.SessionIDEQ(session.ID)).Order(ent.Asc(report.FieldCreatedAt)).All(ctx)
	if err != nil {
		slog.Error("查询任务报告失败", "session", session.ID, "err", err)
		return
	}
	for _, r := range reports {
		// 无异常的只存档：任务多了，「一切正常」的推送本身就是噪音
		if r.Level == "ok" {
			continue
		}
		title := r.Title
		if r.Level == "urgent" {
			title = "【紧急】" + title
		}
		// 一句话结论 + AI 自治摘要 + 待办要点；旧报告没有结论时退回正文摘录
		text := formatReportPushText(g.Name, r)
		if err := s.Notify(ctx, title, text, "/api/agent-reports/"+r.ID.String()+"/html"); err != nil {
			slog.Error("报告推送失败", "report", r.ID, "err", err)
		}
	}
}

// formatReportPushText 组装定时报告的 IM 推送文本（带 Emoji、AI 自治动作与前 3 项待办）。
func formatReportPushText(groupName string, r *ent.Report) string {
	badge := "🟡 需关注"
	if r.Level == "urgent" {
		badge = "🔴 紧急处理"
	} else if r.Level == "ok" {
		badge = "🟢 正常"
	}
	summary := strings.TrimSpace(r.Summary)
	if summary == "" {
		summary = excerpt(r.Markdown, 240)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "🗂️ 资产组：「%s」｜%s\n📌 核心结论：%s", groupName, badge, summary)
	if autoItems := extractSectionItems(r.Markdown, "已执行的操作", 2, 65); len(autoItems) > 0 {
		fmt.Fprintf(&b, "\n🤖 AI 自治动作：%s", strings.Join(autoItems, "；"))
	}
	if todoItems := extractSectionItems(r.Markdown, "需要人处理", 3, 72); len(todoItems) > 0 {
		b.WriteString("\n⚡ 待人工处理：")
		for _, item := range todoItems {
			fmt.Fprintf(&b, "\n  • %s", item)
		}
	}
	return b.String()
}

// extractSectionItems 从报告指定二级章节提取最多 limit 条简洁要点（过滤“无”）。
func extractSectionItems(md, section string, limit, maxRunes int) []string {
	var inSec bool
	var out []string
	for _, raw := range strings.Split(md, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "## ") && !strings.HasPrefix(line, "### ") {
			h := strings.TrimSpace(strings.TrimPrefix(line, "## "))
			inSec = h == section || strings.HasSuffix(h, " "+section)
			continue
		}
		if !inSec || line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "|") {
			continue
		}
		line = strings.TrimLeft(line, "-*• ")
		for i, ch := range line {
			if ch >= '0' && ch <= '9' {
				continue
			}
			if (ch == '.' || ch == '、') && i > 0 {
				line = strings.TrimSpace(line[i+len(string(ch)):])
			}
			break
		}
		line = strings.ReplaceAll(line, "**", "")
		line = strings.ReplaceAll(line, "`", "")
		line = strings.TrimSpace(line)
		if line == "" || line == "无" || line == "无。" || strings.HasPrefix(line, "无（") {
			continue
		}
		out = append(out, excerpt(line, maxRunes))
		if len(out) >= limit {
			break
		}
	}
	return out
}

// excerpt 按字符截断，IM 消息里放全文没人看
func excerpt(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}

// DefaultMaxRunning 默认同一时刻只跑一个定时任务会话：所有会话共用一个模型端点，
// 两个组的巡检同时开跑就曾把每轮推理从 5–17 秒拖到平均 98 秒、双双超时；端点扛得住再调大
const DefaultMaxRunning = 1

func (s *Scheduler) maxRunning() int {
	if s.MaxRunning > 0 {
		return s.MaxRunning
	}
	return DefaultMaxRunning
}

func (s *Scheduler) runTimeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 30 * time.Minute
}
