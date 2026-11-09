package containment

// 慢路径：研判结论驱动的分级处置。确定性信号之外的攻击要等 AI 研判下结论，这里把结论变成处置：
//   - 恶意且置信度达到自动门槛：直接执行，与快路径同一套租约、熔断与处置等级
//   - 可疑或恶意但不够自动门槛：提出处置、等组管理员批准，超时作废，绝不默认执行
//
// 处置对象只从证据里取（告警触发事件里的进程、容器与外部地址），不让模型点名目标，
// 提示注入改写不了要结束哪个进程、封锁哪个地址。先用最小的动作：隔离容器、结束进程、封锁外部地址，
// 一样都认不出时才考虑隔离主机——自动执行只在实验等级上，生产要批准，核心永远不隔离。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/decoy"
)

// SignalVerdict 研判结论驱动的处置在 containments.signal 里的标记
const SignalVerdict = "ai:verdict"

// VerdictPolicy 慢路径的门槛。零值不处置任何结论
type VerdictPolicy struct {
	// Auto 关掉时达到自动门槛的结论也只提出处置、等批准
	Auto bool
	// 恶意且置信度不低于 AutoConfidence 自动执行；可疑或恶意且不低于 ProposeConfidence 提出处置
	AutoConfidence, ProposeConfidence int
	// 待审批处置的有效期，过期作废
	ProposalTTL time.Duration
	// 绝不自动处置的主机名：达到自动门槛也只提出处置
	Exempt map[string]bool
}

// 一条结论最多生成这么多个处置：证据再多也只动最直接的几处，多出来的交给人
const maxVerdictActions = 10

// 作为处置依据的告警至少这个级别；首次出现这类低危观察不足以动手
const verdictMinSeverity = 3

// ErrNotProposed 不是待审批状态（已被处理、已过期或本来就不是提出的处置）
var ErrNotProposed = errors.New("这条处置不在待审批状态")

type verdictOf struct {
	Verdict    string `json:"verdict"`
	Confidence int    `json:"confidence"`
}

// reactVerdicts 回看窗口内研判过的事件，结论新于上次处理的才看
func (e *Engine) reactVerdicts(ctx context.Context) error {
	p := e.Verdicts
	if p.ProposeConfidence <= 0 && !p.Auto {
		return nil
	}
	now := e.now()
	incidents, err := e.DB.Incident.Query().
		Where(incident.TriagedAtGTE(now.Add(-lookback)), incident.StatusIn("open", "triaged")).
		All(ctx)
	if err != nil {
		return err
	}
	if e.verdictSeen == nil {
		e.verdictSeen = map[uuid.UUID]time.Time{}
	}
	for id, at := range e.verdictSeen {
		if at.Before(now.Add(-2 * lookback)) {
			delete(e.verdictSeen, id)
		}
	}
	for _, inc := range incidents {
		if seen, ok := e.verdictSeen[inc.ID]; ok && !inc.TriagedAt.After(seen) {
			continue
		}
		if err := e.reactVerdict(ctx, inc); err != nil {
			return fmt.Errorf("事件 %s: %w", inc.ID, err)
		}
		e.verdictSeen[inc.ID] = *inc.TriagedAt
	}
	return nil
}

func (e *Engine) reactVerdict(ctx context.Context, inc *ent.Incident) error {
	var v verdictOf
	if json.Unmarshal(inc.AiVerdict, &v) != nil || (v.Verdict != "malicious" && v.Verdict != "suspicious") {
		return nil
	}
	p := e.Verdicts
	auto := p.Auto && v.Verdict == "malicious" && v.Confidence >= p.AutoConfidence
	if !auto && (p.ProposeConfidence <= 0 || v.Confidence < p.ProposeConfidence) {
		return nil
	}
	steps, err := e.verdictPlan(ctx, inc, v, auto)
	if err != nil {
		return err
	}
	var proposed []string
	for _, s := range steps {
		if s.auto {
			if err := e.decideWithEdge(ctx, s.alert, nil, s.action, s.last); err != nil {
				return err
			}
			continue
		}
		ok, err := e.propose(ctx, s.alert, s.action, s.last)
		if err != nil {
			return err
		}
		if ok {
			proposed = append(proposed, s.action.asset.Hostname+"："+s.action.why)
		}
	}
	if len(proposed) > 0 && e.Notify != nil {
		text := strings.Join(proposed, "\n") + fmt.Sprintf("\n\n%d 小时内未批准自动作废。", int(p.ProposalTTL.Hours()))
		if err := e.Notify(ctx, "处置待审批："+title(inc), text, "/containment"); err != nil {
			slog.Error("待审批处置推送失败", "incident", inc.ID, "err", err)
		}
	}
	return nil
}

type verdictStep struct {
	alert  *ent.Alert
	action action
	last   time.Time
	auto   bool
}

// verdictPlan 从事件的告警证据里找处置对象，每台主机先取最小的动作
func (e *Engine) verdictPlan(ctx context.Context, inc *ent.Incident, v verdictOf, auto bool) ([]verdictStep, error) {
	alerts, err := e.DB.Alert.Query().
		Where(alert.IncidentIDEQ(inc.ID), alert.AssetIDNotNil(), alert.SeverityGTE(verdictMinSeverity),
			alert.CommandIDIsNil(), alert.AutomationIDIsNil(), alert.HealthcheckEQ(false),
			alert.Not(alert.RuleIDHasPrefix(decoy.ObservationRulePrefix))).
		Order(ent.Desc(alert.FieldSeverity), ent.Desc(alert.FieldTs)).
		Limit(50).All(ctx)
	if err != nil {
		return nil, err
	}
	label := map[string]string{"malicious": "恶意", "suspicious": "可疑"}[v.Verdict]
	because := fmt.Sprintf("事件「%s」研判为%s（置信度 %d）", title(inc), label, v.Confidence)
	type hostPlan struct {
		host    *ent.Asset
		tier    string
		auto    bool
		alert   *ent.Alert
		last    time.Time
		actions []action
	}
	hosts := map[uuid.UUID]*hostPlan{}
	var order []uuid.UUID
	seen := map[string]bool{}
	for _, al := range alerts {
		hp := hosts[*al.AssetID]
		if hp == nil {
			host, err := e.DB.Asset.Get(ctx, *al.AssetID)
			if err != nil {
				return nil, err
			}
			t, _, err := e.tier(ctx, host)
			if err != nil {
				return nil, err
			}
			outOfScope, err := e.scoped(ctx, host)
			if err != nil {
				return nil, err
			}
			hp = &hostPlan{host: host, tier: t, auto: auto && outOfScope == "" && !e.Verdicts.Exempt[host.Hostname], alert: al, last: lastOf(al)}
			hosts[host.ID] = hp
			order = append(order, host.ID)
		}
		ev, err := e.eventOf(ctx, al)
		if err != nil {
			return nil, err
		}
		if ev == nil {
			continue
		}
		for _, a := range e.evidenceActions(ctx, hp.host, hp.tier, ev, because) {
			if seen[a.key()] {
				continue
			}
			seen[a.key()] = true
			a.alert = al
			hp.actions = append(hp.actions, a)
		}
	}
	var steps []verdictStep
	for _, id := range order {
		hp := hosts[id]
		if len(hp.actions) == 0 {
			// 认不出更小的处置对象：实验等级才自动隔离整机，生产只提出，核心不动
			if hp.tier == TierCore {
				continue
			}
			a := action{asset: hp.host, kind: "isolate_host", role: "host", alert: hp.alert,
				why: because + "，证据里认不出可单独处置的进程、容器或外部地址，隔离本机"}
			if len(e.AllowEndpoints) == 0 {
				a.skip = "未配置 ISOLATION_ALLOW，隔离后收不到解除指令"
			}
			hp.actions = append(hp.actions, a)
		}
		for _, a := range hp.actions {
			if len(steps) == maxVerdictActions {
				return steps, nil
			}
			auto := hp.auto && (a.kind != "isolate_host" || hp.tier == TierLab)
			steps = append(steps, verdictStep{alert: a.alert, action: a, last: lastOf(a.alert), auto: auto})
		}
	}
	return steps, nil
}

// evidenceActions 一条告警触发事件里能单独处置的对象：容器里的就隔离容器（不再结束其中的进程），
// 否则结束触发的进程；事件里的外部地址（出站的目的、入站与认证的来源）在本机封锁。内网地址不封：
// 纳管主机之间的处置交给快路径的确定性信号
func (e *Engine) evidenceActions(ctx context.Context, host *ent.Asset, tier string, ev *ent.Event, because string) []action {
	var doc eventDoc
	_ = json.Unmarshal(ev.Raw, &doc)
	var out []action
	switch {
	case doc.Container.UID != "" && doc.Container.Runtime == "docker":
		if tier != TierCore {
			out = append(out, action{asset: host, kind: "isolate_container", target: doc.Container.UID, role: "host",
				why: because + "，隔离涉事容器 " + container{doc.Container.UID, doc.Container.Name}.label()})
		}
	case ev.ClassUID == 1007 && ev.ProcessGUID != nil && doc.Process.PID > 1 && !e.exited(ctx, host, ev, doc):
		out = append(out, e.killProcess(host, ev, doc, "", because+"，结束涉事进程 "+doc.Process.Name))
	}
	peer := doc.Dst.IP
	if ev.ClassUID == 3002 || doc.Connection.Direction == "inbound" {
		peer = doc.Src.IP
	}
	if public(peer) {
		out = append(out, action{asset: host, kind: "block_network", target: peer, role: "host",
			why: because + "，封锁涉事外部地址 " + peer})
	}
	return out
}

// exited 涉事进程（原地 exec 过的取当前那个）的退出事件已经到了：结束它没有意义，不提。
// agent 不单独上报 2 秒内成功退出的进程，这类判断不了，照常处置；查询出错也照常处置
func (e *Engine) exited(ctx context.Context, host *ent.Asset, ev *ent.Event, doc eventDoc) bool {
	guid, err := e.execHead(ctx, host.ID, *ev.ProcessGUID, doc.Process.PID, ev.Ts)
	if err != nil {
		return false
	}
	var gone bool
	err = e.SQL.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM events WHERE asset_id=$1 AND class_uid=1007
  AND ts>=$2 AND ts<=$3 AND process_guid=$4 AND raw->>'activity_id'='2')`, host.ID, ev.Ts.Add(-time.Minute), e.now(), guid).Scan(&gone)
	return err == nil && gone
}

// public 公网地址才自动封：内网、回环、链路本地、组播都不是
func public(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.IsGlobalUnicast() && !a.IsPrivate() && !a.Is4In6() &&
		!netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

func lastOf(al *ent.Alert) time.Time {
	if al.LastTs != nil {
		return *al.LastTs
	}
	return al.Ts
}

func title(inc *ent.Incident) string {
	if inc.Title != nil {
		return *inc.Title
	}
	return inc.ID.String()
}

// propose 记一条待审批处置。同一个键已有在途处置、这条证据已经决定过、或人工解除晚于证据的，不再提出
func (e *Engine) propose(ctx context.Context, al *ent.Alert, a action, last time.Time) (bool, error) {
	if a.skip != "" {
		return false, nil
	}
	key := a.key()
	preds := []predicate.Containment{
		entcontainment.StateIn(entcontainment.StateProposed, entcontainment.StatePending, entcontainment.StateActive),
		entcontainment.AlertIDEQ(al.ID),
		entcontainment.And(entcontainment.StateEQ(entcontainment.StateLifted), entcontainment.EndedAtGTE(last)),
	}
	if a.kind == "kill_process" {
		preds = append(preds, entcontainment.StateIn(entcontainment.StateExecuted, entcontainment.StateFailed))
	}
	decided, err := e.DB.Containment.Query().Where(entcontainment.KeyEQ(key), entcontainment.Or(preds...)).Exist(ctx)
	if err != nil || decided {
		return false, err
	}
	err = e.DB.Containment.Create().SetID(initialContainmentID(al.ID, key)).SetCreatedAt(e.now()).
		SetAssetID(a.asset.ID).SetNillableGroupID(a.asset.GroupID).
		SetKind(a.kind).SetTarget(a.target).SetPid(a.pid).SetKey(key).
		SetSignal(SignalVerdict).SetAlertID(al.ID).SetNillableIncidentID(al.IncidentID).
		SetRole(entcontainment.Role(a.role)).SetState(entcontainment.StateProposed).
		SetReason(a.why).SetExpiresAt(e.now().Add(e.Verdicts.ProposalTTL)).
		Exec(ctx)
	if ent.IsConstraintError(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	audit.System(ctx, e.DB, "containment_proposed", al.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+a.why)
	return true, nil
}

// expireProposals 过了审批期限的作废，不默认执行
func (e *Engine) expireProposals(ctx context.Context) error {
	now := e.now()
	due, err := e.DB.Containment.Query().
		Where(entcontainment.StateEQ(entcontainment.StateProposed), entcontainment.ExpiresAtLTE(now)).All(ctx)
	if err != nil {
		return err
	}
	for _, c := range due {
		if err := e.DB.Containment.Update().Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateProposed)).
			SetState(entcontainment.StateDeclined).SetEndedAt(now).ClearExpiresAt().
			SetReason(c.Reason + "；审批超时未批准，作废").Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Approve 组管理员批准待审批处置：按快路径同一流程下发（目标校验、熔断、租约），租约从批准时算起
func (e *Engine) Approve(ctx context.Context, c *ent.Containment, actor string) (*ent.Containment, error) {
	if c.State != entcontainment.StateProposed || c.ExpiresAt == nil || !c.ExpiresAt.After(e.now()) {
		return nil, ErrNotProposed
	}
	host, err := e.DB.Asset.Get(ctx, c.AssetID)
	if err != nil {
		return nil, err
	}
	al, err := e.DB.Alert.Get(ctx, c.AlertID)
	if err != nil {
		return nil, err
	}
	a := action{asset: host, kind: c.Kind, target: c.Target, pid: c.Pid, role: string(c.Role), why: c.Reason + "；" + actor + " 批准"}
	cmdID := initialCommandID(c.AlertID, c.Key)
	req, skip, err := e.request(ctx, a, cmdID, c.IncidentID, al.Ts)
	if err != nil {
		return nil, err
	}
	end := func(state entcontainment.State, reason string) (*ent.Containment, error) {
		n, err := e.DB.Containment.Update().Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateProposed)).
			SetState(state).SetReason(reason).SetDecidedBy(actor).ClearExpiresAt().Save(ctx)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, ErrNotProposed
		}
		return e.DB.Containment.Get(ctx, c.ID)
	}
	if skip != "" {
		return end(entcontainment.StateSkipped, a.why+"；"+skip)
	}
	busy, err := e.DB.Containment.Query().Where(entcontainment.KeyEQ(c.Key), entcontainment.IDNEQ(c.ID),
		entcontainment.StateIn(entcontainment.StatePending, entcontainment.StateActive)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if busy {
		return end(entcontainment.StateDeclined, a.why+"；同一处置已在生效，不重复下发")
	}
	held, err := e.fuse(ctx, a)
	if err != nil {
		return nil, err
	}
	if held != "" {
		return end(entcontainment.StateHeld, a.why+"；"+held)
	}
	upd := e.DB.Containment.Update().Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateProposed)).
		SetState(entcontainment.StatePending).SetCommandID(cmdID).SetReason(a.why).SetDecidedBy(actor).ClearExpiresAt()
	if _, lease := leases[a.kind]; lease {
		upd.SetExpiresAt(e.now().Add(e.TTL))
	}
	n, err := upd.Save(ctx)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrNotProposed
	}
	pending, err := e.DB.Containment.Get(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	if err := e.dispatch(ctx, pending, a, req, c.AlertID); err != nil {
		return nil, err
	}
	// 批准的是公网封锁就连同边界一起；边界那条按快路径同一流程自动执行
	edge, err := e.edgeActions(ctx, a)
	if err != nil {
		return nil, err
	}
	for _, ea := range edge {
		ea.why = c.Reason + "；" + actor + " 批准后在边界网关 " + ea.asset.Hostname + " 一并封锁"
		if err := e.decide(ctx, al, nil, ea, e.now()); err != nil {
			return nil, err
		}
	}
	return e.DB.Containment.Get(ctx, c.ID)
}

// Decline 组管理员驳回待审批处置
func (e *Engine) Decline(ctx context.Context, c *ent.Containment, actor, reason string) (*ent.Containment, error) {
	why := c.Reason + "；" + actor + " 驳回"
	if reason != "" {
		why += "：" + reason
	}
	n, err := e.DB.Containment.Update().Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateProposed)).
		SetState(entcontainment.StateDeclined).SetDecidedBy(actor).SetEndedAt(e.now()).ClearExpiresAt().SetReason(why).Save(ctx)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrNotProposed
	}
	return e.DB.Containment.Get(ctx, c.ID)
}
