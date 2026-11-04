// Package containment 自主响应：确定性信号命中后，不等研判、不等人，按角色和处置等级直接遏制。
//
// 设计见 docs/autonomous-response-design.md。要点：
//   - 遏制攻击来源，受害方只做外科手术式的处置（封锁来源、锁定被攻破的账号），永远不隔离受害主机
//   - 动作强度看处置等级：实验可以隔离整机，生产不隔离，核心只封锁与结束确认恶意的进程
//   - 封锁与隔离主机是租约：证据持续就续期，到期自动解除。结束进程、隔离文件、锁定账号一次性执行，
//     不自动恢复——把被爆破的账号自动解锁、把恶意文件自动放回，都比不恢复更危险
//   - 没执行的决定也落表，决策记录就是 containments
//   - 熔断：一小时内执行太多、或一个组里隔离的主机太多，就只记录不执行。宁可漏处置，不能让一个误报信号关掉全网
//
// 单活运行（cluster.RunLeader），同一时刻只有一个节点在做决定，表里的键不会并发撞车。
package containment

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	entasset "openxdr/server/ent/asset"
	entcommand "openxdr/server/ent/command"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/response"
	"openxdr/server/internal/triage"
)

// 自动处置范围：lab 只处置涉及实验等级主机的攻击（上线初期），all 不限
const (
	ScopeLab = "lab"
	ScopeAll = "all"
)

type Engine struct {
	DB  *ent.Client
	SQL *sql.DB
	Hub *response.Hub
	// 隔离主机时放行的地址（ISOLATION_ALLOW），为空则不做隔离，同时用来挡住封锁 server 自己
	AllowEndpoints []string
	Scope          string
	// 租约长度：从最后一条证据算起
	TTL time.Duration
	// 一小时内最多执行的处置数，超出熔断
	MaxPerHour int
	Interval   time.Duration
	// 测试回放历史时刻用，默认 time.Now
	Now func() time.Time
	// 租约到期时复核用的模型；未配置时到期直接解除
	LLM *triage.LLM
}

// lookback 每轮回看多久内有新证据的告警。处置是幂等的，回看长一点只为单活切换期间不漏
const lookback = time.Hour

// 一个组里同时被隔离的主机不超过纳管主机数的这个比例（至少允许一台）
const groupIsolationPercent = 20

// 解除失败（agent 离线等）多久后再试
const liftRetry = 5 * time.Minute

// leases 可逆、按租约到期自动解除的动作与对应的解除动作；其余动作一次性执行
var leases = map[string]string{"isolate_host": "unisolate_host", "block_network": "unblock_network", "isolate_container": "unisolate_container"}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Run 单活循环：对新证据做决定，给到期的租约下发解除。
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(e.Interval)
	defer t.Stop()
	for {
		if err := e.Tick(ctx); err != nil && ctx.Err() == nil {
			slog.Error("自主响应本轮失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (e *Engine) Tick(ctx context.Context) error {
	if err := e.reconcile(ctx); err != nil {
		return err
	}
	if err := e.react(ctx); err != nil {
		return err
	}
	return e.expire(ctx)
}

func (e *Engine) reconcile(ctx context.Context) error {
	return Reconcile(ctx, e.DB, e.now())
}

// Reconcile 对账初次处置指令（CommandID）与解除指令（LiftCommandID）的执行回执：
//   - sent / pending / unknown / unsupported 均不视为成功；unknown 绝不自动重发；
//   - 收到 succeeded 回执才推进到 active / executed 或 expired / lifted（并写 EndedAt）；
//   - 历史已标为 active / executed 但实际指令未 succeeded 的记录同步修正。
func Reconcile(ctx context.Context, db *ent.Client, now time.Time) error {
	initialRows, err := db.Containment.Query().
		Where(entcontainment.CommandIDNotNil(),
			entcontainment.StateIn(entcontainment.StatePending, entcontainment.StateActive, entcontainment.StateExecuted)).
		All(ctx)
	if err != nil {
		return err
	}
	if len(initialRows) > 0 {
		ids := make([]uuid.UUID, 0, len(initialRows))
		for _, c := range initialRows {
			ids = append(ids, *c.CommandID)
		}
		cmds, err := db.Command.Query().Where(entcommand.IDIn(ids...)).All(ctx)
		if err != nil {
			return err
		}
		byID := make(map[uuid.UUID]*ent.Command, len(cmds))
		for _, cmd := range cmds {
			byID[cmd.ID] = cmd
		}
		for _, c := range initialRows {
			if c.CommandID == nil {
				continue
			}
			cmdID := *c.CommandID
			cmd := byID[cmdID]
			if cmd == nil {
				continue
			}
			switch cmd.Status {
			case "succeeded":
				if c.State == entcontainment.StatePending {
					upd := db.Containment.Update().Where(
						entcontainment.IDEQ(c.ID),
						entcontainment.StateEQ(entcontainment.StatePending),
						entcontainment.CommandIDEQ(cmdID),
					)
					if _, lease := leases[c.Kind]; lease {
						upd.SetState(entcontainment.StateActive)
						if c.ExpiresAt == nil {
							upd.SetExpiresAt(now.Add(24 * time.Hour))
						}
					} else {
						upd.SetState(entcontainment.StateExecuted)
					}
					if err := upd.Exec(ctx); err != nil {
						return err
					}
				}
			case "failed", "unsupported":
				if c.State != entcontainment.StateFailed {
					suffix := classifyFailure(c.Kind, cmd.Status, cmd.Detail)
					reason := appendReasonOnce(c.Reason, suffix)
					n, err := db.Containment.Update().Where(
						entcontainment.IDEQ(c.ID),
						entcontainment.StateEQ(c.State),
						entcontainment.CommandIDEQ(cmdID),
					).SetState(entcontainment.StateFailed).ClearExpiresAt().SetReason(reason).Save(ctx)
					if err != nil {
						return err
					}
					if n > 0 {
						audit.System(ctx, db, "containment_failed", c.AlertID.String(), c.Kind+" "+c.Target+"："+suffix)
					}
				}
			case "sent", "pending", "unknown":
				reason := c.Reason
				if cmd.Status == "unknown" {
					reason = appendReasonOnce(reason, unknownReason(cmd.Detail))
				}
				if c.State != entcontainment.StatePending || reason != c.Reason {
					if err := db.Containment.Update().Where(
						entcontainment.IDEQ(c.ID),
						entcontainment.StateEQ(c.State),
						entcontainment.CommandIDEQ(cmdID),
						entcontainment.LiftCommandIDIsNil(),
					).SetState(entcontainment.StatePending).SetReason(reason).Exec(ctx); err != nil {
						return err
					}
				}
			}
		}
	}

	liftRows, err := db.Containment.Query().
		Where(entcontainment.LiftCommandIDNotNil(),
			entcontainment.StateIn(entcontainment.StateActive, entcontainment.StateExecuted, entcontainment.StateExpired, entcontainment.StateLifted)).
		All(ctx)
	if err != nil {
		return err
	}
	if len(liftRows) > 0 {
		ids := make([]uuid.UUID, 0, len(liftRows))
		for _, c := range liftRows {
			ids = append(ids, *c.LiftCommandID)
		}
		cmds, err := db.Command.Query().Where(entcommand.IDIn(ids...)).All(ctx)
		if err != nil {
			return err
		}
		byID := make(map[uuid.UUID]*ent.Command, len(cmds))
		for _, cmd := range cmds {
			byID[cmd.ID] = cmd
		}
		for _, c := range liftRows {
			if c.LiftCommandID == nil {
				continue
			}
			liftCmdID := *c.LiftCommandID
			cmd := byID[liftCmdID]
			if cmd == nil {
				continue
			}
			switch cmd.Status {
			case "succeeded":
				if c.State == entcontainment.StateActive || c.State == entcontainment.StateExecuted || c.EndedAt == nil {
					if c.LiftedBy != nil && *c.LiftedBy != "" {
						if err := db.Containment.Update().Where(
							entcontainment.IDEQ(c.ID),
							entcontainment.StateEQ(c.State),
							entcontainment.LiftCommandIDEQ(liftCmdID),
						).SetState(entcontainment.StateLifted).SetEndedAt(now).Exec(ctx); err != nil {
							return err
						}
					} else {
						n, err := db.Containment.Update().Where(
							entcontainment.IDEQ(c.ID),
							entcontainment.StateEQ(c.State),
							entcontainment.LiftCommandIDEQ(liftCmdID),
							entcontainment.Or(entcontainment.LiftedByIsNil(), entcontainment.LiftedByEQ("")),
						).SetState(entcontainment.StateExpired).SetEndedAt(now).Save(ctx)
						if err != nil {
							return err
						}
						if n > 0 {
							audit.System(ctx, db, "containment_expired", cmd.ID.String(), leases[c.Kind]+" "+c.Target+"（租约到期）")
						} else {
							if err := db.Containment.Update().Where(
								entcontainment.IDEQ(c.ID),
								entcontainment.LiftCommandIDEQ(liftCmdID),
								entcontainment.LiftedByNotNil(),
								entcontainment.LiftedByNEQ(""),
								entcontainment.EndedAtIsNil(),
							).SetState(entcontainment.StateLifted).SetEndedAt(now).Exec(ctx); err != nil {
								return err
							}
						}
					}
				}
			case "failed":
				restored := restoreInEffectState(c)
				reason := appendReasonOnce(c.Reason, "解除失败，保持生效")
				needExpiryBump := restored == entcontainment.StateActive && c.ExpiresAt != nil && !c.ExpiresAt.After(now)
				if restored != c.State || c.EndedAt != nil || c.LiftedBy != nil || reason != c.Reason || needExpiryBump {
					upd := db.Containment.Update().Where(
						entcontainment.IDEQ(c.ID),
						entcontainment.StateEQ(c.State),
						entcontainment.LiftCommandIDEQ(liftCmdID),
					).SetState(restored).ClearEndedAt().ClearLiftedBy().SetReason(reason)
					if needExpiryBump {
						upd.SetExpiresAt(now.Add(liftRetry))
					}
					if err := upd.Exec(ctx); err != nil {
						return err
					}
				}
			case "unsupported":
				restored := restoreInEffectState(c)
				reason := appendReasonOnce(c.Reason, "解除指令不被 agent 支持，保持生效")
				if restored != c.State || c.EndedAt != nil || reason != c.Reason {
					if err := db.Containment.Update().Where(
						entcontainment.IDEQ(c.ID),
						entcontainment.StateEQ(c.State),
						entcontainment.LiftCommandIDEQ(liftCmdID),
					).SetState(restored).ClearEndedAt().SetReason(reason).Exec(ctx); err != nil {
						return err
					}
				}
			case "sent", "pending", "unknown":
				restored := restoreInEffectState(c)
				reason := c.Reason
				if cmd.Status == "unknown" {
					reason = appendReasonOnce(reason, "解除执行结果未知（禁止自动重发）")
				}
				if restored != c.State || c.EndedAt != nil || reason != c.Reason {
					if err := db.Containment.Update().Where(
						entcontainment.IDEQ(c.ID),
						entcontainment.StateEQ(c.State),
						entcontainment.LiftCommandIDEQ(liftCmdID),
					).SetState(restored).ClearEndedAt().SetReason(reason).Exec(ctx); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func initialContainmentID(alertID uuid.UUID, key string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("openxdr:containment-row|"+alertID.String()+"|"+key))
}

func initialCommandID(alertID uuid.UUID, key string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("openxdr:containment-init|"+alertID.String()+"|"+key))
}

func liftCommandID(containmentID, prevFailedLiftID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("openxdr:containment-lift|"+containmentID.String()+"|"+prevFailedLiftID.String()))
}

func matchesLiftCommand(c *ent.Containment, cmd *ent.Command) bool {
	if c == nil || cmd == nil || cmd.AssetID != c.AssetID || cmd.Kind != reverse[c.Kind] {
		return false
	}
	if c.Target == "" {
		return cmd.Target == nil || *cmd.Target == ""
	}
	return cmd.Target != nil && *cmd.Target == c.Target
}

// resolveLiftCommand 解析当前处置记录对应的解除指令状态：
//   - 若已有非 failed 的解除指令（含前次已建单但 LiftCommandID 未刷新），返回 existingCmd 供直接复用/对账；
//   - 否则返回本次应当预留并下发的确定性 cmdID 及前序失败指令 prevFailedID。
func resolveLiftCommand(ctx context.Context, db *ent.Client, c *ent.Containment) (existingCmd *ent.Command, cmdID, prevFailedID uuid.UUID, err error) {
	if c.LiftCommandID != nil {
		prev, getErr := db.Command.Get(ctx, *c.LiftCommandID)
		if getErr != nil && !ent.IsNotFound(getErr) {
			return nil, uuid.Nil, uuid.Nil, getErr
		}
		if prev == nil {
			return nil, *c.LiftCommandID, uuid.Nil, nil
		}
		if prev.Status != "failed" {
			return prev, prev.ID, uuid.Nil, nil
		}
		prevFailedID = prev.ID
	}
	candidate := liftCommandID(c.ID, prevFailedID)
	for range 16 {
		cmd, getErr := db.Command.Get(ctx, candidate)
		if ent.IsNotFound(getErr) {
			return nil, candidate, prevFailedID, nil
		}
		if getErr != nil {
			return nil, uuid.Nil, uuid.Nil, getErr
		}
		if !matchesLiftCommand(c, cmd) {
			return nil, candidate, prevFailedID, nil
		}
		if cmd.Status != "failed" {
			return cmd, cmd.ID, prevFailedID, nil
		}
		prevFailedID = cmd.ID
		candidate = liftCommandID(c.ID, prevFailedID)
	}
	return nil, candidate, prevFailedID, nil
}

func restoreInEffectState(c *ent.Containment) entcontainment.State {
	if c.State == entcontainment.StateExpired || c.State == entcontainment.StateLifted {
		if _, lease := leases[c.Kind]; lease {
			return entcontainment.StateActive
		}
		return entcontainment.StateExecuted
	}
	return c.State
}

func classifyFailure(kind, status string, detailPtr *string) string {
	detail := ""
	if detailPtr != nil {
		detail = strings.TrimSpace(*detailPtr)
	}
	if status == "unsupported" {
		if detail != "" {
			return "agent 不支持该动作：" + detail
		}
		return "agent 不支持该动作"
	}
	if kind == "kill_process" {
		lower := strings.ToLower(detail)
		if strings.Contains(lower, "no such process") || strings.Contains(detail, "进程不存在") || strings.Contains(lower, "pidfd") {
			return "目标已消失（进程已退出）：" + detail
		}
		if strings.Contains(detail, "身份不匹配") || strings.Contains(detail, "已过期") || strings.Contains(detail, "身份不符") {
			return "安全闸门拒绝（进程身份不匹配或已过期）：" + detail
		}
	}
	if detail != "" {
		return "执行失败：" + detail
	}
	return "执行失败"
}

func unknownReason(detailPtr *string) string {
	if detailPtr != nil && strings.TrimSpace(*detailPtr) != "" {
		return "执行结果未知（禁止自动重发）：" + strings.TrimSpace(*detailPtr)
	}
	return "执行结果未知（禁止自动重发）"
}

func appendReasonOnce(base, suffix string) string {
	if suffix == "" || strings.Contains(base, suffix) {
		return base
	}
	if base == "" {
		return suffix
	}
	return base + "；" + suffix
}

// action 一条计划中的处置：在 asset 上做 kind。target 是封锁的地址、隔离的文件、锁定的账号或结束的进程 GUID
type action struct {
	asset  *ent.Asset
	kind   string
	target string
	pid    uint32
	role   string
	// 非空表示按规则就不该自动执行，记 skipped
	skip string
	// 进决策记录与审计的理由
	why string
}

func (a action) key() string { return a.asset.ID.String() + "|" + a.kind + "|" + a.target }

// plan 一条告警的处置计划。source 是发起攻击的纳管主机（没有就是 nil）
type plan struct {
	source  *ent.Asset
	actions []action
}

// react 对回看窗口内有新证据的信号告警逐条做决定。平台指令、已知自动化与容器健康检查引起的告警不处置
func (e *Engine) react(ctx context.Context) error {
	now := e.now()
	alerts, err := e.DB.Alert.Query().
		Where(signalAlerts(), alert.AssetIDNotNil(), alert.CommandIDIsNil(), alert.AutomationIDIsNil(), alert.HealthcheckEQ(false),
			alert.Or(alert.LastTsGTE(now.Add(-lookback)), alert.And(alert.LastTsIsNil(), alert.TsGTE(now.Add(-lookback)))),
			alert.TsLTE(now)).
		All(ctx)
	if err != nil {
		return err
	}
	for _, al := range alerts {
		p, err := e.planFor(ctx, al)
		if err != nil {
			return fmt.Errorf("告警 %s: %w", al.ID, err)
		}
		last := al.Ts
		if al.LastTs != nil {
			last = *al.LastTs
		}
		for _, a := range p.actions {
			if err := e.decide(ctx, al, p.source, a, last); err != nil {
				return fmt.Errorf("告警 %s 处置 %s: %w", al.ID, a.key(), err)
			}
		}
	}
	return nil
}

// scoped 上线初期的范围限制：攻击涉及的主机里有实验等级的才处置。返回非空表示超出范围
func (e *Engine) scoped(ctx context.Context, involved ...*ent.Asset) (string, error) {
	if e.Scope == ScopeAll {
		return "", nil
	}
	var names []string
	for _, a := range involved {
		if a == nil {
			continue
		}
		t, why, err := e.tier(ctx, a)
		if err != nil || t == TierLab {
			return "", err
		}
		names = append(names, a.Hostname+" 是"+tierName(t)+"（"+why+"）")
	}
	return "自动处置范围只含实验等级主机涉及的攻击，" + strings.Join(names, "，"), nil
}

// decide 一条计划处置落表：已有生效或待确认租约就续期；人工在最后一条证据之后解除过、或这条告警已经为它做过决定，
// 就不再动；否则新决定，能执行就下发。last 是告警最后一条证据的时间
func (e *Engine) decide(ctx context.Context, al *ent.Alert, source *ent.Asset, a action, last time.Time) error {
	key, expires := a.key(), last.Add(e.TTL)
	active, err := e.DB.Containment.Query().
		Where(entcontainment.KeyEQ(key), entcontainment.StateIn(entcontainment.StatePending, entcontainment.StateActive)).
		Only(ctx)
	switch {
	case err == nil:
		if _, lease := leases[a.kind]; lease && active.LiftCommandID == nil && (active.ExpiresAt == nil || expires.After(*active.ExpiresAt)) {
			return active.Update().SetExpiresAt(expires).Exec(ctx)
		}
		return nil
	case !ent.IsNotFound(err):
		return err
	}
	preds := []predicate.Containment{
		entcontainment.AlertIDEQ(al.ID),
		entcontainment.And(entcontainment.StateEQ(entcontainment.StateLifted), entcontainment.EndedAtGTE(last)),
	}
	if a.kind == "kill_process" {
		preds = append(preds, entcontainment.StateIn(entcontainment.StateExecuted, entcontainment.StateFailed))
	}
	decided, err := e.DB.Containment.Query().
		Where(entcontainment.KeyEQ(key), entcontainment.Or(preds...)).
		Exist(ctx)
	if err != nil || decided {
		return err
	}

	containmentID := initialContainmentID(al.ID, key)
	create := e.DB.Containment.Create().SetID(containmentID).SetCreatedAt(e.now()).
		SetAssetID(a.asset.ID).SetNillableGroupID(a.asset.GroupID).
		SetKind(a.kind).SetTarget(a.target).SetPid(a.pid).SetKey(key).
		SetSignal(al.RuleID).SetAlertID(al.ID).SetNillableIncidentID(al.IncidentID).
		SetRole(entcontainment.Role(a.role))
	if source != nil {
		create.SetSourceAssetID(source.ID)
	}
	if a.skip != "" {
		if err := create.SetState(entcontainment.StateSkipped).SetReason(a.skip).Exec(ctx); err != nil && !ent.IsConstraintError(err) {
			return err
		}
		return nil
	}
	cmdID := initialCommandID(al.ID, key)
	req := response.Request{CommandID: cmdID, AssetID: a.asset.ID, Kind: a.kind, IncidentID: al.IncidentID, IssuedBy: "auto", AllowEndpoints: e.AllowEndpoints}
	switch a.kind {
	case "kill_process":
		guid, err := uuid.Parse(a.target)
		if err != nil || a.pid == 0 {
			if err := create.SetState(entcontainment.StateSkipped).SetReason("事件没有可核对的进程 GUID 与 PID").Exec(ctx); err != nil && !ent.IsConstraintError(err) {
				return err
			}
			return nil
		}
		if guid, err = e.execHead(ctx, a.asset.ID, guid, a.pid, al.Ts); err != nil {
			return err
		}
		req.ProcessGUID, req.PID = &guid, a.pid
	case "block_network", "quarantine_file", "disable_account", "isolate_container":
		target, err := response.NormalizeTarget(a.kind, a.target, response.ProtectedAddrs(e.AllowEndpoints))
		if err != nil {
			if err := create.SetState(entcontainment.StateSkipped).SetReason("目标不能处置：" + err.Error()).Exec(ctx); err != nil && !ent.IsConstraintError(err) {
				return err
			}
			return nil
		}
		req.Target = target
	}
	if held, err := e.fuse(ctx, a); err != nil || held != "" {
		if err != nil {
			return err
		}
		if err := create.SetState(entcontainment.StateHeld).SetReason(held).Exec(ctx); err != nil {
			if ent.IsConstraintError(err) {
				return nil
			}
			return err
		}
		audit.System(ctx, e.DB, "containment_held", al.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+held)
		return nil
	}

	// 先将待确认记录与确定性 CommandID 持久化，再下发指令：若落库失败绝不调用 Hub.Issue，
	// 若下发后进程中断，原记录已绑定 cmdID 且处于 pending，不会重放新建指令。
	create.SetState(entcontainment.StatePending).SetCommandID(cmdID).SetReason(a.why)
	if _, lease := leases[a.kind]; lease {
		create.SetExpiresAt(expires)
	}
	c, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil
		}
		return err
	}

	cmd, issueErr := e.Hub.Issue(ctx, req)
	if (issueErr != nil && !errors.Is(issueErr, response.ErrDeliveryUnknown) && cmd == nil) ||
		(cmd != nil && (cmd.Status == "failed" || cmd.Status == "unsupported")) {
		detail := ""
		clearCmd := false
		if cmd != nil {
			detail = classifyFailure(a.kind, cmd.Status, cmd.Detail)
		} else if issueErr != nil {
			detail = issueErr.Error()
			if _, lookupErr := e.DB.Command.Get(ctx, cmdID); ent.IsNotFound(lookupErr) {
				clearCmd = true
			}
		}
		audit.System(ctx, e.DB, "containment_failed", al.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+detail)
		reason := a.why + "；下发失败：" + detail
		if issueErr == nil && cmd != nil {
			reason = appendReasonOnce(a.why, detail)
		}
		upd := e.DB.Containment.Update().
			Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StatePending), entcontainment.CommandIDEQ(cmdID)).
			SetState(entcontainment.StateFailed).
			ClearExpiresAt().
			SetReason(reason)
		if clearCmd {
			upd.ClearCommandID()
		}
		return upd.Exec(ctx)
	}
	audit.System(ctx, e.DB, "containment", cmdID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+a.why)
	if cmd != nil && cmd.Status == "succeeded" {
		targetState := entcontainment.StateExecuted
		if _, lease := leases[a.kind]; lease {
			targetState = entcontainment.StateActive
		}
		return e.DB.Containment.Update().
			Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StatePending), entcontainment.CommandIDEQ(cmdID)).
			SetState(targetState).
			Exec(ctx)
	}
	if (cmd != nil && cmd.Status == "unknown") || errors.Is(issueErr, response.ErrDeliveryUnknown) {
		var detail *string
		if cmd != nil {
			detail = cmd.Detail
		}
		reason := appendReasonOnce(a.why, unknownReason(detail))
		_ = e.DB.Containment.Update().
			Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StatePending), entcontainment.CommandIDEQ(cmdID)).
			SetReason(reason).
			Exec(ctx)
	}
	return nil
}

// execHead 进程原地 exec 之后的当前 GUID：sh -c 只有一条命令时直接 exec 成那个程序（COPY TO PROGRAM 'sleep 90'
// 就是 sh 变成 sleep），PID 与父进程不变，agent 给新程序登记新 GUID，拿告警事件的旧 GUID 去结束会被 agent 按身份不符拒绝。
// 找同一主机、同一 PID、同一父进程、不早于它的最近一条启动事件；找不到就是它自己
func (e *Engine) execHead(ctx context.Context, asset, guid uuid.UUID, pid uint32, since time.Time) (uuid.UUID, error) {
	var head uuid.UUID
	err := e.SQL.QueryRowContext(ctx, `WITH origin AS (
  SELECT ts, raw->'process'->'parent_process'->>'pid' AS ppid FROM events
  WHERE asset_id=$1 AND class_uid=1007 AND ts>=$3 AND ts<=$4 AND process_guid=$2 LIMIT 1)
SELECT e.process_guid FROM events e, origin o
WHERE e.asset_id=$1 AND e.class_uid=1007 AND e.ts>=o.ts AND e.ts<=$4 AND e.process_guid IS NOT NULL
  AND e.raw->'process'->>'pid'=$5 AND e.raw->>'activity_id'='1'
  AND e.raw->'process'->'parent_process'->>'pid' IS NOT DISTINCT FROM o.ppid
ORDER BY e.ts DESC LIMIT 1`, asset, guid, since.Add(-time.Minute), e.now(), strconv.FormatUint(uint64(pid), 10)).Scan(&head)
	if errors.Is(err, sql.ErrNoRows) {
		return guid, nil
	}
	return head, err
}

// fuse 熔断：返回非空表示挡下。计入真正生效过与待确认（pending）的处置；确定没送到的（failed）不算，
// 否则几台没装 agent 的受害主机就能把熔断顶满
func (e *Engine) fuse(ctx context.Context, a action) (string, error) {
	executed, err := e.DB.Containment.Query().
		Where(entcontainment.CreatedAtGTE(e.now().Add(-time.Hour)),
			entcontainment.StateIn(entcontainment.StatePending, entcontainment.StateActive, entcontainment.StateExpired, entcontainment.StateExecuted, entcontainment.StateLifted)).
		Count(ctx)
	if err != nil {
		return "", err
	}
	if executed >= e.MaxPerHour {
		return fmt.Sprintf("熔断：一小时内已自动处置 %d 次（上限 %d）", executed, e.MaxPerHour), nil
	}
	if a.kind != "isolate_host" || a.asset.GroupID == nil {
		return "", nil
	}
	hosts, err := e.DB.Asset.Query().Where(entasset.GroupIDEQ(*a.asset.GroupID), entasset.AgentIDNotNil()).Count(ctx)
	if err != nil {
		return "", err
	}
	isolated, err := e.DB.Containment.Query().
		Where(entcontainment.GroupIDEQ(*a.asset.GroupID), entcontainment.KindEQ("isolate_host"),
			entcontainment.StateIn(entcontainment.StatePending, entcontainment.StateActive)).
		Count(ctx)
	if err != nil {
		return "", err
	}
	if limit := max(1, hosts*groupIsolationPercent/100); isolated >= limit {
		return fmt.Sprintf("熔断：组内已隔离 %d 台主机（上限 %d，纳管 %d 台的 %d%%）", isolated, limit, hosts, groupIsolationPercent), nil
	}
	return "", nil
}

// expire 处理到期的租约：配了模型就先请 AI 复核，续期则推迟、解除才下发恢复动作；没配模型或租约已满最长期限就直接解除。
// 解除下发失败（agent 离线）就推迟重试，租约保持生效，不能当成已解除；sent/pending/unknown/unsupported 不重复建指令、待回执对账
func (e *Engine) expire(ctx context.Context) error {
	now := e.now()
	due, err := e.DB.Containment.Query().
		Where(entcontainment.StateEQ(entcontainment.StateActive), entcontainment.ExpiresAtLTE(now)).
		All(ctx)
	if err != nil {
		return err
	}
	for _, c := range due {
		existingCmd, cmdID, prevFailedID, err := resolveLiftCommand(ctx, e.DB, c)
		if err != nil {
			return err
		}
		if existingCmd != nil {
			if c.LiftCommandID == nil || *c.LiftCommandID != existingCmd.ID {
				if err := e.DB.Containment.Update().
					Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateActive)).
					SetLiftCommandID(existingCmd.ID).Exec(ctx); err != nil {
					return err
				}
			}
			if existingCmd.Status == "succeeded" {
				if c.LiftedBy != nil && *c.LiftedBy != "" {
					if err := e.DB.Containment.Update().
						Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateActive), entcontainment.LiftCommandIDEQ(existingCmd.ID)).
						SetState(entcontainment.StateLifted).SetEndedAt(now).Exec(ctx); err != nil {
						return err
					}
				} else {
					n, err := e.DB.Containment.Update().
						Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateActive), entcontainment.LiftCommandIDEQ(existingCmd.ID),
							entcontainment.Or(entcontainment.LiftedByIsNil(), entcontainment.LiftedByEQ(""))).
						SetState(entcontainment.StateExpired).SetEndedAt(now).Save(ctx)
					if err != nil {
						return err
					}
					if n > 0 {
						audit.System(ctx, e.DB, "containment_expired", existingCmd.ID.String(), leases[c.Kind]+" "+c.Target+"（租约到期）")
					}
				}
			}
			continue
		}
		if c.LiftCommandID != nil && *c.LiftCommandID == cmdID {
			continue
		}

		reviewed := prevFailedID != uuid.Nil
		reason := c.Reason
		if !reviewed {
			switch {
			case now.Sub(c.CreatedAt) >= maxLease:
				reason = appendReasonOnce(reason, "已到最长期限 7 天，不再复核，解除")
			case e.LLM != nil && e.LLM.Enabled():
				v := e.review(ctx, c)
				if !v.lift {
					// 正常续一个租约；没拿到有效结论只续一小时，尽快再问
					next := now.Add(e.TTL)
					if v.retry {
						next = now.Add(reviewRetry)
					}
					n, err := e.DB.Containment.Update().
						Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateActive), entcontainment.LiftCommandIDIsNil()).
						SetExpiresAt(next).AddReviews(1).SetReason(c.Reason + "；AI 复核续期：" + v.why).Save(ctx)
					if err != nil {
						return err
					}
					if n > 0 {
						audit.System(ctx, e.DB, "containment_extended", c.ID.String(), c.Kind+" "+c.Target+"：AI 复核续期："+v.why)
					}
					continue
				}
				reason = appendReasonOnce(reason, "AI 复核解除："+v.why)
			}
		}

		reserve := e.DB.Containment.Update().
			Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateActive)).
			SetLiftCommandID(cmdID).
			SetReason(reason)
		if prevFailedID == uuid.Nil {
			reserve.Where(entcontainment.LiftCommandIDIsNil())
		} else {
			reserve.Where(entcontainment.LiftCommandIDEQ(prevFailedID))
		}
		n, err := reserve.Save(ctx)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}

		kind := leases[c.Kind]
		cmd, issueErr := e.Hub.Issue(ctx, response.Request{
			CommandID: cmdID, AssetID: c.AssetID, Kind: kind, Target: c.Target, IncidentID: c.IncidentID, IssuedBy: "auto",
		})
		if (issueErr != nil && !errors.Is(issueErr, response.ErrDeliveryUnknown) && cmd == nil) ||
			(cmd != nil && cmd.Status == "failed") {
			slog.Warn("自主响应解除下发失败，稍后重试", "containment", c.ID, "err", issueErr)
			upd := e.DB.Containment.Update().
				Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateActive), entcontainment.LiftCommandIDEQ(cmdID)).
				SetExpiresAt(now.Add(liftRetry)).SetReason(reason)
			if cmd == nil {
				if _, lookupErr := e.DB.Command.Get(ctx, cmdID); ent.IsNotFound(lookupErr) {
					if prevFailedID == uuid.Nil {
						upd.ClearLiftCommandID()
					} else {
						upd.SetLiftCommandID(prevFailedID)
					}
				}
			}
			if err := upd.Exec(ctx); err != nil {
				return err
			}
			continue
		}
		if cmd != nil && cmd.Status == "unsupported" {
			reason = appendReasonOnce(reason, "解除指令不被 agent 支持，保持生效")
			if err := e.DB.Containment.Update().
				Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateActive), entcontainment.LiftCommandIDEQ(cmdID)).
				SetReason(reason).Exec(ctx); err != nil {
				return err
			}
			continue
		}
		if cmd != nil && cmd.Status == "succeeded" {
			n, err := e.DB.Containment.Update().
				Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateActive), entcontainment.LiftCommandIDEQ(cmdID),
					entcontainment.Or(entcontainment.LiftedByIsNil(), entcontainment.LiftedByEQ(""))).
				SetState(entcontainment.StateExpired).SetEndedAt(now).SetReason(reason).Save(ctx)
			if err != nil {
				return err
			}
			if n > 0 {
				audit.System(ctx, e.DB, "containment_expired", cmd.ID.String(), kind+" "+c.Target+"（租约到期）")
			}
			continue
		}
		if (cmd != nil && cmd.Status == "unknown") || errors.Is(issueErr, response.ErrDeliveryUnknown) {
			reason = appendReasonOnce(reason, "解除执行结果未知（禁止自动重发）")
			_ = e.DB.Containment.Update().
				Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateActive), entcontainment.LiftCommandIDEQ(cmdID)).
				SetReason(reason).Exec(ctx)
		}
	}
	return nil
}
