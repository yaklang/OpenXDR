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
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	entasset "openxdr/server/ent/asset"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/response"
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
	if err := e.react(ctx); err != nil {
		return err
	}
	return e.expire(ctx)
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

// react 对回看窗口内有新证据的信号告警逐条做决定。平台指令与已知自动化引起的告警不处置
func (e *Engine) react(ctx context.Context) error {
	now := e.now()
	alerts, err := e.DB.Alert.Query().
		Where(signalAlerts(), alert.AssetIDNotNil(), alert.CommandIDIsNil(), alert.AutomationIDIsNil(),
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

// decide 一条计划处置落表：已有生效租约就续期；人工在最后一条证据之后解除过、或这条告警已经为它做过决定，
// 就不再动；否则新决定，能执行就下发。last 是告警最后一条证据的时间
func (e *Engine) decide(ctx context.Context, al *ent.Alert, source *ent.Asset, a action, last time.Time) error {
	key, expires := a.key(), last.Add(e.TTL)
	active, err := e.DB.Containment.Query().
		Where(entcontainment.KeyEQ(key), entcontainment.StateEQ(entcontainment.StateActive)).
		Only(ctx)
	switch {
	case err == nil:
		if active.ExpiresAt == nil || expires.After(*active.ExpiresAt) {
			return active.Update().SetExpiresAt(expires).Exec(ctx)
		}
		return nil
	case !ent.IsNotFound(err):
		return err
	}
	decided, err := e.DB.Containment.Query().
		Where(entcontainment.KeyEQ(key), entcontainment.Or(
			entcontainment.AlertIDEQ(al.ID),
			entcontainment.And(entcontainment.StateEQ(entcontainment.StateLifted), entcontainment.EndedAtGTE(last)))).
		Exist(ctx)
	if err != nil || decided {
		return err
	}

	create := e.DB.Containment.Create().SetCreatedAt(e.now()).
		SetAssetID(a.asset.ID).SetNillableGroupID(a.asset.GroupID).
		SetKind(a.kind).SetTarget(a.target).SetPid(a.pid).SetKey(key).
		SetSignal(al.RuleID).SetAlertID(al.ID).SetNillableIncidentID(al.IncidentID).
		SetRole(entcontainment.Role(a.role))
	if source != nil {
		create.SetSourceAssetID(source.ID)
	}
	if a.skip != "" {
		return create.SetState(entcontainment.StateSkipped).SetReason(a.skip).Exec(ctx)
	}
	req := response.Request{AssetID: a.asset.ID, Kind: a.kind, IncidentID: al.IncidentID, IssuedBy: "auto", AllowEndpoints: e.AllowEndpoints}
	switch a.kind {
	case "kill_process":
		guid, err := uuid.Parse(a.target)
		if err != nil || a.pid == 0 {
			return create.SetState(entcontainment.StateSkipped).SetReason("事件没有可核对的进程 GUID 与 PID").Exec(ctx)
		}
		req.ProcessGUID, req.PID = &guid, a.pid
	case "block_network", "quarantine_file", "disable_account", "isolate_container":
		target, err := response.NormalizeTarget(a.kind, a.target, response.ProtectedAddrs(e.AllowEndpoints))
		if err != nil {
			return create.SetState(entcontainment.StateSkipped).SetReason("目标不能处置：" + err.Error()).Exec(ctx)
		}
		req.Target = target
	}
	if held, err := e.fuse(ctx, a); err != nil || held != "" {
		if err != nil {
			return err
		}
		audit.System(ctx, e.DB, "containment_held", al.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+held)
		return create.SetState(entcontainment.StateHeld).SetReason(held).Exec(ctx)
	}

	cmd, err := e.Hub.Issue(ctx, req)
	if err != nil || cmd.Status == "failed" {
		detail := ""
		if err != nil {
			detail = err.Error()
		} else if cmd.Detail != nil {
			detail = *cmd.Detail
		}
		audit.System(ctx, e.DB, "containment_failed", al.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+detail)
		create.SetState(entcontainment.StateFailed).SetReason(a.why + "；下发失败：" + detail)
		if cmd != nil {
			create.SetCommandID(cmd.ID)
		}
		return create.Exec(ctx)
	}
	audit.System(ctx, e.DB, "containment", cmd.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+a.why)
	create.SetReason(a.why).SetCommandID(cmd.ID)
	if _, lease := leases[a.kind]; lease {
		return create.SetState(entcontainment.StateActive).SetExpiresAt(expires).Exec(ctx)
	}
	return create.SetState(entcontainment.StateExecuted).Exec(ctx)
}

// fuse 熔断：返回非空表示挡下。只数真正生效过的处置；没送到的不算，
// 否则几台没装 agent 的受害主机就能把熔断顶满
func (e *Engine) fuse(ctx context.Context, a action) (string, error) {
	executed, err := e.DB.Containment.Query().
		Where(entcontainment.CreatedAtGTE(e.now().Add(-time.Hour)),
			entcontainment.StateIn(entcontainment.StateActive, entcontainment.StateExpired, entcontainment.StateExecuted, entcontainment.StateLifted)).
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
			entcontainment.StateEQ(entcontainment.StateActive)).
		Count(ctx)
	if err != nil {
		return "", err
	}
	if limit := max(1, hosts*groupIsolationPercent/100); isolated >= limit {
		return fmt.Sprintf("熔断：组内已隔离 %d 台主机（上限 %d，纳管 %d 台的 %d%%）", isolated, limit, hosts, groupIsolationPercent), nil
	}
	return "", nil
}

// expire 给到期的租约下发解除。解除下发失败（agent 离线）就推迟重试，租约保持生效，不能当成已解除
func (e *Engine) expire(ctx context.Context) error {
	now := e.now()
	due, err := e.DB.Containment.Query().
		Where(entcontainment.StateEQ(entcontainment.StateActive), entcontainment.ExpiresAtLTE(now)).
		All(ctx)
	if err != nil {
		return err
	}
	for _, c := range due {
		kind := leases[c.Kind]
		cmd, err := e.Hub.Issue(ctx, response.Request{
			AssetID: c.AssetID, Kind: kind, Target: c.Target, IncidentID: c.IncidentID, IssuedBy: "auto",
		})
		if err != nil || cmd.Status == "failed" {
			slog.Warn("自主响应解除下发失败，稍后重试", "containment", c.ID, "err", err)
			if err := c.Update().SetExpiresAt(now.Add(liftRetry)).Exec(ctx); err != nil {
				return err
			}
			continue
		}
		audit.System(ctx, e.DB, "containment_expired", cmd.ID.String(), kind+" "+c.Target+"（租约到期）")
		if err := c.Update().SetState(entcontainment.StateExpired).SetLiftCommandID(cmd.ID).SetEndedAt(now).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}
