// Package containment 自主响应：确定性信号命中后，不等研判、不等人，按角色和处置等级直接遏制。
//
// 设计见 docs/autonomous-response-design.md。要点：
//   - 遏制攻击来源，受害方只做外科手术式的处置（封锁来源地址），永远不隔离受害主机
//   - 动作强度看来源的处置等级：实验可以隔离整机，生产与核心不隔离
//   - 每次执行都是租约：证据持续就续期，到期自动解除；没执行的决定也落表，决策记录就是 containments
//   - 熔断：一小时内执行太多、或一个组里隔离的主机太多，就只记录不执行。宁可漏处置，不能让一个误报信号关掉全网
//
// 单活运行（cluster.RunLeader），同一时刻只有一个节点在做决定，表里的键不会并发撞车。
package containment

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	entasset "openxdr/server/ent/asset"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
)

// 自动处置范围：lab 只处置来源是实验等级的攻击（上线初期），all 不限
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

// action 一条计划中的处置：在 asset 上做 kind（封锁时目标是 target）
type action struct {
	asset  *ent.Asset
	kind   string
	target string
	role   string
	// 非空表示按规则就不该自动执行，记 skipped
	skip string
}

func (a action) key() string { return a.asset.ID.String() + "|" + a.kind + "|" + a.target }

// react 对回看窗口内有新证据的信号告警逐条做决定。
func (e *Engine) react(ctx context.Context) error {
	now := e.now()
	alerts, err := e.DB.Alert.Query().
		Where(alert.RuleIDEQ(sigma.RuleLateralSpray), alert.AssetIDNotNil(),
			alert.Or(alert.LastTsGTE(now.Add(-lookback)), alert.And(alert.LastTsIsNil(), alert.TsGTE(now.Add(-lookback)))),
			alert.TsLTE(now)).
		All(ctx)
	if err != nil {
		return err
	}
	for _, al := range alerts {
		plan, err := e.planSpray(ctx, al)
		if err != nil {
			return fmt.Errorf("告警 %s: %w", al.ID, err)
		}
		last := al.Ts
		if al.LastTs != nil {
			last = *al.LastTs
		}
		for _, a := range plan {
			if err := e.decide(ctx, al, a, last.Add(e.TTL)); err != nil {
				return fmt.Errorf("告警 %s 处置 %s: %w", al.ID, a.key(), err)
			}
		}
	}
	return nil
}

// planSpray 内网横向喷洒：来源是告警所在主机，受害方取证据表里窗口内的主机与它们看到的来源地址。
func (e *Engine) planSpray(ctx context.Context, al *ent.Alert) ([]action, error) {
	src, err := e.DB.Asset.Get(ctx, *al.AssetID)
	if err != nil {
		return nil, err
	}
	srcTier, why, err := e.tier(ctx, src)
	if err != nil {
		return nil, err
	}
	last := al.Ts
	if al.LastTs != nil {
		last = *al.LastTs
	}
	rows, err := e.SQL.QueryContext(ctx, `SELECT DISTINCT victim_asset, src_ip FROM lateral_evidence
WHERE src_asset=$1 AND ts>$2 AND ts<=$3 AND src_ip IS NOT NULL AND victim_asset<>src_asset ORDER BY 1, 2`,
		src.ID, al.Ts.Add(-ingest.SprayWindow), last)
	if err != nil {
		return nil, err
	}
	type hit struct {
		victim uuid.UUID
		ip     string
	}
	var hits []hit
	for rows.Next() {
		var h hit
		if err := rows.Scan(&h.victim, &h.ip); err != nil {
			rows.Close()
			return nil, err
		}
		hits = append(hits, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	outOfScope := ""
	if e.Scope != ScopeAll && srcTier != TierLab {
		outOfScope = "自动处置范围只含实验等级的来源，" + src.Hostname + " 是" + tierName(srcTier) + "（" + why + "）"
	}
	var plan []action
	if srcTier == TierLab {
		a := action{asset: src, kind: "isolate_host", role: "source", skip: outOfScope}
		if len(e.AllowEndpoints) == 0 {
			a.skip = "未配置 ISOLATION_ALLOW，隔离后收不到解除指令"
		}
		plan = append(plan, a)
	}
	for _, h := range hits {
		victim, err := e.DB.Asset.Get(ctx, h.victim)
		if err != nil {
			return nil, err
		}
		a := action{asset: victim, kind: "block_network", target: h.ip, role: "victim", skip: outOfScope}
		if a.skip == "" && srcTier == TierCore {
			// 来源与受害方都是核心时不封：两台平台节点互封等于自己切断控制面
			vt, _, err := e.tier(ctx, victim)
			if err != nil {
				return nil, err
			}
			if vt == TierCore {
				a.skip = "来源与受害方都是核心资产，互相封锁会切断控制面"
			}
		}
		plan = append(plan, a)
	}
	return plan, nil
}

// decide 一条计划处置落表：已有生效租约就续期；这条告警已经为它做过决定就不再动；否则新决定，能执行就下发。
func (e *Engine) decide(ctx context.Context, al *ent.Alert, a action, expires time.Time) error {
	key := a.key()
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
		Where(entcontainment.KeyEQ(key), entcontainment.AlertIDEQ(al.ID)).
		Exist(ctx)
	if err != nil || decided {
		return err
	}

	create := e.DB.Containment.Create().SetCreatedAt(e.now()).
		SetAssetID(a.asset.ID).SetNillableGroupID(a.asset.GroupID).
		SetKind(a.kind).SetTarget(a.target).SetKey(key).
		SetSignal(al.RuleID).SetAlertID(al.ID).SetNillableIncidentID(al.IncidentID).
		SetSourceAssetID(*al.AssetID).SetRole(entcontainment.Role(a.role))
	if a.skip != "" {
		return create.SetState(entcontainment.StateSkipped).SetReason(a.skip).Exec(ctx)
	}
	if a.kind == "block_network" {
		target, err := response.NormalizeTarget(a.kind, a.target, response.ProtectedAddrs(e.AllowEndpoints))
		if err != nil {
			return create.SetState(entcontainment.StateSkipped).SetReason("目标不能封锁：" + err.Error()).Exec(ctx)
		}
		a.target = target
	}
	if held, err := e.fuse(ctx, a); err != nil || held != "" {
		if err != nil {
			return err
		}
		audit.System(ctx, e.DB, "containment_held", al.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+held)
		return create.SetState(entcontainment.StateHeld).SetReason(held).Exec(ctx)
	}

	reason := describe(al, a)
	cmd, err := e.Hub.Issue(ctx, response.Request{
		AssetID: a.asset.ID, Kind: a.kind, Target: a.target, IncidentID: al.IncidentID,
		IssuedBy: "auto", AllowEndpoints: e.AllowEndpoints,
	})
	if err != nil || cmd.Status == "failed" {
		detail := ""
		if err != nil {
			detail = err.Error()
		} else if cmd.Detail != nil {
			detail = *cmd.Detail
		}
		audit.System(ctx, e.DB, "containment_failed", al.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+detail)
		create.SetState(entcontainment.StateFailed).SetReason(reason + "；下发失败：" + detail)
		if cmd != nil {
			create.SetCommandID(cmd.ID)
		}
		return create.Exec(ctx)
	}
	audit.System(ctx, e.DB, "containment", cmd.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+reason)
	return create.SetState(entcontainment.StateActive).SetReason(reason).SetCommandID(cmd.ID).SetExpiresAt(expires).Exec(ctx)
}

// fuse 熔断：返回非空表示挡下。只数真正生效过的处置（生效中、已到期解除）；没送到的不算，
// 否则几台没装 agent 的受害主机就能把熔断顶满
func (e *Engine) fuse(ctx context.Context, a action) (string, error) {
	executed, err := e.DB.Containment.Query().
		Where(entcontainment.CreatedAtGTE(e.now().Add(-time.Hour)),
			entcontainment.StateIn(entcontainment.StateActive, entcontainment.StateExpired)).
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
		kind := map[string]string{"isolate_host": "unisolate_host", "block_network": "unblock_network"}[c.Kind]
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

// describe 处置理由，进审计与决策记录，人一眼能看懂为什么动了
func describe(al *ent.Alert, a action) string {
	detail := ""
	if al.Detail != nil {
		detail = "：" + *al.Detail
	}
	switch a.role {
	case "source":
		return "内网横向喷洒的来源，隔离本机" + detail
	default:
		return "遭受来自 " + a.target + " 的内网横向喷洒，封锁该地址" + detail
	}
}
