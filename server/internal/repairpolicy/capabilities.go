package repairpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/repaircmd"
)

// Capabilities 只读查询精确动作的前置条件；执行仍由 Authorize/Revalidate 独立重新核验。
func (s *Store) Capabilities(ctx context.Context, group, session uuid.UUID, f *ent.Finding, cmd, mount string) (findings.RepairCapabilities, error) {
	out := findings.RepairCapabilities{SupportedTemplates: []string{"systemctl restart -- <非关键服务.service>", "docker image prune -f", "docker image prune -a --filter until=168h -f", "docker builder prune -f", "docker builder prune --filter until=168h -f", "apt-get clean", "journalctl --vacuum-size=500M", "find -- <授权目录> -xdev -type f -mtime +<7..3650> -delete"}, Grants: []findings.RepairGrant{}, Command: cmd, Status: "action_required", Reason: "请选择精确修复命令，再检查授权、窗口、冷却与本轮探针"}
	if f == nil {
		return out, errors.New("缺少待办")
	}
	actual, err := s.DB.Finding.Get(ctx, f.ID)
	if err != nil {
		return out, err
	}
	if actual.GroupID != group {
		return out, errors.New("待办不属于当前组")
	}
	owned, err := s.DB.Asset.Query().Where(asset.IDEQ(actual.AssetID), asset.GroupIDEQ(group)).Only(ctx)
	if err != nil {
		return out, err
	}
	var w findings.Work
	if len(actual.Work) > 0 {
		if err := json.Unmarshal(actual.Work, &w); err != nil {
			return out, err
		}
	}
	p, err := s.Load(ctx)
	if err != nil {
		return out, err
	}
	now := time.Now()
	extra, err := standingGrants(ctx, s.DB, group, actual.AssetID, now, false)
	if err != nil {
		return out, err
	}
	p.Grants = append(p.Grants, extra...)
	versions := []string{}
	for _, g := range p.Grants {
		if !grantScopeValid(g, group, actual.AssetID, now) {
			continue
		}
		versions = append(versions, grantVersion(g))
		entry := findings.RepairGrant{Action: g.Action, Units: g.Units, Paths: g.Paths, NotBefore: g.NotBefore, ExpiresAt: g.ExpiresAt, RequiredProbes: []string{}}
		units := g.Units
		if g.Action == ReclaimDisk {
			units = []string{ReclaimDisk}
			entry.RequiredProbes = []string{"df -P <挂载点>（单条命令，本轮新鲜回执）"}
		}
		for _, unit := range units {
			if g.Action == RestartFailedService {
				entry.RequiredProbes = append(entry.RequiredProbes, ProbeCommand(unit))
			}
			row, err := s.DB.Setting.Get(ctx, useKey(actual.AssetID, unit))
			if err != nil && !ent.IsNotFound(err) {
				return out, err
			}
			if row != nil {
				var u use
				if err := strict(row.Value, &u); err != nil {
					return out, err
				}
				if u.NextAllowedAt.After(now) && (entry.CooldownUntil == nil || u.NextAllowedAt.After(*entry.CooldownUntil)) {
					at := u.NextAllowedAt
					entry.CooldownUntil = &at
				}
			}
		}
		if w.Blocker == "maintenance_window_required" && g.NotBefore != nil && g.NotBefore.After(now) && (out.RetryAt == nil || g.NotBefore.Before(*out.RetryAt)) {
			out.RetryAt = g.NotBefore
		}
		out.Grants = append(out.Grants, entry)
	}
	slices.Sort(versions)
	out.PolicyFingerprint = digest(versions)
	reject := func(code, reason string) (findings.RepairCapabilities, error) {
		out.Status, out.Reason = code, reason
		return out, nil
	}
	if cmd != "" {
		switch w.Blocker {
		case "manual_business_decision", "legacy_decommission_confirm":
			return reject(w.Blocker, "业务决定和退役确认尚未解除，不能通过变换命令或分类自动修复")
		case "external_dependency":
			_, all, err := findings.DependencyState(ctx, s.DB, group, actual.ID, w.DependsOn)
			if err != nil {
				return out, err
			}
			if !all {
				return reject("external_dependency", "已登记的上游依赖尚未确认恢复，仅允许只读跟进")
			}
		}
	}
	if cmd != "" && len(w.DependsOn) > 0 {
		_, all, err := findings.DependencyState(ctx, s.DB, group, actual.ID, w.DependsOn)
		if err != nil {
			return out, err
		}
		if !all {
			return reject("external_dependency", "登记的上游依赖尚未确认恢复或已重新打开")
		}
	}
	if cmd == "" {
		return out, nil
	}
	action, unit := RestartFailedService, ""
	if match := restart.FindStringSubmatch(cmd); len(match) == 2 && validUnit(match[1]) {
		unit = match[1]
	} else if _, ok := repaircmd.Parse(cmd); ok && diskFinding(actual) {
		action, unit = ReclaimDisk, ReclaimDisk
	} else {
		return reject("action_unsupported", "该命令或待办类型不属于平台支持的封闭修复模板，新增授权不能使任意命令可执行")
	}
	if action == ReclaimDisk {
		m := mount
		if m == "" {
			m = w.RepairMount
		}
		if m == "" {
			m = "<挂载点>"
		}
		out.Probe = "df -P " + m
	} else {
		out.Probe = ProbeCommand(unit)
	}
	if owned.Os == nil || *owned.Os != "linux" {
		return reject("action_unsupported", "修复模板仅支持指定组内的 Linux 资产")
	}
	if w.RepairAttempts < 0 || w.RepairAttempts >= findings.RepairBudget {
		return reject("budget_exhausted", "修复预算已耗尽或异常，只读调查仍可继续")
	}
	if actual.WorkOwner == "human" {
		return reject("permission", "人工持有的待办仅允许自动只读复查")
	}
	var grant *Grant
	var window *time.Time
	scopedWithoutWindow := false
	for i := range p.Grants {
		g := &p.Grants[i]
		if !grantScopeValid(*g, group, actual.AssetID, now) || !actionScope(*g, action, unit, cmd) {
			continue
		}
		if g.NotBefore != nil && g.NotBefore.After(now) {
			if window == nil || g.NotBefore.Before(*window) {
				window = g.NotBefore
			}
			continue
		}
		if w.Blocker == "maintenance_window_required" && g.NotBefore == nil {
			scopedWithoutWindow = true
			continue
		}
		grant = g
		break
	}
	if grant == nil {
		if window != nil {
			out.RetryAt = window
			return reject("maintenance_window_required", "管理员配置的维护窗口尚未开始")
		}
		if scopedWithoutWindow {
			return reject("maintenance_window_required", "尚未配置适用于此精确动作的管理员维护窗口")
		}
		return reject("policy_required", "当前没有覆盖此组、资产和精确动作/服务/目录的有效维护授权")
	}
	old, err := s.DB.Setting.Get(ctx, useKey(actual.AssetID, unit))
	if err != nil && !ent.IsNotFound(err) {
		return out, err
	}
	if old != nil {
		var u use
		if err := strict(old.Value, &u); err != nil {
			return out, err
		}
		if u.SessionID == session || u.NextAllowedAt.After(now) {
			out.RetryAt = &u.NextAllowedAt
			return reject("cooldown", "原动作已预留或资产动作仍在冷却期；先查原回执，不重放")
		}
	}
	if mount == "" {
		mount = w.RepairMount
	}
	refRow, err := s.DB.Setting.Get(ctx, probeKey(actual.AssetID, unit))
	if err != nil && !ent.IsNotFound(err) {
		return out, err
	}
	if refRow == nil {
		if action == ReclaimDisk && mount == "" {
			mount = "/"
		}
		out.Probe = expectedProbe(action, unit, mount)
		return reject("probe_invalid", "缺少本会话单独下发的固定只读探针，不能复用其它会话回执")
	}
	var ref probeRef
	if err := strict(refRow.Value, &ref); err != nil {
		return out, err
	}
	if action == ReclaimDisk && mount == "" {
		mount = ref.Unit
	}
	if action == ReclaimDisk && !repaircmd.Mount(mount) {
		return reject("probe_invalid", "磁盘探针挂载点无效")
	}
	out.Probe = expectedProbe(action, unit, mount)
	if ref.SessionID != session || ref.AssetID != actual.AssetID || (action == RestartFailedService && ref.Unit != unit) || (action == ReclaimDisk && ref.Unit != mount) {
		return reject("probe_invalid", "固定探针属于其它会话、资产、服务或挂载点，请重新取本轮探针")
	}
	probe, err := s.DB.Command.Get(ctx, ref.CommandID)
	if err != nil {
		return out, err
	}
	active, err := s.DB.AgentSession.Get(ctx, session)
	if err != nil {
		return out, err
	}
	if probe.AssetID != actual.AssetID || probe.Kind != "exec" || probe.Cmd == nil || *probe.Cmd != out.Probe || probe.Status != "succeeded" || probe.ExitCode == nil || *probe.ExitCode != 0 || probe.Truncated || probe.CompletedAt == nil || probe.CompletedAt.Before(now.Add(-10*time.Minute)) || probe.CompletedAt.After(now) || probe.CreatedAt.Before(active.CreatedAt) || probe.Stdout == nil {
		return reject("probe_invalid", "探针过期、不完整、失败或不属于本轮，请重新取完整回执")
	}
	if action == ReclaimDisk {
		if _, err := diskSample(probe, mount); err != nil {
			return reject("probe_invalid", err.Error())
		}
	} else {
		fields := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(*probe.Stdout), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				return reject("probe_invalid", "服务探针字段无效")
			}
			if _, dup := fields[k]; dup {
				return reject("probe_invalid", "服务探针字段重复")
			}
			fields[k] = v
		}
		if len(fields) != 3 || fields["Id"] != unit || fields["ActiveState"] != "failed" || fields["UnitFileState"] != "enabled" {
			return reject("probe_invalid", "探针未证明精确服务 failed 且 enabled")
		}
	}
	out.ProbeID = &probe.ID
	out.Status = "ready"
	out.Reason = "前置条件快照可用；实际执行仍须有效领取、组权限、审批、全局开关、签名及下发前复核"
	return out, nil
}
