package agentchat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/finding"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/piruntime"
	"openxdr/server/internal/repaircmd"
	"time"
)

var repairCapabilitiesTool = piruntime.Tool{Name: "repair_capabilities", Description: "只读查询当前组待办的支持模板、精确维护范围、冷却/窗口时间及本会话固定探针要求。command 为完整精确命令；此查询不授予权限，不消耗预算。", Parameters: json.RawMessage(`{"type":"object","properties":{"finding_id":{"type":"string","format":"uuid"},"command":{"type":"string","maxLength":512},"mount":{"type":"string","maxLength":256}},"required":["finding_id"],"additionalProperties":false}`)}

func (s *Service) repairCapabilities(ctx context.Context, session *ent.AgentSession, args json.RawMessage) (string, error) {
	var body struct {
		FindingID uuid.UUID `json:"finding_id"`
		Command   string    `json:"command"`
		Mount     string    `json:"mount"`
	}
	decoder := json.NewDecoder(bytes.NewReader(args))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return "", err
	}
	if len(body.Command) > 512 || len(body.Mount) > 256 || body.Mount != "" && !repaircmd.Mount(body.Mount) {
		return "", errors.New("修复命令或挂载点无效")
	}
	f, err := s.DB.Finding.Query().Where(finding.IDEQ(body.FindingID), finding.GroupIDEQ(session.GroupID)).Only(ctx)
	if err != nil {
		return "", err
	}
	if s.FindingRepairCapabilities == nil {
		return "", errors.New("未配置可信能力查询")
	}
	state, err := s.FindingRepairCapabilities(ctx, session, f, body.Command, body.Mount)
	if err != nil {
		return "", err
	}
	return marshal(state)
}

type findingPlanOptions struct {
	RepairCommand string       `json:"repair_command"`
	RepairMount   string       `json:"repair_mount"`
	DependsOn     *[]uuid.UUID `json:"depends_on"`
	WakeAt        *time.Time   `json:"wake_at"`
}

func (s *Service) preparePlanConditions(ctx context.Context, session *ent.AgentSession, f *ent.Finding, w *findings.Work, opts findingPlanOptions) (*findings.RepairCapabilities, error) {
	if len(opts.RepairCommand) > 512 {
		return nil, errors.New("精确修复命令最多512字节")
	}
	if opts.RepairMount != "" && !repaircmd.Mount(opts.RepairMount) {
		return nil, errors.New("repair_mount 必须是规范挂载点")
	}
	if opts.RepairCommand != "" {
		w.RepairCommand = opts.RepairCommand
	}
	if opts.RepairMount != "" {
		w.RepairMount = opts.RepairMount
	}
	if opts.WakeAt != nil {
		now := time.Now()
		if opts.WakeAt.Before(now.Add(5*time.Minute)) || opts.WakeAt.After(now.Add(30*24*time.Hour)) {
			return nil, errors.New("wake_at 须在5分钟至30天内，只安排只读重评估，不表示维护授权")
		}
		w.WakeAt = opts.WakeAt
	}
	if opts.DependsOn != nil {
		if err := findings.ValidateDependencies(ctx, s.DB, session.GroupID, f.ID, *opts.DependsOn); err != nil {
			return nil, err
		}
		fp, _, err := findings.DependencyState(ctx, s.DB, session.GroupID, f.ID, *opts.DependsOn)
		if err != nil {
			return nil, err
		}
		w.DependsOn = *opts.DependsOn
		w.DependencyFingerprint = fp
	}
	if s.FindingRepairCapabilities == nil {
		return nil, nil
	}
	state, err := s.FindingRepairCapabilities(ctx, session, f, w.RepairCommand, w.RepairMount)
	if err != nil {
		return nil, err
	}
	w.PolicyFingerprint = state.PolicyFingerprint
	if state.RetryAt != nil {
		w.RetryAt = state.RetryAt
	} else if state.Status != "action_required" {
		w.RetryAt = nil
	}
	return &state, nil
}
func (s *Service) recordRepairBlocker(ctx context.Context, session *ent.AgentSession, f *ent.Finding, cmd string, cause error) error {
	var denied *findings.RepairError
	if !errors.As(cause, &denied) || !findings.MachineBlocker(denied.State.Status) && denied.State.Status != "maintenance_window_required" {
		return nil
	}
	var w findings.Work
	if len(f.Work) > 0 {
		if err := json.Unmarshal(f.Work, &w); err != nil {
			return err
		}
	}
	if f.WorkOwner == "human" || w.Blocker == "manual_business_decision" || w.Blocker == "legacy_decommission_confirm" || w.Blocker == "external_dependency" {
		return nil
	}
	return s.saveFindingPlan(ctx, session, f, "", denied.State.Status, nil, findingPlanOptions{RepairCommand: cmd})
}
