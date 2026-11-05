package agentchat

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
	"openxdr/server/ent/alert"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/response"
	"openxdr/server/internal/triage"
)

const (
	endpointEvidenceTotalTimeout = 12 * time.Second
	endpointEvidenceWaitBudget   = 6 * time.Second
	endpointEvidenceCmdTimeoutMS = 5000
)

// CollectEndpointEvidence 执行 triage 受控端点只读模板补证：
//   - 强制校验 commandgate.ReadOnly、Linux 资产、agent 已绑定、事件与资产同组归属；
//   - 按 (incident_id, evidence_version, asset_id, template) 派生确定性 CommandID，
//     对已有 pending/sent/unknown/终态指令仅查回执，绝不重复生成或重放命令；
//   - 生成绑定 incident/组/短租约的 system 任务会话，经 Gate.Issue 走完整组权限、名单/AI 审计员、硬拒绝与审计链路。
func (s *Service) CollectEndpointEvidence(ctx context.Context, req triage.EndpointEvidenceRequest) (res *triage.EndpointEvidenceResult, retErr error) {
	if s == nil || s.DB == nil || s.Gate == nil {
		return nil, errors.New("端点受控取证服务未初始化")
	}
	if req.IncidentID == uuid.Nil || req.GroupID == uuid.Nil || req.AssetID == uuid.Nil || req.Template == "" || strings.TrimSpace(req.Command) == "" {
		return nil, errors.New("端点受控取证请求参数不完整")
	}
	if !commandgate.ReadOnly(req.Command) {
		return nil, errors.New("端点取证命令未通过只读安全校验")
	}

	ctx, cancel := context.WithTimeout(ctx, endpointEvidenceTotalTimeout)
	defer cancel()

	host, err := s.verifyEndpointEvidenceScope(ctx, req)
	if err != nil {
		return nil, err
	}

	cmdID := triage.EndpointEvidenceCommandID(req.IncidentID, req.EvidenceKey, req.EvidenceVersion, req.AssetID, req.Template)
	existing, getErr := s.DB.Command.Get(ctx, cmdID)
	if getErr != nil && !ent.IsNotFound(getErr) {
		return nil, getErr
	}
	if existing != nil {
		if existing.AssetID != req.AssetID || existing.Kind != "exec" || existing.Cmd == nil || *existing.Cmd != req.Command ||
			existing.IncidentID == nil || *existing.IncidentID != req.IncidentID {
			return nil, errors.New("端点取证幂等指令身份冲突")
		}
		if existing.Status == "pending" || existing.Status == "sent" {
			existing = s.waitEndpointEvidenceReceipt(ctx, existing, endpointEvidenceWaitBudget)
		}
		if _, err := s.verifyEndpointEvidenceScope(ctx, req); err != nil {
			return nil, err
		}
		return toEndpointEvidenceResult(existing, req), nil
	}

	if host.AgentID == nil || *host.AgentID == uuid.Nil {
		return nil, errors.New("目标主机未纳管或未绑定 agent")
	}
	if host.Os == nil || !strings.EqualFold(strings.TrimSpace(*host.Os), "linux") {
		return nil, errors.New("受控只读取证模板仅支持已识别为 Linux 的受管主机")
	}
	if s.Gate.Hub == nil || !s.Gate.Hub.Enabled {
		return nil, errors.New("响应能力未启用")
	}
	if !s.Gate.Hub.Online(*host.AgentID) {
		return nil, errors.New("目标主机 agent 离线，未连接指令通道")
	}

	deadline := time.Now().Add(30 * time.Second)
	session, err := s.DB.AgentSession.Create().
		SetKind("task").
		SetGroupID(req.GroupID).
		SetInitiator(commandgate.SystemActor).
		SetTitle("研判受控只读补证").
		SetSubjects([]string{"incident:" + req.IncidentID.String()}).
		SetModel("system-readonly-template").
		SetStatus("running").
		SetRunDeadlineAt(deadline).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	workCtx, owner, stopLease, err := s.startTaskLease(ctx, session)
	if err != nil {
		_ = s.DB.AgentSession.UpdateOneID(session.ID).SetStatus("failed").ClearRunOwner().ClearRunExpiresAt().Exec(context.WithoutCancel(ctx))
		return nil, err
	}
	defer func() {
		stopLease()
		finalStatus := "succeeded"
		if retErr != nil {
			finalStatus = "failed"
		}
		finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer finishCancel()
		_ = s.DB.AgentSession.Update().
			Where(agentsession.IDEQ(session.ID), agentsession.RunOwnerEQ(owner)).
			SetStatus(finalStatus).
			SetFinishedAt(time.Now()).
			ClearRunOwner().
			ClearRunExpiresAt().
			Exec(finishCtx)
	}()

	if _, err := s.guardTool(workCtx, session, "exec"); err != nil {
		return nil, err
	}

	cmdText := req.Command
	cmd, issueErr := s.Gate.Issue(workCtx, commandgate.Request{
		System:          true,
		PreferReviewer:  true,
		GroupID:         req.GroupID,
		SessionID:       &session.ID,
		Origin:          "ai",
		ApprovalTimeout: 5 * time.Second,
		Command: response.Request{
			CommandID:  cmdID,
			Kind:       "exec",
			AssetID:    host.ID,
			IncidentID: &req.IncidentID,
			Cmd:        &cmdText,
			TimeoutMS:  endpointEvidenceCmdTimeoutMS,
		},
	})
	if issueErr != nil && (!errors.Is(issueErr, response.ErrDeliveryUnknown) || cmd == nil) {
		return nil, issueErr
	}
	if cmd == nil {
		return nil, errors.New("端点取证未生成指令记录")
	}
	if cmd.Status == "pending" || cmd.Status == "sent" {
		cmd = s.waitEndpointEvidenceReceipt(workCtx, cmd, endpointEvidenceWaitBudget)
	}
	if _, err := s.verifyEndpointEvidenceScope(ctx, req); err != nil {
		return nil, err
	}
	return toEndpointEvidenceResult(cmd, req), nil
}

func (s *Service) verifyEndpointEvidenceScope(ctx context.Context, req triage.EndpointEvidenceRequest) (*ent.Asset, error) {
	allowed, err := s.incidentInGroup(ctx, req.IncidentID, req.GroupID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, errors.New("安全事件不在当前资产组或关联资产已发生转组")
	}
	inIncident, err := s.DB.Alert.Query().Where(alert.IncidentIDEQ(req.IncidentID), alert.AssetIDEQ(req.AssetID)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if !inIncident {
		return nil, errors.New("目标资产不属于当前安全事件关联主机")
	}
	host, err := s.DB.Asset.Get(ctx, req.AssetID)
	if err != nil {
		return nil, errors.New("目标资产不存在")
	}
	if host.GroupID == nil || *host.GroupID != req.GroupID {
		return nil, errors.New("目标资产已不在当前资产组")
	}
	return host, nil
}

func (s *Service) waitEndpointEvidenceReceipt(ctx context.Context, cmd *ent.Command, budget time.Duration) *ent.Command {
	waitCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	current := cmd
	for current.Status == "pending" || current.Status == "sent" {
		select {
		case <-waitCtx.Done():
			return current
		case <-ticker.C:
			next, err := s.DB.Command.Get(waitCtx, current.ID)
			if err != nil {
				return current
			}
			current = next
		}
	}
	return current
}

func toEndpointEvidenceResult(cmd *ent.Command, req triage.EndpointEvidenceRequest) *triage.EndpointEvidenceResult {
	var rawOut, rawErr string
	if cmd.Stdout != nil {
		rawOut = *cmd.Stdout
	}
	if cmd.Stderr != nil {
		rawErr = *cmd.Stderr
	}
	stdout, stderr, truncated := triage.TrimEndpointEvidenceStreams(rawOut, rawErr, cmd.Truncated)
	observedAt := cmd.CreatedAt.UTC()
	if cmd.CompletedAt != nil && !cmd.CompletedAt.IsZero() {
		observedAt = cmd.CompletedAt.UTC()
	}
	out := &triage.EndpointEvidenceResult{
		CommandID:  cmd.ID.String(),
		AssetID:    cmd.AssetID.String(),
		Template:   req.Template,
		Status:     cmd.Status,
		ExitCode:   cmd.ExitCode,
		Stdout:     stdout,
		Stderr:     stderr,
		Truncated:  truncated,
		ObservedAt: observedAt,
		Coverage:   req.Coverage,
	}
	if !req.Since.IsZero() {
		out.From = req.Since.UTC().Format(time.RFC3339)
	}
	if !req.Until.IsZero() {
		out.To = req.Until.UTC().Format(time.RFC3339)
	}
	return out
}
