package agentchat

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/command"
	"openxdr/server/internal/piruntime"
	"openxdr/server/internal/response"
)

var commandStatusTool = piruntime.Tool{
	Name:        "command_status",
	Description: "只读查询当前组已有指令的最新回执。exec 超时或结果未知时先查 command UUID；不会重新执行。succeeded 仅是动作回执，不证明处置有效；pending/sent/unknown 不代表未执行，禁止据此自动重试。",
	Parameters:  json.RawMessage(`{"type":"object","properties":{"command":{"type":"string","format":"uuid"}},"required":["command"],"additionalProperties":false}`),
}

var verifyCommandTool = piruntime.Tool{
	Name: "verify_command",
	Description: "记录当前组已有指令的 AI 效果验证（身份由服务端从当前会话派生为 ai:session:<id>，与人工复核严格区分）。" +
		"无后续活动或无新告警不能证明有效；effective 与 ineffective 必须提供同资产下发后与处置目标匹配的正向事件证据 event_ids，且 effective 要求指令回执已 succeeded；" +
		"下发前事件（如下发前进程已退出）放入 context_event_ids，结论必须为 inconclusive。",
	Parameters: json.RawMessage(`{"type":"object","properties":{"command":{"type":"string","format":"uuid"},"outcome":{"type":"string","enum":["effective","ineffective","inconclusive"]},"method":{"type":"string","enum":["telemetry_post_action","exec_probe","receipt_correlation","context_only","ai_investigation"]},"expected":{"type":"string","minLength":1,"maxLength":4000},"observed":{"type":"string","minLength":1,"maxLength":4000},"event_ids":{"type":"array","items":{"type":"string","format":"uuid"},"maxItems":20},"context_event_ids":{"type":"array","items":{"type":"string","format":"uuid"},"maxItems":20}},"required":["command","outcome","method","expected","observed"],"additionalProperties":false}`),
}

func (s *Service) commandStatus(ctx context.Context, session *ent.AgentSession, args json.RawMessage) (string, error) {
	var body struct {
		Command uuid.UUID `json:"command"`
	}
	decoder := json.NewDecoder(bytes.NewReader(args))
	decoder.DisallowUnknownFields()
	if len(args) > 1024 || decoder.Decode(&body) != nil || body.Command == uuid.Nil || session.GroupID == uuid.Nil {
		return "", errors.New("command 必须为有效指令 UUID")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return "", errors.New("指令查询参数包含多余内容")
	}
	cmd, err := s.DB.Command.Query().Where(command.IDEQ(body.Command), command.HasAssetWith(asset.GroupIDEQ(session.GroupID))).Only(ctx)
	if ent.IsNotFound(err) {
		return "", errors.New("指令不存在或不在当前组")
	}
	if err != nil {
		return "", err
	}
	truncated := cmd.Truncated
	stdout := modelOutput(cmd.Stdout, &truncated)
	stderr := modelOutput(cmd.Stderr, &truncated)
	return marshal(map[string]any{
		"commandId": cmd.ID, "assetId": cmd.AssetID, "kind": cmd.Kind, "status": cmd.Status,
		"createdAt": cmd.CreatedAt, "completedAt": cmd.CompletedAt, "exitCode": cmd.ExitCode,
		"stdout": stdout, "stderr": stderr, "truncated": truncated,
		"effect": "not_assessed_by_this_tool", "retry": "not_authorized_by_this_tool",
	})
}

func (s *Service) verifyCommand(ctx context.Context, session *ent.AgentSession, args json.RawMessage) (string, error) {
	if session == nil || session.ID == uuid.Nil || session.GroupID == uuid.Nil {
		return "", errors.New("会话无效")
	}
	var body struct {
		Command         uuid.UUID   `json:"command"`
		Outcome         string      `json:"outcome"`
		Method          string      `json:"method"`
		Expected        string      `json:"expected"`
		Observed        string      `json:"observed"`
		EventIDs        []uuid.UUID `json:"event_ids"`
		ContextEventIDs []uuid.UUID `json:"context_event_ids"`
	}
	decoder := json.NewDecoder(bytes.NewReader(args))
	decoder.DisallowUnknownFields()
	if len(args) > 16384 || decoder.Decode(&body) != nil || body.Command == uuid.Nil {
		return "", errors.New("verify_command 参数无效")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return "", errors.New("verify_command 参数包含多余内容")
	}
	sqlDB, closeFn, err := s.verificationSQL()
	if err != nil {
		return "", err
	}
	if closeFn != nil {
		defer closeFn()
	}
	v, err := response.RecordMachineVerification(ctx, sqlDB, response.MachineVerificationInput{
		CommandID:       body.Command,
		GroupID:         session.GroupID,
		Source:          "ai",
		Method:          body.Method,
		SessionID:       &session.ID,
		Outcome:         body.Outcome,
		Expected:        body.Expected,
		Observed:        body.Observed,
		EventIDs:        body.EventIDs,
		ContextEventIDs: body.ContextEventIDs,
	})
	if err != nil {
		return "", err
	}
	return marshal(map[string]any{
		"verificationId": v.ID,
		"commandId":      v.CommandID,
		"source":         v.Source,
		"method":         v.Method,
		"reviewer":       v.Reviewer,
		"commandStatus":  v.CommandStatus,
		"outcome":        v.Outcome,
	})
}

func (s *Service) verificationSQL() (*sql.DB, func(), error) {
	if s.SQL != nil {
		return s.SQL, nil, nil
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("INTEGRATION_DATABASE_URL")
	}
	if dsn == "" {
		return nil, nil, errors.New("未配置验证数据库连接")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, nil, err
	}
	return db, func() { _ = db.Close() }, nil
}
