package agentchat

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/report"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/closurereview"
)

const proposeCloseDescription = "给本组的一个事件提结案建议；证据充分且符合低风险良性条件时交独立审计员复核，其他保留待处理；人工仍可采纳或忽略。" +
	"查证完一个事件后用它代替只在回复里写建议。status 取 false_positive（误报或良性）或 closed（属实且已处置）；" +
	"note 是给人直接采纳的结案说明：定性、关键证据、依据（10–2000 字）；report 可选，填支撑这个结论的报告 id。" +
	"同一事件再提会覆盖上一条建议。"

var proposeCloseParameters = json.RawMessage(`{"type":"object","properties":{` +
	`"incident":{"type":"string"},` +
	`"status":{"type":"string","enum":["false_positive","closed"]},` +
	`"note":{"type":"string","minLength":10,"maxLength":2000},` +
	`"report":{"type":"string"}},` +
	`"required":["incident","status","note"],"additionalProperties":false}`)

// proposeClose 写结案建议。事件的告警必须全部落在本组资产上：跨组的事件不归这个会话管
func (s *Service) proposeClose(ctx context.Context, session *ent.AgentSession, args json.RawMessage) (string, error) {
	var body struct {
		Incident uuid.UUID `json:"incident"`
		Status   string    `json:"status"`
		Note     string    `json:"note"`
		Report   string    `json:"report"`
	}
	if err := json.Unmarshal(args, &body); err != nil {
		return "", err
	}
	if body.Status != "false_positive" && body.Status != "closed" {
		return "", errors.New("status 只能是 false_positive 或 closed")
	}
	note := strings.TrimSpace(body.Note)
	if n := utf8.RuneCountInString(note); n < 10 || n > 2000 {
		return "", errors.New("note 须为 10–2000 字")
	}
	inc, err := s.DB.Incident.Get(ctx, body.Incident)
	if ent.IsNotFound(err) {
		return "", errors.New("没有这个事件")
	}
	if err != nil {
		return "", err
	}
	if inc.Status == "closed" || inc.Status == "false_positive" {
		return marshal(map[string]any{"status": "already_closed", "note": "事件已经结案"})
	}
	inGroup := alert.HasAssetWith(asset.GroupIDEQ(session.GroupID))
	total, err := s.DB.Alert.Query().Where(alert.IncidentIDEQ(inc.ID)).Count(ctx)
	if err != nil {
		return "", err
	}
	mine, err := s.DB.Alert.Query().Where(alert.IncidentIDEQ(inc.ID), inGroup).Count(ctx)
	if err != nil {
		return "", err
	}
	if total == 0 || mine != total {
		return "", errors.New("事件不全在本组资产上，不能提结案建议")
	}
	proposal := &schema.ClosureProposal{Status: body.Status, Note: note, SessionID: session.ID, At: time.Now()}
	if body.Report != "" {
		id, err := uuid.Parse(body.Report)
		if err != nil {
			return "", errors.New("report 必须是报告 id")
		}
		ok, err := s.DB.Report.Query().Where(report.IDEQ(id), report.GroupIDEQ(session.GroupID)).Exist(ctx)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errors.New("本组没有这份报告")
		}
		proposal.ReportID = &id
	}
	if err := closurereview.BindProposal(ctx, s.DB, inc, session.GroupID, proposal); err != nil {
		return "", err
	}
	n, err := s.DB.Incident.Update().Where(incident.IDEQ(inc.ID), incident.StatusNotIn("closed", "false_positive")).
		SetClosureProposal(proposal).Save(ctx)
	if err != nil {
		return "", err
	}
	if n != 1 {
		return marshal(map[string]any{"status": "already_closed", "note": "事件已经结案"})
	}
	return marshal(map[string]any{"status": "proposed", "note": "结案建议已提交；证据充分且符合条件时由独立审计员复核，否则保留待处理"})
}
