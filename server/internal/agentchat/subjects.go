package agentchat

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/command"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/incident"
)

// subjectsPrompt 会话绑定了事件或待办时追加的说明；结案留给人，因为结案备注会作为人工案例喂回研判。
const subjectsPrompt = "subjects 是用户从界面交给你处理的事件或待办，平台每轮按库里的当前状态提供：围绕它们调查、核实并处置，需要执行的命令照常直接下发，高风险命令与抑制提议照常由 AI 审计员当场评审。" +
	"指令 succeeded 只说明执行回执成功，不证明处置有效；结果未知时先用 command_status 查回执，不要重复执行。结合最新告警与独立复查结果判断效果。" +
	"事件由人在界面上结案：查证完每个事件用 propose_close 提结案建议（属实已处置 closed / 误报或良性 false_positive，附定性与关键证据），人在事件页一键采纳；待办处理好并复查确认后，用 track 标 resolved（host 与 key 取 subject 里的值）。"

// roster 交来的对象逐条列进系统提示：只放在数据里时，模型会数错个数、做完一部分就收工
func roster(subjects []map[string]any) string {
	var b strings.Builder
	b.WriteString("本会话交给你 " + strconv.Itoa(len(subjects)) + " 个对象，必须逐个处理，全部处理完才算结束，结尾逐个说明结果：")
	for i, sub := range subjects {
		b.WriteString(strconv.Itoa(i+1) + ". ")
		if sub["kind"] == "finding" {
			b.WriteString(fmt.Sprintf("待办 %v / %v：%v；", sub["hostname"], sub["key"], sub["title"]))
		} else {
			title, _ := sub["title"].(*string)
			b.WriteString(fmt.Sprintf("事件 %v：%s；", sub["id"], deref(title)))
		}
	}
	return b.String()
}

func deref(s *string) string {
	if s == nil {
		return "（无标题）"
	}
	return *s
}

type subjectAlert struct {
	Rule     string `json:"rule"`
	Severity int16  `json:"severity"`
	Host     string `json:"host,omitempty"`
	Count    int    `json:"count"`
	First    string `json:"first"`
	Evidence string `json:"evidence,omitempty"`
}

// subjectsFor 会话绑定对象的当前状态。对象已删除就跳过，不让整轮请求失败。
func (s *Service) subjectsFor(ctx context.Context, session *ent.AgentSession, hostnames map[uuid.UUID]string) ([]map[string]any, error) {
	out := []map[string]any{}
	for _, subject := range session.Subjects {
		kind, raw, _ := strings.Cut(subject, ":")
		id, err := uuid.Parse(raw)
		if err != nil {
			continue
		}
		var item map[string]any
		switch kind {
		case "incident":
			item, err = s.incidentSubject(ctx, id, session.GroupID, hostnames)
		case "finding":
			item, err = s.findingSubject(ctx, id, session.GroupID, hostnames)
		}
		if ent.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if item != nil {
			out = append(out, item)
		}
	}
	return out, nil
}

func (s *Service) incidentSubject(ctx context.Context, id, group uuid.UUID, hostnames map[uuid.UUID]string) (map[string]any, error) {
	allowed, err := s.incidentInGroup(ctx, id, group)
	if err != nil || !allowed {
		return nil, err
	}
	inc, err := s.DB.Incident.Query().Where(incident.IDEQ(id)).Only(ctx)
	if err != nil {
		return nil, err
	}
	// 最要紧的 10 条：级别高的在前，同级按时间
	alerts, err := s.DB.Alert.Query().Where(alert.IncidentIDEQ(id)).
		Order(ent.Desc(alert.FieldSeverity), ent.Asc(alert.FieldTs)).Limit(10).WithEvent().All(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]subjectAlert, len(alerts))
	for i, a := range alerts {
		rule := a.RuleID
		if s.Rules != nil {
			if title := s.Rules.TitleOf(a.RuleID); title != "" {
				rule = title
			}
		}
		row := subjectAlert{Rule: rule, Severity: a.Severity, Count: a.Count, First: a.Ts.Format("2006-01-02 15:04:05")}
		if a.AssetID != nil {
			row.Host = hostnames[*a.AssetID]
		}
		if a.Edges.Event != nil {
			row.Evidence = evidence(a.Edges.Event.Raw)
		}
		rows[i] = row
	}
	commands, err := s.DB.Command.Query().Where(command.IncidentIDEQ(id), command.HasAssetWith(asset.GroupIDEQ(group))).
		Order(ent.Desc(command.FieldCreatedAt), ent.Desc(command.FieldID)).Limit(10).
		Select(command.FieldID, command.FieldAssetID, command.FieldKind, command.FieldStatus, command.FieldCreatedAt, command.FieldCompletedAt, command.FieldExitCode).All(ctx)
	if err != nil {
		return nil, err
	}
	receipts := make([]map[string]any, 0, len(commands))
	for _, c := range commands {
		receipts = append(receipts, map[string]any{"id": c.ID, "host": c.AssetID, "kind": c.Kind, "status": c.Status,
			"created_at": c.CreatedAt, "completed_at": c.CompletedAt, "exit_code": c.ExitCode})
	}
	total, err := s.DB.Alert.Query().Where(alert.IncidentIDEQ(id)).Count(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"alert_count": total, "alerts_truncated": total > len(rows), "recent_commands": receipts,
		"triaged_at": inc.TriagedAt, "evidence_at": inc.EvidenceAt, "closure_proposal": inc.ClosureProposal,
		"resolution": inc.Resolution, "resolved_at": inc.ResolvedAt,
		"kind": "incident", "id": inc.ID, "title": inc.Title, "status": inc.Status,
		"created_at": inc.CreatedAt, "ai_verdict": inc.AiVerdict, "alerts": rows,
	}, nil
}

func (s *Service) findingSubject(ctx context.Context, id, group uuid.UUID, hostnames map[uuid.UUID]string) (map[string]any, error) {
	f, err := s.DB.Finding.Query().Where(finding.IDEQ(id), finding.GroupIDEQ(group)).Only(ctx)
	if err != nil {
		return nil, err
	}
	allowed, err := s.DB.Asset.Query().Where(asset.IDEQ(f.AssetID), asset.GroupIDEQ(group)).Exist(ctx)
	if err != nil || !allowed {
		return nil, err
	}
	return map[string]any{
		"kind": "finding", "id": f.ID, "host": f.AssetID, "hostname": hostnames[f.AssetID], "key": f.Key,
		"title": f.Title, "detail": f.Detail, "severity": f.Severity, "status": f.Status, "note": f.Note,
		"work_owner": f.WorkOwner, "work": findingWorkJSON(f), "next_check_at": f.WorkNextCheckAt, "work_attempts": f.WorkAttempts,
	}, nil
}

// evidence 告警事件里最能说明发生了什么的那一项：命令行 / 文件路径 / 连接目标，截到 200 字
func evidence(raw json.RawMessage) string {
	var r struct {
		Process struct {
			CmdLine string `json:"cmd_line"`
		} `json:"process"`
		File struct {
			Path string `json:"path"`
		} `json:"file"`
		Dst struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		} `json:"dst_endpoint"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return ""
	}
	text := r.Process.CmdLine
	if text == "" {
		text = r.File.Path
	}
	if text == "" && r.Dst.IP != "" {
		text = "→ " + r.Dst.IP
		if r.Dst.Port > 0 {
			text += ":" + strconv.Itoa(r.Dst.Port)
		}
	}
	if utf8.RuneCountInString(text) > 200 {
		text = string([]rune(text)[:200]) + "…"
	}
	return text
}

// incidentInGroup 每次交接与关联指令时重查，资产转组后不能沿用旧会话的可见范围。
func (s *Service) incidentInGroup(ctx context.Context, id, group uuid.UUID) (bool, error) {
	total, err := s.DB.Alert.Query().Where(alert.IncidentIDEQ(id)).Count(ctx)
	if err != nil || total == 0 {
		return false, err
	}
	mine, err := s.DB.Alert.Query().Where(alert.IncidentIDEQ(id), alert.HasAssetWith(asset.GroupIDEQ(group))).Count(ctx)
	return mine == total, err
}

// commandIncident 只关联会话明确交接且包含目标主机的唯一事件；多个候选时不猜。
func (s *Service) commandIncident(ctx context.Context, session *ent.AgentSession, host uuid.UUID) (*uuid.UUID, error) {
	ids := []uuid.UUID{}
	for _, subject := range session.Subjects {
		kind, raw, _ := strings.Cut(subject, ":")
		if kind == "finding" {
			return nil, nil
		}
		if id, err := uuid.Parse(raw); kind == "incident" && err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	candidates, err := s.DB.Incident.Query().Where(incident.IDIn(ids...), incident.HasAlertsWith(alert.AssetIDEQ(host))).All(ctx)
	if err != nil || len(candidates) != 1 {
		return nil, err
	}
	id := candidates[0].ID
	allowed, err := s.incidentInGroup(ctx, id, session.GroupID)
	if err != nil || !allowed {
		return nil, err
	}
	return &id, nil
}
