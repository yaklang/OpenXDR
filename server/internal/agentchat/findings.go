package agentchat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/command"
	"openxdr/server/ent/finding"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/findings"
)

const trackDescription = "登记或复查一条运维待办。登记需要持续调查、修复或监测的具体问题，默认由平台负责，一个问题一条；" +
	"正常项、正向确认、改进建议、对平台或对自己登记的说明都不登记，写进报告即可。" +
	"同一主机同一问题每轮用同一个 key（小写字母、数字、. _ -），如 backup-service-failed。" +
	"status=open 写具体 next_step；resolved 须附 evidence_commands 的本轮独立只读复查回执，不能仅凭修复回执或空日志关单；withdrawn 撤回本轮登记错的条目。blocker 区分缺策略、维护窗口、业务决定、退役确认、上游依赖、权限拒绝与能力不支持。policy_required由服务端查询真实授权；其他阻塞须引用本轮真实只读证据，不能猜测。" +
	"人工忽略的待办会返回 ignored，不要再登记，也不要列进报告的待处理事项。每轮最多新登记 10 条。"

// maxNewFindings 一轮会话最多新登记的待办数：超出说明在把报告内容往待办里倒
const maxNewFindings = 10

var trackParameters = json.RawMessage(`{"type":"object","properties":{` +
	`"host":{"type":"string"},` +
	`"key":{"type":"string","pattern":"^[a-z0-9][a-z0-9._-]{0,63}$"},` +
	`"title":{"type":"string","minLength":1,"maxLength":200},` +
	`"detail":{"type":"string","minLength":1,"maxLength":4000},` +
	`"severity":{"type":"string","enum":["low","medium","high"]},` +
	`"status":{"type":"string","enum":["open","resolved","withdrawn"]},` +
	`"next_step":{"type":"string","maxLength":1000},"blocker":{"type":"string","enum":["policy_required","maintenance_window_required","manual_business_decision","legacy_decommission_confirm","external_dependency","permission","unsupported","cooldown","probe_invalid","action_unsupported","budget_exhausted","none"]},` +
	`"repair_command":{"type":"string","maxLength":512},"repair_mount":{"type":"string","maxLength":256},"depends_on":{"type":"array","maxItems":5,"items":{"type":"string","format":"uuid"}},"wake_at":{"type":"string","format":"date-time"},` +
	`"evidence_commands":{"type":"array","maxItems":5,"items":{"type":"string","format":"uuid"}}},` +
	`"required":["host","key","title","detail","severity","status"],"additionalProperties":false}`)

var findingKey = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// track 按（组、主机、key）登记或复查待办。人工忽略的不动，原样告诉模型。
func (s *Service) track(ctx context.Context, session *ent.AgentSession, args json.RawMessage) (string, error) {
	var body struct {
		findingPlanOptions
		Host             uuid.UUID   `json:"host"`
		Key              string      `json:"key"`
		Title            string      `json:"title"`
		Detail           string      `json:"detail"`
		Severity         string      `json:"severity"`
		Status           string      `json:"status"`
		NextStep         string      `json:"next_step"`
		Blocker          string      `json:"blocker"`
		EvidenceCommands []uuid.UUID `json:"evidence_commands"`
	}
	decoder := json.NewDecoder(bytes.NewReader(args))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return "", err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return "", errors.New("track 参数包含额外内容")
	}

	switch {
	case !findingKey.MatchString(body.Key):
		return "", errors.New("key 只能是小写字母、数字与 . _ -，不超过 64 位")
	case body.Title == "" || len(body.Title) > 200 || strings.TrimSpace(body.Detail) == "" || len(body.Detail) > 4000:
		return "", errors.New("title 或 detail 长度无效，detail 要写清现象与证据")
	case !slices.Contains([]string{"low", "medium", "high"}, body.Severity):
		return "", errors.New("severity 必须是 low / medium / high")
	case !slices.Contains([]string{"open", "resolved", "withdrawn"}, body.Status):
		return "", errors.New("status 必须是 open / resolved / withdrawn")
	}
	inGroup, err := s.DB.Asset.Query().Where(asset.IDEQ(body.Host), asset.GroupIDEQ(session.GroupID)).Exist(ctx)
	if err != nil {
		return "", err
	}
	if !inGroup {
		return "", errors.New("主机不在本组")
	}
	f, err := s.DB.Finding.Query().
		Where(finding.GroupIDEQ(session.GroupID), finding.AssetIDEQ(body.Host), finding.KeyEQ(body.Key)).
		Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return "", err
	}
	if bound, err := s.isFindingFollowup(ctx, session); err != nil {
		return "", err
	} else if bound {
		if f == nil || f.WorkSessionID == nil || *f.WorkSessionID != session.ID || f.WorkLeaseUntil == nil || !f.WorkLeaseUntil.After(time.Now()) {
			return "", errors.New("自主跟进任务只能更新本轮有效领取的待办")
		}
	}
	now := time.Now()
	switch {
	case f != nil && f.Status == "ignored":
		return marshal(map[string]any{"id": f.ID, "status": "ignored", "note": f.Note})
	case body.Status == "withdrawn":
		// 只能撤回本轮新登记的；遗留待办要么复查修复，要么由人忽略
		if f == nil || f.SessionID == nil || *f.SessionID != session.ID || f.FirstSeen.Before(session.CreatedAt) {
			return "", errors.New("只能撤回本轮新登记的待办")
		}
		if err := s.DB.Finding.DeleteOne(f).Exec(ctx); err != nil {
			return "", err
		}
		return marshal(map[string]any{"id": f.ID, "status": "withdrawn"})
	case f == nil && body.Status == "resolved":
		return "", errors.New("没有这条待办；已修复的问题不用登记")
	case f == nil:
		fresh, err := s.DB.Finding.Query().
			Where(finding.SessionIDEQ(session.ID), finding.FirstSeenGTE(session.CreatedAt)).Count(ctx)
		if err != nil {
			return "", err
		}
		if fresh >= maxNewFindings {
			return "", errors.New("本轮已新登记 10 条，只登记最需要持续处理的，其余写进报告")
		}
		f, err = s.DB.Finding.Create().SetGroupID(session.GroupID).SetAssetID(body.Host).SetKey(body.Key).
			SetTitle(body.Title).SetDetail(body.Detail).SetSeverity(body.Severity).SetSessionID(session.ID).
			SetWorkOwner("ai").SetWorkNextCheckAt(now.Add(time.Hour)).SetWork(findings.EncodeWork(findings.Work{OriginalTitle: body.Title, OriginalProblem: body.Detail, Stage: "waiting", Plan: "先只读复查现状与影响，授权内最小修复后独立验证", WakeOn: "new_observation_or_next_check"})).Save(ctx)
		if err != nil {
			return "", err
		}
		if err := s.saveFindingPlan(ctx, session, f, body.NextStep, body.Blocker, body.EvidenceCommands, body.findingPlanOptions); err != nil {
			return "", err
		}
		return marshal(map[string]any{"id": f.ID, "status": "open", "new": true})
	case body.Status == "resolved":
		reviewReason := ""
		if f.Status == "open" {
			if err := s.findingEvidence(ctx, session, f, body.EvidenceCommands, true, ""); err != nil {
				return "", err
			}
			if s.ReviewFinding == nil {
				return "", errors.New("未配置独立运维效果复核，待办保持 open")
			}
			var work findings.Work
			_ = json.Unmarshal(f.Work, &work)
			work.Version = 2
			work.VerificationAttempts++
			f, err = s.DB.Finding.UpdateOneID(f.ID).Where(finding.StatusEQ("open"), findings.Snapshot(f)).SetWork(findings.EncodeWork(work)).Save(ctx)
			if err != nil {
				return "", err
			}
			commands, err := s.DB.Command.Query().Where(command.IDIn(body.EvidenceCommands...)).All(ctx)
			if err != nil {
				return "", err
			}
			approved, reason, err := s.ReviewFinding(ctx, session, f, commands)
			if err != nil {
				return "", err
			}
			if !approved {
				return "", errors.New("独立复核未确认修复，继续调查或监测：" + reason)
			}
			if _, err := s.guardTool(ctx, session, "track"); err != nil {
				return "", err
			}
			if err := s.findingEvidence(ctx, session, f, body.EvidenceCommands, true, ""); err != nil {
				return "", err
			}
			reviewReason = reason
			now = time.Now()

			tx, err := s.DB.Tx(ctx)
			if err != nil {
				return "", err
			}
			defer tx.Rollback()
			work.Stage, work.Plan, work.WakeOn = "resolved", "独立复核通过："+reviewReason, "recurrence"
			work.Blocker = ""
			work.EvidenceCommands, work.EvidenceAt, work.EvidenceStale = body.EvidenceCommands, &now, false
			err = tx.Finding.UpdateOneID(f.ID).Where(finding.StatusEQ("open"), finding.LastSeenEQ(f.LastSeen), findings.Snapshot(f)).SetStatus("resolved").SetTitle(body.Title).SetDetail(body.Detail).
				SetResolvedAt(now).SetResolvedBy(commandgate.SystemActor).
				SetLastSeen(now).SetSessionID(session.ID).ClearWorkSessionID().ClearWorkLeaseUntil().ClearWorkNextCheckAt().SetWork(findings.EncodeWork(work)).Exec(ctx)
			if err != nil {
				return "", err
			}
			if err := audit.Checked(ctx, tx.AuditLog.Create(), commandgate.SystemActor, "server", "finding_ai_review", f.ID.String(), "独立复核通过，session="+session.ID.String()+" "+reviewReason); err != nil {
				return "", err
			}
			if err := tx.Commit(); err != nil {
				return "", err
			}

		}
		if err != nil {
			return "", err
		}
		return marshal(map[string]any{"id": f.ID, "status": "resolved"})
	default:
		// 仍存在；之前被标成已修复的重新打开
		reopened := f.Status == "resolved"
		err = f.Update().Where(finding.StatusEQ(f.Status), finding.LastSeenEQ(f.LastSeen), findings.Snapshot(f)).SetStatus("open").SetTitle(body.Title).SetDetail(body.Detail).SetSeverity(body.Severity).
			SetLastSeen(now).SetSessionID(session.ID).ClearResolvedAt().ClearResolvedBy().ClearNote().Exec(ctx)
		if err != nil {
			return "", err
		}
		if err := s.saveFindingPlan(ctx, session, f, body.NextStep, body.Blocker, body.EvidenceCommands, body.findingPlanOptions); err != nil {
			return "", err
		}
		return marshal(map[string]any{"id": f.ID, "status": "open", "reopened": reopened})
	}
}

// findingBrief 给模型看的待办摘要。
type findingBrief struct {
	Host         uuid.UUID                    `json:"host"`
	Hostname     string                       `json:"hostname"`
	Key          string                       `json:"key"`
	Title        string                       `json:"title"`
	Severity     string                       `json:"severity,omitempty"`
	FirstSeen    string                       `json:"first_seen,omitempty"`
	WorkOwner    string                       `json:"work_owner,omitempty"`
	NextCheck    *time.Time                   `json:"next_check_at,omitempty"`
	Work         any                          `json:"work,omitempty"`
	Note         *string                      `json:"note,omitempty"`
	ID           uuid.UUID                    `json:"id,omitempty"`
	Capabilities *findings.RepairCapabilities `json:"repair_capabilities,omitempty"`
}

// recentResolvedWindow 人工标为已处理并附说明的待办保留在上下文里的时长：
// 让巡检 AI 知道哪些「待确认授权 / 暴露端口」已被管理员确认或加固，不再换 key 重复追问
const recentResolvedWindow = 30 * 24 * time.Hour

// findingsFor 本组遗留待办、人工忽略的待办，以及近期人工结案并附说明的待办。
func (s *Service) findingsFor(ctx context.Context, group uuid.UUID, hostnames map[uuid.UUID]string) (open, ignored, resolved []findingBrief, err error) {
	open, ignored, resolved = []findingBrief{}, []findingBrief{}, []findingBrief{}
	for _, status := range []string{"open", "ignored"} {
		rows, err := s.DB.Finding.Query().Where(finding.GroupIDEQ(group), finding.StatusEQ(status)).
			Order(ent.Desc(finding.FieldLastSeen)).Limit(100).All(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, f := range rows {
			b := findingBrief{ID: f.ID, Host: f.AssetID, Hostname: hostnames[f.AssetID], Key: f.Key, Title: f.Title}
			if status == "open" {
				b.Severity, b.FirstSeen = f.Severity, f.FirstSeen.Format(time.DateOnly)
				b.WorkOwner, b.NextCheck, b.Work = f.WorkOwner, f.WorkNextCheckAt, findingWorkJSON(f)
				open = append(open, b)
			} else {
				b.Note = f.Note
				ignored = append(ignored, b)
			}
		}
	}
	rows, err := s.DB.Finding.Query().Where(
		finding.GroupIDEQ(group),
		finding.StatusEQ("resolved"),
		finding.ResolvedByNotNil(),
		finding.ResolvedByNEQ(commandgate.SystemActor),
		finding.NoteNotNil(),
		finding.NoteNEQ(""),
		finding.ResolvedAtGTE(time.Now().Add(-recentResolvedWindow)),
	).Order(ent.Desc(finding.FieldResolvedAt)).Limit(50).All(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, f := range rows {
		resolved = append(resolved, findingBrief{
			Host: f.AssetID, Hostname: hostnames[f.AssetID], Key: f.Key, Title: f.Title, Note: f.Note,
		})
	}
	return open, ignored, resolved, nil
}

const ignoreDescription = "按用户在对话里的明确要求忽略一条运维待办，效果同待办页的人工忽略：记在发起对话的人名下，" +
	"巡检 AI 以后不再登记。只有用户明确说要忽略某条待办时才用，不得自行决定忽略；只在组管理员发起的对话里可用，定时任务不能用。" +
	"host 与 key 取 open_findings 里的值；reason 写用户给的忽略理由（1–2000 字）。"

var ignoreParameters = json.RawMessage(`{"type":"object","properties":{` +
	`"host":{"type":"string"},` +
	`"key":{"type":"string"},` +
	`"reason":{"type":"string","minLength":1,"maxLength":2000}},` +
	`"required":["host","key","reason"],"additionalProperties":false}`)

// ignore 代发起对话的组管理员忽略待办：落库与审计走控制台同一套 findings.Set。
// 身份只认人发起的对话会话，用户与组内角色每次从库里重新取。
func (s *Service) ignore(ctx context.Context, session *ent.AgentSession, who commandgate.Request, args json.RawMessage) (string, error) {
	u, err := s.groupAdmin(ctx, session, who)
	if err != nil {
		return "", err
	}
	var body struct {
		Host   uuid.UUID `json:"host"`
		Key    string    `json:"key"`
		Reason string    `json:"reason"`
	}
	if err := json.Unmarshal(args, &body); err != nil {
		return "", err
	}
	note, err := findings.Clean("ignored", body.Reason)
	if err != nil {
		return "", err
	}
	f, err := s.DB.Finding.Query().
		Where(finding.GroupIDEQ(session.GroupID), finding.AssetIDEQ(body.Host), finding.KeyEQ(body.Key)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return "", errors.New("本组这台主机上没有这个 key 的待办，host 与 key 取 xdr context 里 open_findings 的值")
	}
	if err != nil {
		return "", err
	}
	if f.Status == "ignored" {
		return marshal(map[string]any{"id": f.ID, "status": "ignored", "note": f.Note, "already": true})
	}
	via := "AI 会话 " + session.ID.String() + " 代 " + u.Username + " 执行"
	if err := findings.Set(ctx, s.DB, f, "ignored", note, u.Username, "server", via); err != nil {
		return "", err
	}
	return marshal(map[string]any{"id": f.ID, "status": "ignored", "by": u.Username})
}

// errNotHumanAdmin 定时任务或非组管理员的会话里调用忽略时给模型的说明
var errNotHumanAdmin = errors.New("忽略待办只能在组管理员发起的对话里、按用户的明确要求执行；" +
	"当前会话不满足（定时任务或发起人不是组管理员），不要重试，把需要忽略的待办写进回复或报告，由组管理员在待办页处理")

// groupAdmin 会话发起人必须是人，且此刻仍是会话所属组的管理员。
func (s *Service) groupAdmin(ctx context.Context, session *ent.AgentSession, who commandgate.Request) (*ent.User, error) {
	if who.System || who.UserID == uuid.Nil || session.Kind != "chat" || session.Initiator == commandgate.SystemActor {
		return nil, errNotHumanAdmin
	}
	u, err := s.DB.User.Get(ctx, who.UserID)
	if ent.IsNotFound(err) {
		return nil, errNotHumanAdmin
	}
	if err != nil {
		return nil, err
	}
	if u.Username != session.Initiator || !auth.Allowed(auth.GroupRole(ctx, s.DB, u, session.GroupID), "admin") {
		return nil, errNotHumanAdmin
	}
	return u, nil
}
