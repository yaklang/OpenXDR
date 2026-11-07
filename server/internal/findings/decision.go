package findings

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/command"
	"openxdr/server/ent/finding"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/commandgate"
)

// Decision 是管理员交给指定待办的一次执行决定，不是维修模板授权或命令审批。
// 会话索引与当前决定分开保存，撤销/替换后旧会话不能退回普通对话权限。
type Decision struct {
	RequestID   uuid.UUID `json:"requestId"`
	FindingID   uuid.UUID `json:"findingId"`
	GroupID     uuid.UUID `json:"groupId"`
	AssetID     uuid.UUID `json:"assetId"`
	SessionID   uuid.UUID `json:"sessionId"`
	UserID      uuid.UUID `json:"userId"`
	Author      string    `json:"author"`
	Instruction string    `json:"instruction"`
	CreatedAt   time.Time `json:"createdAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Revoked     bool      `json:"revoked"`
}

func decisionKey(id uuid.UUID) string        { return "finding-decision:" + id.String() }
func decisionSessionKey(id uuid.UUID) string { return "finding-decision-session:" + id.String() }
func decisionRequestKey(id uuid.UUID) string { return "finding-decision-request:" + id.String() }

func LoadDecision(ctx context.Context, db *ent.Client, id uuid.UUID) (*Decision, error) {
	row, err := db.Setting.Get(ctx, decisionKey(id))
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var d Decision
	if err = json.Unmarshal(row.Value, &d); err != nil {
		return nil, err
	}
	if d.FindingID != id || d.RequestID == uuid.Nil || d.SessionID == uuid.Nil {
		return nil, errors.New("管理员决定记录无效")
	}
	return &d, nil
}

func (d *Decision) Validate(ctx context.Context, db *ent.Client, now time.Time) error {
	if d.Revoked || !d.ExpiresAt.After(now) {
		return errors.New("管理员执行决定已撤销或到期")
	}
	f, err := db.Finding.Get(ctx, d.FindingID)
	if err != nil {
		return err
	}
	if f.Status != "open" || f.GroupID != d.GroupID || f.AssetID != d.AssetID {
		return errors.New("决定对应的待办已结束或归属改变")
	}
	a, err := db.Asset.Get(ctx, d.AssetID)
	if err != nil {
		return err
	}
	if a.GroupID == nil || *a.GroupID != d.GroupID {
		return errors.New("决定对应资产已转组")
	}
	u, err := db.User.Get(ctx, d.UserID)
	if err != nil {
		return err
	}
	if u.Username != d.Author || !auth.Allowed(auth.GroupRole(ctx, db, u, d.GroupID), "admin") {
		return errors.New("决定签发人已无组管理员权限")
	}
	return nil
}

func DecisionForSession(ctx context.Context, db *ent.Client, session *ent.AgentSession) (*Decision, error) {
	row, err := db.Setting.Get(ctx, decisionSessionKey(session.ID))
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var index Decision
	if err = json.Unmarshal(row.Value, &index); err != nil {
		return nil, err
	}
	d, err := LoadDecision(ctx, db, index.FindingID)
	if err != nil {
		return nil, err
	}
	if d == nil || d.SessionID != session.ID || d.RequestID != index.RequestID || d.GroupID != session.GroupID || session.Kind != "chat" || session.Initiator != d.Author {
		return nil, errors.New("执行会话与当前管理员决定不匹配")
	}
	if err = d.Validate(ctx, db, time.Now()); err != nil {
		return nil, err
	}
	return d, nil
}

func GuardDecisionWrite(ctx context.Context, db *ent.Client, session *ent.AgentSession, host, request uuid.UUID) error {
	d, err := DecisionForSession(ctx, db, session)
	if err != nil {
		return err
	}
	if d == nil || d.RequestID != request || d.AssetID != host {
		return errors.New("写动作与当前管理员执行决定不匹配")
	}
	f, err := db.Finding.Get(ctx, d.FindingID)
	if err != nil {
		return err
	}
	if f.WorkOwner != "ai" {
		return errors.New("人工持有待办不能由执行决定自动接管")
	}
	rows, err := db.Command.Query().Where(command.AssetIDEQ(host), command.StatusIn("pending", "sent", "unknown")).All(ctx)
	if err != nil {
		return err
	}
	for _, c := range rows {
		if c.Kind != "exec" || c.Cmd == nil || !commandgate.ReadOnly(*c.Cmd) {
			return errors.New("主机存在未确认写操作，先查原回执，不新增或重放写动作：" + c.ID.String())
		}
	}
	return nil
}

// Delegate 原子保存决定、唯一执行会话和审计；重复 requestId 只返回原会话，绝不重放。
func Delegate(ctx context.Context, db *ent.Client, id uuid.UUID, u *ent.User, request uuid.UUID, instruction, model, remote string, expires time.Time) (*Decision, bool, error) {
	instruction = strings.TrimSpace(instruction)
	if request == uuid.Nil || instruction == "" || utf8.RuneCountInString(instruction) > 4000 || model == "" {
		return nil, false, errors.New("须提供请求UUID、1–4000字执行决定、模型和30天内有效期")
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	f, err := tx.Finding.Query().Where(finding.IDEQ(id)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx)
	if err != nil {
		return nil, false, err
	}
	fresh, err := tx.User.Get(ctx, u.ID)
	if err != nil {
		return nil, false, err
	}
	if !auth.Allowed(auth.GroupRole(ctx, tx.Client(), fresh, f.GroupID), "admin") {
		return nil, false, errors.New("只有当前组管理员可以签发执行决定")
	}
	owned, err := tx.Asset.Query().Where(asset.IDEQ(f.AssetID), asset.GroupIDEQ(f.GroupID)).Exist(ctx)
	if err != nil {
		return nil, false, err
	}
	if !owned || f.Status != "open" {
		return nil, false, errors.New("只能委托当前组内未结案的待办")
	}
	if row, e := tx.Setting.Get(ctx, decisionRequestKey(request)); e == nil {
		var old Decision
		if e = json.Unmarshal(row.Value, &old); e != nil {
			return nil, false, e
		}
		if old.FindingID != id || old.UserID != u.ID || old.Instruction != instruction || !old.ExpiresAt.Equal(expires) {
			return nil, false, errors.New("同一请求UUID不能改写决定内容")
		}
		return &old, false, nil
	} else if !ent.IsNotFound(e) {
		return nil, false, e
	}
	if !expires.After(time.Now()) || expires.After(time.Now().Add(30*24*time.Hour)) {
		return nil, false, errors.New("执行决定有效期须在未来30天内")
	}
	prior, err := LoadDecision(ctx, tx.Client(), id)
	if err != nil {
		return nil, false, err
	}
	if prior != nil {
		if prior.RequestID == request {
			if prior.UserID != u.ID || prior.Instruction != instruction || !prior.ExpiresAt.Equal(expires) {
				return nil, false, errors.New("同一请求UUID不能改写决定内容")
			}
			return prior, false, nil
		}
		old, e := tx.AgentSession.Get(ctx, prior.SessionID)
		if e != nil {
			return nil, false, e
		}
		if old.Status == "running" {
			return nil, false, errors.New("原决定会话仍在执行，请先查看原回执，不新建重复执行")
		}
	}
	s, err := tx.AgentSession.Create().SetGroupID(f.GroupID).SetKind("chat").SetInitiator(fresh.Username).SetModel(model).SetTitle("管理员执行决定：" + f.Key).SetSubjects([]string{"finding:" + id.String()}).SetStatus("idle").Save(ctx)
	if err != nil {
		return nil, false, err
	}
	d := &Decision{RequestID: request, FindingID: id, GroupID: f.GroupID, AssetID: f.AssetID, SessionID: s.ID, UserID: fresh.ID, Author: fresh.Username, Instruction: instruction, CreatedAt: time.Now(), ExpiresAt: expires}
	b, _ := json.Marshal(d)
	if prior == nil {
		_, err = tx.Setting.Create().SetID(decisionKey(id)).SetValue(b).Save(ctx)
	} else {
		err = tx.Setting.UpdateOneID(decisionKey(id)).SetValue(b).Exec(ctx)
	}
	if err != nil {
		return nil, false, err
	}
	if _, err = tx.Setting.Create().SetID(decisionSessionKey(s.ID)).SetValue(b).Save(ctx); err != nil {
		return nil, false, err
	}
	if _, err = tx.Setting.Create().SetID(decisionRequestKey(request)).SetValue(b).Save(ctx); err != nil {
		return nil, false, err
	}
	// 不改人工归属、预算、原探针和活跃租约；执行决定由绑定会话独立负责。
	if err = audit.Checked(ctx, tx.AuditLog.Create(), fresh.Username, remote, "finding_execution_decided", id.String(), "request="+request.String()+" session="+s.ID.String()+" expires="+expires.Format(time.RFC3339)+" instruction="+instruction); err != nil {
		return nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return nil, false, err
	}
	return d, true, nil
}

func RevokeDecision(ctx context.Context, db *ent.Client, id uuid.UUID, actor, remote string) error {
	tx, err := db.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Finding.Query().Where(finding.IDEQ(id)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx); err != nil {
		return err
	}
	d, err := LoadDecision(ctx, tx.Client(), id)
	if err != nil || d == nil {
		return err
	}
	d.Revoked = true
	b, _ := json.Marshal(d)
	if err = tx.Setting.UpdateOneID(decisionKey(id)).SetValue(b).Exec(ctx); err != nil {
		return err
	}
	if err = audit.Checked(ctx, tx.AuditLog.Create(), actor, remote, "finding_execution_revoked", id.String(), "request="+d.RequestID.String()+" session="+d.SessionID.String()); err != nil {
		return err
	}
	return tx.Commit()
}
