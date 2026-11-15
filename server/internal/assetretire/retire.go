// Package assetretire 主机下线（退役）与恢复。
//
// 资产表被事件、告警、指令、处置引用着，删掉会断掉历史证据，所以下线只打标记：
//   - 清掉 agent_id：失联监控、采集健康、指令下发都以它为前提，下线后这些地方自然不再管这台主机；
//     agent 注册与事件流按主机名或 agent_id 认人，下线的主机在接入口被拒（旧证书接不回来，见 grpcsvc）
//   - 结束挂在它身上的处置：待审批的作废，生效中的标记为解除（主机已不在，解除指令送不到，不再重试）
//   - 自动结案所有告警均落在已下线主机上的未结事件（status=closed, resolution_source=asset_retired），
//     并关闭落在已下线主机上的未结运维待办（资产已退役）、作废只涉及已下线主机的待答问题（资产已退役，问题作废），
//     另有单活兜底循环补收竞态或历史遗留的同类未结项
//   - 资产列表默认不显示，历史事件、告警照常可查
//
// 用接入令牌重新接入或在控制台恢复即取消下线；恢复后 agent 重新注册会拿到新的 agent_id，已结事件不重开。
package assetretire

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/asset"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
	"openxdr/server/ent/question"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/facts"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/incidentstate"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/review"
)

// ResolutionSource 退役资产未结事件自动结案的来源标记
const ResolutionSource = "asset_retired"

const sweepBatch = 200

var ErrRetired = errors.New("主机已下线")
var ErrNotRetired = errors.New("主机没有下线")
var ErrNoReason = errors.New("请填写下线原因")

// Retire 下线主机。reason 必填：下线是不可见的变化，事后要能说清为什么
func Retire(ctx context.Context, db *ent.Client, a *ent.Asset, actor, reason string, now time.Time) (*ent.Asset, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, ErrNoReason
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	n, err := tx.Asset.Update().Where(asset.IDEQ(a.ID), asset.RetiredAtIsNil()).
		SetRetiredAt(now).SetRetiredBy(actor).SetRetiredReason(reason).
		ClearAgentID().ClearSilentSince().ClearHealthProblem().ClearSensorProblem().
		ClearParkedAt().ClearParkedBy().ClearParkedReason().
		Save(ctx)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrRetired
	}
	why := "主机已下线（" + actor + "：" + reason + "）"
	open, err := tx.Containment.Query().Where(entcontainment.AssetIDEQ(a.ID),
		entcontainment.StateIn(entcontainment.StateProposed, entcontainment.StatePending, entcontainment.StateActive)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range open {
		upd := tx.Containment.UpdateOne(c).SetEndedAt(now).ClearExpiresAt().SetReason(c.Reason + "；" + why)
		if c.State == entcontainment.StateProposed {
			upd.SetState(entcontainment.StateDeclined).SetDecidedBy(actor)
		} else {
			// 主机已不在，解除指令送不到；记为解除，到期不再重试
			upd.SetState(entcontainment.StateLifted).SetLiftedBy(actor)
		}
		if err := upd.Exec(ctx); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if incN, findN, qN, err := sweepAsset(ctx, db, a.ID, now); err != nil {
		slog.Error("退役资产自动结案失败，留待单活循环兜底", "asset", a.ID, "err", err)
	} else if incN+findN+qN > 0 {
		slog.Info("退役资产未结项自动收敛", "asset", a.ID, "hostname", a.Hostname, "incidents", incN, "findings", findN, "questions", qN)
	}
	return db.Asset.Get(ctx, a.ID)
}

// Restore 取消下线。agent 下次注册时拿新的 agent_id；已结事件不重开
func Restore(ctx context.Context, db *ent.Client, a *ent.Asset) (*ent.Asset, error) {
	n, err := db.Asset.Update().Where(asset.IDEQ(a.ID), asset.RetiredAtNotNil()).
		ClearRetiredAt().ClearRetiredBy().ClearRetiredReason().Save(ctx)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrNotRetired
	}
	return db.Asset.Get(ctx, a.ID)
}

// Closer 单活兜底循环：把历史遗留或退役竞态窗口内产生的只涉及已退役资产的未结事件、运维待办与待答问题收敛关闭。
type Closer struct {
	DB       *ent.Client
	Interval time.Duration
}

// Run 经 cluster.RunLeader 单活运行
func (c *Closer) Run(ctx context.Context) {
	interval := c.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if incN, findN, qN, err := c.sweepAll(ctx, time.Now()); err != nil && ctx.Err() == nil {
			slog.Error("退役资产未结项兜底收敛失败", "err", err)
		} else if incN+findN+qN > 0 {
			slog.Info("退役资产未结项兜底收敛", "incidents", incN, "findings", findN, "questions", qN)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Sweep 扫描并收敛只涉及已退役资产的未结事件、运维待办与待答问题，返回本次收敛总数
func (c *Closer) Sweep(ctx context.Context, now time.Time) (int, error) {
	incN, findN, qN, err := c.sweepAll(ctx, now)
	return incN + findN + qN, err
}

func (c *Closer) sweepAll(ctx context.Context, now time.Time) (int, int, int, error) {
	incN, err := sweepWhere(ctx, c.DB, now, alert.HasAssetWith(asset.RetiredAtNotNil()))
	if err != nil {
		return incN, 0, 0, err
	}
	findN, err := sweepFindings(ctx, c.DB, now, nil)
	if err != nil {
		return incN, findN, 0, err
	}
	qN, err := sweepQuestions(ctx, c.DB, now)
	return incN, findN, qN, err
}

func sweepAsset(ctx context.Context, db *ent.Client, assetID uuid.UUID, now time.Time) (int, int, int, error) {
	incN, err := sweepWhere(ctx, db, now, alert.AssetIDEQ(assetID))
	if err != nil {
		return incN, 0, 0, err
	}
	findN, err := sweepFindings(ctx, db, now, &assetID)
	if err != nil {
		return incN, findN, 0, err
	}
	qN, err := sweepQuestions(ctx, db, now)
	return incN, findN, qN, err
}

func sweepWhere(ctx context.Context, db *ent.Client, now time.Time, seed predicate.Alert) (int, error) {
	var cursor uuid.UUID
	closed := 0
	for {
		q := db.Incident.Query().
			Where(
				incident.StatusIn("open", "triaged"),
				incident.HasAlertsWith(seed),
				incident.Not(incident.HasAlertsWith(alert.Or(
					alert.AssetIDIsNil(),
					alert.HasAssetWith(asset.RetiredAtIsNil()),
				))),
			).
			Order(ent.Asc(incident.FieldID)).
			Limit(sweepBatch)
		if cursor != uuid.Nil {
			q = q.Where(incident.IDGT(cursor))
		}
		ids, err := q.IDs(ctx)
		if err != nil || len(ids) == 0 {
			return closed, err
		}
		for _, id := range ids {
			cursor = id
			ok, err := closeIncident(ctx, db, id, now)
			if err != nil {
				return closed, err
			}
			if ok {
				closed++
			}
		}
		if len(ids) < sweepBatch {
			return closed, nil
		}
	}
}

func closeIncident(ctx context.Context, db *ent.Client, id uuid.UUID, now time.Time) (bool, error) {
	tx, err := db.Tx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	inc, err := tx.Incident.Query().
		Where(incident.IDEQ(id)).
		Where(func(s *sql.Selector) { s.ForUpdate() }).
		Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if inc.Status != "open" && inc.Status != "triaged" {
		return false, nil
	}
	// 人工明确接管或锁定的事件留给人决定，避免分析师手工重开后又被后台循环关回
	if inc.Work != nil && (inc.Work.ManualLock || inc.Work.ManualOwner != "") {
		return false, nil
	}

	alerts, err := tx.Alert.Query().
		Where(alert.IncidentIDEQ(id)).
		WithAsset().
		Order(ent.Asc(alert.FieldTs), ent.Asc(alert.FieldID)).
		All(ctx)
	if err != nil || len(alerts) == 0 {
		return false, err
	}
	retired, ok := retiredAssetsOnly(alerts)
	if !ok {
		return false, nil
	}

	prev := inc.Status
	resolution := FormatResolution(retired)
	if err := tx.Incident.UpdateOneID(inc.ID).
		SetStatus("closed").
		SetResolvedBy(review.ClosedBy).
		SetResolutionSource(ResolutionSource).
		SetResolvedAt(now).
		SetResolution(resolution).
		ClearClosureProposal().
		Exec(ctx); err != nil {
		return false, err
	}
	done, err := tx.Incident.Get(ctx, inc.ID)
	if err == nil {
		err = incidentwork.Refresh(ctx, tx.Client(), done, now)
	}
	if err == nil {
		err = incidentstate.Record(ctx, tx, inc.ID, incidentstate.StatusChanged,
			incidentstate.Origin{Kind: ResolutionSource, ID: retired[0].ID.String()}, prev)
	}
	if err == nil {
		err = audit.Checked(ctx, tx.AuditLog.Create(), review.ClosedBy, "server", "incident_status", inc.ID.String(), "closed "+resolution)
	}
	if err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// retiredAssetsOnly 校验全部告警均挂在已退役资产上，并按首次出现顺序返回去重后的资产列表
func retiredAssetsOnly(alerts []*ent.Alert) ([]*ent.Asset, bool) {
	if len(alerts) == 0 {
		return nil, false
	}
	var out []*ent.Asset
	for _, a := range alerts {
		if a.AssetID == nil || a.Edges.Asset == nil || a.Edges.Asset.RetiredAt == nil {
			return nil, false
		}
		host := a.Edges.Asset
		if !slices.ContainsFunc(out, func(x *ent.Asset) bool { return x.ID == host.ID }) {
			out = append(out, host)
		}
	}
	return out, true
}

// FormatResolution 生成可审计的退役资产自动结案说明
func FormatResolution(assets []*ent.Asset) string {
	if len(assets) == 0 {
		return ""
	}
	first := assets[0]
	base := fmt.Sprintf("资产已于 %s 由 %s 退役（原因：%s），主机不复存在",
		formatTime(first.RetiredAt),
		retiredActor(first.RetiredBy),
		retiredWhy(first.RetiredReason),
	)
	if len(assets) == 1 {
		if h := strings.TrimSpace(first.Hostname); h != "" {
			return base + "（" + h + "）"
		}
		return base
	}
	parts := make([]string, 0, len(assets))
	for i, a := range assets {
		name := cmp.Or(strings.TrimSpace(a.Hostname), a.ID.String())
		if i == 0 {
			parts = append(parts, name)
			continue
		}
		parts = append(parts, fmt.Sprintf("另涉 %s 于 %s 由 %s 退役，原因：%s",
			name, formatTime(a.RetiredAt), retiredActor(a.RetiredBy), retiredWhy(a.RetiredReason)))
	}
	return base + "（" + strings.Join(parts, "；") + "）"
}

func formatTime(t *time.Time) string {
	if t == nil {
		return "未知时间"
	}
	return t.UTC().Format(time.RFC3339)
}

func retiredActor(by *string) string {
	if by == nil {
		return "未知"
	}
	return cmp.Or(strings.TrimSpace(*by), "未知")
}

func retiredWhy(reason *string) string {
	if reason == nil {
		return "未说明"
	}
	return cmp.Or(strings.TrimSpace(*reason), "未说明")
}

// sweepFindings 把落在已退役资产上的未结运维待办按「资产已退役」关闭并留审计
func sweepFindings(ctx context.Context, db *ent.Client, now time.Time, assetID *uuid.UUID) (int, error) {
	where := []predicate.Finding{finding.StatusEQ("open")}
	if assetID != nil {
		where = append(where, finding.AssetIDEQ(*assetID))
	} else {
		where = append(where, func(s *sql.Selector) {
			t := sql.Table(asset.Table)
			s.Where(sql.In(
				s.C(finding.FieldAssetID),
				sql.Select(t.C(asset.FieldID)).From(t).Where(sql.NotNull(t.C(asset.FieldRetiredAt))),
			))
		})
	}
	rows, err := db.Finding.Query().Where(where...).Order(ent.Asc(finding.FieldID)).Limit(sweepBatch).All(ctx)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	closed := 0
	for _, f := range rows {
		ok, err := closeRetiredFinding(ctx, db, f.ID, now)
		if err != nil {
			return closed, err
		}
		if ok {
			closed++
		}
	}
	return closed, nil
}

func closeRetiredFinding(ctx context.Context, db *ent.Client, id uuid.UUID, now time.Time) (bool, error) {
	tx, err := db.Tx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	f, err := tx.Finding.Query().Where(finding.IDEQ(id)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil || f.Status != "open" {
		return false, err
	}
	host, err := tx.Asset.Get(ctx, f.AssetID)
	if ent.IsNotFound(err) || (err == nil && host.RetiredAt == nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	note := "资产已退役：" + FormatResolution([]*ent.Asset{host})
	var w findings.Work
	_ = json.Unmarshal(f.Work, &w)
	w.Stage = "resolved"
	w.Blocker, w.BlockedReason, w.BlockerDetail, w.BlockedRounds = "", "", "", 0
	w.Question = ""
	w.WakeOn = "human_reopen"
	w.Plan = note
	n, err := tx.Finding.Update().Where(finding.IDEQ(f.ID), finding.StatusEQ("open"), findings.Snapshot(f)).
		SetStatus("resolved").SetResolvedAt(now).SetResolvedBy(review.ClosedBy).SetNote(note).
		ClearWorkSessionID().ClearWorkLeaseUntil().ClearWorkNextCheckAt().
		SetWork(findings.EncodeWork(w)).Save(ctx)
	if err != nil || n == 0 {
		return false, err
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), review.ClosedBy, "server", "finding_status", f.ID.String(), "resolved "+note); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// sweepQuestions 把只涉及已退役资产的未答总控问题按「资产已退役，问题作废」关闭并留审计（不写事实）
func sweepQuestions(ctx context.Context, db *ent.Client, now time.Time) (int, error) {
	rows, err := db.Question.Query().
		Where(question.StatusEQ("open"), question.SubjectKindNotIn("rule", "fact")).
		Order(ent.Asc(question.FieldID)).Limit(sweepBatch).All(ctx)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	closed := 0
	for _, q := range rows {
		ok, err := closeRetiredQuestion(ctx, db, q.ID, now)
		if err != nil {
			return closed, err
		}
		if ok {
			closed++
		}
	}
	return closed, nil
}

func closeRetiredQuestion(ctx context.Context, db *ent.Client, id uuid.UUID, now time.Time) (bool, error) {
	tx, err := db.Tx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	q, err := tx.Question.Query().Where(question.IDEQ(id)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil || q.Status != "open" || q.SubjectKind == "rule" || q.SubjectKind == "fact" {
		return false, err
	}
	retired, ok, err := retiredAssetsForQuestion(ctx, tx, q)
	if err != nil || !ok {
		return false, err
	}
	summary := "资产已退役，问题作废：" + FormatResolution(retired)
	n, err := tx.Question.Update().Where(question.IDEQ(q.ID), question.StatusEQ("open")).
		SetStatus("voided").
		SetAnsweredBy(review.ClosedBy).
		SetAnsweredAt(now).
		SetAnswer(&schema.QuestionAnswer{Choice: "voided_retired", Content: summary}).
		Save(ctx)
	if err != nil || n == 0 {
		return false, err
	}
	detail := fmt.Sprintf("%s %s %s %s %s", facts.Ref("Q", q.ID), q.Kind, q.SubjectKind, q.Subject, summary)
	if err := audit.Checked(ctx, tx.AuditLog.Create(), review.ClosedBy, "server", "question_voided", q.ID.String(), detail); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// retiredAssetsForQuestion 判断一条待答问题是否「只涉及已退役资产」：
//   - 主题就是主机/变更：该主机必须已退役，且关联的全部待办与事件也都只落在已退役资产上；
//   - 主题是钥匙/地址/域名：至少关联一条待办或事件，且所有关联待办与事件全部落在已退役资产上。
func retiredAssetsForQuestion(ctx context.Context, tx *ent.Tx, q *ent.Question) ([]*ent.Asset, bool, error) {
	var out []*ent.Asset
	add := func(a *ent.Asset) {
		if !slices.ContainsFunc(out, func(x *ent.Asset) bool { return x.ID == a.ID }) {
			out = append(out, a)
		}
	}
	if q.SubjectKind == "asset" || q.SubjectKind == "change" {
		aid, err := uuid.Parse(q.Subject)
		if err != nil {
			return nil, false, nil
		}
		host, err := tx.Asset.Get(ctx, aid)
		if ent.IsNotFound(err) || (err == nil && host.RetiredAt == nil) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		add(host)
	} else if len(q.FindingIds) == 0 && len(q.IncidentIds) == 0 {
		return nil, false, nil
	}

	if len(q.FindingIds) > 0 {
		fRows, err := tx.Finding.Query().Where(finding.IDIn(q.FindingIds...)).All(ctx)
		if err != nil {
			return nil, false, err
		}
		if len(fRows) > 0 {
			aids := make([]uuid.UUID, 0, len(fRows))
			for _, f := range fRows {
				aids = append(aids, f.AssetID)
			}
			hosts, err := tx.Asset.Query().Where(asset.IDIn(aids...)).All(ctx)
			if err != nil {
				return nil, false, err
			}
			byID := make(map[uuid.UUID]*ent.Asset, len(hosts))
			for _, h := range hosts {
				byID[h.ID] = h
			}
			for _, f := range fRows {
				h := byID[f.AssetID]
				if h == nil || h.RetiredAt == nil {
					return nil, false, nil
				}
				add(h)
			}
		}
	}

	if len(q.IncidentIds) > 0 {
		for _, incID := range q.IncidentIds {
			alerts, err := tx.Alert.Query().Where(alert.IncidentIDEQ(incID)).WithAsset().
				Order(ent.Asc(alert.FieldTs), ent.Asc(alert.FieldID)).All(ctx)
			if err != nil {
				return nil, false, err
			}
			if len(alerts) == 0 {
				return nil, false, nil
			}
			hosts, ok := retiredAssetsOnly(alerts)
			if !ok {
				return nil, false, nil
			}
			for _, h := range hosts {
				add(h)
			}
		}
	}

	return out, len(out) > 0, nil
}
