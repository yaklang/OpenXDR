package closurereview

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/incidentstate"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/review"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/suppressclose"
)

// sifter 用当前的规则与生效抑制（含内置良性链）回看告警：规则修过之后不再命中、或已被良性链 / 抑制覆盖的，
// 是平台已经认定的噪声，不再计入结案审计。规则和良性链改了，旧事件不用人一条条清。
type sifter struct {
	db    *ent.Client
	rules map[string]*sigma.Rule
	store *suppress.Store
}

func newSifter(db *ent.Client, rules []*sigma.Rule, store *suppress.Store) *sifter {
	s := &sifter{db: db, store: store, rules: map[string]*sigma.Rule{}}
	for _, r := range rules {
		// 只回看单事件规则：时序规则没有单事件条件、信号规则不产生告警，回看会把它们都误判成「不再命中」
		if r != nil && r.Kind == "" && !r.Signal {
			s.rules[r.ID] = r
		}
	}
	return s
}

// noiseAlert 被排除的告警与原因，列进材料，审计员看得见排除了什么
type noiseAlert struct {
	AlertID string `json:"alert_id"`
	RuleID  string `json:"rule_id"`
	Reason  string `json:"reason"`
}

// noise 返回这条告警按当前口径是噪声的原因；仍有效返回空串。口径与入库检测一致：原文补上操作者后按事件类型与资产系统求值
func (s *sifter) noise(ctx context.Context, a *ent.Alert, ev *ent.Event, os string) (string, error) {
	if s == nil || ev == nil {
		return "", nil
	}
	var raw map[string]any
	if json.Unmarshal(ev.Raw, &raw) != nil {
		return "", nil
	}
	if ev.Username != nil {
		sigma.WithActor(raw, *ev.Username)
	}
	if r := s.rules[a.RuleID]; r != nil && !r.Matches(ev.ClassUID, os, raw) {
		return "规则已修订，当前版本不再命中", nil
	}
	if s.store == nil {
		return "", nil
	}
	var lineage []map[string]any
	if ev.ClassUID == 1007 && s.store.NeedsLineage() {
		lineage = suppress.ResolveLineageEnt(ctx, s.db, a.AssetID, ev.ParentProcessGUID, ev.Ts, raw)
	}
	if id := s.store.CoveringWithLineage(a.RuleID, a.AssetID, raw, lineage, time.Now()); id != nil {
		return fmt.Sprintf("已被生效的抑制或内置良性链覆盖（%s）", id), nil
	}
	return "", nil
}

// errAllNoise 事件的全部告警按当前口径都是噪声：研判为良性时直接按抑制口径结案，不必再调模型
type errAllNoise struct{ alerts []noiseAlert }

func (e *errAllNoise) Error() string {
	return fmt.Sprintf("全部 %d 条告警按当前规则与良性链均为噪声", len(e.alerts))
}

// closeNoise 全部告警按当前口径都是噪声、研判为良性：按抑制口径结案（来源 suppression，误报统计不当人工误报）。
// 研判时间对得上才改，期间重研判或有人处理过的，下一轮按新状态再看
func (r *Reviewer) closeNoise(ctx context.Context, id uuid.UUID, alerts []noiseAlert) (bool, error) {
	inc, err := r.DB.Incident.Get(ctx, id)
	if err != nil || inc.Status != "triaged" || inc.TriagedAt == nil {
		return false, err
	}
	reasons := map[string]int{}
	for _, a := range alerts {
		reasons[a.Reason]++
	}
	var parts []string
	for why, n := range reasons {
		parts = append(parts, fmt.Sprintf("%d 条%s", n, why))
	}
	slices.Sort(parts)
	resolution := fmt.Sprintf("按当前规则与内置良性链回看，本事件全部 %d 条告警均为噪声（%s），研判为良性，按抑制口径结案", len(alerts), strings.Join(parts, "；"))
	now := time.Now()
	tx, err := r.DB.Tx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	n, err := tx.Incident.Update().Where(incident.IDEQ(id), incident.StatusEQ("triaged"), incident.TriagedAtEQ(*inc.TriagedAt)).
		SetStatus("false_positive").SetResolvedBy(review.ClosedBy).SetResolutionSource(suppressclose.Source).
		SetResolvedAt(now).SetResolution(resolution).ClearClosureProposal().Save(ctx)
	if err != nil || n != 1 {
		return false, err
	}
	done, err := tx.Incident.Get(ctx, id)
	if err == nil {
		err = incidentwork.Refresh(ctx, tx.Client(), done, now)
	}
	if err == nil {
		err = incidentstate.Record(ctx, tx, id, incidentstate.StatusChanged, incidentstate.Origin{Kind: suppressclose.Source, ID: Actor}, "triaged")
	}
	if err == nil {
		err = audit.Checked(ctx, tx.AuditLog.Create(), review.ClosedBy, "server", "incident_status", id.String(), "false_positive "+resolution)
	}
	if err != nil {
		return false, err
	}
	return true, tx.Commit()
}
