// Package suppressclose 抑制生效后回头结案：生效抑制覆盖了全部告警、AI 研判为良性的未结案事件，按抑制口径结案。
//
// 抑制只挡新命中，批准之前已经成了事件的同一模式仍挂在未结案里；不回头收，人批准一个模式之后还得一个个点。
// 研判可疑或恶意的不收：抑制说的是这类命中是噪声，研判说这个事件里还有别的疑点，留给人。
// 结案来源记为 suppression，误报统计不把它当人工误报，抑制不会自己喂大自己。
package suppressclose

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/suppression"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/incidentstate"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/review"
	"openxdr/server/internal/suppress"
)

// Source 结案来源
const Source = "suppression"

// perSuppression 一条抑制一轮最多看多少个候选事件，下一轮接着收
const perSuppression = 200

type Closer struct {
	DB       *ent.Client
	Store    *suppress.Store
	Interval time.Duration
}

// Run 经 cluster.RunLeader 单活
func (c *Closer) Run(ctx context.Context) {
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	for {
		if n, err := c.Sweep(ctx, time.Now()); err != nil && ctx.Err() == nil {
			slog.Error("抑制回头结案失败", "err", err)
		} else if n > 0 {
			slog.Info("抑制回头结案", "incidents", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Sweep 按每条生效抑制找带它规则命中的未结案事件，逐个核对，返回结案数
func (c *Closer) Sweep(ctx context.Context, now time.Time) (int, error) {
	subs, err := c.DB.Suppression.Query().
		Where(suppression.StatusEQ("active"), suppression.Or(suppression.ExpiresAtIsNil(), suppression.ExpiresAtGT(now))).All(ctx)
	if err != nil {
		return 0, err
	}
	seen, closed := map[uuid.UUID]bool{}, 0
	for _, s := range subs {
		hits := alert.RuleIDEQ(s.RuleID)
		if s.AssetID != nil {
			hits = alert.And(hits, alert.AssetIDEQ(*s.AssetID))
		}
		incs, err := c.DB.Incident.Query().
			Where(incident.StatusIn("open", "triaged"), incident.TriagedAtNotNil(), incident.HasAlertsWith(hits)).
			Order(ent.Asc(incident.FieldID)).Limit(perSuppression).All(ctx)
		if err != nil {
			return closed, err
		}
		for _, inc := range incs {
			if seen[inc.ID] {
				continue
			}
			seen[inc.ID] = true
			ok, err := c.close(ctx, inc, now)
			if err != nil {
				return closed, err
			}
			if ok {
				closed++
			}
		}
	}
	return closed, nil
}

func benign(inc *ent.Incident) bool {
	var v struct {
		Verdict string `json:"verdict"`
	}
	return json.Unmarshal(inc.AiVerdict, &v) == nil && v.Verdict == "benign"
}

// close 全部告警都能读到原始事件、且各自被某条生效抑制覆盖才结案；人工接管的不动
func (c *Closer) close(ctx context.Context, inc *ent.Incident, now time.Time) (bool, error) {
	if !benign(inc) || inc.Work != nil && (inc.Work.ManualLock || inc.Work.ManualOwner != "") {
		return false, nil
	}
	alerts, err := c.DB.Alert.Query().Where(alert.IncidentIDEQ(inc.ID)).WithEvent().All(ctx)
	if err != nil || len(alerts) == 0 {
		return false, err
	}
	var by []string
	for _, a := range alerts {
		var raw map[string]any
		if a.Edges.Event == nil || json.Unmarshal(a.Edges.Event.Raw, &raw) != nil {
			return false, nil
		}
		id := c.Store.Covering(a.RuleID, a.AssetID, raw, now)
		if id == nil {
			return false, nil
		}
		if !slices.Contains(by, id.String()) {
			by = append(by, id.String())
		}
	}
	tx, err := c.DB.Tx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	resolution := fmt.Sprintf("已生效的抑制覆盖本事件全部 %d 条告警（抑制 %s），研判为良性，按抑制口径结案", len(alerts), strings.Join(by, "、"))
	// 研判时间对得上才改：期间重研判或有人处理过的，下一轮按新状态再看
	n, err := tx.Incident.Update().
		Where(incident.IDEQ(inc.ID), incident.StatusEQ(inc.Status), incident.TriagedAtEQ(*inc.TriagedAt)).
		SetStatus("false_positive").SetResolvedBy(review.ClosedBy).SetResolutionSource(Source).
		SetResolvedAt(now).SetResolution(resolution).ClearClosureProposal().Save(ctx)
	if err != nil || n != 1 {
		return false, err
	}
	done, err := tx.Incident.Get(ctx, inc.ID)
	if err == nil {
		err = incidentwork.Refresh(ctx, tx.Client(), done, now)
	}
	if err == nil {
		err = incidentstate.Record(ctx, tx, inc.ID, incidentstate.StatusChanged, incidentstate.Origin{Kind: Source, ID: by[0]}, inc.Status)
	}
	if err == nil {
		err = audit.Checked(ctx, tx.AuditLog.Create(), review.ClosedBy, "server", "incident_status", inc.ID.String(), "false_positive "+resolution)
	}
	if err != nil {
		return false, err
	}
	return true, tx.Commit()
}
