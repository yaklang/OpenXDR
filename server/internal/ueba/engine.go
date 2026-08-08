// Package ueba 行为基线：新进程首次出现检测。
//
// 只做"首次出现"这一种——它的信噪比最高。基线是 (资产, 可执行文件路径) 组合，
// 首次入表即首次出现。学习期按资产从基线里最早一条记录起算：新资产、新部署、
// 服务重启都先安静学习，满期后再告警，不需要任何额外状态就避开了告警风暴。
package ueba

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/event"
	"openxdr/server/ent/processbaseline"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

// OCSF 进程活动
const classProcess = 1007

const batchLimit = 1000

type Engine struct {
	DB             *ent.Client
	Suppress       *suppress.Store
	LearningPeriod time.Duration
	Interval       time.Duration

	cursor time.Time
}

func (e *Engine) Run(ctx context.Context) {
	// 断点从基线表恢复：晚于最后一条基线的事件还没看过。
	// 空表说明是首次启用，从现在开始学，不回放历史。
	last, err := e.DB.ProcessBaseline.Query().
		Order(ent.Desc(processbaseline.FieldFirstSeen)).
		First(ctx)
	if err == nil {
		e.cursor = last.FirstSeen
	} else {
		e.cursor = time.Now()
	}

	ticker := time.NewTicker(e.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				n, err := e.batch(ctx)
				if err != nil {
					slog.Error("UEBA 批次失败", "err", err)
					break
				}
				if n < batchLimit {
					break
				}
			}
		}
	}
}

type comboKey struct {
	asset uuid.UUID
	exe   string
}

func (e *Engine) batch(ctx context.Context) (int, error) {
	events, err := e.DB.Event.Query().
		Where(
			event.ClassUIDEQ(classProcess),
			event.AssetIDNotNil(),
			event.TsGT(e.cursor),
		).
		Order(ent.Asc(event.FieldTs)).
		Limit(batchLimit).
		All(ctx)
	if err != nil || len(events) == 0 {
		return 0, err
	}
	e.cursor = events[len(events)-1].Ts

	// 批内去重，同一组合保留最早那条事件
	fresh := map[comboKey]*ent.Event{}
	for _, ev := range events {
		exe := exePath(ev.Raw)
		if exe == "" {
			continue
		}
		k := comboKey{*ev.AssetID, exe}
		if _, seen := fresh[k]; !seen {
			fresh[k] = ev
		}
	}
	if len(fresh) == 0 {
		return len(events), nil
	}

	// 已知组合从候选里剔掉，剩下的才是首次出现
	paths := make([]string, 0, len(fresh))
	assets := map[uuid.UUID]bool{}
	for k := range fresh {
		paths = append(paths, k.exe)
		assets[k.asset] = true
	}
	known, err := e.DB.ProcessBaseline.Query().
		Where(processbaseline.ExePathIn(paths...)).
		All(ctx)
	if err != nil {
		return 0, err
	}
	for _, b := range known {
		delete(fresh, comboKey{b.AssetID, b.ExePath})
	}
	if len(fresh) == 0 {
		return len(events), nil
	}

	// 学习期：资产在基线里最早的记录距事件不足学习期就只学不报
	assetIDs := make([]uuid.UUID, 0, len(assets))
	for id := range assets {
		assetIDs = append(assetIDs, id)
	}
	var mins []struct {
		AssetID uuid.UUID `json:"asset_id"`
		Min     time.Time `json:"min"`
	}
	if err := e.DB.ProcessBaseline.Query().
		Where(processbaseline.AssetIDIn(assetIDs...)).
		GroupBy(processbaseline.FieldAssetID).
		Aggregate(ent.Min(processbaseline.FieldFirstSeen)).
		Scan(ctx, &mins); err != nil {
		return 0, err
	}
	learnedSince := map[uuid.UUID]time.Time{}
	for _, m := range mins {
		learnedSince[m.AssetID] = m.Min
	}

	baselines := make([]*ent.ProcessBaselineCreate, 0, len(fresh))
	var alerts []*ent.AlertCreate
	for k, ev := range fresh {
		baselines = append(baselines, e.DB.ProcessBaseline.Create().
			SetAssetID(k.asset).
			SetExePath(k.exe).
			SetFirstSeen(ev.Ts))

		since, learning := learnedSince[k.asset]
		if !learning || ev.Ts.Sub(since) < e.LearningPeriod {
			continue
		}
		if e.Suppress.Suppressed(sigma.RuleNewProcess, &k.asset, ev.Ts) {
			continue
		}
		alerts = append(alerts, e.DB.Alert.Create().
			SetTs(ev.Ts).
			SetRuleID(sigma.RuleNewProcess).
			SetSeverity(2).
			SetEventID(ev.ID).
			SetAssetID(k.asset).
			SetLastTs(ev.Ts))
	}

	// 单写者且 known 差集已剔重，直接插入不会撞唯一索引
	if _, err := e.DB.ProcessBaseline.CreateBulk(baselines...).Save(ctx); err != nil {
		return 0, err
	}
	if len(alerts) > 0 {
		if _, err := e.DB.Alert.CreateBulk(alerts...).Save(ctx); err != nil {
			return 0, err
		}
		slog.Info("UEBA 首次出现告警", "count", len(alerts))
	}
	return len(events), nil
}

// exePath 从进程事件里取可执行文件路径，取不到返回空。
func exePath(raw json.RawMessage) string {
	var doc struct {
		Process struct {
			File struct {
				Path string `json:"path"`
			} `json:"file"`
		} `json:"process"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	return doc.Process.File.Path
}
