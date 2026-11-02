package triage

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/incident"
)

const RunningTTL = time.Minute

// RunningStartedAt 只展示心跳仍然有效的执行；节点退出后不永久留在研判中。
func RunningStartedAt(inc *ent.Incident, now time.Time) *time.Time {
	if inc.Status != "open" && inc.Status != "triaged" {
		return nil
	}
	if inc.TriageStartedAt == nil || inc.TriageHeartbeatAt == nil || !inc.TriageHeartbeatAt.After(now.Add(-RunningTTL)) {
		return nil
	}
	return inc.TriageStartedAt
}

// keepRunning 的开始时间也是执行标识，旧执行不能刷新或清除新执行的状态。
func (e *Engine) keepRunning(parent context.Context, id uuid.UUID, started time.Time) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				beatCtx, stop := context.WithTimeout(ctx, 5*time.Second)
				n, err := e.DB.Incident.Update().Where(incident.IDEQ(id), incident.TriageStartedAtEQ(started)).SetTriageHeartbeatAt(time.Now()).Save(beatCtx)
				stop()
				if err != nil || n == 0 {
					if err != nil {
						slog.Warn("研判心跳失败，停止本次执行", "id", id, "err", err)
					}
					cancel()
					return
				}
			}
		}
	}()
	return ctx, func() {
		cancel()
		<-done
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := e.DB.Incident.Update().Where(incident.IDEQ(id), incident.TriageStartedAtEQ(started)).ClearTriageStartedAt().ClearTriageHeartbeatAt().Exec(cleanup); err != nil {
			slog.Warn("清理研判执行状态失败，等待心跳过期", "id", id, "err", err)
		}
	}
}
