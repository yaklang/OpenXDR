package api

import (
	"encoding/json"
	"github.com/google/uuid"
	"io"
	"net/http"
	"openxdr/server/ent"
	"openxdr/server/ent/decoydeployment"
	"openxdr/server/internal/decoy"
	"time"
)

func decoyLeaseActive(row *ent.DecoyDeployment, now time.Time) bool {
	return row.RuntimeInstanceID != nil && row.RuntimeSeenAt != nil && now.Before(row.RuntimeSeenAt.Add(decoy.LeaseTTL)) && (row.RuntimeState == decoydeployment.RuntimeStateStarting || row.RuntimeState == decoydeployment.RuntimeStateRunning)
}
func decoyLeaseAllows(row *ent.DecoyDeployment, instance, token string, now time.Time) bool {
	return decoyLeaseActive(row, now) && row.RuntimeState == decoydeployment.RuntimeStateRunning && row.RuntimeInstanceID.String() == instance && row.RuntimeGeneration == decoyTokenHash(token)
}

// 调用方已认证令牌并持有资产锁；租约、轮换、撤销和迁组不会交叉提交。
func updateDecoyLease(w http.ResponseWriter, r *http.Request, tx *ent.Tx, row *ent.DecoyDeployment, token string) {
	var body struct {
		Instance  uuid.UUID `json:"instance"`
		State     string    `json:"state"`
		Pending   *int      `json:"pending,omitempty"`
		ErrorCode string    `json:"errorCode,omitempty"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil || d.Decode(new(any)) != io.EOF || body.Instance == uuid.Nil {
		http.Error(w, "租约请求无效", 400)
		return
	}
	switch body.State {
	case "starting", "running", "stopped", "failed":
	default:
		http.Error(w, "运行状态无效", 400)
		return
	}
	if body.Pending != nil && (*body.Pending < 0 || *body.Pending > 10000) {
		http.Error(w, "积压数量无效", 400)
		return
	}
	switch body.ErrorCode {
	case "", "delivery_failed", "platform_unavailable", "startup_failed", "pending_on_stop":
	default:
		http.Error(w, "错误码无效", 400)
		return
	}
	now := time.Now()
	generation := decoyTokenHash(token)
	same := row.RuntimeInstanceID != nil && *row.RuntimeInstanceID == body.Instance && row.RuntimeGeneration == generation
	active := decoyLeaseActive(row, now)
	if active && !same {
		http.Error(w, "已有运行实例，请先停止或等待租约过期", 409)
		return
	}
	if same && (row.RuntimeState == decoydeployment.RuntimeStateStopped || row.RuntimeState == decoydeployment.RuntimeStateFailed) {
		if string(row.RuntimeState) == body.State {
			w.WriteHeader(204)
			return
		}
		http.Error(w, "已结束实例不可重新启动", 409)
		return
	}
	if body.State != "starting" && (!same || !active) {
		http.Error(w, "运行租约已失效", 409)
		return
	}
	if body.State == "starting" && same {
		if !active || row.RuntimeState != decoydeployment.RuntimeStateStarting {
			http.Error(w, "不能回退运行状态或复活过期实例", 409)
			return
		}
	}
	update := tx.DecoyDeployment.UpdateOneID(row.ID).SetRuntimeInstanceID(body.Instance).SetRuntimeGeneration(generation).SetRuntimeState(decoydeployment.RuntimeState(body.State)).SetRuntimeSeenAt(now)
	// 持有租约的实例每次续租顺延令牌，常驻诱饵不会在签发 24 小时后自行停服；
	// 撤销、迁组与轮换仍立即失效，停止心跳的令牌照常到期。
	if body.State == "starting" || body.State == "running" {
		update.SetTokenExpiresAt(now.Add(decoyTokenTTL))
	}
	if body.Pending != nil {
		update.SetRuntimePending(*body.Pending).SetRuntimeError(body.ErrorCode)
	}
	if body.State == "starting" && !same {
		update.ClearRuntimePending().SetRuntimeError("")
	}
	err := update.Exec(r.Context())
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		http.Error(w, "更新运行租约失败", 503)
		return
	}
	w.WriteHeader(204)
}

// 状态仅代表运行端回报，不证明服务可达或进程已被远程终止。
func decoyRuntimeStatus(row *ent.DecoyDeployment, now time.Time) string {
	if row.RuntimeInstanceID == nil {
		return "unreported"
	}
	if row.RuntimeState == decoydeployment.RuntimeStateStopped || row.RuntimeState == decoydeployment.RuntimeStateFailed {
		return string(row.RuntimeState)
	}
	if !decoyLeaseActive(row, now) {
		return "stale"
	}
	if row.Status != decoydeployment.StatusRegistered || row.TokenExpiresAt == nil || !now.Before(*row.TokenExpiresAt) || row.RuntimeGeneration != row.TokenHash {
		return "stopping"
	}
	return string(row.RuntimeState)
}
