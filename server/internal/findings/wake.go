package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/finding"
	"openxdr/server/internal/audit"
	"sort"
	"time"
)

// EarlierWake 只缩短复查时间，不解除租约、冷却或授予执行权。
func EarlierWake(w *Work, now, next time.Time) time.Time {
	for _, at := range []*time.Time{w.RetryAt, w.WakeAt} {
		if at != nil && at.After(now) && at.Before(next) {
			next = *at
		}
	}
	return next
}

// DependencyState 仅接受同组实际资产上的待办；resolved 必须由既有独立复核或人工流程产生。
func DependencyState(ctx context.Context, db *ent.Client, group, self uuid.UUID, ids []uuid.UUID) (string, bool, error) {
	if len(ids) > 5 {
		return "", false, errors.New("最多五条依赖待办")
	}
	if len(ids) == 0 {
		return "", false, nil
	}
	values := []string{}
	seen := map[uuid.UUID]bool{}
	all := true
	for _, id := range ids {
		if id == uuid.Nil || id == self || seen[id] {
			return "", false, errors.New("依赖待办不能重复或引用自己")
		}
		seen[id] = true
		row, err := db.Finding.Query().Where(finding.IDEQ(id), finding.GroupIDEQ(group)).Only(ctx)
		if err != nil {
			return "", false, err
		}
		owned, err := db.Asset.Query().Where(asset.IDEQ(row.AssetID), asset.GroupIDEQ(group)).Exist(ctx)
		if err != nil || !owned {
			return "", false, errors.New("依赖待办资产已不属于本组")
		}
		if row.Status != "resolved" {
			all = false
		}
		values = append(values, id.String()+":"+row.Status)
	}
	sort.Strings(values)
	raw, _ := json.Marshal(values)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), all, nil
}

// ValidateDependencies 检查有界依赖图，拒绝环、越组与无法完整核实的长链。
func ValidateDependencies(ctx context.Context, db *ent.Client, group, self uuid.UUID, ids []uuid.UUID) error {
	_, _, err := DependencyState(ctx, db, group, self, ids)
	if err != nil {
		return err
	}
	path := map[uuid.UUID]bool{self: true}
	count := 0
	var walk func([]uuid.UUID, int) error
	walk = func(next []uuid.UUID, depth int) error {
		if depth > 8 {
			return errors.New("依赖链过深，无法安全登记")
		}
		for _, id := range next {
			if path[id] {
				return errors.New("依赖待办形成循环")
			}
			count++
			if count > 64 {
				return errors.New("依赖图过大，无法安全登记")
			}
			row, err := db.Finding.Query().Where(finding.IDEQ(id), finding.GroupIDEQ(group)).Only(ctx)
			if err != nil {
				return err
			}
			owned, err := db.Asset.Query().Where(asset.IDEQ(row.AssetID), asset.GroupIDEQ(group)).Exist(ctx)
			if err != nil || !owned {
				return errors.New("依赖链资产已不属于本组")
			}
			var w Work
			if len(row.Work) > 0 {
				if err := json.Unmarshal(row.Work, &w); err != nil {
					return err
				}
			}
			path[id] = true
			if err := walk(w.DependsOn, depth+1); err != nil {
				return err
			}
			delete(path, id)
		}
		return nil
	}
	return walk(ids, 0)
}

// RefreshWake 在正常调度领取前核对条件；只安排重新调查，不自动结案或提升人工权限。
func RefreshWake(ctx context.Context, db *ent.Client, group uuid.UUID, now time.Time, inspect func(context.Context, *ent.Finding) (RepairCapabilities, error)) error {
	rows, err := db.Finding.Query().Where(finding.GroupIDEQ(group), finding.StatusEQ("open"), finding.Or(finding.WorkLeaseUntilIsNil(), finding.WorkLeaseUntilLTE(now))).All(ctx)
	if err != nil {
		return err
	}
	for _, f := range rows {
		owned, err := db.Asset.Query().Where(asset.IDEQ(f.AssetID), asset.GroupIDEQ(group)).Exist(ctx)
		if err != nil {
			return err
		}
		if !owned {
			continue
		}
		var w Work
		if len(f.Work) > 0 {
			if err := json.Unmarshal(f.Work, &w); err != nil {
				return err
			}
		}
		if f.WorkOwner != "ai" && !(f.WorkOwner == "human" && w.Stage == "blocked") {
			continue
		}
		before := EncodeWork(w)
		reason := ""
		if w.Version < 3 && MachineBlocker(w.Blocker) {
			reason = "capability_upgrade"
		}
		if inspect != nil {
			cap, err := inspect(ctx, f)
			if err != nil {
				return err
			}
			if w.PolicyFingerprint != "" && cap.PolicyFingerprint != w.PolicyFingerprint {
				reason = "authorization_changed"
			}
			w.PolicyFingerprint = cap.PolicyFingerprint
			if w.Blocker == "maintenance_window_required" && w.RetryAt == nil && cap.RetryAt != nil {
				w.RetryAt = cap.RetryAt
			}
		}
		if w.RetryAt != nil && !w.RetryAt.After(now) {
			reason = "cooldown_or_window_elapsed"
			w.RetryAt = nil
		}
		if w.WakeAt != nil && !w.WakeAt.After(now) {
			reason = "scheduled_review"
			w.WakeAt = nil
		}
		if len(w.DependsOn) > 0 {
			fp, all, err := DependencyState(ctx, db, group, f.ID, w.DependsOn)
			if err != nil {
				continue
			} // 依赖转组或不存在时保持阻塞，不把失去证据当成恢复。
			if all && fp != w.DependencyFingerprint {
				reason = "dependency_recovered"
			}
			w.DependencyFingerprint = fp
		}
		w.Version = 3
		if reason != "" {
			w.LastWakeReason = reason
		}
		encoded := EncodeWork(w)
		if string(encoded) == string(before) && reason == "" {
			continue
		}
		tx, err := db.Tx(ctx)
		if err != nil {
			return err
		}
		update := tx.Finding.Update().Where(finding.IDEQ(f.ID), finding.GroupIDEQ(group), finding.StatusEQ("open"), Snapshot(f), finding.Or(finding.WorkLeaseUntilIsNil(), finding.WorkLeaseUntilLTE(now))).SetWork(encoded)
		if reason != "" {
			update.SetWorkNextCheckAt(now)
		}
		n, err := update.Save(ctx)
		if err == nil && n == 1 && reason != "" {
			err = audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "finding_work_woken", f.ID.String(), "reason="+reason)
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
