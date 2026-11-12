package repairpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/command"
	"openxdr/server/ent/setting"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/repaircmd"
)

// ValidServiceUnit 判断服务名是否为允许自动操作的非核心 systemd service。
func ValidServiceUnit(unit string) bool {
	return validUnit(unit)
}

// ParseWindow 解析 HH:MM-HH:MM 格式维护窗口，允许当日窗口或跨零点窗口，起止不得相同。
func ParseWindow(s string) (time.Duration, time.Duration, error) {
	a, b, ok := strings.Cut(strings.TrimSpace(s), "-")
	if !ok {
		return 0, 0, errors.New("维护窗口格式应为 HH:MM-HH:MM")
	}
	parse := func(v string) (time.Duration, error) {
		t, err := time.Parse("15:04", strings.TrimSpace(v))
		if err != nil {
			return 0, errors.New("维护窗口格式应为 HH:MM-HH:MM")
		}
		return time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute, nil
	}
	start, err := parse(a)
	if err != nil {
		return 0, 0, err
	}
	end, err := parse(b)
	if err != nil {
		return 0, 0, err
	}
	if start == end {
		return 0, 0, errors.New("维护窗口起止时间不能相同")
	}
	return start, end, nil
}

// WindowBounds 计算当前或下一轮维护窗口的精确起止时间。window 为空表示不限时段。
func WindowBounds(window string, loc *time.Location, now time.Time) (active bool, start, end time.Time, err error) {
	if loc == nil {
		loc = time.Local
	}
	if strings.TrimSpace(window) == "" {
		u := now.UTC()
		weekday := int(u.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		monday := time.Date(u.Year(), u.Month(), u.Day()-(weekday-1), 0, 0, 0, 0, time.UTC)
		return true, u.Add(-time.Minute), monday.Add(14 * 24 * time.Hour), nil
	}
	wStart, wEnd, err := ParseWindow(window)
	if err != nil {
		return false, time.Time{}, time.Time{}, err
	}
	local := now.In(loc)
	day := func(offsetDays int) time.Time {
		return time.Date(local.Year(), local.Month(), local.Day()+offsetDays, 0, 0, 0, 0, loc)
	}
	midnight := day(0)
	at := local.Sub(midnight)
	if wStart < wEnd {
		switch {
		case at < wStart:
			return false, midnight.Add(wStart), midnight.Add(wEnd), nil
		case at < wEnd:
			return true, midnight.Add(wStart), midnight.Add(wEnd), nil
		default:
			next := day(1)
			return false, next.Add(wStart), next.Add(wEnd), nil
		}
	}
	// 跨零点窗口（如 23:00-05:00）
	switch {
	case at < wEnd:
		return true, day(-1).Add(wStart), midnight.Add(wEnd), nil
	case at >= wStart:
		return true, midnight.Add(wStart), day(1).Add(wEnd), nil
	default:
		return false, midnight.Add(wStart), day(1).Add(wEnd), nil
	}
}

// CooldownUntil 查询指定资产与单元（服务名或 reclaim_disk）当前生效的冷却截止时间。
func (s *Store) CooldownUntil(ctx context.Context, assetID uuid.UUID, unit string, now time.Time) (*time.Time, error) {
	row, err := s.DB.Setting.Get(ctx, useKey(assetID, unit))
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var u use
	if err := strict(row.Value, &u); err != nil {
		return nil, err
	}
	if u.NextAllowedAt.After(now) {
		at := u.NextAllowedAt
		return &at, nil
	}
	return nil, nil
}

// StandingRequest 常设规矩 auto 档下发前的预留参数。
type StandingRequest struct {
	RuleID          uuid.UUID
	RuleVersion     string
	GroupID         uuid.UUID
	AssetID         uuid.UUID
	FindingID       uuid.UUID
	Unit            string
	Command         string
	Mount           string
	AllowedPaths    []string
	BeforeProbeID   uuid.UUID
	CooldownMinutes int
}

// ReserveStanding 为常设规矩 auto 档预留一次性动作并写入资产冷却与审计，与 ops-followup 共用冷却键。
func (s *Store) ReserveStanding(ctx context.Context, req StandingRequest) (retID uuid.UUID, retErr error) {
	defer func() {
		if retErr == nil {
			return
		}
		logCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		target := req.RuleID.String()
		if err := audit.Checked(logCtx, s.DB.AuditLog.Create(), "system", "server", "repair_action_denied", target, retErr.Error()); err != nil {
			retErr = fmt.Errorf("%w；拒绝审计落库失败", retErr)
		}
	}()

	if req.RuleID == uuid.Nil || req.GroupID == uuid.Nil || req.AssetID == uuid.Nil {
		return uuid.Nil, errors.New("常设规矩预留缺少规矩、组或资产标识")
	}
	if req.CooldownMinutes < 60 || req.CooldownMinutes > 10080 {
		return uuid.Nil, errors.New("资产冷却时间须在 60 至 10080 分钟之间")
	}
	isDisk := req.Unit == ReclaimDisk
	if isDisk {
		if !repaircmd.IsStandingDiskAction(req.Command, req.AllowedPaths) || !repaircmd.Mount(req.Mount) {
			return uuid.Nil, errors.New("磁盘动作不属于平台支持的封闭回收或无损压缩模板，或超出规矩授权目录")
		}
	} else {
		if !validUnit(req.Unit) || req.Command != "systemctl restart -- "+req.Unit {
			return uuid.Nil, errors.New("服务动作不属于平台支持的非核心服务重启模板")
		}
	}

	now := time.Now()
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback()

	ok, err := tx.Asset.Query().Where(asset.IDEQ(req.AssetID), asset.GroupIDEQ(req.GroupID), asset.OsEQ("linux")).Exist(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	if !ok {
		return uuid.Nil, errors.New("目标资产不是所属组的 Linux 主机")
	}

	key := useKey(req.AssetID, req.Unit)
	old, err := tx.Setting.Query().Where(setting.IDEQ(key)).Where(func(q *sql.Selector) { q.ForUpdate() }).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return uuid.Nil, err
	}
	if old != nil {
		var prior use
		if err := strict(old.Value, &prior); err != nil {
			return uuid.Nil, err
		}
		if prior.NextAllowedAt.After(now) {
			return uuid.Nil, fmt.Errorf("资产动作仍处于冷却期，最早 %s 后重新评估", prior.NextAllowedAt.UTC().Format(time.RFC3339))
		}
	}

	probe, err := tx.Command.Get(ctx, req.BeforeProbeID)
	if err != nil {
		return uuid.Nil, errors.New("缺少执行前只读探针")
	}
	if probe.AssetID != req.AssetID || probe.Kind != "exec" || probe.Cmd == nil || probe.Status != "succeeded" || probe.ExitCode == nil || *probe.ExitCode != 0 || probe.Truncated || probe.CompletedAt == nil || probe.CompletedAt.Before(now.Add(-10*time.Minute)) || probe.CompletedAt.After(now) || probe.Stdout == nil {
		return uuid.Nil, errors.New("执行前探针未完整成功或已过期")
	}
	if isDisk {
		if _, err := diskSample(probe, req.Mount); err != nil {
			return uuid.Nil, err
		}
	} else {
		if *probe.Cmd != ProbeCommand(req.Unit) {
			return uuid.Nil, errors.New("服务探针命令不匹配")
		}
		fields := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(*probe.Stdout), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				return uuid.Nil, errors.New("systemctl诊断字段不完整")
			}
			fields[k] = v
		}
		if fields["Id"] != req.Unit || fields["ActiveState"] != "failed" || fields["UnitFileState"] != "enabled" {
			return uuid.Nil, errors.New("探针未证明目标服务为 failed 且 enabled")
		}
	}

	pending, err := tx.Command.Query().Where(command.AssetIDEQ(req.AssetID), command.StatusIn("pending", "sent", "unknown")).All(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	for _, c := range pending {
		if c.Kind != "exec" || c.Cmd == nil || !commandgate.ReadOnly(*c.Cmd) {
			return uuid.Nil, errors.New("存在未知写动作，禁止自动新增修复")
		}
	}

	problem := digest([]string{req.RuleID.String(), req.FindingID.String(), req.AssetID.String(), req.Command, now.UTC().Format(time.RFC3339Nano)})
	resID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("openxdr:standing|"+req.RuleID.String()+"|"+req.AssetID.String()+"|"+req.Unit+"|"+problem))
	reserved := use{
		ProblemHash:   problem,
		GrantVersion:  req.RuleVersion,
		FindingID:     req.FindingID,
		Command:       req.Command,
		FinalizedAt:   &now,
		SessionID:     req.RuleID,
		GrantID:       req.RuleID,
		ReservationID: resID,
		ReservedAt:    now,
		NextAllowedAt: now.Add(time.Duration(req.CooldownMinutes) * time.Minute),
		ProbeID:       probe.ID,
	}
	raw, _ := json.Marshal(reserved)
	if old == nil {
		err = tx.Setting.Create().SetID(key).SetValue(raw).Exec(ctx)
	} else {
		err = tx.Setting.UpdateOneID(key).SetValue(raw).Exec(ctx)
	}
	if err != nil {
		return uuid.Nil, err
	}
	target := req.FindingID.String()
	if req.FindingID == uuid.Nil {
		target = req.AssetID.String()
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "repair_action_reserved", target, fmt.Sprintf("standing_rule=%s asset=%s unit=%s probe=%s reservation=%s", req.RuleID, req.AssetID, req.Unit, probe.ID, resID)); err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(); err != nil {
		return uuid.Nil, err
	}
	return resID, nil
}

// BindStandingAction 记录常设规矩实际下发的命令 ID 并写审计。
func (s *Store) BindStandingAction(ctx context.Context, assetID uuid.UUID, unit string, reservationID, commandID uuid.UUID) error {
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	row, err := tx.Setting.Query().Where(setting.IDEQ(useKey(assetID, unit))).Where(func(q *sql.Selector) { q.ForUpdate() }).Only(ctx)
	if err != nil {
		return errors.New("动作已下发但缺少预留记录")
	}
	var u use
	if err := strict(row.Value, &u); err != nil {
		return err
	}
	actual, err := tx.Command.Get(ctx, commandID)
	if err != nil {
		return err
	}
	if u.ReservationID != reservationID || u.ActionID != uuid.Nil || actual.AssetID != assetID || actual.Kind != "exec" || actual.Cmd == nil || *actual.Cmd != u.Command {
		return errors.New("下发命令与常设规矩一次性预留不匹配")
	}
	u.ActionID = actual.ID
	raw, _ := json.Marshal(u)
	if err := tx.Setting.UpdateOneID(row.ID).SetValue(raw).Exec(ctx); err != nil {
		return err
	}
	target := u.FindingID.String()
	if u.FindingID == uuid.Nil {
		target = assetID.String()
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "repair_action_issued", target, "command="+actual.ID.String()+" reservation="+reservationID.String()); err != nil {
		return err
	}
	return tx.Commit()
}

// VerifyStandingDisk 用执行前后的独立 df -P 探针校验常设规矩磁盘回收或无损压缩效果。
func (s *Store) VerifyStandingDisk(ctx context.Context, assetID, reservationID, afterProbeID uuid.UUID) (uint64, uint64, error) {
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	row, err := tx.Setting.Query().Where(setting.IDEQ(useKey(assetID, ReclaimDisk))).Where(func(q *sql.Selector) { q.ForUpdate() }).Only(ctx)
	if err != nil {
		return 0, 0, errors.New("缺少磁盘动作预留记录")
	}
	var u use
	if err := strict(row.Value, &u); err != nil {
		return 0, 0, err
	}
	if u.ReservationID != reservationID || u.ActionID == uuid.Nil {
		return 0, 0, errors.New("磁盘动作未确认下发，不能校验效果")
	}
	action, err := tx.Command.Get(ctx, u.ActionID)
	if err != nil {
		return 0, 0, err
	}
	if action.AssetID != assetID || action.Kind != "exec" || action.Cmd == nil || *action.Cmd != u.Command || action.Status != "succeeded" || action.ExitCode == nil || *action.ExitCode != 0 || action.CompletedAt == nil {
		return 0, 0, errors.New("磁盘动作未成功完成")
	}
	before, err := tx.Command.Get(ctx, u.ProbeID)
	if err != nil || before.Cmd == nil {
		return 0, 0, errors.New("缺少执行前 df -P 探针")
	}
	mount := strings.TrimPrefix(*before.Cmd, "df -P ")
	pre, err := readDiskSample(before, mount, false)
	if err != nil || before.AssetID != assetID {
		return 0, 0, errors.New("执行前 df -P 基线无效")
	}
	after, err := tx.Command.Get(ctx, afterProbeID)
	if err != nil {
		return 0, 0, errors.New("缺少执行后 df -P 探针")
	}
	post, err := diskSample(after, mount)
	if err != nil {
		return 0, 0, err
	}
	if after.AssetID != assetID || after.ID == before.ID || after.ID == action.ID || after.CreatedAt.Before(*action.CompletedAt) || post.filesystem != pre.filesystem || post.total != pre.total || post.available < pre.available {
		return 0, 0, errors.New("独立 df -P 探针未能证明同一文件系统可用空间未减少且探针不早于动作完成")
	}
	now := time.Now()
	u.VerifiedAt, u.AfterProbeID = &now, after.ID
	raw, _ := json.Marshal(u)
	if err := tx.Setting.UpdateOneID(row.ID).SetValue(raw).Exec(ctx); err != nil {
		return 0, 0, err
	}
	target := u.FindingID.String()
	if u.FindingID == uuid.Nil {
		target = assetID.String()
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "repair_action_verified", target, fmt.Sprintf("before=%s after=%s command=%s avail_kb=%d->%d", before.ID, after.ID, action.ID, pre.available, post.available)); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return pre.available, post.available, nil
}
