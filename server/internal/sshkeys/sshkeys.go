// Package sshkeys 物化 Linux agent 上报的 SSH 授权钥匙盘点快照，并与登录记录、权威事实交叉比对。
//
// 安全原则：
//   - 盘点结果只是「观测」，不是「事实」；公钥尾部注释攻击者可随意伪造，仅作界面提示。
//   - 只有平台管理员确认持有人、所在机器与用途后，才写入 facts 表成为 key 事实。
//   - 已有盘点基线的资产上新出现的钥匙：照常产生高危告警（附写入它的登录会话若能关联），
//     并生成一条待审批的移除提议走 commandgate 现有审批，从不自动删除。
package sshkeys

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/approval"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/ent/fact"
	entintegration "openxdr/server/ent/integration"
	"openxdr/server/ent/predicate"
	"openxdr/server/ent/sshkeybaseline"
	"openxdr/server/ent/sshkeyobservation"
	"openxdr/server/ent/sshlogin"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/facts"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/pb"
)

const (
	// IdleWindow 超过 90 天未见公钥成功登录标为闲置
	IdleWindow = 90 * 24 * time.Hour
	// ProposalTTL 新钥匙移除提议的默认待批有效期
	ProposalTTL = 72 * time.Hour

	maxKeysPerAsset = 4096
)

var fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// ValidFingerprint 校验 SHA256 公钥指纹格式（与 ssh-keygen -lf 及 login_session.key_fp 一致）
func ValidFingerprint(fp string) bool {
	return fingerprintRe.MatchString(fp)
}

// RemovalCommand 构造按 SHA256 指纹精确核对并移除目标 authorized_keys 中对应公钥行的 POSIX sh 命令。
// 拒绝操作符号链接，通过同目录临时文件与 cp -p 保留原文件属主和权限，绝不按不可信注释匹配。
func RemovalCommand(filePath, fingerprint string) (string, error) {
	if !ValidFingerprint(fingerprint) {
		return "", errors.New("公钥指纹格式无效")
	}
	if filePath == "" || !strings.HasPrefix(filePath, "/") || len(filePath) > 1024 ||
		strings.ContainsAny(filePath, "\x00\r\n") {
		return "", errors.New("授权文件路径无效")
	}
	quotedFile := quoteSh(filePath)
	quotedFP := quoteSh(fingerprint)
	cmd := fmt.Sprintf(
		`set -eu; f=%s; fp=%s; command -v ssh-keygen >/dev/null; [ -f "$f" ] && [ ! -L "$f" ]; `+
			`tmp=$(mktemp "${f}.openxdr.XXXXXX"); trap 'rm -f "$tmp"' EXIT; cp -p "$f" "$tmp"; : >"$tmp"; `+
			`removed=0; while IFS= read -r line || [ -n "$line" ]; do `+
			`k=$(printf '%%s\n' "$line" | ssh-keygen -lf - 2>/dev/null | awk 'NR==1{print $2}') || k=''; `+
			`if [ "$k" = "$fp" ]; then removed=$((removed+1)); else printf '%%s\n' "$line" >>"$tmp"; fi; `+
			`done <"$f"; [ "$removed" -gt 0 ]; mv -f "$tmp" "$f"; trap - EXIT`,
		quotedFile, quotedFP,
	)
	return cmd, nil
}

func quoteSh(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Execer 支持在 ingest 事务中顺带刷新钥匙最后登录时间
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// RecordLogin 在接入层收到 agent 3002 登录事件时，推进对应观测条目的最后登录时间与来源地址
func RecordLogin(ctx context.Context, q Execer, assetID uuid.UUID, raw []byte, ts time.Time) error {
	if q == nil || assetID == uuid.Nil || len(raw) == 0 {
		return nil
	}
	var payload struct {
		LoginSession struct {
			User  string `json:"user"`
			SrcIP string `json:"src_ip"`
			KeyFP string `json:"key_fp"`
		} `json:"login_session"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return nil
	}
	ls := payload.LoginSession
	if ls.User == "" || !ValidFingerprint(ls.KeyFP) {
		return nil
	}
	_, err := q.ExecContext(ctx, `UPDATE ssh_key_observations
SET last_login_at = $4, last_login_ip = $5
WHERE asset_id = $1 AND account = $2 AND fingerprint = $3
  AND (last_login_at IS NULL OR last_login_at <= $4)`,
		assetID, ls.User, ls.KeyFP, ts, cleanText(ls.SrcIP, 128))
	return err
}

type Service struct {
	DB       *ent.Client
	SQL      *sql.DB
	Gate     *commandgate.Gate
	Suppress *suppress.Store
	Now      func() time.Time
	// OnBackfill 测试钩子：仅在主机首次建基线触发登录历史回填时回调
	OnBackfill func(assetID uuid.UUID)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

type tupleKey struct {
	account     string
	filePath    string
	fingerprint string
}

type sanitizedKey struct {
	tupleKey
	keyType string
	comment string
	options []string
}

type loginKey struct {
	account     string
	fingerprint string
}

type loginInfo struct {
	ts    time.Time
	srcIP string
}

type writerSession struct {
	User  string `json:"user,omitempty"`
	SrcIP string `json:"src_ip,omitempty"`
	KeyFP string `json:"key_fp,omitempty"`
}

// IngestSnapshot 物化单台资产上报的 SSH 授权钥匙盘点快照
func (s *Service) IngestSnapshot(ctx context.Context, assetID uuid.UUID, req *pb.ReportSSHKeysRequest) error {
	if s == nil || s.DB == nil || req == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	assetRow, err := s.DB.Asset.Get(ctx, assetID)
	if err != nil {
		return err
	}
	return s.IngestAssetSnapshot(ctx, assetRow, req)
}

// IngestAssetSnapshot 物化已查出资产实体的 SSH 授权钥匙盘点快照
func (s *Service) IngestAssetSnapshot(ctx context.Context, assetRow *ent.Asset, req *pb.ReportSSHKeysRequest) error {
	if s == nil || s.DB == nil || assetRow == nil || req == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	assetID := assetRow.ID
	now := s.now()
	observedAt := now
	if req.ObservedAtMs > 0 {
		t := time.UnixMilli(req.ObservedAtMs)
		if t.After(now.Add(-24*time.Hour)) && t.Before(now.Add(5*time.Minute)) {
			observedAt = t
		}
	}

	cleaned := sanitizeKeys(req.Keys)
	akCmd := cleanText(req.AuthorizedKeysCommand, 512)
	akUser := cleanText(req.AuthorizedKeysCommandUser, 256)

	base, err := s.DB.SSHKeyBaseline.Query().Where(sshkeybaseline.AssetIDEQ(assetID)).Only(ctx)
	hadBaseline := err == nil
	if err != nil && !ent.IsNotFound(err) {
		return err
	}

	// 快路径：已有基线且快照内容完全未变时，只批量刷新在位钥匙的 last_seen，不开事务、不改基线表、不回填
	if hadBaseline {
		presentRows, err := s.DB.SSHKeyObservation.Query().
			Where(sshkeyobservation.AssetIDEQ(assetID), sshkeyobservation.PresentEQ(true)).
			All(ctx)
		if err != nil {
			return err
		}
		if snapshotUnchanged(base, presentRows, cleaned, akCmd, akUser) {
			if len(presentRows) > 0 {
				if err := s.DB.SSHKeyObservation.Update().
					Where(sshkeyobservation.AssetIDEQ(assetID), sshkeyobservation.PresentEQ(true)).
					SetLastSeen(observedAt).
					Exec(ctx); err != nil {
					return err
				}
			}
			return nil
		}
	}

	// 仅在该主机首次建基线时从 ssh_logins 物化表回填一次最近登录信息；后续快照由 ingest 实时刷新
	var backfilled map[loginKey]loginInfo
	if !hadBaseline {
		backfilled, err = s.loadBackfillLogins(ctx, assetID, now, len(cleaned) > 0)
		if err != nil {
			return err
		}
	}

	var newlyAppeared []*ent.SSHKeyObservation
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	baseInTx, err := tx.SSHKeyBaseline.Query().Where(sshkeybaseline.AssetIDEQ(assetID)).Only(ctx)
	hadBaselineInTx := err == nil
	if err != nil && !ent.IsNotFound(err) {
		return err
	}
	if !hadBaselineInTx {
		if _, err := tx.SSHKeyBaseline.Create().
			SetAssetID(assetID).
			SetFirstReportedAt(observedAt).
			SetLastReportedAt(observedAt).
			SetAuthorizedKeysCommand(akCmd).
			SetAuthorizedKeysCommandUser(akUser).
			Save(ctx); err != nil {
			return err
		}
	} else {
		if err := tx.SSHKeyBaseline.UpdateOneID(baseInTx.ID).
			SetLastReportedAt(observedAt).
			SetAuthorizedKeysCommand(akCmd).
			SetAuthorizedKeysCommandUser(akUser).
			Exec(ctx); err != nil {
			return err
		}
	}

	existingRows, err := tx.SSHKeyObservation.Query().Where(sshkeyobservation.AssetIDEQ(assetID)).All(ctx)
	if err != nil {
		return err
	}
	existing := make(map[tupleKey]*ent.SSHKeyObservation, len(existingRows))
	for _, r := range existingRows {
		existing[tupleKey{account: r.Account, filePath: r.FilePath, fingerprint: r.Fingerprint}] = r
	}

	seen := make(map[tupleKey]bool, len(cleaned))
	var unchangedIDs []uuid.UUID
	for _, item := range cleaned {
		seen[item.tupleKey] = true
		prev, ok := existing[item.tupleKey]
		if !ok {
			c := tx.SSHKeyObservation.Create().
				SetAssetID(assetID).
				SetAccount(item.account).
				SetFilePath(item.filePath).
				SetKeyType(item.keyType).
				SetFingerprint(item.fingerprint).
				SetComment(item.comment).
				SetOptions(item.options).
				SetPresent(true).
				SetFirstSeen(observedAt).
				SetLastSeen(observedAt)
			if !hadBaselineInTx {
				if li, hasLogin := backfilled[loginKey{account: item.account, fingerprint: item.fingerprint}]; hasLogin {
					c.SetLastLoginAt(li.ts).SetLastLoginIP(li.srcIP)
				}
			}
			created, err := c.Save(ctx)
			if err != nil {
				return err
			}
			if hadBaselineInTx {
				newlyAppeared = append(newlyAppeared, created)
			}
			continue
		}
		wasAbsent := !prev.Present
		var backfillHit *loginInfo
		if !hadBaselineInTx {
			if li, hasLogin := backfilled[loginKey{account: item.account, fingerprint: item.fingerprint}]; hasLogin &&
				(prev.LastLoginAt == nil || prev.LastLoginAt.Before(li.ts)) {
				backfillHit = &li
			}
		}
		if !wasAbsent && backfillHit == nil &&
			prev.KeyType == item.keyType &&
			prev.Comment == item.comment &&
			slices.Equal(prev.Options, item.options) {
			unchangedIDs = append(unchangedIDs, prev.ID)
			continue
		}
		u := tx.SSHKeyObservation.UpdateOneID(prev.ID).
			SetKeyType(item.keyType).
			SetComment(item.comment).
			SetOptions(item.options).
			SetPresent(true).
			SetLastSeen(observedAt)
		if backfillHit != nil {
			u.SetLastLoginAt(backfillHit.ts).SetLastLoginIP(backfillHit.srcIP)
		}
		if wasAbsent {
			u.SetFirstSeen(observedAt).
				SetAddedByUser("").
				SetAddedByIP("").
				SetAddedByKeyFp("").
				ClearRemovalApprovalID()
		}
		updated, err := u.Save(ctx)
		if err != nil {
			return err
		}
		if hadBaselineInTx && wasAbsent {
			newlyAppeared = append(newlyAppeared, updated)
		}
	}

	if len(unchangedIDs) > 0 {
		if err := tx.SSHKeyObservation.Update().
			Where(sshkeyobservation.IDIn(unchangedIDs...)).
			SetLastSeen(observedAt).
			Exec(ctx); err != nil {
			return err
		}
	}

	var removedIDs []uuid.UUID
	for tk, prev := range existing {
		if prev.Present && !seen[tk] {
			removedIDs = append(removedIDs, prev.ID)
		}
	}
	if len(removedIDs) > 0 {
		if err := tx.SSHKeyObservation.Update().
			Where(sshkeyobservation.IDIn(removedIDs...)).
			SetPresent(false).
			Exec(ctx); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	for _, obs := range newlyAppeared {
		if err := s.handleNewKey(ctx, assetRow, obs, observedAt); err != nil {
			return err
		}
	}
	return nil
}

func snapshotUnchanged(base *ent.SSHKeyBaseline, presentRows []*ent.SSHKeyObservation, cleaned []sanitizedKey, akCmd, akUser string) bool {
	if base == nil ||
		base.AuthorizedKeysCommand != akCmd ||
		base.AuthorizedKeysCommandUser != akUser ||
		len(presentRows) != len(cleaned) {
		return false
	}
	if len(cleaned) == 0 {
		return true
	}
	byTuple := make(map[tupleKey]*ent.SSHKeyObservation, len(presentRows))
	for _, r := range presentRows {
		byTuple[tupleKey{account: r.Account, filePath: r.FilePath, fingerprint: r.Fingerprint}] = r
	}
	for _, item := range cleaned {
		prev, ok := byTuple[item.tupleKey]
		if !ok ||
			prev.KeyType != item.keyType ||
			prev.Comment != item.comment ||
			!slices.Equal(prev.Options, item.options) {
			return false
		}
	}
	return true
}

func sanitizeKeys(in []*pb.SSHAuthorizedKey) []sanitizedKey {
	out := make([]sanitizedKey, 0, min(len(in), maxKeysPerAsset))
	seen := make(map[tupleKey]bool, len(in))
	for _, k := range in {
		if k == nil {
			continue
		}
		acct := cleanText(k.Account, 64)
		fp := strings.TrimSpace(k.Fingerprint)
		path := cleanText(k.Path, 1024)
		kt := cleanText(k.KeyType, 128)
		if acct == "" || !strings.HasPrefix(path, "/") || kt == "" || !ValidFingerprint(fp) {
			continue
		}
		tk := tupleKey{account: acct, filePath: path, fingerprint: fp}
		if seen[tk] {
			continue
		}
		seen[tk] = true
		opts := make([]string, 0, len(k.Options))
		for _, o := range k.Options {
			if c := cleanText(o, 256); c != "" {
				opts = append(opts, c)
			}
		}
		out = append(out, sanitizedKey{
			tupleKey: tk,
			keyType:  kt,
			comment:  cleanText(k.Comment, 256),
			options:  opts,
		})
		if len(out) >= maxKeysPerAsset {
			break
		}
	}
	return out
}

func cleanText(s string, maxRunes int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxRunes {
			break
		}
		if unicode.IsControl(r) {
			b.WriteByte(' ')
		} else {
			b.WriteRune(r)
		}
		n++
	}
	return strings.TrimSpace(b.String())
}

// loadBackfillLogins 仅在资产首次建立基线时从 ssh_logins 物化表查询各钥匙的最近登录信息。
// 不再扫描 events 分区表，且通过只读短事务的 SET LOCAL statement_timeout 绑定 RPC 超时边界。
func (s *Service) loadBackfillLogins(ctx context.Context, assetID uuid.UUID, now time.Time, hasKeys bool) (map[loginKey]loginInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.OnBackfill != nil {
		s.OnBackfill(assetID)
	}
	if !hasKeys {
		return nil, nil
	}
	since := now.Add(-IdleWindow)
	out := make(map[loginKey]loginInfo)
	if s.SQL != nil {
		ms, err := statementTimeoutMillis(ctx, 10*time.Second)
		if err != nil {
			return nil, err
		}
		tx, err := s.SQL.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL statement_timeout = '%dms'", ms)); err != nil {
			return nil, err
		}
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT ON (login_user, key_fp)
  login_user, key_fp, ts, src_ip
FROM ssh_logins
WHERE asset_id = $1 AND key_fp IS NOT NULL AND ts >= $2
ORDER BY login_user, key_fp, ts DESC`, assetID, since)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var acct, fp, srcIP string
			var ts time.Time
			if err := rows.Scan(&acct, &fp, &ts, &srcIP); err != nil {
				return nil, err
			}
			out[loginKey{account: acct, fingerprint: fp}] = loginInfo{
				ts:    ts,
				srcIP: cleanText(srcIP, 128),
			}
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return out, nil
	}

	rows, err := s.DB.SSHLogin.Query().
		Where(
			sshlogin.AssetIDEQ(assetID),
			sshlogin.KeyFpNotNil(),
			sshlogin.TsGTE(since),
		).
		Order(ent.Desc(sshlogin.FieldTs)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.KeyFp == nil {
			continue
		}
		k := loginKey{account: r.LoginUser, fingerprint: *r.KeyFp}
		if _, exists := out[k]; !exists {
			out[k] = loginInfo{
				ts:    r.Ts,
				srcIP: cleanText(r.SrcIP, 128),
			}
		}
	}
	return out, nil
}

func statementTimeoutMillis(ctx context.Context, maxDuration time.Duration) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	d := maxDuration
	if dl, ok := ctx.Deadline(); ok {
		rem := time.Until(dl)
		if rem <= 0 {
			return 0, context.DeadlineExceeded
		}
		if rem < d {
			d = rem
		}
	}
	return max(d.Milliseconds(), 1), nil
}

// handleNewKey 对基线之后新出现的钥匙：关联写入会话、产生高危告警、生成待批移除提议（绝不自动删除）
func (s *Service) handleNewKey(ctx context.Context, assetRow *ent.Asset, obs *ent.SSHKeyObservation, observedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	writer, err := s.findWriterSession(ctx, assetRow.ID, obs.FilePath, observedAt)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if writer.User != "" || writer.SrcIP != "" || writer.KeyFP != "" {
		if err := s.DB.SSHKeyObservation.UpdateOneID(obs.ID).
			SetAddedByUser(writer.User).
			SetAddedByIP(writer.SrcIP).
			SetAddedByKeyFp(writer.KeyFP).
			Exec(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("更新新 SSH 钥匙写入会话归属失败",
				"asset_id", assetRow.ID,
				"obs_id", obs.ID,
				"fingerprint", obs.Fingerprint,
				"err", err,
			)
		}
	}

	rawForSuppress := map[string]any{
		"user": map[string]any{"name": obs.Account},
		"file": map[string]any{"path": obs.FilePath},
		"key":  map[string]any{"fingerprint": obs.Fingerprint, "type": obs.KeyType},
	}
	if s.Suppress == nil || !s.Suppress.Suppressed(sigma.RuleNewSSHKey, &assetRow.ID, rawForSuppress, observedAt) {
		evidence := map[string]any{
			"account":              obs.Account,
			"file_path":            obs.FilePath,
			"key_type":             obs.KeyType,
			"fingerprint":          obs.Fingerprint,
			"options":              obs.Options,
			"untrusted_comment":    obs.Comment,
			"writer_login_session": writer,
		}
		enc, _ := json.Marshal(evidence)
		detail := "SSH 授权钥匙盘点发现新钥匙（注释字段攻击者可控，仅作提示，不作归属依据）：\n" + string(enc)
		if err := s.DB.Alert.Create().
			SetTs(observedAt).
			SetLastTs(observedAt).
			SetRuleID(sigma.RuleNewSSHKey).
			SetSeverity(4).
			SetAssetID(assetRow.ID).
			SetDetail(detail).
			Exec(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("创建新 SSH 钥匙告警失败",
				"asset_id", assetRow.ID,
				"obs_id", obs.ID,
				"fingerprint", obs.Fingerprint,
				"err", err,
			)
		}
	}

	if s.Gate != nil {
		if _, err := s.EnsureRemovalProposal(ctx, obs.ID); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("新出现的 SSH 钥匙生成移除提议失败",
				"asset_id", assetRow.ID,
				"hostname", assetRow.Hostname,
				"obs_id", obs.ID,
				"account", obs.Account,
				"fingerprint", obs.Fingerprint,
				"err", err,
			)
		}
	}
	return nil
}

// findWriterSession 从同资产近期文件监控（1001）或进程（1007）事件中查找写入该钥匙文件的登录会话
func (s *Service) findWriterSession(ctx context.Context, assetID uuid.UUID, filePath string, observedAt time.Time) (writerSession, error) {
	if err := ctx.Err(); err != nil {
		return writerSession{}, err
	}
	if s.SQL == nil {
		return writerSession{}, nil
	}
	ms, err := statementTimeoutMillis(ctx, 5*time.Second)
	if err != nil {
		return writerSession{}, err
	}
	tx, err := s.SQL.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return writerSession{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL statement_timeout = '%dms'", ms)); err != nil {
		return writerSession{}, err
	}
	var user, srcIP, keyFP string
	err = tx.QueryRowContext(ctx, `SELECT
  COALESCE(raw->'login_session'->>'user', ''),
  COALESCE(raw->'login_session'->>'src_ip', ''),
  COALESCE(raw->'login_session'->>'key_fp', '')
FROM events
WHERE asset_id = $1
  AND ts >= $2 AND ts <= $3
  AND source = 'agent'
  AND class_uid IN (1001, 1007)
  AND jsonb_typeof(raw->'login_session') = 'object'
  AND (
    (class_uid = 1001 AND raw->'file'->>'path' = $4)
    OR (class_uid = 1007 AND COALESCE(raw->'process'->>'cmd_line', '') LIKE '%' || $5 || '%')
  )
ORDER BY CASE WHEN class_uid = 1001 THEN 0 ELSE 1 END, ts DESC
LIMIT 1`,
		assetID, observedAt.Add(-10*time.Minute), observedAt.Add(2*time.Minute),
		filePath, "authorized_keys",
	).Scan(&user, &srcIP, &keyFP)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return writerSession{}, nil
		}
		return writerSession{}, err
	}
	return writerSession{
		User:  cleanText(user, 64),
		SrcIP: cleanText(srcIP, 128),
		KeyFP: cleanText(keyFP, 64),
	}, nil
}

// EnsureRemovalProposal 为指定钥匙观测条目生成（或复用仍有效的）待批移除提议。从不自动删除钥匙。
func (s *Service) EnsureRemovalProposal(ctx context.Context, obsID uuid.UUID) (*ent.Approval, error) {
	if s == nil || s.DB == nil || s.Gate == nil {
		return nil, errors.New("审批服务未配置")
	}
	obs, err := s.DB.SSHKeyObservation.Get(ctx, obsID)
	if err != nil {
		return nil, err
	}
	if !obs.Present {
		return nil, errors.New("该钥匙已不在当前盘点快照中")
	}
	assetRow, err := s.DB.Asset.Get(ctx, obs.AssetID)
	if err != nil {
		return nil, err
	}
	if assetRow.GroupID == nil {
		return nil, errors.New("资产尚未归入资产组，无法创建组审批提议")
	}
	now := s.now()
	if obs.RemovalApprovalID != nil {
		if existing, err := s.DB.Approval.Get(ctx, *obs.RemovalApprovalID); err == nil &&
			existing.Status == approval.StatusPending && existing.ExpiresAt.After(now) {
			return existing, nil
		}
	}
	cmd, err := RemovalCommand(obs.FilePath, obs.Fingerprint)
	if err != nil {
		return nil, err
	}
	created, err := s.Gate.Propose(ctx, *assetRow.GroupID, obs.AssetID, cmd, 30000, ProposalTTL)
	if err != nil {
		return nil, err
	}
	if err := s.DB.SSHKeyObservation.UpdateOneID(obs.ID).SetRemovalApprovalID(created.ID).Exec(ctx); err != nil {
		return nil, err
	}
	return created, nil
}

// KeyRow 供控制台展示的钥匙观测条目（含交叉比对状态与事实引用）
type KeyRow struct {
	ID                uuid.UUID  `json:"id"`
	AssetID           uuid.UUID  `json:"assetId"`
	GroupID           *uuid.UUID `json:"groupId"`
	Hostname          string     `json:"hostname"`
	Account           string     `json:"account"`
	FilePath          string     `json:"filePath"`
	KeyType           string     `json:"keyType"`
	Fingerprint       string     `json:"fingerprint"`
	Comment           string     `json:"comment"`
	Options           []string   `json:"options"`
	FirstSeen         time.Time  `json:"firstSeen"`
	LastSeen          time.Time  `json:"lastSeen"`
	LastLoginAt       *time.Time `json:"lastLoginAt"`
	LastLoginIP       string     `json:"lastLoginIp,omitempty"`
	UsageStatus       string     `json:"usageStatus"` // active（在用）| idle（90 天无登录）
	ClaimStatus       string     `json:"claimStatus"` // claimed（已认领）| unclaimed（未认领）
	FactRef           string     `json:"factRef,omitempty"`
	Holder            string     `json:"holder,omitempty"`
	HolderName        string     `json:"holderName,omitempty"`
	FactContent       string     `json:"factContent,omitempty"`
	AddedByUser       string     `json:"addedByUser,omitempty"`
	AddedByIP         string     `json:"addedByIp,omitempty"`
	AddedByKeyFP      string     `json:"addedByKeyFp,omitempty"`
	RemovalApprovalID *uuid.UUID `json:"removalApprovalId,omitempty"`
	RemovalStatus     string     `json:"removalStatus,omitempty"`
}

// HostKeyConfig 资产 sshd 级动态钥匙命令配置（仅展示配置文本）
type HostKeyConfig struct {
	AssetID                   uuid.UUID `json:"assetId"`
	Hostname                  string    `json:"hostname"`
	AuthorizedKeysCommand     string    `json:"authorizedKeysCommand"`
	AuthorizedKeysCommandUser string    `json:"authorizedKeysCommandUser,omitempty"`
	LastReportedAt            time.Time `json:"lastReportedAt"`
}

// ListResult 钥匙盘点列表响应
type ListResult struct {
	Keys        []KeyRow        `json:"keys"`
	HostConfigs []HostKeyConfig `json:"hostConfigs"`
}

// List 查询可见资产范围内的当前 SSH 钥匙观测，并与登录记录、key 事实交叉计算状态（在用的排前面）
func List(ctx context.Context, db *ent.Client, visibleAssets []*ent.Asset, now time.Time) (ListResult, error) {
	if len(visibleAssets) == 0 {
		return ListResult{Keys: []KeyRow{}, HostConfigs: []HostKeyConfig{}}, nil
	}
	assetMap := make(map[uuid.UUID]*ent.Asset, len(visibleAssets))
	assetIDs := make([]uuid.UUID, 0, len(visibleAssets))
	for _, a := range visibleAssets {
		assetMap[a.ID] = a
		assetIDs = append(assetIDs, a.ID)
	}

	obsRows, err := db.SSHKeyObservation.Query().
		Where(sshkeyobservation.AssetIDIn(assetIDs...), sshkeyobservation.PresentEQ(true)).
		All(ctx)
	if err != nil {
		return ListResult{}, err
	}

	baselines, err := db.SSHKeyBaseline.Query().
		Where(sshkeybaseline.AssetIDIn(assetIDs...), sshkeybaseline.AuthorizedKeysCommandNEQ("")).
		All(ctx)
	if err != nil {
		return ListResult{}, err
	}
	hostConfigs := make([]HostKeyConfig, 0, len(baselines))
	for _, b := range baselines {
		a := assetMap[b.AssetID]
		if a == nil {
			continue
		}
		hostConfigs = append(hostConfigs, HostKeyConfig{
			AssetID:                   b.AssetID,
			Hostname:                  a.Hostname,
			AuthorizedKeysCommand:     b.AuthorizedKeysCommand,
			AuthorizedKeysCommandUser: b.AuthorizedKeysCommandUser,
			LastReportedAt:            b.LastReportedAt,
		})
	}
	slices.SortFunc(hostConfigs, func(a, b HostKeyConfig) int {
		return cmp.Compare(a.Hostname, b.Hostname)
	})

	if len(obsRows) == 0 {
		return ListResult{Keys: []KeyRow{}, HostConfigs: hostConfigs}, nil
	}

	fpSet := make(map[string]bool, len(obsRows))
	var approvalIDs []uuid.UUID
	for _, o := range obsRows {
		fpSet[o.Fingerprint] = true
		if o.RemovalApprovalID != nil {
			approvalIDs = append(approvalIDs, *o.RemovalApprovalID)
		}
	}
	fps := make([]string, 0, len(fpSet))
	for fp := range fpSet {
		fps = append(fps, fp)
	}

	liveFacts, err := db.Fact.Query().
		Where(
			fact.KindEQ("key"),
			fact.SubjectIn(fps...),
			fact.RetiredAtIsNil(),
			fact.Or(fact.ExpiresAtIsNil(), fact.ExpiresAtGT(now)),
		).
		Order(ent.Desc(fact.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return ListResult{}, err
	}
	holderNames := resolveHolderNames(ctx, db, liveFacts)

	approvalStatus := map[uuid.UUID]string{}
	if len(approvalIDs) > 0 {
		if apps, err := db.Approval.Query().Where(approval.IDIn(approvalIDs...)).All(ctx); err == nil {
			for _, ap := range apps {
				st := string(ap.Status)
				if ap.Status == approval.StatusPending && !ap.ExpiresAt.After(now) {
					st = string(approval.StatusExpired)
				}
				approvalStatus[ap.ID] = st
			}
		}
	}

	out := make([]KeyRow, 0, len(obsRows))
	for _, o := range obsRows {
		a := assetMap[o.AssetID]
		if a == nil {
			continue
		}
		usage := "idle"
		if o.LastLoginAt != nil && now.Sub(*o.LastLoginAt) <= IdleWindow {
			usage = "active"
		}
		claim := "unclaimed"
		var fRef, holder, holderName, fContent string
		if matched := matchKeyFact(liveFacts, o.Fingerprint, o.AssetID, a.GroupID); matched != nil {
			claim = "claimed"
			fRef = facts.Ref("F", matched.ID)
			holder = matched.Holder
			holderName = holderNames[matched.Holder]
			fContent = matched.Content
		}
		opts := o.Options
		if opts == nil {
			opts = []string{}
		}
		var remStatus string
		if o.RemovalApprovalID != nil {
			remStatus = approvalStatus[*o.RemovalApprovalID]
		}
		out = append(out, KeyRow{
			ID:                o.ID,
			AssetID:           o.AssetID,
			GroupID:           a.GroupID,
			Hostname:          a.Hostname,
			Account:           o.Account,
			FilePath:          o.FilePath,
			KeyType:           o.KeyType,
			Fingerprint:       o.Fingerprint,
			Comment:           o.Comment,
			Options:           opts,
			FirstSeen:         o.FirstSeen,
			LastSeen:          o.LastSeen,
			LastLoginAt:       o.LastLoginAt,
			LastLoginIP:       o.LastLoginIP,
			UsageStatus:       usage,
			ClaimStatus:       claim,
			FactRef:           fRef,
			Holder:            holder,
			HolderName:        holderName,
			FactContent:       fContent,
			AddedByUser:       o.AddedByUser,
			AddedByIP:         o.AddedByIP,
			AddedByKeyFP:      o.AddedByKeyFp,
			RemovalApprovalID: o.RemovalApprovalID,
			RemovalStatus:     remStatus,
		})
	}

	// 在用的排前面；同为在用按最近登录倒序；同为闲置时未认领排前面，再按主机名与账号排
	slices.SortFunc(out, func(a, b KeyRow) int {
		if a.UsageStatus != b.UsageStatus {
			if a.UsageStatus == "active" {
				return -1
			}
			return 1
		}
		if a.LastLoginAt != nil && b.LastLoginAt != nil && !a.LastLoginAt.Equal(*b.LastLoginAt) {
			if a.LastLoginAt.After(*b.LastLoginAt) {
				return -1
			}
			return 1
		}
		if a.ClaimStatus != b.ClaimStatus {
			if a.ClaimStatus == "unclaimed" {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(a.Hostname, b.Hostname); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Account, b.Account); c != 0 {
			return c
		}
		return cmp.Compare(a.Fingerprint, b.Fingerprint)
	})

	return ListResult{Keys: out, HostConfigs: hostConfigs}, nil
}

// matchKeyFact 按具体度（单资产 > 资产组 > 全局）匹配生效中的 key 事实
func matchKeyFact(candidates []*ent.Fact, fp string, assetID uuid.UUID, groupID *uuid.UUID) *ent.Fact {
	var groupMatch, globalMatch *ent.Fact
	for _, f := range candidates {
		if f.Subject != fp {
			continue
		}
		if f.AssetID != nil {
			if *f.AssetID == assetID {
				return f
			}
			continue
		}
		if f.GroupID != nil {
			if groupID != nil && *f.GroupID == *groupID && groupMatch == nil {
				groupMatch = f
			}
			continue
		}
		if globalMatch == nil {
			globalMatch = f
		}
	}
	if groupMatch != nil {
		return groupMatch
	}
	return globalMatch
}

func resolveHolderNames(ctx context.Context, db *ent.Client, rows []*ent.Fact) map[string]string {
	out := map[string]string{}
	var intIDs []uuid.UUID
	for _, f := range rows {
		if after, ok := strings.CutPrefix(f.Holder, "user:"); ok {
			out[f.Holder] = after
		} else if after, ok := strings.CutPrefix(f.Holder, "integration:"); ok {
			if id, err := uuid.Parse(after); err == nil {
				intIDs = append(intIDs, id)
			}
		} else if f.Holder != "" {
			out[f.Holder] = f.Holder
		}
	}
	if len(intIDs) > 0 {
		if ints, err := db.Integration.Query().Where(entintegration.IDIn(intIDs...)).Select(entintegration.FieldID, entintegration.FieldName).All(ctx); err == nil {
			for _, it := range ints {
				out["integration:"+it.ID.String()] = it.Name
			}
		}
	}
	return out
}

// FilterVisibleAssets 查询调用方可见的未退役资产列表（可按单个 assetId 过滤）
func FilterVisibleAssets(ctx context.Context, db *ent.Client, preds []predicate.Asset, assetID *uuid.UUID) ([]*ent.Asset, error) {
	q := db.Asset.Query().Where(entasset.RetiredAtIsNil()).Where(preds...)
	if assetID != nil {
		q.Where(entasset.IDEQ(*assetID))
	}
	return q.All(ctx)
}
