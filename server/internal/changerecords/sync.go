package changerecords

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/changerecord"
	"openxdr/server/ent/changerecordasset"
	"openxdr/server/ent/changesource"
	"openxdr/server/internal/cluster"
)

const (
	DefaultSyncInterval = 5 * time.Minute
	// InitialLookback 首次接入仓库时的回溯窗口，覆盖近两周运维变更而不爬全量历史。
	InitialLookback = 14 * 24 * time.Hour
	// RelinkWindow 每次同步顺带用最新资产快照重算关联的近期窗口，新纳管资产也能补上近期提交。
	RelinkWindow    = 30 * 24 * time.Hour
	cursorOverlap   = time.Minute
	perPageCommits  = 100
	maxPagesPerSync = 10
)

// Syncer 变更记录源的单活增量同步器。
type Syncer struct {
	DB       *ent.Client
	SQL      *sql.DB
	Cipher   *TokenCipher
	HTTP     *http.Client
	BaseURL  string
	Interval time.Duration
	Now      func() time.Time
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Syncer) baseURL() string {
	if s.BaseURL != "" {
		return s.BaseURL
	}
	return DefaultGitHubBaseURL
}

func (s *Syncer) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return DefaultSyncInterval
}

// Run 集群单活主循环：启动先跑一轮增量拉取，之后按周期拉取全部已启用来源。
func (s *Syncer) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval())
	defer ticker.Stop()
	for {
		if err := s.SyncAll(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("同步外部变更记录失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// SyncAll 同步全部已启用的变更记录源，并补齐近 30 天记录与新纳管资产的关联。
func (s *Syncer) SyncAll(ctx context.Context) error {
	sources, err := s.DB.ChangeSource.Query().Where(changesource.EnabledEQ(true)).Order(ent.Asc(changesource.FieldCreatedAt)).All(ctx)
	if err != nil {
		return err
	}
	var firstErr error
	for _, src := range sources {
		if _, err := s.SyncSource(ctx, src.ID); err != nil {
			slog.Warn("同步单个变更记录源失败", "repo", src.Repo, "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if len(sources) > 0 {
		if err := s.RelinkRecent(ctx, s.now().Add(-RelinkWindow)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// SyncSource 按 since_cursor 增量拉取单个来源，与周期循环按源级锁互斥。
func (s *Syncer) SyncSource(ctx context.Context, id uuid.UUID) (int, error) {
	var added int
	run := func() error {
		var err error
		added, err = s.syncSourceLocked(ctx, id)
		return err
	}
	if s.SQL != nil {
		if err := cluster.WithLock(ctx, s.SQL, "change-source:"+id.String(), run); err != nil {
			return 0, err
		}
		return added, nil
	}
	err := run()
	return added, err
}

func (s *Syncer) syncSourceLocked(ctx context.Context, id uuid.UUID) (int, error) {
	src, err := s.DB.ChangeSource.Get(ctx, id)
	if err != nil {
		return 0, err
	}
	now := s.now().UTC()
	recordFailure := func(cause error) (int, error) {
		msg := sanitizeSingleLine(cause.Error(), 240)
		_ = s.DB.ChangeSource.UpdateOneID(src.ID).
			SetLastAttemptedAt(now).
			SetLastError(msg).
			Exec(ctx)
		return 0, cause
	}
	if src.Provider != ProviderGitHub {
		return recordFailure(errors.New("不支持的变更记录源类型: " + src.Provider))
	}
	token, err := OpenToken(s.Cipher, src)
	if err != nil {
		return recordFailure(err)
	}
	snap, err := LoadSnapshot(ctx, s.DB, now)
	if err != nil {
		return recordFailure(err)
	}

	since := now.Add(-InitialLookback)
	if src.SinceCursor != nil && !src.SinceCursor.IsZero() {
		since = src.SinceCursor.Add(-cursorOverlap)
	}

	var summaries []CommitSummary
	complete := false
	for page := 1; page <= maxPagesPerSync; page++ {
		batch, err := listGitHubCommits(ctx, s.HTTP, s.baseURL(), src.Repo, src.Branch, token, since, page, perPageCommits)
		if err != nil {
			return recordFailure(err)
		}
		summaries = append(summaries, batch...)
		if len(batch) < perPageCommits {
			complete = true
			break
		}
	}

	// 批量筛掉已入库的 SHA，避免重叠窗口内重复拉取单条详情。
	known := map[string]bool{}
	if len(summaries) > 0 {
		shas := make([]string, 0, len(summaries))
		for _, item := range summaries {
			shas = append(shas, item.SHA)
		}
		existing, err := s.DB.ChangeRecord.Query().
			Where(changerecord.SourceIDEQ(src.ID), changerecord.ShaIn(shas...)).
			Select(changerecord.FieldSha).
			Strings(ctx)
		if err != nil {
			return recordFailure(err)
		}
		for _, sha := range existing {
			known[sha] = true
		}
	}

	maxTS := time.Time{}
	if src.SinceCursor != nil {
		maxTS = src.SinceCursor.UTC()
	}
	added := 0
	// 从旧到新入库，便于故障中断时按时间顺序推进。
	for i := len(summaries) - 1; i >= 0; i-- {
		item := summaries[i]
		if item.CommittedAt.After(maxTS) {
			maxTS = item.CommittedAt
		}
		if known[item.SHA] {
			continue
		}
		detail, err := getGitHubCommit(ctx, s.HTTP, s.baseURL(), src.Repo, item.SHA, token)
		if err != nil {
			return recordFailure(err)
		}
		if detail.CommittedAt.After(maxTS) {
			maxTS = detail.CommittedAt
		}
		saved, err := s.saveCommit(ctx, src, detail, snap)
		if err != nil {
			return recordFailure(err)
		}
		if saved {
			added++
		}
		known[item.SHA] = true
	}

	upd := s.DB.ChangeSource.UpdateOneID(src.ID).
		SetLastAttemptedAt(now).
		SetLastSyncedAt(now).
		SetLastError("")
	// 仅在本窗口全部分页都读完时推进游标，防止单轮超 maxPagesPerSync 时漏掉更早分页。
	if complete {
		if maxTS.IsZero() {
			maxTS = now.Add(-cursorOverlap)
		}
		upd.SetSinceCursor(maxTS)
	}
	if err := upd.Exec(ctx); err != nil {
		return added, err
	}
	return added, nil
}

func (s *Syncer) saveCommit(ctx context.Context, src *ent.ChangeSource, d CommitDetail, snap *Snapshot) (bool, error) {
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	rec, err := tx.ChangeRecord.Query().
		Where(changerecord.SourceIDEQ(src.ID), changerecord.ShaEQ(d.SHA)).
		Only(ctx)
	created := false
	if ent.IsNotFound(err) {
		rec, err = tx.ChangeRecord.Create().
			SetSourceID(src.ID).
			SetRepo(src.Repo).
			SetSha(d.SHA).
			SetCommittedAt(d.CommittedAt).
			SetAuthor(d.Author).
			SetTitle(d.Title).
			SetBody(d.Body).
			SetFiles(d.StoredFiles).
			SetFileCount(d.FileCount).
			Save(ctx)
		if err != nil {
			return false, err
		}
		created = true
	} else if err != nil {
		return false, err
	}

	matches := snap.Match(MatchInput{Title: d.Title, Body: d.Body, Files: d.AllFiles})
	if err := upsertLinks(ctx, tx.Client(), rec, matches); err != nil {
		return false, err
	}
	return created, tx.Commit()
}

// RelinkRecent 用当前纳管资产快照重算指定时间以来的提交关联（幂等补齐新纳管资产或更新后的 VMID/IP）。
func (s *Syncer) RelinkRecent(ctx context.Context, since time.Time) error {
	now := s.now().UTC()
	snap, err := LoadSnapshot(ctx, s.DB, now)
	if err != nil {
		return err
	}
	records, err := s.DB.ChangeRecord.Query().
		Where(changerecord.CommittedAtGTE(since)).
		Order(ent.Desc(changerecord.FieldCommittedAt)).
		Limit(1000).
		All(ctx)
	if err != nil {
		return err
	}
	for _, rec := range records {
		matches := snap.Match(MatchInput{Title: rec.Title, Body: rec.Body, Files: rec.Files})
		if err := upsertLinks(ctx, s.DB, rec, matches); err != nil {
			return err
		}
	}
	return nil
}

func upsertLinks(ctx context.Context, db *ent.Client, rec *ent.ChangeRecord, matches []AssetMatch) error {
	if len(matches) == 0 {
		return nil
	}
	existing, err := db.ChangeRecordAsset.Query().
		Where(changerecordasset.ChangeRecordIDEQ(rec.ID)).
		All(ctx)
	if err != nil {
		return err
	}
	byAsset := make(map[uuid.UUID]*ent.ChangeRecordAsset, len(existing))
	for _, link := range existing {
		byAsset[link.AssetID] = link
	}
	for _, m := range matches {
		if cur := byAsset[m.AssetID]; cur != nil {
			if !slices.Equal(cur.Clues, m.Clues) {
				if err := db.ChangeRecordAsset.UpdateOneID(cur.ID).SetClues(m.Clues).Exec(ctx); err != nil {
					return err
				}
			}
			continue
		}
		_, err := db.ChangeRecordAsset.Create().
			SetChangeRecordID(rec.ID).
			SetAssetID(m.AssetID).
			SetCommittedAt(rec.CommittedAt).
			SetClues(m.Clues).
			Save(ctx)
		if err != nil && !ent.IsConstraintError(err) {
			return err
		}
	}
	return nil
}
