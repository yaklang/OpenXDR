package threatbook

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type Service struct {
	DB                *sql.DB
	Key               func(context.Context) string
	Client            *http.Client
	PerMinute, PerDay int
}

type quota struct {
	Minute     string `json:"minute"`
	Day        string `json:"day"`
	MinuteUsed int    `json:"minuteUsed"`
	DayUsed    int    `json:"dayUsed"`
}

func (q *quota) reserve(now time.Time, minute, day int) error {
	m, d := now.UTC().Format("2006-01-02T15:04"), now.UTC().Format("2006-01-02")
	if q.Minute != m {
		q.Minute, q.MinuteUsed = m, 0
	}
	if q.Day != d {
		q.Day, q.DayUsed = d, 0
	}
	if minute <= 0 || day <= 0 || q.MinuteUsed >= minute || q.DayUsed >= day {
		return ErrQuota
	}
	q.MinuteUsed++
	q.DayUsed++
	return nil
}

// Lookup 的缓存和额度跨节点共享；额度先预留，响应不确定时也计费，不重复花额度。
func (s *Service) Lookup(ctx context.Context, value string) (Result, error) {
	ip, err := PublicIP(value)
	if err != nil {
		return Result{}, err
	}
	key := s.Key(ctx)
	if key == "" {
		return Result{}, ErrDisabled
	}
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtextextended('openxdr:threatbook-query',0))`); err != nil {
		return Result{}, err
	}
	defer func() {
		unlock, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, unlockErr := conn.ExecContext(unlock, `SELECT pg_advisory_unlock(hashtextextended('openxdr:threatbook-query',0))`)
		if unlockErr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	cacheID := "threatbook:cache:" + ip
	var result Result
	var raw []byte
	err = conn.QueryRowContext(ctx, `SELECT value FROM settings WHERE id=$1`, cacheID).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	if err == nil && json.Unmarshal(raw, &result) == nil && time.Now().Before(result.ExpiresAt) {
		result.Cached = true
		return result, nil
	}
	var q quota
	err = conn.QueryRowContext(ctx, `SELECT value FROM settings WHERE id='threatbook:quota'`).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	if err == nil && json.Unmarshal(raw, &q) != nil {
		return Result{}, errors.New("微步额度记录损坏，拒绝查询")
	}
	minute, day := s.PerMinute, s.PerDay
	if err = q.reserve(time.Now(), minute, day); err != nil {
		return Result{}, err
	}
	if err = save(ctx, conn, "threatbook:quota", q); err != nil {
		return Result{}, err
	}
	result, err = Query(ctx, s.Client, key, ip)
	if err != nil {
		return Result{}, err
	}
	if err = save(ctx, conn, cacheID, result); err != nil {
		return Result{}, err
	}
	// 缓存只保留两天，避免过期查询记录长期占用 settings。
	if _, err = conn.ExecContext(ctx, `DELETE FROM settings WHERE id LIKE 'threatbook:cache:%' AND updated_at < now()-interval '2 days'`); err != nil {
		return Result{}, err
	}
	return result, nil
}

func save(ctx context.Context, conn *sql.Conn, id string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO settings(id,value,updated_at) VALUES($1,$2::jsonb,now()) ON CONFLICT(id) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, id, string(raw))
	return err
}
