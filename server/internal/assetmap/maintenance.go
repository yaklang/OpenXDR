package assetmap

import (
	"context"
	"database/sql"
)

// 图谱维护锁只协调派生数据；原始事件入库和待办登记不取此锁。
const graphMaintenanceLock = "openxdr:assetmap-materialization"

func lockGraphBatch(ctx context.Context, tx *sql.Tx) (bool, error) {
	var locked bool
	err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, graphMaintenanceLock).Scan(&locked)
	return locked, err
}

func (e *Engine) deleteLinks(ctx context.Context, query string, args ...any) (int64, error) {
	tx, err := e.SQL.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	locked, err := lockGraphBatch(ctx, tx)
	if err != nil || !locked {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}
