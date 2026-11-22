package eventpart

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type lockParentFakeDriver struct {
	conflictsLeft int
	savepoints    int
	rollbacks     int
	releases      int
	locks         int
}

func (d *lockParentFakeDriver) Open(string) (driver.Conn, error) {
	return &lockParentFakeConn{drv: d}, nil
}

type lockParentFakeConnector struct{ drv *lockParentFakeDriver }

func (c *lockParentFakeConnector) Connect(context.Context) (driver.Conn, error) {
	return c.drv.Open("")
}
func (c *lockParentFakeConnector) Driver() driver.Driver { return c.drv }

type lockParentFakeConn struct{ drv *lockParentFakeDriver }

func (c *lockParentFakeConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *lockParentFakeConn) Close() error                        { return nil }
func (c *lockParentFakeConn) Begin() (driver.Tx, error)           { return &lockParentFakeTx{}, nil }

func (c *lockParentFakeConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	q := strings.TrimSpace(query)
	switch {
	case q == "SAVEPOINT lock_parent":
		c.drv.savepoints++
		return driver.RowsAffected(0), nil
	case q == "ROLLBACK TO SAVEPOINT lock_parent":
		c.drv.rollbacks++
		return driver.RowsAffected(0), nil
	case q == "RELEASE SAVEPOINT lock_parent":
		c.drv.releases++
		return driver.RowsAffected(0), nil
	case strings.HasPrefix(q, "LOCK TABLE "):
		c.drv.locks++
		if c.drv.conflictsLeft > 0 {
			c.drv.conflictsLeft--
			return nil, &pgconn.PgError{Code: "55P03", Message: "could not obtain lock"}
		}
		return driver.RowsAffected(0), nil
	default:
		return driver.RowsAffected(0), nil
	}
}

type lockParentFakeTx struct{}

func (t *lockParentFakeTx) Commit() error   { return nil }
func (t *lockParentFakeTx) Rollback() error { return nil }

// 验证超过 64 次锁冲突重试时只建一次 SAVEPOINT、不嵌套子事务，并在拿锁成功后正确 RELEASE。
func TestLockParentReusesSingleSavepoint(t *testing.T) {
	origWait, origRetry := parentLockWait, parentLockRetry
	parentLockWait = 5 * time.Second
	parentLockRetry = time.Millisecond
	t.Cleanup(func() {
		parentLockWait = origWait
		parentLockRetry = origRetry
	})

	const conflicts = 80
	drv := &lockParentFakeDriver{conflictsLeft: conflicts}
	db := sql.OpenDB(&lockParentFakeConnector{drv: drv})
	t.Cleanup(func() { _ = db.Close() })

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	if err := lockParent(context.Background(), tx); err != nil {
		t.Fatalf("预期重试后拿锁成功，实际失败: %v", err)
	}
	if drv.savepoints != 1 {
		t.Fatalf("SAVEPOINT 应只建立 1 次以避免溢出 pg_subtrans，实际=%d", drv.savepoints)
	}
	if drv.rollbacks != conflicts {
		t.Fatalf("ROLLBACK TO SAVEPOINT 次数不对: got=%d want=%d", drv.rollbacks, conflicts)
	}
	if drv.releases != 1 {
		t.Fatalf("拿锁成功后应 RELEASE SAVEPOINT 1 次，实际=%d", drv.releases)
	}
	if drv.locks != conflicts+1 {
		t.Fatalf("LOCK TABLE 尝试次数不对: got=%d want=%d", drv.locks, conflicts+1)
	}
}
