//go:build integration

package auditchain

import (
	"crypto/ed25519"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"openxdr/server/ent/alert"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/testdb"
)

func setup(t *testing.T) (*Sealer, func(string)) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := &Sealer{SQL: db, DB: client, Key: Key(ed25519.NewKeyFromSeed(make([]byte, 32)))}
	write := func(action string) {
		audit.System(ctx, client, action, "t", "d")
	}
	return s, write
}

// 各种写入路径的审计都被封存成连续的链；改中间一条、删中间一条都能发现，并且只告警一次
func TestSealVerifyAndTamper(t *testing.T) {
	s, write := setup(t)
	ctx := t.Context()
	write("a")
	write("b")
	if _, err := s.SQL.Exec(`INSERT INTO audit_logs(id,ts,username,action,remote_addr) VALUES($1,now(),'kei','raw_sql','x')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	write("d")
	if n, err := s.Seal(ctx); err != nil || n != 4 {
		t.Fatalf("应封存 4 条：%d %v", n, err)
	}
	write("e")
	if n, err := s.Seal(ctx); err != nil || n != 1 {
		t.Fatalf("新写入的接着编号：%d %v", n, err)
	}
	if broken, why, err := Verify(ctx, s.SQL, s.Key); err != nil || broken != 0 {
		t.Fatalf("链应完好：%d %s %v", broken, why, err)
	}
	if got := SealedSeq(ctx, s.SQL); got != 5 {
		t.Fatalf("最大编号 %v", got)
	}
	other := Key(ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", 32))))
	if broken, _, _ := Verify(ctx, s.SQL, other); broken != 2 {
		t.Fatalf("换了密钥从第 2 条起对不上：%d", broken)
	}

	if _, err := s.SQL.Exec(`UPDATE audit_logs SET detail='改过' WHERE seq=3`); err != nil {
		t.Fatal(err)
	}
	if broken, why, _ := Verify(ctx, s.SQL, s.Key); broken != 3 || !strings.Contains(why, "改过") {
		t.Fatalf("改了第 3 条：%d %s", broken, why)
	}
	for range 2 {
		s.lastVerify = s.lastVerify.AddDate(-1, 0, 0)
		if err := s.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.DB.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleAuditTamper), alert.Severity(5)).CountX(ctx); n != 1 {
		t.Fatalf("同一处断开只告警一次，实际 %d", n)
	}
}

func TestDeletedMiddleRecord(t *testing.T) {
	s, write := setup(t)
	ctx := t.Context()
	for _, a := range []string{"a", "b", "c", "d"} {
		write(a)
	}
	if _, err := s.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SQL.Exec(`DELETE FROM audit_logs WHERE seq=2`); err != nil {
		t.Fatal(err)
	}
	if broken, why, _ := Verify(ctx, s.SQL, s.Key); broken != 2 || !strings.Contains(why, "不见了") {
		t.Fatalf("删了第 2 条：%d %s", broken, why)
	}
}
