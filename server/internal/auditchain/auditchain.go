// Package auditchain 审计日志防篡改。2026-11-03 的攻击者拿到数据库后第一件事就是读我们的告警，
// 能读就能删：只拿到数据库的人不该能悄悄抹掉审计。
//
//   - 封存：单活任务把还没封存的审计按 (ts, id) 顺序编号，seal = HMAC(密钥, 前一条的 seal ‖ 本条内容)。
//     密钥由指令签名私钥派生，不在库里，只拿到数据库的人算不出 seal
//   - 校验：编号必须连续、每条 seal 都对得上；改一条、删中间一条，链就在那里断开，出 xdr:audit-tamper（5 级）
//   - 删尾：最新编号经 Prometheus 指标 openxdr_audit_sealed_seq 存到集群外的监控里，编号倒退看得出来
//
// 写入路径不用改：audit.Log、事务里的 Checked、直接写 SQL 的几处都照旧插入，封存是事后补上的。
// 还没封存的几秒钟里改动不会被发现，这是异步封存的代价。
package auditchain

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/internal/sigma"
)

// batch 每轮最多封存多少条
const batch = 500

// verifyEvery 全量校验的间隔；审计量级很小（生产三周六千多条），全量走一遍很便宜
const verifyEvery = 10 * time.Minute

// Key 由指令签名私钥派生审计链密钥：两个节点是同一把签名私钥，派生出同一把链密钥
func Key(signer ed25519.PrivateKey) []byte {
	sum := sha256.Sum256(append([]byte("openxdr-audit-chain-v1\x00"), signer.Seed()...))
	return sum[:]
}

type Sealer struct {
	SQL      *sql.DB
	DB       *ent.Client
	Key      []byte
	Interval time.Duration

	lastVerify time.Time
}

func (s *Sealer) Run(ctx context.Context) {
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		if err := s.Tick(ctx); err != nil && ctx.Err() == nil {
			slog.Error("审计链本轮失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick 封存新写入的审计；到时间就全量校验一遍，断了就告警
func (s *Sealer) Tick(ctx context.Context) error {
	if _, err := s.Seal(ctx); err != nil {
		return err
	}
	if time.Since(s.lastVerify) < verifyEvery {
		return nil
	}
	s.lastVerify = time.Now()
	broken, why, err := Verify(ctx, s.SQL, s.Key)
	if err != nil || broken == 0 {
		return err
	}
	return s.alarm(ctx, broken, why)
}

// Seal 封存一批，返回封存的条数。事务里拿咨询锁：单活切换的空档里两个节点也不会编出两条同号的链
func (s *Sealer) Seal(ctx context.Context) (int, error) {
	tx, err := s.SQL.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('openxdr-audit-chain',0))`); err != nil {
		return 0, err
	}
	var seq int64
	var prev string
	err = tx.QueryRowContext(ctx, `SELECT seq, seal FROM audit_logs WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1`).Scan(&seq, &prev)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, ts, username, action, COALESCE(target,''), COALESCE(detail,''), remote_addr
FROM audit_logs WHERE seq IS NULL ORDER BY ts, id LIMIT $1`, batch)
	if err != nil {
		return 0, err
	}
	var pending []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.id, &e.ts, &e.user, &e.action, &e.target, &e.detail, &e.remote); err != nil {
			rows.Close()
			return 0, err
		}
		pending = append(pending, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, e := range pending {
		seq++
		e.seq = seq
		prev = e.seal(s.Key, prev)
		if _, err := tx.ExecContext(ctx, `UPDATE audit_logs SET seq=$2, seal=$3 WHERE id=$1`, e.id, seq, prev); err != nil {
			return 0, err
		}
	}
	return len(pending), tx.Commit()
}

type entry struct {
	seq                                  int64
	id                                   string
	ts                                   time.Time
	user, action, target, detail, remote string
}

// seal 本条的 HMAC：前一条的 seal 加本条全部字段（含编号），字段之间用 \0 分隔
func (e entry) seal(key []byte, prev string) string {
	m := hmac.New(sha256.New, key)
	for _, f := range []string{prev, strconv.FormatInt(e.seq, 10), e.id, e.ts.UTC().Format(time.RFC3339Nano),
		e.user, e.action, e.target, e.detail, e.remote} {
		m.Write([]byte(f))
		m.Write([]byte{0})
	}
	return hex.EncodeToString(m.Sum(nil))
}

// Verify 按编号走一遍已封存的审计：编号连续、seal 对得上。返回第一处断开的编号与原因，完好返回 0。
// 链的起点是现存最小编号那一条（它前面的 seal 无从核对，按空处理），删掉开头一段在这里看不出，靠监控里的编号历史
func Verify(ctx context.Context, db *sql.DB, key []byte) (int64, string, error) {
	rows, err := db.QueryContext(ctx, `SELECT seq, seal, id, ts, username, action, COALESCE(target,''), COALESCE(detail,''), remote_addr
FROM audit_logs WHERE seq IS NOT NULL ORDER BY seq`)
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()
	var prev string
	var expect int64
	for rows.Next() {
		var e entry
		var seal string
		if err := rows.Scan(&e.seq, &seal, &e.id, &e.ts, &e.user, &e.action, &e.target, &e.detail, &e.remote); err != nil {
			return 0, "", err
		}
		if expect != 0 && e.seq != expect {
			return expect, fmt.Sprintf("编号 %d 到 %d 之间的记录不见了", expect, e.seq-1), nil
		}
		if expect != 0 && !hmac.Equal([]byte(e.seal(key, prev)), []byte(seal)) {
			return e.seq, fmt.Sprintf("第 %d 条记录的内容或前一条被改过", e.seq), nil
		}
		prev, expect = seal, e.seq+1
	}
	return 0, "", rows.Err()
}

// alarm 审计链断开：同一处断开一天只报一次
func (s *Sealer) alarm(ctx context.Context, broken int64, why string) error {
	detail := fmt.Sprintf("审计链在第 %d 条断开：%s。审计记录被人改过或删过，需要核查谁有数据库写权限", broken, why)
	seen, err := s.DB.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleAuditTamper), alert.DetailEQ(detail),
		alert.TsGTE(time.Now().Add(-24*time.Hour))).Exist(ctx)
	if err != nil || seen {
		return err
	}
	now := time.Now()
	create := s.DB.Alert.Create().SetTs(now).SetLastTs(now).SetRuleID(sigma.RuleAuditTamper).SetSeverity(5).SetDetail(detail)
	if name, err := os.Hostname(); err == nil {
		if a, err := s.DB.Asset.Query().Where(entasset.HostnameEQ(name)).Only(ctx); err == nil {
			create.SetAssetID(a.ID)
		}
	}
	slog.Error("审计链断开", "seq", broken, "why", why)
	return create.Exec(ctx)
}

// SealedSeq 已封存的最大编号，给 Prometheus：存在集群外的监控里，编号倒退说明尾部被删
func SealedSeq(ctx context.Context, db *sql.DB) float64 {
	var seq sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT max(seq) FROM audit_logs`).Scan(&seq); err != nil {
		return -1
	}
	return float64(seq.Int64)
}
