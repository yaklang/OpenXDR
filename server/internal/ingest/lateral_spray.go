package ingest

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/authfields"
	"openxdr/server/internal/automation"
	"openxdr/server/internal/cmdorigin"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
)

// 内部横向喷洒（xdr:internal-lateral-spray）：同一台纳管主机的地址 60 分钟内作为来源，在 ≥ 3 台其他纳管主机上
// 出现登录失败或被告警命中的入站——跳板在内网口令喷洒、横向探测。与爆破得手同一做法：确定性检测写一条合成告警，
// 落在源主机上、级别 5，去重、抑制、关联升级、立即重研判与推送都走现有通路。
//
// 受害方事件逐条记进 lateral_evidence（事件、源主机、受害主机、时间），回看只扫这张小表的（源主机, 时间）索引，
// 不碰按天分区的 events。同一源主机的记证据、计数与告警在事务锁下串行，集群多节点并发处理不同受害主机时互相看得见。
// 回看以触发事件为终点：受害主机的事件跨 agent 乱序到达时，较早的那条凑不齐，喷洒持续时后续事件照样能凑齐。
//
// 窗口 60 分钟：2026-11-02 的跳板是一台一台换着打的（node2 23:10、node1 23:11、lizhen-dev 23:30），10 分钟凑不齐三台；
// 生产近三天按 60 分钟回放只在这次攻击上触发一次（纳管主机之间的正常 SSH 是密钥登录成功，不计）。
// 告警去重同样按 60 分钟（从首条起算，见 upsertAlert）：一轮喷洒在源主机上只留一条，后来的受害主机累加计数、刷新 detail。
const (
	SprayWindow  = 60 * time.Minute
	sprayVictims = 3
	// 证据保留远长于回看窗口，写入时顺手清掉同一源主机更早的
	sprayRetention = 24 * time.Hour
)

// lateralSpray 记一条受害方证据并判定是否达到喷洒阈值。alerted 表示这条事件刚产出了计入关联的告警
// （平台指令、已知自动化、容器健康检查触发的不算）；没有告警的只认登录失败。
func (p *Processor) lateralSpray(ctx context.Context, tx *sql.Tx, e Envelope, raw map[string]any, alerted bool) (bool, error) {
	if e.AssetID == nil || *e.AssetID == uuid.Nil || !alerted && (e.ClassUID != 3002 || authStatus(raw) != 2) {
		return false, nil
	}
	ip := authfields.PeerIP(e.ClassUID, e.Raw)
	if ip == "" {
		return false, nil
	}
	src, err := addressOwner(ctx, tx, ip)
	if err != nil || src == uuid.Nil || src == *e.AssetID {
		return false, err
	}
	if !alerted {
		// 平台指令、已知自动化的登录不计，与告警的排除口径一致
		if known, err := knownOrigin(ctx, tx, e, raw); err != nil || known {
			return false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "lateral-spray|"+src.String()); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO lateral_evidence(event_id,src_asset,victim_asset,ts,src_ip) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
		e.ID, src, *e.AssetID, e.Timestamp, ip); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM lateral_evidence WHERE src_asset=$1 AND ts<$2`, src, e.Timestamp.Add(-sprayRetention)); err != nil {
		return false, err
	}
	var victims int
	if err := tx.QueryRowContext(ctx, `SELECT count(DISTINCT victim_asset) FROM lateral_evidence WHERE src_asset=$1 AND ts>$2 AND ts<=$3`,
		src, e.Timestamp.Add(-SprayWindow), e.Timestamp).Scan(&victims); err != nil {
		return false, err
	}
	if victims < sprayVictims || p.Suppress.Suppressed(sigma.RuleLateralSpray, &src, raw, e.Timestamp) {
		return false, nil
	}
	// 没有事件：告警落在源主机上，触发它的是别的主机（可能是别的组）的事件，挂上去会把受害方的事件原文露给源主机所在的组
	spray := Envelope{AssetID: &src, PartitionKey: src.String(), Timestamp: e.Timestamp}
	hit := intel.Hit{RuleID: sigma.RuleLateralSpray, Severity: 5}
	created, err := p.upsertAlert(ctx, tx, spray, hit, origin{})
	if err != nil {
		return false, err
	}
	return created, p.sprayDetail(ctx, tx, alertFingerprint(spray, hit, origin{}), src, ip, e.Timestamp)
}

// sprayDetail 把这条告警（去重窗口）以来的受害主机与次数写进 detail，研判上下文与告警页直接可读。
// 受害主机只列地址不列主机名：源主机所在的组看得到这条告警，别组主机的名字不该跟着过去
func (p *Processor) sprayDetail(ctx context.Context, tx *sql.Tx, fingerprint string, src uuid.UUID, ip string, ts time.Time) error {
	var alertID uuid.UUID
	var first time.Time
	if err := tx.QueryRowContext(ctx, `SELECT alert_id, first_ts FROM alert_dedup_state WHERE fingerprint=$1`, fingerprint).Scan(&alertID, &first); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT COALESCE(a.ip_addrs->>0, l.victim_asset::text), count(*) FROM lateral_evidence l
LEFT JOIN assets a ON a.id=l.victim_asset
WHERE l.src_asset=$1 AND l.ts>$2 AND l.ts<=$3 GROUP BY 1 ORDER BY 1`, src, first.Add(-SprayWindow), ts)
	if err != nil {
		return err
	}
	var victims []string
	for rows.Next() {
		var addr string
		var n int
		if err := rows.Scan(&addr, &n); err != nil {
			rows.Close()
			return err
		}
		victims = append(victims, fmt.Sprintf("%s ×%d", addr, n))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	detail := fmt.Sprintf("来自 %s 的登录失败或被告警的入站，首次达到阈值前 %d 分钟起共波及 %d 台纳管主机：%s",
		ip, int(SprayWindow/time.Minute), len(victims), strings.Join(victims, "、"))
	_, err = tx.ExecContext(ctx, `UPDATE alerts SET detail=$2 WHERE id=$1`, alertID, detail)
	return err
}

// addressOwner 地址唯一属于哪台纳管主机。docker 网桥 172.17.0.1 这类多台主机都有的地址认不出是谁，返回空
func addressOwner(ctx context.Context, tx *sql.Tx, ip string) (uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM assets WHERE ip_addrs ? $1 LIMIT 2`, ip)
	if err != nil {
		return uuid.Nil, err
	}
	defer rows.Close()
	var owners []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return uuid.Nil, err
		}
		owners = append(owners, id)
	}
	if err := rows.Err(); err != nil || len(owners) != 1 {
		return uuid.Nil, err
	}
	return owners[0], nil
}

// knownOrigin 事件来自平台指令、已知自动化或容器健康检查（后两者只认 agent 上报的事件）
func knownOrigin(ctx context.Context, tx *sql.Tx, e Envelope, raw map[string]any) (bool, error) {
	command, err := cmdorigin.Of(ctx, tx, raw, e.AssetID, e.Timestamp)
	if err != nil || command != nil || e.Source != "agent" {
		return command != nil, err
	}
	source, err := automation.Of(ctx, tx, raw, e.AssetID, e.Timestamp)
	return source != nil || automation.Healthcheck(raw), err
}
