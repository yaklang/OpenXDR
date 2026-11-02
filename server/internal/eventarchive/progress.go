package eventarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// R3（消费完成证明）：回读 events 的后台消费者在成功完成一轮有固定上界的扫描后，
// 往 settings 写持久完成标记。它替换 Guard 此前的代理证明——beacon 用
// min(beacon_baselines.first_seen) 当进度：基线只记录周期性外联，既证明不了
// [first_seen, now] 已消费（游标只在内存），也会把「扫描完成但没有周期性连接」的
// 正常系统永久挡在 unknown。标记语义与业务数据解耦：扫描完成 ≠ 有数据，
// 空区间/无命中同样推进完成上界。
//
// 账只有一份（settings），写入方是消费者自己，读取方是 ConsumedThrough（guard.go）。
// 不加通用重试框架：整轮成功才发布，失败保守落后——标记缺失只让切换闸门按 unknown
// 拒绝（方向安全），不是数据错误。
//
// R4（定位成本）：settings[archive.locator.complete] 是 locator 覆盖完成标记，
// 由 BackfillLocator 收尾核验后发布，Locate/Exists 未命中时先读它、命中 true 即
// 确定不存在，不再对全部块元数据做反连接。定义与生命周期见 backfill.go。

// BeaconScanKey 是 beacon 扫描完成标记的 settings 键。
const BeaconScanKey = "archive.beacon.scan"

// beaconScanMarker 是 settings[BeaconScanKey] 的载荷：
//
//   - through：本轮扫描的固定上界（引擎 drain 的 upTo，比发起时刻早 lateGrace）。
//     语义是「ts ≤ through 的事件已全部读过且本轮业务副作用（基线、告警）成功提交」；
//   - at：标记写入时刻（观察用，不参与判定）；
//   - rev：影响读范围的配置指纹。学习期/窗口扩大或版本切换使旧证明失效，
//     ConsumedThrough 比对当前指纹，不一致按 unknown 拒绝。
type beaconScanMarker struct {
	Through time.Time `json:"through"`
	At      time.Time `json:"at"`
	Rev     string    `json:"rev"`
}

// BeaconScanRev 由影响读范围的配置算标记指纹。引擎侧传注入的 LearningPeriod/Window
// （main.go 从 BEACON_LEARNING_DAYS / BEACON_WINDOW_HOURS 读入），Guard 侧用同名
// 环境变量按同一口径解析（beaconScanRevFromEnv）——配置一变指纹就变，旧标记自动失效。
func BeaconScanRev(learning, window time.Duration) string {
	return fmt.Sprintf("learning=%s,window=%s", learning, window)
}

// RecordBeaconScan 发布/更新 beacon 扫描完成标记，beacon 引擎每轮扫描收尾调用。
// 调用点必须满足：从扫描起点到 through 的全部事件已读完，且本轮全部业务副作用已成功
// 提交——只有整轮成功才发布；失败时不调用（保守落后）。写入失败由调用方记日志：
// 标记缺失只让闸门更保守。测试播种同一行也走本入口（与引擎写的是同一份账）。
func RecordBeaconScan(ctx context.Context, db *sql.DB, through, at time.Time, learning, window time.Duration) error {
	if db == nil {
		return fmt.Errorf("记录 beacon 扫描完成标记需要数据库连接")
	}
	payload, err := json.Marshal(beaconScanMarker{
		Through: through.UTC(),
		At:      at.UTC(),
		Rev:     BeaconScanRev(learning, window),
	})
	if err != nil {
		return fmt.Errorf("编码 beacon 扫描完成标记: %w", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO settings (id, value, updated_at)
 VALUES ($1, $2::jsonb, now())
 ON CONFLICT (id) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		BeaconScanKey, string(payload)); err != nil {
		return fmt.Errorf("写 settings[%s]: %w", BeaconScanKey, err)
	}
	return nil
}

// beaconScanRevFromEnv 按当前环境变量算期望指纹（与 guardTerms 同一解析口径：
// 数值 + 单位，默认 7d/12h）。解析失败原样报错——配置不明时宁可闸门拒绝。
func beaconScanRevFromEnv() (string, error) {
	learning, err := envDuration("BEACON_LEARNING_DAYS", 24*time.Hour, beaconLearningDefault)
	if err != nil {
		return "", err
	}
	window, err := envDuration("BEACON_WINDOW_HOURS", time.Hour, beaconWindowDefault)
	if err != nil {
		return "", err
	}
	return BeaconScanRev(learning, window), nil
}
