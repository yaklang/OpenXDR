//go:build integration

package suppress

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/testdb"
)

// Reload 从库重建索引 → Suppressed 命中累加 → flush 把计数回写库。
// 验证抑制规则从"建库"到"界面看到压掉多少"的整条链路。
func TestStoreReloadAndFlush(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()

	// 过期规则：不压制
	_, err := client.Suppression.Create().
		SetRuleID("r-stale").SetExpiresAt(now.Add(-time.Hour)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 全局规则（不限资产）
	global, err := client.Suppression.Create().
		SetRuleID("r-global").SetExpiresAt(now.Add(time.Hour)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 限单资产规则
	assetID := uuid.New()
	scoped, err := client.Suppression.Create().
		SetRuleID("r-scoped").SetAssetID(assetID).SetExpiresAt(now.Add(time.Hour)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	store := New(client, time.Hour)
	store.Reload(ctx)

	// 过期规则不压制
	if store.Suppressed("r-stale", nil, now) {
		t.Error("过期抑制规则不应压制")
	}
	// 全局规则压制任意资产
	if !store.Suppressed("r-global", nil, now) {
		t.Error("全局规则应压制空资产")
	}
	// 限定资产的规则：匹配资产压制，其他资产与空资产不压制
	if !store.Suppressed("r-scoped", &assetID, now) {
		t.Error("限定资产规则应压制该资产")
	}
	other := uuid.New()
	if store.Suppressed("r-scoped", &other, now) {
		t.Error("限定资产规则不应压制其他资产")
	}
	if store.Suppressed("r-scoped", nil, now) {
		t.Error("限定资产规则不应压制空资产")
	}
	// 未登记的规则不压制
	if store.Suppressed("r-unknown", nil, now) {
		t.Error("未登记规则不应压制")
	}

	// 命中计数已累计，flush 落库
	store.flush(ctx)

	g, err := client.Suppression.Get(ctx, global.ID)
	if err != nil {
		t.Fatal(err)
	}
	if g.MatchedCount != 1 {
		t.Errorf("全局规则 matched_count = %d, want 1", g.MatchedCount)
	}
	if g.LastMatchedAt == nil {
		t.Error("命中后应记录 last_matched_at")
	}

	sc, err := client.Suppression.Get(ctx, scoped.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sc.MatchedCount != 1 {
		t.Errorf("限定资产规则 matched_count = %d, want 1", sc.MatchedCount)
	}
}
