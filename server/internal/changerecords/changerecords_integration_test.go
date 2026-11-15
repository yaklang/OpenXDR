//go:build integration

package changerecords

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/internal/testdb"
)

func TestSyncerIncrementalAndAssetLinking(t *testing.T) {
	ctx, db := testdb.New(t)
	rawSQL, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer rawSQL.Close()

	// 验证 (asset_id, committed_at) 联合索引真实建在 change_record_assets 表上。
	var idxCount int
	if err := rawSQL.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM pg_indexes
		WHERE tablename = 'change_record_assets'
		  AND indexdef LIKE '%(asset_id, committed_at)%'
	`).Scan(&idxCount); err != nil || idxCount < 1 {
		t.Fatalf("缺少 (asset_id, committed_at) 联合索引: count=%d err=%v", idxCount, err)
	}

	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	pve1 := db.Asset.Create().
		SetHostname("pve1").
		SetIPAddrs([]string{"10.1.1.2"}).
		SetContainers(json.RawMessage(`[{"runtime":"lxc","uid":"100","name":"gateway","addrs":["10.1.1.100"]}]`)).
		SaveX(ctx)
	pve2 := db.Asset.Create().
		SetHostname("pve2").
		SetIPAddrs([]string{"10.1.1.160"}).
		SaveX(ctx)
	gateway := db.Asset.Create().
		SetHostname("gateway").
		SetIPAddrs([]string{"10.1.1.100"}).
		SaveX(ctx)
	zacharyDev := db.Asset.Create().
		SetHostname("zachary-dev").
		SetIPAddrs([]string{"10.1.1.36"}).
		SaveX(ctx)
	db.Fact.Create().
		SetKind("asset_role").
		SetAssetID(zacharyDev.ID).
		SetContent("常驻开发机（pve2 VM 103）").
		SetCreatedBy("admin").
		SaveX(ctx)

	shaOld := "1111111111111111111111111111111111111111"
	shaGateway := "8c16872022222222222222222222222222222222"
	shaVM := "3333333333333333333333333333333333333333"
	var round atomic.Int32
	var detailFetches atomic.Int32
	var lastSince string

	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghp_secret_token_9999" {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/repos/ZacharyZcR/RoyalSecurity-Network/commits":
			lastSince = r.URL.Query().Get("since")
			if round.Load() == 0 {
				_ = json.NewEncoder(w).Encode([]map[string]any{
					{"sha": shaGateway, "commit": map[string]any{"committer": map[string]any{"date": "2026-11-14T09:20:00Z"}}},
					{"sha": shaOld, "commit": map[string]any{"committer": map[string]any{"date": "2026-11-13T20:00:00Z"}}},
				})
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"sha": shaVM, "commit": map[string]any{"committer": map[string]any{"date": "2026-11-14T09:50:00Z"}}},
				{"sha": shaGateway, "commit": map[string]any{"committer": map[string]any{"date": "2026-11-14T09:20:00Z"}}},
			})
		case "/repos/ZacharyZcR/RoyalSecurity-Network/commits/" + shaOld:
			detailFetches.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sha": shaOld,
				"commit": map[string]any{
					"message":   "更新 vpn-proxy 10.1.1.3 订阅节点",
					"committer": map[string]any{"name": "ZacharyZcR", "date": "2026-11-13T20:00:00Z"},
				},
				"files": []map[string]any{{"filename": "configs/mihomo/config.yaml", "patch": "@@ -1 +1 @@\n-DIFF_SECRET_OLD"}},
			})
		case "/repos/ZacharyZcR/RoyalSecurity-Network/commits/" + shaGateway:
			detailFetches.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sha": shaGateway,
				"commit": map[string]any{
					"message":   "下线 dl 站点，回收 node34-36 的隧道钥与 WireGuard peer\n\n清理 gateway 入口",
					"committer": map[string]any{"name": "ZacharyZcR", "date": "2026-11-14T09:20:00Z"},
				},
				"files": []map[string]any{{"filename": "configs/gateway/Caddyfile", "patch": "@@ -1 +1 @@\n-DIFF_SECRET_GW"}},
			})
		case "/repos/ZacharyZcR/RoyalSecurity-Network/commits/" + shaVM:
			detailFetches.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sha": shaVM,
				"commit": map[string]any{
					"message":   "调整 pve2 VM 103 内核参数",
					"committer": map[string]any{"name": "ZacharyZcR", "date": "2026-11-14T09:50:00Z"},
				},
				"files": []map[string]any{{"filename": "docs/hosts.md"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer gh.Close()

	cipher := &TokenCipher{
		Seal: func(plain, binding string) ([]byte, error) { return []byte(binding + "|" + plain), nil },
		Open: func(ciphertext []byte, binding string) (string, error) {
			b, p, ok := strings.Cut(string(ciphertext), "|")
			if !ok || b != binding {
				return "", ErrVaultUnavailable
			}
			return p, nil
		},
	}

	srcID, _ := uuid.NewV7()
	sealed, hint, err := SealToken(cipher, srcID, "ghp_secret_token_9999")
	if err != nil {
		t.Fatal(err)
	}
	src := db.ChangeSource.Create().
		SetID(srcID).
		SetProvider(ProviderGitHub).
		SetRepo("ZacharyZcR/RoyalSecurity-Network").
		SetSecret(sealed).
		SetTokenHint(hint).
		SetEnabled(true).
		SaveX(ctx)

	syncer := &Syncer{
		DB:      db,
		SQL:     rawSQL,
		Cipher:  cipher,
		HTTP:    gh.Client(),
		BaseURL: gh.URL,
		Now:     func() time.Time { return now },
	}

	added, err := syncer.SyncSource(ctx, src.ID)
	if err != nil || added != 2 {
		t.Fatalf("首轮同步异常: added=%d err=%v", added, err)
	}
	if detailFetches.Load() != 2 {
		t.Fatalf("首轮详情请求次数应为 2，实际 %d", detailFetches.Load())
	}

	// 确认绝未入库任何 diff 内容。
	allRecs := db.ChangeRecord.Query().AllX(ctx)
	for _, r := range allRecs {
		if strings.Contains(r.Title+r.Body+strings.Join(r.Files, ","), "DIFF_SECRET") {
			t.Fatalf("入库记录泄漏了 diff 内容: %+v", r)
		}
	}

	// 第二轮增量同步：加入新纳管资产 vpn-proxy (10.1.1.3)，验证游标推进、已存 SHA 不重复调详情接口、且 RelinkRecent 为新资产补齐旧提交关联。
	vpnProxy := db.Asset.Create().
		SetHostname("vpn-proxy").
		SetIPAddrs([]string{"10.1.1.3"}).
		SaveX(ctx)
	round.Store(1)
	if err := syncer.SyncAll(context.Background()); err != nil {
		t.Fatalf("增量 SyncAll 失败: %v", err)
	}
	if !strings.HasPrefix(lastSince, "2026-11-14T09:19:00Z") {
		t.Fatalf("第二轮未按 since_cursor 重叠窗口增量查询，实际 since=%q", lastSince)
	}
	if detailFetches.Load() != 3 {
		t.Fatalf("已入库的 shaGateway 不应重复拉取详情，总详情请求应为 3，实际 %d", detailFetches.Load())
	}

	// 验证窗口检索 [告警前 6h, 告警后 2h] 命中 gateway，排除超窗记录。
	alertTS := time.Date(2026, 11, 14, 9, 35, 0, 0, time.UTC)
	gwWin, err := LookupWindow(ctx, db, []uuid.UUID{gateway.ID}, alertTS.Add(-WindowBefore), alertTS.Add(WindowAfter), 10)
	if err != nil || len(gwWin) != 1 || gwWin[0].ShortSHA != "8c168720" {
		t.Fatalf("gateway 窗口检索结果不符: %+v err=%v", gwWin, err)
	}
	pve1Recent, err := LookupAssetRecent(ctx, db, pve1.ID, 10)
	if err != nil || len(pve1Recent) != 1 || !slices.Contains(pve1Recent[0].Clues, "lxc:gateway") {
		t.Fatalf("pve1 LXC 关联缺失: %+v err=%v", pve1Recent, err)
	}
	vmRecent, err := LookupAssetRecent(ctx, db, zacharyDev.ID, 10)
	if err != nil || len(vmRecent) != 1 || !slices.Contains(vmRecent[0].Clues, "vmid:103") {
		t.Fatalf("zachary-dev VMID 103 关联缺失: %+v err=%v", vmRecent, err)
	}
	pve2Recent, err := LookupAssetRecent(ctx, db, pve2.ID, 10)
	if err != nil || len(pve2Recent) != 1 {
		t.Fatalf("pve2 宿主机关联缺失: %+v err=%v", pve2Recent, err)
	}
	vpnRecent, err := LookupAssetRecent(ctx, db, vpnProxy.ID, 10)
	if err != nil || len(vpnRecent) != 1 || !slices.Contains(vpnRecent[0].Clues, "ip:10.1.1.3") {
		t.Fatalf("RelinkRecent 未能为后纳管的 vpn-proxy 补上关联: %+v err=%v", vpnRecent, err)
	}
}
