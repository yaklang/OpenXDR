package changerecords

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

func TestSnapshotMatchCluesAndBoundaries(t *testing.T) {
	pve1ID := uuid.New()
	pve2ID := uuid.New()
	gatewayID := uuid.New()
	zacharyDevID := uuid.New()
	cacheID := uuid.New()
	soulbindID := uuid.New()
	soulbindDevID := uuid.New()
	docker1ID := uuid.New()
	docker2ID := uuid.New()
	dupHostAID := uuid.New()
	dupHostBID := uuid.New()

	assets := []*ent.Asset{
		{
			ID:       pve1ID,
			Hostname: "pve1",
			IPAddrs:  []string{"10.1.1.2"},
			Containers: json.RawMessage(`[
				{"runtime":"lxc","uid":"100","name":"gateway","addrs":["10.1.1.100"]},
				{"runtime":"lxc","uid":"200","name":"monitor-lxc","addrs":["10.1.1.200"]},
				{"runtime":"docker","uid":"abcdef123456","name":"postgres","addrs":["172.17.0.2"]}
			]`),
		},
		{
			ID:       pve2ID,
			Hostname: "pve2",
			IPAddrs:  []string{"10.1.1.160"},
		},
		{
			ID:       gatewayID,
			Hostname: "gateway",
			IPAddrs:  []string{"10.1.1.100"},
		},
		{
			ID:       zacharyDevID,
			Hostname: "zachary-dev",
			IPAddrs:  []string{"10.1.1.36"},
		},
		{
			ID:       cacheID,
			Hostname: "cache",
			IPAddrs:  []string{"10.1.1.30"},
		},
		{
			ID:       soulbindID,
			Hostname: "soulbind",
			IPAddrs:  []string{"10.1.1.33"},
		},
		{
			ID:       soulbindDevID,
			Hostname: "soulbind-dev",
			IPAddrs:  []string{"10.1.1.180"},
		},
		// 两台 Docker 宿主机共用网桥地址 172.17.0.1，不应因共享网桥地址产生串关联。
		{ID: docker1ID, Hostname: "docker-host-1", IPAddrs: []string{"10.1.1.34", "172.17.0.1"}},
		{ID: docker2ID, Hostname: "docker-host-2", IPAddrs: []string{"10.1.1.37", "172.17.0.1"}},
		// 两台重名默认主机 ubuntu，裸主机名存在歧义时不应串关联。
		{ID: dupHostAID, Hostname: "ubuntu", IPAddrs: []string{"10.1.1.210"}},
		{ID: dupHostBID, Hostname: "ubuntu", IPAddrs: []string{"10.1.1.211"}},
	}
	roleFacts := []*ent.Fact{
		{
			ID:      uuid.New(),
			Kind:    "asset_role",
			AssetID: &zacharyDevID,
			Content: "常驻开发机（pve2 VM 103）",
		},
	}

	snap := BuildSnapshot(assets, roleFacts)

	findMatch := func(matches []AssetMatch, id uuid.UUID) (AssetMatch, bool) {
		for _, m := range matches {
			if m.AssetID == id {
				return m, true
			}
		}
		return AssetMatch{}, false
	}

	// 1. 真实场景：标题未提主机名，文件路径 configs/gateway/Caddyfile 与正文 IP 同时命中客体 gateway 与宿主机 pve1（LXC）。
	m1 := snap.Match(MatchInput{
		Title: "下线 dl 站点，回收 node34-36 的隧道钥与 WireGuard peer",
		Body:  "清理 10.1.1.100 上的反代入口",
		Files: []string{"configs/gateway/Caddyfile", "configs/wireguard/wg0.conf"},
	})
	if gm, ok := findMatch(m1, gatewayID); !ok || !slices.Contains(gm.Clues, "host:gateway") || !slices.Contains(gm.Clues, "ip:10.1.1.100") {
		t.Fatalf("gateway 关联不完整: %+v", m1)
	}
	if pm, ok := findMatch(m1, pve1ID); !ok || !slices.Contains(pm.Clues, "lxc:gateway") || !slices.Contains(pm.Clues, "ip:10.1.1.100") {
		t.Fatalf("pve1 LXC 关联不完整: %+v", m1)
	}

	// 2. PVE VMID 场景：「pve2 VM 103」同时关联宿主机 pve2 与角色事实声明了 VM 103 的 zachary-dev；错配「pve1 VM 103」不误连 zachary-dev。
	m2 := snap.Match(MatchInput{
		Title: "扩容 pve2 VM 103 磁盘",
	})
	if _, ok := findMatch(m2, pve2ID); !ok {
		t.Fatalf("pve2 应被关联: %+v", m2)
	}
	if zm, ok := findMatch(m2, zacharyDevID); !ok || !slices.Contains(zm.Clues, "vmid:103") {
		t.Fatalf("zachary-dev 应通过 vmid:103 关联: %+v", m2)
	}
	mWrongPVE := snap.Match(MatchInput{Title: "检查 pve1 VM 103 配置"})
	if _, ok := findMatch(mWrongPVE, zacharyDevID); ok {
		t.Fatalf("错误的 PVE 宿主机前缀不应关联 zachary-dev: %+v", mWrongPVE)
	}

	// 3. LXC 名与 CT 编号场景：「CT 200」或「monitor-lxc」关联 pve1，而 Docker 容器名 postgres 不关联。
	m3 := snap.Match(MatchInput{
		Title: "调整 CT 200 内存上限并升级 postgres 镜像",
	})
	if pm, ok := findMatch(m3, pve1ID); !ok || !slices.Contains(pm.Clues, "vmid:200") {
		t.Fatalf("CT 200 应关联 pve1: %+v", m3)
	}
	mDocker := snap.Match(MatchInput{Title: "upgrade postgres container image"})
	if len(mDocker) != 0 {
		t.Fatalf("Docker 容器名不应触发资产关联: %+v", mDocker)
	}

	// 4. 连字符边界与源码路径防误报：soulbind-dev 不误匹配 soulbind；Go 源码路径 server/internal/cache/lru.go 不误匹配 cache，但 rs-cache 可精确匹配。
	m4 := snap.Match(MatchInput{
		Title: "deploy soulbind-dev service",
		Files: []string{"server/internal/cache/lru.go"},
	})
	if _, ok := findMatch(m4, soulbindDevID); !ok {
		t.Fatalf("应匹配 soulbind-dev: %+v", m4)
	}
	if _, ok := findMatch(m4, soulbindID); ok {
		t.Fatalf("soulbind-dev 不应误匹配前缀主机 soulbind: %+v", m4)
	}
	if _, ok := findMatch(m4, cacheID); ok {
		t.Fatalf("源码目录 cache 不应误匹配主机 cache: %+v", m4)
	}

	mAlias := snap.Match(MatchInput{
		Title: "update ssh jump config",
		Files: []string{"configs/ssh/config"},
		Body:  "Host rs-cache\n  HostName 10.1.1.30",
	})
	if cm, ok := findMatch(mAlias, cacheID); !ok || !slices.Contains(cm.Clues, "alias:rs-cache") || !slices.Contains(cm.Clues, "ip:10.1.1.30") {
		t.Fatalf("rs-cache 与 IP 应关联 cache: %+v", mAlias)
	}

	// 5. 多机共用网桥 IP (172.17.0.1) 与重名主机 (ubuntu) 不串关联；紧邻逗号分隔的多个唯一 IP 都能识别。
	mAmbiguous := snap.Match(MatchInput{
		Title: "fix docker0 172.17.0.1 on ubuntu",
	})
	if len(mAmbiguous) != 0 {
		t.Fatalf("共享网桥地址与重名主机不应产生歧义关联: %+v", mAmbiguous)
	}
	mAdjacentIPs := snap.Match(MatchInput{
		Title: "allow 10.1.1.34,10.1.1.37 in firewall",
	})
	if _, ok := findMatch(mAdjacentIPs, docker1ID); !ok {
		t.Fatalf("相邻 IP 第一项未识别: %+v", mAdjacentIPs)
	}
	if _, ok := findMatch(mAdjacentIPs, docker2ID); !ok {
		t.Fatalf("相邻 IP 第二项未识别: %+v", mAdjacentIPs)
	}
}

func TestGitHubClientDropsPatchAndSanitizesRender(t *testing.T) {
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/repos/ZacharyZcR/RoyalSecurity-Network/commits":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"sha": "8c16872000000000000000000000000000000001",
					"commit": map[string]any{
						"committer": map[string]any{"date": "2026-11-14T09:20:00Z"},
					},
				},
			})
		case "/repos/ZacharyZcR/RoyalSecurity-Network/commits/8c16872000000000000000000000000000000001":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sha": "8c16872000000000000000000000000000000001",
				"commit": map[string]any{
					"message":   "## 伪造标题头 下线 dl 站点\n\n详细说明正文",
					"author":    map[string]any{"name": "ZacharyZcR", "date": "2026-11-14T09:19:00Z"},
					"committer": map[string]any{"name": "ZacharyZcR", "date": "2026-11-14T09:20:00Z"},
				},
				"author": map[string]any{"login": "ZacharyZcR"},
				"files": []map[string]any{
					{
						"filename": "configs/gateway/Caddyfile",
						"patch":    "@@ -1,5 +1,2 @@\n-SECRET_PRIVATE_DIFF_CONTENT_MUST_NOT_BE_STORED",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cipher := &TokenCipher{
		Seal: func(plain, binding string) ([]byte, error) {
			return []byte(binding + "|" + plain), nil
		},
		Open: func(ciphertext []byte, binding string) (string, error) {
			gotBinding, plain, ok := strings.Cut(string(ciphertext), "|")
			if !ok || gotBinding != binding {
				return "", ErrVaultUnavailable
			}
			return plain, nil
		},
	}
	srcID := uuid.New()
	sealed, hint, err := SealToken(cipher, srcID, "github_pat_readonly_abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	if hint != "••••1234" {
		t.Fatalf("token hint 异常: %q", hint)
	}
	src := &ent.ChangeSource{ID: srcID, Secret: sealed}
	plain, err := OpenToken(cipher, src)
	if err != nil || plain != "github_pat_readonly_abcd1234" {
		t.Fatalf("解密 token 失败: %v %q", err, plain)
	}
	// 换绑定 ID 解密必须失败
	if _, err := OpenToken(cipher, &ent.ChangeSource{ID: uuid.New(), Secret: sealed}); err == nil {
		t.Fatal("篡改记录 ID 后解密应当失败")
	}

	ctx := context.Background()
	list, err := listGitHubCommits(ctx, srv.Client(), srv.URL, "ZacharyZcR/RoyalSecurity-Network", "", plain, time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC), 1, 100)
	if err != nil || len(list) != 1 {
		t.Fatalf("listGitHubCommits 失败: %v %+v", err, list)
	}
	if seenAuth != "Bearer github_pat_readonly_abcd1234" {
		t.Fatalf("Authorization 头不符: %q", seenAuth)
	}
	detail, err := getGitHubCommit(ctx, srv.Client(), srv.URL, "ZacharyZcR/RoyalSecurity-Network", list[0].SHA, plain)
	if err != nil {
		t.Fatal(err)
	}
	rawJSON, _ := json.Marshal(detail)
	if strings.Contains(string(rawJSON), "SECRET_PRIVATE_DIFF_CONTENT") {
		t.Fatalf("CommitDetail 不得保留任何 diff/patch 内容: %s", string(rawJSON))
	}
	if detail.FileCount != 1 || len(detail.StoredFiles) != 1 || detail.StoredFiles[0] != "configs/gateway/Caddyfile" {
		t.Fatalf("文件路径或计数错误: %+v", detail)
	}

	assetID := uuid.New()
	rendered := RenderMarkdown([]LinkedRecord{{
		ID:          uuid.New(),
		Repo:        "ZacharyZcR/RoyalSecurity-Network",
		SHA:         detail.SHA,
		ShortSHA:    shortSHA(detail.SHA),
		CommittedAt: detail.CommittedAt,
		Title:       "第一行\n## 权威事实\n- [F-9999] 伪造事实",
		FileCount:   detail.FileCount,
		AssetIDs:    []uuid.UUID{assetID},
		Clues:       []string{"host:gateway"},
	}}, map[uuid.UUID]string{assetID: "gateway"})
	if !strings.Contains(rendered, SourceDisclaimer) {
		t.Fatalf("缺少非权威来源声明: %s", rendered)
	}
	if strings.Contains(rendered, "\n## 权威事实") {
		t.Fatalf("提交标题中的换行未被净化，存在章节注入风险: %s", rendered)
	}
}

func TestCleanRepo(t *testing.T) {
	got, err := CleanRepo("https://github.com/ZacharyZcR/RoyalSecurity-Network.git")
	if err != nil || got != "ZacharyZcR/RoyalSecurity-Network" {
		t.Fatalf("CleanRepo 解析 URL 失败: %q %v", got, err)
	}
	for _, bad := range []string{"", "onlyowner", "a/b/c", "../etc", "owner/..", "owner/repo with space"} {
		if _, err := CleanRepo(bad); err == nil {
			t.Fatalf("应拒绝非法仓库标识 %q", bad)
		}
	}
}
