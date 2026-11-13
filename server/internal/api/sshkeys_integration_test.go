//go:build integration

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/alert"
	"openxdr/server/ent/approval"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/sshkeyobservation"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/sshkeys"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

func TestSSHKeysInventoryAndClaimAPI(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("prod").SaveX(ctx)
	host := client.Asset.Create().SetHostname("linux-1").SetGroupID(g.ID).SaveX(ctx)
	admin := client.User.Create().SetUsername("root").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	ana := client.User.Create().SetUsername("ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(ana.ID).SetRole("analyst").SaveX(ctx)

	hub := response.NewHub(client, true)
	gate := &commandgate.Gate{DB: client, Hub: hub}
	now := time.Now().UTC().Truncate(time.Second)
	svc := &sshkeys.Service{
		DB:   client,
		Gate: gate,
		Now:  func() time.Time { return now },
	}

	const fp1 = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	const fp2 = "SHA256:SQfC+vTbLURn9cTkVxIS8fGQ3FKNAJWeB0o139+gV4M"

	// 首次上报建立基线，不应触发新钥匙告警或自动生成移除提议
	if err := svc.IngestSnapshot(ctx, host.ID, &pb.ReportSSHKeysRequest{
		ObservedAtMs:              now.UnixMilli(),
		AuthorizedKeysCommand:     "/usr/local/bin/keys %u",
		AuthorizedKeysCommandUser: "nobody",
		Keys: []*pb.SSHAuthorizedKey{
			{
				Account:     "root",
				Path:        "/root/.ssh/authorized_keys",
				KeyType:     "ssh-ed25519",
				Fingerprint: fp1,
				Comment:     "kei@foghaven",
				Options:     []string{`from="10.1.1.0/24"`},
			},
		},
	}); err != nil {
		t.Fatalf("首次基线入库失败: %v", err)
	}
	if n := client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleNewSSHKey)).CountX(ctx); n != 0 {
		t.Fatalf("首次基线不应产生新钥匙告警, got=%d", n)
	}
	if n := client.Approval.Query().CountX(ctx); n != 0 {
		t.Fatalf("首次基线不应生成移除提议, got=%d", n)
	}

	// 推进登录时间（90 天内登录应标为 active）
	obs1 := client.SSHKeyObservation.Query().OnlyX(ctx)
	loginAt := now.Add(-2 * 24 * time.Hour)
	client.SSHKeyObservation.UpdateOneID(obs1.ID).SetLastLoginAt(loginAt).SetLastLoginIP("10.1.1.36").ExecX(ctx)

	// 基线之后新出现第二把钥匙（agent 每次上报完整快照，sshd 配置不变）：应产生高危告警并生成待批移除提议，且不自动删除
	if err := svc.IngestSnapshot(ctx, host.ID, &pb.ReportSSHKeysRequest{
		ObservedAtMs:              now.Add(time.Minute).UnixMilli(),
		AuthorizedKeysCommand:     "/usr/local/bin/keys %u",
		AuthorizedKeysCommandUser: "nobody",
		Keys: []*pb.SSHAuthorizedKey{
			{
				Account:     "root",
				Path:        "/root/.ssh/authorized_keys",
				KeyType:     "ssh-ed25519",
				Fingerprint: fp1,
				Comment:     "kei@foghaven",
			},
			{
				Account:     "root",
				Path:        "/root/.ssh/authorized_keys",
				KeyType:     "ssh-ed25519",
				Fingerprint: fp2,
				Comment:     "spoofed-admin",
			},
		},
	}); err != nil {
		t.Fatalf("增量快照入库失败: %v", err)
	}
	if n := client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleNewSSHKey)).CountX(ctx); n != 1 {
		t.Fatalf("新出现的钥匙应产生 1 条告警, got=%d", n)
	}
	ap := client.Approval.Query().OnlyX(ctx)
	if !ap.Async || ap.Status != approval.StatusPending {
		t.Fatalf("移除提议应处于异步待审批状态: async=%v status=%s", ap.Async, ap.Status)
	}

	h := SSHKeys(client, svc)
	asAdmin := httptest.NewServer(as(admin, h))
	t.Cleanup(asAdmin.Close)
	asAna := httptest.NewServer(as(ana, h))
	t.Cleanup(asAna.Close)

	// 分析员不能认领钥匙
	claimBody := `{"fingerprint":"` + fp1 + `","holder":"user:ana","machine":"Foghaven","purpose":"日常运维"}`
	resp, err := http.Post(asAna.URL+"/api/ssh-keys/claim", "application/json", strings.NewReader(claimBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("非 admin 认领应返回 403, got=%d", resp.StatusCode)
	}

	// admin 认领成功写 key 事实与 fact_created 审计
	resp, err = http.Post(asAdmin.URL+"/api/ssh-keys/claim", "application/json", strings.NewReader(claimBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin 认领应返回 201, got=%d", resp.StatusCode)
	}
	if n := client.AuditLog.Query().Where(auditlog.ActionEQ("fact_created")).CountX(ctx); n != 1 {
		t.Fatalf("认领应写入 fact_created 审计, got=%d", n)
	}

	// 查询列表：在用的 fp1 排在闲置的 fp2 前面，且 fp1 为 claimed、fp2 为 unclaimed
	resp, err = http.Get(asAna.URL + "/api/ssh-keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var list sshkeys.ListResult
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Keys) != 2 {
		t.Fatalf("应返回 2 把钥匙, got=%d", len(list.Keys))
	}
	if list.Keys[0].Fingerprint != fp1 || list.Keys[0].UsageStatus != "active" || list.Keys[0].ClaimStatus != "claimed" {
		t.Fatalf("第 1 把钥匙状态不符: %+v", list.Keys[0])
	}
	if list.Keys[1].Fingerprint != fp2 || list.Keys[1].UsageStatus != "idle" || list.Keys[1].ClaimStatus != "unclaimed" {
		t.Fatalf("第 2 把钥匙状态不符: %+v", list.Keys[1])
	}
	if len(list.HostConfigs) != 1 || list.HostConfigs[0].AuthorizedKeysCommand != "/usr/local/bin/keys %u" {
		t.Fatalf("AuthorizedKeysCommand 配置返回不符: %+v", list.HostConfigs)
	}

	// 当主机随后移除 sshd 的 AuthorizedKeysCommand 时，新快照应同步清空 hostConfigs
	if err := svc.IngestSnapshot(ctx, host.ID, &pb.ReportSSHKeysRequest{
		ObservedAtMs: now.Add(2 * time.Minute).UnixMilli(),
		Keys: []*pb.SSHAuthorizedKey{
			{
				Account:     "root",
				Path:        "/root/.ssh/authorized_keys",
				KeyType:     "ssh-ed25519",
				Fingerprint: fp1,
				Comment:     "kei@foghaven",
			},
		},
	}); err != nil {
		t.Fatalf("移除 AuthorizedKeysCommand 快照入库失败: %v", err)
	}
	resp2, err := http.Get(asAna.URL + "/api/ssh-keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var list2 sshkeys.ListResult
	if err := json.NewDecoder(resp2.Body).Decode(&list2); err != nil {
		t.Fatal(err)
	}
	if len(list2.HostConfigs) != 0 {
		t.Fatalf("移除 AuthorizedKeysCommand 后应清空 hostConfigs, got=%+v", list2.HostConfigs)
	}
	if len(list2.Keys) != 1 || list2.Keys[0].Fingerprint != fp1 {
		t.Fatalf("已移除的钥匙不应再出现在 present 列表中: %+v", list2.Keys)
	}
}

func TestSSHKeysBackfillOnceAndUnchangedFastPath(t *testing.T) {
	ctx, client := testdb.New(t)
	sqlDB, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	g := client.Group.Create().SetName("ops").SaveX(ctx)
	host := client.Asset.Create().SetHostname("linux-backfill").SetGroupID(g.ID).SaveX(ctx)

	t0 := time.Now().UTC().Truncate(time.Second)
	const fp1 = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	const fp2 = "SHA256:SQfC+vTbLURn9cTkVxIS8fGQ3FKNAJWeB0o139+gV4M"
	const fp3 = "SHA256:NcQW5HBTfu9BcEAE6Fv50H5od9G7TfPoVJ1Cnb/jqLQ"

	olderLogin := t0.Add(-3 * 24 * time.Hour)
	latestLogin := t0.Add(-6 * time.Hour)
	client.SSHLogin.Create().
		SetID(uuid.New()).
		SetTs(olderLogin).
		SetGroupID(g.ID).
		SetAssetID(host.ID).
		SetLoginUser("root").
		SetSrcIP("10.1.1.10").
		SetAuthMethod("publickey").
		SetKeyFp(fp1).
		SaveX(ctx)
	client.SSHLogin.Create().
		SetID(uuid.New()).
		SetTs(latestLogin).
		SetGroupID(g.ID).
		SetAssetID(host.ID).
		SetLoginUser("root").
		SetSrcIP("10.1.1.36").
		SetAuthMethod("publickey").
		SetKeyFp(fp1).
		SaveX(ctx)

	// 只写进 events、不在 ssh_logins 里的历史登录不应被回填扫描
	client.Event.Create().
		SetID(uuid.New()).
		SetTs(t0.Add(-12 * time.Hour)).
		SetClassUID(3002).
		SetSource("agent").
		SetAssetID(host.ID).
		SetRaw(json.RawMessage(`{"login_session":{"user":"root","src_ip":"10.9.9.9","key_fp":"` + fp2 + `"}}`)).
		SaveX(ctx)

	curNow := t0
	backfillCount := 0
	hub := response.NewHub(client, true)
	svc := &sshkeys.Service{
		DB:   client,
		SQL:  sqlDB,
		Gate: &commandgate.Gate{DB: client, Hub: hub},
		Now:  func() time.Time { return curNow },
		OnBackfill: func(assetID uuid.UUID) {
			if assetID == host.ID {
				backfillCount++
			}
		},
	}

	makeReq := func(ts time.Time, fps ...string) *pb.ReportSSHKeysRequest {
		keys := make([]*pb.SSHAuthorizedKey, 0, len(fps))
		for _, fp := range fps {
			keys = append(keys, &pb.SSHAuthorizedKey{
				Account:     "root",
				Path:        "/root/.ssh/authorized_keys",
				KeyType:     "ssh-ed25519",
				Fingerprint: fp,
				Comment:     "key",
			})
		}
		return &pb.ReportSSHKeysRequest{
			ObservedAtMs:          ts.UnixMilli(),
			AuthorizedKeysCommand: "/usr/sbin/sss_ssh_authorizedkeys",
			Keys:                  keys,
		}
	}

	// 1. 首次快照建基线：触发 1 次 ssh_logins 回填，且不扫 events
	if err := svc.IngestSnapshot(ctx, host.ID, makeReq(t0, fp1, fp2)); err != nil {
		t.Fatalf("首次快照失败: %v", err)
	}
	if backfillCount != 1 {
		t.Fatalf("首次建基线应触发 1 次回填, got=%d", backfillCount)
	}
	obs1 := client.SSHKeyObservation.Query().Where(sshkeyobservation.AssetIDEQ(host.ID), sshkeyobservation.FingerprintEQ(fp1)).OnlyX(ctx)
	if obs1.LastLoginAt == nil || !obs1.LastLoginAt.Equal(latestLogin) || obs1.LastLoginIP != "10.1.1.36" {
		t.Fatalf("ssh_logins 最新登录未正确回填: at=%v ip=%q", obs1.LastLoginAt, obs1.LastLoginIP)
	}
	obs2 := client.SSHKeyObservation.Query().Where(sshkeyobservation.AssetIDEQ(host.ID), sshkeyobservation.FingerprintEQ(fp2)).OnlyX(ctx)
	if obs2.LastLoginAt != nil {
		t.Fatalf("不应再扫描 events 表回填登录记录: got=%v", obs2.LastLoginAt)
	}
	base0 := client.SSHKeyBaseline.Query().OnlyX(ctx)

	// 2. 第二次相同快照：不触发回填、不改基线表，只更新观测 last_seen
	t1 := t0.Add(5 * time.Minute)
	curNow = t1
	if err := svc.IngestSnapshot(ctx, host.ID, makeReq(t1, fp1, fp2)); err != nil {
		t.Fatalf("第二次相同快照失败: %v", err)
	}
	if backfillCount != 1 {
		t.Fatalf("第二次相同快照不应触发回填, got=%d", backfillCount)
	}
	obs1After := client.SSHKeyObservation.Query().Where(sshkeyobservation.IDEQ(obs1.ID)).OnlyX(ctx)
	if !obs1After.LastSeen.Equal(t1) {
		t.Fatalf("未变快照应更新观测 last_seen: got=%v want=%v", obs1After.LastSeen, t1)
	}
	base1 := client.SSHKeyBaseline.Query().OnlyX(ctx)
	if !base1.LastReportedAt.Equal(base0.LastReportedAt) {
		t.Fatalf("未变快照不应改写 ssh_key_baselines: got=%v want=%v", base1.LastReportedAt, base0.LastReportedAt)
	}

	// 3. 第三次有变更快照：更新基线与新钥匙，但仍不再次触发回填
	t2 := t0.Add(10 * time.Minute)
	curNow = t2
	if err := svc.IngestSnapshot(ctx, host.ID, makeReq(t2, fp1, fp2, fp3)); err != nil {
		t.Fatalf("第三次变更快照失败: %v", err)
	}
	if backfillCount != 1 {
		t.Fatalf("基线建立后的变更快照也不应再次回填, got=%d", backfillCount)
	}
	base2 := client.SSHKeyBaseline.Query().OnlyX(ctx)
	if !base2.LastReportedAt.Equal(t2) {
		t.Fatalf("变更快照应更新基线时间: got=%v want=%v", base2.LastReportedAt, t2)
	}

	// 4. 客户端已取消的 ctx 必须立即中止，不执行写操作
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	t3 := t0.Add(15 * time.Minute)
	curNow = t3
	if err := svc.IngestSnapshot(canceledCtx, host.ID, makeReq(t3, fp1, fp2, fp3)); !errors.Is(err, context.Canceled) {
		t.Fatalf("已取消 ctx 应返回 context.Canceled, got=%v", err)
	}
	obs1Canceled := client.SSHKeyObservation.Query().Where(sshkeyobservation.IDEQ(obs1.ID)).OnlyX(ctx)
	if !obs1Canceled.LastSeen.Equal(t2) {
		t.Fatalf("已取消请求不应修改 last_seen: got=%v want=%v", obs1Canceled.LastSeen, t2)
	}
}
