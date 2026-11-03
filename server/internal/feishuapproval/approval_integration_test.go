//go:build integration

package feishuapproval

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/approval"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/commandpolicy"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/hostimport"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

type fixture struct {
	s     *Service
	c     Config
	ctx   context.Context
	u     *ent.User
	group uuid.UUID
	asset *ent.Asset
}

func setup(t *testing.T) fixture {
	ctx, db := testdb.New(t)
	raw, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	vault, err := hostimport.NewVault(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{SQL: raw, DB: db, Vault: vault, Gate: &commandgate.Gate{DB: db, Hub: response.NewHub(db, true), ApprovalTimeout: 4 * time.Second}}
	if err = s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	g := db.Group.Create().SetName("test").SaveX(ctx)
	u := db.User.Create().SetUsername("approver").SetRole("admin").SetPasswordHash("unused").SaveX(ctx)
	asset := db.Asset.Create().SetHostname("test-host").SetAgentID(uuid.New()).SetGroupID(g.ID).SaveX(ctx)
	sealed, err := vault.Seal(hostimport.Secret{Password: "fake-secret"}, "feishu-approval:cli_test00001")
	if err != nil {
		t.Fatal(err)
	}
	c := Config{AppID: "cli_test00001", Enabled: true, Sealed: sealed, Revision: uuid.NewString()}
	b, _ := json.Marshal(c)
	db.Setting.Create().SetID(configKey).SetValue(b).SaveX(ctx)
	return fixture{s, c, ctx, u, g.ID, asset}
}
func bindUser(t *testing.T, f fixture, u *ent.User, openID string) {
	code, err := f.s.bindingCode(f.ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.bind(f.ctx, f.c, "tenant", openID, code); err != nil {
		t.Fatal(err)
	}
}
func pendingApproval(t *testing.T, f fixture) *ent.Approval {
	return f.s.DB.Approval.Create().SetGroupID(f.group).SetAssetID(f.asset.ID).SetRequestedBy(f.u.Username).SetOrigin(approval.OriginAi).SetCmd("id").SetTimeoutMs(1000).SetExpiresAt(time.Now().Add(time.Minute)).SaveX(f.ctx)
}
func delivered(t *testing.T, f fixture, a *ent.Approval) string {
	if err := f.s.enqueue(f.ctx, f.c); err != nil {
		t.Fatal(err)
	}
	var nonce string
	err := f.s.SQL.QueryRowContext(f.ctx, `UPDATE feishu_approval_deliveries SET message_id='message-1' WHERE approval_id=$1 AND user_id=$2 RETURNING nonce`, a.ID, f.u.ID).Scan(&nonce)
	if err != nil {
		t.Fatal(err)
	}
	return nonce
}

func TestBindingLifecycle(t *testing.T) {
	f := setup(t)
	old, err := f.s.bindingCode(f.ctx, f.u)
	if err != nil {
		t.Fatal(err)
	}
	code, err := f.s.bindingCode(f.ctx, f.u)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.bind(f.ctx, f.c, "tenant", "open-1", old); err == nil {
		t.Fatal("旧绑定码被接受")
	}
	if err = f.s.bind(f.ctx, f.c, "tenant", "open-1", code); err != nil {
		t.Fatal(err)
	}
	if err = f.s.bind(f.ctx, f.c, "tenant", "open-2", code); err == nil {
		t.Fatal("绑定码重复使用")
	}
	code, err = f.s.bindingCode(f.ctx, f.u)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.bind(f.ctx, f.c, "tenant", "open-2", code); err == nil {
		t.Fatal("既有绑定被静默替换")
	}
	if err = f.s.unbind(f.ctx, f.u); err != nil {
		t.Fatal(err)
	}
	if err = f.s.bind(f.ctx, f.c, "tenant", "open-2", code); err == nil {
		t.Fatal("解绑未撤销绑定码")
	}
	code, err = f.s.bindingCode(f.ctx, f.u)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.SQL.ExecContext(f.ctx, `UPDATE feishu_approval_codes SET expires_at=now()-interval '1 second'`)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.bind(f.ctx, f.c, "tenant", "open-2", code); err == nil {
		t.Fatal("过期绑定码被接受")
	}
}

func TestRejectMismatchedAndRevokedCards(t *testing.T) {
	for _, mode := range []string{"operator", "tenant", "message", "nonce", "expired", "revoked", "disabled", "revision", "too_long", "unbind"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			bindUser(t, f, f.u, "open-1")
			a := pendingApproval(t, f)
			nonce := delivered(t, f, a)
			tenant, openID, messageID := "tenant", "open-1", "message-1"
			switch mode {
			case "operator":
				openID = "other"
			case "tenant":
				tenant = "other"
			case "message":
				messageID = "forwarded-message"
			case "nonce":
				nonce = uuid.NewString()
			case "expired":
				f.s.DB.Approval.UpdateOneID(a.ID).SetExpiresAt(time.Now().Add(-time.Minute)).SaveX(f.ctx)
			case "revoked":
				f.s.DB.User.UpdateOneID(f.u.ID).SetRole("viewer").SaveX(f.ctx)
			case "disabled", "revision":
				c := f.c
				if mode == "disabled" {
					c.Enabled = false
				} else {
					c.Revision = uuid.NewString()
				}
				b, _ := json.Marshal(c)
				f.s.DB.Setting.UpdateOneID(configKey).SetValue(b).SaveX(f.ctx)
			case "too_long":
				f.s.DB.Approval.UpdateOneID(a.ID).SetCmd(strings.Repeat("x", 4001)).SaveX(f.ctx)
			case "unbind":
				if err := f.s.unbind(f.ctx, f.u); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.s.decide(f.ctx, f.c, tenant, openID, messageID, nonce, "approve"); err == nil {
				t.Fatal("非法审批被接受")
			}
			if f.s.DB.Approval.GetX(f.ctx, a.ID).Status != approval.StatusPending {
				t.Fatal("拒绝的回调改变了审批状态")
			}
		})
	}
}

func TestConcurrentDecisionsOnce(t *testing.T) {
	f := setup(t)
	bindUser(t, f, f.u, "open-1")
	a := pendingApproval(t, f)
	nonce := delivered(t, f, a)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.s.decide(f.ctx, f.c, "tenant", "open-1", "message-1", nonce, "approve")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("应恰好决定一次: %d", success)
	}
	if f.s.DB.AuditLog.Query().Where(auditlog.ActionEQ("approval_decided")).CountX(f.ctx) != 1 {
		t.Fatal("审批审计不唯一")
	}
}

func TestGateConsumesFeishuApprovalOnce(t *testing.T) {
	for _, action := range []string{"approve", "reject"} {
		t.Run(action, func(t *testing.T) {
			f := setup(t)
			bindUser(t, f, f.u, "open-1")
			ch := f.s.Gate.Hub.Attach(*f.asset.AgentID)
			webhookCalls := 0
			f.s.Gate.Notify = ApprovalNotifier(f.s.DB, func(context.Context, string, string, string) error { webhookCalls++; return nil })
			defer f.s.Gate.Hub.Detach(*f.asset.AgentID, ch)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			cmd := "id"
			f.s.DB.CommandPolicy.Create().SetGroupID(f.group).SetOrigin(commandpolicy.OriginHuman).SetMode(commandpolicy.ModeDeny).SetPattern("^id$").SaveX(f.ctx)
			done := make(chan error, 1)
			go func() {
				_, err := f.s.Gate.Issue(ctx, commandgate.Request{UserID: f.u.ID, GroupID: f.group, Origin: "human", Command: response.Request{Kind: "exec", AssetID: f.asset.ID, Cmd: &cmd, TimeoutMS: 1000}})
				done <- err
			}()
			var a *ent.Approval
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				a, _ = f.s.DB.Approval.Query().Where(approval.StatusEQ(approval.StatusPending)).Only(f.ctx)
				if a != nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if a == nil {
				t.Fatal("未生成审批")
			}
			nonce := delivered(t, f, a)
			select {
			case <-ch:
				t.Fatal("审批前下发了命令")
			default:
			}
			if _, err := f.s.decide(f.ctx, f.c, "tenant", "open-1", "message-1", nonce, action); err != nil {
				t.Fatal(err)
			}
			if action == "approve" {
				select {
				case issued := <-ch:
					if issued.Cmd != "id" {
						t.Fatal("执行命令改变")
					}
					if err := f.s.Gate.Hub.Complete(f.ctx, *f.asset.AgentID, &pb.CommandResult{CommandId: issued.Id, AgentId: f.asset.AgentID.String(), Status: pb.CommandResult_SUCCEEDED, Stdout: "uid=1000"}); err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("批准后未下发")
				}
			}
			select {
			case err := <-done:
				if (action == "approve") != (err == nil) {
					t.Fatalf("执行结果不符: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("闸门未结束")
			}
			if _, err := f.s.decide(f.ctx, f.c, "tenant", "open-1", "message-1", nonce, "approve"); err == nil {
				t.Fatal("旧卡片重复批准")
			}
			if webhookCalls != 0 {
				t.Fatal("飞书审批仍向 Webhook 重复通知")
			}
			select {
			case <-ch:
				t.Fatal("重复下发")
			default:
			}
		})
	}
}

func TestSettingsHideSecretAndRequireAdmin(t *testing.T) {
	f := setup(t)
	r := httptest.NewRequest("GET", "/api/approvals/feishu", nil).WithContext(auth.WithUser(f.ctx, f.u))
	w := httptest.NewRecorder()
	f.s.status(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "sealed") || strings.Contains(w.Body.String(), "fake-secret") {
		t.Fatal("配置读取泄密")
	}
	viewer := f.s.DB.User.Create().SetUsername("viewer").SetRole("viewer").SetPasswordHash("unused").SaveX(f.ctx)
	r = httptest.NewRequest("PUT", "/api/settings/feishu-approval", strings.NewReader(`{"app_id":"cli_test00001","enabled":false}`)).WithContext(auth.WithUser(f.ctx, viewer))
	w = httptest.NewRecorder()
	f.s.saveConfig(w, r)
	if w.Code != 403 {
		t.Fatal("非管理员修改配置")
	}
}
