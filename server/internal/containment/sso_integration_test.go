//go:build integration

package containment

import (
	"context"
	"errors"
	"testing"

	entasset "openxdr/server/ent/asset"
	entcontainment "openxdr/server/ent/containment"
	entevent "openxdr/server/ent/event"
	"openxdr/server/internal/sigma"
)

type fakeSSO struct{ disabled, enabled []string }

func (f *fakeSSO) Disable(_ context.Context, u string) (string, error) {
	if u == "akadmin" {
		return "", errors.New("是超级管理员，不自动停用")
	}
	f.disabled = append(f.disabled, u)
	return "已停用 " + u, nil
}

func (f *fakeSSO) Enable(_ context.Context, u string) (string, error) {
	f.enabled = append(f.enabled, u)
	return "已恢复 " + u, nil
}

// Authentik 上的爆破得手：在 Authentik 停用 SSO 账号（核心资产也照样，与能否登上主机无关）、封锁来源；
// 超级管理员被拒记为失败；人工可恢复
func TestBruteforceOnSSODisablesTheAccount(t *testing.T) {
	f := setup(t)
	gw := f.host(t, "gateway", "10.1.1.100", tierPtr(entasset.ResponseTierCore), "")
	sso := &fakeSSO{}
	e := f.engine(ScopeAll)
	e.SSO = sso
	for _, user := range []string{"alice", "akadmin"} {
		al := f.alertOn(t, gw, sigma.RuleBruteforceSuccess, 3002, user, `{"status_id":1,"user":{"name":"`+user+`"},"src_endpoint":{"ip":"203.0.113.9"},"service":{"name":"authentik"}}`)
		f.client.Event.Update().Where(entevent.IDEQ(*al.EventID)).SetSource("authentik").ExecX(f.ctx)
	}
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if len(sso.disabled) != 1 || sso.disabled[0] != "alice" {
		t.Fatalf("应停用 alice：%v", sso.disabled)
	}
	rows := f.client.Containment.Query().Where(entcontainment.KindEQ(KindSSO)).AllX(f.ctx)
	states := map[string]entcontainment.State{}
	for _, c := range rows {
		states[c.Target] = c.State
	}
	if states["alice"] != entcontainment.StateExecuted || states["akadmin"] != entcontainment.StateFailed {
		t.Fatalf("状态不对：%v", states)
	}
	if n := f.client.Containment.Query().Where(entcontainment.KindEQ("disable_account")).CountX(f.ctx); n != 0 {
		t.Fatal("SSO 账号不该再去锁主机本地账号")
	}
	alice := f.client.Containment.Query().Where(entcontainment.KindEQ(KindSSO), entcontainment.TargetEQ("alice")).OnlyX(f.ctx)
	lifted, err := e.LiftSSO(f.ctx, alice, "admin", "已改密")
	if err != nil || lifted.State != entcontainment.StateLifted || len(sso.enabled) != 1 {
		t.Fatalf("应能恢复：%v %v", lifted, err)
	}
	if _, err := e.LiftSSO(f.ctx, lifted, "admin", ""); err != ErrNotLiftable {
		t.Fatalf("不能重复恢复：%v", err)
	}
}
