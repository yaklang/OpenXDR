//go:build integration

package triage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/findings"
	"openxdr/server/internal/testdb"
)

// 涉事主机的待办、管理员执行决定与监听端口要进研判上下文；别的主机的不进
func TestBuildContextAssetWork(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	g := client.Group.Create().SetName("g").SaveX(ctx)
	a := client.Asset.Create().SetHostname("blue-server").SetGroupID(g.ID).
		SetListening(json.RawMessage(`[{"addr":"0.0.0.0","port":5555,"proto":"tcp","process":"node","path":"/usr/local/bin/node"}]`)).SetInventoryAt(now).SaveX(ctx)
	other := client.Asset.Create().SetHostname("elsewhere").SetGroupID(g.ID).SaveX(ctx)
	f := client.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("smb").SetTitle("SMB 445 源收口").SaveX(ctx)
	client.Finding.Create().SetGroupID(g.ID).SetAssetID(other.ID).SetKey("x").SetTitle("别的主机的待办").ExecX(ctx)
	d := findings.Decision{RequestID: uuid.New(), FindingID: f.ID, GroupID: g.ID, AssetID: a.ID, SessionID: uuid.New(), UserID: uuid.New(),
		Author: "admin", Instruction: "只允许 Termix 访问 445，用 systemd 单元持久化 nft 规则", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
	b, _ := json.Marshal(d)
	client.Setting.Create().SetID("finding-decision:" + f.ID.String()).SetValue(b).ExecX(ctx)

	ev := client.Event.Create().SetTs(now).SetClassUID(1007).SetSource("agent").SetAssetID(a.ID).SetRaw(json.RawMessage(`{"process":{"name":"nft"}}`)).SaveX(ctx)
	inc := client.Incident.Create().SetStatus("open").SetTitle("Kernel Module Loaded").SetGraph(json.RawMessage(`{"nodes":[]}`)).SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("r").SetSeverity(4).SetAssetID(a.ID).SetEventID(ev.ID).SetIncidentID(inc.ID).ExecX(ctx)

	// 登记晚于告警入库：告警没打可信来源标记，但登录会话对得上，上下文照样注明
	ssh := client.Event.Create().SetTs(now).SetClassUID(1007).SetSource("agent").SetAssetID(a.ID).
		SetRaw(json.RawMessage(`{"process":{"name":"bash"},"login_session":{"user":"root","src_ip":"10.1.1.3","key_fp":"SHA256:ops"}}`)).SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("r2").SetSeverity(4).SetAssetID(a.ID).SetEventID(ssh.ID).SetIncidentID(inc.ID).ExecX(ctx)
	fp, cidr, user := "SHA256:ops", "10.1.1.3/32", "root"
	client.TrustedSource.Create().SetGroupID(g.ID).SetName("运维钥匙").SetCreatedBy("admin").SetExpiresAt(now.Add(24 * time.Hour)).
		SetKeyFingerprint(fp).SetSourceCidr(cidr).SetLoginUser(user).ExecX(ctx)
	client.TrustedSource.Create().SetGroupID(g.ID).SetName("已撤销的").SetCreatedBy("admin").SetExpiresAt(now.Add(24 * time.Hour)).
		SetKeyFingerprint(fp).SetRevokedAt(now).ExecX(ctx)

	out, err := (&Engine{DB: client}).buildContext(ctx, inc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "登录会话符合当前登记的可信自动化「运维钥匙」") || strings.Contains(out, "已撤销的") {
		t.Errorf("应只按有效登记标注来源:\n%s", out)
	}
	for _, want := range []string{"SMB 445 源收口", "管理员执行决定（admin", "只允许 Termix 访问 445", "有效", "tcp/5555 0.0.0.0 node(/usr/local/bin/node)"} {
		if !strings.Contains(out, want) {
			t.Errorf("上下文缺少 %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "别的主机的待办") {
		t.Error("不涉事主机的待办不应进上下文")
	}
}
