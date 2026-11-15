//go:build integration

package commandgate

import (
	"testing"
	"time"
)

// 回执悬着的写指令只在窗口内挡住新修复；只读指令和过了窗口的旧回执不挡
func TestUnsettledWriteWindow(t *testing.T) {
	f := setup(t)
	host, now := f.req.Command.AssetID, time.Now()
	add := func(cmd, status string, age time.Duration) {
		f.db.Command.Create().SetAssetID(host).SetKind("exec").SetCmd(cmd).SetStatus(status).SetIssuedBy("system").
			SetCreatedAt(now.Add(-age)).SaveX(f.ctx)
	}
	add("systemctl restart -- app.service", "unknown", UnsettledWindow+time.Hour)
	add("apt-get clean", "sent", 30*24*time.Hour)
	add("df -P /", "unknown", time.Minute)
	if c, err := UnsettledWrite(f.ctx, f.db.Command, host, now); err != nil || c != nil {
		t.Fatalf("过了窗口的旧回执与只读指令不应挡住修复：%v %+v", err, c)
	}
	add("docker builder prune -f", "unknown", time.Hour)
	if c, err := UnsettledWrite(f.ctx, f.db.Command, host, now); err != nil || c == nil || *c.Cmd != "docker builder prune -f" {
		t.Fatalf("窗口内回执未知的写指令应挡住修复：%v %+v", err, c)
	}
}
