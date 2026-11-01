package native

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
	"openxdr/server/deception/sshdecoy"
)

// ServeSSH 复用原有拒绝认证的监听器；仅回传有限事实，不上传身份、密码和模板正文。
func ServeSSH(ctx context.Context, listener net.Listener, signer ssh.Signer, m Manifest, record func(string) error) error {
	if m.Kind != "ssh" || record == nil {
		return fmt.Errorf("SSH 诱饵配置无效")
	}
	server, err := sshdecoy.New(sshdecoy.Config{Signer: signer, DeploymentID: m.ID, GroupID: m.GroupID, AssetID: m.AssetID, Profile: m.Profile, Record: func(event sshdecoy.Event) error { return record("ssh_" + event.Kind) }})
	if err != nil {
		return err
	}
	return server.Serve(ctx, listener)
}
