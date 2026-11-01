//go:build integration

package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"openxdr/server/deception/native"
	"openxdr/server/deception/sdk"
	"openxdr/server/ent/decoydeployment"
	"openxdr/server/ent/decoyobservation"
	"openxdr/server/internal/testdb"
)

func TestDecoySSHAuthenticatedReporting(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("ssh").SaveX(ctx)
	asset := db.Asset.Create().SetHostname("ssh-decoy").SetGroupID(group.ID).SaveX(ctx)
	token := randomDecoyToken()
	row := db.DecoyDeployment.Create().SetAssetID(asset.ID).SetKind(decoydeployment.KindSSH).SetPort(2222).SetProfile("decoy").SetTemplate("identify-v1").SetCreatedBy("admin").SetTokenHash(decoyTokenHash(token)).SetTokenGroupID(group.ID).SetTokenExpiresAt(time.Now().Add(time.Hour)).SetMarker(randomDecoyToken()).SaveX(ctx)
	platform := httptest.NewServer(DecoyRuntime(db))
	defer platform.Close()
	client, err := sdk.NewClient(platform.URL, row.ID.String(), token)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := client.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- native.ServeSSH(runCtx, listener, signer, manifest, func(kind string) error { return client.Record(runCtx, kind) })
	}()
	connection, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "synthetic", Auth: []ssh.AuthMethod{ssh.Password("synthetic")}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 3 * time.Second})
	if err == nil {
		connection.Close()
		t.Fatal("诱饵授予了 SSH 访问")
	}
	if count := db.DecoyObservation.Query().Where(decoyobservation.DeploymentIDEQ(row.ID), decoyobservation.KindEQ("ssh_authentication_attempt")).CountX(ctx); count != 1 {
		t.Fatalf("认证事件未入库: %d", count)
	}
	if count := db.DecoyObservation.Query().Where(decoyobservation.KindEQ("ssh_banner_prepared")).CountX(ctx); count != 1 {
		t.Fatalf("Banner 事件未入库: %d", count)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SSH 未停止")
	}
}
