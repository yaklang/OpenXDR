//go:build integration

package grpcsvc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"openxdr/server/internal/enroll"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

type fakeDownloadStream struct {
	ctx  context.Context
	data bytes.Buffer
	n    int
}

func (f *fakeDownloadStream) Send(c *pb.AgentChunk) error {
	f.n++
	f.data.Write(c.Data)
	return nil
}
func (f *fakeDownloadStream) Context() context.Context     { return f.ctx }
func (f *fakeDownloadStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeDownloadStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeDownloadStream) SetTrailer(metadata.MD)       {}
func (f *fakeDownloadStream) SendMsg(any) error            { return nil }
func (f *fakeDownloadStream) RecvMsg(any) error            { return nil }

var _ grpc.ServerStreamingServer[pb.AgentChunk] = (*fakeDownloadStream)(nil)

// 分发目录的版本与 agent 不同才要求升级；老 agent 与关闭开关时不升级；下载按块拼回原文件。
func TestRegisterOffersUpgradeAndStreamsBinary(t *testing.T) {
	ctx, client := testdb.New(t)
	dir := t.TempDir()
	binary := bytes.Repeat([]byte("agent-v2"), 100_000) // 跨多个分块
	if err := os.WriteFile(filepath.Join(dir, "openxdr-agent-linux-amd64"), binary, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binary)
	want := hex.EncodeToString(sum[:])
	srv := &Server{DB: client, Dist: enroll.AgentDist(dir), AutoUpgrade: true}

	register := func(sha, arch string) *pb.RegisterResponse {
		t.Helper()
		resp, err := srv.Register(ctx, &pb.RegisterRequest{Hostname: "web01", Os: "linux", Arch: arch, AgentVersion: "0.1.0", BinarySha256: sha})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if r := register("old", "x86_64"); r.UpgradeSha256 != want || r.UpgradePlatform != "linux-amd64" {
		t.Fatalf("版本不同应要求升级：%+v", r)
	}
	if r := register("old", "x86_64"); r.UpgradeSignature != nil {
		t.Fatal("没放 .sig 时不带发布签名")
	}
	sig := bytes.Repeat([]byte{7}, 64)
	sigPath := filepath.Join(dir, "openxdr-agent-linux-amd64.sig")
	if err := os.WriteFile(sigPath, []byte(hex.EncodeToString(sig)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := register("old", "x86_64"); !bytes.Equal(r.UpgradeSignature, sig) {
		t.Fatalf("应随升级指示下发发布签名：%x", r.UpgradeSignature)
	}
	if err := os.WriteFile(sigPath, []byte("not-hex"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := register("old", "x86_64"); r.UpgradeSignature != nil {
		t.Fatal("格式不对的签名文件不下发")
	}
	if got := client.Asset.Query().OnlyX(ctx); got.AgentVersion == nil || *got.AgentVersion != "0.1.0" {
		t.Errorf("应记录 agent 版本：%v", got.AgentVersion)
	}
	if r := register(want, "x86_64"); r.UpgradeSha256 != "" {
		t.Error("已是分发版本不应再升级")
	}
	if r := register("", "x86_64"); r.UpgradeSha256 != "" {
		t.Error("不报哈希的老 agent 不应被要求升级")
	}
	if r := register("old", "aarch64"); r.UpgradeSha256 != "" {
		t.Error("分发目录没有该平台安装包时不应升级")
	}
	srv.AutoUpgrade = false
	if r := register("old", "x86_64"); r.UpgradeSha256 != "" {
		t.Error("关闭自动升级后不应下发")
	}

	stream := &fakeDownloadStream{ctx: ctx}
	if err := srv.DownloadAgent(&pb.DownloadRequest{Platform: "linux-amd64", Sha256: want}, stream); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stream.data.Bytes(), binary) || stream.n < 2 {
		t.Fatalf("下载内容应与安装包一致且分块发送，得到 %d 字节 %d 块", stream.data.Len(), stream.n)
	}
	if err := srv.DownloadAgent(&pb.DownloadRequest{Platform: "linux-amd64", Sha256: "stale"}, &fakeDownloadStream{ctx: ctx}); err == nil {
		t.Error("哈希不符应拒绝下载")
	}
}
