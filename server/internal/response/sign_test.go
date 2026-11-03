package response

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"openxdr/server/pb"
)

func TestSealBindsAgentAndExpiry(t *testing.T) {
	h := NewHub(nil, true)
	agent := uuid.New()
	plain := &pb.Command{Id: uuid.NewString(), Kind: pb.CommandKind_BLOCK_NETWORK, Target: "10.1.1.170"}
	sealed, err := h.seal(agent, plain)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(h.SignerPublic(), append([]byte(signContext), sealed.Envelope...), sealed.Signature) {
		t.Fatal("签名校验失败")
	}
	var env pb.SignedCommand
	if err := proto.Unmarshal(sealed.Envelope, &env); err != nil {
		t.Fatal(err)
	}
	if env.AgentId != agent.String() || !proto.Equal(env.Command, plain) {
		t.Fatalf("信封内容不对: %v", &env)
	}
	if left := time.Until(time.Unix(env.ExpiresUnix, 0)); left <= 0 || left > signedValidity {
		t.Fatalf("有效期 %v", left)
	}
	if plain.Envelope != nil || sealed.Target != plain.Target {
		t.Fatal("seal 不应改动入参，明文字段要保留给内部投递")
	}
	tampered := proto.Clone(sealed).(*pb.Command)
	tampered.Envelope[len(tampered.Envelope)-1] ^= 1
	if ed25519.Verify(h.SignerPublic(), append([]byte(signContext), tampered.Envelope...), tampered.Signature) {
		t.Fatal("篡改后的信封不应通过校验")
	}
}

// 与 agent 侧 respond::signed 测试共用的向量：两端对签名域与算法的理解必须一致。
func TestSignatureVector(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	envelope := []byte("vector")
	sig := ed25519.Sign(key, append([]byte(signContext), envelope...))
	const want = "910c37eca5987fa58fd26fc717f63836271fcdd9a8258fdc26d303fba9ae675f" +
		"3de392bab17596105c3268b2ea48f4b60cac0467ca755b72c30b747693f94f0b"
	if got := hex.EncodeToString(sig); got != want {
		t.Fatalf("签名向量变了: %s（公钥 %x）", got, key.Public())
	}
}

func TestLoadSigner(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(nil)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	path := filepath.Join(t.TempDir(), "command-signing.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSigner(path)
	if err != nil || !got.Equal(key) {
		t.Fatalf("加载结果不一致: %v", err)
	}
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigner(path); err == nil {
		t.Fatal("非 PEM 内容应报错")
	}
}
