package response

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"openxdr/server/pb"
)

// signedValidity 信封的有效期。指令只在 agent 在线时下发、到达即执行，
// 留一小时只为容忍主机时钟偏差；重放另由 agent 本地的执行回执挡住
const signedValidity = time.Hour

// signContext 签名的域分隔前缀，与 agent 侧一致：这把私钥签出的东西不能被挪作别用
const signContext = "openxdr-command-v1\x00"

// LoadSigner 读取 PKCS#8 PEM 格式的 Ed25519 指令签名私钥（gencerts 生成的 command-signing.key）。
func LoadSigner(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s 不是 PKCS#8 PEM 私钥", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	signer, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s 不是 Ed25519 私钥", path)
	}
	return signer, nil
}

// SignerPublic 下发给 agent 固定的公钥；未配置签名时为空，agent 不会固定任何公钥。
func (h *Hub) SignerPublic() []byte {
	if h.Signer == nil {
		return nil
	}
	return h.Signer.Public().(ed25519.PublicKey)
}

// seal 把指令装进绑定 agent 与有效期的签名信封。明文字段保留给 server 内部投递与回写。
func (h *Hub) seal(agentID uuid.UUID, cmd *pb.Command) (*pb.Command, error) {
	envelope, err := proto.Marshal(&pb.SignedCommand{
		Command:     cmd,
		AgentId:     agentID.String(),
		ExpiresUnix: time.Now().Add(signedValidity).Unix(),
	})
	if err != nil {
		return nil, err
	}
	out := proto.Clone(cmd).(*pb.Command)
	out.Envelope = envelope
	out.Signature = ed25519.Sign(h.Signer, append([]byte(signContext), envelope...))
	return out, nil
}

func newEphemeralSigner() ed25519.PrivateKey {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}
