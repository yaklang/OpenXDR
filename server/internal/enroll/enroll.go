// Package enroll 主机在线接入：一条安装命令完成下载、签证书、入组、起服务。
//
// 信任链：
//   - 令牌只存哈希，按组签发、有有效期、可撤销；持有者能把主机接入该组，仅此而已
//   - 私钥在主机本地生成，server 只签 CSR，证书 CN 固定为 host:<主机名>（agent）
//     或 sensor:<主机名>（流量探针），与 gRPC 侧的身份绑定校验是同一套身份；
//     两种证书互不通用，探针证书进不了 agent 通道，反之亦然
//   - 令牌分用途：agent 令牌签不出探针证书，探针令牌也签不出主机证书
//   - 已有在线 agent（或在线探针）的主机名不能重签，令牌不能拿来冒充一台正在运行的主机；
//     已在别的组的主机不能被令牌改组
//
// 启用条件：配了 ENROLL_GRPC_URL（agent 连 server 的地址）；server 开了 mTLS 时还需要
// TLS_CA_KEY_FILE 用来签发。缺哪样就不启用并说明原因，绝不发一份连不上的配置。
//
// TLS_CA_FILE 可以是多张 CA 的信任包：签发用其中与 TLS_CA_KEY_FILE 配对的那张，下发给
// agent 的是整个信任包。这样原 CA 私钥丢了也能另起一张接入 CA，老证书照常可用。
package enroll

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/enrolltoken"
)

// 令牌有效期上限：批量装机够用，泄露了也不会长期有效
const MaxTTL = 30 * 24 * time.Hour

// 证书有效期与 gencerts 一致；agent 不会自动续期，过短会让整片主机同时掉线
const certValidity = 10 * 365 * 24 * time.Hour

var (
	ErrToken    = errors.New("接入令牌无效、已过期或已撤销")
	ErrHostname = errors.New("主机名不合法")
	ErrOnline   = errors.New("该主机名已有在线 agent，不能重复接入；重装请先停掉旧 agent，等它失联后再装")
	ErrSensor   = errors.New("该主机名已有在线流量探针，不能重复接入；重装请先停掉旧探针，等它失联后再装")
	ErrMoved    = errors.New("该主机已在其他组，令牌不能改变主机所属组，请在控制台调整")
	ErrKind     = errors.New("令牌用途不符：agent 令牌只能接入 agent，流量探针令牌只能接入流量探针")
)

// 令牌与证书的两种用途
const (
	KindAgent  = "agent"
	KindSensor = "sensor"
)

// cnPrefix 各用途证书的 CN 前缀，gRPC 侧按它区分身份
var cnPrefix = map[string]string{KindAgent: "host:", KindSensor: "sensor:"}

var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

type Service struct {
	DB *ent.Client
	// agent 连接 server 的 gRPC 地址，写进 agent.env
	GRPCURL string
	// 为空表示 server 未开 mTLS，接入只下发地址
	CA    *x509.Certificate
	CAKey crypto.Signer
	// 下发给 agent 的信任包（TLS_CA_FILE 原文），用来校验 server 证书
	Bundle []byte
	// mTLS 已开但缺签发密钥时的原因
	broken string
	// 判定"在线"的心跳窗口，与失联通知同一口径
	OnlineWindow time.Duration
}

// FromEnv 读取启用接入所需的配置。返回的 Service 总是可用来查询状态。
func FromEnv(db *ent.Client, onlineWindow time.Duration) (*Service, error) {
	s := &Service{DB: db, GRPCURL: os.Getenv("ENROLL_GRPC_URL"), OnlineWindow: onlineWindow}
	caFile, keyFile := os.Getenv("TLS_CA_FILE"), os.Getenv("TLS_CA_KEY_FILE")
	if caFile == "" {
		return s, nil
	}
	if keyFile == "" {
		s.broken = "server 已启用 mTLS，但未配置 TLS_CA_KEY_FILE，无法在线签发主机证书"
		return s, nil
	}
	bundle, ca, key, err := loadCA(caFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("加载签发 CA 失败：%w", err)
	}
	s.Bundle, s.CA, s.CAKey = bundle, ca, key
	return s, nil
}

// Disabled 不能接入的原因，空串表示可用。
func (s *Service) Disabled() string {
	switch {
	case s.broken != "":
		return s.broken
	case s.GRPCURL == "":
		return "未配置 ENROLL_GRPC_URL（agent 连接 server 的 gRPC 地址，如 https://10.1.1.199:8081）"
	}
	return ""
}

// Issue 签发 agent 令牌，明文只在这里出现一次。
func (s *Service) Issue(ctx context.Context, group uuid.UUID, by string, ttl time.Duration) (string, *ent.EnrollToken, error) {
	return s.IssueKind(ctx, KindAgent, group, by, ttl)
}

// IssueKind 签发指定用途的令牌。
func (s *Service) IssueKind(ctx context.Context, kind string, group uuid.UUID, by string, ttl time.Duration) (string, *ent.EnrollToken, error) {
	if _, ok := cnPrefix[kind]; !ok {
		return "", nil, fmt.Errorf("未知的令牌用途 %q", kind)
	}
	if ttl <= 0 || ttl > MaxTTL {
		return "", nil, fmt.Errorf("有效期须在 0 到 %d 天之间", int(MaxTTL.Hours()/24))
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	plain := "oxe_" + base64.RawURLEncoding.EncodeToString(b)
	t, err := s.DB.EnrollToken.Create().SetTokenHash(hash(plain)).SetGroupID(group).SetKind(enrolltoken.Kind(kind)).
		SetCreatedBy(by).SetExpiresAt(time.Now().Add(ttl)).Save(ctx)
	return plain, t, err
}

// Request 主机发来的接入请求。
type Request struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	CSR      string `json:"csr"`
	// agent 或 sensor，空按 agent（旧版 agent 不带）
	Kind string `json:"kind,omitempty"`
}

// Grant 接入应答，agent / sensor 的 enroll-apply 直接写成配置与证书文件。
type Grant struct {
	Server string `json:"server"`
	CA     string `json:"ca,omitempty"`
	Cert   string `json:"cert,omitempty"`
}

// Enroll 校验令牌、把主机放进令牌所属组、签发证书。成功返回资产与应答。
func (s *Service) Enroll(ctx context.Context, token string, req Request) (*ent.Asset, Grant, error) {
	if reason := s.Disabled(); reason != "" {
		return nil, Grant{}, errors.New(reason)
	}
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return nil, Grant{}, err
	}
	defer tx.Rollback()
	// 先验令牌：没有有效令牌的请求碰不到后面任何逻辑，也拿不到更具体的报错
	t, err := tx.EnrollToken.Query().Where(enrolltoken.TokenHashEQ(hash(token))).Only(ctx)
	if err != nil || t.Revoked || time.Now().After(t.ExpiresAt) {
		return nil, Grant{}, ErrToken
	}
	kind := req.Kind
	if kind == "" {
		kind = KindAgent
	}
	if string(t.Kind) != kind {
		return nil, Grant{}, ErrKind
	}
	if !hostnameRe.MatchString(req.Hostname) {
		return nil, Grant{}, ErrHostname
	}
	var cert []byte
	if s.CA != nil {
		if cert, err = s.sign(req.CSR, cnPrefix[kind]+req.Hostname); err != nil {
			return nil, Grant{}, err
		}
	}
	a, err := tx.Asset.Query().Where(asset.HostnameEQ(req.Hostname)).First(ctx)
	switch {
	case ent.IsNotFound(err):
		a, err = tx.Asset.Create().SetHostname(req.Hostname).SetOs(req.OS).SetGroupID(t.GroupID).Save(ctx)
	case err != nil:
	case a.GroupID != nil && *a.GroupID != t.GroupID:
		return nil, Grant{}, ErrMoved
	case kind == KindAgent && a.AgentID != nil && time.Since(a.LastSeen) < s.OnlineWindow && a.SilentSince == nil:
		return nil, Grant{}, ErrOnline
	case kind == KindSensor && a.SensorSeen != nil && time.Since(*a.SensorSeen) < s.OnlineWindow:
		return nil, Grant{}, ErrSensor
	default:
		// 用令牌重新接入是管理员的明确动作：下线的主机就此恢复
		a, err = a.Update().SetGroupID(t.GroupID).ClearRetiredAt().ClearRetiredBy().ClearRetiredReason().Save(ctx)
	}
	if err != nil {
		return nil, Grant{}, err
	}
	if err := tx.EnrollToken.UpdateOne(t).AddUses(1).Exec(ctx); err != nil {
		return nil, Grant{}, err
	}
	if err := tx.Commit(); err != nil {
		return nil, Grant{}, err
	}

	grant := Grant{Server: s.GRPCURL}
	if cert != nil {
		grant.CA = string(s.Bundle)
		grant.Cert = string(cert)
	}
	return a, grant, nil
}

// sign 只认 CSR 里的公钥：主题按用途与主机名重新填，CSR 自带的 CN、SAN、扩展一概不采信。
func (s *Service) sign(csrPEM, cn string) ([]byte, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("CSR 不是 PEM 格式")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CSR 无法解析：%w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("CSR 签名无效")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(certValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.CA, csr.PublicKey, s.CAKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// loadCA 读信任包与签发私钥，返回信任包原文和其中与私钥配对的 CA。
func loadCA(certFile, keyFile string) ([]byte, *x509.Certificate, crypto.Signer, error) {
	bundle, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, nil, errors.New("CA 私钥不是 PEM 格式")
	}
	var key any
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, nil, errors.New("CA 私钥类型不支持签名")
	}
	for rest := bundle; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		ca, err := x509.ParseCertificate(b.Bytes)
		if err == nil && ca.IsCA && publicKeysEqual(ca.PublicKey, signer.Public()) {
			return bundle, ca, signer, nil
		}
	}
	return nil, nil, nil, errors.New("CA 私钥与信任包里的任何 CA 证书都不匹配")
}

func publicKeysEqual(a, b any) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

func hash(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}
