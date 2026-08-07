package grpcsvc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 生成本地自签 CA + 服务端证书链，返回 (ca, cert, key) 三个文件路径。
func writeTestCerts(t *testing.T, dir string) (caFile, certFile, keyFile string) {
	t.Helper()
	now := time.Now()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caParsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTpl, caParsed, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caFile = filepath.Join(dir, "ca.pem")
	writePEM(t, caFile, "CERTIFICATE", caDER)
	// 服务端证书要带 CA 链，tls.LoadX509KeyPair 才能验签发链
	certFile = filepath.Join(dir, "server.pem")
	writePEM(t, certFile, "CERTIFICATE", serverDER)
	if f, err := os.OpenFile(certFile, os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
		f.Close()
	}
	keyFile = filepath.Join(dir, "server.key")
	writePEM(t, keyFile, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))
	return
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

// 三个变量全空 → 明文，不启用 mTLS。
func TestServerOptionsPlaintext(t *testing.T) {
	t.Setenv("TLS_CA_FILE", "")
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")

	opts, mtls, err := ServerOptions()
	if err != nil || mtls || opts != nil {
		t.Fatalf("全空应明文：opts=%v mtls=%v err=%v", opts, mtls, err)
	}
}

// 只配一部分是配置错误，不能悄悄降级成明文。
func TestServerOptionsPartial(t *testing.T) {
	t.Setenv("TLS_CA_FILE", "/nope/ca.pem")
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	if _, _, err := ServerOptions(); err == nil {
		t.Fatal("部分配置应报错")
	}
}

// 证书文件路径不存在 → 报"加载服务端证书"错误。
func TestServerOptionsBadCertPath(t *testing.T) {
	t.Setenv("TLS_CA_FILE", "/none/ca.pem")
	t.Setenv("TLS_CERT_FILE", "/none/cert.pem")
	t.Setenv("TLS_KEY_FILE", "/none/key.pem")
	if _, _, err := ServerOptions(); err == nil {
		t.Fatal("证书路径不存在应报错")
	}
}

// cert/key 正常但 CA 文件不是有效证书 → 报错。
func TestServerOptionsBadCA(t *testing.T) {
	dir := t.TempDir()
	_, cert, key := writeTestCerts(t, dir)
	badCA := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badCA, []byte("this is not a cert"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("TLS_CA_FILE", badCA)
	t.Setenv("TLS_CERT_FILE", cert)
	t.Setenv("TLS_KEY_FILE", key)
	if _, _, err := ServerOptions(); err == nil {
		t.Fatal("CA 无有效证书应报错")
	}
}

// 三件套齐且合法 → 启用 mTLS 并返回 creds。
func TestServerOptionsMTLS(t *testing.T) {
	ca, cert, key := writeTestCerts(t, t.TempDir())
	t.Setenv("TLS_CA_FILE", ca)
	t.Setenv("TLS_CERT_FILE", cert)
	t.Setenv("TLS_KEY_FILE", key)

	opts, mtls, err := ServerOptions()
	if err != nil {
		t.Fatalf("合法配置不应报错：%v", err)
	}
	if !mtls {
		t.Fatal("应启用 mTLS")
	}
	if len(opts) != 1 {
		t.Fatalf("应返回一个 ServerOption，得到 %d", len(opts))
	}
}
