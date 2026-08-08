// gencerts 生成 OpenXDR 自签证书：一个 CA，一张服务端证书，一张采集端通用证书，
// 以及可选的按主机绑定的 agent 证书。只用标准库，不依赖 openssl 命令。
//
// 用法: go run ./cmd/gencerts <输出目录> [server 的域名或 IP] [agent 主机名...]
//
// 按主机发证时 CN 写成 "host:<hostname>"，server 会强制该证书只能以
// 对应主机的身份注册、上报和认领指令流；通用证书不受限（sensor 用它）。
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const validFor = 10 * 365 * 24 * time.Hour

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法: gencerts <输出目录> [server 的域名或 IP]")
		os.Exit(2)
	}
	dir := os.Args[1]
	host := "localhost"
	if len(os.Args) > 2 {
		host = os.Args[2]
	}
	if err := run(dir, host, os.Args[3:]); err != nil {
		fmt.Fprintln(os.Stderr, "生成失败:", err)
		os.Exit(1)
	}
}

func run(dir, host string, agentHosts []string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	notBefore := time.Now().Add(-time.Hour) // 容忍机器间的时钟偏差
	notAfter := notBefore.Add(validFor)

	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "OpenXDR Root CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	if err := writePair(dir, "ca", caDER, caKey); err != nil {
		return err
	}

	// 服务端证书：SAN 必须包含采集端实际连接的地址，否则握手会被拒
	serverTmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if ip := net.ParseIP(host); ip != nil {
		serverTmpl.IPAddresses = append(serverTmpl.IPAddresses, ip)
	} else {
		serverTmpl.DNSNames = append(serverTmpl.DNSNames, host)
	}
	if err := issue(dir, "server", serverTmpl, ca, caKey); err != nil {
		return err
	}

	// 采集端证书：agent 和 sensor 共用，需要按主机区分身份时各签一张
	clientTmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "openxdr-collector"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := issue(dir, "client", clientTmpl, ca, caKey); err != nil {
		return err
	}

	// 按主机绑定的 agent 证书：server 强制它只能以该主机身份行事
	for _, agentHost := range agentHosts {
		tmpl := &x509.Certificate{
			SerialNumber: serial(),
			Subject:      pkix.Name{CommonName: "host:" + agentHost},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if err := issue(dir, "agent-"+agentHost, tmpl, ca, caKey); err != nil {
			return err
		}
	}

	fmt.Printf("证书已生成于 %s:\n", dir)
	fmt.Println("  server: TLS_CA_FILE=ca.crt TLS_CERT_FILE=server.crt TLS_KEY_FILE=server.key")
	fmt.Println("  采集端: OPENXDR_CA=ca.crt OPENXDR_CERT=client.crt OPENXDR_KEY=client.key")
	for _, agentHost := range agentHosts {
		fmt.Printf("  %s: OPENXDR_CERT=agent-%s.crt OPENXDR_KEY=agent-%s.key（身份已绑定，只能以该主机注册上报）\n",
			agentHost, agentHost, agentHost)
	}
	return nil
}

func issue(dir, name string, tmpl, ca *x509.Certificate, caKey *rsa.PrivateKey) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	return writePair(dir, name, der, key)
}

func writePair(dir, name string, der []byte, key *rsa.PrivateKey) error {
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, name+".crt"), crt, 0o644); err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustPKCS8(key),
	})
	// 私钥只给属主读
	return os.WriteFile(filepath.Join(dir, name+".key"), keyPEM, 0o600)
}

func mustPKCS8(key *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err) // RSA 私钥必然可编码
	}
	return der
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n
}
