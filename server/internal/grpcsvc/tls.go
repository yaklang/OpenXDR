package grpcsvc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ServerOptions 按环境变量决定 gRPC 是否启用 mTLS。
// 三个证书文件都配齐才启用；一个都没配则明文（仅适合本机调试）；
// 配了一半属于配置错误，直接报错而不是悄悄降级成明文。
func ServerOptions() ([]grpc.ServerOption, bool, error) {
	caFile := os.Getenv("TLS_CA_FILE")
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")

	switch {
	case caFile == "" && certFile == "" && keyFile == "":
		return nil, false, nil
	case caFile == "" || certFile == "" || keyFile == "":
		return nil, false, fmt.Errorf("TLS_CA_FILE / TLS_CERT_FILE / TLS_KEY_FILE 必须同时配置")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, false, fmt.Errorf("加载服务端证书: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, false, fmt.Errorf("读取 CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, false, fmt.Errorf("CA 文件中没有可用证书: %s", caFile)
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	})
	return []grpc.ServerOption{grpc.Creds(creds)}, true, nil
}
