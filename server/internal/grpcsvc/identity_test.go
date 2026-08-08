package grpcsvc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// 构造带指定 CN 客户端证书的 peer 上下文，免去真实 TLS 握手。
func ctxWithCN(cn string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{
					{Subject: pkix.Name{CommonName: cn}},
				}},
			},
		},
	})
}

func TestCertHostname(t *testing.T) {
	cases := []struct {
		name  string
		ctx   context.Context
		host  string
		bound bool
	}{
		{"绑定证书", ctxWithCN("host:web01"), "web01", true},
		{"通用证书不受限", ctxWithCN("openxdr-collector"), "", false},
		{"明文连接不受限", context.Background(), "", false},
	}
	for _, c := range cases {
		host, bound := certHostname(c.ctx)
		if host != c.host || bound != c.bound {
			t.Errorf("%s: want (%q,%v) got (%q,%v)", c.name, c.host, c.bound, host, bound)
		}
	}
}
