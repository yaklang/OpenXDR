package grpcsvc

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"openxdr/server/ent/asset"
)

// 身份绑定：权限是凭证自身的属性，同 SSH principal 的思路。
//
// CN 为 "host:<hostname>" 的客户端证书只能以该主机的身份行事——
// 注册、上报、认领指令流都会核对。通用证书（sensor、旧发证）不受限，
// 但只要给 agent 换上绑定证书，失陷主机就冒充不了别人。

// certHostname 取 mTLS 客户端证书绑定的主机名；未启用 TLS 或
// 证书不带 "host:" 前缀视为未绑定。
func certHostname(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", false
	}
	host, bound := strings.CutPrefix(tlsInfo.State.VerifiedChains[0][0].Subject.CommonName, "host:")
	if !bound {
		return "", false
	}
	return host, true
}

// verifyAgentID 校验声称的 agent_id 属于证书绑定的主机。未绑定则放行。
func (s *Server) verifyAgentID(ctx context.Context, claimed uuid.UUID) error {
	host, bound := certHostname(ctx)
	if !bound {
		return nil
	}
	a, err := s.DB.Asset.Query().Where(asset.HostnameEQ(host)).First(ctx)
	if err != nil || a.AgentID == nil || *a.AgentID != claimed {
		return status.Error(codes.PermissionDenied, "agent_id 与证书绑定的主机不符")
	}
	return nil
}
