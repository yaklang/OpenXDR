package grpcsvc

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"openxdr/server/ent/asset"
	"openxdr/server/pb"
)

// 身份绑定：权限是凭证自身的属性，同 SSH principal 的思路。
//
// CN 为 "host:<hostname>" 的客户端证书只能以该主机 agent 的身份行事——
// 注册、上报、认领指令流都会核对；"sensor:<hostname>" 是该主机上流量探针的身份，
// 只能以这个主机名注册、上报抓包状态与会话。两种证书互不通用：探针证书进不了 agent 通道，
// agent 证书进不了探针通道，失陷的网关拿探针证书下发不了指令、也冒充不了 agent。
// 通用证书（gencerts 的 openxdr-collector、旧发证）不受限，按主机签发后即可消除。

const (
	kindHost   = "host"
	kindSensor = "sensor"
)

// certIdentity 取 mTLS 客户端证书的绑定用途与主机名；未启用 TLS 或通用证书返回空。
func certIdentity(ctx context.Context) (kind, host string) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", ""
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", ""
	}
	cn := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
	for _, k := range []string{kindHost, kindSensor} {
		if h, ok := strings.CutPrefix(cn, k+":"); ok {
			return k, h
		}
	}
	return "", ""
}

// certHostname 证书绑定的 agent 主机名；探针证书、通用证书与明文连接视为未绑定。
func certHostname(ctx context.Context) (string, bool) {
	kind, host := certIdentity(ctx)
	return host, kind == kindHost
}

// sensorHostname 证书绑定的探针主机名。
func sensorHostname(ctx context.Context) (string, bool) {
	kind, host := certIdentity(ctx)
	return host, kind == kindSensor
}

// checkService 证书用途与所调服务对得上：绑定证书只能进自己那条通道。
func checkService(ctx context.Context, fullMethod string) error {
	kind, _ := certIdentity(ctx)
	switch {
	case kind == kindSensor && strings.HasPrefix(fullMethod, "/"+pb.AgentService_ServiceDesc.ServiceName+"/"):
		return status.Error(codes.PermissionDenied, "流量探针证书不能访问 agent 通道")
	case kind == kindHost && strings.HasPrefix(fullMethod, "/"+pb.SensorService_ServiceDesc.ServiceName+"/"):
		return status.Error(codes.PermissionDenied, "agent 证书不能访问流量探针通道")
	}
	return nil
}

// Interceptors 在所有 RPC 之前核对证书用途，放在 handler 之外，新加的 RPC 不会漏检；
// 同时开启 HTTP/2 PING 保活，穿过四层负载均衡空闲超时并及时收回失联对端的半开指令通道。
func Interceptors() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    60 * time.Second,
			Timeout: 20 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             15 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if err := checkService(ctx, info.FullMethod); err != nil {
				return nil, err
			}
			return handler(ctx, req)
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			if err := checkService(ss.Context(), info.FullMethod); err != nil {
				return err
			}
			return handler(srv, ss)
		}),
	}
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
