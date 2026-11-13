package grpcsvc

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/sshkeys"
	"openxdr/server/pb"
)

// ReportSSHKeys 接收 Linux agent 上报的 SSH 授权钥匙盘点快照（不含公钥原文）。
func (s *Server) ReportSSHKeys(ctx context.Context, req *pb.ReportSSHKeysRequest) (*pb.ReportSSHKeysResponse, error) {
	id, err := uuid.Parse(req.GetAgentId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "agent_id 无效")
	}
	if err := s.verifyAgentID(ctx, id); err != nil {
		return nil, err
	}
	a, err := s.DB.Asset.Query().Where(asset.AgentIDEQ(id)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, status.Error(codes.NotFound, "agent 尚未注册")
	}
	if err != nil {
		if ctxErr := rpcContextError(ctx, err); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, status.Error(codes.Internal, "资产查询失败")
	}
	if err := s.DB.Asset.UpdateOneID(a.ID).SetLastSeen(time.Now()).Exec(ctx); err != nil {
		if ctxErr := rpcContextError(ctx, err); ctxErr != nil {
			return nil, ctxErr
		}
	}

	svc := s.SSHKeys
	if svc == nil {
		var sqlDB *sql.DB
		if raw, ok := s.SQL.(*sql.DB); ok {
			sqlDB = raw
		}
		svc = &sshkeys.Service{
			DB:       s.DB,
			SQL:      sqlDB,
			Gate:     &commandgate.Gate{DB: s.DB, Hub: s.Hub},
			Suppress: s.Suppress,
		}
	}
	if err := svc.IngestAssetSnapshot(ctx, a, req); err != nil {
		if ctxErr := rpcContextError(ctx, err); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, status.Errorf(codes.Internal, "钥匙盘点保存失败: %v", err)
	}
	return &pb.ReportSSHKeysResponse{}, nil
}

func rpcContextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return status.FromContextError(ctxErr).Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	return nil
}
