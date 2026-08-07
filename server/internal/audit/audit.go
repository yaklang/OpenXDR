// Package audit 操作审计。谁、何时、从哪里、做了什么——
// 写入失败只记日志不阻断业务：审计是留痕，不是闸门。
package audit

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"openxdr/server/ent"
)

type actorKey struct{}

// WithActor 把操作者身份放进请求上下文，由认证中间件调用。
func WithActor(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, actorKey{}, username)
}

// Actor 取当前操作者；未认证的内部调用（如集成测试）记为 "api"。
func Actor(ctx context.Context) string {
	if v, ok := ctx.Value(actorKey{}).(string); ok {
		return v
	}
	return "api"
}

// Log 记一条审计。target/detail 可为空串，空串不落列。
func Log(ctx context.Context, db *ent.Client, r *http.Request, action, target, detail string) {
	create := db.AuditLog.Create().
		SetUsername(Actor(ctx)).
		SetAction(action).
		SetRemoteAddr(remoteAddr(r))
	if target != "" {
		create.SetTarget(target)
	}
	if detail != "" {
		create.SetDetail(detail)
	}
	if err := create.Exec(ctx); err != nil {
		slog.Error("审计写入失败", "action", action, "err", err)
	}
}

func remoteAddr(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
