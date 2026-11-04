//go:build integration

package commandgate

import (
	"context"
	"testing"
	"time"
)

func TestSessionRevokedWhileCommandReviewIsPending(t *testing.T) {
	f := setup(t)
	session := f.db.AgentSession.Create().SetKind("chat").SetGroupID(f.req.GroupID).SetInitiator("analyst").SetModel("m").SetRunExpiresAt(time.Now().Add(time.Hour)).SaveX(f.ctx)
	f.req.SessionID = &session.ID
	f.gate.Reviewer = func(context.Context, Request) (bool, string, error) {
		f.db.AgentSession.UpdateOneID(session.ID).SetStatus("failed").ExecX(f.ctx)
		return true, "审核通过但执行者已被回收", nil
	}
	if _, err := f.gate.Issue(f.ctx, f.req); err == nil {
		t.Fatal("审核等待后没有重新核对会话有效性")
	}
	assertNoCommand(t, f)
	if f.db.Command.Query().CountX(f.ctx) != 0 {
		t.Fatal("旧执行者仍创建了处置指令")
	}
}
