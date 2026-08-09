//go:build integration

package audit

import (
	"net/http"
	"testing"

	"openxdr/server/ent"
	entalog "openxdr/server/ent/auditlog"
	"openxdr/server/internal/testdb"
)

func TestLogAndSystemPersist(t *testing.T) {
	ctx, client := testdb.New(t)

	// Log：需要 *http.Request，actor 从上下文取；缺省记为 api
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:54321"
	Log(ctx, client, req, "view_incident", "inc-1", "")

	// WithActor 注入后走真实身份
	ctx = WithActor(ctx, "alice")
	req2, _ := http.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "[2001:db8::1]:443"
	Log(ctx, client, req2, "run_response", "", "已隔离")

	// System：无请求、无用户视角，user 固定 system，remote 固定 server
	System(ctx, client, "auto_response", "inc-2", "prod-db 已隔离")

	rows, err := client.AuditLog.Query().Order(ent.Asc(entalog.FieldTs)).All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("应落库 3 条审计，实际 %d", len(rows))
	}

	// 第一条：无 actor → api；空 detail 不落列
	r0 := rows[0]
	if r0.Username != "api" || r0.Action != "view_incident" || r0.Target == nil || *r0.Target != "inc-1" {
		t.Errorf("首条审计字段错误: %+v", r0)
	}
	if r0.Detail != nil {
		t.Errorf("空 detail 不应落列，实际 %q", *r0.Detail)
	}
	if r0.RemoteAddr != "203.0.113.9" {
		t.Errorf("remote_ip = %q, want 203.0.113.9", r0.RemoteAddr)
	}

	// 第二条：WithActor 注入 → alice；空 target 不落列
	r1 := rows[1]
	if r1.Username != "alice" || r1.Detail == nil || *r1.Detail != "已隔离" {
		t.Errorf("第二条审计字段错误: %+v", r1)
	}
	if r1.Target != nil {
		t.Errorf("空 target 不应落列，实际 %q", *r1.Target)
	}
	if r1.RemoteAddr != "2001:db8::1" {
		t.Errorf("remote_ip = %q, want 2001:db8::1", r1.RemoteAddr)
	}

	// 第三条：system 动作
	r2 := rows[2]
	if r2.Username != "system" || r2.RemoteAddr != "server" || r2.Action != "auto_response" {
		t.Errorf("system 审计字段错误: %+v", r2)
	}
}
