//go:build integration

package grpcsvc

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"google.golang.org/grpc"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

const mimikatzRule = `
id: proc-mimikatz
title: Mimikatz
logsource:
  category: process_creation
detection:
  selection:
    commandline|contains: 'mimikatz'
  condition: selection
`

func loadMimikatzRule(t *testing.T) *sigma.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "m.yml"), []byte(mimikatzRule), 0o644); err != nil {
		t.Fatal(err)
	}
	return sigma.LoadDir(dir)
}

// fakeAgentStream 预置一批事件，依次 Recv 后 EOF，并捕获 SendAndClose 的 ack。
type fakeAgentStream struct {
	grpc.ServerStream
	ctx    context.Context
	events []*pb.AgentEvent
	ack    *pb.ReportAck
}

func (f *fakeAgentStream) Context() context.Context { return f.ctx }
func (f *fakeAgentStream) Recv() (*pb.AgentEvent, error) {
	if len(f.events) == 0 {
		return nil, io.EOF
	}
	e := f.events[0]
	f.events = f.events[1:]
	return e, nil
}
func (f *fakeAgentStream) SendAndClose(a *pb.ReportAck) error {
	f.ack = a
	return nil
}

// agent.ReportEvents 端到端：两条事件（agent 归属、规则命中）→ 流结束 flush 落库 → ack。
func TestAgentReportEvents(t *testing.T) {
	ctx, client := testdb.New(t)

	agentGUID := uuid.New()
	_, err := client.Asset.Create().
		SetHostname("work-1").SetOs("windows").SetAgentID(agentGUID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	pg := uuid.New()
	enroll := &pb.AgentEvent{
		AgentId:     agentGUID.String(),
		ClassUid:    1007,
		TsUnixNs:    time.Now().UnixNano(),
		ProcessGuid: pg.String(),
		Username:    "user",
		RawJson:     `{"process":{"cmd_line":"run mimikatz sekurlsa"}}`,
	}
	// 第二条：同 agent 无关紧要的进程（不命中规则）
	boring := &pb.AgentEvent{
		AgentId:     agentGUID.String(),
		ClassUid:    1007,
		TsUnixNs:    time.Now().UnixNano(),
		ProcessGuid: uuid.New().String(),
		RawJson:     `{"process":{"cmd_line":"explorer.exe"}}`,
	}

	stream := &fakeAgentStream{ctx: ctx, events: []*pb.AgentEvent{enroll, boring}}
	s := &Server{DB: client, Rules: loadMimikatzRule(t), DedupWindow: time.Hour, Suppress: suppress.New(client, time.Hour), Intel: intel.New(client, time.Hour)}
	if err := s.ReportEvents(stream); err != nil {
		t.Fatalf("ReportEvents 失败: %v", err)
	}
	if stream.ack == nil || stream.ack.Received != 2 {
		t.Errorf("ack 应为 2 条，得到 %+v", stream.ack)
	}

	evts, err := client.Event.Query().Count(ctx)
	if err != nil || evts != 2 {
		t.Errorf("应落库 2 条事件，实际 %d (err=%v)", evts, err)
	}

	// 只有 mimikatz 命中 → 1 条告警，归属 work-1 资产
	alerts, err := client.Alert.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].RuleID != "proc-mimikatz" {
		t.Fatalf("应命中 1 条 mimikatz 告警，实际 %+v", alerts)
	}
	if alerts[0].AssetID == nil {
		t.Error("告警应按 agent 归属资产")
	}
}

// 流异常中断也应返回错误（这里是空流触发 EOF 前的错误路径验证）。
func TestAgentReportEventsEOF(t *testing.T) {
	ctx, client := testdb.New(t)
	empty := &fakeAgentStream{ctx: ctx} // 无事件，立即 EOF
	s := &Server{DB: client, Rules: loadMimikatzRule(t), DedupWindow: time.Hour, Suppress: suppress.New(client, time.Hour), Intel: intel.New(client, time.Hour)}
	if err := s.ReportEvents(empty); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("空流应正常收尾，得到 %v", err)
	}
	if empty.ack == nil {
		t.Error("空流也应回 ack")
	}
}
