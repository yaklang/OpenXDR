//go:build integration

package grpcsvc

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

// 使用真实数据库处理器，避免仅验证重传 payload 相同却没有覆盖告警副作用。
type replayBus struct{ processor *ingest.Processor }

func (b replayBus) Publish(ctx context.Context, e ingest.Envelope) error {
	return b.processor.Process(ctx, e)
}
func (replayBus) Ready() bool  { return true }
func (replayBus) Close() error { return nil }

type lostAckStream struct{ *fakeAgentStream }

func (s lostAckStream) SendAndClose(*pb.ReportAck) error {
	return errors.New("模拟接收完成后 ACK 丢失")
}

func TestDurableAgentReplayAfterLostAck(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := ingest.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	agentID := uuid.New()
	_, err = client.Asset.Create().SetHostname("durable-replay").SetOs("windows").SetAgentID(agentID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	processor := &ingest.Processor{DB: db, Rules: loadMimikatzRule(t), Suppress: suppress.New(client, 0), Intel: intel.New(client, 0), DedupWindow: time.Hour}
	srv := &Server{DB: client, Events: replayBus{processor}}
	event := &pb.AgentEvent{AgentId: agentID.String(), ClassUid: 1007, TsUnixNs: time.Now().UnixNano(), ProcessGuid: uuid.NewString(), RawJson: `{"process":{"cmd_line":"mimikatz"}}`}
	failed := lostAckStream{&fakeAgentStream{ctx: ctx, events: []*pb.AgentEvent{event}}}
	if err := srv.ReportEvents(failed); err == nil {
		t.Fatal("应返回 ACK 丢失")
	}
	// 新建 gateway 实例与流，模拟重连到另一节点；收到完整 ACK 但不重复事件或告警计数。
	srv = &Server{DB: client, Events: replayBus{processor}}
	retry := &fakeAgentStream{ctx: ctx, events: []*pb.AgentEvent{event}}
	if err := srv.ReportEvents(retry); err != nil {
		t.Fatal(err)
	}
	if retry.ack == nil || retry.ack.Received != 1 {
		t.Fatal("未确认整批")
	}
	if count, err := client.Event.Query().Count(ctx); err != nil || count != 1 {
		t.Fatalf("重投产生重复事件: %d %v", count, err)
	}
	alerts, err := client.Alert.Query().All(ctx)
	if err != nil || len(alerts) != 1 || alerts[0].Count != 1 {
		t.Fatalf("重投产生重复告警或计数: %+v %v", alerts, err)
	}
}

type batchReplayBus struct {
	replayBus
	sizes []int
	fail  bool
}

func (*batchReplayBus) BatchSize() int { return 64 }
func (b *batchReplayBus) PublishBatch(ctx context.Context, events []ingest.Envelope) error {
	if b.fail {
		return errors.New("模拟持久队列不可用")
	}
	b.sizes = append(b.sizes, len(events))
	return b.processor.ProcessBatch(ctx, events)
}

func TestAgentBatchFlushAndLostAck(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := ingest.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	agentID := uuid.New()
	client.Asset.Create().SetHostname("batch-replay").SetOs("windows").SetAgentID(agentID).SaveX(ctx)
	p := &ingest.Processor{DB: db, Rules: loadMimikatzRule(t), Suppress: suppress.New(client, 0), Intel: intel.New(client, 0), DedupWindow: time.Hour}
	bus := &batchReplayBus{replayBus: replayBus{p}}
	srv := &Server{DB: client, Events: bus}
	var events []*pb.AgentEvent
	for i := 0; i < 65; i++ {
		events = append(events, &pb.AgentEvent{AgentId: agentID.String(), ClassUid: 1007, TsUnixNs: time.Now().UnixNano(), ProcessGuid: uuid.NewString(), RawJson: `{"process":{"cmd_line":"mimikatz"}}`})
	}
	failed := lostAckStream{&fakeAgentStream{ctx: ctx, events: events}}
	if err := srv.ReportEvents(failed); err == nil {
		t.Fatal("ACK 丢失必须返回错误")
	}
	if len(bus.sizes) != 2 || bus.sizes[0] != 64 || bus.sizes[1] != 1 {
		t.Fatalf("未在满批和 EOF 刷入: %v", bus.sizes)
	}
	retry := &fakeAgentStream{ctx: ctx, events: events}
	if err := srv.ReportEvents(retry); err != nil {
		t.Fatal(err)
	}
	if retry.ack == nil || retry.ack.Received != 65 {
		t.Fatalf("整批确认错误: %v", retry.ack)
	}
	if n, err := client.Event.Query().Count(ctx); err != nil || n != 65 {
		t.Fatalf("重投事件数错误: %d %v", n, err)
	}
	alerts, err := client.Alert.Query().All(ctx)
	if err != nil || len(alerts) != 1 || alerts[0].Count != 65 {
		t.Fatalf("重投告警计数错误: %v %v", alerts, err)
	}
	bus.fail = true
	rejected := &fakeAgentStream{ctx: ctx, events: events[:1]}
	if err := srv.ReportEvents(rejected); err == nil || rejected.ack != nil {
		t.Fatalf("未持久化却返回成功: %v %v", err, rejected.ack)
	}
}
