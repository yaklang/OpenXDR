package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"openxdr/server/pb"
	"testing"
	"time"
)

func validOptions() options {
	return options{agent: uuid.NewString(), run: uuid.NewString(), source: "10.0.0.1", target: "localhost:8081", ca: "ca.pem", cert: "cert.pem", key: "key.pem", rate: 5, duration: time.Second}
}
func TestLimits(t *testing.T) {
	base := validOptions()
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*options){func(o *options) { o.rate = 0 }, func(o *options) { o.rate = 1001 }, func(o *options) { o.duration = 61 * time.Second }, func(o *options) { o.duration = time.Millisecond }, func(o *options) { o.key = "" }, func(o *options) { o.run = "invalid" }, func(o *options) { o.agent = uuid.Nil.String() }, func(o *options) { o.source = "0.0.0.0" }} {
		o := base
		change(&o)
		if o.validate() == nil {
			t.Fatal("非法配置被放行")
		}
	}
}
func TestSyntheticMixIsMarkedAndUnique(t *testing.T) {
	o := validOptions()
	counts := map[uint32]int{}
	for i := 0; i < 100; i++ {
		at := time.Unix(100, int64(i))
		ev := synthetic(o, i, at)
		counts[ev.ClassUid]++
		if _, err := uuid.Parse(ev.ProcessGuid); err != nil {
			t.Fatal("进程 GUID 缺失")
		}
		if _, err := uuid.Parse(ev.ParentProcessGuid); err != nil {
			t.Fatal("父进程 GUID 缺失")
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(ev.RawJson), &body); err != nil {
			t.Fatal(err)
		}
		if ev.AgentId != o.agent || ev.TsUnixNs != at.UnixNano() || body["acceptance_test"] != true || body["acceptance_run"] != o.run || body["acceptance_sequence"] != float64(i) {
			t.Fatal("事件身份或标记错误")
		}
		if ev.ClassUid == 4001 && body["dst_endpoint"].(map[string]any)["ip"] != "203.0.113.77" {
			t.Fatal("网络元数据应使用 TEST-NET")
		}
	}
	if counts[1007] != 95 || counts[4001] != 3 || counts[4003] != 2 {
		t.Fatalf("分布错误: %v", counts)
	}
}

type fakeClient struct {
	pb.AgentServiceClient
	stream *fakeStream
	opens  int
}

func (c *fakeClient) ReportEvents(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.AgentEvent, pb.ReportAck], error) {
	c.opens++
	return c.stream, nil
}

type fakeStream struct {
	grpc.ClientStream
	events []*pb.AgentEvent
	failAt int
	ack    uint64
	closed int
}

func (s *fakeStream) Send(ev *pb.AgentEvent) error {
	if s.failAt > 0 && len(s.events) == s.failAt {
		return errors.New("发送失败")
	}
	s.events = append(s.events, ev)
	return nil
}
func (s *fakeStream) CloseAndRecv() (*pb.ReportAck, error) {
	s.closed++
	return &pb.ReportAck{Received: s.ack}, nil
}
func TestSendRequiresMatchingReceipt(t *testing.T) {
	for _, ack := range []uint64{5, 4} {
		o := validOptions()
		stream := &fakeStream{ack: ack}
		client := &fakeClient{stream: stream}
		r, err := send(context.Background(), client, o)
		if (err == nil) != (ack == 5) || r.Complete != (ack == 5) || r.Sent != 5 || r.Acknowledged == nil || *r.Acknowledged != ack || r.Seconds < 0.9 {
			t.Fatalf("确认与完成口径错误: %+v %v", r, err)
		}
		for i := 1; i < len(stream.events); i++ {
			if stream.events[i].TsUnixNs <= stream.events[i-1].TsUnixNs {
				t.Fatal("事件时间重复")
			}
		}
	}
}
func TestFailureDoesNotReconnectOrReplay(t *testing.T) {
	o := validOptions()
	o.rate = 100
	stream := &fakeStream{failAt: 2}
	client := &fakeClient{stream: stream}
	r, err := send(context.Background(), client, o)
	if err == nil || r.Complete || r.Sent != 2 || r.Acknowledged != nil || client.opens != 1 || stream.closed != 0 {
		t.Fatalf("错误后重连或报告假确认: %+v %v", r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stream = &fakeStream{}
	client = &fakeClient{stream: stream}
	r, err = send(ctx, client, o)
	if !errors.Is(err, context.Canceled) || r.Complete || r.Sent != 0 {
		t.Fatalf("取消未生效: %+v %v", r, err)
	}
}
