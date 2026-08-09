package response

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/pb"
)

// fakeRouter 内存版 Router：记录 attach 的 agent，配合 Hub 的通道状态机测试。
type fakeRouter struct {
	online map[uuid.UUID]bool
	sent   map[uuid.UUID][]*pb.Command
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{online: map[uuid.UUID]bool{}, sent: map[uuid.UUID][]*pb.Command{}}
}

func (f *fakeRouter) Attach(id uuid.UUID, _ func(*pb.Command) error) func() {
	f.online[id] = true
	return func() { delete(f.online, id) }
}
func (f *fakeRouter) Deliver(_ context.Context, id uuid.UUID, c *pb.Command) error {
	f.sent[id] = append(f.sent[id], c)
	return nil
}
func (f *fakeRouter) Online(_ context.Context, id uuid.UUID) bool { return f.online[id] }
func (f *fakeRouter) Close()                                      {}

func TestKindToProto(t *testing.T) {
	cases := []struct {
		kind string
		want pb.CommandKind
	}{
		{"kill_process", pb.CommandKind_KILL_PROCESS},
		{"isolate_host", pb.CommandKind_ISOLATE_HOST},
		{"unisolate_host", pb.CommandKind_UNISOLATE_HOST},
		{"未知动作", pb.CommandKind_COMMAND_KIND_UNSPECIFIED}, // 未注册 → zero value
	}
	for _, tc := range cases {
		if got := kindToProto(tc.kind); got != tc.want {
			t.Errorf("kindToProto(%q) = %v, want %v", tc.kind, got, tc.want)
		}
	}
}

func TestKinds(t *testing.T) {
	if len(Kinds) != 3 {
		t.Fatalf("Kinds 应恰好含三种动作，got %d", len(Kinds))
	}
	for _, kind := range []string{"kill_process", "isolate_host", "unisolate_host"} {
		if _, ok := Kinds[kind]; !ok {
			t.Errorf("Kinds 缺 %q", kind)
		}
	}
}

func TestRequestToProto(t *testing.T) {
	id := uuid.New()
	asset := uuid.New()
	incident := uuid.New()
	proc := uuid.New()

	cases := []struct {
		name string
		req  Request
		want func() bool
	}{
		{
			name: "带进程 GUID 与放行地址",
			req: Request{
				AssetID:        asset,
				Kind:           "isolate_host",
				DryRun:         true,
				IncidentID:     &incident,
				ProcessGUID:    &proc,
				PID:            1234,
				IssuedBy:       "admin",
				AllowEndpoints: []string{"1.2.3.4"},
			},
			want: func() bool {
				cmd := (&Request{
					AssetID: asset, Kind: "isolate_host", DryRun: true,
					IncidentID: &incident, ProcessGUID: &proc,
					PID: 1234, IssuedBy: "admin", AllowEndpoints: []string{"1.2.3.4"},
				}).toProto(id)
				return cmd.Id == id.String() &&
					cmd.Kind == pb.CommandKind_ISOLATE_HOST &&
					cmd.DryRun &&
					cmd.ProcessGuid == proc.String() &&
					cmd.Pid == 1234 &&
					len(cmd.AllowEndpoints) == 1 && cmd.AllowEndpoints[0] == "1.2.3.4"
			},
		},
		{
			name: "无进程 GUID 留空",
			req:  Request{AssetID: asset, Kind: "kill_process", DryRun: false},
			want: func() bool {
				cmd := (&Request{AssetID: asset, Kind: "kill_process"}).toProto(id)
				return cmd.ProcessGuid == "" && cmd.DryRun == false
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.want() {
				t.Error("toProto 字段映射不符合预期")
			}
		})
	}
}

func TestResultStatus(t *testing.T) {
	cases := []struct {
		st   pb.CommandResult_Status
		want string
	}{
		{pb.CommandResult_SUCCEEDED, "succeeded"},
		{pb.CommandResult_FAILED, "failed"},
		{pb.CommandResult_UNSUPPORTED, "unsupported"},
		{pb.CommandResult_Status(999), "failed"}, // 未知状态兜底
	}
	for _, tc := range cases {
		if got := resultStatus(tc.st); got != tc.want {
			t.Errorf("resultStatus(%v) = %q, want %q", tc.st, got, tc.want)
		}
	}
}

func TestToProto(t *testing.T) {
	id := uuid.New()
	proc := uuid.New()
	testToProto := (&Hub{}).ToProto

	// 无进程 GUID
	cmd := testToProto(&ent.Command{ID: id, Kind: "kill_process"})
	if cmd.Id != id.String() || cmd.Kind != pb.CommandKind_KILL_PROCESS || cmd.ProcessGuid != "" {
		t.Errorf("无 GUID 映射错误: %+v", cmd)
	}

	// 有进程 GUID
	cmd = testToProto(&ent.Command{ID: id, Kind: "isolate_host", DryRun: true, ProcessGUID: &proc})
	if cmd.ProcessGuid != proc.String() || cmd.Kind != pb.CommandKind_ISOLATE_HOST || cmd.DryRun != true {
		t.Errorf("有 GUID 映射错误: %+v", cmd)
	}
}

// Attach/Detach 是内存通道状态机：认领后 Online 为真、重连挤掉旧连接、摘除后不再在线。
func TestHubAttachDetach(t *testing.T) {
	id := uuid.New()
	fr := newFakeRouter()
	h := &Hub{Router: fr, conns: map[uuid.UUID]chan *pb.Command{}, routeDetach: map[uuid.UUID]func(){}}

	if h.Online(id) {
		t.Fatal("未 Attach 前不应在线")
	}

	ch1 := h.Attach(id)
	if !h.Online(id) {
		t.Fatal("Attach 后应在线")
	}
	if !fr.online[id] {
		t.Fatal("Router 也应被 attach")
	}

	// 同 agent 重连：旧通道被关闭，新通道接管
	ch2 := h.Attach(id)
	select {
	case <-ch1:
	default:
		t.Error("旧通道应被关闭")
	}

	// 新通道可接收
	ch2 <- &pb.Command{Id: id.String()}
	if got := <-ch2; got.Id != id.String() {
		t.Errorf("新通道内容 = %v", got)
	}

	// Detach 摘除当前通道后不再在线
	h.Detach(id, ch2)
	if h.Online(id) {
		t.Error("Detach 后不应在线")
	}
	if fr.online[id] {
		t.Error("Router detach 应被调用")
	}

	// 摘除旧通道（非当前）不应影响状态
	h.Attach(id)
	h.Detach(id, ch1) // ch1 早被关闭，是"旧"连接
	if !h.Online(id) {
		t.Error("摘除旧连接不应影响当前在线状态")
	}
	h.Detach(id, h.conns[id])
}

// Online 在无 Router 时只查本地通道；有 Router 时才问远端。
func TestHubOnlineLocalOnly(t *testing.T) {
	id := uuid.New()
	h := &Hub{conns: map[uuid.UUID]chan *pb.Command{}}
	if h.Online(id) {
		t.Error("无连接应不在线")
	}
	h.Attach(id)
	if !h.Online(id) {
		t.Error("本地通道存在应在线")
	}
}
