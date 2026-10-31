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
	online  map[uuid.UUID]bool
	deliver map[uuid.UUID]func(*pb.Command) error
	sent    map[uuid.UUID][]*pb.Command
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{
		online:  map[uuid.UUID]bool{},
		deliver: map[uuid.UUID]func(*pb.Command) error{},
		sent:    map[uuid.UUID][]*pb.Command{},
	}
}

func (f *fakeRouter) Attach(id uuid.UUID, fn func(*pb.Command) error) func() {
	f.online[id] = true
	f.deliver[id] = fn
	return func() {
		delete(f.online, id)
		delete(f.deliver, id)
	}
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
		{"exec", pb.CommandKind_EXEC},
		{"未知动作", pb.CommandKind_COMMAND_KIND_UNSPECIFIED}, // 未注册 → zero value
	}
	for _, tc := range cases {
		if got := kindToProto(tc.kind); got != tc.want {
			t.Errorf("kindToProto(%q) = %v, want %v", tc.kind, got, tc.want)
		}
	}
}

func TestKinds(t *testing.T) {
	if len(Kinds) != 10 {
		t.Fatalf("Kinds 应恰好含十种动作，got %d", len(Kinds))
	}
	for kind := range TargetKinds {
		if _, ok := Kinds[kind]; !ok {
			t.Errorf("需要目标的动作 %q 没有登记", kind)
		}
	}
	for _, kind := range []string{"kill_process", "isolate_host", "unisolate_host", "exec", "block_network", "unblock_network", "quarantine_file", "restore_file", "disable_account", "enable_account"} {
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
				IncidentID:     &incident,
				ProcessGUID:    &proc,
				PID:            1234,
				IssuedBy:       "admin",
				AllowEndpoints: []string{"1.2.3.4"},
			},
			want: func() bool {
				cmd := (&Request{
					AssetID: asset, Kind: "isolate_host",
					IncidentID: &incident, ProcessGUID: &proc,
					PID: 1234, IssuedBy: "admin", AllowEndpoints: []string{"1.2.3.4"},
				}).toProto(id)
				return cmd.Id == id.String() &&
					cmd.Kind == pb.CommandKind_ISOLATE_HOST &&
					cmd.ProcessGuid == proc.String() &&
					cmd.Pid == 1234 &&
					len(cmd.AllowEndpoints) == 1 && cmd.AllowEndpoints[0] == "1.2.3.4"
			},
		},
		{
			name: "无进程 GUID 留空",
			req:  Request{AssetID: asset, Kind: "kill_process"},
			want: func() bool {
				cmd := (&Request{AssetID: asset, Kind: "kill_process"}).toProto(id)
				return cmd.ProcessGuid == ""
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
		{pb.CommandResult_STATUS_UNSPECIFIED, "unknown"},
		{pb.CommandResult_Status(999), "unknown"}, // 未知状态兜底
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
	cmd = testToProto(&ent.Command{ID: id, Kind: "isolate_host", ProcessGUID: &proc})
	if cmd.ProcessGuid != proc.String() || cmd.Kind != pb.CommandKind_ISOLATE_HOST {
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
	ch3 := h.Attach(id)
	h.Detach(id, ch1) // ch1 早被关闭，是"旧"连接
	if !h.Online(id) {
		t.Error("摘除旧连接不应影响当前在线状态")
	}

	// 另一集群节点重连同一 agent 时，Router 通过 deliver(nil) 通知挤掉本节点的半开旧通道
	if err := fr.deliver[id](nil); err != nil {
		t.Fatalf("跨节点挤掉旧通道不应报错: %v", err)
	}
	select {
	case _, ok := <-ch3:
		if ok {
			t.Fatal("被跨节点挤掉的通道应已关闭")
		}
	default:
		t.Fatal("被跨节点挤掉的通道应立即关闭")
	}
	if h.Online(id) {
		t.Error("被跨节点挤掉后本地与路由旧订阅都应已摘除")
	}
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

func TestEnqueueDuringReconnect(t *testing.T) {
	h := NewHub(nil, true)
	id := uuid.New()
	old := h.Attach(id)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			h.Attach(id)
		}
	}()
	for range 1000 {
		_, _ = h.enqueue(id, nil, &pb.Command{})
	}
	<-done
	if online, err := h.enqueue(id, old, &pb.Command{}); online || err == nil {
		t.Fatal("旧 Router 回调应被拒绝")
	}
}

func TestStorable(t *testing.T) {
	if got := storable("bash\x00-c\x00ls\xff"); got != "bash␀-c␀ls�" {
		t.Fatalf("%q", got)
	}
}

// exec 的唯一入口是 commandgate；Hub 的普通下发必须拒绝，不能靠调用方自觉。
func TestIssueRejectsExec(t *testing.T) {
	h := NewHub(nil, true)
	cmd := "id"
	if _, err := h.Issue(context.Background(), Request{Kind: "exec", Cmd: &cmd}); err == nil {
		t.Fatal("Issue 不应接受 exec")
	}
	if _, err := h.IssueExec(context.Background(), Request{Kind: "kill_process"}); err == nil {
		t.Fatal("IssueExec 只应接受 exec")
	}
}
