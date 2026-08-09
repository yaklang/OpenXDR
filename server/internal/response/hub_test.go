package response

import (
	"testing"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/pb"
)

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
