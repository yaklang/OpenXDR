//go:build integration

package grpcsvc

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

// 绑定证书的身份强制：注册冒名被拒，上报假 agent_id 断流。
func TestIdentityEnforcement(t *testing.T) {
	ctx, client := testdb.New(t)
	srv := &Server{
		DB: client, Rules: loadMimikatzRule(t),
		DedupWindow: time.Minute, Suppress: suppress.New(client, 0), Intel: intel.New(client, 0),
	}

	// 用 web01 的绑定证书注册 web01：放行，拿到 agent_id
	resp, err := srv.Register(ctxWithCN("host:web01"), &pb.RegisterRequest{Hostname: "web01"})
	if err != nil {
		t.Fatalf("本机注册应放行: %v", err)
	}
	webID := resp.AgentId

	// 用 web01 的证书注册 db01：拒绝
	if _, err := srv.Register(ctxWithCN("host:web01"), &pb.RegisterRequest{Hostname: "db01"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("冒名注册应 PermissionDenied，got %v", err)
	}

	// 通用证书注册任意主机：不受限（sensor / 旧发证的兼容路径）
	if _, err := srv.Register(ctxWithCN("openxdr-collector"), &pb.RegisterRequest{Hostname: "db01"}); err != nil {
		t.Fatalf("通用证书注册应放行: %v", err)
	}

	event := func(agentID string) *pb.AgentEvent {
		return &pb.AgentEvent{
			AgentId: agentID, TsUnixNs: time.Now().UnixNano(), ClassUid: 1007,
			ProcessGuid: uuid.NewString(), RawJson: `{"process":{"cmd_line":"ls"}}`,
		}
	}

	// 正确身份上报：接受
	ok := &fakeAgentStream{ctx: ctxWithCN("host:web01"), events: []*pb.AgentEvent{event(webID)}}
	if err := srv.ReportEvents(ok); err != nil {
		t.Fatalf("本机上报应放行: %v", err)
	}
	if ok.ack == nil || ok.ack.Received != 1 {
		t.Fatalf("应回执 1 条，got %+v", ok.ack)
	}

	// 持 web01 证书冒用 db01 的 agent_id：断流
	dbResp, err := srv.Register(ctxWithCN("openxdr-collector"), &pb.RegisterRequest{Hostname: "db01"})
	if err != nil {
		t.Fatal(err)
	}
	forged := &fakeAgentStream{ctx: ctxWithCN("host:web01"), events: []*pb.AgentEvent{event(dbResp.AgentId)}}
	if err := srv.ReportEvents(forged); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("冒用他机 agent_id 应 PermissionDenied，got %v", err)
	}

	_ = ctx
}

// 采集配置随 Register 下发：设过配置的资产，agent 注册时应拿到它。
func TestRegisterReturnsConfig(t *testing.T) {
	ctx, client := testdb.New(t)
	srv := &Server{
		DB: client, Rules: sigma.LoadDir(t.TempDir()),
		DedupWindow: time.Minute, Suppress: suppress.New(client, 0), Intel: intel.New(client, 0),
	}

	// 首次注册：还没配置，下发空串（agent 用内置默认）
	resp, err := srv.Register(ctx, &pb.RegisterRequest{Hostname: "web01", Os: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ConfigJson != "" {
		t.Errorf("未配置时应下发空串，实际 %q", resp.ConfigJson)
	}

	// 配置后重连：注册应带回配置
	cfg := `{"fileWatchDirs":["/srv/app"],"collectAuth":false}`
	if err := client.Asset.Update().SetConfig([]byte(cfg)).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	resp, err = srv.Register(ctx, &pb.RegisterRequest{Hostname: "web01", Os: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	// jsonb 会重排键序，按语义比较——agent 解析 JSON 本就不在乎顺序
	var got, want map[string]any
	if err := json.Unmarshal([]byte(resp.ConfigJson), &got); err != nil {
		t.Fatalf("下发的配置不是合法 JSON：%q", resp.ConfigJson)
	}
	_ = json.Unmarshal([]byte(cfg), &want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("配置未正确下发：got %v want %v", got, want)
	}
}
