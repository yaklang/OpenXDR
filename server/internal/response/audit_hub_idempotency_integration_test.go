//go:build integration

package response

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
)

func TestAuditReservedCommandIdentityAndSingleDelivery(t *testing.T) {
	for _, status := range []string{"pending", "sent", "unknown", "succeeded"} {
		for _, changed := range []string{"none", "pid", "guid", "actor", "incident", "cmd", "timeout", "allow"} {
			t.Run(status+"/"+changed, func(t *testing.T) {
				ctx, db := testdb.New(t)
				agent := uuid.New()
				asset := db.Asset.Create().SetHostname("reserved-command").SetAgentID(agent).SaveX(ctx)
				hub := NewHub(db, true)
				ch := hub.Attach(agent)
				guid, incident := uuid.New(), uuid.New()
				req := Request{CommandID: uuid.New(), AssetID: asset.ID, Kind: "kill_process", PID: 4242, ProcessGUID: &guid, IncidentID: &incident, IssuedBy: "auto"}
				if changed == "cmd" || changed == "timeout" {
					line := "uname -a"
					req.Kind = "exec"
					req.Cmd = &line
					req.TimeoutMS = 1000
				}
				if changed == "allow" {
					req.Kind = "isolate_host"
					req.AllowEndpoints = []string{"192.0.2.1:8081"}
				}
				issue := hub.Issue
				if req.Kind == "exec" {
					issue = hub.IssueExec
				}
				first, err := issue(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				db.Command.UpdateOneID(first.ID).SetStatus(status).ExecX(ctx)
				next := req
				switch changed {
				case "pid":
					next.PID++
				case "guid":
					v := uuid.New()
					next.ProcessGUID = &v
				case "actor":
					next.IssuedBy = "other-operator"
				case "incident":
					v := uuid.New()
					next.IncidentID = &v
				case "cmd":
					v := "hostname"
					next.Cmd = &v
				case "timeout":
					next.TimeoutMS++
				case "allow":
					next.AllowEndpoints = []string{"192.0.2.2:8081"}
				}
				repeated, err := issue(ctx, next)
				if changed == "none" {
					if err != nil || repeated == nil || repeated.ID != first.ID || repeated.Status != status {
						t.Fatalf("真实重复未返回原指令状态: %+v %v", repeated, err)
					}
				} else if err == nil {
					t.Error("同一预留身份被不同动作复用，返回了其他动作的回执")
				}
				if n := db.Command.Query().CountX(ctx); n != 1 {
					t.Errorf("创建了%d条命令", n)
				}
				if n := len(ch); n != 1 {
					t.Errorf("重复投递%d次", n)
				}
				raw, err := json.Marshal(req)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(raw), req.CommandID.String()) {
					t.Error("内部预留身份暴露为可序列化请求字段")
				}
			})
		}
	}
}
