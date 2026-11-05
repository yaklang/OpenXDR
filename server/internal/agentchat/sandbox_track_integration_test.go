//go:build integration

package agentchat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/findingreview"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

func TestSandboxCLITrackEndToEndWithRealReviewerAndUnknownBlock(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	agentID := uuid.New()
	a := db.Asset.Create().SetHostname("pve1").SetGroupID(g.ID).SetAgentID(agentID).SetOs("linux").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("glm-5.3-flash").SetStatus("running").SaveX(ctx)
	f1 := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("service").SetTitle("app.service failed").SetDetail("ActiveState=failed").SaveX(ctx)
	f2 := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("service2").SetTitle("perm check").SetDetail("need root").SaveX(ctx)

	hub := response.NewHub(db, true)
	inbox := hub.Attach(agentID)
	defer hub.Detach(agentID, inbox)
	var latestProbeID atomic.Value
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case cmd, ok := <-inbox:
				if !ok {
					return
				}
				latestProbeID.Store(cmd.Id)
				_ = hub.Complete(ctx, agentID, &pb.CommandResult{
					CommandId: cmd.Id,
					Status:    pb.CommandResult_SUCCEEDED,
					ExitCode:  0,
					Stdout:    "ActiveState=active\nSubState=running\n",
				})
			}
		}
	}()

	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cid, _ := latestProbeID.Load().(string)
		w.Header().Set("Content-Type", "application/json")
		resp := fmt.Sprintf(`{"choices":[{"message":{"role":"assistant","content":%q}}]}`,
			fmt.Sprintf(`{"approve":true,"reason":"app.service 已恢复运行","proofs":[{"command_id":%q,"quote":"ActiveState=active"}]}`, cid))
		_, _ = w.Write([]byte(resp))
	}))
	defer llm.Close()

	reviewer := &findingreview.Reviewer{
		Endpoint: func() (string, string, string) { return llm.URL, "test-key", "glm-5.3-flash" },
	}
	gate := &commandgate.Gate{DB: db, Hub: hub}
	svc := &Service{
		DB:            db,
		Gate:          gate,
		ReviewFinding: reviewer.Review,
	}

	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "xdr.sock")
	ctxPath := filepath.Join(tmpDir, "context.json")
	ctxData, err := svc.contextData(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	ctxBytes, _ := json.Marshal(ctxData)
	if err := os.WriteFile(ctxPath, ctxBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/tool", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string          `json:"name"`
			Args json.RawMessage `json:"args"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		out, err := svc.tool(ctx, session, commandgate.Request{System: true}, req.Name, req.Args)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"output": out})
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	xdrBin, err := filepath.Abs("../../../deploy/pi-sandbox/xdr")
	if err != nil {
		t.Fatal(err)
	}
	runXdr := func(args ...string) (string, string, error) {
		cmd := exec.CommandContext(ctx, xdrBin, args...)
		cmd.Env = append(os.Environ(), "XDR_SOCKET="+sockPath, "XDR_CONTEXT="+ctxPath)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}

	// 1. Positive E2E: xdr exec -> extract command ID -> xdr track resolved --evidence <id> -> real findingreview.Reviewer.Review -> DB resolved
	execOut, execErr, err := runXdr("exec", "pve1", "systemctl show app.service -p ActiveState -p SubState", "30")
	if err != nil {
		t.Fatalf("xdr exec failed: %v stderr=%s", err, execErr)
	}
	re := regexp.MustCompile(`^\[id=([0-9a-f-]+) status=succeeded exit=0\]`)
	m := re.FindStringSubmatch(execOut)
	if len(m) != 2 {
		t.Fatalf("unexpected xdr exec output: %q", execOut)
	}
	probeID := m[1]

	trackOut, trackErr, err := runXdr("track", "pve1", "service", "low", "resolved", "app.service 已恢复", "ActiveState=active SubState=running", "--evidence", probeID)
	if err != nil {
		t.Fatalf("xdr track resolved failed: %v stderr=%s", err, trackErr)
	}
	if !strings.Contains(trackOut, `"status":"resolved"`) {
		t.Fatalf("unexpected track resolved output: %s", trackOut)
	}
	gotF1 := db.Finding.GetX(ctx, f1.ID)
	var w1 findings.Work
	_ = json.Unmarshal(gotF1.Work, &w1)
	if gotF1.Status != "resolved" || w1.Stage != "resolved" || len(w1.EvidenceCommands) != 1 || w1.EvidenceCommands[0].String() != probeID {
		t.Fatalf("f1 not properly resolved in DB: status=%s work=%s", gotF1.Status, string(gotF1.Work))
	}

	// 2. Negative E2E: unconfirmed write command (status=unknown) -> xdr command-status + block xdr track resolved
	unknownWrite := db.Command.Create().
		SetAssetID(a.ID).
		SetKind("exec").
		SetCmd("systemctl restart app.service").
		SetStatus("unknown").
		SaveX(ctx)

	statusOut, statusErr, err := runXdr("command-status", unknownWrite.ID.String())
	if err != nil {
		t.Fatalf("xdr command-status failed: %v stderr=%s", err, statusErr)
	}
	if !strings.Contains(statusOut, `"status":"unknown"`) || !strings.Contains(statusOut, `"retry":"not_authorized_by_this_tool"`) {
		t.Fatalf("unexpected command-status output: %s", statusOut)
	}

	_, resolveNegErr, err := runXdr("track", "pve1", "service2", "high", "resolved", "试图关单", "已恢复", "--evidence", probeID)
	if err == nil || !strings.Contains(resolveNegErr, "存在未确认写操作，不能宣称已修复") {
		t.Fatalf("expected unknown write to block track resolved, got err=%v stderr=%s", err, resolveNegErr)
	}
	if db.Finding.GetX(ctx, f2.ID).Status != "open" {
		t.Fatal("f2 should remain open when unknown write exists")
	}

	// 3. Negative E2E: write command succeeded receipt alone cannot be used as resolved evidence
	unknownWrite.Update().SetStatus("succeeded").SetExitCode(0).SetStdout("restarted").SetCompletedAt(time.Now()).ExecX(ctx)
	_, writeEvidenceErr, err := runXdr("track", "pve1", "service2", "high", "resolved", "仅凭重启成功关单", "restarted", "--evidence", unknownWrite.ID.String())
	if err == nil || !strings.Contains(writeEvidenceErr, "须引用独立只读复查") {
		t.Fatalf("expected write command evidence to be rejected, got err=%v stderr=%s", err, writeEvidenceErr)
	}

	// 4. Positive E2E: xdr track open with --next-step, --blocker permission, --evidence <failed_cmd_id>
	failedPerm := db.Command.Create().
		SetAssetID(a.ID).
		SetKind("exec").
		SetCmd("cat /etc/sudoers.d/restricted").
		SetStatus("failed").
		SetExitCode(1).
		SetStderr("cat: /etc/sudoers.d/restricted: Permission denied").
		SetCompletedAt(time.Now()).
		SaveX(ctx)

	_, trackBlockErr, err := runXdr(
		"track", "pve1", "service2", "high", "open", "权限不足待人工处理", "读取受限配置失败",
		"--next-step", "待管理员授权只读访问后复查",
		"--blocker", "permission",
		"--evidence", failedPerm.ID.String(),
	)
	if err != nil {
		t.Fatalf("xdr track open with blocker failed: %v stderr=%s", err, trackBlockErr)
	}
	gotF2 := db.Finding.GetX(ctx, f2.ID)
	var w2 findings.Work
	_ = json.Unmarshal(gotF2.Work, &w2)
	if gotF2.WorkOwner != "human" || w2.Stage != "blocked" || w2.Blocker != "permission" || w2.Plan != "待管理员授权只读访问后复查" || len(w2.EvidenceCommands) != 1 || w2.EvidenceCommands[0] != failedPerm.ID {
		t.Fatalf("f2 work metadata not preserved: owner=%s work=%s", gotF2.WorkOwner, string(gotF2.Work))
	}
	_ = ent.MaskNotFound
}
