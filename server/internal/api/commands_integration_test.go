//go:build integration

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openxdr/server/internal/testdb"
)

func TestCommandListSummary(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("可见组").SaveX(ctx)
	other := db.Group.Create().SetName("其他组").SaveX(ctx)
	asset := db.Asset.Create().SetHostname("visible").SetGroupID(group.ID).SaveX(ctx)
	hidden := db.Asset.Create().SetHostname("hidden").SetGroupID(other.ID).SaveX(ctx)
	user := db.User.Create().SetUsername("viewer").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	db.GroupMember.Create().SetGroupID(group.ID).SetUserID(user.ID).SetRole("viewer").SaveX(ctx)
	output := strings.Repeat("输出", 20000)
	command := db.Command.Create().SetAssetID(asset.ID).SetKind("exec").SetStatus("succeeded").
		SetCmd("echo example").SetStdout(output).SetStderr(output).SetDetail("执行成功").SetExitCode(0).SaveX(ctx)
	secret := db.Command.Create().SetAssetID(hidden.ID).SetKind("exec").SetStdout("不可见").SaveX(ctx)
	mux := http.NewServeMux()
	mapCommands(mux, db, nil, nil, nil, nil)
	server := httptest.NewServer(as(user, mux))
	t.Cleanup(server.Close)

	resp, body := get(t, server, "/api/commands?view=summary&assetId="+asset.ID.String())
	if resp.StatusCode != 200 || len(body) > 2000 {
		t.Fatalf("摘要响应状态 %d，长度 %d", resp.StatusCode, len(body))
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) != 1 {
		t.Fatalf("摘要列表无效：%s", body)
	}
	for _, field := range []string{"cmd", "stdout", "stderr"} {
		if _, ok := rows[0][field]; ok {
			t.Fatalf("摘要包含 %s", field)
		}
	}
	if string(rows[0]["detail"]) != `"执行成功"` || string(rows[0]["exitCode"]) != "0" {
		t.Fatal("摘要丢失结果或退出码")
	}
	for _, path := range []string{"/api/commands", "/api/commands?view=full", "/api/commands/" + command.ID.String()} {
		resp, body = get(t, server, path)
		if resp.StatusCode != 200 || !strings.Contains(string(body), output) {
			t.Fatalf("完整内容未保留：%s", path)
		}
	}
	resp, body = get(t, server, "/api/commands?view=summary&assetId="+hidden.ID.String())
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != "[]" {
		t.Fatal("摘要泄露跨组指令")
	}
	if resp, _ = get(t, server, "/api/commands/"+secret.ID.String()); resp.StatusCode != 403 {
		t.Fatalf("跨组详情状态 %d", resp.StatusCode)
	}
	if resp, _ = get(t, server, "/api/commands?view=invalid"); resp.StatusCode != 400 {
		t.Fatalf("非法视图状态 %d", resp.StatusCode)
	}
	for n := 0; n < 105; n++ {
		db.Command.Create().SetAssetID(asset.ID).SetKind("exec").SaveX(ctx)
	}
	seen := map[string]bool{}
	for page := 1; page <= 11; page++ {
		resp, body = get(t, server, fmt.Sprintf("/api/commands?view=summary&page=%d&pageSize=10", page))
		var result struct {
			Items []commandRow `json:"items"`
			Total int          `json:"total"`
		}
		if resp.StatusCode != 200 || json.Unmarshal(body, &result) != nil || result.Total != 106 {
			t.Fatalf("分页无效：%s", body)
		}
		for _, row := range result.Items {
			if seen[row.ID.String()] {
				t.Fatal("分页重复")
			}
			seen[row.ID.String()] = true
		}
	}
	if len(seen) != 106 {
		t.Fatalf("未读取 100 条以后的历史：%d", len(seen))
	}
	for _, query := range []string{"page=0", "page=x", "page=1&pageSize=101", "page=1&pageSize=-1"} {
		if resp, _ = get(t, server, "/api/commands?"+query); resp.StatusCode != 400 {
			t.Fatalf("非法分页未拒绝：%s", query)
		}
	}

}
