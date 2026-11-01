//go:build integration

package commandreview

import (
	"encoding/json"
	"strings"
	"testing"

	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
)

// 多轮对话里审计员要看到本轮的请求：只给第一条，后来交代的事会被判成与目标无关
func TestMaterialUsesCurrentRequest(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	host := db.Asset.Create().SetHostname("web-01").SetGroupID(g.ID).SaveX(ctx)
	s := db.AgentSession.Create().SetKind("chat").SetGroupID(g.ID).SetInitiator("admin").SetModel("m").SetTitle("验证").SaveX(ctx)
	for i, m := range []string{
		`{"role":"user","content":"重启时间同步服务"}`,
		`{"role":"assistant","content":[{"type":"text","text":"已重启"}]}`,
		`{"role":"user","content":"再往 /etc 写一个测试文件然后删掉"}`,
		`{"role":"assistant","content":[{"type":"text","text":"先写入测试标记"},{"type":"toolCall","name":"exec"}]}`,
	} {
		role := map[bool]string{true: "user", false: "assistant"}[i%2 == 0]
		db.SessionMessage.Create().SetSessionID(s.ID).SetSeq(i).SetRole(role).SetContent(json.RawMessage(m)).SaveX(ctx)
	}
	cmd := "echo x | tee /etc/t"
	r := &Reviewer{DB: db}
	got, err := r.material(ctx, s, commandgate.Request{SessionID: &s.ID, Command: response.Request{AssetID: host.ID, Cmd: &cmd, TimeoutMS: 30000}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"会话最初的请求：\n重启时间同步服务", "本轮用户的请求（以它为准）：\n再往 /etc 写一个测试文件然后删掉", "执行前模型最后的说明：\n先写入测试标记", "目标主机：web-01", "待审命令：\necho x | tee /etc/t"} {
		if !strings.Contains(got, want) {
			t.Errorf("材料缺少 %q:\n%s", want, got)
		}
	}
}
