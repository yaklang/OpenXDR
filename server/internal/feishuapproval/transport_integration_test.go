//go:build integration

package feishuapproval

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher/callback"
	larkim "github.com/larksuite/oapi-sdk-go/v3/service/im/v1"
	"openxdr/server/ent/approval"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPrivateEventSendAndCallback(t *testing.T) {
	f := setup(t)
	code, err := f.s.bindingCode(f.ctx, f.u)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{"app_id": f.c.AppID, "tenant_key": "tenant", "event_type": "im.message.receive_v1", "create_time": strconv.FormatInt(time.Now().UnixMilli(), 10)}
	text, _ := json.Marshal(map[string]string{"text": code})
	msg := map[string]any{"chat_type": "group", "message_type": "text", "content": string(text)}
	event := map[string]any{"header": header, "event": map[string]any{"sender": map[string]any{"sender_id": map[string]string{"open_id": "open-1"}, "sender_type": "user", "tenant_key": "tenant"}, "message": msg}}
	receive := func() {
		b, _ := json.Marshal(event)
		var e larkim.P2MessageReceiveV1
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatal(err)
		}
		if err := f.s.message(f.ctx, f.c, &e); err != nil {
			t.Fatal(err)
		}
	}
	receive()
	var n int
	if err := f.s.SQL.QueryRowContext(f.ctx, `SELECT count(*) FROM feishu_approval_bindings`).Scan(&n); err != nil || n != 0 {
		t.Fatal("群聊不能绑定身份")
	}
	msg["chat_type"] = "p2p"
	receive()
	a := pendingApproval(t, f)
	if err := f.s.enqueue(f.ctx, f.c); err != nil {
		t.Fatal(err)
	}
	sends := 0
	f.s.HTTP = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "open.feishu.cn" {
			t.Fatal("请求目标不符")
		}
		response := `{"code":0,"tenant_access_token":"fake-token","expire":3600}`
		if strings.HasSuffix(r.URL.Path, "/im/v1/messages") {
			sends++
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if r.URL.Query().Get("receive_id_type") != "open_id" || body["receive_id"] != "open-1" || body["uuid"] == "" || r.Header.Get("Authorization") != "Bearer fake-token" {
				t.Fatal("发送目标或去重身份错误")
			}
			if !strings.Contains(body["content"], `"action":"approve"`) {
				t.Fatal("未发送审批按钮")
			}
			response = `{"code":0,"data":{"message_id":"message-1"}}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
	})}
	if err := f.s.deliver(f.ctx, f.c); err != nil {
		t.Fatal(err)
	}
	if err := f.s.deliver(f.ctx, f.c); err != nil {
		t.Fatal(err)
	}
	if sends != 1 {
		t.Fatalf("卡片发送次数 %d", sends)
	}
	var nonce string
	if err := f.s.SQL.QueryRowContext(f.ctx, `SELECT nonce FROM feishu_approval_deliveries WHERE approval_id=$1`, a.ID).Scan(&nonce); err != nil {
		t.Fatal(err)
	}
	header["event_type"] = "card.action.trigger"
	header["create_time"] = strconv.FormatInt(time.Now().UnixMicro(), 10)
	actionEvent := map[string]any{"header": header, "event": map[string]any{"host": "im_message", "operator": map[string]string{"open_id": "open-1", "tenant_key": "tenant"}, "context": map[string]string{"open_message_id": "message-1"}, "action": map[string]any{"tag": "button", "value": map[string]string{"nonce": nonce, "action": "approve"}}}}
	b, _ := json.Marshal(actionEvent)
	var e callback.CardActionTriggerEvent
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	result, err := f.s.action(f.ctx, f.c, &e)
	if err != nil || result.Toast.Type != "success" || f.s.DB.Approval.GetX(f.ctx, a.ID).Status != approval.StatusApproved {
		t.Fatalf("按钮回调未决定审批: %+v %v", result, err)
	}
	result, err = f.s.action(f.ctx, f.c, &e)
	if err != nil || result.Toast.Type != "error" {
		t.Fatal("重复回调未被拒绝")
	}
}
