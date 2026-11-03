package feishuapproval

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	larkevent "github.com/larksuite/oapi-sdk-go/v3/event"
)

func TestCommandVisibility(t *testing.T) {
	for _, cmd := range []string{"id", "printf '%s\\n' 'test'", strings.Repeat("界", 4000)} {
		if !directCommand(cmd) {
			t.Fatal("完整可见命令不能被误拒")
		}
	}
	for _, cmd := range []string{"", strings.Repeat("界", 4001), "id\u202erm -rf", "id\x00", "id\x1b[2J", string([]byte{0xff})} {
		if directCommand(cmd) {
			t.Fatal("不可完整安全展示的命令不应允许卡片批准")
		}
	}
	card := (&Service{}).card(context.Background(), delivery{Nonce: "private-test"}, nil)
	raw, _ := json.Marshal(card)
	if strings.Contains(string(raw), `"action":"approve"`) || !strings.Contains(string(raw), `"action":"test"`) {
		t.Fatal("连接测试不允许批准执行")
	}
}

func TestAuthenticatedEventHeader(t *testing.T) {
	c := Config{AppID: "cli_test"}
	h := &larkevent.EventV2Base{Header: &larkevent.EventHeader{AppID: c.AppID, TenantKey: "tenant", EventType: "card.action.trigger", CreateTime: strconv.FormatInt(time.Now().UnixMilli(), 10)}}
	if !freshHeader(h, c, "card.action.trigger") {
		t.Fatal("有效事件被拒")
	}
	h.Header.AppID = "other"
	if freshHeader(h, c, "card.action.trigger") {
		t.Fatal("跨应用事件被接受")
	}
	h.Header.AppID = c.AppID
	h.Header.CreateTime = strconv.FormatInt(time.Now().Add(-11*time.Minute).UnixMilli(), 10)
	if freshHeader(h, c, "card.action.trigger") {
		t.Fatal("旧事件被接受")
	}
	h.Header.CreateTime = strconv.FormatInt(time.Now().Add(2*time.Minute).UnixMilli(), 10)
	if freshHeader(h, c, "card.action.trigger") {
		t.Fatal("未来事件被接受")
	}
	if freshHeader(nil, c, "card.action.trigger") {
		t.Fatal("无认证头事件被接受")
	}
	h.Header.CreateTime = strconv.FormatInt(time.Now().UnixMicro(), 10)
	if !freshHeader(h, c, "card.action.trigger") {
		t.Fatal("飞书卡片的微秒时间戳应通过")
	}
	h.Header.CreateTime = strconv.FormatInt(time.Now().Add(-11*time.Minute).UnixMicro(), 10)
	if freshHeader(h, c, "card.action.trigger") {
		t.Fatal("过期微秒时间戳不能通过")
	}
	h.Header.CreateTime = strconv.FormatInt(time.Now().Add(2*time.Minute).UnixMicro(), 10)
	if freshHeader(h, c, "card.action.trigger") {
		t.Fatal("未来微秒时间戳不能通过")
	}
	h.Header.CreateTime = strconv.FormatInt(time.Now().UnixNano(), 10)
	if freshHeader(h, c, "card.action.trigger") {
		t.Fatal("未知精度不能自动放行")
	}
}
