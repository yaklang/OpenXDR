package feishuapproval

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	larkevent "github.com/larksuite/oapi-sdk-go/v3/event"
	"openxdr/server/ent"
	entcontainment "openxdr/server/ent/containment"
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

func TestOneLineCannotForgeFields(t *testing.T) {
	got := oneLine("id\n组：生产\r\n主机：db\t\u200b")
	if strings.ContainsAny(got, "\n\r\t\u200b") || got != "id⏎组：生产\uFFFD⏎主机：db⇥\uFFFD" {
		t.Fatalf("控制字符未转成可见符号: %q", got)
	}
}

type stubContainmentDecider struct {
	approve func(ctx context.Context, c *ent.Containment, actor string) (*ent.Containment, error)
}

func (d stubContainmentDecider) Approve(ctx context.Context, c *ent.Containment, actor string) (*ent.Containment, error) {
	return d.approve(ctx, c, actor)
}

func (d stubContainmentDecider) Decline(context.Context, *ent.Containment, string, string) (*ent.Containment, error) {
	return nil, nil
}

func TestApproveContainmentAuditTiming(t *testing.T) {
	cases := []struct {
		name      string
		res       *ent.Containment
		err       error
		wantAudit int
	}{
		{name: "批准生效写入审计", res: &ent.Containment{State: entcontainment.StatePending}, wantAudit: 1},
		{name: "并发冲突或下发失败不写审计", err: errors.New("not proposed"), wantAudit: 0},
		{name: "触发熔断不写审计", res: &ent.Containment{State: entcontainment.StateHeld}, wantAudit: 0},
		{name: "重复处置被驳回不写审计", res: &ent.Containment{State: entcontainment.StateDeclined}, wantAudit: 0},
		{name: "目标跳过不写审计", res: &ent.Containment{State: entcontainment.StateSkipped}, wantAudit: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var audits []string
			svc := &Service{
				Containment: stubContainmentDecider{
					approve: func(_ context.Context, _ *ent.Containment, _ string) (*ent.Containment, error) {
						return tc.res, tc.err
					},
				},
			}
			svc.approveContainment(context.Background(), &ent.Containment{ID: uuid.New()}, "admin", func(action string) {
				audits = append(audits, action)
			})
			if len(audits) != tc.wantAudit {
				t.Fatalf("审计记录数不符：got=%v want=%d", audits, tc.wantAudit)
			}
			if tc.wantAudit == 1 && audits[0] != "containment_approved" {
				t.Fatalf("审计动作不符：got=%q", audits[0])
			}
		})
	}
}
