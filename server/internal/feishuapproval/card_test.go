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

func TestApproveContainmentAuditAndOutcome(t *testing.T) {
	cases := []struct {
		name          string
		res           *ent.Containment
		err           error
		stillProposed bool
		checkErr      error
		wantAudits    []string
		wantOutcome   string
	}{
		{
			name:        "批准进入pending写入成功审计并锁卡",
			res:         &ent.Containment{State: entcontainment.StatePending},
			wantAudits:  []string{"containment_approved"},
			wantOutcome: "approve",
		},
		{
			name:        "批准进入active写入成功审计并锁卡",
			res:         &ent.Containment{State: entcontainment.StateActive},
			wantAudits:  []string{"containment_approved"},
			wantOutcome: "approve",
		},
		{
			name:        "批准进入executed写入成功审计并锁卡",
			res:         &ent.Containment{State: entcontainment.StateExecuted},
			wantAudits:  []string{"containment_approved"},
			wantOutcome: "approve",
		},
		{
			name:        "下发失败返回StateFailed不写成功审计而记失败审计",
			res:         &ent.Containment{State: entcontainment.StateFailed},
			wantAudits:  []string{"containment_approve_failed"},
			wantOutcome: "approve",
		},
		{
			name:          "瞬时失败且仍处于proposed不写审计并释放卡片锁",
			err:           errors.New("transient db error"),
			stillProposed: true,
			wantOutcome:   "",
		},
		{
			name:          "部分成功后报错不写假成功审计并锁卡",
			err:           errors.New("edge dispatch failed"),
			stillProposed: false,
			wantOutcome:   "approve",
		},
		{
			name:        "瞬时失败且回查状态失败时不永久锁死卡片",
			err:         errors.New("transient error"),
			checkErr:    errors.New("db unavailable"),
			wantOutcome: "",
		},
		{
			name:        "返回仍为proposed时不写审计并释放卡片锁",
			res:         &ent.Containment{State: entcontainment.StateProposed},
			wantOutcome: "",
		},
		{
			name:        "触发熔断不写审计并锁卡",
			res:         &ent.Containment{State: entcontainment.StateHeld},
			wantOutcome: "approve",
		},
		{
			name:        "重复处置被驳回不写审计并锁卡",
			res:         &ent.Containment{State: entcontainment.StateDeclined},
			wantOutcome: "approve",
		},
		{
			name:        "目标跳过不写审计并锁卡",
			res:         &ent.Containment{State: entcontainment.StateSkipped},
			wantOutcome: "approve",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var audits []string
			outcome := containmentOutcomeApproving
			svc := &Service{
				Containment: stubContainmentDecider{
					approve: func(_ context.Context, _ *ent.Containment, _ string) (*ent.Containment, error) {
						return tc.res, tc.err
					},
				},
			}
			svc.approveContainment(context.Background(), &ent.Containment{ID: uuid.New()}, "admin", containmentApproveHooks{
				audit: func(action string) {
					audits = append(audits, action)
				},
				stillProposed: func(context.Context) (bool, error) {
					return tc.stillProposed, tc.checkErr
				},
				setOutcome: func(_ context.Context, value string) {
					outcome = value
				},
			})
			if len(audits) != len(tc.wantAudits) {
				t.Fatalf("审计记录数不符：got=%v want=%v", audits, tc.wantAudits)
			}
			for i := range audits {
				if audits[i] != tc.wantAudits[i] {
					t.Fatalf("审计动作不符：got=%v want=%v", audits, tc.wantAudits)
				}
			}
			if outcome != tc.wantOutcome {
				t.Fatalf("卡片 outcome 不符：got=%q want=%q", outcome, tc.wantOutcome)
			}
		})
	}
}

func TestContainmentCardRetryAfterRestartOrConcurrentClick(t *testing.T) {
	svc := &Service{}
	nonce := uuid.NewString()

	// 未处理卡片允许进入
	if err := svc.containmentOutcomeBlocks("", nonce); err != nil {
		t.Fatalf("空 outcome 应允许处理：%v", err)
	}
	// 终态卡片拒绝重复处理
	for _, finalOutcome := range []string{"approve", "reject"} {
		if err := svc.containmentOutcomeBlocks(finalOutcome, nonce); err == nil {
			t.Fatalf("终态 %q 不应允许重复处理", finalOutcome)
		}
	}
	// 模拟进程在 CAS 前重启：库里残留 approving，但本进程无 in-flight 记录，应允许重试
	if err := svc.containmentOutcomeBlocks(containmentOutcomeApproving, nonce); err != nil {
		t.Fatalf("重启后残留 approving 应允许重试：%v", err)
	}
	// 正常处理中：本进程持有 in-flight 占位，并发双击必须被拦截
	release, ok := svc.claimContainmentInFlight(nonce)
	if !ok {
		t.Fatal("首次占位应成功")
	}
	if _, okAgain := svc.claimContainmentInFlight(nonce); okAgain {
		t.Fatal("并发重复占位应失败")
	}
	if err := svc.containmentOutcomeBlocks(containmentOutcomeApproving, nonce); err == nil {
		t.Fatal("后台仍在执行时应拦截并发点击")
	}
	// 释放占位后（如后台瞬时失败或事务回滚），可重新接管
	release()
	if err := svc.containmentOutcomeBlocks(containmentOutcomeApproving, nonce); err != nil {
		t.Fatalf("释放占位后应允许重试：%v", err)
	}
}
