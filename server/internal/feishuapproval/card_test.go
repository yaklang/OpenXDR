package feishuapproval

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	larkevent "github.com/larksuite/oapi-sdk-go/v3/event"
	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher/callback"
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
	assertCardUpdateMulti(t, raw)
	statusRaw, _ := json.Marshal(statusCard("已批准"))
	assertCardUpdateMulti(t, statusRaw)
}

func assertCardUpdateMulti(t *testing.T, cardJSON []byte) {
	t.Helper()
	var parsed struct {
		Config struct {
			UpdateMulti *bool `json:"update_multi"`
		} `json:"config"`
	}
	if err := json.Unmarshal(cardJSON, &parsed); err != nil {
		t.Fatalf("卡片 JSON 解析失败：%v (%s)", err, string(cardJSON))
	}
	if parsed.Config.UpdateMulti == nil || !*parsed.Config.UpdateMulti {
		t.Fatalf("卡片必须显式声明 config.update_multi=true：%s", string(cardJSON))
	}
}

func patchBodyHasUpdateMulti(raw []byte) bool {
	var req struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.Content == "" {
		return false
	}
	var card struct {
		Config struct {
			UpdateMulti *bool `json:"update_multi"`
		} `json:"config"`
	}
	if err := json.Unmarshal([]byte(req.Content), &card); err != nil {
		return false
	}
	return card.Config.UpdateMulti != nil && *card.Config.UpdateMulti
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
		name           string
		res            *ent.Containment
		err            error
		stillProposed  bool
		checkErr       error
		wantAudits     []string
		wantOutcome    string
		wantCardUpdate bool
	}{
		{
			name:           "批准进入pending写入成功审计并锁卡更新终态卡",
			res:            &ent.Containment{State: entcontainment.StatePending},
			wantAudits:     []string{"containment_approved"},
			wantOutcome:    "approve",
			wantCardUpdate: true,
		},
		{
			name:           "批准进入active写入成功审计并锁卡更新终态卡",
			res:            &ent.Containment{State: entcontainment.StateActive},
			wantAudits:     []string{"containment_approved"},
			wantOutcome:    "approve",
			wantCardUpdate: true,
		},
		{
			name:           "批准进入executed写入成功审计并锁卡更新终态卡",
			res:            &ent.Containment{State: entcontainment.StateExecuted},
			wantAudits:     []string{"containment_approved"},
			wantOutcome:    "approve",
			wantCardUpdate: true,
		},
		{
			name:           "下发失败返回StateFailed不写成功审计而记失败审计并更新终态卡",
			res:            &ent.Containment{State: entcontainment.StateFailed},
			wantAudits:     []string{"containment_approve_failed"},
			wantOutcome:    "approve",
			wantCardUpdate: true,
		},
		{
			name:           "瞬时失败且仍处于proposed不写审计不覆盖卡片并释放卡片锁",
			err:            errors.New("transient db error"),
			stillProposed:  true,
			wantOutcome:    "",
			wantCardUpdate: false,
		},
		{
			name:           "部分成功后报错不写假成功审计并锁卡更新终态卡",
			err:            errors.New("edge dispatch failed"),
			stillProposed:  false,
			wantOutcome:    "approve",
			wantCardUpdate: true,
		},
		{
			name:           "瞬时失败且回查状态失败时不永久锁死卡片也不覆盖卡片",
			err:            errors.New("transient error"),
			checkErr:       errors.New("db unavailable"),
			wantOutcome:    "",
			wantCardUpdate: false,
		},
		{
			name:           "返回仍为proposed时不写审计不覆盖卡片并释放卡片锁",
			res:            &ent.Containment{State: entcontainment.StateProposed},
			wantOutcome:    "",
			wantCardUpdate: false,
		},
		{
			name:           "触发熔断不写审计并锁卡更新终态卡",
			res:            &ent.Containment{State: entcontainment.StateHeld},
			wantOutcome:    "approve",
			wantCardUpdate: true,
		},
		{
			name:           "重复处置被驳回不写审计并锁卡更新终态卡",
			res:            &ent.Containment{State: entcontainment.StateDeclined},
			wantOutcome:    "approve",
			wantCardUpdate: true,
		},
		{
			name:           "目标跳过不写审计并锁卡更新终态卡",
			res:            &ent.Containment{State: entcontainment.StateSkipped},
			wantOutcome:    "approve",
			wantCardUpdate: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var audits []string
			var cardUpdates []string
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
				updateCard: func(_ context.Context, text string) {
					cardUpdates = append(cardUpdates, text)
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
			if tc.wantCardUpdate {
				if len(cardUpdates) != 1 || strings.TrimSpace(cardUpdates[0]) == "" {
					t.Fatalf("终态应更新一次卡片：got=%v", cardUpdates)
				}
			} else if len(cardUpdates) != 0 {
				t.Fatalf("可重试分支不应覆盖原交互卡：got=%v", cardUpdates)
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newCallbackEvent(appID, tenant, openID, messageID, nonce, action string) *callback.CardActionTriggerEvent {
	tenantCopy := tenant
	return &callback.CardActionTriggerEvent{
		EventV2Base: &larkevent.EventV2Base{
			Header: &larkevent.EventHeader{
				AppID:      appID,
				TenantKey:  tenant,
				EventType:  "card.action.trigger",
				CreateTime: strconv.FormatInt(time.Now().UnixMicro(), 10),
			},
		},
		Event: &callback.CardActionTriggerRequest{
			Host: "im_message",
			Operator: &callback.Operator{
				OpenID:    openID,
				TenantKey: &tenantCopy,
			},
			Context: &callback.Context{
				OpenMessageID: messageID,
			},
			Action: &callback.CallBackAction{
				Value: map[string]any{
					"nonce":  nonce,
					"action": action,
				},
			},
		},
	}
}

func TestActionCallbackKeepsInteractiveCardUntilTerminalAndAllowsRetry(t *testing.T) {
	cfg := Config{AppID: "cli_test", Revision: "rev-1", Enabled: true}
	nonce := uuid.NewString()
	messageID := "om_card_retry_1"
	containmentID := uuid.New()

	var (
		patchMu       sync.Mutex
		patchedPaths  []string
		patchedBodies []string
		stateMu       sync.Mutex
		outcome       string
		attempt       int
		firstBlocked  = make(chan struct{})
		releaseFirst  = make(chan struct{})
		firstDone     = make(chan struct{})
		secondDone    = make(chan struct{})
	)

	svc := &Service{
		HTTP: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodPatch {
					t.Errorf("更新卡片应使用 PATCH，实际为 %s", r.Method)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
					t.Errorf("鉴权头不符：%q", got)
				}
				body, _ := io.ReadAll(r.Body)
				if !patchBodyHasUpdateMulti(body) {
					return &http.Response{
						StatusCode: http.StatusBadRequest,
						Header:     http.Header{"Content-Type": []string{"application/json"}},
						Body:       io.NopCloser(strings.NewReader(`{"code":230072,"msg":"card must set update_multi true"}`)),
					}, nil
				}
				patchMu.Lock()
				patchedPaths = append(patchedPaths, r.URL.Path)
				patchedBodies = append(patchedBodies, string(body))
				patchMu.Unlock()
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"code":0}`)),
				}, nil
			}),
		},
		token:         "test-token",
		tokenRevision: cfg.Revision,
		tokenUntil:    time.Now().Add(time.Hour),
		Containment: stubContainmentDecider{
			approve: func(_ context.Context, _ *ent.Containment, _ string) (*ent.Containment, error) {
				stateMu.Lock()
				attempt++
				cur := attempt
				stateMu.Unlock()
				if cur == 1 {
					close(firstBlocked)
					<-releaseFirst
					return nil, errors.New("transient dispatch timeout")
				}
				return &ent.Containment{ID: containmentID, State: entcontainment.StatePending}, nil
			},
		},
	}

	prevHook := decideCardHook
	t.Cleanup(func() { decideCardHook = prevHook })
	decideCardHook = func(s *Service, ctx context.Context, c Config, _, _, msgID, n, act string) (decideOutcome, error) {
		if act == "reject" {
			return decideOutcome{text: "已驳回，这条处置不会执行。"}, nil
		}
		stateMu.Lock()
		curOutcome := outcome
		stateMu.Unlock()
		if err := s.containmentOutcomeBlocks(curOutcome, n); err != nil {
			return decideOutcome{}, err
		}
		release, ok := s.claimContainmentInFlight(n)
		if !ok {
			return decideOutcome{}, errors.New("这张卡片正在处理中，请稍候")
		}
		stateMu.Lock()
		outcome = containmentOutcomeApproving
		curAttempt := attempt
		stateMu.Unlock()
		go func(runIdx int) {
			defer release()
			s.approveContainment(ctx, &ent.Containment{ID: containmentID}, "admin", containmentApproveHooks{
				stillProposed: func(context.Context) (bool, error) { return true, nil },
				setOutcome: func(_ context.Context, value string) {
					stateMu.Lock()
					outcome = value
					stateMu.Unlock()
				},
				updateCard: func(updCtx context.Context, text string) {
					if err := s.patchCard(updCtx, c, msgID, statusCard(text)); err != nil {
						t.Errorf("异步更新终态卡片失败：%v", err)
					}
				},
			})
			if runIdx == 0 {
				close(firstDone)
			} else {
				close(secondDone)
			}
		}(curAttempt)
		return decideOutcome{text: "审批处理中，请稍候；结果以 OpenXDR 自主响应页的记录为准。", pending: true}, nil
	}

	ev := newCallbackEvent(cfg.AppID, "tenant-1", "ou_admin", messageID, nonce, "approve")

	// 1. 首次点击批准：同步回调仅返回处理中 toast，严禁返回覆盖卡片销毁按钮
	resp, err := svc.action(context.Background(), cfg, ev)
	if err != nil {
		t.Fatalf("首次回调失败：%v", err)
	}
	if resp.Card != nil {
		t.Fatalf("异步批准回调不应立即覆盖原交互卡：%#v", resp.Card)
	}
	if resp.Toast == nil || resp.Toast.Type != "info" || !strings.Contains(resp.Toast.Content, "审批处理中，请稍候") {
		t.Fatalf("首次回调 toast 不符：%#v", resp.Toast)
	}

	// 2. 后台正在执行时并发双击同一回调应被拦截
	<-firstBlocked
	dupResp, err := svc.action(context.Background(), cfg, ev)
	if err != nil {
		t.Fatalf("并发回调出错：%v", err)
	}
	if dupResp.Toast == nil || dupResp.Toast.Type != "error" || dupResp.Card != nil {
		t.Fatalf("并发点击应返回错误 toast 且不覆盖卡片：%#v", dupResp)
	}

	// 3. 首次后台瞬时失败：应解锁 outcome 且绝不异步覆盖原卡片
	close(releaseFirst)
	<-firstDone
	patchMu.Lock()
	if len(patchedPaths) != 0 {
		t.Fatalf("瞬时失败可重试时不应更新卡片：%v", patchedPaths)
	}
	patchMu.Unlock()
	stateMu.Lock()
	if outcome != "" {
		t.Fatalf("瞬时失败后应解锁 outcome，实际=%q", outcome)
	}
	stateMu.Unlock()

	// 4. 故障窗口后重放同一回调：可重新提交批准，同样先保留交互卡，终态后异步 PATCH 更新为无按钮 statusCard
	retryResp, err := svc.action(context.Background(), cfg, ev)
	if err != nil {
		t.Fatalf("重试回调失败：%v", err)
	}
	if retryResp.Card != nil || retryResp.Toast == nil || retryResp.Toast.Type != "info" {
		t.Fatalf("重试回调应保留交互卡并返回处理中 toast：%#v", retryResp)
	}
	<-secondDone

	patchMu.Lock()
	if len(patchedPaths) != 1 || patchedPaths[0] != "/open-apis/im/v1/messages/"+messageID {
		t.Fatalf("终态后应异步 PATCH 原消息卡片一次：got=%v", patchedPaths)
	}
	body := patchedBodies[0]
	patchMu.Unlock()
	if strings.Contains(body, `"tag":"button"`) || !strings.Contains(body, "已批准") {
		t.Fatalf("终态更新的卡片应为无按钮状态卡：%s", body)
	}
	var patchedReq struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal([]byte(body), &patchedReq); err != nil {
		t.Fatalf("解析 PATCH 请求体失败：%v", err)
	}
	assertCardUpdateMulti(t, []byte(patchedReq.Content))

	// 5. 落到终态后再次重放同一回调必须被拒绝
	afterTerminal, err := svc.action(context.Background(), cfg, ev)
	if err != nil {
		t.Fatalf("终态重放回调出错：%v", err)
	}
	if afterTerminal.Toast == nil || afterTerminal.Toast.Type != "error" || afterTerminal.Card != nil {
		t.Fatalf("终态后重放应返回错误 toast：%#v", afterTerminal)
	}

	// 6. 同步终态路径（驳回）仍立即返回无按钮 statusCard
	rejectEv := newCallbackEvent(cfg.AppID, "tenant-1", "ou_admin", messageID, nonce, "reject")
	rejectResp, err := svc.action(context.Background(), cfg, rejectEv)
	if err != nil {
		t.Fatalf("驳回回调出错：%v", err)
	}
	if rejectResp.Card == nil || rejectResp.Toast == nil || rejectResp.Toast.Type != "success" {
		t.Fatalf("同步终态回调应返回状态卡片与成功 toast：%#v", rejectResp)
	}
}

func TestPatchCardEnforcesUpdateMultiAndLogsError(t *testing.T) {
	cfg := Config{AppID: "cli_test", Revision: "rev-1", Enabled: true}
	svc := &Service{
		HTTP: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(r.Body)
				if !patchBodyHasUpdateMulti(body) {
					return &http.Response{
						StatusCode: http.StatusBadRequest,
						Header:     http.Header{"Content-Type": []string{"application/json"}},
						Body:       io.NopCloser(strings.NewReader(`{"code":230072,"msg":"card must set update_multi true"}`)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"code":0}`)),
				}, nil
			}),
		},
		token:         "test-token",
		tokenRevision: cfg.Revision,
		tokenUntil:    time.Now().Add(time.Hour),
	}
	// statusCard 携带 update_multi: true，应更新成功
	if err := svc.patchCard(context.Background(), cfg, "om_ok", statusCard("已批准")); err != nil {
		t.Fatalf("带 update_multi 的 statusCard 更新应成功：%v", err)
	}
	// 缺少 update_multi 时，mock 服务端返回 400 + 飞书错误码，patchCard 应返回含错误码和消息的错误而不崩溃
	legacyCard := map[string]any{
		"config":   map[string]any{"wide_screen_mode": true},
		"elements": []any{paragraph("旧卡")},
	}
	err := svc.patchCard(context.Background(), cfg, "om_legacy", legacyCard)
	if err == nil || !strings.Contains(err.Error(), "230072") || !strings.Contains(err.Error(), "update_multi") {
		t.Fatalf("缺少 update_multi 应返回含飞书错误码与消息的错误，实际：%v", err)
	}
}
