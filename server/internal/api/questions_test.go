package api

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/schema"
)

func TestFilterQuestionEvidenceCrossGroup(t *testing.T) {
	incA, incB := uuid.New(), uuid.New()
	findA, findB := uuid.New(), uuid.New()
	sessA, sessB := uuid.New(), uuid.New()

	evidence := []schema.QuestionEvidence{
		{At: time.Now(), Source: "ask_controller", Incident: &incA, Note: "组A事件证据"},
		{At: time.Now(), Source: "ask_controller", Incident: &incB, Note: "组B事件机密"},
		{At: time.Now(), Source: "ask_controller", Finding: &findA, Note: "组A待办证据"},
		{At: time.Now(), Source: "ask_controller", Finding: &findB, Note: "组B待办机密"},
		{At: time.Now(), Source: "ask_controller", Session: &sessA, Note: "组A会话证据"},
		{At: time.Now(), Source: "ask_controller", Session: &sessB, Note: "组B会话机密"},
		{At: time.Now(), Source: "ask_controller", Incident: &incA, Finding: &findB, Note: "跨组混合引用"},
		{At: time.Now(), Source: "standing_rule", Note: "无对象引用公共证据"},
	}

	visInc := map[uuid.UUID]bool{incA: true}
	visFind := map[uuid.UUID]bool{findA: true}
	visSess := map[uuid.UUID]bool{sessA: true}

	// 跨组问题：只保留明确归属当前组可见对象的 3 条，公共无归属证据与他组/混合引用均裁掉
	gotCross := filterQuestionEvidence(evidence, visInc, visFind, visSess, false)
	if len(gotCross) != 3 {
		t.Fatalf("跨组问题应只保留 3 条本组证据，实际 %d: %+v", len(gotCross), gotCross)
	}
	for _, ev := range gotCross {
		if ev.Note != "组A事件证据" && ev.Note != "组A待办证据" && ev.Note != "组A会话证据" {
			t.Errorf("不应透出非本组证据: %+v", ev)
		}
	}

	// 单组问题（问题所有组都在当前用户作用域内）：保留公共无归属证据
	gotSingle := filterQuestionEvidence(evidence, visInc, visFind, visSess, true)
	if len(gotSingle) != 4 {
		t.Fatalf("单组问题应保留 4 条（含公共无归属证据），实际 %d", len(gotSingle))
	}
}

func TestAllGroupsInScope(t *testing.T) {
	gA, gB := uuid.New(), uuid.New()
	s := scope{groups: []uuid.UUID{gA}}
	if !allGroupsInScope(s, []uuid.UUID{gA}) {
		t.Fatal("仅含本组应返回 true")
	}
	if allGroupsInScope(s, []uuid.UUID{gA, gB}) {
		t.Fatal("跨他组应返回 false")
	}
	if allGroupsInScope(s, nil) {
		t.Fatal("无组列表对非全局 admin 应返回 false")
	}
	if !allGroupsInScope(scope{all: true}, []uuid.UUID{gA, gB}) {
		t.Fatal("全局 admin 应返回 true")
	}
}
