//go:build integration

package closurereview

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/question"
	"openxdr/server/internal/facts"
	"openxdr/server/internal/questions"
)

// 单项变更的批准不能让同主机高危良性获得送审资格；资产角色与主机级已授权变更照旧可以，单项变更只作上下文
func TestSingleChangeApprovalIsNotHostCoverage(t *testing.T) {
	f := setupBenign(t)
	f.db.Alert.UpdateOneID(f.al.ID).SetSeverity(4).ExecX(f.ctx)
	single := f.db.Fact.Create().SetKind("change").SetAssetID(f.asset.ID).SetGroupID(f.group.ID).
		SetSubject("authorization:change:" + f.asset.ID.String() + "/retire-cyberedge-agent").SetContent("授权：仅这一项变更（retire-cyberedge-agent）：退役").SetCreatedBy("admin").SaveX(f.ctx)
	legacy := f.db.Fact.Create().SetKind("change").SetAssetID(f.asset.ID).SetGroupID(f.group.ID).
		SetSubject("authorization:change:" + f.asset.ID.String()).SetContent("授权：存量单项变更").SetCreatedBy("admin").SaveX(f.ctx)
	if refs, _ := facts.HostRefs(f.ctx, f.db, f.asset.ID, time.Now()); len(refs) != 0 {
		t.Fatalf("单项变更不算主机兜底：%v", refs)
	}
	if ok, err := f.r.Review(f.ctx, f.inc.ID); ok || err != nil || f.calls != 0 {
		t.Fatal("只有单项变更批准的高危良性不送审", ok, err, f.calls)
	}
	for name, mk := range map[string]func() string{
		"资产角色": func() string {
			return facts.Ref("F", f.db.Fact.Create().SetKind("asset_role").SetAssetID(f.asset.ID).SetContent("包管理更新是业务").SetCreatedBy("admin").SaveX(f.ctx).ID)
		},
		"主机级已授权变更": func() string {
			return facts.Ref("F", f.db.Fact.Create().SetKind("change").SetAssetID(f.asset.ID).SetContent("本机日常更新").SetCreatedBy("admin").SaveX(f.ctx).ID)
		},
	} {
		ref := mk()
		var material string
		f.r.Judge = func(_ context.Context, _ string, m string) (Decision, error) {
			f.calls++
			material = m
			return Decision{Reason: "保持事件，等待更多正面证据"}, nil
		}
		calls := f.calls
		if _, err := f.r.Review(f.ctx, f.inc.ID); err != nil || f.calls != calls+1 {
			t.Fatalf("%s 应让事件送审：%v", name, err)
		}
		if !strings.Contains(material, ref) {
			t.Fatalf("%s 进 severe_hosts", name)
		}
		var m struct {
			Benign struct {
				Severe []struct {
					Facts []string `json:"facts"`
				} `json:"severe_hosts"`
			} `json:"benign"`
		}
		_ = json.Unmarshal([]byte(material), &m)
		for _, s := range m.Benign.Severe {
			for _, r := range s.Facts {
				if r == facts.Ref("F", single.ID) || r == facts.Ref("F", legacy.ID) {
					t.Fatalf("单项变更不进 severe_hosts：%v", s.Facts)
				}
			}
		}
		f.db.Fact.Update().Where().SetRetiredAt(time.Now()).ExecX(f.ctx)
		f.db.Fact.UpdateOneID(single.ID).ClearRetiredAt().ExecX(f.ctx)
		f.db.Fact.UpdateOneID(legacy.ID).ClearRetiredAt().ExecX(f.ctx)
	}
}

// 审计员因目标不在已登记事实范围拒绝时给出结构化缺口：服务端核对对象在材料里出现过才提问，按完整主机名合并；
// 管理员作答后新事实进入材料，快照变化，审计员按新事实重审
func TestMissingFactAsksControllerAndReReviews(t *testing.T) {
	f := setupBenign(t)
	cmd := "/usr/bin/nmap -sV scan.gzmpc.com"
	raw, _ := json.Marshal(map[string]any{"activity_id": 1, "process": map[string]any{"cmd_line": cmd, "pid": 42}})
	f.db.Event.UpdateOneID(f.ev.ID).SetRaw(raw).ExecX(f.ctx)
	var material string
	f.r.Judge = func(_ context.Context, _ string, m string) (Decision, error) {
		f.calls++
		material = m
		return Decision{Reason: "扫描目标 scan.gzmpc.com 不在已登记的授权范围内", MissingFacts: []MissingFact{
			{Kind: "authorization", SubjectKind: "domain", Subject: "scan.gzmpc.com"},
			{Kind: "authorization", SubjectKind: "domain", Subject: "not-in-material.example"},
			{Kind: "owner", SubjectKind: "asset", Subject: f.asset.Hostname},
		}}, nil
	}
	if ok, err := f.r.Review(f.ctx, f.inc.ID); ok || err != nil || f.calls != 1 {
		t.Fatal(ok, err, f.calls)
	}
	qs := f.db.Question.Query().Order(question.ByCreatedAt()).AllX(f.ctx)
	if len(qs) != 2 {
		t.Fatalf("材料里没有的对象不提问：%d", len(qs))
	}
	var domainQ uuid.UUID
	for _, q := range qs {
		if len(q.IncidentIds) != 1 || q.IncidentIds[0] != f.inc.ID || len(q.GroupIds) != 1 || q.GroupIds[0] != f.group.ID || q.CreatedBy != Actor {
			t.Fatalf("问题要关联事件与组：%+v", q)
		}
		switch q.SubjectKind {
		case "domain":
			domainQ = q.ID
			if q.Subject != "scan.gzmpc.com" || q.Kind != "authorization" {
				t.Fatalf("域名按完整主机名提问：%+v", q)
			}
		case "asset":
			if q.Subject != f.asset.ID.String() {
				t.Fatalf("主机名换成资产 ID：%+v", q)
			}
		}
	}
	// 同快照不重审，也不重复提问
	if _, err := f.r.Review(f.ctx, f.inc.ID); err != nil || f.calls != 1 {
		t.Fatal(err, f.calls)
	}
	txn, err := f.db.Tx(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	out, err := questions.Answer(f.ctx, txn, domainQ, questions.AnswerInput{Choice: "grant", Content: "SoulRaid 红队授权测试", Scope: "gzmpc.com"}, "admin", "", time.Now())
	if err != nil {
		_ = txn.Rollback()
		t.Fatal(err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.r.Review(f.ctx, f.inc.ID); err != nil || f.calls != 2 {
		t.Fatal("作答后快照变化应重审", err, f.calls)
	}
	if !strings.Contains(material, facts.Ref("F", out.Fact.ID)) {
		t.Fatal("新事实要进审计材料", material)
	}
}

func TestMissingFactAbbreviatedKeyFingerprint(t *testing.T) {
	const (
		fpRoyal = "SHA256:mtwVQQEIr75wGTFfVAuMn6y/LsfD5ULsqChRXqfXqJY"
		fpAmb1  = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
		fpAmb2  = "SHA256:47DEQpBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	)
	f := setupBenign(t)
	raw, _ := json.Marshal(map[string]any{
		"activity_id":   1,
		"process":       map[string]any{"cmd_line": "/usr/bin/id", "pid": 99},
		"login_session": map[string]any{"user": "root", "src_ip": "10.1.1.35", "key_fp": fpRoyal},
		"other_keys":    []string{fpAmb1, fpAmb2},
	})
	f.db.Event.UpdateOneID(f.ev.ID).SetRaw(raw).ExecX(f.ctx)
	f.r.Judge = func(_ context.Context, _ string, _ string) (Decision, error) {
		f.calls++
		return Decision{Reason: "SSH 公钥归属尚未登记，暂不自动结案", MissingFacts: []MissingFact{
			{Kind: "owner", SubjectKind: "key", Subject: "SHA256:mtwVQQ…"},
			{Kind: "owner", SubjectKind: "key", Subject: "SHA256:47DEQp..."},
			{Kind: "owner", SubjectKind: "key", Subject: "SHA256:NcQW5H…"},
		}}, nil
	}
	if ok, err := f.r.Review(f.ctx, f.inc.ID); ok || err != nil || f.calls != 1 {
		t.Fatal(ok, err, f.calls)
	}
	qs := f.db.Question.Query().AllX(f.ctx)
	if len(qs) != 1 || qs[0].SubjectKind != "key" || qs[0].Subject != fpRoyal {
		t.Fatalf("唯一命中的缩写钥匙指纹应补全为完整指纹建问题，零命中与多命中应丢弃: %+v", qs)
	}
}
