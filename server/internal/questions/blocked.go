package questions

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/finding"
	"openxdr/server/internal/findings"
)

// humanBlockers 只有人能解的机器阻塞：动作不在封闭修复模板里、缺维护授权、修复预算用完。冷却与探针失效会自己恢复，不问
var humanBlockers = []string{"action_unsupported", "policy_required", "budget_exhausted"}

// BlockedSweep 卡在 humanBlockers、又没挂问题的待办不能静默等着：每条待办提一个变更类问题（主题是主机加待办编号，
// 作答只回答这一条），问题编号写进 work.question，作答后 requeue 把待办交回平台重新评估。
// 已经答过、待办仍卡在原处的不再重复提问：答案已写进计划，交给待办自己的跟进
func BlockedSweep(ctx context.Context, db *ent.Client, now time.Time) (int, error) {
	rows, err := db.Finding.Query().Where(finding.StatusEQ("open")).Order(ent.Asc(finding.FieldFirstSeen)).Limit(500).All(ctx)
	if err != nil {
		return 0, err
	}
	asked := 0
	for _, f := range rows {
		var w findings.Work
		if json.Unmarshal(f.Work, &w) != nil || w.Stage != "blocked" || w.Question != "" || !slices.Contains(humanBlockers, w.Blocker) {
			continue
		}
		req := Request{Kind: "policy", SubjectKind: "change", Subject: ChangeSubject(f.AssetID, "finding-"+f.ID.String()),
			Groups: []uuid.UUID{f.GroupID}, Assets: []uuid.UUID{f.AssetID}, Finding: &f.ID, Source: "finding_blocked",
			Note: f.Title + "：" + w.BlockerDetail, CreatedBy: "system"}
		if w.Blocker == "policy_required" {
			req.Kind = "authorization"
		}
		known, err := Lookup(ctx, db, req, now)
		if err != nil {
			return asked, err
		}
		if known.Answered {
			continue
		}
		res, err := Ask(ctx, db, req, now)
		if err != nil {
			return asked, err
		}
		if res.Question == nil {
			continue
		}
		w.Question = Ref(res.Question.ID)
		n, err := db.Finding.Update().Where(finding.IDEQ(f.ID), finding.StatusEQ("open"), findings.Snapshot(f)).SetWork(findings.EncodeWork(w)).Save(ctx)
		if err != nil {
			return asked, err
		}
		asked += n
	}
	return asked, nil
}
