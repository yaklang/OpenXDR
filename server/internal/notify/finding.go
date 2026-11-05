package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/command"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/findings"
)

// sweepFindings 只通知服务端已验证的持续资源风险，不依据模型标题、严重度或普通策略阻塞打扰人。
// 发送成功和落库无法原子提交；崩溃或并发计划变化时可能重推，完整快照 CAS 只保证不覆盖新状态。
func (n *Notifier) sweepFindings(ctx context.Context) error {
	target := n.Settings.Load(ctx)
	if target.URL == "" {
		n.start = time.Time{}
		return nil
	}
	now := time.Now()
	if n.start.IsZero() {
		n.start = now
	}
	// 固定探针确认的持续紧急风险由服务端定为5级，沿用当前渠道数值门槛。
	if target.MinSeverity > 5 {
		return nil
	}
	rows, err := n.DB.Finding.Query().Where(finding.StatusEQ("open"), finding.WorkNotNil(), findingAssetScope(), func(s *sql.Selector) {
		col := s.C(finding.FieldWork)
		s.Where(sql.ExprP(fmt.Sprintf(`%[1]s->>'version' = '2' AND %[1]s->>'risk_kind' IN ('disk_pressure','memory_pressure') AND %[1]s->>'escalated_at' IS NOT NULL AND %[1]s->>'escalation_notified_at' IS NULL`, col)))
		s.Where(sql.P(func(b *sql.Builder) {
			b.WriteString("(" + col + "->>'escalated_at')::timestamptz >= ").Arg(n.start).WriteString(" AND (" + col + "->>'risk_observed_at')::timestamptz >= ").Arg(now.Add(-10 * time.Minute))
		}))
	}).Order(ent.Asc(finding.FieldLastSeen), ent.Asc(finding.FieldID)).Limit(20).All(ctx)
	if err != nil {
		return err
	}
	sender := &Webhook{Settings: n.Settings, Client: n.Client}
	for _, f := range rows {
		now = time.Now()
		var w findings.Work
		if json.Unmarshal(f.Work, &w) != nil || !validFindingEscalation(f, &w, n.start, now) {
			continue
		}
		valid, err := n.findingRiskReceipt(ctx, f, &w, now)
		if err != nil {
			return err
		}
		if !valid {
			continue
		}
		// 出网前再次核对完整计划和资产归组；不能把已转组或人工关闭的旧快照发出去。
		current, err := n.DB.Finding.Query().Where(finding.IDEQ(f.ID), finding.GroupIDEQ(f.GroupID), finding.AssetIDEQ(f.AssetID), finding.StatusEQ("open"), findings.Snapshot(f), findingAssetScope()).Exist(ctx)
		if err != nil {
			return err
		}
		if !current {
			continue
		}
		a, err := n.DB.Asset.Get(ctx, f.AssetID)
		if err != nil {
			return err
		}
		problem := "根分区持续容量压力"
		if w.RiskKind == "memory_pressure" {
			problem = "内存与交换空间持续压力"
		}
		refs := make([]string, 0, len(w.EvidenceCommands))
		for _, id := range w.EvidenceCommands {
			refs = append(refs, id.String())
		}
		body := fmt.Sprintf("主机：%s\n风险：%s\n持续观测：%s 至 %s（UTC）\n依据：固定只读探针的真实成功回执 %s\n平台继续自治跟进；本通知不代表已经修复。", a.Hostname, problem, w.RiskSince.UTC().Format(time.RFC3339), w.RiskObservedAt.UTC().Format(time.RFC3339), strings.Join(refs, ", "))
		err = sender.SendTo(ctx, target, "紧急运维风险："+problem, body, "/?finding="+f.ID.String())
		n.Settings.Record(ctx, err)
		if err != nil {
			return err
		}
		sent := time.Now()
		w.EscalationNotifiedAt = &sent
		// 网络成功不赋予旧快照写权限：保留并发修复次数、计划与人工终态。
		_, err = n.DB.Finding.Update().Where(finding.IDEQ(f.ID), finding.GroupIDEQ(f.GroupID), finding.AssetIDEQ(f.AssetID), finding.StatusEQ("open"), findings.Snapshot(f), findingAssetScope()).SetWork(findings.EncodeWork(w)).Save(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

func findingAssetScope() predicate.Finding {
	return func(s *sql.Selector) {
		a := sql.Table(asset.Table).As("finding_notice_asset")
		s.Where(sql.Exists(sql.Select(a.C(asset.FieldID)).From(a).Where(sql.And(sql.ColumnsEQ(a.C(asset.FieldID), s.C(finding.FieldAssetID)), sql.ColumnsEQ(a.C(asset.FieldGroupID), s.C(finding.FieldGroupID))))))
	}
}

func validFindingEscalation(f *ent.Finding, w *findings.Work, start, now time.Time) bool {
	if w.Version != 2 || w.EscalatedAt == nil || w.EscalationNotifiedAt != nil || w.EvidenceStale || w.EvidenceAt == nil || w.RiskSince == nil || w.RiskObservedAt == nil || w.RiskTarget == nil || w.RiskTarget.AssetID != f.AssetID || len(w.EvidenceCommands) == 0 || len(w.EvidenceCommands) > 5 {
		return false
	}
	if w.EscalatedAt.Before(w.RiskSince.Add(10*time.Minute)) || w.EscalatedAt.Before(start) || w.EscalatedAt.After(now) || w.EscalatedAt.After(*w.RiskObservedAt) || w.RiskObservedAt.After(now) || w.RiskObservedAt.Before(now.Add(-10*time.Minute)) || w.EvidenceAt.After(now) || w.EvidenceAt.Before(now.Add(-10*time.Minute)) || w.EvidenceAt.Before(*w.RiskObservedAt) || w.RiskSince.After(w.RiskObservedAt.Add(-10*time.Minute)) {
		return false
	}
	return w.RiskKind == "disk_pressure" && w.RiskTarget.Kind == "disk_root" && w.RiskTarget.Mount == "/" || w.RiskKind == "memory_pressure" && w.RiskTarget.Kind == "memory" && w.RiskTarget.Mount == ""
}

func (n *Notifier) findingRiskReceipt(ctx context.Context, f *ent.Finding, w *findings.Work, now time.Time) (bool, error) {
	probe := "df -P /"
	if w.RiskKind == "memory_pressure" {
		probe = "free -b"
	}
	seen := map[uuid.UUID]bool{}
	matched := false
	for _, id := range w.EvidenceCommands {
		if id == uuid.Nil || seen[id] {
			return false, nil
		}
		seen[id] = true
		c, err := n.DB.Command.Query().Where(command.IDEQ(id), command.AssetIDEQ(f.AssetID)).Only(ctx)
		if ent.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if c.Kind != "exec" || c.Status != "succeeded" || c.CompletedAt == nil || c.CreatedAt.After(now) || c.CompletedAt.Before(c.CreatedAt) || c.CompletedAt.After(now) || c.CompletedAt.Before(now.Add(-10*time.Minute)) || c.Truncated || c.ExitCode == nil || *c.ExitCode != 0 || c.Stdout == nil || strings.TrimSpace(*c.Stdout) == "" || len(*c.Stdout) > 8192 || c.Stderr != nil && strings.TrimSpace(*c.Stderr) != "" {
			return false, nil
		}
		if c.Cmd != nil && *c.Cmd == probe && c.CompletedAt.After(*w.RiskObservedAt) {
			return false, nil
		}
		if c.Cmd != nil && *c.Cmd == probe && c.CompletedAt.Equal(*w.RiskObservedAt) {
			matched = true
		}
	}
	if !matched {
		return false, nil
	}
	// 不能只引用旧的高压回执；更晚的同目标探针（包括待确认投递）要求先核对新观测。
	newer, err := n.DB.Command.Query().Where(command.AssetIDEQ(f.AssetID), command.KindEQ("exec"), command.CmdEQ(probe),
		command.Or(command.CompletedAtGT(*w.RiskObservedAt), command.And(command.StatusIn("pending", "sent", "unknown"), command.CreatedAtGT(*w.RiskObservedAt)))).Exist(ctx)
	if err != nil {
		return false, err
	}
	return !newer, nil
}
