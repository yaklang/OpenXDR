package agentchat

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/findings"
)

// 风险类别只作探针路由；是否紧急始终由实际回执数值和持续时间决定。
func bindFindingRiskTarget(f *ent.Finding, w *findings.Work) {
	if w.RiskTarget != nil {
		return
	}
	original := strings.ToLower(w.OriginalTitle + " " + w.OriginalProblem)
	if original == " " {
		original = strings.ToLower(f.Title + " " + f.Detail)
	}
	switch {
	case strings.Contains(original, "根分区") || strings.Contains(original, "根盘") || strings.Contains(original, "root filesystem"):
		w.RiskTarget = &findings.RiskTarget{Kind: "disk_root", Mount: "/", AssetID: f.AssetID}
	case strings.Contains(original, "内存") || strings.Contains(original, "swap") || strings.Contains(original, "memory"):
		w.RiskTarget = &findings.RiskTarget{Kind: "memory", AssetID: f.AssetID}
	}
}

func (s *Service) updateFindingRisk(ctx context.Context, session *ent.AgentSession, f *ent.Finding, w *findings.Work, ids []uuid.UUID) (bool, error) {
	if len(ids) == 0 {
		return false, nil
	}
	bindFindingRiskTarget(f, w)
	snapshot := *f
	snapshot.Work = findings.EncodeWork(*w)
	kind, observed, err := s.findingRisk(ctx, session, &snapshot, ids)
	if err != nil {
		return false, err
	}
	if kind == "" {
		return false, nil
	}
	if w.RiskObservedAt != nil && !observed.After(*w.RiskObservedAt) {
		return false, nil
	}
	if kind == "disk_ok" || kind == "memory_ok" {
		w.RiskKind = ""
		w.RiskSince = nil
		w.RiskObservedAt = &observed
		return false, nil
	}
	if w.RiskSince == nil || w.RiskKind != kind || w.RiskObservedAt == nil || observed.Sub(*w.RiskObservedAt) > 2*time.Hour {
		w.RiskSince = &observed
	}
	w.RiskKind = kind
	w.RiskObservedAt = &observed
	if w.EscalatedAt == nil && observed.Sub(*w.RiskSince) >= 10*time.Minute {
		w.EscalatedAt = &observed
		return true, nil
	}
	return false, nil
}

func readFindingWork(f *ent.Finding) findings.Work {
	var w findings.Work
	_ = json.Unmarshal(f.Work, &w)
	return w
}
