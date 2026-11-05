// Package incidentwork 保存服务端自治责任、后续调查预算和唤醒条件，不把缺证冒充已解决。
package incidentwork

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/schema"
	decoyrule "openxdr/server/internal/decoy"
)

const MaxAttempts = 3
const FollowupDelay = 6 * time.Hour

func EvidenceKey(inc *ent.Incident) string {
	t := inc.CreatedAt
	for _, at := range []*time.Time{inc.EvidenceAt, inc.UrgentAt} {
		if at != nil && at.After(t) {
			t = *at
		}
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// Plan 只根据服务端已落库的结论及告警级别决定责任，不接受模型自报 owner。
func Plan(inc *ent.Incident, severity int, decoy bool, now time.Time) (*schema.IncidentWork, *time.Time) {
	w := &schema.IncidentWork{Version: 1, Owner: "ai", Stage: "monitoring", EvidenceKey: EvidenceKey(inc), WakeOn: []string{"new_evidence", "capability_upgrade"}, Reason: "持续监测；新证据到达后重研判"}
	if inc.TriagedAt != nil {
		w.VerdictAt = *inc.TriagedAt
	}
	var v struct {
		Verdict string   `json:"verdict"`
		Actions []string `json:"action_codes"`
		Tier    string   `json:"response_tier"`
	}
	err := json.Unmarshal(inc.AiVerdict, &v)
	var ledger struct {
		Queries []struct {
			Tool  string             `json:"tool"`
			Facts schema.WorkReceipt `json:"facts"`
		} `json:"query_evidence"`
	}
	_ = json.Unmarshal(inc.AiVerdict, &ledger)
	gap := slices.Contains(v.Actions, "collect_original_records")
	if gap {
		w.GapKind = "evidence_unavailable"
	}
	if inc.Work != nil && inc.Work.EvidenceKey == w.EvidenceKey {
		w.Attempts = inc.Work.Attempts
		w.Receipts = append(w.Receipts, inc.Work.Receipts...)
	}
	for _, q := range ledger.Queries {
		if q.Tool == "collect_endpoint_evidence" && (q.Facts.CommandID != "" || q.Facts.Template != "") {
			duplicate := false
			for _, prior := range w.Receipts {
				if prior == q.Facts {
					duplicate = true
				}
			}
			if !duplicate && len(w.Receipts) < 32 {
				w.Receipts = append(w.Receipts, q.Facts)
			}
		}
	}
	switch {
	case inc.Status == "closed" || inc.Status == "false_positive":
		w.Stage = "completed"
		w.Reason = "事件已结案"
		return w, nil
	case err != nil || inc.TriagedAt == nil || inc.Status == "open":
		w.Stage = "investigating"
		w.Reason = "等待研判队列调查"
		return w, nil
	case decoy || v.Verdict == "malicious" || v.Tier == "contain" || v.Tier == "isolate" || slices.Contains(v.Actions, "review_response") || v.Verdict == "suspicious" && severity >= 4:
		w.Owner = "human"
		w.Stage = "escalated"
		w.Reason = "高危可疑、恶意、响应决策或人工指定复核"
		return w, nil
	case v.Verdict != "benign" && v.Verdict != "suspicious":
		w.Owner = "human"
		w.Stage = "escalated"
		w.Reason = "研判结论不可用"
		return w, nil
	case gap && w.Attempts < MaxAttempts:
		w.Stage = "followup"
		w.Reason = "缺证由自治队列有界跟进，不按误报结案"
		next := now.Add(FollowupDelay * time.Duration(1<<w.Attempts))
		return w, &next
	case gap:
		w.Reason = "本证据版本调查预算耗尽；保留缺口，等待新证据或能力变化"
	}
	return w, nil
}

// Refresh 在研判落库的同一事务内调用；只更新仍对应同一研判快照的事件。
func Refresh(ctx context.Context, db *ent.Client, inc *ent.Incident, now time.Time) error {
	alerts, err := db.Alert.Query().Where(alert.IncidentIDEQ(inc.ID)).All(ctx)
	if err != nil {
		return err
	}
	severity := 0
	decoy := false
	for _, a := range alerts {
		severity = max(severity, int(a.Severity))
		if strings.HasPrefix(a.RuleID, decoyrule.ObservationRulePrefix) {
			decoy = true
		}
	}
	w, next := Plan(inc, severity, decoy, now)
	upd := db.Incident.UpdateOneID(inc.ID).Where(incident.StatusEQ(inc.Status)).SetWork(w).SetNillableWorkNextCheckAt(next)
	if next == nil {
		upd.ClearWorkNextCheckAt()
	}
	if inc.Work == nil {
		upd.Where(incident.WorkIsNil())
	} else {
		raw, err := json.Marshal(inc.Work)
		if err != nil {
			return err
		}
		upd.Where(workEquals(string(raw)))
	}
	if inc.TriagedAt != nil {
		upd.Where(incident.TriagedAtEQ(*inc.TriagedAt))
	} else {
		upd.Where(incident.TriagedAtIsNil())
	}
	if inc.EvidenceAt != nil {
		upd.Where(incident.EvidenceAtEQ(*inc.EvidenceAt))
	} else {
		upd.Where(incident.EvidenceAtIsNil())
	}
	if inc.UrgentAt != nil {
		upd.Where(incident.UrgentAtEQ(*inc.UrgentAt))
	} else {
		upd.Where(incident.UrgentAtIsNil())
	}
	return upd.Exec(ctx)
}

// Reconcile 接管历史事件并撤销过期提案；分页限额，不修改证据时间或既有结论。
func Reconcile(ctx context.Context, db *ent.Client, now time.Time) error {
	rows, err := db.Incident.Query().Where(incident.StatusIn("open", "triaged"), incident.Or(incident.TriageStartedAtIsNil(), incident.TriageHeartbeatAtIsNil(), incident.TriageHeartbeatAtLTE(now.Add(-time.Minute))), needsRefresh()).Order(ent.Asc(incident.FieldID)).Limit(100).All(ctx)
	if err != nil {
		return err
	}
	for _, inc := range rows {
		if inc.ClosureProposal != nil && StaleProposal(inc) {
			if err := clearStaleProposal(ctx, db, inc); err != nil {
				return err
			}
		}
		if inc.Work == nil || inc.TriagedAt != nil && !inc.Work.VerdictAt.Equal(*inc.TriagedAt) || inc.Work.EvidenceKey != EvidenceKey(inc) || inc.Work.Stage == "followup" && (inc.Work.Attempts >= MaxAttempts || inc.WorkNextCheckAt == nil) {
			if err := Refresh(ctx, db, inc, now); err != nil && !ent.IsNotFound(err) {
				return err
			}
		}
	}
	return nil
}

func StaleProposal(inc *ent.Incident) bool {
	p := inc.ClosureProposal
	if p == nil {
		return false
	}
	for _, at := range []*time.Time{inc.TriagedAt, inc.EvidenceAt, inc.UrgentAt} {
		if at != nil && at.After(p.At) {
			return true
		}
	}
	return false
}

func clearStaleProposal(ctx context.Context, db *ent.Client, inc *ent.Incident) error {
	// 以完整建议 JSON 比较保护并发替换的新建议。
	raw, err := json.Marshal(inc.ClosureProposal)
	if err != nil {
		return err
	}
	_, err = db.Incident.Update().Where(incident.IDEQ(inc.ID), incident.StatusIn("open", "triaged"), proposalEquals(string(raw))).ClearClosureProposal().Save(ctx)
	return err
}
