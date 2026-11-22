package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/question"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/facts"
	"openxdr/server/internal/questions"
	"openxdr/server/internal/standingrules"
)

type questionRow struct {
	ID            uuid.UUID              `json:"id"`
	Ref           string                 `json:"ref"`
	CreatedAt     time.Time              `json:"createdAt"`
	UpdatedAt     time.Time              `json:"updatedAt"`
	Kind          string                 `json:"kind"`
	SubjectKind   string                 `json:"subjectKind"`
	Subject       string                 `json:"subject"`
	SubjectLabel  string                 `json:"subjectLabel"`
	Status        string                 `json:"status"`
	IncidentCount int                    `json:"incidentCount"`
	FindingCount  int                    `json:"findingCount"`
	AskedCount    int                    `json:"askedCount"`
	Answer        *schema.QuestionAnswer `json:"answer,omitempty"`
	AnsweredBy    *string                `json:"answeredBy,omitempty"`
	AnsweredAt    *time.Time             `json:"answeredAt,omitempty"`
	FactRef       string                 `json:"factRef,omitempty"`
	RuleRef       string                 `json:"ruleRef,omitempty"`
	RuleID        *uuid.UUID             `json:"ruleId,omitempty"`
	// 域名问题：注册域只用于界面分组；Scopes 是作答可选的父域（共享托管、外带、隧道类域为空，只能按完整主机名）
	DomainGroup string   `json:"domainGroup,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	// 同一次结案审计拒绝里一并提出的同类待答问题：作答时可一并答掉
	Siblings []questionSibling `json:"siblings,omitempty"`
}

type questionSibling struct {
	ID           uuid.UUID `json:"id"`
	Ref          string    `json:"ref"`
	SubjectLabel string    `json:"subjectLabel"`
}

type questionDetail struct {
	questionRow
	Evidence  []schema.QuestionEvidence `json:"evidence"`
	Incidents []questionIncident        `json:"incidents"`
	Findings  []questionFinding         `json:"findings"`
}

type questionIncident struct {
	ID     uuid.UUID `json:"id"`
	Title  string    `json:"title"`
	Status string    `json:"status"`
}

type questionFinding struct {
	ID       uuid.UUID `json:"id"`
	Title    string    `json:"title"`
	Hostname string    `json:"hostname"`
	Status   string    `json:"status"`
}

func toQuestionRow(q *ent.Question, names map[uuid.UUID]string) questionRow {
	row := questionRow{ID: q.ID, Ref: questions.Ref(q.ID), CreatedAt: q.CreatedAt, UpdatedAt: q.UpdatedAt, Kind: q.Kind, SubjectKind: q.SubjectKind,
		Subject: q.Subject, SubjectLabel: questions.Label(q.SubjectKind, q.Subject, names), Status: q.Status, IncidentCount: len(q.IncidentIds),
		FindingCount: len(q.FindingIds), AskedCount: q.AskedCount, Answer: q.Answer, AnsweredBy: q.AnsweredBy, AnsweredAt: q.AnsweredAt, RuleID: q.RuleID}
	if id, ok := questions.SubjectAsset(q.SubjectKind, q.Subject); ok && q.SubjectKind == "asset" {
		if h := names[id]; h != "" {
			row.SubjectLabel = h
		}
	}
	if q.SubjectKind == "domain" {
		row.DomainGroup, row.Scopes = questions.RegistrableDomain(q.Subject), questions.DomainScopes(q.Subject)
	}
	if q.SubjectKind == "rule" {
		id := uuid.MustParse(q.Subject)
		row.RuleID = &id
	}
	if q.FactID != nil {
		row.FactRef = facts.Ref("F", *q.FactID)
	}
	if q.RuleID != nil {
		row.RuleRef = standingrules.Ref(*q.RuleID)
	}
	return row
}

func questionAssets(rows ...*ent.Question) []uuid.UUID {
	var ids []uuid.UUID
	for _, q := range rows {
		if id, ok := questions.SubjectAsset(q.SubjectKind, q.Subject); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

// visibleQuestion 平台管理员看全部；其他人只看证据涉及自己所在组的问题
func visibleQuestion(s scope, q *ent.Question) bool {
	return s.all || slices.ContainsFunc(q.GroupIds, func(g uuid.UUID) bool { return slices.Contains(s.groups, g) })
}

// allGroupsInScope 问题涉及的全部组是否都在用户作用域内（用于判断无具体对象引用的公共证据能否透出）
func allGroupsInScope(s scope, groups []uuid.UUID) bool {
	if s.all {
		return true
	}
	if len(groups) == 0 {
		return false
	}
	for _, g := range groups {
		if !slices.Contains(s.groups, g) {
			return false
		}
	}
	return true
}

// filterQuestionEvidence 对非全局 admin 按可见的事件、待办与会话集合裁剪证据，防止跨组问题的证据泄露他组内容。
func filterQuestionEvidence(
	evidence []schema.QuestionEvidence,
	visibleInc, visibleFind, visibleSess map[uuid.UUID]bool,
	allGroupsVisible bool,
) []schema.QuestionEvidence {
	out := make([]schema.QuestionEvidence, 0, len(evidence))
	for _, ev := range evidence {
		if ev.Incident != nil && !visibleInc[*ev.Incident] {
			continue
		}
		if ev.Finding != nil && !visibleFind[*ev.Finding] {
			continue
		}
		if ev.Session != nil && !visibleSess[*ev.Session] {
			continue
		}
		if ev.Incident == nil && ev.Finding == nil && ev.Session == nil && !allGroupsVisible {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// registerQuestionRoutes 总控待答问题：viewer 可看（证据只在这里显示），只有平台管理员能作答；
// 作答在同一事务里写回事实或常设规矩、落审计、把关联待办重新排队。不提供批量作答
func registerQuestionRoutes(mux *http.ServeMux, db *ent.Client) {
	mux.HandleFunc("GET /api/questions", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		status := r.URL.Query().Get("status")
		if status == "" {
			status = "open"
		}
		if !slices.Contains([]string{"open", "answered", "voided"}, status) {
			http.Error(w, "status 只能是 open / answered / voided", http.StatusBadRequest)
			return
		}
		order := ent.Asc(question.FieldCreatedAt)
		if status != "open" {
			order = ent.Desc(question.FieldAnsweredAt)
		}
		rows, err := db.Question.Query().Where(question.StatusEQ(status)).Order(order).Limit(500).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var visible []*ent.Question
		for _, q := range rows {
			if visibleQuestion(s, q) {
				visible = append(visible, q)
			}
		}
		names := hostnamesOf(r.Context(), db, questionAssets(visible...))
		out := make([]questionRow, len(visible))
		batches := map[string][]int{}
		for i, q := range visible {
			out[i] = toQuestionRow(q, names)
			if status == "open" {
				for _, k := range questions.BatchKeys(q) {
					batches[k] = append(batches[k], i)
				}
			}
		}
		for _, members := range batches {
			for _, i := range members {
				for _, j := range members {
					if i != j && !slices.ContainsFunc(out[i].Siblings, func(s questionSibling) bool { return s.ID == out[j].ID }) {
						out[i].Siblings = append(out[i].Siblings, questionSibling{out[j].ID, out[j].Ref, out[j].SubjectLabel})
					}
				}
			}
		}
		writeJSON(w, out)
	})

	mux.HandleFunc("GET /api/questions/{id}", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q, ok := getByPath(w, r, "id", "question", db.Question.Get)
		if !ok {
			return
		}
		if !visibleQuestion(s, q) {
			http.Error(w, "无查看权限", http.StatusForbidden)
			return
		}
		ctx := r.Context()
		d := questionDetail{Evidence: []schema.QuestionEvidence{}, Incidents: []questionIncident{}, Findings: []questionFinding{}}

		// 汇总详情和证据里引用的事件、待办、会话 ID，非全局 admin 按所属组统一过滤，不泄露他组标题/主机名/证据
		incQueryIDs := append([]uuid.UUID(nil), q.IncidentIds...)
		findQueryIDs := append([]uuid.UUID(nil), q.FindingIds...)
		var sessQueryIDs []uuid.UUID
		for _, ev := range q.Evidence {
			if ev.Incident != nil && !slices.Contains(incQueryIDs, *ev.Incident) {
				incQueryIDs = append(incQueryIDs, *ev.Incident)
			}
			if ev.Finding != nil && !slices.Contains(findQueryIDs, *ev.Finding) {
				findQueryIDs = append(findQueryIDs, *ev.Finding)
			}
			if ev.Session != nil && !slices.Contains(sessQueryIDs, *ev.Session) {
				sessQueryIDs = append(sessQueryIDs, *ev.Session)
			}
		}

		visibleInc := map[uuid.UUID]bool{}
		if len(incQueryIDs) > 0 {
			iq := db.Incident.Query().Where(incident.IDIn(incQueryIDs...))
			if !s.all {
				iq = iq.Where(s.incident()...)
			}
			incs, err := iq.Order(ent.Desc(incident.FieldCreatedAt)).All(ctx)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for _, inc := range incs {
				visibleInc[inc.ID] = true
				if !slices.Contains(q.IncidentIds, inc.ID) {
					continue
				}
				title := ""
				if inc.Title != nil {
					title = *inc.Title
				}
				d.Incidents = append(d.Incidents, questionIncident{ID: inc.ID, Title: title, Status: inc.Status})
			}
		}

		visibleFind := map[uuid.UUID]bool{}
		var assets []uuid.UUID
		var rows []*ent.Finding
		if len(findQueryIDs) > 0 {
			fq := db.Finding.Query().Where(finding.IDIn(findQueryIDs...))
			if !s.all {
				fq = fq.Where(finding.GroupIDIn(s.groups...))
			}
			allFindings, err := fq.Order(ent.Desc(finding.FieldLastSeen)).All(ctx)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for _, f := range allFindings {
				visibleFind[f.ID] = true
				if !slices.Contains(q.FindingIds, f.ID) {
					continue
				}
				rows = append(rows, f)
				assets = append(assets, f.AssetID)
			}
		}

		if s.all {
			if q.Evidence != nil {
				d.Evidence = q.Evidence
			}
		} else {
			visibleSess := map[uuid.UUID]bool{}
			if len(sessQueryIDs) > 0 {
				sessIDs, err := db.AgentSession.Query().
					Where(agentsession.IDIn(sessQueryIDs...), agentsession.GroupIDIn(s.groups...)).
					IDs(ctx)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				for _, sid := range sessIDs {
					visibleSess[sid] = true
				}
			}
			d.Evidence = filterQuestionEvidence(q.Evidence, visibleInc, visibleFind, visibleSess, allGroupsInScope(s, q.GroupIds))
		}

		for _, aid := range questionAssets(q) {
			if s.has(aid) {
				assets = append(assets, aid)
			}
		}
		names := hostnamesOf(ctx, db, assets)
		for _, f := range rows {
			d.Findings = append(d.Findings, questionFinding{ID: f.ID, Title: f.Title, Hostname: names[f.AssetID], Status: f.Status})
		}
		d.questionRow = toQuestionRow(q, names)
		if !s.all {
			d.IncidentCount = len(d.Incidents)
			d.FindingCount = len(d.Findings)
		}
		writeJSON(w, d)
	})

	mux.HandleFunc("POST /api/questions/{id}/answer", func(w http.ResponseWriter, r *http.Request) {
		u := auth.From(r.Context())
		cur, err := db.User.Get(r.Context(), u.ID)
		if err != nil || cur.Role != "admin" {
			http.Error(w, "只有平台管理员能作答", http.StatusForbidden)
			return
		}
		q, ok := getByPath(w, r, "id", "question", db.Question.Get)
		if !ok {
			return
		}
		var body questions.AnswerInput
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
		dec.DisallowUnknownFields()
		if dec.Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		// 档位须在规矩模板允许的范围内（如「指向不存在目标的密钥」固定为 human）
		if q.Kind == "policy" && body.Choice == "rule" && body.RuleID != nil {
			rule, err := db.StandingRule.Get(r.Context(), *body.RuleID)
			if err != nil {
				http.Error(w, "常设规矩不存在", http.StatusBadRequest)
				return
			}
			if tpl, ok := standingrules.LookupTemplate(rule.ActionTemplate); ok && !slices.Contains(tpl.AllowedTiers, body.Tier) {
				http.Error(w, "该规矩不允许这个档位", http.StatusBadRequest)
				return
			}
		}
		var out *questions.Outcome
		siblings := 0
		err = withTx(r, db, func(tx *ent.Tx) error {
			var err error
			out, siblings, err = questions.AnswerBatch(r.Context(), tx, q, body, cur.Username, audit.RemoteAddr(r), time.Now())
			return err
		})
		var invalid questions.ErrInvalid
		switch {
		case errors.As(err, &invalid):
			http.Error(w, invalid.Error(), http.StatusBadRequest)
			return
		case errors.Is(err, questions.ErrAnswered):
			http.Error(w, err.Error(), http.StatusConflict)
			return
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		res := map[string]any{"requeuedFindings": out.Findings, "siblingsAnswered": siblings}
		if out.Fact != nil {
			res["factRef"] = facts.Ref("F", out.Fact.ID)
		}
		if out.Rule != nil {
			res["ruleRef"] = standingrules.Ref(out.Rule.ID)
		}
		writeJSON(w, res)
	})
}
