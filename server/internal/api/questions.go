package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
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
	if q.SubjectKind == "asset" || q.SubjectKind == "change" {
		if h := names[uuid.MustParse(q.Subject)]; h != "" {
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
		if q.SubjectKind == "asset" || q.SubjectKind == "change" {
			ids = append(ids, uuid.MustParse(q.Subject))
		}
	}
	return ids
}

// visibleQuestion 平台管理员看全部；其他人只看证据涉及自己所在组的问题
func visibleQuestion(s scope, q *ent.Question) bool {
	return s.all || slices.ContainsFunc(q.GroupIds, func(g uuid.UUID) bool { return slices.Contains(s.groups, g) })
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
		for i, q := range visible {
			out[i] = toQuestionRow(q, names)
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
		d := questionDetail{Evidence: q.Evidence, Incidents: []questionIncident{}, Findings: []questionFinding{}}
		if d.Evidence == nil {
			d.Evidence = []schema.QuestionEvidence{}
		}
		if len(q.IncidentIds) > 0 {
			incs, err := db.Incident.Query().Where(incident.IDIn(q.IncidentIds...)).Order(ent.Desc(incident.FieldCreatedAt)).All(ctx)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for _, inc := range incs {
				title := ""
				if inc.Title != nil {
					title = *inc.Title
				}
				d.Incidents = append(d.Incidents, questionIncident{ID: inc.ID, Title: title, Status: inc.Status})
			}
		}
		var assets []uuid.UUID
		var rows []*ent.Finding
		if len(q.FindingIds) > 0 {
			var err error
			if rows, err = db.Finding.Query().Where(finding.IDIn(q.FindingIds...)).Order(ent.Desc(finding.FieldLastSeen)).All(ctx); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for _, f := range rows {
				assets = append(assets, f.AssetID)
			}
		}
		names := hostnamesOf(ctx, db, append(assets, questionAssets(q)...))
		for _, f := range rows {
			d.Findings = append(d.Findings, questionFinding{ID: f.ID, Title: f.Title, Hostname: names[f.AssetID], Status: f.Status})
		}
		d.questionRow = toQuestionRow(q, names)
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
		err = withTx(r, db, func(tx *ent.Tx) error {
			var err error
			out, err = questions.Answer(r.Context(), tx, q.ID, body, cur.Username, audit.RemoteAddr(r), time.Now())
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
		res := map[string]any{"requeuedFindings": out.Findings}
		if out.Fact != nil {
			res["factRef"] = facts.Ref("F", out.Fact.ID)
		}
		if out.Rule != nil {
			res["ruleRef"] = standingrules.Ref(out.Rule.ID)
		}
		writeJSON(w, res)
	})
}
