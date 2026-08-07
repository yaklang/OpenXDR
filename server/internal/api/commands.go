package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entcommand "openxdr/server/ent/command"
	"openxdr/server/internal/response"
)

type commandRow struct {
	ID          uuid.UUID  `json:"id"`
	CreatedAt   time.Time  `json:"createdAt"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	DryRun      bool       `json:"dryRun"`
	AssetID     uuid.UUID  `json:"assetId"`
	IncidentID  *uuid.UUID `json:"incidentId"`
	IssuedBy    string     `json:"issuedBy"`
	Detail      *string    `json:"detail"`
	CompletedAt *time.Time `json:"completedAt"`
}

func toRow(c *ent.Command) commandRow {
	return commandRow{
		ID: c.ID, CreatedAt: c.CreatedAt, Kind: c.Kind, Status: c.Status,
		DryRun: c.DryRun, AssetID: c.AssetID, IncidentID: c.IncidentID,
		IssuedBy: c.IssuedBy, Detail: c.Detail, CompletedAt: c.CompletedAt,
	}
}

type issueBody struct {
	Kind string `json:"kind"`
	// 指针以便区分"没传"和"显式传 false"：没传一律按 dry-run 处理
	DryRun      *bool      `json:"dryRun"`
	AssetID     uuid.UUID  `json:"assetId"`
	IncidentID  *uuid.UUID `json:"incidentId"`
	ProcessGUID *uuid.UUID `json:"processGuid"`
	PID         uint32     `json:"pid"`
}

func mapCommands(api *http.ServeMux, db *ent.Client, hub *response.Hub, selfEndpoints []string) {
	api.HandleFunc("POST /api/commands", func(w http.ResponseWriter, r *http.Request) {
		var body issueBody
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
			return
		}
		if _, ok := response.Kinds[body.Kind]; !ok {
			http.Error(w, "kind 必须是 kill_process / isolate_host / unisolate_host", http.StatusBadRequest)
			return
		}
		// 不传就是演练。真执行必须显式写明，绝不默认动手
		dryRun := true
		if body.DryRun != nil {
			dryRun = *body.DryRun
		}

		req := response.Request{
			AssetID:     body.AssetID,
			Kind:        body.Kind,
			DryRun:      dryRun,
			IncidentID:  body.IncidentID,
			ProcessGUID: body.ProcessGUID,
			PID:         body.PID,
			IssuedBy:    issuer(r),
		}
		// 隔离必须放行 server 自身，否则 agent 失联后再也解除不了
		if body.Kind == "isolate_host" {
			req.AllowEndpoints = selfEndpoints
		}

		cmd, err := hub.Issue(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		writeJSON(w, toRow(cmd))
	})

	api.HandleFunc("GET /api/commands", func(w http.ResponseWriter, r *http.Request) {
		q := db.Command.Query()
		if v := r.URL.Query().Get("incidentId"); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				http.Error(w, "无效的 incidentId", http.StatusBadRequest)
				return
			}
			q = q.Where(entcommand.IncidentIDEQ(id))
		}
		cmds, err := q.Order(ent.Desc(entcommand.FieldCreatedAt)).Limit(100).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]commandRow, len(cmds))
		for i, c := range cmds {
			out[i] = toRow(c)
		}
		writeJSON(w, out)
	})
}

// issuer 记录下发者。目前没有认证体系，退回调用方地址，
// 至少让审计能追到来源；接入认证后换成用户身份。
func issuer(r *http.Request) string {
	if u := r.Header.Get("X-OpenXDR-User"); u != "" {
		return u
	}
	return r.RemoteAddr
}
