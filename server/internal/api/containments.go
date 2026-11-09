package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	entcommand "openxdr/server/ent/command"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/containment"
	"openxdr/server/internal/response"
)

// Containments 自主响应的决策记录、熔断状态、开关与人工解除。engine 为 nil 表示没开 RESPONSE_ENABLED（记录照样可查、可解除）
func Containments(db *ent.Client, hub *response.Hub, engine *containment.Engine, config *containment.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/containments", listContainments(db))
	mux.HandleFunc("GET /api/containments/status", containmentStatus(db, engine))
	mux.HandleFunc("PUT /api/containments/config", saveContainmentConfig(db, engine, config))
	mux.HandleFunc("POST /api/containments/{id}/lift", liftContainment(db, hub, engine))
	mux.HandleFunc("POST /api/containments/{id}/approve", decideContainment(db, engine, true))
	mux.HandleFunc("POST /api/containments/{id}/decline", decideContainment(db, engine, false))
	return mux
}

type containmentRow struct {
	ID             uuid.UUID  `json:"id"`
	CreatedAt      time.Time  `json:"createdAt"`
	AssetID        uuid.UUID  `json:"assetId"`
	AssetHostname  string     `json:"assetHostname"`
	Kind           string     `json:"kind"`
	Target         string     `json:"target"`
	PID            uint32     `json:"pid,omitempty"`
	Signal         string     `json:"signal"`
	AlertID        uuid.UUID  `json:"alertId"`
	IncidentID     *uuid.UUID `json:"incidentId"`
	SourceHostname string     `json:"sourceHostname,omitempty"`
	Role           string     `json:"role"`
	State          string     `json:"state"`
	Reason         string     `json:"reason"`
	CommandID      *uuid.UUID `json:"commandId"`
	CommandStatus  string     `json:"commandStatus,omitempty"`
	CommandDetail  string     `json:"commandDetail,omitempty"`
	LiftStatus     string     `json:"liftStatus,omitempty"`
	ExpiresAt      *time.Time `json:"expiresAt"`
	EndedAt        *time.Time `json:"endedAt"`
	LiftedBy       *string    `json:"liftedBy"`
	DecidedBy      *string    `json:"decidedBy"`
	Liftable       bool       `json:"liftable"`
}

// listContainments 决策记录，按组可见；来源主机在别组时不给主机名
func listContainments(db *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.Containment.Query()
		if !s.all {
			q.Where(entcontainment.AssetIDIn(s.assets...))
		}
		if v := r.URL.Query().Get("state"); v != "" {
			var states []entcontainment.State
			for _, st := range strings.Split(v, ",") {
				if entcontainment.StateValidator(entcontainment.State(st)) != nil {
					http.Error(w, "无效的 state", http.StatusBadRequest)
					return
				}
				states = append(states, entcontainment.State(st))
			}
			q.Where(entcontainment.StateIn(states...))
		}
		if v := r.URL.Query().Get("assetId"); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				http.Error(w, "无效的 assetId", http.StatusBadRequest)
				return
			}
			q.Where(entcontainment.AssetIDEQ(id))
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		size, _ := strconv.Atoi(r.URL.Query().Get("pageSize"))
		page, size = max(page, 1), min(max(size, 1), 100)
		if r.URL.Query().Get("pageSize") == "" {
			size = 20
		}
		total, err := q.Clone().Count(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rows, err := q.Order(ent.Desc(entcontainment.FieldCreatedAt)).Offset((page - 1) * size).Limit(size).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out, err := containmentRows(r, db, s, rows)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"items": out, "total": total})
	}
}

func containmentRows(r *http.Request, db *ent.Client, s scope, rows []*ent.Containment) ([]containmentRow, error) {
	var assetIDs, commandIDs []uuid.UUID
	for _, c := range rows {
		assetIDs = append(assetIDs, c.AssetID)
		if c.SourceAssetID != nil {
			assetIDs = append(assetIDs, *c.SourceAssetID)
		}
		for _, id := range []*uuid.UUID{c.CommandID, c.LiftCommandID} {
			if id != nil {
				commandIDs = append(commandIDs, *id)
			}
		}
	}
	assets, err := db.Asset.Query().Where(entasset.IDIn(assetIDs...)).Select(entasset.FieldID, entasset.FieldHostname).All(r.Context())
	if err != nil {
		return nil, err
	}
	names := map[uuid.UUID]string{}
	for _, a := range assets {
		names[a.ID] = a.Hostname
	}
	cmds, err := db.Command.Query().Where(entcommand.IDIn(commandIDs...)).
		Select(entcommand.FieldID, entcommand.FieldStatus, entcommand.FieldDetail).All(r.Context())
	if err != nil {
		return nil, err
	}
	byID := map[uuid.UUID]*ent.Command{}
	for _, c := range cmds {
		byID[c.ID] = c
	}
	out := make([]containmentRow, len(rows))
	for i, c := range rows {
		row := containmentRow{ID: c.ID, CreatedAt: c.CreatedAt, AssetID: c.AssetID, AssetHostname: names[c.AssetID],
			Kind: c.Kind, Target: c.Target, PID: c.Pid, Signal: c.Signal, AlertID: c.AlertID, IncidentID: c.IncidentID,
			Role: string(c.Role), State: string(c.State), Reason: c.Reason, CommandID: c.CommandID,
			ExpiresAt: c.ExpiresAt, EndedAt: c.EndedAt, LiftedBy: c.LiftedBy, DecidedBy: c.DecidedBy, Liftable: containment.Liftable(c)}
		if c.SourceAssetID != nil && s.has(*c.SourceAssetID) {
			row.SourceHostname = names[*c.SourceAssetID]
		}
		if cmd := byID[ptrID(c.CommandID)]; cmd != nil {
			row.CommandStatus = cmd.Status
			if cmd.Detail != nil {
				row.CommandDetail = *cmd.Detail
			}
		}
		if cmd := byID[ptrID(c.LiftCommandID)]; cmd != nil {
			row.LiftStatus = cmd.Status
		}
		out[i] = row
	}
	return out, nil
}

func ptrID(id *uuid.UUID) uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	return *id
}

// containmentStatus 开关、范围与熔断计数。熔断是全局的，任何登录用户都能看
func containmentStatus(db *ent.Client, engine *containment.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, err := containment.StatusOf(r.Context(), db, engine)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, st)
	}
}

// saveContainmentConfig 全局 admin 开关自主响应、改范围（门槛见 auth.minRole），各节点下一轮生效
func saveContainmentConfig(db *ent.Client, engine *containment.Engine, config *containment.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var c containment.Config
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&c) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		if engine == nil && c.Enabled {
			http.Error(w, "处置功能未开启（RESPONSE_ENABLED），自主响应无法启用", http.StatusConflict)
			return
		}
		err := config.Save(r.Context(), c)
		if errors.Is(err, containment.ErrLocked) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		detail, _ := json.Marshal(c)
		audit.Log(r.Context(), db, r, "containment_config_updated", "containment", string(detail))
		containmentStatus(db, engine)(w, r)
	}
}

// liftContainment 组 analyst 人工解除或恢复一条处置；解除时间之前的证据不再触发同一处置
func liftContainment(db *ent.Client, hub *response.Hub, engine *containment.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := getByPath(w, r, "id", "containment", db.Containment.Get)
		if !ok || !assetInScope(w, r, db, c.AssetID, "analyst") {
			return
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if r.ContentLength != 0 && json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		actor := auth.From(r.Context()).Username
		var lifted *ent.Containment
		var err error
		switch {
		case c.Kind == containment.KindSSO && engine == nil:
			http.Error(w, "未开启 RESPONSE_ENABLED，SSO 账号请在 Authentik 后台恢复", http.StatusConflict)
			return
		case c.Kind == containment.KindSSO:
			// SSO 账号由 server 直接调 Authentik 恢复，不经 agent
			lifted, err = engine.LiftSSO(r.Context(), c, actor, strings.TrimSpace(body.Reason))
		default:
			lifted, err = containment.Lift(r.Context(), db, hub, c, actor, strings.TrimSpace(body.Reason))
		}
		if errors.Is(err, containment.ErrNotLiftable) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		audit.Log(r.Context(), db, r, "containment_lifted", c.ID.String(), c.Kind+" "+c.Target+" "+strings.TrimSpace(body.Reason))
		s, _ := scopeOf(r.Context(), db, "viewer")
		rows, err := containmentRows(r, db, s, []*ent.Containment{lifted})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rows[0])
	}
}

// decideContainment 批准或驳回研判提出的处置：只有资产所在组的 admin 可以，与命令审批同一口径
func decideContainment(db *ent.Client, engine *containment.Engine, approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := getByPath(w, r, "id", "containment", db.Containment.Get)
		if !ok || !assetInScope(w, r, db, c.AssetID, "admin") {
			return
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if r.ContentLength != 0 && json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		if engine == nil {
			http.Error(w, "未开启 RESPONSE_ENABLED，不能执行处置", http.StatusConflict)
			return
		}
		actor := auth.From(r.Context()).Username
		reason := strings.TrimSpace(body.Reason)
		var decided *ent.Containment
		var err error
		action := "containment_approved"
		if approve {
			decided, err = engine.Approve(r.Context(), c, actor)
		} else {
			action = "containment_declined"
			decided, err = engine.Decline(r.Context(), c, actor, reason)
		}
		if errors.Is(err, containment.ErrNotProposed) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		audit.Log(r.Context(), db, r, action, c.ID.String(), c.Kind+" "+c.Target+" "+reason)
		s, _ := scopeOf(r.Context(), db, "viewer")
		rows, err := containmentRows(r, db, s, []*ent.Containment{decided})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rows[0])
	}
}
