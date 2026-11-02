package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entalert "openxdr/server/ent/alert"
	entcommand "openxdr/server/ent/command"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
)

type commandRow struct {
	ID          uuid.UUID  `json:"id"`
	CreatedAt   time.Time  `json:"createdAt"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	AssetID     uuid.UUID  `json:"assetId"`
	IncidentID  *uuid.UUID `json:"incidentId"`
	IssuedBy    string     `json:"issuedBy"`
	Detail      *string    `json:"detail"`
	CompletedAt *time.Time `json:"completedAt"`
	Cmd         *string    `json:"cmd,omitempty"`
	Target      *string    `json:"target,omitempty"`
	ExitCode    *int32     `json:"exitCode,omitempty"`
	Stdout      *string    `json:"stdout,omitempty"`
	Stderr      *string    `json:"stderr,omitempty"`
	Truncated   bool       `json:"truncated,omitempty"`
	// Detections 这条指令拉起的进程触发的检测，按规则汇总：来源已知，不进事件
	Detections []commandDetection `json:"detections,omitempty"`
}

type commandDetection struct {
	RuleID string `json:"ruleId"`
	Title  string `json:"title,omitempty"`
	Author string `json:"author,omitempty"`
	Count  int    `json:"count"`
}

// withDetections 给指令行补上它触发的检测
func withDetections(ctx context.Context, db *ent.Client, rules sigma.Catalog, rows []commandRow) error {
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	var hits []struct {
		CommandID uuid.UUID `json:"command_id"`
		RuleID    string    `json:"rule_id"`
		Sum       int       `json:"sum"`
	}
	if err := db.Alert.Query().Where(entalert.CommandIDIn(ids...)).
		GroupBy(entalert.FieldCommandID, entalert.FieldRuleID).
		Aggregate(ent.Sum(entalert.FieldCount)).Scan(ctx, &hits); err != nil {
		return err
	}
	by := map[uuid.UUID][]commandDetection{}
	for _, h := range hits {
		d := commandDetection{RuleID: h.RuleID, Count: h.Sum}
		if rules != nil {
			d.Title, d.Author = rules.TitleOf(h.RuleID), rules.AuthorOf(h.RuleID)
		}
		by[h.CommandID] = append(by[h.CommandID], d)
	}
	for i := range rows {
		rows[i].Detections = by[rows[i].ID]
	}
	return nil
}

func toRow(c *ent.Command) commandRow {
	return commandRow{
		ID: c.ID, CreatedAt: c.CreatedAt, Kind: c.Kind, Status: c.Status,
		AssetID: c.AssetID, IncidentID: c.IncidentID,
		IssuedBy: c.IssuedBy, Detail: c.Detail, CompletedAt: c.CompletedAt,
		Cmd: c.Cmd, Target: c.Target, ExitCode: c.ExitCode, Stdout: c.Stdout, Stderr: c.Stderr, Truncated: c.Truncated,
	}
}

type issueBody struct {
	Kind        string     `json:"kind"`
	AssetID     uuid.UUID  `json:"assetId"`
	IncidentID  *uuid.UUID `json:"incidentId"`
	ProcessGUID *uuid.UUID `json:"processGuid"`
	PID         uint32     `json:"pid"`
	Cmd         string     `json:"cmd"`
	TimeoutMS   uint32     `json:"timeoutMs"`
	// 封锁、隔离文件、锁定账号的目标
	Target string `json:"target"`
}

func mapCommands(api *http.ServeMux, db *ent.Client, rules sigma.Catalog, hub *response.Hub, selfEndpoints []string, gate *commandgate.Gate) {
	api.HandleFunc("POST /api/commands", func(w http.ResponseWriter, r *http.Request) {
		var body issueBody
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
			return
		}
		if _, ok := response.Kinds[body.Kind]; !ok {
			http.Error(w, "kind 必须是 kill_process / isolate_host / unisolate_host / exec / block_network / unblock_network / quarantine_file / restore_file / disable_account / enable_account", http.StatusBadRequest)
			return
		}
		target := ""
		if response.TargetKinds[body.Kind] {
			t, err := response.NormalizeTarget(body.Kind, body.Target, response.ProtectedAddrs(selfEndpoints))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			target = t
		}
		if body.Kind == "exec" && body.Cmd == "" {
			http.Error(w, "exec 必须带 cmd", http.StatusBadRequest)
			return
		}
		// 处置要在目标主机所在组里有 analyst
		if !assetInScope(w, r, db, body.AssetID, "analyst") {
			return
		}
		req := response.Request{
			AssetID:     body.AssetID,
			Kind:        body.Kind,
			IncidentID:  body.IncidentID,
			ProcessGUID: body.ProcessGUID,
			PID:         body.PID,
			IssuedBy:    audit.Actor(r.Context()),
			TimeoutMS:   body.TimeoutMS,
			Target:      target,
		}
		if body.Kind == "exec" {
			req.Cmd = &body.Cmd
		}
		// 隔离必须放行 server 自身，否则 agent 失联后再也解除不了
		if body.Kind == "isolate_host" {
			req.AllowEndpoints = selfEndpoints
		}

		var cmd *ent.Command
		var err error
		if body.Kind == "exec" {
			a, e := db.Asset.Get(r.Context(), body.AssetID)
			if e != nil || a.GroupID == nil {
				http.Error(w, "exec 资产必须归组", http.StatusConflict)
				return
			}
			u := auth.From(r.Context())
			if u == nil {
				http.Error(w, "未认证", http.StatusUnauthorized)
				return
			}
			cmd, err = gate.Issue(r.Context(), commandgate.Request{UserID: u.ID, GroupID: *a.GroupID, Origin: "human", Command: req})
		} else {
			cmd, err = hub.Issue(r.Context(), req)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		detail := body.Kind
		if body.Kind == "exec" {
			detail += ": " + body.Cmd
		} else if target != "" {
			detail += ": " + target
		}
		audit.Log(r.Context(), db, r, "command_issued", cmd.ID.String(), detail)
		w.WriteHeader(http.StatusAccepted)
		rows := []commandRow{toRow(cmd)}
		if err := withDetections(r.Context(), db, rules, rows); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rows[0])
	})

	api.HandleFunc("GET /api/commands/{id}", func(w http.ResponseWriter, r *http.Request) {
		cmd, ok := getByPath(w, r, "id", "command", db.Command.Get)
		if !ok {
			return
		}
		asset, err := db.Asset.Get(r.Context(), cmd.AssetID)
		if err != nil {
			http.Error(w, "资产不存在", 404)
			return
		}
		if asset.GroupID != nil {
			if !requireGroup(w, r, db, *asset.GroupID, "viewer") {
				return
			}
		} else if u := auth.From(r.Context()); u == nil || u.Role != "admin" {
			http.Error(w, "无未分组资产权限", 403)
			return
		}
		writeJSON(w, toRow(cmd))
	})
	api.HandleFunc("GET /api/commands", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.Command.Query().Where(s.command()...)
		switch r.URL.Query().Get("view") {
		case "", "full", "summary":
		default:
			http.Error(w, "view 必须是 summary 或 full", http.StatusBadRequest)
			return
		}
		if v := r.URL.Query().Get("incidentId"); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				http.Error(w, "无效的 incidentId", http.StatusBadRequest)
				return
			}
			q = q.Where(entcommand.IncidentIDEQ(id))
		}
		if v := r.URL.Query().Get("assetId"); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				http.Error(w, "无效的 assetId", http.StatusBadRequest)
				return
			}
			q = q.Where(entcommand.AssetIDEQ(id))
		}
		limit, offset, total := 100, 0, 0
		paginated := r.URL.Query().Has("page")
		if paginated {
			page, err := strconv.Atoi(r.URL.Query().Get("page"))
			size := r.URL.Query().Get("pageSize")
			if size == "" {
				size = "20"
			}
			limit, _ = strconv.Atoi(size)
			if err != nil || page < 1 || page > 100000 || limit < 1 || limit > 100 {
				http.Error(w, "分页参数无效", 400)
				return
			}
			offset = (page - 1) * limit
			total, err = q.Clone().Count(r.Context())
			if err != nil {
				http.Error(w, "读取指令数量失败", 500)
				return
			}
		}
		if r.URL.Query().Get("view") == "summary" {
			// 列表不读取大段命令与输出；完整内容仍由详情接口提供。
			q.Select(entcommand.FieldID, entcommand.FieldCreatedAt, entcommand.FieldKind,
				entcommand.FieldStatus, entcommand.FieldAssetID, entcommand.FieldIncidentID,
				entcommand.FieldIssuedBy, entcommand.FieldDetail, entcommand.FieldCompletedAt,
				entcommand.FieldTarget, entcommand.FieldExitCode, entcommand.FieldTruncated)
		}
		cmds, err := q.Order(ent.Desc(entcommand.FieldCreatedAt), ent.Desc(entcommand.FieldID)).Offset(offset).Limit(limit).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]commandRow, len(cmds))
		for i, c := range cmds {
			out[i] = toRow(c)
		}
		if err := withDetections(r.Context(), db, rules, out); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if paginated {
			writeJSON(w, map[string]any{"items": out, "total": total})
			return
		}
		writeJSON(w, out)
	})
}
