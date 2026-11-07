package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/agentchat"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/findings"
)

func mapFindingDecisions(mux *http.ServeMux, db *ent.Client, chat *agentchat.Service) {
	mux.HandleFunc("GET /api/findings/{id}/decision", func(w http.ResponseWriter, r *http.Request) {
		f, ok := getByPath(w, r, "id", "finding", db.Finding.Get)
		if !ok || !requireGroup(w, r, db, f.GroupID, "viewer") {
			return
		}
		d, err := findings.LoadDecision(r.Context(), db, f.ID)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if d != nil && (d.GroupID != f.GroupID || d.AssetID != f.AssetID) {
			d = nil
		}
		writeJSON(w, d)
	})
	mux.HandleFunc("POST /api/findings/{id}/decision", func(w http.ResponseWriter, r *http.Request) {
		f, ok := getByPath(w, r, "id", "finding", db.Finding.Get)
		if !ok || !requireGroup(w, r, db, f.GroupID, "admin") {
			return
		}
		var body struct {
			RequestID   uuid.UUID `json:"requestId"`
			Instruction string    `json:"instruction"`
			ExpiresAt   time.Time `json:"expiresAt"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			http.Error(w, "请求格式错误", 400)
			return
		}
		if chat == nil || piModel(chat) == "" {
			http.Error(w, "Pi未启用，不能接收执行委托", 503)
			return
		}
		u := auth.From(r.Context())
		d, created, err := findings.Delegate(r.Context(), db, f.ID, u, body.RequestID, body.Instruction, piModel(chat), audit.RemoteAddr(r), body.ExpiresAt)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		// 决定与会话已经原子提交；启动失败也返回原句柄，客户端不得盲目重建或重放。
		result := map[string]any{"decision": d, "created": created}
		if created {
			prompt := fmt.Sprintf("组管理员%s已对待办%s作出执行决定（请求%s，有效至%s）。请先读取context中的operator_decision，按其精确资产与范围执行，已决定的事项不要再次要求同一授权。\n决定：%s\n先取得本轮独立只读证据，再经既有commandgate/AI审计员执行最小动作；写后独立验证。此决定不覆盖硬拒绝、人工持有、未知指令、不支持动作或维护模板要求。旧探针和模型说明不能代替最新真实回执，审计拒绝后仅有新证据才可重评，不得换写法绕过；超时先查原指令，不能重放。完成后提交报告，未完成保留真实阻塞。", d.Author, d.FindingID, d.RequestID, d.ExpiresAt.Format(time.RFC3339), d.Instruction)
			if err = chat.Start(r.Context(), d.SessionID, u, prompt); err != nil {
				result["runError"] = err.Error()
			}
		}
		w.WriteHeader(http.StatusAccepted)
		writeJSON(w, result)
	})
	mux.HandleFunc("DELETE /api/findings/{id}/decision", func(w http.ResponseWriter, r *http.Request) {
		f, ok := getByPath(w, r, "id", "finding", db.Finding.Get)
		if !ok || !requireGroup(w, r, db, f.GroupID, "admin") {
			return
		}
		if err := findings.RevokeDecision(r.Context(), db, f.ID, auth.From(r.Context()).Username, audit.RemoteAddr(r)); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
