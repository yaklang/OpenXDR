package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"openxdr/server/ent"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/triage"
)

// hunter 只要狩猎这一件事，不把整个研判引擎的接口面拖进 api。
type hunter interface {
	Hunt(ctx context.Context, question string) (string, []triage.Step, error)
}

func mapHunt(api *http.ServeMux, db *ent.Client, h hunter) {
	api.HandleFunc("POST /api/hunt", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Question string `json:"question"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || strings.TrimSpace(body.Question) == "" {
			http.Error(w, "question 必填", http.StatusBadRequest)
			return
		}

		if h == nil {
			http.Error(w, "AI 未启用", http.StatusServiceUnavailable)
			return
		}
		answer, steps, err := h.Hunt(r.Context(), body.Question)
		if errors.Is(err, triage.ErrLLMDisabled) {
			http.Error(w, "AI 未启用：server 未配置 AI_MODEL", http.StatusServiceUnavailable)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		// 狩猎会读全量事件，属于需要留痕的调查行为
		audit.Log(r.Context(), db, r, "hunt", "", body.Question)
		writeJSON(w, map[string]any{"answer": answer, "steps": steps})
	})
}
