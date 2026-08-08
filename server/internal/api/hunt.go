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

// hunter 只要狩猎与起草两件事，不把整个研判引擎的接口面拖进 api。
type hunter interface {
	Hunt(ctx context.Context, question string) (string, []triage.Step, error)
	DraftRule(ctx context.Context, question, answer string) (string, error)
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

	// 狩猎结论转写为 Sigma 规则草稿。只起草不落盘：
	// 检测面变更必须过分析师的眼睛，AI 直接上规则等于把检测面交给幻觉。
	api.HandleFunc("POST /api/hunt/rule", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Question string `json:"question"`
			Answer   string `json:"answer"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil ||
			strings.TrimSpace(body.Question) == "" || strings.TrimSpace(body.Answer) == "" {
			http.Error(w, "question 与 answer 必填", http.StatusBadRequest)
			return
		}
		if h == nil {
			http.Error(w, "AI 未启用", http.StatusServiceUnavailable)
			return
		}
		draft, err := h.DraftRule(r.Context(), body.Question, body.Answer)
		if errors.Is(err, triage.ErrLLMDisabled) {
			http.Error(w, "AI 未启用：server 未配置 AI_MODEL", http.StatusServiceUnavailable)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]string{"yaml": draft})
	})
}
