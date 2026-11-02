package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/aiconf"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/notify"
	"openxdr/server/internal/triage"
)

var notifyFormats = map[string]bool{"generic": true, "dingtalk": true, "feishu": true, "wecom": true}

// Settings 控制台可改的运行时配置，只有 admin 能动（门槛见 auth.minRole）。
func Settings(db *ent.Client, settings *notify.Settings, webhook *notify.Webhook, ai *aiconf.Store, sqlDB *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mapAISettings(mux, db, ai, sqlDB)
	mux.HandleFunc("GET /api/settings/notify", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, settings.Load(r.Context()))
	})
	mux.HandleFunc("PUT /api/settings/notify", func(w http.ResponseWriter, r *http.Request) {
		t, ok := decodeTarget(w, r)
		if !ok {
			return
		}
		if err := settings.Save(r.Context(), t); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// 地址里可能带 token，审计只记格式与开关
		detail, _ := json.Marshal(map[string]any{"enabled": t.URL != "", "format": t.Format, "minSeverity": t.MinSeverity})
		audit.Log(r.Context(), db, r, "notify_settings_updated", "notify", string(detail))
		writeJSON(w, t)
	})
	// 用表单里还没保存的配置发一条，先验证再保存
	mux.HandleFunc("POST /api/settings/notify/test", func(w http.ResponseWriter, r *http.Request) {
		t, ok := decodeTarget(w, r)
		if !ok {
			return
		}
		if t.URL == "" {
			http.Error(w, "未填写推送地址", http.StatusBadRequest)
			return
		}
		if err := webhook.SendTo(r.Context(), t, "测试消息", "收到这条说明 OpenXDR 通知已接通。", "/"); err != nil {
			http.Error(w, "推送失败："+err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func decodeTarget(w http.ResponseWriter, r *http.Request) (notify.Target, bool) {
	var t notify.Target
	if json.NewDecoder(r.Body).Decode(&t) != nil {
		http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
		return t, false
	}
	if t.Format == "" {
		t.Format = "generic"
	}
	if !notifyFormats[t.Format] {
		http.Error(w, "format 只能是 generic / dingtalk / feishu / wecom", http.StatusBadRequest)
		return t, false
	}
	for _, raw := range []string{t.URL, t.LinkBase} {
		if raw == "" {
			continue
		}
		if u, err := url.Parse(raw); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			http.Error(w, "地址必须是 http(s) 链接："+raw, http.StatusBadRequest)
			return t, false
		}
	}
	if t.MinSeverity < 0 || t.MinSeverity > 5 {
		http.Error(w, "minSeverity 取 0–5", http.StatusBadRequest)
		return t, false
	}
	return t, true
}

// vtBase 测试时替换
var vtBase = "https://www.virustotal.com"

func mapAISettings(mux *http.ServeMux, db *ent.Client, ai *aiconf.Store, sqlDB *sql.DB) {
	mux.HandleFunc("GET /api/settings/ai", func(w http.ResponseWriter, r *http.Request) {
		v, err := ai.View(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, v)
	})
	mux.HandleFunc("PUT /api/settings/ai", func(w http.ResponseWriter, r *http.Request) {
		var p aiconf.Patch
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&p) != nil {
			http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
			return
		}
		if err := ai.Save(r.Context(), p); err != nil {
			code := http.StatusInternalServerError
			if errors.Is(err, aiconf.ErrNoVault) || p.Check() != nil {
				code = http.StatusBadRequest
			}
			http.Error(w, err.Error(), code)
			return
		}
		// 审计只记改了哪些项，密钥只记设置或清空
		audit.Log(r.Context(), db, r, "ai_settings_updated", "ai", changedFields(p))
		v, err := ai.View(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, v)
	})
	// 用表单里还没保存的值试一次：target 为 model / piModel 发一句最短的对话，vt 查一个公共地址
	mux.HandleFunc("POST /api/settings/ai/test", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			aiconf.Patch
			Target string `json:"target"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body) != nil {
			http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
			return
		}
		c, err := ai.Preview(r.Context(), body.Patch)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		start := time.Now()
		var reply string
		switch body.Target {
		case "model", "piModel":
			model := map[bool]string{true: c.Model, false: c.PiModel}[body.Target == "model"]
			if model == "" {
				http.Error(w, "没有填写模型", http.StatusBadRequest)
				return
			}
			llm := triage.NewLLM(c.BaseURL, model, c.APIKey, 30*time.Second)
			llm.MaxTokens, llm.NoThinking = 16, true
			msg, err := llm.Chat(ctx, []triage.Message{{Role: "user", Content: "只回复 OK"}}, nil)
			if err != nil {
				http.Error(w, "调用失败："+redact(err.Error(), c.APIKey), http.StatusBadGateway)
				return
			}
			reply = msg.Content
		case "vt":
			if c.VTKey == "" {
				http.Error(w, "没有填写 VirusTotal key", http.StatusBadRequest)
				return
			}
			if err := vtPing(ctx, c.VTKey); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
		default:
			http.Error(w, "target 只能是 model / piModel / vt", http.StatusBadRequest)
			return
		}
		// 回复只回显开头一段，够看出模型通了
		if r := []rune(reply); len(r) > 80 {
			reply = string(r[:80])
		}
		writeJSON(w, map[string]any{"ms": time.Since(start).Milliseconds(), "reply": reply})
	})
	mux.HandleFunc("GET /api/settings/ai/usage", func(w http.ResponseWriter, r *http.Request) {
		days, err := strconv.Atoi(r.URL.Query().Get("days"))
		if err != nil || days < 1 || days > 365 {
			days = 30
		}
		tz := r.URL.Query().Get("tz")
		if _, err := time.LoadLocation(tz); err != nil || tz == "" {
			tz = "UTC"
		}
		out, err := aiconf.Usage(r.Context(), sqlDB, days, tz)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, out)
	})
}

func vtPing(ctx context.Context, key string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vtBase+"/api/v3/ip_addresses/8.8.8.8", nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-apikey", key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("连不上 VirusTotal：%w", err)
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return errors.New("VirusTotal 拒绝了这个 key")
	case http.StatusTooManyRequests:
		return errors.New("VirusTotal 额度已用完，key 本身有效")
	default:
		return fmt.Errorf("VirusTotal 返回 HTTP %d", resp.StatusCode)
	}
}

func changedFields(p aiconf.Patch) string {
	var out []string
	for name, set := range map[string]bool{"baseUrl": p.BaseURL != nil, "model": p.Model != nil, "piModel": p.PiModel != nil, "ptr": p.PTR != nil, "vtAlertMin": p.VTAlertMin != nil} {
		if set {
			out = append(out, name)
		}
	}
	for name, k := range map[string]*string{"apiKey": p.APIKey, "vtKey": p.VTKey, "abuseCHKey": p.AbuseCHKey} {
		if k != nil {
			out = append(out, name+map[bool]string{true: "（清空）", false: "（设置）"}[*k == ""])
		}
	}
	for _, r := range p.Reset {
		out = append(out, r+"（恢复默认）")
	}
	slices.Sort(out)
	return strings.Join(out, "、")
}

// redact 错误信息里不能带出密钥
func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "[已隐藏]")
}
