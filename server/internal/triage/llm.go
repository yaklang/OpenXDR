package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// LLM OpenAI 兼容 chat completions 客户端。BaseURL 默认本地 Ollama——安全数据不出内网。
type LLM struct {
	BaseURL string
	Model   string
	APIKey  string
	http    *http.Client
}

func NewLLM(baseURL, model, apiKey string, timeout time.Duration) *LLM {
	return &LLM{
		BaseURL: baseURL,
		Model:   model,
		APIKey:  apiKey,
		http:    &http.Client{Timeout: timeout},
	}
}

func (l *LLM) Enabled() bool { return l.Model != "" }

func (l *LLM) Chat(ctx context.Context, system, user string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model": l.Model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"response_format": map[string]string{"type": "json_object"},
		"temperature":     0.1,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		l.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if l.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+l.APIKey)
	}

	resp, err := l.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("LLM 返回 %s", resp.Status)
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("LLM 返回空 choices")
	}
	return out.Choices[0].Message.Content, nil
}
