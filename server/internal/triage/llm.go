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

// Message OpenAI chat 消息。工具调用往返都用它承载。
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// Tool OpenAI function 工具定义。
type Tool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

func makeTool(name, description string, parameters string) Tool {
	var t Tool
	t.Type = "function"
	t.Function.Name = name
	t.Function.Description = description
	t.Function.Parameters = json.RawMessage(parameters)
	return t
}

// Chat 一轮对话。带 tools 时模型可能返回 tool_calls 而非最终答案，由调用方循环。
// 不设 response_format：与 tool calling 混用在部分推理服务上不兼容，
// 最终答案的 JSON 提取交给 parseVerdict 的容错逻辑。
func (l *LLM) Chat(ctx context.Context, msgs []Message, tools []Tool) (Message, error) {
	payload := map[string]any{
		"model":       l.Model,
		"messages":    msgs,
		"temperature": 0.1,
	}
	if len(tools) > 0 {
		payload["tools"] = tools
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		l.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Message{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if l.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+l.APIKey)
	}

	resp, err := l.http.Do(req)
	if err != nil {
		return Message{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Message{}, fmt.Errorf("LLM 返回 %s", resp.Status)
	}

	var out struct {
		Choices []struct {
			Message Message `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Message{}, err
	}
	if len(out.Choices) == 0 {
		return Message{}, fmt.Errorf("LLM 返回空 choices")
	}
	return out.Choices[0].Message, nil
}
