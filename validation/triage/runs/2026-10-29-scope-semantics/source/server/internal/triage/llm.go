package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

// glmModel 与 Pi runner 判定 GLM 的规则一致
var glmModel = regexp.MustCompile(`(?i)(^|/)glm[-_.]`)

var deepseekThinkingModel = regexp.MustCompile(`(?i)(^|/)deepseek-(v4-)?(flash|pro)$`)

// LLM OpenAI 兼容 chat completions 客户端。BaseURL 默认本地 Ollama——安全数据不出内网。
type LLM struct {
	BaseURL string
	Model   string
	APIKey  string
	// NoThinking 关闭 GLM / DeepSeek 的思考，避免后台短输出预算被思考耗尽。
	// 按模型使用各自的参数，未知模型不发送扩展字段。
	NoThinking bool
	// MaxTokens 输出上限，0 表示不设
	MaxTokens int
	// Endpoint 每次调用时取地址、模型与密钥（控制台可改）；为空用上面的固定值
	Endpoint func() (baseURL, model, apiKey string)
	// OnUsage 调用成功后报告用量，供用量概览；为空不记
	OnUsage func(model string, input, output int)
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

func (l *LLM) endpoint() (string, string, string) {
	if l.Endpoint != nil {
		return l.Endpoint()
	}
	return l.BaseURL, l.Model, l.APIKey
}

func (l *LLM) Enabled() bool {
	_, model, _ := l.endpoint()
	return model != ""
}

// Message OpenAI chat 消息。工具调用往返都用它承载。
type Message struct {
	FinishReason string        `json:"-"`
	Parts        []ContentPart `json:"-"`
	Role         string        `json:"role"`
	Content      string        `json:"content"`
	ToolCalls    []ToolCall    `json:"tool_calls,omitempty"`
	ToolCallID   string        `json:"tool_call_id,omitempty"`
}

// 多模态消息仅在 Parts 非空时使用内容数组；现有文本聊天协议保持不变。
type ContentPart struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *ImageURL `json:"image_url,omitempty"`
}
type ImageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

func (m Message) MarshalJSON() ([]byte, error) {
	type plain Message
	if m.Parts == nil {
		return json.Marshal(plain(m))
	}
	return json.Marshal(struct {
		plain
		Content []ContentPart `json:"content"`
	}{plain(m), m.Parts})
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
	baseURL, model, apiKey := l.endpoint()
	payload := map[string]any{
		"model":       model,
		"messages":    msgs,
		"temperature": 0.1,
	}
	if len(tools) > 0 {
		payload["tools"] = tools
	}
	if l.NoThinking && glmModel.MatchString(model) {
		payload["chat_template_kwargs"] = map[string]bool{"enable_thinking": false}
	}
	if l.NoThinking && deepseekThinkingModel.MatchString(model) {
		payload["thinking"] = map[string]string{"type": "disabled"}
	}
	if l.MaxTokens > 0 {
		payload["max_tokens"] = l.MaxTokens
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Message{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := l.http.Do(req)
	if err != nil {
		return Message{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Message{}, &LLMHTTPError{StatusCode: resp.StatusCode}
	}

	var out struct {
		Choices []struct {
			Message      Message `json:"message"`
			FinishReason string  `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Message{}, err
	}
	if l.OnUsage != nil {
		l.OnUsage(model, out.Usage.PromptTokens, out.Usage.CompletionTokens)
	}
	if len(out.Choices) == 0 {
		return Message{}, fmt.Errorf("LLM 返回空 choices")
	}
	out.Choices[0].Message.FinishReason = out.Choices[0].FinishReason
	return out.Choices[0].Message, nil
}

// LLMHTTPError 保留状态码供诊断，不携带响应正文与请求凭据。
type LLMHTTPError struct{ StatusCode int }

func (e *LLMHTTPError) Error() string {
	return fmt.Sprintf("LLM 返回 %d %s", e.StatusCode, http.StatusText(e.StatusCode))
}
