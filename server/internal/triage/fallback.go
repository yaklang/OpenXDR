package triage

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"openxdr/server/internal/modelroute"
	"strings"
	"sync"
	"time"
)

// 冷却仅存于节点内存，按端点、凭据与模型隔离；不记录明文密钥。
var modelCooldown = struct {
	sync.Mutex
	until map[[32]byte]time.Time
}{until: make(map[[32]byte]time.Time)}

func cooldownKey(base, key, model string) [32]byte {
	return sha256.Sum256([]byte(base + "\x00" + key + "\x00" + model))
}

// LLMTransportError 不携带地址、凭据或上游诊断正文。Timeout 非零表示连上了、但在客户端超时内没等到完整回答，
// 多半是模型慢或推理服务排队，不是服务挂了
type LLMTransportError struct{ Timeout time.Duration }

func (e *LLMTransportError) Error() string {
	if e.Timeout > 0 {
		return fmt.Sprintf("推理超时（超过 %d 秒没有返回完整回答，上下文大或推理服务繁忙时可调大 AI_TIMEOUT_SECONDS）", int(e.Timeout.Seconds()))
	}
	return "连接推理服务失败"
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (l *LLM) transportError(err error) *LLMTransportError {
	if isTimeout(err) {
		return &LLMTransportError{Timeout: l.http.Timeout}
	}
	return &LLMTransportError{}
}

func (l *LLM) chatFallback(ctx context.Context, base, primary, key string, msgs []Message, tools []Tool) (Message, error) {
	models := []modelroute.Endpoint{{BaseURL: base, APIKey: key, Model: primary}}
	textOnly := true
	for _, msg := range msgs {
		for _, part := range msg.Parts {
			if part.Type != "text" {
				textOnly = false
			}
		}
	}
	if primary != "" && textOnly && l.FallbackModels != nil {
		seen := map[string]bool{primary: true}
		for _, m := range strings.Split(l.FallbackModels(), ",") {
			if m != "" && !seen[m] && len(models) < 9 {
				seen[m] = true
				models = append(models, modelroute.Endpoint{BaseURL: base, APIKey: key, Model: m})
			}
		}
	}
	hasProviders := false
	if primary != "" && textOnly && l.FallbackEndpoints != nil {
		seen := map[modelroute.Endpoint]bool{}
		for _, v := range models {
			seen[v] = true
		}
		for _, v := range l.FallbackEndpoints() {
			if v.Model != "" && !seen[v] && len(models) < 25 {
				seen[v] = true
				models = append(models, v)
				hasProviders = true
			}
		}
	}
	// 未启用备用模型时维持原调用行为，也方便管理员直接测试主模型。
	if len(models) == 1 {
		return l.chatOnce(ctx, base, primary, key, msgs, tools)
	}
	var last error
	skipped := map[[32]byte]bool{}
	for _, candidate := range models {
		base, key, model := candidate.BaseURL, candidate.APIKey, candidate.Model
		group := cooldownKey(base, key, "")
		if skipped[group] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return Message{}, err
		}
		id := cooldownKey(base, key, model)
		modelCooldown.Lock()
		until := modelCooldown.until[id]
		groupUntil := modelCooldown.until[group]
		modelCooldown.Unlock()
		if time.Now().Before(until) || time.Now().Before(groupUntil) {
			continue
		}
		msg, err := l.chatOnce(ctx, base, model, key, msgs, tools)
		if err == nil {
			return msg, nil
		}
		last = err
		var status *LLMHTTPError
		var transport *LLMTransportError
		if errors.As(err, &transport) && hasProviders && ctx.Err() == nil {
			skipped[group] = true
			modelCooldown.Lock()
			if len(modelCooldown.until) < 2048 {
				modelCooldown.until[group] = time.Now().Add(time.Minute)
			}
			modelCooldown.Unlock()
			continue
		}
		if !errors.As(err, &status) {
			return Message{}, err
		}
		delay := time.Minute
		switch status.StatusCode {
		case 401, 403:
			if !hasProviders {
				return Message{}, err
			}
			skipped[group] = true
			delay = 5 * time.Minute
			id = group
		case 402:
			delay = 15 * time.Minute
		case 429:
			delay = 5 * time.Minute
		case 500, 502, 503, 504:
		default:
			return Message{}, err
		}
		modelCooldown.Lock()
		// 有界缓存；到期条目优先删除，避免长期积累历史配置。
		for k, expiry := range modelCooldown.until {
			if time.Now().After(expiry) {
				delete(modelCooldown.until, k)
			}
		}
		if len(modelCooldown.until) < 2048 {
			modelCooldown.until[id] = time.Now().Add(delay)
		}
		modelCooldown.Unlock()
	}
	if last != nil {
		return Message{}, last
	}
	return Message{}, errors.New("所有已配置模型均在冷却中，请稍后重试")
}
