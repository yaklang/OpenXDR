package triageeval

import (
	"context"
	"errors"
	"net"

	"openxdr/server/internal/triage"
)

// Diagnostic 仅记录固定诊断码；不序列化请求地址、响应正文或模型输出。
type Diagnostic struct {
	Stage        string `json:"stage"`
	Code         string `json:"code"`
	FinishReason string `json:"finish_reason,omitempty"`
	HTTPStatus   int    `json:"http_status,omitempty"`
}

type reviewError struct{ diagnostic Diagnostic }

func (e *reviewError) Error() string { return e.diagnostic.Stage + ": " + e.diagnostic.Code }

type validationError string

func (e validationError) Error() string { return string(e) }

func reviewFailure(stage, code string, err error) error {
	d := Diagnostic{Stage: stage, Code: code}
	var validation validationError
	var httpError *triage.LLMHTTPError
	var timeout net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		d.Code = "timeout"
	case errors.Is(err, context.Canceled):
		d.Code = "canceled"
	case errors.As(err, &httpError):
		d.Code = "http_error"
		d.HTTPStatus = httpError.StatusCode
	case errors.As(err, &timeout) && timeout.Timeout():
		d.Code = "timeout"
	case errors.As(err, &validation):
		d.Code = string(validation)
	}
	return &reviewError{diagnostic: d}
}

func outputFailure(stage string, msg triage.Message) error {
	if msg.FinishReason != "stop" {
		reason := "unknown"
		switch msg.FinishReason {
		case "length", "content_filter", "tool_calls", "function_call", "":
			reason = msg.FinishReason
		}
		if reason == "" {
			reason = "missing"
		}
		return &reviewError{diagnostic: Diagnostic{Stage: stage, Code: "incomplete_output", FinishReason: reason}}
	}
	if len(msg.ToolCalls) > 0 {
		return &reviewError{diagnostic: Diagnostic{Stage: stage, Code: "unexpected_tool_call", FinishReason: "stop"}}
	}
	return nil
}

// Diagnose 不返回原始 error 文本，即使错误内含 URL 或凭据也不会写入报告。
func Diagnose(err error) Diagnostic {
	var review *reviewError
	if errors.As(err, &review) {
		return review.diagnostic
	}
	classified := reviewFailure("generation", "generation_or_format", err).(*reviewError)
	return classified.diagnostic
}
