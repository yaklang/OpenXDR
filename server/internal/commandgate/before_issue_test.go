package commandgate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestBeforeIssueIsInternal(t *testing.T) {
	raw, err := json.Marshal(Request{BeforeIssue: func(context.Context) error { return nil }})
	if err != nil || strings.Contains(string(raw), "BeforeIssue") || strings.Contains(string(raw), "before_issue") {
		t.Fatalf("internal hook serialized: %s %v", raw, err)
	}
}
