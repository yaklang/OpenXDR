package findings

import (
	"github.com/google/uuid"
	"time"
)

// RepairCapabilities 是服务端观察到的能力快照，不是可供模型回传的执行凭证。
type RepairCapabilities struct {
	SupportedTemplates []string      `json:"supported_templates"`
	Grants             []RepairGrant `json:"grants"`
	PolicyFingerprint  string        `json:"policy_fingerprint"`
	Command            string        `json:"command,omitempty"`
	Status             string        `json:"status"`
	Reason             string        `json:"reason"`
	Probe              string        `json:"required_probe,omitempty"`
	ProbeID            *uuid.UUID    `json:"probe_id,omitempty"`
	RetryAt            *time.Time    `json:"retry_at,omitempty"`
}
type RepairGrant struct {
	RequiredProbes []string   `json:"required_probes"`
	Action         string     `json:"action"`
	Units          []string   `json:"units,omitempty"`
	Paths          []string   `json:"paths,omitempty"`
	NotBefore      *time.Time `json:"not_before,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	CooldownUntil  *time.Time `json:"cooldown_until,omitempty"`
}

// RepairError 仅表示预留前确定拒绝；未知提交结果不可用它归类或重放。
type RepairError struct{ State RepairCapabilities }

func (e *RepairError) Error() string {
	if e.State.RetryAt != nil {
		return e.State.Status + ": " + e.State.Reason + "；最早 " + e.State.RetryAt.UTC().Format(time.RFC3339) + " 后重新评估"
	}
	return e.State.Status + ": " + e.State.Reason
}

func MachineBlocker(code string) bool {
	switch code {
	case "policy_required", "action_unsupported", "cooldown", "probe_invalid", "budget_exhausted":
		return true
	}
	return false
}
