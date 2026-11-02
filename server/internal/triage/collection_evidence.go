package triage

import (
	"encoding/json"
	"slices"
	"time"
)

// collectionEvidence 只提供最近一次已存的 agent 状态，不能回推事件发生时的采集情况。
func collectionEvidence(raw json.RawMessage) map[string]any {
	facts := map[string]any{"collection_status": "unknown"}
	var snapshot struct {
		ReceivedAt   time.Time `json:"receivedAt"`
		Capabilities map[string]struct {
			State string `json:"state"`
			Path  string `json:"path"`
		} `json:"capabilities"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &snapshot) != nil || snapshot.ReceivedAt.IsZero() {
		return facts
	}
	states := make(map[string]string)
	paths := make(map[string]string)
	for name, capability := range snapshot.Capabilities {
		if !slices.Contains([]string{"active", "degraded", "unavailable", "disabled", "unknown"}, capability.State) {
			continue
		}
		states[name] = capability.State
		if capability.Path != "" {
			paths[name] = capability.Path
		}
	}
	facts["collection_status"] = "recorded_snapshot"
	facts["collection_received_at"] = snapshot.ReceivedAt.UTC().Format(time.RFC3339Nano)
	facts["collection_states"] = states
	facts["collection_paths"] = paths
	facts["collection_scope"] = "仅最近一次 agent 自报状态，不是事件发生时的历史状态；缺失组件未知，active 不证明无漏采，时间过旧时需重新核实。"
	return facts
}
