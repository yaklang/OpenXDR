package containment

import (
	"context"
	"time"

	"openxdr/server/ent"
	entcontainment "openxdr/server/ent/containment"
)

// Status 自主响应的开关、范围与熔断计数，给页面展示
type Status struct {
	Enabled          bool   `json:"enabled"`
	Scope            string `json:"scope,omitempty"`
	TTLHours         int    `json:"ttlHours,omitempty"`
	MaxPerHour       int    `json:"maxPerHour,omitempty"`
	ExecutedLastHour int    `json:"executedLastHour"`
	Pending          int    `json:"pending"`
	HeldLastHour     int    `json:"heldLastHour"`
	Active           int    `json:"active"`
	// 熔断中：一小时内已生效与待确认的处置达到上限，新的决定只记录不执行
	Tripped bool `json:"tripped"`
	// 没开 RESPONSE_ENABLED，控制台开关无效
	Unavailable   bool `json:"unavailable,omitempty"`
	EnabledLocked bool `json:"enabledLocked,omitempty"`
	ScopeLocked   bool `json:"scopeLocked,omitempty"`
}

// StatusOf engine 为 nil 表示没开 RESPONSE_ENABLED；计数照样给，开关之前留下的记录也要看得到
func StatusOf(ctx context.Context, db *ent.Client, engine *Engine) (Status, error) {
	hour := time.Now().Add(-time.Hour)
	executed, err := db.Containment.Query().Where(entcontainment.CreatedAtGTE(hour),
		entcontainment.StateIn(entcontainment.StateActive, entcontainment.StateExpired, entcontainment.StateExecuted, entcontainment.StateLifted)).Count(ctx)
	if err != nil {
		return Status{}, err
	}
	pendingLastHour, err := db.Containment.Query().Where(entcontainment.CreatedAtGTE(hour),
		entcontainment.StateEQ(entcontainment.StatePending)).Count(ctx)
	if err != nil {
		return Status{}, err
	}
	held, err := db.Containment.Query().Where(entcontainment.CreatedAtGTE(hour), entcontainment.StateEQ(entcontainment.StateHeld)).Count(ctx)
	if err != nil {
		return Status{}, err
	}
	active, err := db.Containment.Query().Where(entcontainment.StateEQ(entcontainment.StateActive)).Count(ctx)
	if err != nil {
		return Status{}, err
	}
	pending, err := db.Containment.Query().Where(entcontainment.StateEQ(entcontainment.StatePending)).Count(ctx)
	if err != nil {
		return Status{}, err
	}
	st := Status{ExecutedLastHour: executed, Pending: pending, HeldLastHour: held, Active: active, Unavailable: engine == nil}
	if engine == nil {
		return st, nil
	}
	v, err := engine.Config.Load(ctx)
	if err != nil {
		return Status{}, err
	}
	st.Enabled, st.Scope, st.EnabledLocked, st.ScopeLocked = v.Enabled, v.Scope, v.EnabledLocked, v.ScopeLocked
	st.TTLHours, st.MaxPerHour = int(engine.TTL/time.Hour), engine.MaxPerHour
	st.Tripped = v.Enabled && (executed+pendingLastHour) >= engine.MaxPerHour
	return st, nil
}
