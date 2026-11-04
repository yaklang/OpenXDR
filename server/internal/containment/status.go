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
	HeldLastHour     int    `json:"heldLastHour"`
	Active           int    `json:"active"`
	// 熔断中：一小时内生效的处置已到上限，新的决定只记录不执行
	Tripped bool `json:"tripped"`
}

// StatusOf engine 为 nil 表示没开启；计数照样给，开关之前留下的记录也要看得到
func StatusOf(ctx context.Context, db *ent.Client, engine *Engine) (Status, error) {
	hour := time.Now().Add(-time.Hour)
	executed, err := db.Containment.Query().Where(entcontainment.CreatedAtGTE(hour),
		entcontainment.StateIn(entcontainment.StateActive, entcontainment.StateExpired, entcontainment.StateExecuted, entcontainment.StateLifted)).Count(ctx)
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
	st := Status{ExecutedLastHour: executed, HeldLastHour: held, Active: active}
	if engine != nil {
		st.Enabled, st.Scope, st.TTLHours, st.MaxPerHour = true, engine.Scope, int(engine.TTL/time.Hour), engine.MaxPerHour
		st.Tripped = executed >= engine.MaxPerHour
	}
	return st, nil
}
