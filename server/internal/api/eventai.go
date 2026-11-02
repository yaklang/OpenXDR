package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entevent "openxdr/server/ent/event"
	"openxdr/server/internal/aijob"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/eventai"
	"openxdr/server/internal/eventarchive"
	"openxdr/server/internal/triage"
)

type relatedGroup struct {
	Relation string     `json:"relation"`
	Events   []eventRow `json:"events"`
}

// archiveScope 说明本次调查入口的数据来源边界，两个事实分开表达：
//   - CandidatesHotOnly 关联候选恒只查热表（eventai.HotOnlyCoverage）：冷层没有关联索引，
//     已归档的同进程 / 父子 / 同连接事件不在候选中。这对热目标同样成立——它的历史关联
//     事件可能已归档，无论目标冷热都要说明，不能让「没有关联」被读成「没有相关事件」；
//   - TargetFromArchive 目标事件本身来自冷块（热表里已经没有这行），按实际。
type archiveScope struct {
	TargetFromArchive bool `json:"target_from_archive"`
	CandidatesHotOnly bool `json:"candidates_hot_only"`
}

// archiveScopeOf 汇出本次调查的数据来源边界：候选覆盖取自 eventai.HotOnlyCoverage
// （单一来源——related 响应、explain 结果与发给模型的覆盖说明共用同一份事实），
// 目标是否来自冷层按实际。
func archiveScopeOf(fromArchive bool) *archiveScope {
	return &archiveScope{TargetFromArchive: fromArchive, CandidatesHotOnly: eventai.HotOnlyCoverage.CandidatesHotOnly}
}

// relatedResponse related 的响应契约：groups 是关联候选，archive 恒非空——
// 候选边界（恒只查热表）与目标来源（是否冷层）都如实说明。
type relatedResponse struct {
	Groups  []relatedGroup `json:"groups"`
	Archive *archiveScope  `json:"archive,omitempty"`
}

// explainResult explain 的结果：模型解读（平铺字段）加上平台侧的候选边界说明。
type explainResult struct {
	eventai.Explanation
	Archive *archiveScope `json:"archive,omitempty"`
}

// EventAIPaths 只挂这几个精确路径：挂 /api/events/ 子树会让 ServeMux 把 /api/events 重定向进子树，日志检索就没了
var EventAIPaths = []string{"GET /api/events/{id}/related", "GET /api/events/{id}/explain", "POST /api/events/{id}/explain"}

// EventAI 日志检索里的「问 AI」：related 只查库给出确定关联的日志；explain 让模型读日志和这些候选，
// 给出解读并挑出相关的几条。两者都只在调用者能看的资产范围内取数。
//
// conn 是冷归档读取连接，遵循与 /api/events 相同的闸门（EVENT_ARCHIVE_READ，由 main.go 接线）：
// 热表查不到这条日志时按 id 经 eventarchive.Locate 找冷事件。只读——不自动物化回热表、
// 不自动 pin，把冷事件变成受保护证据要走 restore + 人工/研判流程。
func EventAI(db *ent.Client, conn *sql.DB, llm *triage.LLM) http.Handler {
	mux := http.NewServeMux()
	load := func(w http.ResponseWriter, r *http.Request) (*ent.Event, []eventai.Group, bool, bool) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return nil, nil, false, false
		}
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "日志 ID 无效", http.StatusBadRequest)
			return nil, nil, false, false
		}
		e, fromArchive, ok := loadEventHotOrCold(w, r, db, conn, s, id)
		if !ok {
			return nil, nil, false, false
		}
		groups, err := eventai.Related(r.Context(), db, s.event(), e)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil, nil, false, false
		}
		return e, groups, fromArchive, true
	}

	mux.HandleFunc("GET /api/events/{id}/related", func(w http.ResponseWriter, r *http.Request) {
		_, groups, fromArchive, ok := load(w, r)
		if !ok {
			return
		}
		out := make([]relatedGroup, len(groups))
		for i, g := range groups {
			out[i] = relatedGroup{Relation: g.Relation, Events: make([]eventRow, len(g.Events))}
			for j, e := range g.Events {
				out[i].Events[j] = toEventRow(e)
			}
		}
		// 候选边界恒说明（热目标的关联事件同样可能已归档），目标来源按实际
		writeJSON(w, relatedResponse{Groups: out, Archive: archiveScopeOf(fromArchive)})
	})

	// 解读在后台跑：POST 发起（已有在跑的或已有结果就直接返回它，refresh=1 才重来），GET 读当前这次。
	// 结果按发起人存：候选是按调用者能看的范围捞的，别人的解读可能提到他看不到的主机
	// 每个节点同时最多几次后台解读：调用不再挂在请求上，没有名额就能被连点拉起任意多次
	slots := make(chan struct{}, 4)
	// explainCoverageRev 是解读结果的覆盖契约版本（R5），并进缓存键的 variant：
	// 旧结果生成时模型输入里没有候选来源说明、响应也不带热目标的候选边界，不能当作按
	// 新契约生成的结果复用——版本号让旧结果自然查不到、按需重新生成，不长期兼容两套语义。
	const explainCoverageRev = "cov1"
	explainVariant := func(lang string) string { return lang + "/" + explainCoverageRev }
	key := func(r *http.Request) aijob.Key {
		return aijob.Key{Kind: "explain", Subject: r.PathValue("id"), Variant: explainVariant(r.URL.Query().Get("lang")), Owner: auth.From(r.Context()).ID.String()}
	}
	mux.HandleFunc("GET /api/events/{id}/explain", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireScope(w, r, db, "viewer"); !ok {
			return
		}
		j, err := aijob.Latest(r.Context(), db, key(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, aijob.ViewOf(j))
	})
	mux.HandleFunc("POST /api/events/{id}/explain", func(w http.ResponseWriter, r *http.Request) {
		if !llm.Enabled() {
			http.Error(w, "未配置研判与标注模型，无法解读", http.StatusServiceUnavailable)
			return
		}
		e, groups, fromArchive, ok := load(w, r)
		if !ok {
			return
		}
		k := key(r)
		prev, err := aijob.Latest(r.Context(), db, k)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if aijob.Running(prev) || (prev != nil && prev.Status == "done" && r.URL.Query().Get("refresh") != "1") {
			writeJSON(w, aijob.ViewOf(prev))
			return
		}
		host := map[string]any{}
		if e.AssetID != nil {
			if a, err := db.Asset.Get(r.Context(), *e.AssetID); err == nil {
				host = map[string]any{"hostname": a.Hostname, "os": a.Os, "ips": a.IPAddrs, "role": a.Role, "summary": a.Summary}
			}
		}
		select {
		case slots <- struct{}{}:
		default:
			http.Error(w, "解读繁忙，请稍后重试", http.StatusTooManyRequests)
			return
		}
		// 结果与模型输入共用同一份覆盖事实（单一来源）；lang 是原始查询值，
		// variant 里并进的覆盖契约版本不参与 Messages 的语言判断
		archive := archiveScopeOf(fromArchive)
		system, user := eventai.Messages(e, host, groups, r.URL.Query().Get("lang"), eventai.HotOnlyCoverage)
		// 已有一次在跑（别的标签页或节点刚发起）时 Start 返回那一次，照样轮询它
		j, _, err := aijob.Start(r.Context(), db, k, func(ctx context.Context) (any, error) {
			reply, err := llm.Chat(ctx, []triage.Message{{Role: "system", Content: system}, {Role: "user", Content: user}}, nil)
			if err != nil {
				return nil, fmt.Errorf("模型调用失败：%w", err)
			}
			parsed, err := eventai.Parse(reply.Content, groups)
			if err != nil {
				return nil, err
			}
			// 模型解读 + 平台侧的候选边界说明一起进结果：读结果的人（前端、模型重放）都看得到
			return explainResult{Explanation: parsed, Archive: archive}, nil
		}, func() { <-slots })
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, aijob.ViewOf(j))
	})
	return mux
}

// loadEventHotOrCold 先查热表（带作用域），查不到再按 id 定位冷事件。
// 返回 (事件, 是否来自冷层, 是否继续)；失败时已写好响应。
func loadEventHotOrCold(w http.ResponseWriter, r *http.Request, db *ent.Client, conn *sql.DB, s scope, id uuid.UUID) (*ent.Event, bool, bool) {
	e, err := db.Event.Query().Where(append(s.event(), entevent.IDEQ(id))...).Only(r.Context())
	if ent.IsNotFound(err) {
		return loadColdEvent(w, r, conn, s, id)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, false, false
	}
	return e, false, true
}

// loadColdEvent 按 id 在冷层找一条事件。只读：不物化回热表、不建 pin。
//
// 权限与热表同口径：冷事件没有组视图，也没有热表那样的谓词下推，只能按
// asset_id ∈ 可见资产过滤（asset_id 为 NULL 的冷事件只有 admin 能看）——
// 复用 /api/events 冷查询的 visibleAssets 同一口径（events.go），两边不会漂移。
// 作用域外与不存在同样报 404，不暴露冷层里有没有这条事件。
func loadColdEvent(w http.ResponseWriter, r *http.Request, conn *sql.DB, s scope, id uuid.UUID) (*ent.Event, bool, bool) {
	if conn == nil {
		// 冷读关闭：与热表查不到同一口径
		http.Error(w, "日志不存在或无权查看", http.StatusNotFound)
		return nil, false, false
	}
	e, found, err := eventarchive.Locate(r.Context(), conn, id)
	if err != nil {
		// 冷层状态说不清（表未初始化、locator 未回填完）时不能断言「不存在」：
		// 404 并在响应体说明原因。块损坏等真实读取错误如实 500，不用 404 掩盖。
		if errors.Is(err, eventarchive.ErrNoSchema) || errors.Is(err, eventarchive.ErrLocatorIncomplete) {
			http.Error(w, "日志不在热表，且冷层状态未知（"+err.Error()+"）", http.StatusNotFound)
			return nil, false, false
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, false, false
	}
	if !found || !coldEventVisible(s, e) {
		http.Error(w, "日志不存在或无权查看", http.StatusNotFound)
		return nil, false, false
	}
	// 转成与热表同构的行：Related / Messages 只认 *ent.Event，字段一个不少地带过去
	return &ent.Event{
		ID: e.ID, Ts: e.Ts, ClassUID: int(e.ClassUID), Source: e.Source,
		AssetID: e.AssetID, ProcessGUID: e.ProcessGUID, ParentProcessGUID: e.ParentProcessGUID,
		Username: e.Username, ConnTuple: e.ConnTuple, Raw: e.Raw,
	}, true, true
}

// coldEventVisible 冷事件可见性，与热表 scope.event()（AssetIDIn(可见资产)）等效。
func coldEventVisible(s scope, e eventarchive.Event) bool {
	assets := visibleAssets(s, nil)
	if assets == nil {
		return true // admin 不限
	}
	// 非 admin：asset_id 为 NULL（无归属）或组外资产都不可见
	return e.AssetID != nil && slices.Contains(assets, *e.AssetID)
}

func toEventRow(e *ent.Event) eventRow {
	return eventRow{ID: e.ID, Ts: e.Ts, ClassUID: e.ClassUID, Source: e.Source, AssetID: e.AssetID, Username: e.Username, ConnTuple: e.ConnTuple, Raw: e.Raw}
}
