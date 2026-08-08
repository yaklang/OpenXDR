package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/audit"
)

// agentConfig 采集配置。字段少而具体——配置项每多一个，
// 就多一种"线上行为与代码不符"的可能，只放真正需要按机器调的东西。
type agentConfig struct {
	// 覆盖内置的敏感目录清单，为空表示用 agent 默认（Linux inotify）
	FileWatchDirs []string `json:"fileWatchDirs,omitempty"`
	// 采集开关，缺省全开。裸机排查噪声时按需关
	CollectFiles   *bool `json:"collectFiles,omitempty"`
	CollectAuth    *bool `json:"collectAuth,omitempty"`
	CollectPersist *bool `json:"collectPersist,omitempty"`
	CollectNetwork *bool `json:"collectNetwork,omitempty"`
}

func mapAgentConfig(api *http.ServeMux, db *ent.Client) {
	api.HandleFunc("GET /api/assets/{id}/config", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的 asset id", http.StatusBadRequest)
			return
		}
		a, err := db.Asset.Get(r.Context(), id)
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(a.Config) == 0 {
			writeJSON(w, agentConfig{})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(a.Config)
	})

	api.HandleFunc("PUT /api/assets/{id}/config", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的 asset id", http.StatusBadRequest)
			return
		}
		// 先解成结构体再存回去：拒绝无法识别的配置，
		// 免得 agent 拿到一份自己看不懂的 JSON 却无从报错
		var cfg agentConfig
		if json.NewDecoder(r.Body).Decode(&cfg) != nil {
			http.Error(w, "请求体不是合法配置 JSON", http.StatusBadRequest)
			return
		}
		normalized, err := json.Marshal(cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = db.Asset.UpdateOneID(id).SetConfig(normalized).Exec(r.Context())
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "agent_config_set", id.String(), string(normalized))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(normalized)
	})
}
