package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/decoydeployment"
	"openxdr/server/ent/decoyobservation"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/decoy"
)

func mapDecoyRuntimeManagement(mux *http.ServeMux, db *ent.Client) {
	mux.HandleFunc("POST /api/decoys/{id}/token", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		row, ok := getByPath(w, r, "id", "decoy", db.DecoyDeployment.Get)
		if !ok {
			return
		}
		tx, err := db.Tx(r.Context())
		if err != nil {
			http.Error(w, "开启事务失败", 500)
			return
		}
		defer tx.Rollback()
		if !lockDecoyAsset(w, r, tx, row.AssetID) {
			return
		}
		a, err := tx.Asset.Get(r.Context(), row.AssetID)
		if err != nil {
			http.Error(w, "查询资产失败", 500)
			return
		}
		current, err := tx.DecoyDeployment.Get(r.Context(), row.ID)
		if err != nil {
			http.Error(w, "登记不可用", 409)
			return
		}
		if current.InstallState == decoydeployment.InstallStateInstalling {
			http.Error(w, "安装结果待确认，请先核查目标主机", 409)
			return
		}
		token, marker := randomDecoyToken(), randomDecoyToken()
		expires := time.Now().Add(decoyTokenTTL)
		n, err := tx.DecoyDeployment.Update().Where(decoydeployment.IDEQ(row.ID), decoydeployment.StatusEQ(decoydeployment.StatusRegistered)).SetTokenHash(decoyTokenHash(token)).SetTokenGroupID(*a.GroupID).SetTokenExpiresAt(expires).SetMarker(marker).SetNillableTokenRevisionID(current.ActiveRevisionID).SetStopRequested(false).Save(r.Context())
		if err == nil && n == 0 {
			http.Error(w, "登记已撤销", 409)
			return
		}
		if err == nil {
			err = decoyAudit(r, tx, "decoy_runtime_token_rotated", row.ID)
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			http.Error(w, "签发令牌失败", 500)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"token": token, "expiresAt": expires})
	})
	mux.HandleFunc("GET /api/decoys/{id}/observations", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		row, ok := getByPath(w, r, "id", "decoy", db.DecoyDeployment.Get)
		if !ok {
			return
		}
		if !assetInScope(w, r, db, row.AssetID, "viewer") {
			return
		}
		rows, err := db.DecoyObservation.Query().Where(decoyobservation.DeploymentIDEQ(row.ID)).Order(ent.Desc(decoyobservation.FieldReceivedAt), ent.Desc(decoyobservation.FieldID)).Limit(101).All(r.Context())
		if err != nil {
			http.Error(w, "查询事件失败", 500)
			return
		}
		more := len(rows) > 100
		if more {
			rows = rows[:100]
		}
		writeJSON(w, struct {
			Items []*ent.DecoyObservation `json:"items"`
			More  bool                    `json:"more"`
		}{rows, more})
	})
}

// decoyTokenTTL 是令牌未被续租时的有效期；运行实例续租时顺延。
const decoyTokenTTL = 24 * time.Hour

func randomDecoyToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
func decoyTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// DecoyRuntime 必须单独挂载；只接受布放令牌，不借用控制台会话或客户端声称的资产身份。
func DecoyRuntime(db *ent.Client) http.Handler {
	mux := http.NewServeMux()
	handle := func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		w.Header().Set("Cache-Control", "no-store")
		tx, row, a, token, ok := authenticateDecoyRuntime(w, r, db)
		if !ok {
			return
		}
		defer tx.Rollback()
		id := row.ID
		if row.ActiveRevisionID != nil {
			http.Error(w, "此登记要求版本化运行协议", 409)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/lease") {
			updateDecoyLease(w, r, tx, row, token)
			return
		}
		if r.Method == http.MethodGet {
			writeJSON(w, decoy.Manifest{AssetID: row.AssetID.String(), GroupID: a.GroupID.String(), ID: row.ID.String(), Kind: string(row.Kind), Profile: row.Profile, Template: row.Template, Port: row.Port, Resource: row.Resource, Marker: row.Marker})
			return
		}
		if row.RuntimeInstanceID != nil && !decoyLeaseAllows(row, r.Header.Get("X-Decoy-Instance"), token, time.Now()) {
			http.Error(w, "运行租约无效", 409)
			return
		}
		var event decoy.Observation
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		d.DisallowUnknownFields()
		if d.Decode(&event) != nil || d.Decode(new(any)) != io.EOF || !decoy.ValidEvent(string(row.Kind), event.Kind) {
			http.Error(w, "事件无效", 400)
			return
		}
		eventID, err := uuid.Parse(event.ID)
		if err != nil || eventID == uuid.Nil {
			http.Error(w, "事件 ID 无效", 400)
			return
		}
		old, err := tx.DecoyObservation.Get(ctx, eventID)
		if err == nil {
			if old.DeploymentID != id || old.Kind != event.Kind || old.Generation != decoyTokenHash(row.Marker) {
				http.Error(w, "事件 ID 冲突", 409)
				return
			}
			w.WriteHeader(204)
			return
		}
		if !ent.IsNotFound(err) {
			http.Error(w, "查询事件失败", 503)
			return
		}
		count, err := tx.DecoyObservation.Query().Where(decoyobservation.DeploymentIDEQ(id), decoyobservation.ReceivedAtGT(time.Now().Add(-24*time.Hour))).Count(ctx)
		if err != nil {
			http.Error(w, "查询配额失败", 503)
			return
		}
		if count >= 1000 {
			http.Error(w, "本布放已达到每日事件上限", 429)
			return
		}
		observation, err := tx.DecoyObservation.Create().SetID(eventID).SetDeploymentID(id).SetKind(event.Kind).SetGeneration(decoyTokenHash(row.Marker)).Save(ctx)
		if ent.IsConstraintError(err) {
			http.Error(w, "事件 ID 冲突", 409)
			return
		}
		// 标记命中直接进待复核，不必等人翻诱饵页；与观察同事务，开单失败则整条拒收让运行端重试。
		if err == nil && decoy.AutoReview(event.Kind) {
			severity, _ := decoy.ReviewSeverity(event.Kind)
			var incidentID uuid.UUID
			if incidentID, err = openDecoyIncident(ctx, tx, row, a, observation, severity, "marker"); err == nil {
				err = audit.Checked(ctx, tx.AuditLog.Create(), "system", audit.RemoteAddr(r), "decoy_marker_review_opened", incidentID.String(), "标记命中自动开单，观察 "+observation.ID.String()+"；不代表攻击归因")
			}
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			http.Error(w, "保存事件失败", 503)
			return
		}
		w.WriteHeader(204)
	}
	mux.HandleFunc("GET /api/decoy-runtime/{id}/config", handle)
	mux.HandleFunc("POST /api/decoy-runtime/{id}/events", handle)
	mux.HandleFunc("POST /api/decoy-runtime/{id}/lease", handle)
	return mux
}
func validDecoyToken(row *ent.DecoyDeployment, token string) bool {
	return row.Status == decoydeployment.StatusRegistered && row.TokenExpiresAt != nil && time.Now().Before(*row.TokenExpiresAt) && len(row.TokenHash) == 64 && subtle.ConstantTimeCompare([]byte(row.TokenHash), []byte(decoyTokenHash(token))) == 1
}

func authenticateDecoyRuntime(w http.ResponseWriter, r *http.Request, db *ent.Client) (*ent.Tx, *ent.DecoyDeployment, *ent.Asset, string, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "未认证", 401)
		return nil, nil, nil, "", false
	}
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		http.Error(w, "未认证", 401)
		return nil, nil, nil, "", false
	}
	token := strings.TrimPrefix(authorization, "Bearer ")
	if len(token) != 64 {
		http.Error(w, "未认证", 401)
		return nil, nil, nil, "", false
	}
	tx, err := db.Tx(r.Context())
	if err != nil {
		http.Error(w, "服务不可用", 503)
		return nil, nil, nil, "", false
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	row, err := tx.DecoyDeployment.Get(r.Context(), id)
	if err != nil || !validDecoyToken(row, token) {
		http.Error(w, "未认证", 401)
		return nil, nil, nil, "", false
	}
	// 与迁组、撤销、令牌轮换共用资产锁，防止认证后归属变化。
	a, err := tx.Asset.Query().Where(asset.IDEQ(row.AssetID), func(s *sql.Selector) { s.ForUpdate() }).Only(r.Context())
	if err != nil {
		http.Error(w, "未认证", 401)
		return nil, nil, nil, "", false
	}
	row, err = tx.DecoyDeployment.Get(r.Context(), id)
	if err != nil || !validDecoyToken(row, token) || a.GroupID == nil || row.TokenGroupID == nil || *a.GroupID != *row.TokenGroupID {
		http.Error(w, "未认证", 401)
		return nil, nil, nil, "", false
	}
	committed = true
	return tx, row, a, token, true
}
