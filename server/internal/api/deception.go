package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"openxdr/server/deception/contract"
	"openxdr/server/ent"
	"openxdr/server/ent/decoyenginerelease"
	"openxdr/server/ent/decoyobservation"
	"openxdr/server/ent/decoyrevision"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/decoy"
)

func decodeDeception(w http.ResponseWriter, r *http.Request, out any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "请求格式无效", 400)
		return false
	}
	return true
}
func releaseSpec(r *ent.DecoyEngineRelease) contract.Release {
	return contract.Release{Engine: r.Engine, Version: r.Version, Digest: r.Digest, Protocol: r.Protocol, StateSchema: r.StateSchema}
}
func revisionConfig(rev *ent.DecoyRevision) (contract.EngineConfig, error) {
	raw, err := json.Marshal(rev.Spec)
	if err != nil {
		return contract.EngineConfig{}, err
	}
	return contract.DecodeConfig(raw)
}

func mapDeceptionManagement(mux *http.ServeMux, db *ent.Client) {
	mux.HandleFunc("GET /api/deception/hosted-status", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		var status struct {
			SeenAt *time.Time `json:"seenAt"`
			Online bool       `json:"online"`
		}
		row, err := db.Setting.Get(r.Context(), "deception.hosted")
		if err != nil && !ent.IsNotFound(err) {
			http.Error(w, "读取管理器状态失败", 503)
			return
		}
		if err == nil {
			if json.Unmarshal(row.Value, &status) != nil {
				http.Error(w, "管理器状态无效", 503)
				return
			}
			status.Online = status.SeenAt != nil && time.Since(*status.SeenAt) >= 0 && time.Since(*status.SeenAt) <= 30*time.Second
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, status)
	})
	mux.HandleFunc("GET /api/deception/hosted-release", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		release, err := hostedRelease(db, r.Context())
		if ent.IsNotFound(err) {
			writeJSON(w, nil)
			return
		}
		if err != nil {
			http.Error(w, "读取托管版本失败", 503)
			return
		}
		writeJSON(w, release)
	})
	mux.HandleFunc("GET /api/deception/releases", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		rows, err := db.DecoyEngineRelease.Query().Order(ent.Desc(decoyenginerelease.FieldCreatedAt)).Limit(201).All(r.Context())
		if err != nil {
			http.Error(w, "查询引擎版本失败", 500)
			return
		}
		if len(rows) > 200 {
			rows = rows[:200]
		}
		writeJSON(w, rows)
	})
	mux.HandleFunc("POST /api/deception/releases", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		if auth.From(r.Context()).Role != "admin" {
			http.Error(w, "仅全局管理员可准入引擎版本", 403)
			return
		}
		var body contract.Release
		if !decodeDeception(w, r, &body) {
			return
		}
		if body.Validate() != nil {
			http.Error(w, "引擎版本或协议无效", 400)
			return
		}
		tx, err := db.Tx(r.Context())
		if err != nil {
			http.Error(w, "开启事务失败", 500)
			return
		}
		defer tx.Rollback()
		row, err := tx.DecoyEngineRelease.Create().SetEngine(body.Engine).SetVersion(body.Version).SetDigest(body.Digest).SetProtocol(body.Protocol).SetStateSchema(body.StateSchema).SetCreatedBy(auth.From(r.Context()).Username).Save(r.Context())
		if ent.IsConstraintError(err) {
			http.Error(w, "引擎版本已登记", 409)
			return
		}
		if err == nil {
			err = audit.Checked(r.Context(), tx.AuditLog.Create(), auth.From(r.Context()).Username, audit.RemoteAddr(r), "deception_release_admitted", row.ID.String(), body.Engine+" "+body.Version+" "+body.Digest)
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			http.Error(w, "保存引擎版本失败", 500)
			return
		}
		w.WriteHeader(201)
		writeJSON(w, row)
	})
	mux.HandleFunc("POST /api/deception/releases/{id}/disable", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		if auth.From(r.Context()).Role != "admin" {
			http.Error(w, "仅全局管理员可停用版本", 403)
			return
		}
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "版本 ID 无效", 400)
			return
		}
		tx, err := db.Tx(r.Context())
		if err != nil {
			http.Error(w, "开启事务失败", 500)
			return
		}
		defer tx.Rollback()
		if err = tx.DecoyEngineRelease.UpdateOneID(id).SetEnabled(false).Exec(r.Context()); err == nil {
			err = audit.Checked(r.Context(), tx.AuditLog.Create(), auth.From(r.Context()).Username, audit.RemoteAddr(r), "deception_release_disabled", id.String(), "停用版本并拒绝后续运行认证")
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			http.Error(w, "停用版本失败", 500)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /api/decoys/{id}/revisions", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		row, ok := getByPath(w, r, "id", "decoy", db.DecoyDeployment.Get)
		if !ok || !assetInScope(w, r, db, row.AssetID, "viewer") {
			return
		}
		items, err := db.DecoyRevision.Query().Where(decoyrevision.DeploymentIDEQ(row.ID)).Order(ent.Desc(decoyrevision.FieldNumber)).Limit(101).All(r.Context())
		if err != nil {
			http.Error(w, "查询修订失败", 500)
			return
		}
		more := len(items) > 100
		if more {
			items = items[:100]
		}
		writeJSON(w, map[string]any{"items": items, "more": more})
	})
	mux.HandleFunc("POST /api/decoys/{id}/revisions", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		row, ok := getByPath(w, r, "id", "decoy", db.DecoyDeployment.Get)
		if !ok {
			return
		}
		var body struct {
			ReleaseID        uuid.UUID       `json:"releaseId"`
			Config           json.RawMessage `json:"config"`
			ExpectedRevision *uuid.UUID      `json:"expectedRevision"`
		}
		if !decodeDeception(w, r, &body) {
			return
		}
		cfg, err := contract.DecodeConfig(body.Config)
		if err != nil {
			http.Error(w, err.Error(), 400)
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
		row, err = tx.DecoyDeployment.Get(r.Context(), row.ID)
		if err != nil {
			http.Error(w, "登记不可用", 409)
			return
		}
		if row.Status != "registered" || row.InstallState == "installing" || decoyLeaseActive(row, time.Now()) || (row.RuntimeInstanceID != nil && row.RuntimeState != "stopped" && row.RuntimeState != "failed") {
			http.Error(w, "请先停止并确认旧实例退出，再切换引擎修订", 409)
			return
		}
		if (row.ActiveRevisionID == nil) != (body.ExpectedRevision == nil) || (row.ActiveRevisionID != nil && *row.ActiveRevisionID != *body.ExpectedRevision) {
			http.Error(w, "部署修订已变化，请刷新", 409)
			return
		}
		rel, err := tx.DecoyEngineRelease.Get(r.Context(), body.ReleaseID)
		if err != nil || !rel.Enabled {
			http.Error(w, "引擎版本未准入或已停用", 400)
			return
		}
		if rel.Engine == "dygk" && (row.Kind != "http" || row.Profile != "decoy") {
			http.Error(w, "DYGK Web 版本仅适用于 HTTP 诱饵识别策略", 400)
			return
		}
		if cfg.Hosted && rel.Engine != "dygk" {
			http.Error(w, "平台托管仅支持 DYGK Web 引擎", 400)
			return
		}
		if rel.Engine == "native" && (cfg.Attachment != "standalone" || cfg.Mode != "observe") {
			http.Error(w, "原生兼容载体仅支持独立观察模式", 400)
			return
		}
		if row.ActiveRevisionID != nil {
			old, e := tx.DecoyRevision.Get(r.Context(), *row.ActiveRevisionID)
			if e != nil {
				http.Error(w, "旧修订不可用", 409)
				return
			}
			oldRel, e := tx.DecoyEngineRelease.Get(r.Context(), old.ReleaseID)
			if e != nil || oldRel.StateSchema != rel.StateSchema {
				http.Error(w, "状态格式不兼容，需建立新登记并完成状态迁移", 422)
				return
			}
		}
		previous, err := tx.DecoyRevision.Query().Where(decoyrevision.DeploymentIDEQ(row.ID)).Order(ent.Desc(decoyrevision.FieldNumber)).First(r.Context())
		number := 1
		if err == nil {
			number = previous.Number + 1
		} else if !ent.IsNotFound(err) {
			http.Error(w, "读取旧修订失败", 500)
			return
		}
		raw, _ := json.Marshal(cfg)
		var spec map[string]any
		_ = json.Unmarshal(raw, &spec)
		rev, err := tx.DecoyRevision.Create().SetDeploymentID(row.ID).SetNumber(number).SetReleaseID(rel.ID).SetSpec(spec).SetCreatedBy(auth.From(r.Context()).Username).Save(r.Context())
		if err == nil {
			err = tx.DecoyDeployment.UpdateOneID(row.ID).SetActiveRevisionID(rev.ID).ClearTokenHash().ClearTokenExpiresAt().ClearTokenGroupID().ClearTokenRevisionID().SetStopRequested(false).Exec(r.Context())
		}
		if err == nil {
			err = audit.Checked(r.Context(), tx.AuditLog.Create(), auth.From(r.Context()).Username, audit.RemoteAddr(r), "deception_revision_selected", row.ID.String(), fmt.Sprintf("修订 %d；%s %s；动作 %s；接入 %s", number, rel.Engine, rel.Version, cfg.Mode, cfg.Attachment))
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			http.Error(w, "保存部署修订失败", 500)
			return
		}
		w.WriteHeader(201)
		writeJSON(w, rev)
	})
	mux.HandleFunc("POST /api/decoys/{id}/stop", func(w http.ResponseWriter, r *http.Request) {
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
		row, err = tx.DecoyDeployment.Get(r.Context(), row.ID)
		if err != nil || row.ActiveRevisionID == nil {
			http.Error(w, "旧运行端请按部署说明停止", 409)
			return
		}
		err = tx.DecoyDeployment.UpdateOneID(row.ID).SetStopRequested(true).Exec(r.Context())
		if err == nil {
			err = audit.Checked(r.Context(), tx.AuditLog.Create(), auth.From(r.Context()).Username, audit.RemoteAddr(r), "deception_stop_requested", row.ID.String(), "已请求停止，仍需等待运行实例确认")
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			http.Error(w, "请求停止失败", 500)
			return
		}
		w.WriteHeader(202)
	})
}

// DeceptionRuntime 与旧运行入口共用登记认证与资产锁；新协议必须绑定修订。
func DeceptionRuntime(db *ent.Client) http.Handler {
	mux := http.NewServeMux()
	for _, pattern := range []string{"GET /api/deception-runtime/v1/deployments/{id}/config", "POST /api/deception-runtime/v1/deployments/{id}/handshake", "POST /api/deception-runtime/v1/deployments/{id}/lease", "POST /api/deception-runtime/v1/deployments/{id}/observations"} {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			r = r.WithContext(ctx)
			w.Header().Set("Cache-Control", "no-store")
			tx, row, host, token, ok := authenticateDecoyRuntime(w, r, db)
			if !ok {
				return
			}
			defer tx.Rollback()
			if row.ActiveRevisionID == nil || row.TokenRevisionID == nil || *row.ActiveRevisionID != *row.TokenRevisionID {
				http.Error(w, "运行令牌未绑定有效修订", 409)
				return
			}
			rev, err := tx.DecoyRevision.Get(ctx, *row.ActiveRevisionID)
			if err != nil {
				http.Error(w, "修订不可用", 409)
				return
			}
			rel, err := tx.DecoyEngineRelease.Get(ctx, rev.ReleaseID)
			if err != nil || !rel.Enabled {
				http.Error(w, "引擎版本已停用", 403)
				return
			}
			cfg, err := revisionConfig(rev)
			if err != nil {
				http.Error(w, "修订配置无效", 409)
				return
			}
			manifest := contract.Manifest{AssetID: host.ID.String(), GroupID: host.GroupID.String(), ID: row.ID.String(), Kind: string(row.Kind), Profile: row.Profile, Template: row.Template, Port: row.Port, Resource: row.Resource, Marker: row.Marker}
			if r.Method == http.MethodGet {
				writeJSON(w, contract.RuntimeConfig{Manifest: manifest, Revision: rev.ID.String(), Release: releaseSpec(rel), Config: cfg, StopRequested: row.StopRequested})
				return
			}
			operation := r.URL.Path[stringsLastSlash(r.URL.Path)+1:]
			if operation == "handshake" {
				var body contract.Handshake
				if !decodeDeception(w, r, &body) {
					return
				}
				if body.Revision != rev.ID.String() || body.Release != releaseSpec(rel) || body.Instance != r.Header.Get("X-Decoy-Instance") || row.StopRequested {
					http.Error(w, "运行产物、修订或实例不匹配", 409)
					return
				}
				b, _ := json.Marshal(map[string]string{"instance": body.Instance, "state": "starting"})
				r.Body = io.NopCloser(bytes.NewReader(b))
				updateDecoyLease(w, r, tx, row, token)
				return
			}
			if r.Header.Get("X-Decoy-Revision") != rev.ID.String() {
				http.Error(w, "修订不匹配", 409)
				return
			}
			if operation == "lease" {
				if row.StopRequested {
					var state struct {
						Instance  string `json:"instance"`
						State     string `json:"state"`
						Pending   *int   `json:"pending,omitempty"`
						ErrorCode string `json:"errorCode,omitempty"`
					}
					if !decodeDeception(w, r, &state) {
						return
					}
					if state.State != "stopped" && state.State != "failed" {
						http.Error(w, "已请求停止", 409)
						return
					}
					b, _ := json.Marshal(state)
					r.Body = io.NopCloser(bytes.NewReader(b))
				}
				updateDecoyLease(w, r, tx, row, token)
				return
			}
			if !decoyLeaseAllows(row, r.Header.Get("X-Decoy-Instance"), token, time.Now()) {
				http.Error(w, "运行实例不可写入观察", 409)
				return
			}
			var body struct {
				Items []contract.Fact `json:"items"`
			}
			if !decodeDeception(w, r, &body) {
				return
			}
			if len(body.Items) == 0 || len(body.Items) > 100 {
				http.Error(w, "每批应为 1 到 100 条观察", 400)
				return
			}
			count, err := tx.DecoyObservation.Query().Where(decoyobservation.DeploymentIDEQ(row.ID), decoyobservation.ReceivedAtGT(time.Now().Add(-24*time.Hour))).Count(ctx)
			if err != nil {
				http.Error(w, "查询观察配额失败", 503)
				return
			}
			accepted := make([]string, 0, len(body.Items))
			for _, fact := range body.Items {
				if err = fact.Validate(); err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				if (fact.Kind == "ip_banned" && cfg.Mode != "block") || ((fact.Kind == "quarantine_started" || fact.Kind == "quarantine_request") && cfg.Mode != "quarantine") {
					http.Error(w, "事实与已授权动作不匹配", 400)
					return
				}
				id, _ := uuid.Parse(fact.ID)
				payload, _ := json.Marshal(fact)
				sum := sha256.Sum256(payload)
				hash := hex.EncodeToString(sum[:])
				old, e := tx.DecoyObservation.Get(ctx, id)
				if e == nil {
					if old.DeploymentID != row.ID || old.RevisionID == nil || *old.RevisionID != rev.ID || old.PayloadHash != hash {
						http.Error(w, "事件 ID 内容冲突", 409)
						return
					}
					accepted = append(accepted, fact.ID)
					continue
				}
				if !ent.IsNotFound(e) {
					http.Error(w, "读取观察失败", 503)
					return
				}
				if count >= 10000 {
					http.Error(w, "本登记达到每日结构化观察配额", 429)
					return
				}
				count++
				kind := contract.FactKinds[fact.Kind]
				if rel.Engine == "native" {
					if !contract.ValidEvent(string(row.Kind), fact.Kind) {
						http.Error(w, "事实与原生载体不匹配", 400)
						return
					}
					kind = fact.Kind
				} else if kind == "" {
					http.Error(w, "Web 引擎不接受原生事实", 400)
					return
				}
				trigger := ""
				var related *uuid.UUID
				if fact.Session != "" {
					prior, e := tx.DecoyObservation.Query().Where(decoyobservation.DeploymentIDEQ(row.ID), decoyobservation.RevisionIDEQ(rev.ID), decoyobservation.SessionIDEQ(fact.Session), decoyobservation.IncidentIDNotNil()).First(ctx)
					if e == nil {
						related = prior.IncidentID
					} else if !ent.IsNotFound(e) {
						http.Error(w, "查询会话失败", 503)
						return
					}
				}
				if decoy.AutoReview(kind) && related == nil {
					trigger = rev.ID.String() + ":" + kind + ":" + fact.Session
				}
				item, err := tx.DecoyObservation.Create().SetID(id).SetDeploymentID(row.ID).SetRevisionID(rev.ID).SetKind(kind).SetSessionID(fact.Session).SetTriggerKey(trigger).SetPayloadHash(hash).SetOccurredAt(fact.Time).SetDetails(map[string]any{"source_kind": fact.Kind, "stream_epoch": fact.Epoch, "sequence": fact.Sequence, "count": fact.Count}).SetNillableIncidentID(related).Save(ctx)
				if err != nil {
					http.Error(w, "保存观察失败", 503)
					return
				}
				if trigger != "" {
					severity, _ := decoy.ReviewSeverity(kind)
					incidentID, e := openDecoyIncident(ctx, tx, row, host, item, severity, "engine")
					if e != nil {
						http.Error(w, "保存复核事件失败", 503)
						return
					}
					_, err = tx.DecoyObservation.Update().Where(decoyobservation.DeploymentIDEQ(row.ID), decoyobservation.RevisionIDEQ(rev.ID), decoyobservation.SessionIDEQ(fact.Session), decoyobservation.IncidentIDIsNil()).SetIncidentID(incidentID).Save(ctx)
					if err == nil {
						err = audit.Checked(ctx, tx.AuditLog.Create(), "system", audit.RemoteAddr(r), "deception_trigger_review_opened", incidentID.String(), "模拟凭据验证触发；归因未确认")
					}
					if err != nil {
						http.Error(w, "保存会话复核关联失败", 503)
						return
					}
				}
				accepted = append(accepted, fact.ID)
			}
			if err = tx.Commit(); err != nil {
				http.Error(w, "保存观察失败", 503)
				return
			}
			writeJSON(w, map[string]any{"accepted": accepted})
		})
	}
	return mux
}

func stringsLastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}
