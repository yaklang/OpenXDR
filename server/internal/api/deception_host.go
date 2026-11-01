package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/google/uuid"
	"openxdr/server/deception/contract"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/decoydeployment"
	"openxdr/server/ent/decoyenginerelease"
	"openxdr/server/ent/decoyrevision"
	"openxdr/server/internal/audit"
)

// StartDeceptionHost 只在编排注入的 Unix socket 上提供内部调度，不开放网络管理端口。
func StartDeceptionHost(ctx context.Context, db *ent.Client, socket string) error {
	if socket == "" {
		return nil
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("托管引擎控制通道需要 Linux 文件权限，其他环境可使用远端运行包")
	}
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("引擎控制位置已存在且不是 socket")
		}
		c, e := net.DialTimeout("unix", socket, time.Second)
		if e == nil {
			c.Close()
			return fmt.Errorf("引擎控制 socket 已被使用")
		}
		if err = os.Remove(socket); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	if err = os.Chmod(socket, 0600); err != nil {
		listener.Close()
		return err
	}
	server := &http.Server{Handler: HostedDeception(db), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	go func() { <-ctx.Done(); _ = server.Close(); _ = listener.Close() }()
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("欺骗引擎控制通道退出", "err", err)
		}
	}()
	return nil
}

// HostedDeception 由 Unix socket 权限保护；实例令牌只由平台生成，不交给运维填写。
func HostedDeception(db *ent.Client) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/deception-runtime/", DeceptionRuntime(db))
	mux.HandleFunc("POST /engine/finished", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Release   contract.Release `json:"release"`
			Instances []struct {
				ID        uuid.UUID `json:"id"`
				Instance  uuid.UUID `json:"instance"`
				Revision  uuid.UUID `json:"revision"`
				State     string    `json:"state"`
				Pending   *int      `json:"pending,omitempty"`
				ErrorCode string    `json:"errorCode,omitempty"`
			} `json:"instances"`
		}
		if !decodeDeception(w, r, &body) {
			return
		}
		if body.Release.Validate() != nil || body.Release.Engine != "dygk" || len(body.Instances) > 100 {
			http.Error(w, "实例退出声明无效", 400)
			return
		}
		for _, item := range body.Instances {
			if item.Pending != nil && (*item.Pending < 0 || *item.Pending > 10000) {
				http.Error(w, "积压数量无效", 400)
				return
			}
			switch item.ErrorCode {
			case "", "delivery_failed", "platform_unavailable", "startup_failed", "pending_on_stop":
			default:
				http.Error(w, "错误码无效", 400)
				return
			}
			if item.ID == uuid.Nil || item.Instance == uuid.Nil || item.Revision == uuid.Nil || (item.State != "stopped" && item.State != "failed") {
				http.Error(w, "实例退出状态无效", 400)
				return
			}
		}
		accepted := []string{}
		for _, item := range body.Instances {
			row, err := db.DecoyDeployment.Get(r.Context(), item.ID)
			if ent.IsNotFound(err) {
				accepted = append(accepted, item.ID.String())
				continue
			}
			if err != nil {
				http.Error(w, "读取登记失败", 503)
				return
			}
			tx, err := db.Tx(r.Context())
			if err != nil {
				http.Error(w, "开启事务失败", 503)
				return
			}
			err = func() error {
				defer tx.Rollback()
				_, e := tx.Asset.Query().Where(asset.IDEQ(row.AssetID), func(s *sql.Selector) { s.ForUpdate() }).Only(r.Context())
				if e != nil {
					return e
				}
				current, e := tx.DecoyDeployment.Get(r.Context(), row.ID)
				if e != nil {
					return e
				}
				expectedRevision := current.TokenRevisionID
				if expectedRevision == nil {
					expectedRevision = current.ActiveRevisionID
				}
				if current.RuntimeInstanceID == nil || *current.RuntimeInstanceID != item.Instance || expectedRevision == nil || *expectedRevision != item.Revision {
					return nil
				}
				rev, e := tx.DecoyRevision.Get(r.Context(), item.Revision)
				if e != nil {
					return e
				}
				release, e := tx.DecoyEngineRelease.Get(r.Context(), rev.ReleaseID)
				if e != nil {
					return e
				}
				cfg, e := revisionConfig(rev)
				if e != nil {
					return e
				}
				if !cfg.Hosted || releaseSpec(release) != body.Release {
					return fmt.Errorf("退出声明与托管实例不一致")
				}
				if string(current.RuntimeState) == item.State && current.RuntimeError == item.ErrorCode && (item.Pending == nil || current.RuntimePending != nil && *current.RuntimePending == *item.Pending) {
					return nil
				}
				update := tx.DecoyDeployment.UpdateOneID(row.ID).SetRuntimeState(decoydeployment.RuntimeState(item.State)).SetRuntimeSeenAt(time.Now()).SetRuntimeError(item.ErrorCode)
				if item.Pending != nil {
					update.SetRuntimePending(*item.Pending)
				}
				e = update.Exec(r.Context())
				if e == nil {
					e = audit.Checked(r.Context(), tx.AuditLog.Create(), "system", "", "deception_host_exit_confirmed", row.ID.String(), "受控引擎确认实例 "+item.Instance.String()+" 已退出，状态 "+item.State)
				}
				if e == nil {
					e = tx.Commit()
				}
				return e
			}()
			if err != nil {
				http.Error(w, "确认实例退出失败", 409)
				return
			}
			accepted = append(accepted, item.ID.String())
		}
		writeJSON(w, map[string]any{"accepted": accepted})
	})
	mux.HandleFunc("POST /engine/poll", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Release   contract.Release `json:"release"`
			Instances []struct {
				ID       string `json:"id"`
				Instance string `json:"instance"`
				Revision string `json:"revision"`
			} `json:"instances"`
		}
		if !decodeDeception(w, r, &body) {
			return
		}
		if body.Release.Engine != "dygk" || body.Release.Validate() != nil || len(body.Instances) > 100 {
			http.Error(w, "引擎声明无效", 400)
			return
		}
		rel, err := db.DecoyEngineRelease.Query().Where(decoyenginerelease.EngineEQ(body.Release.Engine), decoyenginerelease.VersionEQ(body.Release.Version), decoyenginerelease.DigestEQ(body.Release.Digest)).Only(r.Context())
		if ent.IsNotFound(err) {
			tx, e := db.Tx(r.Context())
			if e != nil {
				http.Error(w, "开启事务失败", 503)
				return
			}
			defer tx.Rollback()
			rel, err = tx.DecoyEngineRelease.Create().SetEngine(body.Release.Engine).SetVersion(body.Release.Version).SetDigest(body.Release.Digest).SetProtocol(body.Release.Protocol).SetStateSchema(body.Release.StateSchema).SetCreatedBy("system:deception-host").Save(r.Context())
			if err == nil {
				err = audit.Checked(r.Context(), tx.AuditLog.Create(), "system", "", "deception_host_release_registered", rel.ID.String(), "受控引擎服务回报实际产物 "+body.Release.Digest)
			}
			if err == nil {
				err = tx.Commit()
			}
		}
		if err != nil {
			http.Error(w, "登记运行版本失败", 503)
			return
		}
		if !rel.Enabled {
			http.Error(w, "运行版本已停用", 403)
			return
		}
		if releaseSpec(rel) != body.Release {
			http.Error(w, "运行包声明与已登记契约不一致", 409)
			return
		}
		status, _ := json.Marshal(map[string]any{"releaseId": rel.ID, "seenAt": time.Now()})
		if _, err = db.Setting.UpdateOneID("deception.hosted").SetValue(status).Save(r.Context()); ent.IsNotFound(err) {
			_, err = db.Setting.Create().SetID("deception.hosted").SetValue(status).Save(r.Context())
			if ent.IsConstraintError(err) {
				_, err = db.Setting.UpdateOneID("deception.hosted").SetValue(status).Save(r.Context())
			}
		}
		if err != nil {
			http.Error(w, "保存引擎状态失败", 503)
			return
		}
		rows, err := db.DecoyDeployment.Query().Where(decoydeployment.StatusEQ(decoydeployment.StatusRegistered), func(s *sql.Selector) {
			revs := sql.Table(decoyrevision.Table)
			s.Where(sql.In(s.C(decoydeployment.FieldActiveRevisionID), sql.Select(revs.C(decoyrevision.FieldID)).From(revs).Where(sql.And(
				sql.EQ(revs.C(decoyrevision.FieldReleaseID), rel.ID),
				sqljson.ValueEQ(revs.C(decoyrevision.FieldSpec), true, sqljson.Path("hosted")),
			))))
		}).Order(ent.Asc(decoydeployment.FieldID)).Limit(101).All(r.Context())
		if err != nil {
			http.Error(w, "读取托管登记失败", 503)
			return
		}
		if len(rows) > 100 {
			http.Error(w, "托管登记扫描达到当前容量限制", 422)
			return
		}
		type job struct {
			ID       string `json:"id"`
			Revision string `json:"revision"`
			Instance string `json:"instance"`
			Token    string `json:"token,omitempty"`
			Stop     bool   `json:"stop"`
		}
		jobs := []job{}
		for _, candidate := range rows {
			rev, e := db.DecoyRevision.Get(r.Context(), *candidate.ActiveRevisionID)
			if e != nil || rev.ReleaseID != rel.ID {
				continue
			}
			cfg, e := revisionConfig(rev)
			if e != nil || !cfg.Hosted {
				continue
			}
			tx, e := db.Tx(r.Context())
			if e != nil {
				http.Error(w, "开启事务失败", 503)
				return
			}
			func() {
				defer tx.Rollback()
				host, e := tx.Asset.Query().Where(asset.IDEQ(candidate.AssetID), func(s *sql.Selector) { s.ForUpdate() }).Only(r.Context())
				if e != nil || host.GroupID == nil {
					return
				}
				row, e := tx.DecoyDeployment.Get(r.Context(), candidate.ID)
				if e != nil || row.Status != "registered" || row.ActiveRevisionID == nil || *row.ActiveRevisionID != rev.ID {
					return
				}
				for _, instance := range body.Instances {
					if instance.ID == row.ID.String() && row.RuntimeInstanceID != nil && instance.Instance == row.RuntimeInstanceID.String() && instance.Revision == rev.ID.String() {
						jobs = append(jobs, job{ID: row.ID.String(), Revision: rev.ID.String(), Instance: instance.Instance, Stop: row.StopRequested || row.TokenGroupID == nil || *row.TokenGroupID != *host.GroupID})
						return
					}
				}
				if row.TokenGroupID != nil && *row.TokenGroupID != *host.GroupID {
					return
				}
				if row.StopRequested || decoyLeaseActive(row, time.Now()) {
					return
				}
				// 已明确退出的同一修订保持停止；新修订或失联实例可在租约过期后重新领取。
				if row.TokenRevisionID != nil && *row.TokenRevisionID == rev.ID && (row.RuntimeState == "stopped" || row.RuntimeState == "failed") {
					return
				}
				token, marker, instance := randomDecoyToken(), randomDecoyToken(), uuid.New()
				err := tx.DecoyDeployment.UpdateOneID(row.ID).SetTokenHash(decoyTokenHash(token)).SetMarker(marker).SetTokenGroupID(*host.GroupID).SetTokenRevisionID(rev.ID).SetTokenExpiresAt(time.Now().Add(decoyTokenTTL)).SetRuntimeInstanceID(instance).SetRuntimeState(decoydeployment.RuntimeStateStarting).ClearRuntimePending().SetRuntimeError("").SetRuntimeSeenAt(time.Now()).SetRuntimeGeneration(decoyTokenHash(token)).Exec(r.Context())
				if err == nil {
					err = audit.Checked(r.Context(), tx.AuditLog.Create(), "system", "", "deception_host_instance_assigned", row.ID.String(), "平台签发运行身份并分配修订 "+rev.ID.String())
				}
				if err == nil {
					err = tx.Commit()
				}
				if err == nil {
					jobs = append(jobs, job{ID: row.ID.String(), Revision: rev.ID.String(), Instance: instance.String(), Token: token})
				}
			}()
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"jobs": jobs})
	})
	return mux
}

func hostedRelease(db *ent.Client, ctx context.Context) (*ent.DecoyEngineRelease, error) {
	row, err := db.Setting.Get(ctx, "deception.hosted")
	if err != nil {
		return nil, err
	}
	var status struct {
		ReleaseID uuid.UUID `json:"releaseId"`
		SeenAt    time.Time `json:"seenAt"`
	}
	if json.Unmarshal(row.Value, &status) != nil || time.Since(status.SeenAt) > 30*time.Second {
		return nil, nil
	}
	release, err := db.DecoyEngineRelease.Get(ctx, status.ReleaseID)
	if err != nil {
		return nil, err
	}
	if !release.Enabled {
		return nil, nil
	}
	return release, nil
}
