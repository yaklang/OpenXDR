package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/decoydeployment"
	"openxdr/server/ent/hostcredential"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/decoy"
	"openxdr/server/internal/hostimport"
)

type DecoyInstallConfig struct {
	Enabled            bool
	PublicURL, DistDir string
	install            func(context.Context, *ent.HostCredential, hostimport.Secret, string, string, string, string, string, string) error
}

func DecoyInstalls(s *hostimport.Service, cfg DecoyInstallConfig) http.Handler {
	mux := http.NewServeMux()
	_, urlErr := hostimport.EnrollmentURL(cfg.PublicURL)
	ready := cfg.Enabled && s.Vault != nil && urlErr == nil && cfg.DistDir != ""
	if cfg.install == nil {
		cfg.install = hostimport.Install
	}
	mux.HandleFunc("GET /api/decoy-install/status", func(w http.ResponseWriter, r *http.Request) {
		if decoyAuthenticated(w, r) {
			writeJSON(w, map[string]bool{"enabled": ready})
		}
	})
	mux.HandleFunc("POST /api/decoy-install/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		row, ok := getByPath(w, r, "id", "decoy", s.DB.DecoyDeployment.Get)
		if !ok {
			return
		}
		var body struct {
			Fingerprint string `json:"fingerprint"`
			Arch        string `json:"arch"`
			ListenHost  string `json:"listenHost"`
			FileRoot    string `json:"fileRoot"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&body) != nil || d.Decode(new(any)) != io.EOF || !hostimport.ValidFingerprint(body.Fingerprint) {
			http.Error(w, "须提供独立核对的 SSH 指纹及有效安装参数", 400)
			return
		}
		if body.ListenHost == "" {
			body.ListenHost = "127.0.0.1"
		}
		tx, err := s.DB.Tx(r.Context())
		if err != nil {
			http.Error(w, "开启事务失败", 500)
			return
		}
		defer tx.Rollback()
		if !lockDecoyAsset(w, r, tx, row.AssetID) {
			return
		}
		if !ready {
			http.Error(w, "诱饵远程安装未启用", 503)
			return
		}
		row, err = tx.DecoyDeployment.Get(r.Context(), row.ID)
		if err != nil {
			http.Error(w, "登记不可用", 409)
			return
		}
		if row.Status != decoydeployment.StatusRegistered || row.InstallState != decoydeployment.InstallStateIdle || row.RuntimeInstanceID != nil || row.TokenHash != "" {
			http.Error(w, "仅允许全新登记安装；已有操作请先核查目标主机，勿直接重试", 409)
			return
		}
		if row.ActiveRevisionID != nil {
			http.Error(w, "独立引擎请通过受控运行包或容器部署，兼容安装入口不支持引擎修订", 400)
			return
		}
		if row.Kind == decoydeployment.KindShell || (row.Port > 0 && row.Port < 1024) {
			http.Error(w, "只支持文件或非特权端口的 SSH/HTTP 服务", 400)
			return
		}
		host, err := tx.Asset.Get(r.Context(), row.AssetID)
		if err != nil || host.Os == nil || *host.Os != "linux" {
			http.Error(w, "只支持明确标注为 Linux 的资产", 400)
			return
		}
		credential, err := tx.HostCredential.Query().Where(hostcredential.AssetIDEQ(host.ID), hostcredential.GroupIDEQ(*host.GroupID)).Only(r.Context())
		if err != nil {
			http.Error(w, "当前组没有此资产的可用凭据", 409)
			return
		}
		if credential.HostKey != "" && credential.HostKey != body.Fingerprint {
			http.Error(w, "指纹与保存的凭据不一致", 409)
			return
		}
		_, secret, err := (&hostimport.Service{DB: tx.Client(), Vault: s.Vault}).Credential(r.Context(), credential.ID, *host.GroupID)
		if err != nil {
			http.Error(w, "凭据解密失败", 409)
			return
		}
		script, err := decoy.InstallScript(cfg.DistDir, body.Arch, cfg.PublicURL, row.ID.String(), string(row.Kind), body.ListenHost, body.FileRoot)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		now := time.Now()
		lease := now.Add(3 * time.Minute)
		n, err := tx.HostCredential.Update().Where(hostcredential.IDEQ(credential.ID), hostcredential.LeaseUntilLT(now)).SetLeaseUntil(lease).Save(r.Context())
		if err != nil || n != 1 {
			http.Error(w, "此主机已有纳管操作进行中", 409)
			return
		}
		token := randomDecoyToken()
		err = tx.DecoyDeployment.UpdateOneID(row.ID).SetInstallState(decoydeployment.InstallStateInstalling).SetInstallStartedAt(now).SetTokenHash(decoyTokenHash(token)).SetTokenGroupID(*host.GroupID).SetTokenExpiresAt(now.Add(decoyTokenTTL)).SetMarker(randomDecoyToken()).Exec(r.Context())
		if err == nil {
			err = audit.Checked(r.Context(), tx.AuditLog.Create(), auth.From(r.Context()).Username, audit.RemoteAddr(r), "decoy_install_started", row.ID.String(), "使用已保存凭据安装专用诱饵；安装结果须结合运行租约核查")
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			http.Error(w, "安装登记与审计写入失败，未下发", 500)
			return
		}
		// 浏览器或反代断开不中断安装：半途切断 SSH 只会留下未确认的远端现场。
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Minute)
		defer cancel()
		installErr := cfg.install(ctx, credential, secret, host.Hostname, "linux", cfg.PublicURL, token, script, body.Fingerprint)
		resultCtx, resultCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer resultCancel()
		// 不自动重试，且不将连接中断当成未产生副作用；脚本开始前的失败确定无副作用，退回全新登记可修正后重试。
		state := decoydeployment.InstallStateInstalled
		if errors.Is(installErr, hostimport.ErrNotStarted) {
			state = decoydeployment.InstallStateIdle
		} else if installErr != nil {
			state = decoydeployment.InstallStateUnconfirmed
		}
		resultErr := finishDecoyInstall(resultCtx, s.DB, r, row.ID, credential.ID, lease, state)
		if state == decoydeployment.InstallStateIdle && resultErr == nil {
			http.Error(w, installErr.Error()+"；目标未执行安装，修正后可重试", 409)
			return
		}
		if installErr != nil || resultErr != nil {
			http.Error(w, "安装结果未确认；请核查目标服务、文件和运行租约，勿直接重试", 502)
			return
		}
		writeJSON(w, map[string]string{"status": "installed", "message": "安装脚本完成，待运行租约与端点核验"})
	})
	return mux
}

func finishDecoyInstall(ctx context.Context, db *ent.Client, r *http.Request, id, credentialID uuid.UUID, lease time.Time, state decoydeployment.InstallState) error {
	tx, err := db.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	update := tx.DecoyDeployment.UpdateOneID(id).SetInstallState(state)
	action := "decoy_install_" + string(state)
	if state == decoydeployment.InstallStateIdle {
		// 未下发的令牌作废，登记回到可安装状态。
		update.ClearTokenHash().ClearTokenGroupID().ClearTokenExpiresAt().ClearMarker().ClearInstallStartedAt()
		action = "decoy_install_not_started"
	}
	err = update.Exec(ctx)
	if err == nil {
		err = audit.Checked(ctx, tx.AuditLog.Create(), auth.From(r.Context()).Username, audit.RemoteAddr(r), action, id.String(), "安装脚本结果；不代表诱饵已在线，需核对租约与目标服务")
	}
	if err == nil {
		_, err = tx.HostCredential.Update().Where(hostcredential.IDEQ(credentialID), hostcredential.LeaseUntilEQ(lease)).SetLeaseUntil(time.Unix(0, 0)).Save(ctx)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
