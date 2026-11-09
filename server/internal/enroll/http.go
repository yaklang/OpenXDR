package enroll

import (
	"cmp"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"openxdr/server/internal/audit"
)

//go:embed install.sh
var installSh []byte

//go:embed install.ps1
var installPs1 []byte

//go:embed sensor-install.sh
var sensorInstallSh []byte

//go:embed sensor-install.ps1
var sensorInstallPs1 []byte

// Public 免登录的接入端点：安装脚本、agent / sensor 二进制与注册。注册靠令牌鉴权。
func (s *Service) Public(dists Dists) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/enroll/install.sh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write(installSh)
	})
	mux.HandleFunc("GET /api/enroll/install.ps1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(installPs1)
	})
	mux.HandleFunc("GET /api/enroll/sensor-install.sh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write(sensorInstallSh)
	})
	mux.HandleFunc("GET /api/enroll/sensor-install.ps1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(sensorInstallPs1)
	})
	mux.Handle("GET /api/enroll/agent/{platform}", serveDist(dists.Agent, "agent"))
	mux.Handle("GET /api/enroll/sensor/{platform}", serveDist(dists.Sensor, "sensor"))
	mux.Handle("GET /api/enroll/tray/{platform}", serveDist(dists.Tray, "tray"))
	mux.HandleFunc("POST /api/enroll/register", func(w http.ResponseWriter, r *http.Request) {
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		var req Request
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
			http.Error(w, "接入请求不是合法 JSON", http.StatusBadRequest)
			return
		}
		a, grant, err := s.Enroll(r.Context(), token, req)
		switch {
		case errors.Is(err, ErrToken):
			http.Error(w, err.Error(), http.StatusUnauthorized)
		case errors.Is(err, ErrOnline), errors.Is(err, ErrSensor), errors.Is(err, ErrMoved):
			http.Error(w, err.Error(), http.StatusConflict)
		case errors.Is(err, ErrKind):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, ErrHostname):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case err != nil && s.Disabled() != "":
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		case err != nil:
			slog.Error("主机接入失败", "hostname", req.Hostname, "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			action := "host_enrolled"
			if req.Kind == KindSensor {
				action = "sensor_enrolled"
			}
			audit.Log(r.Context(), s.DB, r, action, a.ID.String(), req.Hostname)
			slog.Info("主机已接入", "hostname", req.Hostname, "kind", cmp.Or(req.Kind, KindAgent), "group", a.GroupID)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(grant)
		}
	})
	return mux
}

// serveDist 下载安装包。
func serveDist(dist *Dist, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, err := dist.Open(r.PathValue("platform"))
		if err != nil {
			http.Error(w, "server 未提供该平台的 "+name+"（检查 AGENT_DIST_DIR）", http.StatusNotFound)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, "", st.ModTime(), f)
	})
}

// InstallScript 返回平台维护的安装脚本，远程纳管不接受文档提供的脚本内容。
func InstallScript(os string) string {
	if os == "windows" {
		return string(installPs1)
	}
	return string(installSh)
}
