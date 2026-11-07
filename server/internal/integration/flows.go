package integration

import (
	"io"
	"net/http"
	"openxdr/server/internal/flowinput"
	"time"
)

func (s *Service) flowEvents(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey{}).(principal)
	if len(p.Groups) != 1 {
		Error(w, 403, "forbidden", "流量写入须恰好授权一个组")
		return
	}
	if s.Flows == nil {
		Error(w, 503, "unavailable", "流量接入暂不可用")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if err != nil {
		Error(w, 413, "payload_too_large", "报文读取失败或超过 256 KiB")
		return
	}
	event, err := flowinput.Parse(r.PathValue("source"), raw)
	if err != nil {
		Error(w, 400, "invalid_argument", err.Error())
		return
	}
	origin := flowinput.Origin{Observer: p.Integration.ID.String(), GroupID: p.Groups[0], Received: time.Now().UTC()}
	if err := s.Flows(r.Context(), origin, event); err != nil {
		Error(w, 503, "unavailable", "暂时无法接收，请保留原始流量重试")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
