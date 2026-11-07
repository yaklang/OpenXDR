package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"openxdr/server/internal/flowinput"
	"time"
)

func FlowEnvelope(origin flowinput.Origin, event flowinput.Event) Envelope {
	raw, _ := json.Marshal(map[string]any{
		"metadata":        map[string]any{"product": map[string]string{"name": event.Source}, "observer": origin.Observer, "group_id": origin.GroupID},
		"src_endpoint":    map[string]any{"ip": event.SrcIP, "port": event.SrcPort},
		"dst_endpoint":    map[string]any{"ip": event.DstIP, "port": event.DstPort},
		"connection_info": map[string]any{"protocol_name": event.Protocol, "protocol_num": event.ProtocolNum},
		"flow":            event.Raw,
		"traffic":         event.Traffic,
	})
	return Envelope{Version: EnvelopeVersion, ID: StableID(event.Source, origin.GroupID.String(), origin.Observer, string(event.Raw)),
		PartitionKey: event.Source + "|" + origin.GroupID.String() + "|" + origin.Observer, Timestamp: event.Time, ClassUID: 4001, Source: event.Source,
		ConnTuple: event.ConnTuple(), Raw: raw, Flow: &origin, FingerprintSuffix: "|" + origin.GroupID.String() + "|" + origin.Observer}
}

// flowAsset 消费时再次核对组和在线资产；历史流不按当前 IP 反推资产。
func flowAsset(ctx context.Context, tx *sql.Tx, e Envelope) (Envelope, error) {
	if e.Source != "ntopng" && e.Source != "nprobe" {
		return e, nil
	}
	var raw struct {
		Flow json.RawMessage `json:"flow"`
	}
	if err := json.Unmarshal(e.Raw, &raw); err != nil {
		return e, err
	}
	event, err := flowinput.Parse(e.Source, raw.Flow)
	if err != nil {
		return e, err
	}
	if !event.Time.Equal(e.Timestamp) || e.ClassUID != 4001 || event.ConnTuple() != e.ConnTuple {
		return e, fmt.Errorf("流量信封与原始证据不一致")
	}
	e.AssetID, e.AssetOS = nil, ""
	delta := e.Flow.Received.Sub(e.Timestamp)
	if delta < -5*time.Minute || delta > 5*time.Minute {
		return e, nil
	}
	// 一条流只归属一个端点，优先发起端，未匹配再查目的端；不猜测不存在的进程归属。
	e.AssetID, e.AssetOS, err = suricataAsset(ctx, tx, e.Flow.GroupID, event.SrcIP, event.Time)
	if err == nil && e.AssetID == nil {
		e.AssetID, e.AssetOS, err = suricataAsset(ctx, tx, e.Flow.GroupID, event.DstIP, event.Time)
	}
	if e.AssetID != nil {
		e.PartitionKey = e.AssetID.String()
	}
	return e, err
}
