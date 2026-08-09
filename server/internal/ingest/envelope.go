// Package ingest 定义跨接入节点传递的稳定事件信封与幂等处理器。
package ingest

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const EnvelopeVersion = 1

// Envelope 是队列中的唯一事件契约。接入节点只负责归一化与资产归属，
// 检测节点负责规则、情报、抑制、去重和落库。
type Envelope struct {
	Version           int             `json:"version"`
	ID                uuid.UUID       `json:"id"`
	PartitionKey      string          `json:"partition_key"`
	Timestamp         time.Time       `json:"timestamp"`
	ClassUID          int             `json:"class_uid"`
	Source            string          `json:"source"`
	AssetID           *uuid.UUID      `json:"asset_id,omitempty"`
	AssetOS           string          `json:"asset_os,omitempty"`
	ProcessGUID       *uuid.UUID      `json:"process_guid,omitempty"`
	ParentProcessGUID *uuid.UUID      `json:"parent_process_guid,omitempty"`
	Username          string          `json:"username,omitempty"`
	ConnTuple         string          `json:"conn_tuple,omitempty"`
	FingerprintSuffix string          `json:"fingerprint_suffix,omitempty"`
	Raw               json.RawMessage `json:"raw"`
}

func (e Envelope) Validate() error {
	if e.Version != EnvelopeVersion {
		return fmt.Errorf("不支持的事件信封版本 %d", e.Version)
	}
	if e.ID == uuid.Nil || e.Timestamp.IsZero() || e.ClassUID <= 0 || e.Source == "" || e.PartitionKey == "" {
		return fmt.Errorf("事件信封缺少必要字段")
	}
	if !json.Valid(e.Raw) {
		return fmt.Errorf("事件体不是合法 JSON")
	}
	return nil
}

// StableID 把来源侧稳定字段映射成 UUID。JetStream 重投、gateway 重试和
// agent 重连重放都会得到同一个 ID，数据库主键负责最终幂等。
func StableID(parts ...string) uuid.UUID {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	var id uuid.UUID
	copy(id[:], sum[:16])
	id[6] = (id[6] & 0x0f) | 0x80 // 私有确定性 UUID，使用 version 8 位型
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}

func (e Envelope) Marshal() ([]byte, error) { return json.Marshal(e) }

func Unmarshal(data []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return e, err
	}
	return e, e.Validate()
}
