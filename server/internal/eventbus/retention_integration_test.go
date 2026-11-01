//go:build integration

package eventbus

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"openxdr/server/internal/ingest"
)

// 每次使用独立实例，不修改 NATS_URL 指向的共享队列。
func isolatedNATS(t *testing.T) string {
	t.Helper()
	binary, err := exec.LookPath("nats-server")
	if err != nil {
		t.Skip("未安装 nats-server")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nats.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "nats.conf")
	if err := os.WriteFile(config, []byte("max_payload: 4MB\njetstream { sync_interval: always }"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-c", config, "-a", "127.0.0.1", "-p", "-1", "-sd", filepath.Join(dir, "data"))
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		log.Close()
	})
	pattern := regexp.MustCompile(`Listening for client connections on (127\.0\.0\.1:\d+)`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(logPath)
		if match := pattern.FindSubmatch(data); len(match) > 1 {
			url := "nats://" + string(match[1])
			nc, err := nats.Connect(url, nats.Timeout(100*time.Millisecond))
			if err == nil {
				nc.Close()
				return url
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("临时 NATS 未就绪")
	return ""
}

type heldProcessor struct{ ready atomic.Bool }

func (p *heldProcessor) Process(context.Context, ingest.Envelope) error {
	if !p.ready.Load() {
		return errors.New("测试处理器暂停")
	}
	return nil
}

func TestQueueFullPreservesAcknowledgedEvents(t *testing.T) {
	url := isolatedNATS(t)
	processor := &heldProcessor{}
	bus, err := NewJetStream(url, "retention-test", 1, 1, 2048, 0, processor, testMetrics{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var accepted []ingest.Envelope
	var rejected ingest.Envelope
	for i := 0; i < 20; i++ {
		event := ingest.Envelope{Version: ingest.EnvelopeVersion, ID: ingest.StableID(t.Name(), time.Now().String()), PartitionKey: "host", Timestamp: time.Now(), ClassUID: 1007, Source: "agent", Raw: json.RawMessage(`{"process":{"name":"test"}}`)}
		if err := bus.Publish(ctx, event); err != nil {
			if !strings.Contains(err.Error(), "maximum bytes") {
				t.Fatalf("不是容量拒收：%v", err)
			}
			rejected = event
			break
		}
		accepted = append(accepted, event)
	}
	if len(accepted) == 0 || rejected.Source == "" {
		t.Fatal("未验证有限容量拒收")
	}
	info, err := bus.js.StreamInfo(streamName)
	if err != nil {
		t.Fatal(err)
	}
	if info.Config.Discard != nats.DiscardNew || info.Config.MaxAge != 0 || info.State.Msgs != uint64(len(accepted)) {
		t.Fatalf("已确认消息丢失或配置错误: %+v", info)
	}
	for i, event := range accepted {
		msg, err := bus.js.GetMsg(streamName, uint64(i+1))
		if err != nil {
			t.Fatal("已确认消息被淘汰", err)
		}
		stored, err := ingest.Unmarshal(msg.Data)
		if err != nil || stored.ID != event.ID {
			t.Fatal("已确认消息发生变化", err)
		}
	}
	if other, err := NewJetStream(url, "shrink-test", 1, 1, 1, 0, processor, testMetrics{}, 1); err == nil {
		other.Close()
		t.Fatal("接受会丢弃积压的缩容")
	}
	processor.ready.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		info, err = bus.js.StreamInfo(streamName)
		if err != nil {
			t.Fatal(err)
		}
		if info.State.Msgs == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if info.State.Msgs != 0 {
		t.Fatal("恢复后队列未排空")
	}
	if err := bus.Publish(ctx, rejected); err != nil {
		t.Fatal("恢复后无法补传", err)
	}
}

func TestQueueMigratesOldRetentionWithoutDroppingBacklog(t *testing.T) {
	url := isolatedNATS(t)
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := nc.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	_, err = js.AddStream(&nats.StreamConfig{Name: streamName, Subjects: []string{subjectAll}, Description: "OpenXDR events; shards=1", Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage, MaxBytes: 4096, MaxAge: time.Hour, Discard: nats.DiscardOld})
	if err != nil {
		t.Fatal(err)
	}
	event := ingest.Envelope{Version: ingest.EnvelopeVersion, ID: ingest.StableID(t.Name()), PartitionKey: "host", Timestamp: time.Now(), ClassUID: 1007, Source: "agent", Raw: json.RawMessage(`{}`)}
	payload, err := event.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ack, err := js.Publish("openxdr.events.00", payload)
	if err != nil {
		t.Fatal(err)
	}
	bus, err := NewJetStream(url, "migration", 1, 1, 4096, 0, &heldProcessor{}, testMetrics{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	info, err := js.StreamInfo(streamName)
	if err != nil {
		t.Fatal(err)
	}
	if info.Config.Discard != nats.DiscardNew || info.Config.MaxAge != 0 {
		t.Fatal("未迁移保留策略")
	}
	msg, err := js.GetMsg(streamName, ack.Sequence)
	if err != nil || string(msg.Data) != string(payload) {
		t.Fatal("迁移丢失积压消息", err)
	}
}

func TestQueueAcceptsAgentSizedEvent(t *testing.T) {
	bus, err := NewJetStream(isolatedNATS(t), "large-event", 1, 1, 8<<20, 0, &heldProcessor{}, testMetrics{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	raw, _ := json.Marshal(map[string]string{"script": strings.Repeat("a", 2<<20)})
	event := ingest.Envelope{Version: ingest.EnvelopeVersion, ID: ingest.StableID(t.Name()), PartitionKey: "host", Timestamp: time.Now(), ClassUID: 1007, Source: "agent", Raw: raw}
	if err := bus.Publish(context.Background(), event); err != nil {
		t.Fatal("合法大事件无法入队", err)
	}
	info, err := bus.js.StreamInfo(streamName)
	if err != nil || info.State.Msgs != 1 {
		t.Fatal("大事件未保留", err)
	}
}
