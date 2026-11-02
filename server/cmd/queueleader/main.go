// queueleader 将指定节点上的事件队列 Leader 迁回已同步的节点，默认只预览。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

const stream = "OPENXDR_EVENTS"

type move struct {
	subject, name string
	cluster       *nats.ClusterInfo
}

func main() {
	url := flag.String("url", "nats://127.0.0.1:4222", "本机 NATS 客户端地址")
	from := flag.String("from", "openxdr-witness", "只迁移这个节点持有的 Leader")
	to := flag.String("to", "", "目标节点名称，必须已同步")
	apply := flag.Bool("apply", false, "实际迁移；默认只预览")
	flag.Parse()
	if err := run(*url, *from, *to, *apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(url, from, to string, apply bool) error {
	if from == "" || to == "" || from == to {
		return fmt.Errorf("from/to 必须非空且不同")
	}
	nc, err := nats.Connect(url, nats.Timeout(5*time.Second))
	if err != nil {
		return err
	}
	defer nc.Close()
	js, err := nc.JetStream(nats.MaxWait(5 * time.Second))
	if err != nil {
		return err
	}
	info, err := js.StreamInfo(stream)
	if err != nil {
		return err
	}
	moves := []move{{"$JS.API.STREAM.LEADER.STEPDOWN." + stream, "", info.Cluster}}
	// 先完整读取并校验计划，发现不健康目标时不做部分迁移。
	var shards int
	if _, err := fmt.Sscanf(info.Config.Description, "OpenXDR events; shards=%d", &shards); err != nil || shards < 1 || shards > 256 {
		return fmt.Errorf("无法确认事件流分片数，停止迁移")
	}
	for i := 0; i < shards; i++ {
		name := fmt.Sprintf("ingest-%02x", i)
		c, err := js.ConsumerInfo(stream, name)
		if err != nil {
			return err
		}
		moves = append(moves, move{"$JS.API.CONSUMER.LEADER.STEPDOWN." + stream + "." + name, name, c.Cluster})
	}
	for _, m := range moves {
		if err := validateTarget(m.cluster, from, to); err != nil {
			return fmt.Errorf("%s: %w", m.subject, err)
		}
	}
	payload, _ := json.Marshal(map[string]any{"placement": map[string]string{"preferred": to}})
	for _, m := range moves {
		if m.cluster.Leader != from {
			continue
		}
		fmt.Printf("%s: %s -> %s\n", m.subject, from, to)
		if !apply {
			continue
		}
		// 执行前再核对 Leader 和目标，防止预览后发生选举。
		current, err := clusterInfo(js, m.name)
		if err != nil {
			return err
		}
		if current == nil || current.Leader != from {
			return fmt.Errorf("Leader 已变化，停止并重新预览")
		}
		if err := validateTarget(current, from, to); err != nil {
			return err
		}
		msg, err := nc.Request(m.subject, payload, 8*time.Second)
		if err != nil {
			return fmt.Errorf("迁移结果未知，先查询状态，不自动重试: %w", err)
		}
		var response struct {
			Success bool           `json:"success"`
			Error   *nats.APIError `json:"error"`
		}
		if err = json.Unmarshal(msg.Data, &response); err != nil {
			return err
		}
		if response.Error != nil {
			return response.Error
		}
		if !response.Success {
			return fmt.Errorf("迁移未确认成功")
		}
		deadline := time.Now().Add(30 * time.Second)
		verified := false
		for time.Now().Before(deadline) {
			c, e := clusterInfo(js, m.name)
			if e == nil && c != nil && c.Leader == to {
				verified = true
				break
			}
			time.Sleep(time.Second)
		}
		if !verified {
			return fmt.Errorf("新 Leader 未在30秒内确认；停止后续迁移，不自动重试")
		}
		fmt.Println("已验证 Leader:", to)
	}
	return nil
}

func clusterInfo(js nats.JetStreamContext, name string) (*nats.ClusterInfo, error) {
	if name == "" {
		i, e := js.StreamInfo(stream)
		if e != nil {
			return nil, e
		}
		return i.Cluster, nil
	}
	i, e := js.ConsumerInfo(stream, name)
	if e != nil {
		return nil, e
	}
	return i.Cluster, nil
}

func validateTarget(c *nats.ClusterInfo, from, to string) error {
	if c == nil || c.Leader == "" {
		return fmt.Errorf("没有可确认的 Leader")
	}
	if c.Leader != from {
		return nil
	}
	for _, p := range c.Replicas {
		if p != nil && p.Name == to && p.Current && !p.Offline {
			return nil
		}
	}
	return fmt.Errorf("目标 %s 不是已同步的在线副本", to)
}
