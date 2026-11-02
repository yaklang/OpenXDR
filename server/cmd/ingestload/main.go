// ingestload 用专用测试机身份发送有界、明确标记的合成事件，不执行主机命令。
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"openxdr/server/pb"
)

type options struct {
	agent, run, source, target, ca, cert, key string
	rate                                      int
	duration                                  time.Duration
}

const fixtureVersion = "mixed-v2-process-identities"

type result struct {
	Fixture         string    `json:"fixture"`
	Rate            int       `json:"plannedRate"`
	DurationSeconds int       `json:"plannedSeconds"`
	Run             string    `json:"runId"`
	Planned         int       `json:"planned"`
	Sent            int       `json:"sent"`
	Acknowledged    *uint64   `json:"acknowledged"`
	First           time.Time `json:"firstEvent"`
	Last            time.Time `json:"lastEvent"`
	Seconds         float64   `json:"seconds"`
	Complete        bool      `json:"complete"`
}

func (o options) validate() error {
	for _, id := range []string{o.agent, o.run} {
		if u, err := uuid.Parse(id); err != nil || u == uuid.Nil {
			return fmt.Errorf("agent-id 和 run-id 必须为非空 UUID")
		}
	}
	ip, err := netip.ParseAddr(o.source)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("需要测试机自身的有效 source-ip")
	}
	if o.rate < 1 || o.rate > 1000 || o.duration < time.Second || o.duration > time.Minute || o.duration%time.Second != 0 {
		return fmt.Errorf("rate 必须为 1–1000；duration 必须为 1–60 秒整数")
	}
	if o.target == "" || o.ca == "" || o.cert == "" || o.key == "" {
		return fmt.Errorf("必须提供 OPENXDR_SERVER、OPENXDR_CA、OPENXDR_CERT、OPENXDR_KEY")
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	o := options{target: os.Getenv("OPENXDR_SERVER"), ca: os.Getenv("OPENXDR_CA"), cert: os.Getenv("OPENXDR_CERT"), key: os.Getenv("OPENXDR_KEY")}
	flag.StringVar(&o.agent, "agent-id", "", "专用测试机现有 Agent ID")
	flag.StringVar(&o.run, "run-id", "", "本轮唯一 UUID；失败时不得盲目复用重投")
	flag.StringVar(&o.source, "source-ip", "", "专用测试机自身 IP")
	flag.IntVar(&o.rate, "rate", 0, "每秒计划发送事件数，最大 1000")
	flag.DurationVar(&o.duration, "duration", 0, "发送时长，最大 60s")
	flag.Parse()
	if err := o.validate(); err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(o.cert, o.key)
	if err != nil {
		return fmt.Errorf("无法加载测试机客户端证书")
	}
	ca, err := os.ReadFile(o.ca)
	if err != nil {
		return fmt.Errorf("无法读取 CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return fmt.Errorf("CA 无效")
	}
	conn, err := grpc.NewClient(strings.TrimPrefix(o.target, "https://"), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})))
	if err != nil {
		return fmt.Errorf("无法初始化 gRPC 客户端")
	}
	defer conn.Close()
	stop, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(stop, o.duration+10*time.Second)
	defer cancel()
	r, err := send(ctx, pb.NewAgentServiceClient(conn), o)
	if encodeErr := json.NewEncoder(os.Stdout).Encode(r); encodeErr != nil {
		return encodeErr
	}
	return err
}

func send(ctx context.Context, client pb.AgentServiceClient, o options) (r result, err error) {
	r.Fixture = fixtureVersion
	r.Run = o.run
	r.Rate = o.rate
	r.DurationSeconds = int(o.duration / time.Second)
	r.Planned = o.rate * int(o.duration/time.Second)
	started := time.Now()
	defer func() { r.Seconds = time.Since(started).Seconds() }()
	stream, err := client.ReportEvents(ctx)
	if err != nil {
		return r, err
	}
	ticker := time.NewTicker(time.Second / time.Duration(o.rate))
	defer ticker.Stop()
	for i := 0; i < r.Planned; i++ {
		select {
		case <-ctx.Done():
			return r, ctx.Err()
		case <-ticker.C:
		}
		now := time.Now().UTC()
		if !now.After(r.Last) {
			now = r.Last.Add(time.Nanosecond)
		}
		ev := synthetic(o, i, now)
		if err := stream.Send(ev); err != nil {
			return r, err
		}
		if r.Sent == 0 {
			r.First = now
		}
		r.Last = now
		r.Sent++
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		return r, err
	}
	received := uint64(ack.Received)
	r.Acknowledged = &received
	if received != uint64(r.Sent) {
		return r, fmt.Errorf("接收确认数量不一致：发送 %d，确认 %d", r.Sent, received)
	}
	r.Complete = true
	return r, nil
}

func synthetic(o options, i int, at time.Time) *pb.AgentEvent {
	processIndex := i
	if i%100 >= 95 {
		processIndex = i - i%100 + 94
	}
	guid := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("%s:%d", o.run, processIndex))).String()
	parent := uuid.NewSHA1(uuid.NameSpaceOID, []byte(o.run+":parent")).String()
	body := map[string]any{"acceptance_test": true, "acceptance_run": o.run, "acceptance_sequence": i, "activity_id": 1,
		"process": map[string]any{"name": "true", "uid": guid, "pid": 1000 + processIndex, "cmd_line": "/usr/bin/true", "file": map[string]any{"path": "/usr/bin/true"}}}
	class := uint32(1007)
	tuple := ""
	switch i % 100 {
	case 95, 96, 97:
		class = 4001
		body["src_endpoint"] = map[string]any{"ip": o.source, "port": 40443}
		body["dst_endpoint"] = map[string]any{"ip": "203.0.113.77", "port": 443}
		tuple = fmt.Sprintf("tcp:%s:40443>203.0.113.77:443", o.source)
	case 98, 99:
		class = 4003
		body["activity_id"] = 6
		body["query"] = map[string]any{"hostname": "openxdr-load.example", "type": "A", "rcode_id": 3}
	}
	raw, _ := json.Marshal(body)
	return &pb.AgentEvent{AgentId: o.agent, TsUnixNs: at.UnixNano(), ClassUid: class, ProcessGuid: guid, ParentProcessGuid: parent, ConnTuple: tuple, RawJson: string(raw)}
}
