// Package flowinput 将 ntopng / nProbe 标签式 JSON 流量归一化，不信任报文中的平台身份。
package flowinput

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net"
	"net/netip"
	"strconv"
	"time"
)

type Origin struct {
	Observer string    `json:"observer"`
	GroupID  uuid.UUID `json:"group_id"`
	Received time.Time `json:"received_at"`
}

type Event struct {
	ProtocolNum      uint8
	Traffic          map[string]uint64
	Source           string
	Time             time.Time
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Protocol         string
	Raw              json.RawMessage
}

func (e Event) ConnTuple() string {
	return e.Protocol + ":" + net.JoinHostPort(e.SrcIP, strconv.Itoa(int(e.SrcPort))) + ">" + net.JoinHostPort(e.DstIP, strconv.Itoa(int(e.DstPort)))
}

func Parse(source string, raw []byte) (Event, error) {
	e := Event{Source: source}
	if source != "ntopng" && source != "nprobe" {
		return e, fmt.Errorf("不支持的流量来源")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return e, fmt.Errorf("流量必须是 JSON 对象")
	}
	text := func(key string) string {
		value := fields[key]
		var s string
		if json.Unmarshal(value, &s) == nil {
			return s
		}
		return string(value)
	}
	address := func(v4, v6 string) (string, error) {
		value := text(v4)
		if value == "" || value == "0.0.0.0" {
			value = text(v6)
		}
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			return "", fmt.Errorf("无效的流量端点地址")
		}
		return ip.Unmap().String(), nil
	}
	var err error
	if e.SrcIP, err = address("IPV4_SRC_ADDR", "IPV6_SRC_ADDR"); err != nil {
		return e, err
	}
	if e.DstIP, err = address("IPV4_DST_ADDR", "IPV6_DST_ADDR"); err != nil {
		return e, err
	}
	protocol, err := strconv.ParseUint(text("PROTOCOL"), 10, 8)
	if err != nil {
		return e, fmt.Errorf("PROTOCOL 必须是 0..255 的协议号")
	}
	e.ProtocolNum = uint8(protocol)
	e.Protocol = map[uint64]string{6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}[protocol]
	if e.Protocol == "" {
		e.Protocol = strconv.FormatUint(protocol, 10)
	}
	for key, target := range map[string]*uint16{"L4_SRC_PORT": &e.SrcPort, "L4_DST_PORT": &e.DstPort} {
		value := text(key)
		if value == "" && protocol != 6 && protocol != 17 {
			continue
		}
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return e, fmt.Errorf("%s 必须是 0..65535 的端口", key)
		}
		*target = uint16(port)
	}
	// ntopng 的 Syslog JSON 使用 epoch 秒；nProbe 的 SWITCHED 是 uptime，不能当绝对时间。
	key, unit := "FLOW_START_SEC", int64(1)
	if text("FLOW_START_MILLISECONDS") != "" {
		key, unit = "FLOW_START_MILLISECONDS", 1000
	} else if source == "ntopng" && text(key) == "" {
		key = "FIRST_SWITCHED"
	}
	stamp, err := strconv.ParseInt(text(key), 10, 64)
	if err != nil || stamp/unit < 946684800 || stamp/unit > 253402300799 {
		return e, fmt.Errorf("%s 需要有效的 epoch 时间字段 %s", source, key)
	}
	e.Time = time.Unix(stamp/unit, (stamp%unit)*(int64(time.Second)/unit)).UTC()
	e.Traffic = map[string]uint64{}
	for key, normalized := range map[string]string{"IN_BYTES": "bytes_out", "OUT_BYTES": "bytes_in", "IN_PKTS": "packets_out", "OUT_PKTS": "packets_in"} {
		if value := text(key); value != "" {
			count, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return e, fmt.Errorf("%s 必须是无符号整数", key)
			}
			e.Traffic[normalized] = count
		}
	}
	// RawMessage 保留大整数，按键排序让 JSON 空白或键顺序不同的重传仍然幂等。
	e.Raw, err = json.Marshal(fields)
	return e, err
}
