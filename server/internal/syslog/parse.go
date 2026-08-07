// Package syslog 日志接入：收 syslog 报文，归一化成事件。
//
// 同时支持 RFC3164（BSD 老格式）和 RFC5424。两者靠 PRI 之后的第一个字符区分：
// RFC5424 一定是版本号 "1 "，RFC3164 则直接跟月份缩写。
package syslog

import (
	"strconv"
	"strings"
	"time"
)

// Message 归一化后的 syslog 报文。缺失的字段留空，不猜。
type Message struct {
	Ts       time.Time
	Facility int
	Severity int
	Hostname string
	AppName  string
	ProcID   string
	MsgID    string
	Content  string
}

// syslog 严重级别 0..7（越小越严重）映射到 alert 的 1..5
var severityToAlert = [8]int16{5, 5, 5, 4, 3, 2, 2, 1}

// AlertSeverity 把 syslog 级别换算成本系统的告警级别。
func AlertSeverity(sev int) int16 {
	if sev < 0 || sev > 7 {
		return 3
	}
	return severityToAlert[sev]
}

// Parse 解析一条 syslog 报文。now 用于补齐 RFC3164 缺失的年份。
func Parse(line string, now time.Time) Message {
	m := Message{Ts: now, Severity: 6, Facility: 1} // 默认 info/user
	rest := line

	// PRI: <facility*8+severity>
	if after, ok := strings.CutPrefix(rest, "<"); ok {
		if end := strings.IndexByte(after, '>'); end > 0 && end <= 3 {
			if pri, err := strconv.Atoi(after[:end]); err == nil {
				m.Facility, m.Severity = pri/8, pri%8
				rest = after[end+1:]
			}
		}
	}

	if v, ok := strings.CutPrefix(rest, "1 "); ok {
		parse5424(&m, v)
	} else {
		parse3164(&m, rest, now)
	}
	return m
}

// RFC5424: VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP [SD] SP MSG
func parse5424(m *Message, rest string) {
	fields := strings.SplitN(rest, " ", 6)
	// 少于 6 段说明报文被截断，能取多少算多少
	get := func(i int) string {
		if i >= len(fields) || fields[i] == "-" {
			return ""
		}
		return fields[i]
	}
	if ts, err := time.Parse(time.RFC3339Nano, get(0)); err == nil {
		m.Ts = ts
	}
	m.Hostname, m.AppName, m.ProcID, m.MsgID = get(1), get(2), get(3), get(4)

	// 第 6 段是 STRUCTURED-DATA + MSG。结构化数据本身不解析，只把它从正文里剥掉
	tail := get(5)
	if strings.HasPrefix(tail, "[") {
		if end := strings.Index(tail, "] "); end > 0 {
			tail = tail[end+2:]
		}
	} else {
		tail = strings.TrimPrefix(tail, "- ")
	}
	m.Content = tail
}

// RFC3164: TIMESTAMP(Mmm dd hh:mm:ss) SP HOSTNAME SP TAG[PID]: MSG
func parse3164(m *Message, rest string, now time.Time) {
	const stamp = "Jan _2 15:04:05"
	if len(rest) > len(stamp) {
		// RFC3164 时间戳不带时区，惯例是发送方本地时间。
		// 当成 UTC 解析会整体偏移时区差，把关联的时间窗全毁掉。
		if ts, err := time.ParseInLocation(stamp, rest[:len(stamp)], now.Location()); err == nil {
			// RFC3164 不带年份，按当前年补；跨年时用去年更合理
			year := now.Year()
			ts = ts.AddDate(year, 0, 0)
			if ts.Sub(now) > 24*time.Hour {
				ts = ts.AddDate(-1, 0, 0)
			}
			m.Ts = ts
			rest = rest[len(stamp)+1:]
		}
	}

	host, tail, ok := strings.Cut(rest, " ")
	if !ok {
		m.Content = rest
		return
	}
	m.Hostname = host

	// TAG 到第一个冒号为止，可带 [pid]
	tag, msg, ok := strings.Cut(tail, ":")
	if !ok || strings.ContainsAny(tag, " \t") {
		m.Content = tail
		return
	}
	if open := strings.IndexByte(tag, '['); open > 0 && strings.HasSuffix(tag, "]") {
		m.AppName, m.ProcID = tag[:open], tag[open+1:len(tag)-1]
	} else {
		m.AppName = tag
	}
	m.Content = strings.TrimSpace(msg)
}
