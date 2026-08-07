package syslog

import (
	"net"
	"testing"
	"time"
)

// AlertSeverity：syslog 级别(0 最严重) → 平台级别(1 最低)，越界回退中位 3。
func TestAlertSeverity(t *testing.T) {
	cases := []struct {
		sev  int
		want int16
	}{
		{0, 5}, {1, 5}, {2, 5}, {3, 4}, {4, 3}, {5, 2}, {6, 2}, {7, 1},
		{-1, 3}, {8, 3}, {99, 3},
	}
	for _, c := range cases {
		if got := AlertSeverity(c.sev); got != c.want {
			t.Errorf("AlertSeverity(%d) = %d, want %d", c.sev, got, c.want)
		}
	}
}

// RFC5424：带时间戳、完整八个字段、结构化数据 -。
func TestParseRFC5424(t *testing.T) {
	line := `<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su 231 12345 - BOM'start'`
	m := Parse(line, time.Now())

	if m.Facility != 4 || m.Severity != 2 {
		t.Errorf("facility/severity = %d/%d, want 4/2", m.Facility, m.Severity)
	}
	if want := time.Date(2003, 10, 11, 22, 14, 15, 3e6, time.UTC); !m.Ts.Equal(want) {
		t.Errorf("Ts = %v, want %v", m.Ts, want)
	}
	if m.Hostname != "mymachine.example.com" || m.AppName != "su" || m.ProcID != "231" || m.MsgID != "12345" {
		t.Errorf("头部字段解析错误: %+v", m)
	}
	if m.Content != "BOM'start'" {
		t.Errorf("Content = %q", m.Content)
	}
}

// RFC5424 带结构化数据：把 [SD] 从正文剥离。（MSGID 非 "-" 的典型形态）
func TestParseRFC5424StructuredData(t *testing.T) {
	line := `<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 ID47 [exampleSDID@32473 iut="3"] App started`
	m := Parse(line, time.Now())

	if m.Hostname != "192.0.2.1" || m.AppName != "myproc" || m.ProcID != "8710" || m.MsgID != "ID47" {
		t.Errorf("头部字段解析错误: %+v", m)
	}
	if m.Content != "App started" {
		t.Errorf("Content 应剥离结构化数据，得到 %q", m.Content)
	}
}

// RFC5424 的 MSGID 占位 "-" 与结构化数据同时出现（"- - [SD] msg"）也须正确剥离。
func TestParseRFC5424DashMsgIDWithSD(t *testing.T) {
	line := `<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc - - [exampleSDID@32473 iut="3"] App started`
	m := Parse(line, time.Now())
	if m.Content != "App started" {
		t.Errorf("MSGID 为 '-' 加结构化数据应剥离，得到 %q", m.Content)
	}
}

// RFC5424 缺段容错：截断报文能取多少算多少，不 panic。
func TestParseRFC5424Truncated(t *testing.T) {
	m := Parse(`<13>1 2004-01-01T00:00:00.000Z host`, time.Now())
	if m.Hostname != "host" {
		t.Errorf("Hostname = %q", m.Hostname)
	}
}

func TestParseNoPRI(t *testing.T) {
	// 无 PRI 保持默认 info/user
	m := Parse("Oct 11 22:14:15 host app: msg", time.Now())
	if m.Severity != 6 || m.Facility != 1 {
		t.Errorf("无 PRI 应保持默认 severity=6 facility=1，得到 %d/%d", m.Severity, m.Facility)
	}
}

// RFC3164：本地时区解析 + 当年补年份。now 取年中，报文日期在未来 → 回退一年。
func TestParseRFC3164(t *testing.T) {
	loc := time.FixedZone("X", 8*3600)
	now := time.Date(2023, time.May, 1, 0, 0, 0, 0, loc)

	m := Parse(`<34>Oct 11 22:14:15 mymachine su: 'su root' failed`, now)

	if m.Facility != 4 || m.Severity != 2 {
		t.Errorf("facility/severity = %d/%d", m.Facility, m.Severity)
	}
	// Oct 11 晚于 now(5 月)，跨年修正到 2022
	want := time.Date(2022, time.October, 11, 22, 14, 15, 0, loc)
	if !m.Ts.Equal(want) {
		t.Errorf("Ts = %v, want %v", m.Ts, want)
	}
	if m.Hostname != "mymachine" || m.AppName != "su" {
		t.Errorf("hostname/appname = %q/%q", m.Hostname, m.AppName)
	}
	if m.Content != "'su root' failed" {
		t.Errorf("Content = %q", m.Content)
	}
}

// RFC3164 空月份补零日期（"Feb  5" 双空格）用 _2 布局能解。
func TestParseRFC3164SpacePrefixDay(t *testing.T) {
	loc := time.FixedZone("X", 8*3600)
	now := time.Date(2023, time.February, 20, 0, 0, 0, 0, loc)
	m := Parse(`<13>Feb  5 17:32:18 10.0.0.1 myprogram[123]: Test message`, now)

	if m.Hostname != "10.0.0.1" {
		t.Errorf("Hostname = %q", m.Hostname)
	}
	if m.AppName != "myprogram" || m.ProcID != "123" {
		t.Errorf("TAG[pid] 拆分错误: app=%q pid=%q", m.AppName, m.ProcID)
	}
	if m.Content != "Test message" {
		t.Errorf("Content = %q", m.Content)
	}
}

// RFC3164 无 TAG 冒号 → 时间戳后的首段当 hostname，其余整体当 Content。
func TestParseRFC3164FreeForm(t *testing.T) {
	loc := time.FixedZone("X", 8*3600)
	now := time.Date(2023, time.May, 1, 0, 0, 0, 0, loc)

	m := Parse(`Oct 11 22:14:15 raw freeform message no tag`, now)
	if m.Hostname != "raw" {
		t.Errorf("时间戳后首段应为 hostname，得到 %q", m.Hostname)
	}
	if m.Content != "freeform message no tag" {
		t.Errorf("其余整体应进 Content，得到 %q", m.Content)
	}
}

// 取来源 IP：UDP/TCP 地址都解，其他类型 n 返回 nil。
// 取来源 IP：UDP/TCP 地址都解，其他类型返回 nil。
func TestAddrIP(t *testing.T) {
	u := &net.UDPAddr{IP: net.ParseIP("10.0.0.1")}
	if got := addrIP(u); got == nil || got.String() != "10.0.0.1" {
		t.Errorf("UDPAddr → %v", got)
	}
	tc := &net.TCPAddr{IP: net.ParseIP("10.0.0.2")}
	if got := addrIP(tc); got == nil || got.String() != "10.0.0.2" {
		t.Errorf("TCPAddr → %v", got)
	}
	if addrIP(nil) != nil {
		t.Error("nil 应返回 nil")
	}
}
func TestParseRFC3164SameYear(t *testing.T) {
	loc := time.FixedZone("X", 0)
	now := time.Date(2023, time.December, 31, 23, 0, 0, 0, loc)
	m := Parse(`Dec 30 10:00:00 host a: ok`, now)
	if m.Ts.Year() != 2023 {
		t.Errorf("日志在 now 之前不应回修年份，Ts=%v", m.Ts)
	}
}
