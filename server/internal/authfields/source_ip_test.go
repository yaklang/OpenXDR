package authfields

import "testing"

func TestSourceIPBoundaries(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{`{"src_endpoint":{"ip":"192.0.2.10"}}`, "192.0.2.10"},
		{`{"src_endpoint":{"ip":"::ffff:192.0.2.10"}}`, "192.0.2.10"},
		{`{"src_endpoint":{"ip":"2001:0DB8::1"}}`, "2001:db8::1"},
		{`{"src_endpoint":{"ip":"192.0.2.10:22"}}`, ""},
		{`{"src_endpoint":{"ip":"fe80::1%eth0"}}`, ""},
		{`{"src_endpoint":{"ip":"0.0.0.0"}}`, ""},
		{`{"src_endpoint":{"ip":"::ffff:0.0.0.0"}}`, ""},
		{`{"src_endpoint":{"ip":"224.0.0.1"}}`, ""},
		{`{"src_endpoint":{"ip":4}}`, ""},
		{`{"src_endpoint":{"ip":"host.example"}}`, ""},
		{`{"src_endpoint":{"ip":"-"},"metadata":{"product":{"name":"sshd"}},"message":"Invalid user lab from 192.0.2.1 port 22"}`, ""},
		{`{"metadata":{"product":{"name":"sshd"}},"message":"Failed password for invalid user lab from 192.0.2.10 port 2222 ssh2"}`, "192.0.2.10"},
		{`{"metadata":{"product":{"name":"sshd"}},"message":"Invalid user lab from 2001:db8::1 port 22 [preauth]"}`, "2001:db8::1"},
		{`{"metadata":{"product":{"name":"nginx"}},"message":"Invalid user lab from 192.0.2.10 port 22"}`, ""},
		{`{"metadata":{"product":{"name":"sshd"}},"message":"Failed password for lab from 192.0.2.10 port 99999 ssh2"}`, ""},
		{`{"metadata":{"product":{"name":"sshd"}},"message":"user input: Invalid user lab from 192.0.2.10 port 22"}`, ""},
		{`{"metadata":{"product":{"name":"sshd"}},"message":"Failed password for x from 198.51.100.2 port 22 from 192.0.2.10 port 22"}`, ""},
		{`{"metadata":{"product":{"name":"sshd"}},"message":"authentication failure; rhost="}`, ""},
		{`{"src_endpoint":null}`, ""},
		{`{}`, ""},
		{`not json`, ""},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			if got := SourceIP([]byte(tc.raw)); got != tc.want {
				t.Fatalf("来源解析错误: %q != %q", got, tc.want)
			}
		})
	}
}
