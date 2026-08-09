package suppress

import (
	"testing"
	"time"

	"github.com/google/uuid"
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
			got := matchRule(tc.entries, tc.assetID, fixNow)
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

	if !s.Suppressed("r1", ptr(fixAsset), now) {
		t.Fatal("r1 应命中")
	}
	if !s.Suppressed("r1", nil, now.Add(time.Second)) {
		t.Fatal("r1 第二次应命中")
	}
	if s.Suppressed("r2", ptr(fixAsset), now) {
		t.Fatal("r2 限定资产不匹配应不命中")
	}
	if s.Suppressed("不存在", ptr(fixAsset), now) {
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
