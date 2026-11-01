package eventarchive

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/uuid"
)

// 本文件不连数据库：只验 ID Bloom filter 的约定——零漏报是硬要求，假阳性率只是性能保障。
// 按 ID 定位本身（Locate / Materialize）由 lookup_integration_test.go 对着真实冷块验证。

// bloomIDSet 造 n 个确定性 id：首字节是集合标识，后 8 字节是序号。
// 不同 prefix 的两个集合不会相交，正好用来造「确定不在 filter 里」的 id。
func bloomIDSet(prefix byte, n int) []uuid.UUID {
	out := make([]uuid.UUID, n)
	for i := range out {
		var id uuid.UUID
		id[0] = prefix
		binary.BigEndian.PutUint64(id[8:], uint64(i+1))
		out[i] = id
	}
	return out
}

// 1. 零漏报：凡是写进 filter 的 id，MayContainID 必须返回 true。漏报会让重传被当成新事件、
// 让证据物化找不到事件，是这个方案唯一不能接受的错误。
//
// n 从 1 到 5000 全覆盖（块的实际条数就是这个量级），每条都逐条断言；8192 是单块条数上限，
// 单独覆盖边界。
func TestIDBloomNoFalseNegatives(t *testing.T) {
	pool := bloomIDSet(0x11, MaxCount)
	for n := 1; n <= 5000; n++ {
		ids := pool[:n]
		bloom := BuildIDBloom(ids, n)
		for _, id := range ids {
			if !MayContainID(bloom, id) {
				t.Fatalf("漏报：n=%d 的块里 id %s 让 filter 返回 false", n, id)
			}
		}
	}
}

// 2. 零漏报在不同 id 集合上重复一遍：全零位、高位相近、低位相近、以及 n=1 / n=8192 两个边界。
// 这几个集合分别压不同的 hash 位：如果位置计算有系统性偏差（只看首字节、只看尾部），
// 会在其中某个集合上漏报。
func TestIDBloomNoFalseNegativesAcrossIDSets(t *testing.T) {
	sets := []struct {
		name string
		ids  []uuid.UUID
	}{
		{"n=1（最小块）", bloomIDSet(0x01, 1)},
		{"n=2（filter 走最小 64 字节）", bloomIDSet(0x02, 2)},
		{"n=51（10 bit/事件正好用满 64 字节）", bloomIDSet(0x03, 51)},
		{"n=52（刚过 64 字节，进位边界）", bloomIDSet(0x04, 52)},
		{"n=2048（默认块大小）", bloomIDSet(0x05, 2048)},
		{"n=8192（单块上限）", bloomIDSet(0x06, MaxCount)},
		{"全零 id 集", allZeroIDs(4)},
		{"仅末位不同的 id 集", sequentialTailIDs(1024)},
	}
	for _, s := range sets {
		t.Run(s.name, func(t *testing.T) {
			bloom := BuildIDBloom(s.ids, len(s.ids))
			for _, id := range s.ids {
				if !MayContainID(bloom, id) {
					t.Fatalf("漏报：id %s 在 filter 里查不到", id)
				}
			}
		})
	}
}

func allZeroIDs(n int) []uuid.UUID {
	out := make([]uuid.UUID, n)
	return out
}

func sequentialTailIDs(n int) []uuid.UUID {
	out := make([]uuid.UUID, n)
	for i := range out {
		out[i][15] = byte(i) // 只有最后一个字节不同：最坏情况下的低位聚集
	}
	return out
}

// 3. 假阳性率粗略上界：这不是正确性要求，而是「性能不崩」的保障——假阳性只意味着多解压
// 几块。用最坏的块规模（8192 条）测 10 万个确定不在块里的 id，打印实测值并要求 < 2%。
//
// 理论上界：k=3、m/n=10 时 (1-e^{-3/10})^3 ≈ 1.74%。
func TestIDBloomFalsePositiveRate(t *testing.T) {
	ids := bloomIDSet(0x11, MaxCount)
	bloom := BuildIDBloom(ids, len(ids))
	if len(ids)*BloomBits > len(bloom)*8 {
		t.Fatalf("filter 太小：%d 条事件只有 %d bit（每事件 %d bit）", len(ids), len(bloom)*8, BloomBits)
	}
	absent := bloomIDSet(0x22, 100_000)
	falsePositives := 0
	for _, id := range absent {
		if MayContainID(bloom, id) {
			falsePositives++
		}
	}
	rate := float64(falsePositives) / float64(len(absent)) * 100
	t.Logf("假阳性实测：%d / %d = %.3f%%（filter %d 字节，%d 条事件，%d bit/事件）",
		falsePositives, len(absent), rate, len(bloom), len(ids), BloomBits)
	if falsePositives == 0 {
		t.Log("100% 精确是允许的（filter 足够大），但 0 也可能说明 filter 根本没起作用")
	}
	if rate >= 2 {
		t.Fatalf("假阳性率 %.3f%% 超过 2%% 上限：候选块会被多解压，按 ID 查的性能不可控", rate)
	}
	// 顺带证明 filter 真的在排除：排除率必须远高于 0，否则每块都要解压
	if rate > 90 {
		t.Fatalf("几乎没有排除任何块（假阳性率 %.3f%%），filter 没起作用", rate)
	}
}

// 4. bloom == nil（老块没有 id_bloom）恒为 true：语义是「没有过滤器，必须解压后精确比对」，
// 绝不能返回 false 把可能命中的块排掉。空字节与不成 8 字节对齐的 filter 同样按此处理。
func TestMayContainIDWithoutUsableFilter(t *testing.T) {
	id := uuid.New()
	for _, bloom := range [][]byte{nil, {}, make([]byte, 7), make([]byte, 63), make([]byte, 65)} {
		if !MayContainID(bloom, id) {
			t.Fatalf("没有可用过滤器（%d 字节）时必须返回 true", len(bloom))
		}
	}
	// 全零的合规 filter 没有任何位被置起：必须给出确定的 false（证明排除确实发生）
	if MayContainID(make([]byte, bloomMinBytes), id) {
		t.Fatal("全零 filter 不该命中任何 id")
	}
}

// 5. 编码约定：长度按 BloomBits 与 8 字节对齐算出、不小于最小值、同输入同字节。
func TestBuildIDBloomLayout(t *testing.T) {
	if got := BuildIDBloom(nil, 0); got != nil {
		t.Fatalf("没有 id 时应返回 nil（没有过滤器），实际 %d 字节", len(got))
	}
	if got := BuildIDBloom([]uuid.UUID{}, 0); got != nil {
		t.Fatalf("空集合且 n=0 时应返回 nil，实际 %d 字节", len(got))
	}

	cases := []struct {
		name string
		ids  []uuid.UUID
		n    int
	}{
		{"1 条走最小 64 字节", bloomIDSet(0x11, 1), 1},
		{"51 条仍在 64 字节内", bloomIDSet(0x11, 51), 51},
		{"8192 条按 10 bit/事件", bloomIDSet(0x11, MaxCount), MaxCount},
		{"ids 比声明条数多时按实际条数取大", bloomIDSet(0x11, 100), 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bloom := BuildIDBloom(c.ids, c.n)
			if len(bloom) < bloomMinBytes {
				t.Fatalf("filter 只有 %d 字节，小于最小值 %d", len(bloom), bloomMinBytes)
			}
			if len(bloom)%bloomAlign != 0 {
				t.Fatalf("filter 长度 %d 不是 %d 字节对齐", len(bloom), bloomAlign)
			}
			want := (len(c.ids)*BloomBits + bloomAlign*8 - 1) / (bloomAlign * 8) * bloomAlign
			if want < bloomMinBytes {
				want = bloomMinBytes
			}
			if len(bloom) != want {
				t.Fatalf("filter 长度 %d，按约定应为 %d（%d 条事件、%d bit/事件）",
					len(bloom), want, len(c.ids), BloomBits)
			}
			if len(bloom)*8 < len(c.ids)*BloomBits {
				t.Fatalf("filter 装不下 %d 条事件：只有 %d bit", len(c.ids), len(bloom)*8)
			}
			// 同输入同字节：filter 是随块一起落库的元数据，必须可复现
			if again := BuildIDBloom(c.ids, c.n); !bytes.Equal(bloom, again) {
				t.Fatal("同样输入两次 BuildIDBloom，字节不一致")
			}
			// 拷贝后按同样方式查询仍然命中（编码本身不丢位）
			clone := append([]byte(nil), bloom...)
			for _, id := range c.ids {
				if !MayContainID(clone, id) {
					t.Fatalf("拷贝后的 filter 丢了 id %s", id)
				}
			}
		})
	}
}
