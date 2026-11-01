package eventarchive

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// sampleEvents 覆盖全部字段：可空字段既有 NULL 也有值，raw 带未转义 Unicode、
// jsonb 文本里的空格、需要转义的引号与制表符。
func sampleEvents(t *testing.T) []Event {
	t.Helper()
	asset, proc, parent := uuid.New(), uuid.New(), uuid.New()
	user, conn := "张三", "10.0.0.1:50123>10.0.0.2:443"
	other := "svc"
	return []Event{
		{
			ID: uuid.MustParse("0199d3a0-0000-7000-8000-000000000001"),
			Ts: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), ClassUID: 4001, Source: "sensor",
			AssetID: &asset, ProcessGUID: &proc, ParentProcessGUID: &parent,
			Username: &user, ConnTuple: &conn,
			Raw: json.RawMessage(`{"conn": {"dst": "10.0.0.2", "sni": "例子.测试"}, "path": "a\tb\\c\"d<e>", "n": 1}`),
		},
		{
			// 可空字段全 NULL
			ID: uuid.MustParse("0199d3a0-0000-7000-8000-000000000002"),
			Ts: time.Date(2026, 9, 2, 23, 59, 59, 123456789, time.UTC), ClassUID: 4003, Source: "agent",
			Username: &other,
			Raw:      json.RawMessage(`{"file": {"path": "/tmp/中文文件名"}, "cmd": "echo \"hi\""}`),
		},
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	events := sampleEvents(t)
	block, err := EncodeBlock(events)
	if err != nil {
		t.Fatal(err)
	}
	if block.Codec != CodecZstd {
		t.Fatalf("这批数据应该被压缩，实际 codec=%d", block.Codec)
	}
	raw, err := block.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeBlock(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(events) {
		t.Fatalf("解出 %d 条，期望 %d 条", len(got), len(events))
	}
	for i := range events {
		want, have := events[i], got[i]
		if want.ID != have.ID || !want.Ts.Equal(have.Ts) || want.ClassUID != have.ClassUID || want.Source != have.Source {
			t.Fatalf("第 %d 条基本字段不一致: %+v vs %+v", i, want, have)
		}
		if !uuidPtrEqual(want.AssetID, have.AssetID) || !uuidPtrEqual(want.ProcessGUID, have.ProcessGUID) ||
			!uuidPtrEqual(want.ParentProcessGUID, have.ParentProcessGUID) {
			t.Fatalf("第 %d 条 uuid 字段不一致", i)
		}
		if !strPtrEqual(want.Username, have.Username) || !strPtrEqual(want.ConnTuple, have.ConnTuple) {
			t.Fatalf("第 %d 条可空字符串不一致", i)
		}
		if !bytes.Equal(want.Raw, have.Raw) {
			t.Fatalf("第 %d 条 raw 不是逐字节相同:\n期望 %s\n实际 %s", i, want.Raw, have.Raw)
		}
	}
}

// 直接从库里按列解码（decoder 用的是行上的头部字段）也要得到同样的结果。
func TestDecodeFromChunkColumns(t *testing.T) {
	events := sampleEvents(t)
	block, err := EncodeBlock(events)
	if err != nil {
		t.Fatal(err)
	}
	ch := Chunk{Block: Block{Format: block.Format, Codec: block.Codec, Count: block.Count,
		PlainLen: block.PlainLen, PlainSHA256: block.PlainSHA256, Payload: block.Payload}}
	got, err := ch.Block.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(events) || !bytes.Equal(got[1].Raw, events[1].Raw) {
		t.Fatalf("按列解码结果不一致: %+v", got)
	}
}

func TestEmptyBlockRejected(t *testing.T) {
	if _, err := EncodeBlock(nil); err == nil {
		t.Fatal("空块必须被拒绝")
	}
	if _, err := EncodeBlock([]Event{}); err == nil {
		t.Fatal("空块必须被拒绝")
	}
	if _, err := seal([]byte{}, 0); err == nil {
		t.Fatal("空块必须被拒绝")
	}
}

func TestTamperedHeaderRejected(t *testing.T) {
	block, err := EncodeBlock(sampleEvents(t))
	if err != nil {
		t.Fatal(err)
	}
	good, err := block.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	clone := func() []byte { return append([]byte(nil), good...) }
	putU32 := func(b []byte, v uint32) { binary.BigEndian.PutUint32(b[10:14], v) }
	putU64 := func(b []byte, v uint64) { binary.BigEndian.PutUint64(b[14:22], v) }

	cases := []struct {
		name string
		mod  func([]byte)
		want string
	}{
		{"magic", func(b []byte) { b[0] = 'X' }, "magic"},
		{"format", func(b []byte) { b[8] = 99 }, "格式版本"},
		{"codec", func(b []byte) { b[9] = 7 }, "codec"},
		{"count 少一条", func(b []byte) { putU32(b, uint32(block.Count-1)) }, "实际解出"},
		{"count 多一条", func(b []byte) { putU32(b, uint32(block.Count+1)) }, "实际解出"},
		{"plainLen 偏小", func(b []byte) { putU64(b, uint64(block.PlainLen-1)) }, "不符"},
		{"plainLen 偏大", func(b []byte) { putU64(b, uint64(block.PlainLen+1)) }, "不符"},
		{"sha 翻一位", func(b []byte) { b[22] ^= 0xff }, "SHA256"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bad := clone()
			c.mod(bad)
			events, err := DecodeBlock(bad)
			if err == nil {
				t.Fatalf("头部被篡改（%s）仍然解码成功", c.name)
			}
			if events != nil {
				t.Fatalf("出错时必须返回 nil 事件，实际返回 %d 条", len(events))
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("错误信息应包含 %q，实际 %v", c.want, err)
			}
		})
	}
}

func TestTruncatedPayloadRejected(t *testing.T) {
	block, err := EncodeBlock(sampleEvents(t))
	if err != nil {
		t.Fatal(err)
	}
	good, err := block.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, cut := range []int{1, len(good) / 2, len(good) - 1, headerLen - 1, headerLen} {
		if cut < 0 || cut >= len(good) {
			continue
		}
		if _, err := DecodeBlock(good[:cut]); err == nil {
			t.Fatalf("截到 %d 字节仍然解码成功", cut)
		}
	}
	// 原文 codec 下少一个字节就是长度不符
	plainBlock, err := seal([]byte(`{"id":"x"}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	if plainBlock.Codec != CodecPlain {
		plainBlock.Codec = CodecPlain
	}
	plainRaw, err := plainBlock.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBlock(plainRaw[:len(plainRaw)-1]); err == nil {
		t.Fatal("原文载荷被截断必须报错")
	}
}

func TestHeaderLimitsRejectedBeforeDecode(t *testing.T) {
	block, err := EncodeBlock(sampleEvents(t))
	if err != nil {
		t.Fatal(err)
	}
	good, err := block.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// count 超上限：头部写着 10 万条，载荷只有几十字节
	bad := append([]byte(nil), good...)
	binary.BigEndian.PutUint32(bad[10:14], MaxCount+1)
	if _, err := DecodeBlock(bad); err == nil || !strings.Contains(err.Error(), "超过上限") {
		t.Fatalf("count 超上限必须直接拒绝，实际 %v", err)
	}
	// plainLen 超上限（1 TiB）：必须在解压前按上限拒绝，不能按声明大小分配
	bad = append([]byte(nil), good...)
	binary.BigEndian.PutUint64(bad[14:22], 1<<40)
	if _, err := DecodeBlock(bad); err == nil || !strings.Contains(err.Error(), "超过上限") {
		t.Fatalf("plainLen 超上限必须直接拒绝，实际 %v", err)
	}
	// 同样的字节流给解码器（绕过头部检查）也不能解出超过上限的明文
	bombPayload := bytes.Repeat([]byte("a"), MaxPlainLen+1024)
	enc, err := zstdEncoder()
	if err != nil {
		t.Fatal(err)
	}
	frame := enc.EncodeAll(bombPayload, nil)
	dec, err := zstdDecoder()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dec.DecodeAll(frame, nil); err == nil {
		t.Fatal("解码器必须拒绝超过 MaxPlainLen 的帧")
	}
}

// 不可压数据（随机串）压不小，必须退化 codec=0 且照样能往返。
func TestIncompressibleFallsBackToPlainCodec(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var sb strings.Builder
	for i := 0; i < 4096; i++ {
		sb.WriteByte(byte('a' + rng.Intn(26)))
	}
	events := []Event{{
		ID: uuid.New(), Ts: time.Date(2026, 9, 3, 1, 2, 3, 0, time.UTC), ClassUID: 4001, Source: "agent",
		Raw: json.RawMessage(`{"blob":"` + sb.String() + `"}`),
	}}
	block, err := EncodeBlock(events)
	if err != nil {
		t.Fatal(err)
	}
	if block.Codec != CodecPlain {
		t.Fatalf("随机数据压缩后不小于原文，应退化为 codec=0，实际 %d", block.Codec)
	}
	if int64(len(block.Payload)) != block.PlainLen {
		t.Fatalf("原文载荷长度 %d 应等于 plainLen %d", len(block.Payload), block.PlainLen)
	}
	raw, err := block.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeBlock(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !bytes.Equal(got[0].Raw, events[0].Raw) {
		t.Fatal("原文块的往返结果不一致")
	}
}

func TestEncodeDeterministic(t *testing.T) {
	events := sampleEvents(t)
	first, err := EncodeBlock(events)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncodeBlock(events)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Payload, second.Payload) {
		t.Fatal("同样输入两次编码，payload 字节不一致")
	}
	if first.PlainSHA256 != second.PlainSHA256 || first.PlainLen != second.PlainLen || first.Count != second.Count {
		t.Fatal("同样输入两次编码，头部字段不一致")
	}
	firstBytes, err := first.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := second.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("同样输入两次编码，整块字节不一致")
	}
}

// jsonb 文本里的空格、Unicode 与转义字符不能被重新压紧或转义：raw 必须逐字节原样写进块里。
func TestRawKeptVerbatim(t *testing.T) {
	raw := json.RawMessage(`{"a": 1, "b": [1, 2], "c": {"d": "中文<>&\t"}}`)
	events := []Event{{ID: uuid.New(), Ts: time.Now().UTC(), ClassUID: 4001, Source: "agent", Raw: raw}}
	block, err := EncodeBlock(events)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := block.plainText()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain, raw) {
		t.Fatalf("明文里应当原样包含 raw，实际 %s", plain)
	}
	sum := sha256.Sum256(plain)
	if sum != block.PlainSHA256 {
		t.Fatal("明文 SHA 与头部不一致")
	}
}

// 超过单块条数上限的输入直接拒绝，不会悄悄截断。
func TestTooManyEventsRejected(t *testing.T) {
	events := make([]Event, MaxCount+1)
	for i := range events {
		events[i] = Event{ID: uuid.New(), Ts: time.Now().UTC(), ClassUID: 4001, Source: "agent", Raw: json.RawMessage(`{}`)}
	}
	if _, err := EncodeBlock(events); err == nil {
		t.Fatal("超过条数上限必须拒绝")
	}
}
