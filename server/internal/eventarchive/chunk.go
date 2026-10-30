// Package eventarchive 是冷归档：把 events 里过期的候选事件编码成自校验的冷块，
// 写进新建的 event_archive_chunks / event_archive_runs，再逐事件对拍与度量；
// 读取侧提供冷块查询（Query）、按事件 ID 定位（Locate / Exists）与证据物化（Materialize）；
// 切换侧提供单日计划（Plan）、重建日分区（Swap）与整日还原（Restore）。
//
// 阶段 A/B 不修改、删除或切换 events 的任何既有行，也不 DETACH / ATTACH / DROP 任何分区：
// 那时唯一的 events 写入是 Materialize 往 events **插入**缺失的事件（ON CONFLICT DO NOTHING）。
// 阶段 C 的 Swap 会移走已归档的行，但它不自己写分区 DDL：保留口径交给
// eventpart.RewriteDay，在单个事务里重建日分区，失败整体回滚。
// 格式、口径与阶段见 docs/event-archive.md。
package eventarchive

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
)

const (
	// Magic 是冷块头部前 8 字节，用于把冷块与任意字节流区分开。
	Magic = "OXDRARC1"
	// FormatV1 是当前唯一格式版本：头部字段与载荷布局见 docs/event-archive.md。
	FormatV1 uint8 = 1

	// CodecPlain 载荷就是逐行 JSON 原文；CodecZstd 是单个 zstd frame。
	CodecPlain uint8 = 0
	CodecZstd  uint8 = 1

	// MaxPlainLen 是单块明文上限（16 MiB）：读取端先看头部这个数，超限直接拒绝，
	// 不会按头部声明的大小分配内存。
	MaxPlainLen = 16 << 20
	// MaxCount 是单块事件条数上限（8192）：同样在解压前校验。
	MaxCount = 8192
	// MaxEventBytes 是单条事件编码成一行后的上限（4 MiB），超过的不进冷块、单独计数。
	MaxEventBytes = 4 << 20

	// headerLen = magic(8) + format(1) + codec(1) + count(4) + plainLen(8) + sha256(32)。
	headerLen = len(Magic) + 1 + 1 + 4 + 8 + sha256.Size

	// BloomBits 是每个事件在 ID Bloom filter 里占的比特数：10 bit/事件 + 3 个 hash，
	// 理论假阳性率约 1.7%。假阳性只是多重解压几块，**漏报不可接受**（见 BuildIDBloom）。
	BloomBits = 10
	// bloomHashes 是每个 ID 在 filter 上置位的个数，与 BloomBits 一起决定假阳性率。
	bloomHashes = 3
	// bloomMinBytes 是 filter 的最小字节数（64 B = 512 bit）：小块也留出足够余量，
	// 让只有几块、几十块的归档几乎不会产生假阳性。
	bloomMinBytes = 64
	// bloomAlign 是 filter 的字节对齐：bit 数必须是 8 字节（64 bit）的整数倍，
	// 这样字节长度本身就唯一确定 bit 数，读端不需要额外长度字段。
	bloomAlign = 8
)

// Event 是冷块里的一条事件，字段与 events 公共列一一对应（顺序即 JSON 字段顺序）。
// 可空列用指针：JSON 里写 null，与 events 里的 NULL 一一对应，不会把 NULL 折成空串。
type Event struct {
	ID                uuid.UUID
	Ts                time.Time
	ClassUID          int64
	Source            string
	AssetID           *uuid.UUID
	ProcessGUID       *uuid.UUID
	ParentProcessGUID *uuid.UUID
	Username          *string
	ConnTuple         *string
	Raw               json.RawMessage
}

// Block 是一块冷块的头部字段加载荷。落库时头部拆成 event_archive_chunks 的列，
// MarshalBinary 拼回「magic | format | codec | count | plainLen | sha256 | payload」的独立块。
type Block struct {
	Format      uint8
	Codec       uint8
	Count       int
	PlainLen    int64
	PlainSHA256 [sha256.Size]byte
	Payload     []byte
}

var (
	encoderOnce sync.Once
	encoder     *zstd.Encoder
	encoderErr  error
	decoderOnce sync.Once
	decoder     *zstd.Decoder
	decoderErr  error
)

// zstdEncoder 是包级单例：并发 1、级别 1。EncodeAll 本身可并发调用，
// 同一输入两次编码字节完全一致（没有时间戳、没有字典）。
func zstdEncoder() (*zstd.Encoder, error) {
	encoderOnce.Do(func() {
		encoder, encoderErr = zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(1)),
			zstd.WithEncoderConcurrency(1))
	})
	if encoderErr != nil {
		return nil, fmt.Errorf("创建 zstd encoder: %w", encoderErr)
	}
	return encoder, nil
}

// zstdDecoder 的解码上限就是 MaxPlainLen：头部声明的明文超过它直接报错，
// 解压过程中分配的内存也被这个上限卡住，恶意或损坏的头部撑不爆内存。
func zstdDecoder() (*zstd.Decoder, error) {
	decoderOnce.Do(func() {
		decoder, decoderErr = zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(MaxPlainLen))
	})
	if decoderErr != nil {
		return nil, fmt.Errorf("创建 zstd decoder: %w", decoderErr)
	}
	return decoder, nil
}

// EncodeBlock 把事件编码成冷块：逐行 JSON（\n 分隔、末行不带 \n），能压小就 zstd，
// 压不小就存原文。空输入直接拒绝——空块没有意义，也不该占一行。
func EncodeBlock(events []Event) (Block, error) {
	if len(events) == 0 {
		return Block{}, fmt.Errorf("空块不允许写入")
	}
	if len(events) > MaxCount {
		return Block{}, fmt.Errorf("块内事件 %d 条超过上限 %d", len(events), MaxCount)
	}
	plain := make([]byte, 0, 4096)
	for i, e := range events {
		if i > 0 {
			plain = append(plain, '\n')
		}
		plain = e.appendJSON(plain)
	}
	return seal(plain, len(events))
}

// seal 给已经是「逐行 JSON」的明文加校验与压缩。payload 是明文时 codec 记 0。
func seal(plain []byte, count int) (Block, error) {
	if count == 0 {
		return Block{}, fmt.Errorf("空块不允许写入")
	}
	if count > MaxCount {
		return Block{}, fmt.Errorf("块内事件 %d 条超过上限 %d", count, MaxCount)
	}
	if int64(len(plain)) > MaxPlainLen {
		return Block{}, fmt.Errorf("块明文 %d 字节超过上限 %d", len(plain), MaxPlainLen)
	}
	enc, err := zstdEncoder()
	if err != nil {
		return Block{}, err
	}
	compressed := enc.EncodeAll(plain, nil)
	if len(compressed) == 0 {
		return Block{}, fmt.Errorf("zstd 压缩返回空结果")
	}
	b := Block{
		Format:      FormatV1,
		Codec:       CodecZstd,
		Count:       count,
		PlainLen:    int64(len(plain)),
		PlainSHA256: sha256.Sum256(plain),
		Payload:     compressed,
	}
	// 压不小（已经压过的数据、太短的块）就退化原文，读端按 codec 分辨
	if len(compressed) >= len(plain) {
		b.Codec = CodecPlain
		b.Payload = append([]byte(nil), plain...)
	}
	return b, nil
}

// MarshalBinary 拼出带头的独立冷块字节。库里的冷块头部在列上，这个只用于导出与测试。
func (b Block) MarshalBinary() ([]byte, error) {
	if err := b.validateHeader(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, headerLen+len(b.Payload))
	out = append(out, Magic...)
	out = append(out, b.Format, b.Codec)
	out = binary.BigEndian.AppendUint32(out, uint32(b.Count))
	out = binary.BigEndian.AppendUint64(out, uint64(b.PlainLen))
	out = append(out, b.PlainSHA256[:]...)
	return append(out, b.Payload...), nil
}

// DecodeBlock 解码一个独立的冷块字节串：先解头并按 count / plainLen 做上限校验，
// 再解压、校验 SHA256 与条数，最后逐行反序列化。任何一步不符都返回错误，绝不返回部分结果。
func DecodeBlock(raw []byte) ([]Event, error) {
	if len(raw) < headerLen {
		return nil, fmt.Errorf("冷块只有 %d 字节，不足头部 %d 字节（已被截断）", len(raw), headerLen)
	}
	if string(raw[:len(Magic)]) != Magic {
		return nil, fmt.Errorf("冷块 magic 是 %q，不是 %q（头部损坏或不是冷块）", raw[:len(Magic)], Magic)
	}
	b := Block{Format: raw[8], Codec: raw[9]}
	count := binary.BigEndian.Uint32(raw[10:14])
	plainLen := binary.BigEndian.Uint64(raw[14:22])
	copy(b.PlainSHA256[:], raw[22:headerLen])
	payload := raw[headerLen:]
	if count > MaxCount {
		return nil, fmt.Errorf("冷块声明 %d 条事件，超过上限 %d（头部不可信，拒绝解码）", count, MaxCount)
	}
	if plainLen > MaxPlainLen {
		return nil, fmt.Errorf("冷块声明明文 %d 字节，超过上限 %d（头部不可信，拒绝解码）", plainLen, MaxPlainLen)
	}
	b.Count, b.PlainLen, b.Payload = int(count), int64(plainLen), payload
	return b.Decode()
}

func (b Block) validateHeader() error {
	if b.Format != FormatV1 {
		return fmt.Errorf("冷块格式版本 %d 不受支持（当前 %d）", b.Format, FormatV1)
	}
	if b.Codec != CodecPlain && b.Codec != CodecZstd {
		return fmt.Errorf("冷块 codec %d 未知（支持 %d 原文、%d zstd）", b.Codec, CodecPlain, CodecZstd)
	}
	if b.Count <= 0 {
		return fmt.Errorf("冷块事件条数 %d 非法：空块不允许", b.Count)
	}
	if b.Count > MaxCount {
		return fmt.Errorf("冷块事件条数 %d 超过上限 %d", b.Count, MaxCount)
	}
	if b.PlainLen <= 0 {
		return fmt.Errorf("冷块明文长度 %d 非法", b.PlainLen)
	}
	if b.PlainLen > MaxPlainLen {
		return fmt.Errorf("冷块明文长度 %d 超过上限 %d", b.PlainLen, MaxPlainLen)
	}
	if b.Payload == nil {
		return fmt.Errorf("冷块载荷缺失")
	}
	return nil
}

// Decode 解码载荷并逐条反序列化。所有校验都在返回前做完，出错时返回 nil 事件列表。
func (b Block) Decode() ([]Event, error) {
	if err := b.validateHeader(); err != nil {
		return nil, err
	}
	plain, err := b.plainText()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(plain)
	if sum != b.PlainSHA256 {
		return nil, fmt.Errorf("冷块明文 SHA256 校验失败（块声明 %x，实际 %x）：载荷已损坏", b.PlainSHA256, sum)
	}
	lines := bytes.Split(plain, []byte("\n"))
	if len(lines) != b.Count {
		return nil, fmt.Errorf("冷块声明 %d 条事件，实际解出 %d 行", b.Count, len(lines))
	}
	events := make([]Event, 0, b.Count)
	for i, line := range lines {
		if len(line) == 0 {
			return nil, fmt.Errorf("冷块第 %d 行是空行", i+1)
		}
		e, err := decodeLine(line)
		if err != nil {
			return nil, fmt.Errorf("冷块第 %d 行反序列化失败: %w", i+1, err)
		}
		events = append(events, e)
	}
	return events, nil
}

// plainText 按 codec 还原明文。codec 为原文时必须与头部声明的长度一致；
// zstd 时用带上限的解码器，解出来再核对长度。
func (b Block) plainText() ([]byte, error) {
	switch b.Codec {
	case CodecPlain:
		if int64(len(b.Payload)) != b.PlainLen {
			return nil, fmt.Errorf("冷块声明明文 %d 字节，载荷实际 %d 字节（已被截断或 header 不符）", b.PlainLen, len(b.Payload))
		}
		return b.Payload, nil
	case CodecZstd:
		if len(b.Payload) == 0 {
			return nil, fmt.Errorf("冷块载荷为空，无法解压")
		}
		dec, err := zstdDecoder()
		if err != nil {
			return nil, err
		}
		plain, err := dec.DecodeAll(b.Payload, nil)
		if err != nil {
			return nil, fmt.Errorf("冷块解压失败: %w", err)
		}
		if int64(len(plain)) != b.PlainLen {
			return nil, fmt.Errorf("冷块解压得到 %d 字节，与头部声明的 %d 字节不符", len(plain), b.PlainLen)
		}
		return plain, nil
	default:
		return nil, fmt.Errorf("冷块 codec %d 未知（支持 %d 原文、%d zstd）", b.Codec, CodecPlain, CodecZstd)
	}
}

// appendJSON 按固定字段顺序手写一行 JSON。
//
// 不用 encoding/json 整体序列化：它会把 json.RawMessage 重新压紧并转义 < > &，
// 而 events.raw 的 jsonb 文本表示带空格、可能含这些字符，一过 encoding/json 就不再逐字节相同，
// 对拍就永远过不去。raw 必须原样写出，其余字段自己转义。
func (e Event) appendJSON(dst []byte) []byte {
	dst = append(dst, `{"id":`...)
	dst = appendJSONString(dst, e.ID.String())
	dst = append(dst, `,"ts":`...)
	dst = appendJSONString(dst, e.Ts.UTC().Format(time.RFC3339Nano))
	dst = append(dst, `,"class_uid":`...)
	dst = appendInt(dst, e.ClassUID)
	dst = append(dst, `,"source":`...)
	dst = appendJSONString(dst, e.Source)
	dst = append(dst, `,"asset_id":`...)
	dst = appendUUID(dst, e.AssetID)
	dst = append(dst, `,"process_guid":`...)
	dst = appendUUID(dst, e.ProcessGUID)
	dst = append(dst, `,"parent_process_guid":`...)
	dst = appendUUID(dst, e.ParentProcessGUID)
	dst = append(dst, `,"username":`...)
	dst = appendString(dst, e.Username)
	dst = append(dst, `,"conn_tuple":`...)
	dst = appendString(dst, e.ConnTuple)
	dst = append(dst, `,"raw":`...)
	if len(e.Raw) == 0 {
		dst = append(dst, `null`...)
	} else {
		dst = append(dst, e.Raw...)
	}
	return append(dst, '}')
}

func appendUUID(dst []byte, id *uuid.UUID) []byte {
	if id == nil {
		return append(dst, `null`...)
	}
	return appendJSONString(dst, id.String())
}

func appendString(dst []byte, s *string) []byte {
	if s == nil {
		return append(dst, `null`...)
	}
	return appendJSONString(dst, *s)
}

func appendInt(dst []byte, n int64) []byte {
	if n < 0 {
		return append(dst, '-')
	}
	var buf [20]byte
	i := len(buf)
	u := uint64(n)
	if n < 0 {
		u = uint64(-n)
	}
	for {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
		if u == 0 {
			break
		}
	}
	return append(dst, buf[i:]...)
}

const hexDigits = "0123456789abcdef"

// appendJSONString 按 RFC 8259 转义：只处理 "、\ 与控制字符，非 ASCII 的 UTF-8 原样保留。
func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\\':
			dst = append(dst, '\\', c)
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
				continue
			}
			dst = append(dst, c)
		}
	}
	return append(dst, '"')
}

// wireEvent 是逐行 JSON 的镜像结构，字段顺序与 Event.appendJSON 一致。
type wireEvent struct {
	ID                string          `json:"id"`
	Ts                string          `json:"ts"`
	ClassUID          int64           `json:"class_uid"`
	Source            string          `json:"source"`
	AssetID           *string         `json:"asset_id"`
	ProcessGUID       *string         `json:"process_guid"`
	ParentProcessGUID *string         `json:"parent_process_guid"`
	Username          *string         `json:"username"`
	ConnTuple         *string         `json:"conn_tuple"`
	Raw               json.RawMessage `json:"raw"`
}

func decodeLine(line []byte) (Event, error) {
	var w wireEvent
	if err := json.Unmarshal(line, &w); err != nil {
		return Event{}, err
	}
	id, err := uuid.Parse(w.ID)
	if err != nil {
		return Event{}, fmt.Errorf("id %q 不是 UUID: %w", w.ID, err)
	}
	ts, err := time.Parse(time.RFC3339Nano, w.Ts)
	if err != nil {
		return Event{}, fmt.Errorf("ts %q 不是 RFC3339: %w", w.Ts, err)
	}
	e := Event{ID: id, Ts: ts.UTC(), ClassUID: w.ClassUID, Source: w.Source}
	if e.AssetID, err = parseUUIDPtr(w.AssetID); err != nil {
		return Event{}, fmt.Errorf("asset_id: %w", err)
	}
	if e.ProcessGUID, err = parseUUIDPtr(w.ProcessGUID); err != nil {
		return Event{}, fmt.Errorf("process_guid: %w", err)
	}
	if e.ParentProcessGUID, err = parseUUIDPtr(w.ParentProcessGUID); err != nil {
		return Event{}, fmt.Errorf("parent_process_guid: %w", err)
	}
	e.Username, e.ConnTuple = w.Username, w.ConnTuple
	e.Raw = w.Raw
	return e, nil
}

func parseUUIDPtr(s *string) (*uuid.UUID, error) {
	if s == nil {
		return nil, nil
	}
	id, err := uuid.Parse(*s)
	if err != nil {
		return nil, fmt.Errorf("%q 不是 UUID: %w", *s, err)
	}
	return &id, nil
}

// ---- ID Bloom filter（阶段 B2：按 ID 定位冷事件）----
//
// 冷块元数据里没有 ID 索引，按 ID 查一条事件只能逐块解压全文扫。filter 的职责只有一个：
// **排除不可能命中的块**，把解压次数压到常数级。命中仍必须解压并逐事件精确比对 ID，
// 所以假阳性只是多解压几块；漏报则会把重传当成新事件（重复告警）、让证据物化找不到事件，
// 绝对不允许。
//
// 零漏报由构造保证，不依赖参数选择：
//   - 只置位、从不复位，filter 里只有「写进去的 id 的位」；
//   - bit 数只由 len(bloom) 决定（8 字节对齐），写端读端共用 bloomPositions，
//     不存在「写的时候算一个位、读的时候算另一个位」的可能；
//   - 位宽不够只抬高假阳性率，不会漏报。
// 唯一会漏报的情形是 filter 本身被截断或改坏，用长度校验挡掉：长度不是 8 字节对齐
// （或为空）就当作「没有过滤器」，MayContainID 返回 true，退回解压后精确比对。

// BuildIDBloom 给一块里的 id 建 ID Bloom filter，写进 event_archive_chunks.id_bloom。
//
// n 是块的声明条数（event_count），用来定 filter 大小；ids 条数比 n 多时按实际条数取大——
// 宁可 filter 大一点，也不能有 id 装不进去。count <= 0 返回 nil（没有 id 就没有 filter）。
// 同样的 ids 与 n 两次调用得到完全相同的字节（没有随机种子、没有时间戳）。
func BuildIDBloom(ids []uuid.UUID, n int) []byte {
	count := n
	if len(ids) > count {
		count = len(ids)
	}
	if count <= 0 {
		return nil
	}
	// ceil(count*BloomBits / (bloomAlign*8)) * bloomAlign，最小 bloomMinBytes
	bytesLen := (count*BloomBits + bloomAlign*8 - 1) / (bloomAlign * 8) * bloomAlign
	if bytesLen < bloomMinBytes {
		bytesLen = bloomMinBytes
	}
	bloom := make([]byte, bytesLen)
	bits := uint64(bytesLen) * 8
	for _, id := range ids {
		for _, pos := range bloomPositions(id, bits) {
			bloom[pos>>3] |= 1 << (pos & 7)
		}
	}
	return bloom
}

// MayContainID 报告 id 是否**可能**在这一块里。
//
//   - bloom == nil（阶段 B2 之前写的老块，id_bloom 为 NULL）恒为 true：没有过滤器，
//     调用方必须解压后精确比对；
//   - 长度不是 8 字节对齐（filter 被截断或不是本包写的）同样返回 true，宁可多解压一块；
//   - 返回 false 是确定的「这块里没有这条事件」。
func MayContainID(bloom []byte, id uuid.UUID) bool {
	bits, ok := bloomBits(bloom)
	if !ok {
		return true
	}
	for _, pos := range bloomPositions(id, bits) {
		if bloom[pos>>3]&(1<<(pos&7)) == 0 {
			return false
		}
	}
	return true
}

// bloomBits 返回 filter 的 bit 数；没有可用过滤器时 ok=false。
func bloomBits(bloom []byte) (uint64, bool) {
	if len(bloom) == 0 || len(bloom)%bloomAlign != 0 {
		return 0, false
	}
	return uint64(len(bloom)) * 8, true
}

// bloomPositions 把 id 映射到 bloomHashes 个 bit 位：sha256 前两段加 FNV-1a 64，三个独立值
// 直接取模。不用「双哈希派生第三位」那类做法：多算一个独立值更省心，反正每块只算 count 次。
func bloomPositions(id uuid.UUID, bits uint64) [bloomHashes]uint64 {
	sum := sha256.Sum256(id[:])
	return [bloomHashes]uint64{
		binary.BigEndian.Uint64(sum[0:8]) % bits,
		binary.BigEndian.Uint64(sum[8:16]) % bits,
		fnv1a64(id[:]) % bits,
	}
}

// fnv1a64 是标准 FNV-1a 64 位（offset basis 14695981039346656037、prime 1099511628211）。
// 内联展开只是为了避免每次调用都新建一个 hash.Hash64。
func fnv1a64(b []byte) uint64 {
	const (
		offset64 uint64 = 14695981039346656037
		prime64  uint64 = 1099511628211
	)
	h := offset64
	for _, c := range b {
		h ^= uint64(c)
		h *= prime64
	}
	return h
}
