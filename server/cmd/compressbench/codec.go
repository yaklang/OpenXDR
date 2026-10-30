// 压缩算法封装。每个 codec 只对一段批字节做压缩/解压；吞吐计时与无损断言
// 由 measure.go 统一负责，codec 不吞错、不做降级。
package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// codecNames 是表格里的固定顺序：先无压缩基线，再按实现与级别排列。
var codecNames = []string{"none", "gzip", "zstd-1", "zstd-3", "lz4"}

type codec interface {
	compress(src []byte) ([]byte, error)
	decompress(src []byte) ([]byte, error)
	close()
}

func newCodec(name string) (codec, error) {
	switch name {
	case "none":
		return noneCodec{}, nil
	case "gzip":
		return newGzipCodec()
	case "zstd-1":
		return newZstdCodec(1)
	case "zstd-3":
		return newZstdCodec(3)
	case "lz4":
		return newLZ4Codec(), nil
	default:
		return nil, fmt.Errorf("未知 codec %q", name)
	}
}

// noneCodec 是基线：压缩与解压都是等长拷贝，字节必须完全一致。
type noneCodec struct{}

func (noneCodec) compress(src []byte) ([]byte, error) {
	out := make([]byte, len(src))
	copy(out, src)
	return out, nil
}

func (noneCodec) decompress(src []byte) ([]byte, error) {
	out := make([]byte, len(src))
	copy(out, src)
	return out, nil
}

func (noneCodec) close() {}

// gzipCodec 使用标准库默认压缩级（gzip.DefaultCompression）。
type gzipCodec struct {
	buf bytes.Buffer
	w   *gzip.Writer
}

func newGzipCodec() (*gzipCodec, error) {
	c := &gzipCodec{}
	w, err := gzip.NewWriterLevel(&c.buf, gzip.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("创建 gzip writer: %w", err)
	}
	c.w = w
	return c, nil
}

func (c *gzipCodec) compress(src []byte) ([]byte, error) {
	c.buf.Reset()
	c.w.Reset(&c.buf)
	if _, err := c.w.Write(src); err != nil {
		return nil, fmt.Errorf("gzip 压缩: %w", err)
	}
	if err := c.w.Close(); err != nil {
		return nil, fmt.Errorf("gzip 压缩收尾: %w", err)
	}
	return append([]byte(nil), c.buf.Bytes()...), nil
}

func (c *gzipCodec) decompress(src []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(src))
	if err != nil {
		return nil, fmt.Errorf("gzip 解压: %w", err)
	}
	out, readErr := io.ReadAll(r)
	closeErr := r.Close()
	if readErr != nil {
		return nil, fmt.Errorf("gzip 解压: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("gzip 解压收尾: %w", closeErr)
	}
	return out, nil
}

func (c *gzipCodec) close() {
	_ = c.w.Close()
}

// zstdCodec 用 EncodeAll/DecodeAll 对整批生成一个 zstd frame。
// 级别经 EncoderLevelFromZstd 映射：1 -> SpeedFastest，3 -> SpeedDefault。
type zstdCodec struct {
	enc *zstd.Encoder
	dec *zstd.Decoder
}

func newZstdCodec(level int) (*zstdCodec, error) {
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)),
		zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil, fmt.Errorf("创建 zstd encoder（level %d）: %w", level, err)
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
	if err != nil {
		enc.Close()
		return nil, fmt.Errorf("创建 zstd decoder（level %d）: %w", level, err)
	}
	return &zstdCodec{enc: enc, dec: dec}, nil
}

func (c *zstdCodec) compress(src []byte) ([]byte, error) {
	out := c.enc.EncodeAll(src, nil)
	if out == nil && len(src) > 0 {
		return nil, fmt.Errorf("zstd 压缩返回空结果")
	}
	return out, nil
}

func (c *zstdCodec) decompress(src []byte) ([]byte, error) {
	out, err := c.dec.DecodeAll(src, nil)
	if err != nil {
		return nil, fmt.Errorf("zstd 解压: %w", err)
	}
	return out, nil
}

func (c *zstdCodec) close() {
	_ = c.enc.Close()
	c.dec.Close()
}

// lz4Codec 使用 lz4 frame 格式（默认 frame 参数，非 block API）。
type lz4Codec struct {
	buf bytes.Buffer
	w   *lz4.Writer
}

func newLZ4Codec() *lz4Codec {
	c := &lz4Codec{}
	c.w = lz4.NewWriter(&c.buf)
	return c
}

func (c *lz4Codec) compress(src []byte) ([]byte, error) {
	c.buf.Reset()
	c.w.Reset(&c.buf)
	if _, err := c.w.Write(src); err != nil {
		return nil, fmt.Errorf("lz4 压缩: %w", err)
	}
	if err := c.w.Close(); err != nil {
		return nil, fmt.Errorf("lz4 压缩收尾: %w", err)
	}
	return append([]byte(nil), c.buf.Bytes()...), nil
}

func (c *lz4Codec) decompress(src []byte) ([]byte, error) {
	r := lz4.NewReader(bytes.NewReader(src))
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("lz4 解压: %w", err)
	}
	return out, nil
}

func (c *lz4Codec) close() {
	_ = c.w.Close()
}
