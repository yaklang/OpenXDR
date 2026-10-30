// 批级测量：压缩一遍、解压一遍，分别按总未压缩字节/墙钟时间算吞吐；
// 解压结果逐批与原文比较，任何不一致都返回错误，绝不放宽。
package main

import (
	"bytes"
	"fmt"
	"time"
)

type row struct {
	Source            string
	Representation    string
	BatchEvents       int
	Codec             string
	Batches           int
	UncompressedBytes int
	CompressedBytes   int
	Ratio             float64
	CompressMBps      float64
	DecompressMBps    float64
	Lossless          bool
}

// measureBatches 对一个表示的全部批次跑给定 codec，返回每个 codec 一行统计。
// batchEvents 是请求的批大小；最后一批可能更小，batches 是实际批数。
func measureBatches(source, representation string, batchEvents int, batches [][]byte, names []string) ([]row, error) {
	if len(batches) == 0 {
		return nil, fmt.Errorf("%s/%s 没有可测量的批次", source, representation)
	}
	total := 0
	for _, b := range batches {
		total += len(b)
	}
	if total == 0 {
		return nil, fmt.Errorf("%s/%s 的未压缩表示是 0 字节", source, representation)
	}

	rows := make([]row, 0, len(names))
	for _, name := range names {
		r, err := measureCodec(source, representation, batchEvents, batches, total, name)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	return rows, nil
}

func measureCodec(source, representation string, batchEvents int, batches [][]byte, total int, name string) (row, error) {
	where := fmt.Sprintf("source=%s representation=%s batch=%d codec=%s", source, representation, batchEvents, name)
	c, err := newCodec(name)
	if err != nil {
		return row{}, fmt.Errorf("%s: %w", where, err)
	}
	defer c.close()

	compressed := make([][]byte, len(batches))
	started := time.Now()
	for i, b := range batches {
		out, err := c.compress(b)
		if err != nil {
			return row{}, fmt.Errorf("%s 第 %d/%d 批压缩失败: %w", where, i+1, len(batches), err)
		}
		compressed[i] = out
	}
	compressElapsed := time.Since(started)

	compressedBytes := 0
	for _, b := range compressed {
		compressedBytes += len(b)
	}
	if compressedBytes == 0 {
		return row{}, fmt.Errorf("%s 压缩后总字节为 0", where)
	}

	decompressed := make([][]byte, len(batches))
	started = time.Now()
	for i, b := range compressed {
		out, err := c.decompress(b)
		if err != nil {
			return row{}, fmt.Errorf("%s 第 %d/%d 批解压失败: %w", where, i+1, len(batches), err)
		}
		decompressed[i] = out
	}
	decompressElapsed := time.Since(started)

	for i, want := range batches {
		if name == "none" && !bytes.Equal(compressed[i], want) {
			return row{}, fmt.Errorf("none 基线校验失败：%s 第 %d/%d 批压缩结果与原文不一致", where, i+1, len(batches))
		}
		if !bytes.Equal(decompressed[i], want) {
			return row{}, fmt.Errorf("无损校验失败：%s 第 %d/%d 批解压结果与原文不一致（原文 %d 字节，解压 %d 字节）",
				where, i+1, len(batches), len(want), len(decompressed[i]))
		}
	}

	return row{
		Source:            source,
		Representation:    representation,
		BatchEvents:       batchEvents,
		Codec:             name,
		Batches:           len(batches),
		UncompressedBytes: total,
		CompressedBytes:   compressedBytes,
		Ratio:             float64(total) / float64(compressedBytes),
		CompressMBps:      mbPerSecond(total, compressElapsed),
		DecompressMBps:    mbPerSecond(total, decompressElapsed),
		Lossless:          true,
	}, nil
}

// mbPerSecond 的 MB 按 1,000,000 字节计；分子统一是总未压缩字节。
// 极小批次可能短于时钟分辨率（elapsed 为 0），按 1ns 计，避免把"测不出来"报成 0 吞吐。
func mbPerSecond(n int, elapsed time.Duration) float64 {
	secs := elapsed.Seconds()
	if secs < 1e-9 {
		secs = 1e-9
	}
	return float64(n) / 1e6 / secs
}
