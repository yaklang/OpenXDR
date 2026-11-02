package intel

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"strings"
)

// ThreatFox 的认证导出是单个 CSV 的 ZIP；仅在内存中读取，压缩前后均限制大小。
func parseThreatFoxZIP(r io.Reader) ([]Entry, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxFeedBytes+1))
	if err != nil {
		return nil, errors.New("情报压缩包读取失败")
	}
	if len(raw) > maxFeedBytes {
		return nil, errors.New("情报压缩包超过 50 MiB 上限")
	}
	archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || len(archive.File) != 1 {
		return nil, errors.New("情报压缩包必须只含一个 CSV 文件")
	}
	file := archive.File[0]
	if !strings.HasSuffix(strings.ToLower(file.Name), ".csv") || file.UncompressedSize64 > maxFeedBytes {
		return nil, errors.New("情报压缩包内容格式或大小不符合要求")
	}
	content, err := file.Open()
	if err != nil {
		return nil, errors.New("无法打开情报压缩包中的 CSV")
	}
	defer content.Close()
	limited := &io.LimitedReader{R: content, N: maxFeedBytes + 1}
	entries, err := parseThreatFox(limited)
	if err != nil {
		if errors.Is(err, errFeedEntryLimit) {
			return nil, errFeedEntryLimit
		}
		return nil, errors.New("情报压缩包中的 CSV 不完整或损坏")
	}
	if limited.N == 0 {
		return nil, errors.New("情报解压后超过 50 MiB 上限")
	}
	return entries, nil
}
