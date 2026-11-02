package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"openxdr/server/deception/contract"
)

func NewManagedClient(base, id, token string, release contract.Release) (*Client, error) {
	if err := release.Validate(); err != nil {
		return nil, err
	}
	c, err := NewClient(base, id, token)
	if err != nil {
		return nil, err
	}
	c.managed = true
	c.release = release
	return c, nil
}

// NativeRelease 以实际可执行文件摘要绑定产物，不接受调用方覆盖摘要。
func NativeRelease() (contract.Release, error) {
	path, err := os.Executable()
	if err != nil {
		return contract.Release{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return contract.Release{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return contract.Release{}, err
	}
	return contract.Release{Engine: "native", Version: contract.Version, Digest: "sha256:" + hex.EncodeToString(h.Sum(nil)), Protocol: contract.ProtocolVersion, StateSchema: "native-v1"}, nil
}
