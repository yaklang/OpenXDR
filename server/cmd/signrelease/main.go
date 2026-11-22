// signrelease 给 agent / sensor 安装包做发布签名。私钥只放在发布者自己的机器上，不放进 server 节点：
// 拿下 server 节点的人能换掉分发目录里的安装包，但签不出嵌了发布公钥的采集端肯装的签名。
//
//	signrelease keygen <私钥文件>                            生成 Ed25519 私钥（PKCS#8 PEM，0600），打印公钥十六进制
//	signrelease sign [--kind agent|sensor] <私钥> <平台> <包> 写出 <安装包>.sig（十六进制签名；省略 --kind 时按 openxdr-sensor- 前缀自动区分）
//	signrelease pubkey <私钥文件>                            打印公钥十六进制，构建采集端时设为 OPENXDR_RELEASE_PUBKEY
//
// 平台与分发目录一致：linux-amd64 / linux-arm64 / windows-amd64。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// 签名域前缀，分别与 agent/src/upgrade.rs、sensor/src/upgrade.rs 一致；域分离防止跨组件混用签名
const (
	agentContext  = "openxdr-agent-release-v1\x00"
	sensorContext = "openxdr-sensor-release-v1\x00"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	switch {
	case len(args) == 2 && args[0] == "keygen":
		return keygen(args[1])
	case len(args) >= 1 && args[0] == "sign":
		kind, rest, err := parseSignArgs(args[1:])
		if err != nil {
			return err
		}
		ctx, err := contextFor(kind, rest[2])
		if err != nil {
			return err
		}
		key, err := load(rest[0])
		if err != nil {
			return err
		}
		sig, err := signWithContext(key, ctx, rest[1], rest[2])
		if err != nil {
			return err
		}
		return os.WriteFile(rest[2]+".sig", []byte(hex.EncodeToString(sig)+"\n"), 0o644)
	case len(args) == 2 && args[0] == "pubkey":
		key, err := load(args[1])
		if err != nil {
			return err
		}
		fmt.Println(hex.EncodeToString(key.Public().(ed25519.PublicKey)))
		return nil
	}
	return errors.New("用法：signrelease keygen <私钥文件> | sign [--kind agent|sensor] <私钥文件> <平台> <安装包> | pubkey <私钥文件>")
}

func parseSignArgs(args []string) (kind string, rest []string, err error) {
	if len(args) == 5 && (args[0] == "--kind" || args[0] == "-kind") {
		return args[1], args[2:], nil
	}
	if len(args) == 4 && (strings.HasPrefix(args[0], "--kind=") || strings.HasPrefix(args[0], "-kind=")) {
		_, k, _ := strings.Cut(args[0], "=")
		return k, args[1:], nil
	}
	if len(args) == 3 {
		return "", args, nil
	}
	return "", nil, errors.New("用法：signrelease sign [--kind agent|sensor] <私钥文件> <平台> <安装包>")
}

func contextFor(kind, file string) (string, error) {
	switch kind {
	case "":
		if strings.HasPrefix(filepath.Base(file), "openxdr-sensor-") {
			return sensorContext, nil
		}
		return agentContext, nil
	case "agent":
		return agentContext, nil
	case "sensor":
		return sensorContext, nil
	default:
		return "", fmt.Errorf("未知组件类型 %q，仅支持 agent 或 sensor", kind)
	}
}

func keygen(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s 已存在，不覆盖：换发布私钥意味着已部署的 agent 都不再接受新安装包", path)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(pub))
	return nil
}

func load(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s 不是 PEM", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s 不是 Ed25519 私钥", path)
	}
	return signer, nil
}

// sign 对 前缀 + 平台 + "\0" + 安装包 SHA-256（小写十六进制）签名；按文件名前缀区分 agent / sensor
func sign(key ed25519.PrivateKey, platform, file string) ([]byte, error) {
	ctx, err := contextFor("", file)
	if err != nil {
		return nil, err
	}
	return signWithContext(key, ctx, platform, file)
}

func signWithContext(key ed25519.PrivateKey, ctx, platform, file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return ed25519.Sign(key, messageWithContext(ctx, platform, hex.EncodeToString(h.Sum(nil)))), nil
}

func message(platform, sha string) []byte {
	return messageWithContext(agentContext, platform, sha)
}

func messageWithContext(ctx, platform, sha string) []byte {
	return []byte(ctx + platform + "\x00" + sha)
}
