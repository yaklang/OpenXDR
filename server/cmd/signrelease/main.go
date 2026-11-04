// signrelease 给 agent 安装包做发布签名。私钥只放在发布者自己的机器上，不放进 server 节点：
// 拿下 server 节点的人能换掉分发目录里的安装包，但签不出嵌了发布公钥的 agent 肯装的签名。
//
//	signrelease keygen <私钥文件>             生成 Ed25519 私钥（PKCS#8 PEM，0600），打印公钥十六进制
//	signrelease sign <私钥文件> <平台> <安装包>  写出 <安装包>.sig（十六进制签名）
//	signrelease pubkey <私钥文件>             打印公钥十六进制，构建 agent 时设为 OPENXDR_RELEASE_PUBKEY
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
)

// context 签名域前缀，与 agent/src/upgrade.rs 一致
const context = "openxdr-agent-release-v1\x00"

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
	case len(args) == 4 && args[0] == "sign":
		key, err := load(args[1])
		if err != nil {
			return err
		}
		sig, err := sign(key, args[2], args[3])
		if err != nil {
			return err
		}
		return os.WriteFile(args[3]+".sig", []byte(hex.EncodeToString(sig)+"\n"), 0o644)
	case len(args) == 2 && args[0] == "pubkey":
		key, err := load(args[1])
		if err != nil {
			return err
		}
		fmt.Println(hex.EncodeToString(key.Public().(ed25519.PublicKey)))
		return nil
	}
	return errors.New("用法：signrelease keygen <私钥文件> | sign <私钥文件> <平台> <安装包> | pubkey <私钥文件>")
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

// sign 对 前缀 + 平台 + "\0" + 安装包 SHA-256（小写十六进制）签名
func sign(key ed25519.PrivateKey, platform, file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return ed25519.Sign(key, message(platform, hex.EncodeToString(h.Sum(nil)))), nil
}

func message(platform, sha string) []byte {
	return []byte(context + platform + "\x00" + sha)
}
