package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// 与 agent/src/upgrade.rs 的 release_signature_vector 共用：全零种子对 linux-amd64 + "abc" 的哈希签名
func TestReleaseSignatureVector(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	dir := t.TempDir()
	file := filepath.Join(dir, "openxdr-agent-linux-amd64")
	if err := os.WriteFile(file, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	sig, err := sign(key, "linux-amd64", file)
	if err != nil {
		t.Fatal(err)
	}
	const want = "e3b72a71a5927467e125239596e627ac089a981cd8c3c0421ff940747348c5fe" +
		"34a7505a6edf487eae2dc5ca5b6d612d02bb33c92b1f504b1b6f0f68ed31810d"
	if got := hex.EncodeToString(sig); got != want {
		t.Fatalf("签名向量变了：%s", got)
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey),
		message("linux-amd64", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), sig) {
		t.Fatal("签名应能用公钥验证")
	}
}

// 与 sensor/src/upgrade.rs 的 release_signature_vector 共用：全零种子对 sensor 域 + linux-amd64 + "abc" 哈希签名
func TestSensorReleaseSignatureVector(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	dir := t.TempDir()
	file := filepath.Join(dir, "openxdr-sensor-linux-amd64")
	if err := os.WriteFile(file, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	sig, err := sign(key, "linux-amd64", file)
	if err != nil {
		t.Fatal(err)
	}
	const want = "b10e0add23b86cf0bd97111a07eca82a4e4b78d1de69e63495ef040194b95fba" +
		"a66a6f35713561bd12663fa54adf3ae87b6f696da45b14068d3a8ff391161000"
	if got := hex.EncodeToString(sig); got != want {
		t.Fatalf("sensor 签名向量变了：%s", got)
	}
	const sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	pub := key.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, messageWithContext(sensorContext, "linux-amd64", sha), sig) {
		t.Fatal("sensor 签名应能用 sensor 域验证")
	}
	if ed25519.Verify(pub, messageWithContext(agentContext, "linux-amd64", sha), sig) {
		t.Fatal("sensor 签名不能通过 agent 域验证（必须域分离）")
	}
}

func TestRunSignExplicitKind(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "release.key")
	if err := keygen(keyPath); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(dir, "custom-name.bin")
	if err := os.WriteFile(binPath, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", "--kind", "sensor", keyPath, "linux-amd64", binPath}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(binPath + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(string(raw[:len(raw)-1]))
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("签名文件格式不对：%q", raw)
	}
	key, err := load(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	const sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), messageWithContext(sensorContext, "linux-amd64", sha), sig) {
		t.Fatal("--kind sensor 应使用 sensor 域签名")
	}
	if err := run([]string{"sign", "--kind", "bogus", keyPath, "linux-amd64", binPath}); err == nil {
		t.Fatal("非法 --kind 应拒绝")
	}
}

func TestKeygenRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.key")
	if err := keygen(path); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("私钥权限应为 0600：%v", st.Mode())
	}
	if err := keygen(path); err == nil {
		t.Fatal("已有私钥不能覆盖")
	}
	if _, err := load(path); err != nil {
		t.Fatal(err)
	}
}
