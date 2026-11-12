package sshkeys

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

func TestRemovalCommandRemovesOnlyMatchingFingerprintAndRejectsSymlink(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("本机未安装 ssh-keygen，跳过命令执行验证")
	}

	fpTarget := "SHA256:NcQW5HBTfu9BcEAE6Fv50H5od9G7TfPoVJ1Cnb/jqLQ"
	keyTarget := "AAAAC3NzaC1lZDI1NTE5AAAAIBEREhMUFRYXGBkaGxwdHh8REhMUFRYXGBkaGxwdHh8R"
	keyKeep := "AAAAC3NzaC1lZDI1NTE5AAAAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg"

	dir := t.TempDir()
	akFile := filepath.Join(dir, "authorized_keys")
	initial := strings.Join([]string{
		"# keep comment",
		`from="10.1.1.1,10.1.1.2",command="echo ssh-ed25519 fake" ssh-ed25519 ` + keyTarget + ` attacker@evil`,
		`ssh-ed25519 ` + keyKeep + ` admin@workstation`,
		"",
	}, "\n")
	if err := os.WriteFile(akFile, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	cmdStr, err := RemovalCommand(akFile, fpTarget)
	if err != nil {
		t.Fatalf("生成移除命令失败: %v", err)
	}
	if out, err := exec.Command("sh", "-c", cmdStr).CombinedOutput(); err != nil {
		t.Fatalf("执行移除命令失败: %v, out=%s", err, string(out))
	}

	after, err := os.ReadFile(akFile)
	if err != nil {
		t.Fatal(err)
	}
	got := string(after)
	if strings.Contains(got, keyTarget) {
		t.Fatalf("目标钥匙未被移除: %s", got)
	}
	if !strings.Contains(got, keyKeep) || !strings.Contains(got, "# keep comment") {
		t.Fatalf("误伤了同文件的其他合法钥匙或注释: %s", got)
	}
	st, err := os.Stat(akFile)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("文件权限改变: got %o, want 0600", st.Mode().Perm())
	}

	// 再次执行应因找不到该指纹而非零退出，且不破坏原文件
	if err := exec.Command("sh", "-c", cmdStr).Run(); err == nil {
		t.Fatal("重复移除不存在的指纹应当返回非零退出码")
	}

	// 符号链接必须拒绝执行
	sym := filepath.Join(dir, "symlink_keys")
	if err := os.Symlink(akFile, sym); err != nil {
		t.Fatal(err)
	}
	symCmd, err := RemovalCommand(sym, fpTarget)
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("sh", "-c", symCmd).Run(); err == nil {
		t.Fatal("指向文件的符号链接必须拒绝修改")
	}
}

func TestRemovalCommandValidation(t *testing.T) {
	validFP := "SHA256:SQfC+vTbLURn9cTkVxIS8fGQ3FKNAJWeB0o139+gV4M"
	if _, err := RemovalCommand("relative/path", validFP); err == nil {
		t.Fatal("相对路径应拒绝")
	}
	if _, err := RemovalCommand("/root/.ssh/authorized_keys\nrm -rf /", validFP); err == nil {
		t.Fatal("含换行的路径应拒绝")
	}
	if _, err := RemovalCommand("/root/.ssh/authorized_keys", "MD5:aa:bb"); err == nil {
		t.Fatal("非 SHA256 指纹应拒绝")
	}
}

func TestMatchKeyFactSpecificity(t *testing.T) {
	fp := "SHA256:SQfC+vTbLURn9cTkVxIS8fGQ3FKNAJWeB0o139+gV4M"
	assetA := uuid.New()
	assetB := uuid.New()
	group1 := uuid.New()
	group2 := uuid.New()

	fGlobal := &ent.Fact{ID: uuid.New(), Kind: "key", Subject: fp, Content: "global"}
	fGroup1 := &ent.Fact{ID: uuid.New(), Kind: "key", Subject: fp, GroupID: &group1, Content: "group1"}
	fAssetA := &ent.Fact{ID: uuid.New(), Kind: "key", Subject: fp, AssetID: &assetA, GroupID: &group1, Content: "assetA"}

	candidates := []*ent.Fact{fGlobal, fGroup1, fAssetA}

	if got := matchKeyFact(candidates, fp, assetA, &group1); got != fAssetA {
		t.Fatalf("应优先匹配单资产级事实，got=%v", got)
	}
	if got := matchKeyFact(candidates, fp, assetB, &group1); got != fGroup1 {
		t.Fatalf("同组其他资产应匹配组级事实，got=%v", got)
	}
	if got := matchKeyFact(candidates, fp, assetB, &group2); got != fGlobal {
		t.Fatalf("其他组资产应回退全局事实，got=%v", got)
	}
}
