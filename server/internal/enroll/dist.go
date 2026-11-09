package enroll

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Dist AGENT_DIST_DIR 里的采集端安装包。agent 与 sensor 放同一个目录、按文件名区分，
// 安装脚本从这里下载，在线的 agent / sensor 也按这里的版本自动升级。
type Dist struct {
	Dir string
	// 平台到文件名，由 AgentDist / SensorDist 给定
	Files map[string]string

	mu    sync.Mutex
	cache map[string]distEntry
}

type distEntry struct {
	size    int64
	modTime time.Time
	sha256  string
}

// AgentDist agent 安装包。
func AgentDist(dir string) *Dist {
	return &Dist{Dir: dir, Files: map[string]string{
		"linux-amd64":   "openxdr-agent-linux-amd64",
		"linux-arm64":   "openxdr-agent-linux-arm64",
		"windows-amd64": "openxdr-agent-windows-amd64.exe",
	}}
}

// SensorDist sensor 安装包。Windows 版靠系统自带的 Packet Monitor 实时 API，只有 x64。
func SensorDist(dir string) *Dist {
	return &Dist{Dir: dir, Files: map[string]string{
		"linux-amd64":   "openxdr-sensor-linux-amd64",
		"linux-arm64":   "openxdr-sensor-linux-arm64",
		"windows-amd64": "openxdr-sensor-windows-amd64.exe",
	}}
}

// TrayDist 受管主机上的托盘程序（只显示防护状态），安装脚本顺带装上；不随 agent 自动升级，
// 状态协议只增不改，旧托盘读新 agent 照样能用。
func TrayDist(dir string) *Dist {
	return &Dist{Dir: dir, Files: map[string]string{
		"linux-amd64":   "openxdr-tray-linux-amd64",
		"linux-arm64":   "openxdr-tray-linux-arm64",
		"windows-amd64": "openxdr-tray-windows-amd64.exe",
	}}
}

// Dists 同一个分发目录里的三类安装包。
type Dists struct{ Agent, Sensor, Tray *Dist }

func NewDists(dir string) Dists { return Dists{AgentDist(dir), SensorDist(dir), TrayDist(dir)} }

// arches Rust std::env::consts::ARCH 到分发平台后缀。
var arches = map[string]string{"x86_64": "amd64", "aarch64": "arm64"}

// Platform 采集端上报的 os/arch 对应的分发平台，不支持时返回空。
func (d *Dist) Platform(os, arch string) string {
	p := os + "-" + arches[arch]
	if _, ok := d.path(p); !ok {
		return ""
	}
	return p
}

func (d *Dist) path(platform string) (string, bool) {
	if d == nil || d.Dir == "" {
		return "", false
	}
	name, ok := d.Files[platform]
	if !ok {
		return "", false
	}
	return filepath.Join(d.Dir, name), true
}

// Available 实际放了安装包的平台。
func (d *Dist) Available() []string {
	if d == nil {
		return nil
	}
	var out []string
	for p := range d.Files {
		if path, ok := d.path(p); ok {
			if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

// SHA256 平台安装包的哈希，没有安装包返回空。文件没变就用缓存，不每次注册都重算。
func (d *Dist) SHA256(platform string) string {
	path, ok := d.path(platform)
	if !ok {
		return ""
	}
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if e, ok := d.cache[platform]; ok && e.size == st.Size() && e.modTime.Equal(st.ModTime()) {
		return e.sha256
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if d.cache == nil {
		d.cache = map[string]distEntry{}
	}
	d.cache[platform] = distEntry{st.Size(), st.ModTime(), sum}
	return sum
}

// Signature 平台安装包的发布签名：安装包旁边的 <文件名>.sig，十六进制的 64 字节 Ed25519 签名（cmd/signrelease 生成）。
// 没有或格式不对返回 nil；server 不持有发布私钥，也不校验，校验在 agent 上
func (d *Dist) Signature(platform string) []byte {
	path, ok := d.path(platform)
	if !ok {
		return nil
	}
	raw, err := os.ReadFile(path + ".sig")
	if err != nil {
		return nil
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(sig) != 64 {
		return nil
	}
	return sig
}

// Open 打开平台安装包。
func (d *Dist) Open(platform string) (*os.File, error) {
	path, ok := d.path(platform)
	if !ok {
		return nil, os.ErrNotExist
	}
	return os.Open(path)
}
