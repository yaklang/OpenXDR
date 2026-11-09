package vuln

import (
	"archive/zip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/schema"
	"openxdr/server/ent/setting"
)

// DefaultBaseURL OSV 按生态打包的公告：<base>/<Debian|Ubuntu>/all.zip
const DefaultBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// Ecosystem 资产软件清单对应的漏洞生态（Debian:13、Ubuntu:22.04），认不出的发行版返回空
func Ecosystem(os, version string) string {
	switch os {
	case "debian":
		return "Debian:" + version
	case "ubuntu":
		return "Ubuntu:" + version
	}
	return ""
}

// archive 生态在 OSV 上的打包名
func archive(eco string) string {
	name, _, _ := strings.Cut(eco, ":")
	return name
}

// osvEcosystem 把 OSV 的生态名归到我们的生态键：Ubuntu 的 LTS、Pro 后缀都归到版本号上，
// 只认普通仓库（Pro / FIPS 是另一套包）
func osvEcosystem(s string) string {
	parts := strings.Split(s, ":")
	switch {
	case parts[0] == "Debian" && len(parts) == 2:
		return s
	case parts[0] == "Ubuntu" && len(parts) >= 2 && parts[1] != "Pro":
		return "Ubuntu:" + parts[1]
	}
	return ""
}

// Syncer 每天同步一次需要的生态；Dir 非空时只读离线目录里的 <Debian|Ubuntu>.zip，不联网
type Syncer struct {
	DB       *ent.Client
	SQL      *sql.DB
	BaseURL  string
	Dir      string
	Interval time.Duration
	HTTP     *http.Client
}

// Run 每小时看一次哪些生态该同步了：新出现的发行版不用等满一个同步周期
func (s *Syncer) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		if err := s.Sync(ctx); err != nil {
			slog.Error("漏洞库同步失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Status 每个生态最近一次同步的结果，存在 settings 表，界面据此说明数据有多新
type Status struct {
	At      time.Time `json:"at"`
	Records int       `json:"records"`
	Error   string    `json:"error,omitempty"`
}

const statusKey = "vuln_sync"

// due 生态该不该同步：没同步过、成功已超过一个周期、失败已超过一小时
func due(st Status, ok bool, interval time.Duration, now time.Time) bool {
	switch {
	case !ok:
		return true
	case st.Error != "":
		return now.Sub(st.At) >= time.Hour
	default:
		return now.Sub(st.At) >= interval
	}
}

// Sync 按资产实际用到、且到期的生态同步；同一生态整批替换，失败不动旧数据
func (s *Syncer) Sync(ctx context.Context) error {
	ecos, err := s.needed(ctx)
	if err != nil || len(ecos) == 0 {
		return err
	}
	status := LoadStatus(ctx, s.DB)
	now := time.Now()
	byArchive := map[string][]string{}
	for _, e := range ecos {
		if st, ok := status[e]; due(st, ok, s.Interval, now) {
			byArchive[archive(e)] = append(byArchive[archive(e)], e)
		}
	}
	if len(byArchive) == 0 {
		return nil
	}
	for name, want := range byArchive {
		n, err := s.syncArchive(ctx, name, want)
		for _, e := range want {
			st := Status{At: time.Now(), Records: n[e]}
			if err != nil {
				// 记下失败时刻，一小时后重试；旧数据与记录数保留
				st = Status{At: time.Now(), Records: status[e].Records, Error: err.Error()}
			}
			status[e] = st
		}
		if err != nil {
			slog.Error("漏洞库同步失败", "archive", name, "err", err)
		} else {
			slog.Info("漏洞库已同步", "archive", name, "records", n)
		}
	}
	return saveStatus(ctx, s.DB, status)
}

func (s *Syncer) needed(ctx context.Context) ([]string, error) {
	rows, err := s.SQL.QueryContext(ctx, `SELECT DISTINCT software->>'os', software->>'version' FROM assets WHERE software IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var o, v sql.NullString
		if err := rows.Scan(&o, &v); err != nil {
			return nil, err
		}
		if e := Ecosystem(o.String, v.String); e != "" {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

func (s *Syncer) open(ctx context.Context, name string) (string, func(), error) {
	if s.Dir != "" {
		return filepath.Join(s.Dir, name+".zip"), func() {}, nil
	}
	tmp, err := os.CreateTemp("", "osv-*.zip")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { tmp.Close(); os.Remove(tmp.Name()) }
	url := strings.TrimRight(s.BaseURL, "/") + "/" + name + "/all.zip"
	if err := s.download(ctx, url, tmp); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("下载 %s 失败：%w", name, err)
	}
	return tmp.Name(), cleanup, nil
}

// 分段下载：同一条线路上单个连接时快时慢（生产实测同一容器里一条连接 20 秒 55 MB，另一条几分钟不动），
// 一条连接走到底会被慢的那条拖死。每段单独限时，超时换新连接重下这一段（测试里调小）
var (
	chunkSize    = 8 << 20
	chunkTimeout = 90 * time.Second
)

const (
	chunkAttempts = 4
	maxArchive    = 1 << 30 // Debian 全量约 80 MB，远超就是源不对
)

// download 按 Range 分段下载到 w；源不支持 Range（返回 200）时退回整包下载
func (s *Syncer) download(ctx context.Context, url string, w io.Writer) error {
	client := s.HTTP
	if client == nil {
		client = &http.Client{}
	}
	for off := int64(0); off < maxArchive; {
		var n int64
		var whole, last bool
		var err error
		for attempt := 1; attempt <= chunkAttempts; attempt++ {
			n, whole, last, err = s.chunk(ctx, client, url, off, w)
			if err == nil || ctx.Err() != nil {
				break
			}
			slog.Warn("漏洞库分段下载重试", "offset", off, "attempt", attempt, "err", err)
		}
		if err != nil {
			return err
		}
		if whole || last {
			return nil
		}
		off += n
	}
	return errors.New("漏洞库压缩包超过 1 GiB")
}

// chunk 下载一段。whole：源不支持 Range、已整包写完；last：这是最后一段
func (s *Syncer) chunk(ctx context.Context, client *http.Client, url string, off int64, w io.Writer) (n int64, whole, last bool, err error) {
	timeout := chunkTimeout
	if off == 0 {
		timeout = 10 * time.Minute // 第一段可能拿到整包（源不支持 Range）
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false, false, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+int64(chunkSize)-1))
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusRequestedRangeNotSatisfiable:
		return 0, false, true, nil // 恰好下完
	case http.StatusOK:
		if off > 0 {
			return 0, false, false, errors.New("源中途不再支持分段下载")
		}
		n, err = io.Copy(w, io.LimitReader(resp.Body, maxArchive))
		return n, true, true, err
	case http.StatusPartialContent:
	default:
		return 0, false, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// 先读进内存再写：半段失败重试时文件里不留残片
	buf, err := io.ReadAll(io.LimitReader(resp.Body, int64(chunkSize)))
	if err != nil {
		return 0, false, false, err
	}
	if _, err := w.Write(buf); err != nil {
		return 0, false, false, err
	}
	return int64(len(buf)), false, len(buf) < chunkSize, nil
}

type osvRecord struct {
	ID        string    `json:"id"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details"`
	Aliases   []string  `json:"aliases"`
	Published time.Time `json:"published"`
	Withdrawn string    `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

type row struct {
	osvID, eco, pkg, summary, vector string
	ranges                           []schema.VulnRange
	aliases                          []string
	score                            float64
	published                        *time.Time
}

// rows 一条 OSV 公告里属于 want 生态的部分，按（生态, 包）拆行
func rows(rec osvRecord, want map[string]bool) []row {
	if rec.Withdrawn != "" {
		return nil
	}
	var score float64
	var vector string
	for _, sv := range rec.Severity {
		if v, ok := CVSSv3(sv.Score); ok && v >= score {
			score, vector = v, sv.Score
		}
	}
	summary := rec.Summary
	if summary == "" {
		summary = rec.Details
	}
	if r := []rune(summary); len(r) > 500 {
		summary = string(r[:500])
	}
	// 复制出来再取地址：指向 rec 的字段会让整条公告（Details 全文、全部发行版的 affected）随每一行常驻内存，
	// Ubuntu 全量同步因此涨到数 GB
	var pub *time.Time
	if !rec.Published.IsZero() {
		p := rec.Published
		pub = &p
	}
	var out []row
	for _, a := range rec.Affected {
		eco := osvEcosystem(a.Package.Ecosystem)
		if !want[eco] || a.Package.Name == "" {
			continue
		}
		var ranges []schema.VulnRange
		for _, r := range a.Ranges {
			if r.Type != "ECOSYSTEM" {
				continue
			}
			cur := schema.VulnRange{}
			for _, ev := range r.Events {
				if v, ok := ev["introduced"]; ok {
					cur = schema.VulnRange{Introduced: v}
				}
				if v, ok := ev["fixed"]; ok {
					cur.Fixed = v
					ranges = append(ranges, cur)
					cur = schema.VulnRange{}
				}
			}
			if cur.Introduced != "" {
				ranges = append(ranges, cur)
			}
		}
		if len(ranges) > 0 {
			out = append(out, row{osvID: rec.ID, eco: eco, pkg: a.Package.Name, summary: summary, vector: vector,
				ranges: ranges, aliases: rec.Aliases, score: score, published: pub})
		}
	}
	return out
}

func (s *Syncer) syncArchive(ctx context.Context, name string, ecos []string) (map[string]int, error) {
	path, cleanup, err := s.open(ctx, name)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	z, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("打开 %s 失败：%w", path, err)
	}
	defer z.Close()
	want := map[string]bool{}
	for _, e := range ecos {
		want[e] = true
	}
	var all []row
	for _, f := range z.File {
		if !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > 8<<20 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		var rec osvRecord
		err = json.NewDecoder(rc).Decode(&rec)
		rc.Close()
		if err != nil {
			continue // 单条坏了不影响整批
		}
		all = append(all, rows(rec, want)...)
	}
	counts := map[string]int{}
	for _, r := range all {
		counts[r.eco]++
	}
	return counts, s.replace(ctx, ecos, all)
}

// replace 一个事务里删掉这些生态的旧记录、写入新的
func (s *Syncer) replace(ctx context.Context, ecos []string, all []row) error {
	tx, err := s.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range ecos {
		if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_records WHERE ecosystem=$1`, e); err != nil {
			return err
		}
	}
	const batch = 500
	now := time.Now()
	for i := 0; i < len(all); i += batch {
		end := min(i+batch, len(all))
		var sb strings.Builder
		args := make([]any, 0, (end-i)*10)
		sb.WriteString(`INSERT INTO vuln_records (osv_id, ecosystem, package, ranges, aliases, summary, score, vector, published, synced_at) VALUES `)
		for j, r := range all[i:end] {
			if j > 0 {
				sb.WriteByte(',')
			}
			n := len(args)
			fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)", n+1, n+2, n+3, n+4, n+5, n+6, n+7, n+8, n+9, n+10)
			ranges, _ := json.Marshal(r.ranges)
			aliases, _ := json.Marshal(r.aliases)
			args = append(args, r.osvID, r.eco, r.pkg, string(ranges), string(aliases), r.summary, r.score, r.vector, r.published, now)
		}
		if _, err := tx.ExecContext(ctx, sb.String(), args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadStatus 读同步状态；没同步过返回空表
func LoadStatus(ctx context.Context, db *ent.Client) map[string]Status {
	out := map[string]Status{}
	if row, err := db.Setting.Get(ctx, statusKey); err == nil {
		_ = json.Unmarshal(row.Value, &out)
	}
	return out
}

func saveStatus(ctx context.Context, db *ent.Client, st map[string]Status) error {
	value, err := json.Marshal(st)
	if err != nil {
		return err
	}
	n, err := db.Setting.Update().Where(setting.IDEQ(statusKey)).SetValue(value).Save(ctx)
	if err != nil || n > 0 {
		return err
	}
	return db.Setting.Create().SetID(statusKey).SetValue(value).Exec(ctx)
}
