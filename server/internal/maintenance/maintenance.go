// Package maintenance 夜间维护：每天窗口内逐台装安全更新，需要重启就重启，确认恢复后再轮下一台。
//
// 主机早就由 unattended-upgrades 装好了安全更新与新内核，却常年不重启，新内核不生效。这里只做确定的几步，
// 不经 AI 判断：
//   - 一次只动一台：装更新 → 需要重启就定时重启 → 等 agent 回来、启动 ID 变了才算完成，再轮下一台
//   - 跑着 OpenXDR server 的平台节点放在最后，一晚最多一台，另一台平台节点必须在线
//   - 有一台没按时回来，当晚停手并通知；排除名单（PVE 宿主机）永远不碰
//
// 下发的只有本文件里写死的三条命令（见 upgradeScript、rebootCommand、bootIDCommand），没有任何外部输入，
// 等同封闭模板，所以直接走签名下发（Hub.IssueExec），不经命令闸门的 AI 审计。
package maintenance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/containment"
	"openxdr/server/internal/response"
)

// runningContainers 正在运行的容器名，--rm 的一次性容器除外（停了就没了，重启后不该回来）。
// 不按重启策略筛：2026-11-10 SoulStream 的 PG、blue-server 的 source-sentinel 是手动拉起、策略为 no 的，
// 维护重启后没回来，业务断了一天也没人发现
const runningContainers = `docker ps -q | xargs -r docker inspect -f '{{if not .HostConfig.AutoRemove}}{{.Name}}{{end}}' | sed 's#^/##' | grep -v '^$' | sort`

// runningFile 重启前在跑的容器名单，留在主机上，重启后由 bootIDCommand 照着拉起；名单出自主机自己，不经服务端
const runningFile = "/var/lib/openxdr/maintenance-running"

// upgradeScript 装安全更新（unattended-upgrades 的默认配置只装安全源），报出启动 ID、是否需要重启，
// 记下并报出正在运行的容器（重启后它们都该回来）
const upgradeScript = `set -u
export DEBIAN_FRONTEND=noninteractive
if command -v unattended-upgrade >/dev/null 2>&1; then unattended-upgrade || echo "UPGRADE_FAILED $?"; fi
echo "BOOT_ID $(cat /proc/sys/kernel/random/boot_id)"
if [ -f /var/run/reboot-required ]; then echo REBOOT_REQUIRED; fi
if command -v docker >/dev/null 2>&1; then mkdir -p /var/lib/openxdr; ` + runningContainers + ` > ` + runningFile + `; echo "CONTAINERS $(tr '\n' ' ' < ` + runningFile + `)"; fi`

// rebootCommand 20 秒后重启：指令先回执，agent 再随系统重启
const rebootCommand = `systemd-run --on-active=20 --unit=openxdr-maintenance-reboot systemctl reboot`

// bootIDCommand 报出启动 ID 与正在运行的容器；重启前在跑、现在没跑的先照名单拉起来（策略为 no 的不会自己回来），
// 拉起的报 STARTED。还没重启时名单里的都在跑，什么也不做
const bootIDCommand = `echo "BOOT_ID $(cat /proc/sys/kernel/random/boot_id)"; if [ -f /var/run/reboot-required ]; then echo REBOOT_REQUIRED; fi
if command -v docker >/dev/null 2>&1; then
if [ -f ` + runningFile + ` ]; then while read -r n; do [ "$(docker inspect -f '{{.State.Running}}' "$n" 2>/dev/null)" = false ] && docker start "$n" >/dev/null 2>&1 && echo "STARTED $n"; done < ` + runningFile + `; fi
echo "CONTAINERS $(` + runningContainers + ` | tr '\n' ' ')"; fi`

const (
	stateKey = "maintenance.state"
	// 一台主机两次维护至少间隔这么久：同一晚不重复
	minInterval = 20 * time.Hour
	// 重启后最长等这么久 agent 回来
	rebootDeadline = 15 * time.Minute
	// 窗口剩余不足这么多就不开始新主机
	minRemaining = 20 * time.Minute
	// 主机在线的判定：agent 最近这么久内上报过
	onlineWithin = 3 * time.Minute
)

// Config 维护窗口（当地时间的起止小时分钟）与排除的主机名
type Config struct {
	Start, End time.Duration // 距当天零点
	Location   *time.Location
	Exclude    map[string]bool
	// 重启平台节点前交出数据库主节点；nil 时不交接（测试与单机部署）
	Patroni *Patroni
}

// ParseWindow "02:00-05:00"
func ParseWindow(s string) (time.Duration, time.Duration, error) {
	a, b, ok := strings.Cut(strings.TrimSpace(s), "-")
	if !ok {
		return 0, 0, errors.New("维护窗口格式应为 HH:MM-HH:MM")
	}
	parse := func(v string) (time.Duration, error) {
		t, err := time.Parse("15:04", strings.TrimSpace(v))
		if err != nil {
			return 0, errors.New("维护窗口格式应为 HH:MM-HH:MM")
		}
		return time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute, nil
	}
	start, err := parse(a)
	if err != nil {
		return 0, 0, err
	}
	end, err := parse(b)
	if err != nil {
		return 0, 0, err
	}
	if end <= start {
		return 0, 0, errors.New("维护窗口须在同一天内且结束晚于开始")
	}
	return start, end, nil
}

// remaining 窗口内还剩多久；不在窗口内返回 0
func (c Config) remaining(now time.Time) time.Duration {
	local := now.In(c.Location)
	midnight := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, c.Location)
	at := local.Sub(midnight)
	if at < c.Start || at >= c.End {
		return 0
	}
	return c.End - at
}

func (c Config) night(now time.Time) string {
	return now.In(c.Location).Format("2006-01-02")
}

// State 持久在 settings：单活切换、主节点自己被重启后接着做
type State struct {
	Night    string               `json:"night"`
	Halted   string               `json:"halted,omitempty"`
	CoreDone bool                 `json:"core_done"`
	Current  *Reboot              `json:"current,omitempty"`
	Done     map[string]time.Time `json:"done"`
	// Rev 每次写入加一，写入时比对：拿着过时状态的执行者写不进去，放弃本轮
	Rev int64 `json:"rev"`
}

// errStale 状态已被别的执行者改过。切换数据库主节点的那几秒里租约可能两边都拿到
// （2026-11-12 node1、node2 同时在跑维护，慢的那个超时后把已完成的一晚覆盖成停手并误报）
var errStale = errors.New("维护状态已被别的执行者更新")

// Reboot 已下发重启、等它回来的主机
type Reboot struct {
	AssetID    uuid.UUID `json:"asset_id"`
	Hostname   string    `json:"hostname"`
	BootBefore string    `json:"boot_before"`
	At         time.Time `json:"at"`
	// 重启前在跑、带重启策略的容器：重启后都回来了才算完成
	Containers []string `json:"containers,omitempty"`
	Missing    []string `json:"missing,omitempty"`
}

type Runner struct {
	DB     *ent.Client
	SQL    *sql.DB
	Hub    *response.Hub
	Config Config
	Notify func(ctx context.Context, title, text, path string) error
	Now    func() time.Time
	// 等指令回执的轮询间隔
	Poll time.Duration
	// Exec 下发固定命令并等回执，缺省走 Hub；测试里换成模拟的 agent
	Exec func(ctx context.Context, a *ent.Asset, cmd string, timeout time.Duration) (string, error)
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Runner) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		if err := r.Tick(ctx); err != nil && ctx.Err() == nil {
			slog.Error("夜间维护本轮失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick 一步：等着重启的先核对；窗口内再挑下一台
func (r *Runner) Tick(ctx context.Context) error {
	err := r.tick(ctx)
	if errors.Is(err, errStale) {
		slog.Info("夜间维护：状态已被另一执行者推进，本轮放弃")
		return nil
	}
	return err
}

func (r *Runner) tick(ctx context.Context) error {
	st, err := r.load(ctx)
	if err != nil {
		return err
	}
	now := r.now()
	if night := r.Config.night(now); st.Night != night && st.Current == nil && r.Config.remaining(now) > 0 {
		st.Night, st.Halted, st.CoreDone = night, "", false
		if err := r.save(ctx, st); err != nil {
			return err
		}
	}
	if st.Current != nil {
		return r.verify(ctx, st)
	}
	if st.Halted != "" || r.Config.remaining(now) < minRemaining {
		return nil
	}
	next, err := r.next(ctx, st)
	if err != nil || next == nil {
		return err
	}
	return r.maintain(ctx, st, next)
}

// next 下一台：普通主机按主机名依次，全部做完再轮平台节点（一晚一台，另一台须在线）
func (r *Runner) next(ctx context.Context, st *State) (*ent.Asset, error) {
	now := r.now()
	all, err := r.DB.Asset.Query().
		Where(asset.OsEQ("linux"), asset.AgentIDNotNil(), asset.RetiredAtIsNil()).
		Order(ent.Asc(asset.FieldHostname)).All(ctx)
	if err != nil {
		return nil, err
	}
	online := func(a *ent.Asset) bool { return a.SilentSince == nil && now.Sub(a.LastSeen) < onlineWithin }
	var plain, core []*ent.Asset
	for _, a := range all {
		if r.Config.Exclude[a.Hostname] || !online(a) {
			continue
		}
		if at, ok := st.Done[a.ID.String()]; ok && now.Sub(at) < minInterval {
			continue
		}
		if containment.RunsServer(a) {
			core = append(core, a)
		} else {
			plain = append(plain, a)
		}
	}
	if len(plain) > 0 {
		return plain[0], nil
	}
	if st.CoreDone || len(core) == 0 {
		return nil, nil
	}
	for _, a := range all {
		if containment.RunsServer(a) && a.ID != core[0].ID && !online(a) {
			return nil, nil // 另一台平台节点不在线，今晚不动平台节点
		}
	}
	return core[0], nil
}

// maintain 装更新；需要重启就记下状态再下发定时重启。
// 平台节点确认要重启才切数据库主节点：2026-11-12 node1 不需要重启也先切了一次，切完的瞬间又发不出指令，当晚停手
func (r *Runner) maintain(ctx context.Context, st *State, a *ent.Asset) error {
	out, err := r.exec(ctx, a, upgradeScript, 30*time.Minute)
	if err != nil {
		return r.halt(ctx, st, a.Hostname+" 装更新失败："+err.Error())
	}
	boot, reboot, failed, containers := parse(out)
	if failed != "" {
		slog.Warn("夜间维护：更新有失败", "host", a.Hostname, "detail", failed)
	}
	if !reboot {
		return r.done(ctx, st, a, "")
	}
	if boot == "" {
		return r.halt(ctx, st, a.Hostname+" 需要重启但读不到启动 ID，不重启")
	}
	if containment.RunsServer(a) {
		if err := r.handoff(ctx, a); err != nil {
			return r.halt(ctx, st, err.Error())
		}
		if err := r.reachable(ctx, a); err != nil {
			return r.halt(ctx, st, a.Hostname+" 切换数据库主节点后 agent 没回来："+err.Error())
		}
	}
	st.Current = &Reboot{AssetID: a.ID, Hostname: a.Hostname, BootBefore: boot, At: r.now(), Containers: containers}
	if containment.RunsServer(a) {
		st.CoreDone = true
	}
	// 先落状态再重启：被重启的是本节点时，接手的节点据此接着核对
	if err := r.save(ctx, st); err != nil {
		return err
	}
	if _, err := r.exec(ctx, a, rebootCommand, time.Minute); err != nil {
		st.Current = nil
		return r.halt(ctx, st, a.Hostname+" 下发重启失败："+err.Error())
	}
	slog.Info("夜间维护：已下发重启", "host", a.Hostname)
	return nil
}

// reachable 切换主库时 agent 会断开重连，切完立刻下发会回「agent 未连接任何集群节点」：
// 用只读的 bootIDCommand 探到 agent 回来再往下走
func (r *Runner) reachable(ctx context.Context, a *ent.Asset) error {
	deadline := time.Now().Add(reconnectWait)
	for {
		_, err := r.exec(ctx, a, bootIDCommand, time.Minute)
		if err == nil || !time.Now().Before(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.pollInterval()):
		}
	}
}

// reconnectWait 切换主库后等 agent 重连的上限
const reconnectWait = 3 * time.Minute

// verify 等着重启的主机回来：agent 在线且启动 ID 变了才算完成；超时当晚停手
func (r *Runner) verify(ctx context.Context, st *State) error {
	c := st.Current
	a, err := r.DB.Asset.Get(ctx, c.AssetID)
	if err != nil {
		return err
	}
	now := r.now()
	if a.AgentID != nil && a.LastSeen.After(c.At.Add(20*time.Second)) {
		if out, err := r.exec(ctx, a, bootIDCommand, time.Minute); err == nil {
			if boot, still, _, running := parse(out); boot != "" && boot != c.BootBefore {
				// 主机回来了，但服务也得回来：2026-11-10 node1 重启后 NATS 没被拉起，平台节点掉线 10 小时没人发现
				if missing := absent(c.Containers, running); len(missing) > 0 {
					c.Missing = missing
					if now.Sub(c.At) <= rebootDeadline {
						return r.save(ctx, st)
					}
					st.Current = nil
					return r.halt(ctx, st, fmt.Sprintf("%s 重启后 %d 分钟，这些容器仍没起来：%s", c.Hostname, int(rebootDeadline.Minutes()), strings.Join(missing, " ")))
				}
				st.Current = nil
				note := ""
				if still {
					note = "（重启后仍提示需要重启）"
				}
				if started := startedIn(out); len(started) > 0 {
					note += "（重启后照重启前名单拉起：" + strings.Join(started, " ") + "）"
				}
				return r.done(ctx, st, a, note)
			}
		}
	}
	if now.Sub(c.At) > rebootDeadline {
		st.Current = nil
		return r.halt(ctx, st, fmt.Sprintf("%s 重启后 %d 分钟仍未恢复（agent 未上线或启动 ID 未变）", c.Hostname, int(rebootDeadline.Minutes())))
	}
	return nil
}

// startedIn bootIDCommand 照名单拉起的容器
func startedIn(out string) []string {
	var started []string
	for _, line := range strings.Split(out, "\n") {
		if n, ok := strings.CutPrefix(strings.TrimSpace(line), "STARTED "); ok {
			started = append(started, n)
		}
	}
	return started
}

// absent before 里有、now 里没有的
func absent(before, now []string) []string {
	have := map[string]bool{}
	for _, n := range now {
		have[n] = true
	}
	var out []string
	for _, n := range before {
		if !have[n] {
			out = append(out, n)
		}
	}
	return out
}

func (r *Runner) done(ctx context.Context, st *State, a *ent.Asset, note string) error {
	if st.Done == nil {
		st.Done = map[string]time.Time{}
	}
	st.Done[a.ID.String()] = r.now()
	if err := r.save(ctx, st); err != nil {
		return err
	}
	r.audit(ctx, "maintenance_done", a.ID.String(), a.Hostname+" 夜间维护完成"+note)
	return nil
}

// halt 当晚停手、通知，第二天的窗口重新开始
func (r *Runner) halt(ctx context.Context, st *State, why string) error {
	st.Halted = why
	// 先写状态再审计、通知：过时的执行者写不进去，就不会误报
	if err := r.save(ctx, st); err != nil {
		return err
	}
	r.audit(ctx, "maintenance_halted", "", why)
	if r.Notify != nil {
		if err := r.Notify(ctx, "夜间维护已停止", why+"\n\n今晚不再继续，明晚窗口重新开始。请检查这台主机。", "/assets"); err != nil {
			slog.Error("夜间维护通知失败", "err", err)
		}
	}
	return nil
}

func (r *Runner) audit(ctx context.Context, action, target, detail string) {
	audit.System(ctx, r.DB, action, target, detail)
}

// exec 下发固定命令并等回执
func (r *Runner) exec(ctx context.Context, a *ent.Asset, cmd string, timeout time.Duration) (string, error) {
	if r.Exec != nil {
		return r.Exec(ctx, a, cmd, timeout)
	}
	c, err := r.Hub.IssueExec(ctx, response.Request{AssetID: a.ID, Kind: "exec", IssuedBy: "maintenance", Cmd: &cmd, TimeoutMS: uint32(timeout.Milliseconds())})
	if err != nil {
		return "", err
	}
	poll := r.pollInterval()
	deadline := time.Now().Add(timeout + time.Minute)
	for time.Now().Before(deadline) {
		c, err = r.DB.Command.Get(ctx, c.ID)
		if err != nil {
			return "", err
		}
		switch c.Status {
		case "succeeded":
			if c.Stdout == nil {
				return "", nil
			}
			return *c.Stdout, nil
		case "failed", "unsupported", "unknown":
			detail := c.Status
			if c.Detail != nil {
				detail += "：" + *c.Detail
			}
			return "", errors.New(detail)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(poll):
		}
	}
	return "", errors.New("等回执超时")
}

func (r *Runner) pollInterval() time.Duration {
	if r.Poll > 0 {
		return r.Poll
	}
	return 5 * time.Second
}

// parse 固定脚本的输出：启动 ID、是否需要重启、更新失败信息、运行中的容器
func parse(out string) (boot string, reboot bool, failed string, containers []string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "CONTAINERS"):
			containers = strings.Fields(strings.TrimPrefix(line, "CONTAINERS"))
		case strings.HasPrefix(line, "BOOT_ID "):
			boot = strings.TrimSpace(strings.TrimPrefix(line, "BOOT_ID "))
		case line == "REBOOT_REQUIRED":
			reboot = true
		case strings.HasPrefix(line, "UPGRADE_FAILED"):
			failed = line
		}
	}
	return boot, reboot, failed, containers
}

func (r *Runner) load(ctx context.Context) (*State, error) {
	var raw []byte
	err := r.SQL.QueryRowContext(ctx, `SELECT value FROM settings WHERE id=$1`, stateKey).Scan(&raw)
	st := &State{Done: map[string]time.Time{}}
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, st); err != nil {
		return nil, err
	}
	if st.Done == nil {
		st.Done = map[string]time.Time{}
	}
	return st, nil
}

func (r *Runner) save(ctx context.Context, st *State) error {
	// 记录只留最近 30 天的主机，避免下线主机越积越多
	for id, at := range st.Done {
		if r.now().Sub(at) > 30*24*time.Hour {
			delete(st.Done, id)
		}
	}
	prev := st.Rev
	st.Rev++
	b, _ := json.Marshal(st)
	res, err := r.SQL.ExecContext(ctx, `INSERT INTO settings (id, value, updated_at) VALUES ($1, $2::jsonb, now())
ON CONFLICT (id) DO UPDATE SET value=EXCLUDED.value, updated_at=now()
WHERE COALESCE((settings.value->>'rev')::bigint, 0) = $3`, stateKey, string(b), prev)
	if err != nil {
		st.Rev = prev
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		st.Rev = prev
		return errStale
	}
	return nil
}

// Status 给控制台与排查看的当前状态
func (r *Runner) Status(ctx context.Context) (*State, error) { return r.load(ctx) }
