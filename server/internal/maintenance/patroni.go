package maintenance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/containment"
)

// Patroni 重启平台节点前把数据库主节点平滑交出去：计划内切换只停顿几秒，
// 直接重启主节点要等 Patroni 判定失联再选主，平台会写不进库好几分钟（2026-11-10 node1 重启时诱饵因此停掉）
type Patroni struct {
	Port           int
	User, Password string
	HTTP           *http.Client
	// Addrs 节点的 Patroni 接口地址（scheme://host:port），缺省按资产登记的内网 IPv4 与 Port 拼
	Addrs func(*ent.Asset) []string
}

type member struct {
	addr string
	name string
	role string
}

func (p *Patroni) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (p *Patroni) addrs(a *ent.Asset) []string {
	if p.Addrs != nil {
		return p.Addrs(a)
	}
	var out []string
	for _, s := range a.IPAddrs {
		ip, err := netip.ParseAddr(s)
		// docker 网桥（172.16/12）上没有 Patroni 接口，只试其余的内网 IPv4
		if err != nil || !ip.Is4() || !ip.IsPrivate() || netip.MustParsePrefix("172.16.0.0/12").Contains(ip) {
			continue
		}
		out = append(out, fmt.Sprintf("http://%s:%d", ip, p.Port))
	}
	return out
}

// member 节点上 Patroni 的名字与角色。登记的地址里可能有高可用虚拟地址（指向当时持有它的那台），
// 所以成员名与主机名一致的才采信；都对不上时，只有所有应答都来自同一个成员才用它，说不清就报错
func (p *Patroni) member(ctx context.Context, a *ent.Asset) (*member, error) {
	var answers []*member
	for _, addr := range p.addrs(a) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, addr+"/patroni", nil)
		resp, err := p.client().Do(req)
		if err != nil {
			continue
		}
		var body struct {
			Role    string `json:"role"`
			Patroni struct {
				Name string `json:"name"`
			} `json:"patroni"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body)
		resp.Body.Close()
		if err != nil || body.Patroni.Name == "" {
			continue
		}
		m := &member{addr: addr, name: body.Patroni.Name, role: body.Role}
		if m.name == a.Hostname {
			return m, nil
		}
		answers = append(answers, m)
	}
	if len(answers) == 0 {
		return nil, fmt.Errorf("读不到 %s 的 Patroni 状态", a.Hostname)
	}
	for _, m := range answers[1:] {
		if m.name != answers[0].name {
			return nil, fmt.Errorf("%s 的地址上应答的 Patroni 成员不一致，说不清哪个是它", a.Hostname)
		}
	}
	return answers[0], nil
}

func primary(role string) bool { return role == "primary" || role == "master" }

// healthyReplica GET /replica 只在从节点运行正常、复制延迟在阈值内时返回 200
func (p *Patroni) healthyReplica(ctx context.Context, m *member) bool {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, m.addr+"/replica", nil)
	resp, err := p.client().Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// handoff 要重启的平台节点是数据库主节点时，先计划内切换到健康的另一台，等它变成从节点。
// 没有健康的从节点、切换失败或超时都返回错误，调用方据此停手、不重启
func (r *Runner) handoff(ctx context.Context, a *ent.Asset) error {
	p := r.Config.Patroni
	if p == nil {
		return nil
	}
	self, err := p.member(ctx, a)
	if err != nil {
		return err
	}
	if !primary(self.role) {
		return nil
	}
	peers, err := r.DB.Asset.Query().Where(asset.IDNEQ(a.ID), asset.RetiredAtIsNil()).All(ctx)
	if err != nil {
		return err
	}
	var candidate *member
	for _, peer := range peers {
		if !containment.RunsServer(peer) {
			continue
		}
		if m, err := p.member(ctx, peer); err == nil && !primary(m.role) && p.healthyReplica(ctx, m) {
			candidate = m
			break
		}
	}
	if candidate == nil {
		return fmt.Errorf("%s 是数据库主节点，但另一台平台节点不是健康的从节点，不切换也不重启", a.Hostname)
	}
	body, _ := json.Marshal(map[string]string{"leader": self.name, "candidate": candidate.name})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, self.addr+"/switchover", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(p.User, p.Password)
	resp, err := p.client().Do(req)
	if err != nil {
		return errors.New("发起数据库主节点切换失败")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("数据库主节点切换被拒绝（HTTP %d）", resp.StatusCode)
	}
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.pollInterval()):
		}
		if m, err := p.member(ctx, a); err == nil && !primary(m.role) {
			r.audit(ctx, "maintenance_switchover", a.ID.String(), fmt.Sprintf("重启 %s 前把数据库主节点切到 %s", a.Hostname, candidate.name))
			return nil
		}
	}
	return fmt.Errorf("数据库主节点切换后 90 秒 %s 仍是主节点", a.Hostname)
}
