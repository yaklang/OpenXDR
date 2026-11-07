// Package customrule 控制台维护的自定义 Sigma 规则：存 custom_rules 表，各节点周期读取，
// 内容变了就整体重编译并原子替换 sigma.Overlay 的自定义层。
package customrule

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/customrule"
	"openxdr/server/internal/sigma"
)

type Loader struct {
	DB    *ent.Client
	Rules *sigma.Overlay

	mu          sync.Mutex
	fingerprint string
	failed      map[string]string
}

// Reload 读出启用的规则，内容没变就不动；读库失败保留当前已加载的规则。
func (l *Loader) Reload(ctx context.Context) error {
	rows, err := l.DB.CustomRule.Query().Where(customrule.Enabled(true)).All(ctx)
	if err != nil {
		return err
	}
	sources := make(map[string]string, len(rows))
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		sources[r.ID] = r.Content
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	h := sha256.New()
	for _, id := range ids {
		fmt.Fprintf(h, "%s\x00%s\x00", id, sources[id])
	}
	fp := fmt.Sprintf("%x", h.Sum(nil))

	l.mu.Lock()
	defer l.mu.Unlock()
	if fp == l.fingerprint {
		return nil
	}
	errs := l.Rules.SetCustom(sources)
	failed := make(map[string]string, len(errs))
	for id, err := range errs {
		failed[id] = err.Error()
		slog.Warn("自定义规则加载失败", "id", id, "err", err)
	}
	l.fingerprint, l.failed = fp, failed
	slog.Info("自定义规则已加载", "loaded", len(sources)-len(failed), "failed", len(failed))
	return nil
}

// Run 各节点都跑：每个节点各自求值，都要拿到最新规则。
func (l *Loader) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := l.Reload(ctx); err != nil && ctx.Err() == nil {
				slog.Error("读取自定义规则失败，保留当前规则", "err", err)
			}
		}
	}
}

// Failed 本节点上次加载失败的规则与原因（规则目录升级后旧写法不再支持时会出现）
func (l *Loader) Failed() map[string]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]string, len(l.failed))
	for id, why := range l.failed {
		out[id] = why
	}
	return out
}
