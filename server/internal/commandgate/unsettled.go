package commandgate

import (
	"context"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	entcommand "openxdr/server/ent/command"
)

// UnsettledWindow 回执悬而未决的写指令挡住同主机新修复与结案的时长。指令超时上限 5 分钟，指令只经内存通道下发、
// 不会从库里重投，过了这个窗口它不可能还在执行；之后的修复照旧先取只读探针，不靠这条旧回执判断现状。
const UnsettledWindow = 24 * time.Hour

// UnsettledWrite 主机上窗口内回执未落定（pending / sent / unknown）的写指令，没有返回 nil
func UnsettledWrite(ctx context.Context, c *ent.CommandClient, asset uuid.UUID, now time.Time) (*ent.Command, error) {
	rows, err := c.Query().Where(entcommand.AssetIDEQ(asset), entcommand.StatusIn("pending", "sent", "unknown"),
		entcommand.CreatedAtGT(now.Add(-UnsettledWindow))).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Kind != "exec" || row.Cmd == nil || !ReadOnly(*row.Cmd) {
			return row, nil
		}
	}
	return nil, nil
}
