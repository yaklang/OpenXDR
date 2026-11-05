// Package findings 运维待办的人工状态变更：控制台待办页与对话里代人忽略共用同一套校验、落库与审计。
package findings

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"openxdr/server/ent"
	"openxdr/server/internal/audit"
)

// Clean 校验人工设定的状态与原因，返回去掉首尾空白的原因。
// 已处理与忽略必须写原因：忽略原因会交给巡检 AI，已处理的下一轮仍会复查。
func Clean(status, note string) (string, error) {
	if !slices.Contains([]string{"open", "resolved", "ignored"}, status) {
		return "", errors.New("status 必须是 open / resolved / ignored")
	}
	note = strings.TrimSpace(note)
	if status != "open" && (note == "" || utf8.RuneCountInString(note) > 2000) {
		return "", errors.New("须写明原因（1–2000 字）")
	}
	return note, nil
}

// Set 以 username 的名义把待办改成 status（note 须先经 Clean），同一事务写审计 finding_status。
// via 非空时追加在审计说明后，记下操作经由哪里（如代人执行的 AI 会话）。
func Set(ctx context.Context, db *ent.Client, f *ent.Finding, status, note, username, remote, via string) error {
	tx, err := db.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	u := tx.Finding.UpdateOneID(f.ID).SetStatus(status)
	if status == "open" {
		u.ClearResolvedAt().ClearResolvedBy().ClearNote().SetWorkOwner("ai").SetWorkAttempts(0).SetWorkNextCheckAt(time.Now()).ClearWorkSessionID().ClearWorkLeaseUntil().SetWork(EncodeWork(Work{Stage: "waiting", Plan: "人工重新打开，重新评估现状", WakeOn: "next_check"}))
	} else {
		u.SetResolvedAt(time.Now()).SetResolvedBy(username).SetNote(note).ClearWorkSessionID().ClearWorkLeaseUntil().ClearWorkNextCheckAt().SetWork(EncodeWork(Work{Stage: status, Plan: note, WakeOn: "human_reopen"}))
	}
	if err := u.Exec(ctx); err != nil {
		return err
	}
	detail := strings.TrimSpace(status + " " + note)
	if via != "" {
		detail += "（" + via + "）"
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), username, remote, "finding_status", f.Title, detail); err != nil {
		return err
	}
	return tx.Commit()
}
