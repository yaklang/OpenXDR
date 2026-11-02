package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"openxdr/server/deception/contract"
	"time"
)

const LeaseTTL = 90 * time.Second

// Acquire 在绑定端口或创建文件前申请独占租约；不可将租约当成主机身份的远程证明。
func (c *Client) Acquire(ctx context.Context) error {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if c.leaseState != "" {
		return fmt.Errorf("此客户端已申请过运行租约")
	}
	if err := c.sendLease(ctx, "starting"); err != nil {
		return err
	}
	c.leaseState = "starting"
	return nil
}
func (c *Client) Ready(ctx context.Context) error {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if c.leaseState == "running" {
		return nil
	}
	if c.leaseState != "starting" {
		return fmt.Errorf("未持有启动租约")
	}
	if err := c.sendLease(ctx, "running"); err != nil {
		return err
	}
	c.leaseState = "running"
	return nil
}
func (c *Client) Heartbeat(ctx context.Context) error {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if c.leaseState != "starting" && c.leaseState != "running" {
		return fmt.Errorf("未持有运行租约")
	}
	return c.sendLease(ctx, c.leaseState)
}
func (c *Client) Finish(ctx context.Context, failed bool) error {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if c.leaseState == "" {
		return nil
	}
	state := "stopped"
	if failed {
		state = "failed"
	}
	if err := c.sendLease(ctx, state); err != nil {
		return err
	}
	c.leaseState = state
	return nil
}
func (c *Client) sendLease(ctx context.Context, state string) error {
	body, _ := json.Marshal(map[string]string{"instance": c.instance, "state": state})
	path := "/lease"
	if c.managed && state == "starting" {
		c.configMu.RLock()
		rev := c.revision
		c.configMu.RUnlock()
		body, _ = json.Marshal(contract.Handshake{Instance: c.instance, Revision: rev, Release: c.release})
		path = "/handshake"
	}
	var err error
	// 同一实例与状态重复提交是幂等的，提交成功后连接丢失可重试。
	for range 2 {
		if _, err = c.call(ctx, "POST", path, body); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return err
}
