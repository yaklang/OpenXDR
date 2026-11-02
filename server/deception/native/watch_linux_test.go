//go:build linux

package native

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestFileOpenWatch(t *testing.T) {
	m := manifest("file", "decoy")
	f, err := InstallFile(adminRoot(t), m)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Remove()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan string, 8)
	done := make(chan error, 1)
	go func() { done <- WatchFile(ctx, f.Path, func(kind string) error { events <- kind; return nil }) }()
	select {
	case event := <-events:
		if event != "file_installed" {
			t.Fatal(event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("监视未启动")
	}
	file, err := os.Open(f.Path)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	select {
	case event := <-events:
		if event != "file_opened" {
			t.Fatal(event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("没有捕获打开")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("监视未停止")
	}
}
