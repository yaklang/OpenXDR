package native

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/google/uuid"
)

// InstalledFile 持有目录描述符；只创建独占目录里的固定文件，清理前核对内容。
type InstalledFile struct {
	root            *os.Root
	directory, name string
	data            []byte
	Path            string
}

func InstallFile(rootPath string, m Manifest) (*InstalledFile, error) {
	if _, err := uuid.Parse(m.ID); err != nil {
		return nil, err
	}
	if m.Kind != "file" || filepath.Base(m.Resource) != m.Resource || len(m.Resource) > 128 || !strings.HasSuffix(m.Resource, ".md") || strings.ContainsAny(m.Resource, "\\:\x00") || strings.IndexFunc(m.Resource, unicode.IsControl) >= 0 {
		return nil, fmt.Errorf("文件诱饵配置无效")
	}
	text, err := Text(m.Kind, m.Profile, m.Marker)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	// 清理前的内容核对依赖父目录外人不可写，否则可被换成别的文件骗删。
	if info, err := root.Stat("."); err != nil || info.Mode().Perm()&0022 != 0 {
		root.Close()
		return nil, fmt.Errorf("诱饵父目录不能允许属组或其他用户写入")
	}
	// 目录名不带 decoy 字样，避免来访者一眼识破。
	dir := "archive-" + m.ID
	if err = root.Mkdir(dir, 0755); err != nil {
		root.Close()
		return nil, fmt.Errorf("诱饵目录必须不存在: %w", err)
	}
	name := dir + "/" + m.Resource
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		root.Remove(dir)
		root.Close()
		return nil, err
	}
	data := []byte("# 维护归档\n\n" + text + "\n")
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		root.Remove(name)
		root.Remove(dir)
		root.Close()
		return nil, err
	}
	return &InstalledFile{root: root, directory: dir, name: name, data: data, Path: filepath.Join(rootPath, dir, m.Resource)}, nil
}
func (f *InstalledFile) Remove() error {
	defer f.root.Close()
	info, err := f.root.Lstat(f.name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("诱饵文件类型已变化，保留现场")
	}
	file, err := f.root.Open(f.name)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(len(f.data)+1)))
	file.Close()
	if err != nil {
		return err
	}
	if !bytes.Equal(data, f.data) {
		return fmt.Errorf("诱饵文件已变化，保留现场，不删除")
	}
	if err = f.root.Remove(f.name); err != nil {
		return err
	}
	return f.root.Remove(f.directory)
}
