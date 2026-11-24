package hostimport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"openxdr/server/internal/triage"
	"os"
	"strings"
	"testing"
	"time"
)

func analysisService(t *testing.T, output, finish string) *Service {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if _, ok := body["tools"]; ok {
			t.Error("文档解析不应注册工具")
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": output}, "finish_reason": finish}}})
	}))
	t.Cleanup(server.Close)
	vault, _ := NewVault(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	return &Service{Vault: vault, LLM: triage.NewLLM(server.URL, "test", "", time.Second)}
}

const proseDocument = "交接：应用主机 app-prod 位于 192.0.2.10，Ubuntu。\nSSH 登录用户 ops，密码是 doc-only-secret。"
const extractedResult = `{"hosts":[{"hostname":"app-prod","address":"192.0.2.10","os":"linux","port":0,"username":"ops","password":"doc-only-secret","lines":[1,2]}]}`

func TestAnalyzeProseConfirmSnapshot(t *testing.T) {
	s := analysisService(t, extractedResult, "stop")
	preview, err := s.AnalyzeDocument(context.Background(), Document{Text: proseDocument}, "owner", "group")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(preview)
	if strings.Contains(string(raw), "doc-only-secret") {
		t.Fatal("预览回显了凭据")
	}
	if len(preview.Hosts) != 1 || !preview.Hosts[0].NeedsReview || preview.Hosts[0].Port != 22 {
		t.Fatal("未标记默认端口")
	}
	preview.Hosts[0].Hostname = "corrected-name"
	s.LLM = nil
	hosts, err := s.ConfirmHosts(preview.Hosts, "owner", "group")
	if err != nil {
		t.Fatal(err)
	}
	if hosts[0].Hostname != "corrected-name" || hosts[0].Secret.Password != "doc-only-secret" {
		t.Fatal("确认未使用修正结果及原凭据")
	}
	for _, pair := range [][2]string{{"other", "group"}, {"owner", "other"}} {
		if _, err := s.ConfirmHosts(preview.Hosts, pair[0], pair[1]); err == nil {
			t.Fatal("跨身份解密成功")
		}
	}
	dup := append(preview.Hosts, preview.Hosts[0])
	dup[1].Hostname = "another"
	if _, err := s.ConfirmHosts(dup, "owner", "group"); err == nil {
		t.Fatal("接受重复凭据引用")
	}
	preview.Hosts[0].CredentialToken = ""
	hosts, err = s.ConfirmHosts(preview.Hosts, "owner", "group")
	if err != nil || hosts[0].Kind != "none" {
		t.Fatal("无法丢弃凭据")
	}
}
func TestAnalyzeRejectsIncompleteOrInventedCredentials(t *testing.T) {
	for _, test := range []struct{ output, finish string }{{extractedResult, "length"}, {extractedResult, ""}, {strings.ReplaceAll(extractedResult, "doc-only-secret", "invented-password"), "stop"}, {`{"hosts":`, "stop"}, {`{"hosts":[]}`, "stop"}, {`{"incomplete":true,"hosts":[{"address":"192.0.2.10"}]}`, "stop"}} {
		s := analysisService(t, test.output, test.finish)
		if _, err := s.AnalyzeDocument(context.Background(), Document{Text: proseDocument}, "owner", "group"); err == nil {
			t.Fatal("接受不完整或编造结果")
		}
	}
}
func TestPreviewExpiryAndValidation(t *testing.T) {
	s := analysisService(t, extractedResult, "stop")
	payload, _ := json.Marshal(map[string]any{"secret": Secret{Password: "test-secret"}, "expires": time.Now().Add(-time.Minute).Unix()})
	sealed, _ := s.Vault.sealBytes(payload, previewBinding("owner", "group"))
	row := ReviewHost{Host: Host{Hostname: "test", Address: "192.0.2.1", OS: "linux", Port: 22, Username: "ops"}, CredentialToken: base64.RawURLEncoding.EncodeToString(sealed)}
	if _, err := s.ConfirmHosts([]ReviewHost{row}, "owner", "group"); err == nil {
		t.Fatal("接受过期预览")
	}
	row.CredentialToken = ""
	row.OS = ""
	if _, err := s.ConfirmHosts([]ReviewHost{row}, "owner", "group"); err == nil {
		t.Fatal("静默猜测操作系统")
	}
	s.Vault = nil
	if _, err := s.AnalyzeDocument(context.Background(), Document{Text: proseDocument}, "owner", "group"); err == nil {
		t.Fatal("未配置密钥仍返回凭据引用")
	}
	s = analysisService(t, `{"hosts":[{"address":"192.0.2.10","os":"linux","port":22,"lines":[1]}]}`, "stop")
	s.Vault = nil
	if _, err := s.AnalyzeDocument(context.Background(), Document{Text: proseDocument}, "owner", "group"); err != nil {
		t.Fatal("无凭据文档不应要求密钥", err)
	}
}

func TestPreviewRedactsSecretMatchingMetadata(t *testing.T) {
	s := analysisService(t, strings.ReplaceAll(extractedResult, "doc-only-secret", "ops"), "stop")
	preview, err := s.AnalyzeDocument(context.Background(), Document{Text: strings.ReplaceAll(proseDocument, "doc-only-secret", "ops")}, "owner", "group")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Hosts[0].Username != "" || !preview.Hosts[0].NeedsReview {
		t.Fatal("用户名与密码相同应隐藏并允许补充")
	}
	preview.Hosts[0].Username = "ops"
	hosts, err := s.ConfirmHosts(preview.Hosts, "owner", "group")
	if err != nil || hosts[0].Secret.Password != "ops" {
		t.Fatal("人工补充后无法保存", err)
	}
}

func TestAnalyzeVisionOriginalImage(t *testing.T) {
	data, err := os.ReadFile("testdata/handoff.png")
	if err != nil {
		t.Fatal(err)
	}
	img, err := documentImage("交接截图", data)
	if err != nil {
		t.Fatal(err)
	}
	output := strings.Replace(extractedResult, `"lines":[1,2]`, `"images":[1]`, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model    string
			Messages []struct{ Content json.RawMessage }
			Tools    json.RawMessage
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		var parts []triage.ContentPart
		if len(req.Messages) != 2 || json.Unmarshal(req.Messages[1].Content, &parts) != nil {
			t.Fatal("未发送多模态内容")
		}
		if req.Model != "vision" || len(parts) != 3 || parts[2].ImageURL == nil || parts[2].ImageURL.URL != img.DataURL || len(req.Tools) > 0 {
			t.Error("模型、原图或工具边界错误")
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": output}, "finish_reason": "stop"}}})
	}))
	defer server.Close()
	vault, _ := NewVault(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	s := &Service{Vault: vault, VisionLLM: triage.NewLLM(server.URL, "vision", "", time.Second)}
	doc := Document{Images: []DocumentImage{img}}
	result, err := s.AnalyzeDocument(context.Background(), doc, "owner", "group")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Hosts[0].NeedsReview || len(result.Hosts[0].Images) != 1 {
		t.Fatal("视觉结果未要求核对")
	}
	hosts, err := s.ConfirmHosts(result.Hosts, "owner", "group")
	if err != nil || hosts[0].Secret.Password != "doc-only-secret" {
		t.Fatal("视觉凭据未保存", err)
	}
	for _, refs := range []string{`"images":[]`, `"images":[2]`} {
		output = strings.Replace(output, `"images":[1]`, refs, 1)
		if _, err := s.AnalyzeDocument(context.Background(), doc, "owner", "group"); err == nil {
			t.Fatal("缺少有效图像证据仍接受凭据")
		}
		output = strings.Replace(extractedResult, `"lines":[1,2]`, `"images":[1]`, 1)
	}
}
