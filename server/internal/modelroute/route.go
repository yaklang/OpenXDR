// Package modelroute 定义只在服务端内存与可信 Pi 输入中传递的候选端点。
package modelroute

// Endpoint 绑定地址、凭据与模型，切换时必须整组替换，不能跨服务复用密钥。
type Endpoint struct {
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key"`
	Model   string `json:"model"`
}
