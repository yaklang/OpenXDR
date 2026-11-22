package aijob

import "testing"

func TestEncodeResultPreservesUnmarshalError(t *testing.T) {
	// 正常结构体与 map 应成功转为 map[string]any
	m, err := encodeResult(struct {
		OK bool `json:"ok"`
	}{OK: true})
	if err != nil || m["ok"] != true {
		t.Fatalf("正常结构体编码失败：m=%v err=%v", m, err)
	}

	// 可 Marshal 但不能 Unmarshal 成 map 的值（如切片、字符串、数字）必须返回非空 error，不能被 nil 覆盖
	for _, bad := range []any{[]string{"a", "b"}, "plain-string", 42} {
		if got, err := encodeResult(bad); err == nil {
			t.Errorf("非对象值 %#v 应返回反序列化错误，却得到 %v", bad, got)
		}
	}

	// 不可 Marshal 的值（如 chan）同样返回非空 error
	if _, err := encodeResult(make(chan int)); err == nil {
		t.Fatal("不可序列化值应返回错误")
	}
}
