package closurereview

import (
	"testing"
)

func TestMissingSubjectKeyPrefixCompletion(t *testing.T) {
	const (
		fpRoyal = "SHA256:mtwVQQEIr75wGTFfVAuMn6y/LsfD5ULsqChRXqfXqJY"
		fpSameP = "SHA256:mtwVQQBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		fpOther = "SHA256:SQfC+vTbLURn9cTkVxIS8fGQ3FKNAJWeB0o139+gV4M"
	)

	// 材料中同一完整指纹在原始事件与权威事实里重复出现，且研判摘要里还出现了缩写形式，去重后仍应唯一命中完整指纹。
	singleKeyMaterial := `{"verdict":{"summary":"公钥 SHA256:mtwVQQEIr75wGTFfVAuMn… 未登记"},"events":[{"raw":{"login_session":{"key_fp":"` + fpRoyal + `"}}}],"authoritative":"登录公钥 ` + fpRoyal + ` 暂无归属","blob":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
	ambiguousMaterial := `{"events":[{"raw":{"login_session":{"key_fp":"` + fpRoyal + `"}}},{"raw":{"login_session":{"key_fp":"` + fpSameP + `"}}},{"raw":{"login_session":{"key_fp":"` + fpOther + `"}}}]}`

	cases := []struct {
		name     string
		subject  string
		material string
		want     string
		ok       bool
	}{
		{
			name:     "完整指纹精确命中",
			subject:  fpRoyal,
			material: singleKeyMaterial,
			want:     fpRoyal,
			ok:       true,
		},
		{
			name:     "Unicode省略号缩写唯一命中",
			subject:  "SHA256:mtwVQQ…",
			material: singleKeyMaterial,
			want:     fpRoyal,
			ok:       true,
		},
		{
			name:     "ASCII三点省略号缩写唯一命中",
			subject:  "SHA256:mtwVQQEIr75w...",
			material: singleKeyMaterial,
			want:     fpRoyal,
			ok:       true,
		},
		{
			name:     "无省略号超过20位截断前缀仍补全为43位完整指纹",
			subject:  "SHA256:mtwVQQEIr75wGTFfVAuMn6y",
			material: singleKeyMaterial,
			want:     fpRoyal,
			ok:       true,
		},
		{
			name:     "多钥匙材料中较长前缀唯一区分",
			subject:  "SHA256:mtwVQQEI…",
			material: ambiguousMaterial,
			want:     fpRoyal,
			ok:       true,
		},
		{
			name:     "多钥匙共享前缀时丢弃",
			subject:  "SHA256:mtwVQQ…",
			material: ambiguousMaterial,
			want:     "",
			ok:       false,
		},
		{
			name:     "零命中时丢弃",
			subject:  "SHA256:NcQW5H…",
			material: singleKeyMaterial,
			want:     "",
			ok:       false,
		},
		{
			name:     "裸SHA256加省略号无有效前缀丢弃",
			subject:  "SHA256:…",
			material: singleKeyMaterial,
			want:     "",
			ok:       false,
		},
		{
			name:     "Base64大小写不匹配时丢弃",
			subject:  "SHA256:mtwvqq…",
			material: singleKeyMaterial,
			want:     "",
			ok:       false,
		},
		{
			name:     "完整指纹不在材料中丢弃",
			subject:  fpOther,
			material: singleKeyMaterial,
			want:     "",
			ok:       false,
		},
	}

	m := &material{Benign: &benignEvidence{}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := missingSubject(MissingFact{Kind: "owner", SubjectKind: "key", Subject: tc.subject}, m, tc.material)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("missingSubject(%q) = (%q, %v), want (%q, %v)", tc.subject, got, ok, tc.want, tc.ok)
			}
		})
	}
}
