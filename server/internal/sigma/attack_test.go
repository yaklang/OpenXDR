package sigma

import "testing"

func TestParseAttackTags(t *testing.T) {
	tactics, techniques := parseAttackTags([]any{
		"attack.execution",
		"attack.defense_evasion",
		"attack.t1059.001",
		"attack.T1027",
		"attack.g0016", // 组织标签，与覆盖无关
		"cve.2021-44228",
		"attack.not_a_tactic",
		"attack.execution", // 重复
	})

	if len(tactics) != 2 || tactics[0] != "execution" || tactics[1] != "defense-evasion" {
		t.Errorf("战术解析不对：%v", tactics)
	}
	if len(techniques) != 2 || techniques[0] != "T1027" || techniques[1] != "T1059.001" {
		t.Errorf("技术解析不对：%v", techniques)
	}
}

func TestParseAttackTagsEmpty(t *testing.T) {
	tactics, techniques := parseAttackTags(nil)
	if tactics != nil || techniques != nil {
		t.Errorf("无 tags 应返回空：%v %v", tactics, techniques)
	}
	// 非列表（写成字符串）也不能崩
	if _, _, ok := func() ([]string, []string, bool) {
		a, b := parseAttackTags("attack.execution")
		return a, b, true
	}(); !ok {
		t.Error("非列表 tags 应安全忽略")
	}
}
