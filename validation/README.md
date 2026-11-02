# 检测验证语料

把攻击手法的**真实命令行**归一化成本平台的事件格式，回放过规则引擎，
验证"规则到底能不能抓住 Atomic Red Team 实际执行的那条命令"。

```bash
cd server && go run ./cmd/detectcheck            # 出报告
cd server && go run ./cmd/detectcheck --strict   # 有未达预期用例则非零退出（CI 用）
```

## 这个东西验证什么、不验证什么

**验证**：规则的匹配逻辑对真实命令有效；ATT&CK 标注与实际检出一致。

**不验证**：采集端能否看见这个动作。合成回放绕过了采集层——
`vssadmin delete shadows` 的语料能过，不代表 ETW 真的报了这条进程事件。
那部分由实机回放覆盖：见 [replay/](replay/README.md)（脚本 + 各系统×
采集路径验证矩阵）。

AI 研判的证据与建议质量另见 [研判证据回归](triage/README.md)，不与规则检出率混算。

## 判定标准

命中的规则**必须标了该技术**。只要"有规则响了"就算过，ATT&CK 标注错了
也发现不了，覆盖矩阵就会开始骗人。

## 用例格式

```yaml
technique: T1490          # 文件级默认技术
name: Inhibit System Recovery
cases:
  - name: vssadmin 删除全部卷影
    technique: T1490      # 可选，覆盖文件级默认
    source: atomic T1490  # 手法出处
    class: 1007           # OCSF class：1001 文件 / 1007 进程 / 3002 认证 /
                          # 4001 网络 / 4003 DNS / 201002 注册表 / 100001 日志
    os: windows           # 资产 OS，留空表示不限
    event:                # 事件体，与采集端产出的结构一致
      process:
        name: vssadmin.exe
        file:
          path: "C:\\Windows\\System32\\vssadmin.exe"
        cmd_line: "vssadmin.exe delete shadows /all /quiet"
    expect: detected      # 默认 detected；undetected = 已知缺口，显式记录；signal = 仅信号规则命中
```

`level`（可选）：命中规则里的**最高级别**必须正好是它（informational / low / medium / high / critical）。
降噪只降级不删除时，维护动作的良性对照写 `level: low`，同类劫持写 `level: high`——只看"有没有响"守不住分级。

`expect: undetected` 有两个用途：记录尚未覆盖的手法，
以及**良性对照**——`sh -c 'echo hello'` 这类正常命令必须不告警，
它变成"命中"同样是回归。

`expect: signal`：没有告警规则命中，但有标了该技术的**信号规则**（`rules/signals/`，`openxdr_signal: true`）命中。
信号规则不单独告警，只供时序规则关联（如脚本内 `curl … | bash` 的两个兄弟进程，见 `temporal-rules/README.md`）；
链路本身由 `validation/temporal/` 回放验证。实际结果与 expect 三选一不符都算不符合预期。

## 加用例的原则

命令行要抄真实的手法过程，不要自己编一条"应该能匹配"的。
这个语料库唯一的价值就是它比规则作者更诚实。

## 其他验证入口

[控制台离线浏览器回归](web/README.md)验证构建后的前端交互，与本目录的检测语料回放分别运行、分别验收。
