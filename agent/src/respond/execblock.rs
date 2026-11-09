//! 禁止执行：Linux 实现见 execblock_linux；下文为 Windows。
//! Windows：用系统自带的 WDAC（App Control for Business）按文件内容（Authenticode 与页哈希）拒绝执行。
//! 内核的代码完整性模块执行拦截，不需要自研驱动或证书；策略编译后放进 CiPolicies\Active，经 WMI 刷新免重启生效
//! （Windows 10 1903 起、Server 2019 起都有这个刷新接口，Win11 的 CiTool 不是必需）。
//!
//! 本机只维护一份 OpenXDR 自己的基础策略：「允许全部」加上拦截过的文件的拒绝规则。WDAC 的多个基础策略取交集，
//! 这份策略单独不会挡住任何别的程序；解除时把对应规则删掉再刷新，不删策略本身（老系统卸载策略要重启）。
//!
//! 按内容拦截意味着同一份内容的所有拷贝一起被拦，所以有有效数字签名的文件一律拒绝：系统程序与正规厂商的软件
//! 都有签名，攻击者拿 powershell.exe、certutil.exe 这类自带程序干活时，按哈希拦它就是把主机的系统程序封掉了。

use super::Outcome;
use crate::pb::Command;

#[cfg(windows)]
const POLICY_ID: &str = "{A61AFF97-CF54-413D-875E-3E204EA34241}";

pub fn block(cmd: &Command) -> Outcome {
    run(cmd, true)
}

pub fn unblock(cmd: &Command) -> Outcome {
    run(cmd, false)
}

#[cfg(not(any(windows, all(target_os = "linux", feature = "execblock"))))]
fn run(_cmd: &Command, _block: bool) -> Outcome {
    Outcome::unsupported("当前构建不支持执行拦截；Linux 需要 execblock 特性与 BPF LSM/IMA 内核支持")
}

#[cfg(windows)]
fn run(cmd: &Command, block: bool) -> Outcome {
    let target = cmd.target.trim();
    if target.is_empty() || target.contains(['\0', '\n', '\r']) {
        return Outcome::failed("文件路径无效");
    }
    let state = crate::enroll::default_env_file().with_file_name("exec-block.xml");
    let script = script(target, &state.to_string_lossy(), block);
    match super::powershell(&script) {
        Ok(out) => outcome(
            target,
            block,
            out.lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or(""),
        ),
        Err(e) => Outcome::failed(format!("WDAC 策略更新失败：{e}")),
    }
}

/// 把脚本最后一行的状态码翻成给人看的结果。脚本只输出机器可读的码，中文都在这里拼
#[cfg(any(windows, test))]
fn outcome(target: &str, block: bool, line: &str) -> Outcome {
    let (code, rest) = line.trim().split_once(' ').unwrap_or((line.trim(), ""));
    match code {
        "OK" if block => Outcome::ok(format!(
            "已禁止执行 {target}（同一内容的所有拷贝一起拦截），本机现有 {rest} 条拦截规则"
        )),
        "OK" => Outcome::ok(format!(
            "已解除对 {target} 的执行拦截，本机现有 {rest} 条拦截规则"
        )),
        "NONE" => Outcome::ok(format!("本机没有 {target} 的执行拦截")),
        "MISSING" => Outcome::failed(format!("文件不存在：{target}")),
        "SIGNED" => Outcome::failed(format!(
            "{target} 有有效数字签名（{rest}），系统或厂商程序不按哈希拦截：同一内容的所有拷贝都会被封掉"
        )),
        "NORULE" => Outcome::failed(format!("{target} 不是可执行文件，生成不了拦截规则")),
        "REFRESH" => Outcome::failed(format!(
            "策略已写入，但刷新失败（返回码 {rest}），重启后生效"
        )),
        _ => Outcome::failed(format!("WDAC 策略更新结果无法识别：{line}")),
    }
}

/// PowerShell 单引号字符串：内部的单引号写两遍
#[cfg(any(windows, test))]
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[cfg(windows)]
fn script(target: &str, state: &str, block: bool) -> String {
    let action = if block { "block" } else { "unblock" };
    format!(
        r#"[Console]::OutputEncoding = [Text.Encoding]::UTF8
$Target = {target}; $State = {state}; $Action = '{action}'; $Id = '{POLICY_ID}'
$Active = "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active\$Id.cip"
function Deny {{ @(([xml](Get-Content -LiteralPath $State)).SiPolicy.FileRules.Deny) | Where-Object {{ $_ }} }}
if ($Action -eq 'block') {{
    if (-not (Test-Path -LiteralPath $Target -PathType Leaf)) {{ 'MISSING'; return }}
    $sig = Get-AuthenticodeSignature -LiteralPath $Target
    if ($sig.Status -eq 'Valid') {{ 'SIGNED ' + $sig.SignerCertificate.Subject; return }}
    $rules = New-CIPolicyRule -DriverFilePath $Target -Level Hash -Deny -WarningAction SilentlyContinue
    if (-not $rules) {{ 'NORULE'; return }}
    if (-not (Test-Path -LiteralPath $State)) {{
        Copy-Item "$env:SystemRoot\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml" $State
    }}
    Merge-CIPolicy -PolicyPaths $State -OutputFilePath $State -Rules $rules | Out-Null
}} else {{
    if (-not (Test-Path -LiteralPath $State)) {{ 'NONE'; return }}
    $prefix = [Management.Automation.WildcardPattern]::Escape($Target) + ' Hash *'
    $ids = @(Deny | Where-Object {{ $_.FriendlyName -like $prefix }} | ForEach-Object {{ $_.ID }})
    if ($ids.Count -eq 0) {{ 'NONE'; return }}
    # -Id 只收单个
    foreach ($i in $ids) {{ Remove-CIPolicyRule -FilePath $State -Id $i }}
}}
# 固定策略 ID 与名称（合并会改写它们），去掉审核模式、允许免重启更新
$p = [xml](Get-Content -LiteralPath $State)
$p.SiPolicy.PolicyID = $Id; $p.SiPolicy.BasePolicyID = $Id; $p.Save($State)
Set-CIPolicyIdInfo -FilePath $State -PolicyName 'OpenXDR execution block'
Set-RuleOption -FilePath $State -Option 3 -Delete
Set-RuleOption -FilePath $State -Option 16
$cip = [IO.Path]::ChangeExtension($State, 'cip')
ConvertFrom-CIPolicy -XmlFilePath $State -BinaryFilePath $cip | Out-Null
Copy-Item -LiteralPath $cip $Active -Force
$r = Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{{ FilePath = $Active }}
if ($r.ReturnValue -ne 0) {{ 'REFRESH ' + $r.ReturnValue; return }}
'OK ' + @(Deny).Count
"#,
        target = quote(target),
        state = quote(state),
    )
}

#[cfg(all(target_os = "linux", feature = "execblock"))]
fn run(cmd: &Command, block: bool) -> Outcome {
    super::execblock_linux::run(cmd.target.trim(), block)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_quotes_are_doubled() {
        assert_eq!(quote(r"C:\a'b\c.exe"), r"'C:\a''b\c.exe'");
    }

    #[test]
    fn status_lines_become_outcomes() {
        use crate::pb::command_result::Status;
        let ok = outcome(r"C:\x.exe", true, "OK 4");
        assert_eq!(ok.status, Status::Succeeded);
        assert!(ok.detail.contains("4 条"), "{}", ok.detail);
        assert_eq!(
            outcome("x", false, "NONE").status,
            Status::Succeeded,
            "没有可解除的也算达成"
        );
        let signed = outcome("x", true, "SIGNED CN=Microsoft Windows");
        assert_eq!(signed.status, Status::Failed);
        assert!(signed.detail.contains("CN=Microsoft Windows"));
        assert_eq!(outcome("x", true, "MISSING").status, Status::Failed);
        assert_eq!(outcome("x", true, "garbage").status, Status::Failed);
    }

    /// 真机验证（管理员，会改本机的 WDAC 策略，用完只剩「允许全部」）：编一个无签名小程序，拦截后启动不了、
    /// 解除后又能跑；有微软签名的 notepad.exe 被签名闸门挡下。
    /// `cargo test --target x86_64-pc-windows-gnu --no-run` 后在目标机 `<测试程序> --ignored execblock --nocapture`
    #[cfg(windows)]
    #[test]
    #[ignore = "需要管理员的真 Windows，会改本机的 WDAC 策略"]
    fn blocks_and_unblocks_on_real_windows() {
        use crate::pb::command_result::Status;
        let dir = std::env::temp_dir().join("openxdr-execblock-test");
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("target.exe");
        super::super::powershell(&format!(
            "Add-Type -OutputAssembly {} -OutputType ConsoleApplication \
             -TypeDefinition 'public static class P {{ public static void Main() {{ }} }}'",
            quote(&exe.to_string_lossy())
        ))
        .unwrap();
        let runs = || {
            std::process::Command::new(&exe)
                .status()
                .is_ok_and(|s| s.success())
        };
        assert!(runs(), "拦截前应能运行");
        let cmd = Command {
            target: exe.to_string_lossy().into(),
            ..Default::default()
        };
        let r = block(&cmd);
        eprintln!("block: {}", r.detail);
        assert_eq!(r.status, Status::Succeeded);
        assert!(!runs(), "拦截后不应能运行");
        let r = unblock(&cmd);
        eprintln!("unblock: {}", r.detail);
        assert_eq!(r.status, Status::Succeeded);
        assert!(runs(), "解除后应恢复");
        let signed = block(&Command {
            target: r"C:\Windows\System32\notepad.exe".into(),
            ..Default::default()
        });
        eprintln!("signed: {}", signed.detail);
        assert_eq!(signed.status, Status::Failed);
        assert!(signed.detail.contains("数字签名"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(not(any(windows, all(target_os = "linux", feature = "execblock"))))]
    #[test]
    fn other_platforms_say_unsupported() {
        let r = block(&Command::default());
        assert_eq!(r.status, crate::pb::command_result::Status::Unsupported);
    }
}
