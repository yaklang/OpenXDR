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

#[cfg(any(windows, test))]
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

/// 校验 Windows 目标文件路径：必须是绝对路径，拒绝控制字符、Unicode 换行与 `..` 路径穿越段
#[cfg(any(windows, test))]
fn validate_target(raw: &str) -> Result<&str, String> {
    let target = raw.trim();
    if target.is_empty() {
        return Err("文件路径无效".into());
    }
    if target
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{0085}' | '\u{2028}' | '\u{2029}'))
    {
        return Err("文件路径包含非法控制字符或换行符".into());
    }
    let bytes = target.as_bytes();
    let is_drive_abs = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    let is_unc_abs = target.strip_prefix(r"\\").is_some_and(|rest| {
        let mut parts = rest.split(['\\', '/']).filter(|s| !s.is_empty());
        parts.next().is_some() && parts.next().is_some()
    });
    if !is_drive_abs && !is_unc_abs {
        return Err("文件路径必须是绝对路径".into());
    }
    if target.split(['\\', '/']).any(|seg| seg == "..") {
        return Err("文件路径不允许包含 .. 路径段".into());
    }
    Ok(target)
}

#[cfg(windows)]
fn run(cmd: &Command, block: bool) -> Outcome {
    let target = match validate_target(&cmd.target) {
        Ok(t) => t,
        Err(e) => return Outcome::failed(e),
    };
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

/// PowerShell 5.1 单引号字符串：ASCII `'` 与被 PS 5.1 词法器视作单引号的 Unicode 弯引号均双写转义
#[cfg(test)]
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// 标准 Base64 编码：只输出 `[A-Za-z0-9+/=]`，绝不会触发 PowerShell 词法器的任何引号或换行解析
#[cfg(any(windows, test))]
fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// 生成 PowerShell UTF-8 Base64 还原表达式，彻底杜绝引号逃逸
#[cfg(any(windows, test))]
fn ps_utf8(s: &str) -> String {
    format!(
        "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}'))",
        encode_base64(s.as_bytes())
    )
}

#[cfg(any(windows, test))]
fn script(target: &str, state: &str, block: bool) -> String {
    let action = if block { "block" } else { "unblock" };
    format!(
        r#"[Console]::OutputEncoding = [Text.Encoding]::UTF8
$Target = [IO.Path]::GetFullPath({target}); $State = [IO.Path]::GetFullPath({state}); $Action = '{action}'; $Id = '{POLICY_ID}'
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
        target = ps_utf8(target),
        state = ps_utf8(state),
    )
}

#[cfg(all(target_os = "linux", feature = "execblock"))]
fn run(cmd: &Command, block: bool) -> Outcome {
    super::execblock_linux::run(cmd.target.trim(), block)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_base64(input: &str) -> Vec<u8> {
        let val = |b: u8| match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        };
        let bytes = input.as_bytes();
        let (chunks, rem) = bytes.as_chunks::<4>();
        assert!(rem.is_empty());
        let mut out = Vec::new();
        for chunk in chunks {
            let a = val(chunk[0]).unwrap() as u32;
            let b = val(chunk[1]).unwrap() as u32;
            let c = if chunk[2] == b'=' {
                0
            } else {
                val(chunk[2]).unwrap() as u32
            };
            let d = if chunk[3] == b'=' {
                0
            } else {
                val(chunk[3]).unwrap() as u32
            };
            let n = (a << 18) | (b << 12) | (c << 6) | d;
            out.push(((n >> 16) & 0xff) as u8);
            if chunk[2] != b'=' {
                out.push(((n >> 8) & 0xff) as u8);
            }
            if chunk[3] != b'=' {
                out.push((n & 0xff) as u8);
            }
        }
        out
    }

    #[test]
    fn single_quotes_and_unicode_quotes_are_doubled() {
        assert_eq!(quote(r"C:\a'b\c.exe"), r"'C:\a''b\c.exe'");
        assert_eq!(
            quote("C:\\a\u{2018}\u{2019}\u{201A}\u{201B}\\c.exe"),
            "'C:\\a\u{2018}\u{2018}\u{2019}\u{2019}\u{201A}\u{201A}\u{201B}\u{201B}\\c.exe'"
        );
    }

    #[test]
    fn validates_windows_absolute_paths_and_rejects_traversal_and_controls() {
        assert_eq!(
            validate_target(r"  C:\Users\a\evil.exe  ").unwrap(),
            r"C:\Users\a\evil.exe"
        );
        assert_eq!(
            validate_target(r"D:/tools/x.exe").unwrap(),
            r"D:/tools/x.exe"
        );
        assert_eq!(
            validate_target(r"\\srv\share\x.exe").unwrap(),
            r"\\srv\share\x.exe"
        );
        for bad in [
            "",
            "   ",
            "relative.exe",
            r".\evil.exe",
            r"\rootonly.exe",
            r"C:rel.exe",
            r"C:\Users\..\Windows\cmd.exe",
            "C:/Users/../Windows/cmd.exe",
            "C:\\a\\b\n; calc.exe",
            "C:\\a\\b\r; calc.exe",
            "C:\\a\\b\0.exe",
            "C:\\a\\b\u{0085}; calc.exe",
            "C:\\a\\b\u{2028}; calc.exe",
            "C:\\a\\b\u{2029}; calc.exe",
        ] {
            assert!(validate_target(bad).is_err(), "{bad:?} 应被拒绝");
        }
    }

    #[test]
    fn script_uses_base64_and_getfullpath_against_curly_quote_injection() {
        // PowerShell 5.1 会把 Unicode 弯引号 ’ (\u{2019}) 当成单引号，借此闭合字面量注入命令
        let payload = "C:\\Users\\test\\a\u{2019}; calc.exe; \u{2018}.exe";
        let state = r"C:\ProgramData\OpenXDR\exec-block.xml";
        assert!(validate_target(payload).is_ok());

        let ps = script(payload, state, true);
        assert!(
            !ps.contains('\u{2019}') && !ps.contains('\u{2018}') && !ps.contains("calc.exe"),
            "脚本中绝不能出现原始弯引号或注入载荷：{ps}"
        );
        assert!(
            ps.contains("$Target = [IO.Path]::GetFullPath([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"),
            "应通过 Base64 UTF-8 还原并用 GetFullPath 规范化"
        );
        assert!(
            ps.contains("$State = [IO.Path]::GetFullPath([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('")
        );

        // 验证 Base64 编码还原后与原始 UTF-8 完全一致
        let b64 = encode_base64(payload.as_bytes());
        assert!(ps.contains(&b64));
        assert_eq!(String::from_utf8(decode_base64(&b64)).unwrap(), payload);

        let b64_state = encode_base64(state.as_bytes());
        assert!(ps.contains(&b64_state));
        assert_eq!(String::from_utf8(decode_base64(&b64_state)).unwrap(), state);
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
