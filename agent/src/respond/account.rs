//! 账号锁定：挡住指定本机账号的新登录，已有会话不动（要断开用结束进程或隔离主机）。
//!
//! Linux 用 `usermod -L -e 1`：只锁密码挡不住 SSH 公钥登录，账号过期经 PAM 账户检查后公钥也进不来。
//! Windows 停用本地账号；域账号要在域控上处理。root、Administrator 这类账号和 agent 自身运行的账号一律拒绝。

use super::Outcome;
use crate::pb::Command;

/// 账号名只收常见字符：它会进命令行参数
fn valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

const PROTECTED: [&str; 5] = [
    "root",
    "administrator",
    "system",
    "localsystem",
    "defaultaccount",
];

fn checked(cmd: &Command) -> Result<String, String> {
    let name = cmd.target.trim();
    if !valid(name) {
        return Err("账号名无效".into());
    }
    if PROTECTED.contains(&name.to_ascii_lowercase().as_str()) || platform::is_builtin_admin(name) {
        return Err(format!("{name} 是系统内置账号，锁定会让主机无法管理"));
    }
    if platform::is_self(name) {
        return Err(format!("{name} 是 agent 自身运行的账号"));
    }
    Ok(name.to_string())
}

pub fn disable(cmd: &Command) -> Outcome {
    let name = match checked(cmd) {
        Ok(n) => n,
        Err(e) => return Outcome::failed(format!("拒绝执行：{e}")),
    };
    match platform::disable(&name) {
        Ok(()) => Outcome::ok(format!(
            "已锁定账号 {name}，新登录（含公钥）会被拒绝；已有会话不受影响"
        )),
        Err(e) => Outcome::failed(format!("锁定 {name} 失败：{e}")),
    }
}

pub fn enable(cmd: &Command) -> Outcome {
    let name = match checked(cmd) {
        Ok(n) => n,
        Err(e) => return Outcome::failed(format!("拒绝执行：{e}")),
    };
    match platform::enable(&name) {
        Ok(note) => Outcome::ok(format!("已解锁账号 {name}{note}")),
        Err(e) => Outcome::failed(format!("解锁 {name} 失败：{e}")),
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::process::Command as Proc;

    fn run(args: &[&str]) -> Result<String, String> {
        let out = Proc::new("usermod")
            .args(args)
            .output()
            .map_err(|e| format!("无法执行 usermod: {e}"))?;
        if out.status.success() {
            Ok(String::new())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    pub fn is_builtin_admin(_: &str) -> bool {
        false
    }

    /// uid 0 的账号与 agent 自己的账号都不能锁
    pub fn is_self(name: &str) -> bool {
        // SAFETY: geteuid 无参数、总是成功，不读写任何内存。
        let uid = unsafe { libc::geteuid() };
        std::fs::read_to_string("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                Some((*f.first()?, f.get(2)?.parse::<u32>().ok()?))
            })
            .any(|(n, u)| n == name && (u == 0 || u == uid))
    }

    pub fn disable(name: &str) -> Result<(), String> {
        run(&["-L", "-e", "1", "--", name]).map(|_| ())
    }

    /// 原本没设密码的账号，usermod 只清掉过期、密码保持锁住（退出码仍为 0），公钥登录照常恢复
    pub fn enable(name: &str) -> Result<String, String> {
        run(&["-U", "-e", "", "--", name])
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use crate::respond::powershell;

    /// Windows 内置管理员账号 RID（DOMAIN_USER_RID_ADMIN = 500），不随系统语言或改名变化
    const DOMAIN_USER_RID_ADMIN: u32 = 500;

    pub fn is_builtin_admin(name: &str) -> bool {
        use std::ptr::{null, null_mut};
        use windows_sys::Win32::Security::{
            GetSidSubAuthority, GetSidSubAuthorityCount, LookupAccountNameW,
        };

        let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let mut sid_len = 0u32;
        let mut domain_len = 0u32;
        let mut sid_use = 0i32;
        // 第一次调用查询 SID 与域名缓冲区所需大小
        // SAFETY: wide 为以 0 结尾的 UTF-16 串，系统名传空表示本机；出参均为栈上变量，传空缓冲只查询长度。
        unsafe {
            LookupAccountNameW(
                null(),
                wide.as_ptr(),
                null_mut(),
                &mut sid_len,
                null_mut(),
                &mut domain_len,
                &mut sid_use,
            );
        }
        if sid_len == 0 || sid_len > 1024 || domain_len > 1024 {
            return false;
        }
        let mut sid = vec![0u8; sid_len as usize];
        let mut domain = vec![0u16; domain_len.max(1) as usize];
        // SAFETY: sid 与 domain 已按首次查询返回的长度分配；指针与长度匹配且在调用期间有效。
        let ok = unsafe {
            LookupAccountNameW(
                null(),
                wide.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut sid_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut sid_use,
            )
        };
        if ok == 0 {
            return false;
        }
        let sid_ptr = sid.as_mut_ptr().cast();
        // SAFETY: LookupAccountNameW 成功时 sid_ptr 指向系统写入的有效 SID；
        // 先读取子授权计数，再在 count > 0 时读取最后一个子授权（即 RID）。
        let count = unsafe {
            let p = GetSidSubAuthorityCount(sid_ptr);
            if p.is_null() { 0 } else { *p }
        };
        if count == 0 {
            return false;
        }
        // SAFETY: count >= 1，count - 1 在该有效 SID 的子授权下标范围内。
        let rid = unsafe {
            let p = GetSidSubAuthority(sid_ptr, u32::from(count - 1));
            if p.is_null() { 0 } else { *p }
        };
        rid == DOMAIN_USER_RID_ADMIN
    }

    pub fn is_self(name: &str) -> bool {
        std::env::var("USERNAME").is_ok_and(|u| u.eq_ignore_ascii_case(name))
    }

    pub fn disable(name: &str) -> Result<(), String> {
        powershell(&format!("Disable-LocalUser -Name '{name}'")).map(|_| ())
    }

    pub fn enable(name: &str) -> Result<String, String> {
        powershell(&format!("Enable-LocalUser -Name '{name}'")).map(|_| String::new())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod platform {
    pub fn is_builtin_admin(_: &str) -> bool {
        false
    }
    pub fn is_self(_: &str) -> bool {
        false
    }
    pub fn disable(_: &str) -> Result<(), String> {
        Err("本平台不支持账号锁定".into())
    }
    pub fn enable(_: &str) -> Result<String, String> {
        Err("本平台不支持账号锁定".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(target: &str) -> Command {
        Command {
            target: target.into(),
            ..Default::default()
        }
    }

    #[test]
    fn refuses_builtin_invalid_and_self() {
        for bad in ["", "-e", "a b", "x'; rm -rf /", "a".repeat(33).as_str()] {
            assert!(checked(&cmd(bad)).unwrap_err().contains("无效"), "{bad:?}");
        }
        for builtin in ["root", "Administrator", "SYSTEM"] {
            assert!(checked(&cmd(builtin)).unwrap_err().contains("内置"));
        }
        assert_eq!(checked(&cmd(" deploy ")).unwrap(), "deploy");
    }
}
