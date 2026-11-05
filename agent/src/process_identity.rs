//! 将采集时的 GUID 绑定到操作系统进程创建时间。处置必须同时匹配，PID 本身不是身份。
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

fn identities() -> &'static Mutex<HashMap<u32, (Uuid, u64)>> {
    static IDENTITIES: OnceLock<Mutex<HashMap<u32, (Uuid, u64)>>> = OnceLock::new();
    IDENTITIES.get_or_init(Default::default)
}

pub fn record(pid: u32, guid: Uuid) {
    let birth = Target::open(pid).and_then(|p| p.birth()).ok();
    let mut ids = identities().lock().unwrap_or_else(|e| e.into_inner());
    if ids.len() >= 65536 {
        ids.clear();
    }
    ids.remove(&pid);
    if let Some(birth) = birth {
        ids.insert(pid, (guid, birth));
    }
}

pub fn verified(pid: u32, guid: &str) -> Result<Target, String> {
    let target = Target::open(pid)?;
    let expected = Uuid::parse_str(guid).map_err(|_| "缺少合法的进程 GUID".to_string())?;
    let birth = target.birth()?;
    let ids = identities().lock().unwrap_or_else(|e| e.into_inner());
    if ids.get(&pid) != Some(&(expected, birth)) {
        return Err("进程身份不匹配或已过期，拒绝结束进程".into());
    }
    #[cfg(target_os = "linux")]
    {
        let mut target = target;
        target.verified_birth = Some(birth);
        Ok(target)
    }
    #[cfg(not(target_os = "linux"))]
    Ok(target)
}

#[cfg(target_os = "linux")]
pub struct Target {
    pid: u32,
    fd: Option<std::os::fd::OwnedFd>,
    verified_birth: Option<u64>,
}

#[cfg(target_os = "linux")]
impl Target {
    fn open(pid: u32) -> Result<Self, String> {
        use std::os::fd::FromRawFd;
        // pidfd 固定进程实例，校验之后 PID 再被复用也不会误杀。
        // SAFETY: pidfd_open 只接收整数参数（pid 与 flags 0），不涉及指针；返回值在下面检查 < 0。
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS) {
            return Err(format!(
                "进程不存在或无法打开 pidfd: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            pid,
            // SAFETY: fd ≥ 0 是 pidfd_open 刚返回的新描述符，此处之外无人持有，交给 OwnedFd 独占并负责关闭；
            // fd 值不超过 RLIMIT_NOFILE，转 i32 不截断。
            fd: (fd >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) }),
            verified_birth: None,
        })
    }
    fn birth(&self) -> Result<u64, String> {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.pid))
            .map_err(|e| e.to_string())?;
        stat.rsplit_once(')')
            .and_then(|(_, fields)| fields.split_whitespace().nth(19))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| "无法读取进程创建时间".into())
    }
    pub fn terminate(&self) -> Result<(), String> {
        use std::os::fd::AsRawFd;
        if let Some(fd) = &self.fd {
            // SAFETY: fd 由 Target 持有；空 info 与 flags 0 是合法参数。
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if rc >= 0 {
                return Ok(());
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOSYS) {
                return Err(err.to_string());
            }
        }
        // 旧内核不支持 pidfd 时，发送信号前再次核对已验证的创建时间。
        if Some(self.birth()?) != self.verified_birth {
            return Err("进程身份已变化，拒绝结束进程".into());
        }
        // SAFETY: PID 来自已验证的目标，且刚刚重新核对了创建时间。
        if unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGKILL) } < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
}

#[cfg(windows)]
pub struct Target(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Target {
    fn open(pid: u32) -> Result<Self, String> {
        use windows_sys::Win32::System::Threading::*;
        // SAFETY: OpenProcess 只接收整数参数，不涉及指针；返回空句柄表示失败，下面已检查。
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                0,
                pid,
            )
        };
        if handle.is_null() {
            return Err(format!(
                "进程不存在或无法打开: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self(handle))
    }
    fn birth(&self) -> Result<u64, String> {
        use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
        let (mut created, mut exited, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        // SAFETY: self.0 是 open 时以 PROCESS_QUERY_LIMITED_INFORMATION 打开的有效句柄（GetProcessTimes
        // 所需的访问权），在 Drop 前一直有效；四个出参都指向栈上已初始化的 FILETIME。
        if unsafe { GetProcessTimes(self.0, &mut created, &mut exited, &mut kernel, &mut user) }
            == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }
    pub fn terminate(&self) -> Result<(), String> {
        // SAFETY: self.0 是 open 时带 PROCESS_TERMINATE 权限打开的有效句柄，在 Drop 前一直有效。
        if unsafe { windows_sys::Win32::System::Threading::TerminateProcess(self.0, 1) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for Target {
    fn drop(&mut self) {
        // SAFETY: Target 独占这个句柄（open 成功才构造，不可 Clone），Drop 只执行一次，不会重复关闭。
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
pub struct Target;
#[cfg(not(any(target_os = "linux", windows)))]
impl Target {
    fn open(_: u32) -> Result<Self, String> {
        Err("当前平台不支持可靠进程身份校验".into())
    }
    fn birth(&self) -> Result<u64, String> {
        Err("不支持进程创建时间".into())
    }
    pub fn terminate(&self) -> Result<(), String> {
        Err("不支持结束进程".into())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn terminate_without_pidfd_checks_birth() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut target = Target {
            pid: child.id(),
            fd: None,
            verified_birth: Some(0),
        };
        let refused = target.terminate();
        target.verified_birth = Some(target.birth().unwrap());
        let killed = target.terminate();
        // 即使断言失败也先回收子进程。
        let _ = child.kill();
        let status = child.wait().unwrap();
        assert_eq!(refused.unwrap_err(), "进程身份已变化，拒绝结束进程");
        assert!(killed.is_ok());
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn stale_guid_and_birth_are_rejected() {
        // 用自己的进程做只读校验，绝不调用 terminate。
        let pid = std::process::id();
        let guid = Uuid::new_v4();
        record(pid, guid);
        assert!(verified(pid, &guid.to_string()).is_ok());
        assert!(verified(pid, &Uuid::new_v4().to_string()).is_err());
        assert!(verified(pid, "").is_err());
        identities().lock().unwrap().insert(pid, (guid, 0));
        assert!(verified(pid, &guid.to_string()).is_err());
    }
}
