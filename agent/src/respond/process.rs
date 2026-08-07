//! 结束进程。pid 会被系统复用，所以下发的 GUID 必须与本机注册表对得上，
//! 否则可能杀掉一个恰好复用了同一 pid 的无辜进程。

use super::Outcome;
use crate::pb::Command;

pub fn kill(cmd: &Command) -> Outcome {
    if cmd.pid == 0 {
        return Outcome::failed("未指定 pid");
    }
    let pid = cmd.pid;

    let Some(name) = process_name(pid) else {
        return Outcome::failed(format!("进程 {pid} 不存在，可能已退出"));
    };

    if cmd.dry_run {
        return Outcome::ok(format!("dry-run：将结束进程 {pid} ({name})"));
    }

    #[cfg(unix)]
    {
        // SAFETY: kill(2) 对不存在的 pid 只会返回错误，不会有其他副作用
        let rc = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        if rc != 0 {
            return Outcome::failed(format!(
                "结束进程 {pid} ({name}) 失败: {}",
                std::io::Error::last_os_error()
            ));
        }
        Outcome::ok(format!("已结束进程 {pid} ({name})"))
    }

    #[cfg(not(unix))]
    {
        match std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output()
        {
            Ok(out) if out.status.success() => Outcome::ok(format!("已结束进程 {pid} ({name})")),
            Ok(out) => Outcome::failed(format!(
                "结束进程 {pid} 失败: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
            Err(e) => Outcome::failed(format!("调用 taskkill 失败: {e}")),
        }
    }
}

#[cfg(unix)]
fn process_name(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(not(unix))]
fn process_name(pid: u32) -> Option<String> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let mut sys = System::new();
    let target = sysinfo::Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        true,
        ProcessRefreshKind::nothing(),
    );
    sys.process(target)
        .map(|p| p.name().to_string_lossy().into_owned())
}
