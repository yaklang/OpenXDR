//! 容器隔离：进容器自己的网络命名空间建一张独立的 nftables 表，除回环外进出全部丢弃，已建立的连接一并切断。
//! 宿主机与其他容器不受影响——靶场容器被拿下当跳板时，断掉它而不是整台宿主机。
//!
//! 用宿主机网络的容器拒绝执行：那等于隔离宿主机，必须走主机隔离和它的放行闸门。
//! 容器重启会换网络命名空间，隔离随之失效；租约期内的复查由 server 负责。

use super::Outcome;
use crate::pb::Command;

/// 容器网络命名空间里的独立表，解除只删它
#[cfg(target_os = "linux")]
const TABLE: &str = "openxdr_container_isolation";

pub fn isolate(cmd: &Command) -> Outcome {
    run(cmd, true)
}

pub fn unisolate(cmd: &Command) -> Outcome {
    run(cmd, false)
}

#[cfg(not(target_os = "linux"))]
fn run(_cmd: &Command, _isolate: bool) -> Outcome {
    Outcome::unsupported("容器隔离只支持 Linux")
}

#[cfg(target_os = "linux")]
fn run(cmd: &Command, isolate: bool) -> Outcome {
    let uid = cmd.target.trim();
    if !valid_uid(uid) {
        return Outcome::failed("容器 ID 无效");
    }
    let ns = match netns_of(uid) {
        Ok(ns) => ns,
        Err(e) => return Outcome::failed(e),
    };
    let script = if isolate {
        ruleset()
    } else {
        format!("delete table inet {TABLE}\n")
    };
    match in_netns(ns, script) {
        Ok(()) if isolate => Outcome::ok(format!("已隔离容器 {uid}，宿主机与其他容器不受影响")),
        Ok(()) => Outcome::ok(format!("已解除容器 {uid} 的隔离")),
        Err(e) if !isolate && (e.contains("No such file") || e.contains("does not exist")) => {
            Outcome::ok(format!("容器 {uid} 当前未处于隔离状态"))
        }
        Err(e) => Outcome::failed(e),
    }
}

/// docker 系的十六进制 ID，或 LXC / QEMU 的数字 VMID
#[cfg(target_os = "linux")]
fn valid_uid(uid: &str) -> bool {
    (12..=64).contains(&uid.len()) && uid.bytes().all(|b| b.is_ascii_hexdigit())
        || (1..=9).contains(&uid.len()) && uid.bytes().all(|b| b.is_ascii_digit())
}

/// 先建再删再建：同一事务里保证表是确定的而不是叠加的，重复下发幂等
#[cfg(target_os = "linux")]
fn ruleset() -> String {
    format!(
        "add table inet {TABLE}\n\
         delete table inet {TABLE}\n\
         add table inet {TABLE}\n\
         add chain inet {TABLE} input {{ type filter hook input priority -100 ; policy drop ; }}\n\
         add chain inet {TABLE} output {{ type filter hook output priority -100 ; policy drop ; }}\n\
         add rule inet {TABLE} input iif lo accept\n\
         add rule inet {TABLE} output oif lo accept\n"
    )
}

/// 找容器里任意一个进程，打开它的网络命名空间。和宿主机（pid 1）同一个命名空间的拒绝
#[cfg(target_os = "linux")]
fn netns_of(uid: &str) -> Result<std::fs::File, String> {
    use std::os::unix::fs::MetadataExt;
    let entries = std::fs::read_dir("/proc").map_err(|e| e.to_string())?;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if crate::collector::container_uid(pid).as_deref() != Some(uid) {
            continue;
        }
        let Ok(ns) = std::fs::File::open(format!("/proc/{pid}/ns/net")) else {
            continue; // 进程刚退出，换下一个
        };
        let meta = ns.metadata().map_err(|e| e.to_string())?;
        let host = std::fs::metadata("/proc/1/ns/net")
            .map_err(|e| format!("读不到宿主机网络命名空间：{e}"))?;
        if meta.ino() == host.ino() && meta.dev() == host.dev() {
            return Err(format!(
                "容器 {uid} 用的是宿主机网络，隔离它等于隔离宿主机，拒绝执行"
            ));
        }
        return Ok(ns);
    }
    Err(format!(
        "本机找不到容器 {uid} 的进程（已停止或不在这台主机上）"
    ))
}

/// 在临时线程里切进容器的网络命名空间执行 nft：命名空间按线程生效，子进程继承这个线程的，
/// 线程结束即丢弃，agent 其余线程一直留在宿主机网络里
#[cfg(target_os = "linux")]
fn in_netns(ns: std::fs::File, script: String) -> Result<(), String> {
    std::thread::spawn(move || {
        use std::os::fd::AsRawFd;
        // SAFETY: ns 在调用期间一直打开，fd 有效；CLONE_NEWNET 只切换当前这个临时线程
        if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(format!(
                "进入容器网络命名空间失败：{}",
                std::io::Error::last_os_error()
            ));
        }
        super::isolate::nft_script(&script)
    })
    .join()
    .map_err(|_| "容器隔离线程异常退出".to_string())?
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn ruleset_drops_everything_but_loopback() {
        let s = ruleset();
        assert_eq!(s.matches("policy drop").count(), 2);
        assert!(s.contains("iif lo accept") && s.contains("oif lo accept"));
        assert!(!s.contains("established"), "已建立的连接也要切断");
        assert!(s.find("delete table").unwrap() < s.rfind("add table").unwrap());
    }

    #[test]
    fn uid_must_be_container_id_or_vmid() {
        assert!(valid_uid("4f173e0d45b0"));
        assert!(valid_uid("101"));
        assert!(!valid_uid(""));
        assert!(!valid_uid("../../etc"));
        assert!(!valid_uid("4f173e0d45b0; rm -rf /"));
    }

    #[test]
    fn unknown_container_fails_without_touching_host() {
        let cmd = Command {
            target: "0123456789ab".into(),
            ..Default::default()
        };
        let r = isolate(&cmd);
        assert_eq!(r.status, crate::pb::command_result::Status::Failed);
        assert!(r.detail.contains("找不到容器"), "{}", r.detail);
    }
}
