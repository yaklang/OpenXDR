//! 本机容器的地址：随资产清单上报，server 据此把图谱里容器的地址归到这台主机，
//! 不把它们当成待纳管的设备（容器连宿主机自己时，宿主机上只看得到容器的地址）。
//!
//! 每个容器取一个进程，进入它的网络命名空间读网卡地址。和宿主机共用网络的（--network host、
//! QEMU 虚拟机）没有自己的地址，跳过；同一个命名空间里的多个容器（K8s Pod）只读一次。

use std::collections::HashSet;
use std::net::IpAddr;

use serde_json::{Value, json};

use super::container;

/// 一次最多报这么多个容器，防异常主机撑爆清单事件
const MAX_CONTAINERS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hosted {
    pub runtime: &'static str,
    pub uid: String,
    pub name: Option<String>,
    pub addrs: Vec<IpAddr>,
}

/// 网络命名空间的身份：设备号 + inode
fn netns(pid: &str) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(format!("/proc/{pid}/ns/net")).ok()?;
    Some((m.dev(), m.ino()))
}

pub fn snapshot() -> Vec<Hosted> {
    let Some(host) = netns("1") else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let (mut seen_uid, mut seen_ns) = (HashSet::new(), HashSet::new());
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().filter(|s| s.bytes().all(|b| b.is_ascii_digit())) else {
            continue;
        };
        let Some(c) = pid.parse().ok().and_then(container::of) else {
            continue;
        };
        if !seen_uid.insert(c.uid.clone()) {
            continue;
        }
        let Some(ns) = netns(pid).filter(|ns| *ns != host) else {
            continue;
        };
        if !seen_ns.insert(ns) {
            continue;
        }
        let addrs = addrs_in(pid);
        if addrs.is_empty() {
            continue;
        }
        out.push(Hosted {
            runtime: c.runtime,
            uid: c.uid.clone(),
            name: c.name.clone(),
            addrs,
        });
        if out.len() == MAX_CONTAINERS {
            break;
        }
    }
    out.sort_by(|a, b| a.uid.cmp(&b.uid));
    out
}

/// 在临时线程里切进 pid 的网络命名空间读网卡地址：命名空间按线程生效，线程结束即丢弃，
/// agent 其余线程一直留在宿主机网络里
fn addrs_in(pid: &str) -> Vec<IpAddr> {
    let Ok(ns) = std::fs::File::open(format!("/proc/{pid}/ns/net")) else {
        return Vec::new();
    };
    std::thread::spawn(move || {
        use std::os::fd::AsRawFd;
        // SAFETY: ns 在调用期间一直打开，fd 有效；CLONE_NEWNET 只切换当前这个临时线程
        if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Vec::new();
        }
        let mut addrs: Vec<IpAddr> = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .map(|i| i.ip())
            .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
            .collect();
        addrs.sort();
        addrs.dedup();
        addrs
    })
    .join()
    .unwrap_or_default()
}

pub fn to_json(list: &[Hosted]) -> Value {
    Value::Array(
        list.iter()
            .map(|h| {
                let mut v = json!({
                    "runtime": h.runtime,
                    "uid": h.uid,
                    "addrs": h.addrs.iter().map(IpAddr::to_string).collect::<Vec<_>>(),
                });
                if let Some(n) = &h.name {
                    v["name"] = n.clone().into();
                }
                v
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_lists_runtime_uid_name_and_addrs() {
        let v = to_json(&[Hosted {
            runtime: "docker",
            uid: "4f1c2a3b5d6e".into(),
            name: Some("jellyfin".into()),
            addrs: vec!["172.17.1.8".parse().unwrap()],
        }]);
        assert_eq!(
            v,
            json!([{"runtime": "docker", "uid": "4f1c2a3b5d6e", "name": "jellyfin", "addrs": ["172.17.1.8"]}])
        );
    }
}
