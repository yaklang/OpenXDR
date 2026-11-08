//! exec 那一刻从 /proc 补的事实：控制终端、经 fd 执行时的真实程序、容器里的程序是否来自 overlay 可写层、
//! 按进程自己的 /etc/passwd 解析的用户名。都是尽力而为：短命进程已经退场就缺省，事件照常上报。

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// 缓存条目上限：超过就整表清空重来，这几张表的键都很少变
const CACHE_MAX: usize = 4096;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 控制终端：/proc/<pid>/stat 第 7 列 tty_nr。没有终端（守护进程、cron、管道里的脚本）是 0，返回 None
pub fn tty(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // 进程名在括号里，可能含空格：从最后一个右括号之后开始数列
    let rest = &stat[stat.rfind(')')? + 2..];
    tty_name(rest.split_whitespace().nth(4)?.parse().ok()?)
}

/// tty_nr 按内核 new_encode_dev 编码：major 在 8~19 位，minor 拆在 0~7 位与 20~31 位
fn tty_name(nr: u32) -> Option<String> {
    let major = (nr >> 8) & 0xfff;
    let minor = (nr & 0xff) | ((nr >> 12) & 0xfff00);
    match major {
        0 => None,
        136..=143 => Some(format!("pts/{}", (major - 136) * 256 + minor)),
        4 if minor < 64 => Some(format!("tty{minor}")),
        4 => Some(format!("ttyS{}", minor - 64)),
        5 if minor == 1 => Some("console".into()),
        _ => Some(format!("{major}:{minor}")),
    }
}

/// 经 fexecve / execveat(AT_EMPTY_PATH) 或 /proc/self/fd/N 执行时，内核记下的是 fd 路径，看不出执行了什么。
/// 这时读 /proc/<pid>/exe 的真实目标：memfd 载荷是 `/memfd:名字 (deleted)`，runc 的自我克隆是
/// `/memfd:runc_cloned:/proc/self/exe (deleted)`，systemd-executor 是磁盘上的真实路径。不是 fd 路径返回 None
pub fn real_exe(pid: u32, exe: &str) -> Option<String> {
    if !is_fd_path(exe) {
        return None;
    }
    let target = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(target.to_string_lossy().into_owned())
}

fn is_fd_path(exe: &str) -> bool {
    if exe.starts_with("/dev/fd/") || exe.starts_with("/proc/self/fd/") {
        return true;
    }
    exe.strip_prefix("/proc/")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(pid, rest)| {
            !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) && rest.starts_with("fd/")
        })
}

/// 容器里执行的程序是否在 overlay 可写层（upperdir）：镜像里本来没有、运行时才写进去或改过的程序。
/// 拿进程根挂载的 upperdir 拼上程序在容器里的路径（/proc/<pid>/exe 是相对进程自己的根），看文件在不在
pub fn in_upper_layer(pid: u32) -> bool {
    let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    let exe = exe.to_string_lossy();
    let Some(upper) = upperdir(pid) else {
        return false;
    };
    std::fs::symlink_metadata(format!("{upper}{exe}")).is_ok()
}

/// 进程根挂载（mount point 为 /）是 overlay 时的 upperdir；按挂载命名空间缓存，同一个容器只解析一次
fn upperdir(pid: u32) -> Option<String> {
    static CACHE: OnceLock<Mutex<HashMap<u64, Option<String>>>> = OnceLock::new();
    let ns = std::fs::metadata(format!("/proc/{pid}/ns/mnt")).ok()?.ino();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(hit) = lock(cache).get(&ns) {
        return hit.clone();
    }
    let found = std::fs::read_to_string(format!("/proc/{pid}/mountinfo"))
        .ok()
        .and_then(|m| root_upperdir(&m));
    let mut cache = lock(cache);
    if cache.len() >= CACHE_MAX {
        cache.clear();
    }
    cache.insert(ns, found.clone());
    found
}

/// mountinfo 每行：ID 父ID 设备 root 挂载点 选项 [可选字段...] - 文件系统类型 来源 超级块选项
fn root_upperdir(mountinfo: &str) -> Option<String> {
    mountinfo.lines().find_map(|line| {
        let (head, tail) = line.split_once(" - ")?;
        if head.split(' ').nth(4)? != "/" {
            return None;
        }
        let mut tail = tail.split(' ');
        if tail.next()? != "overlay" {
            return None;
        }
        tail.nth(1)?
            .split(',')
            .find_map(|o| o.strip_prefix("upperdir="))
            .map(str::to_string)
    })
}

/// 进程的 real uid（/proc/<pid>/status 的 Uid 行第一列）
pub fn uid_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status.lines().find_map(|l| {
        l.strip_prefix("Uid:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

/// 按某份 passwd 把 uid 解析成用户名。容器进程传 /proc/<pid>/root/etc/passwd：
/// 同一个 uid 在镜像里和宿主机上常常是两个用户。按文件身份（设备号 + inode）与 uid 缓存，
/// 各个容器的 passwd 互不串，useradd 换掉文件后自然换新键
pub fn username(passwd: &str, uid: u32) -> Option<String> {
    type Names = HashMap<(u64, u64, u32), Option<String>>;
    static CACHE: OnceLock<Mutex<Names>> = OnceLock::new();
    let meta = std::fs::metadata(passwd).ok()?;
    let key = (meta.dev(), meta.ino(), uid);
    let cache = CACHE.get_or_init(Default::default);
    if let Some(hit) = lock(cache).get(&key) {
        return hit.clone();
    }
    let name = std::fs::read_to_string(passwd)
        .ok()
        .and_then(|text| passwd_name(&text, uid));
    let mut cache = lock(cache);
    if cache.len() >= CACHE_MAX {
        cache.clear();
    }
    cache.insert(key, name.clone());
    name
}

fn passwd_name(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        fields.next()?; // 口令占位
        (fields.next()?.parse::<u32>().ok()? == uid).then(|| name.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tty_numbers_decode_to_device_names() {
        assert_eq!(tty_name(0), None);
        assert_eq!(tty_name(136 << 8).as_deref(), Some("pts/0"));
        assert_eq!(tty_name((136 << 8) | 5).as_deref(), Some("pts/5"));
        // minor 超过 255 时高位编在 20 位以上
        assert_eq!(
            tty_name((136 << 8) | 0x2c | (1 << 20)).as_deref(),
            Some("pts/300")
        );
        assert_eq!(tty_name((4 << 8) | 1).as_deref(), Some("tty1"));
        assert_eq!(tty_name((4 << 8) | 64).as_deref(), Some("ttyS0"));
        assert_eq!(tty_name((5 << 8) | 1).as_deref(), Some("console"));
    }

    #[test]
    fn own_tty_matches_stat() {
        // 测试进程自己有没有终端取决于运行环境，只验证读得出来且与 stat 一致
        let nr: u32 = {
            let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
            let rest = &stat[stat.rfind(')').unwrap() + 2..];
            rest.split_whitespace().nth(4).unwrap().parse().unwrap()
        };
        assert_eq!(tty(std::process::id()), tty_name(nr));
    }

    #[test]
    fn only_fd_paths_are_resolved() {
        assert!(is_fd_path("/dev/fd/3"));
        assert!(is_fd_path("/proc/self/fd/7"));
        assert!(is_fd_path("/proc/1234/fd/4"));
        assert!(!is_fd_path("/proc/sys/fd/1"));
        assert!(!is_fd_path("/usr/bin/bash"));
        assert_eq!(real_exe(std::process::id(), "/usr/bin/bash"), None);
        let me = std::fs::read_link("/proc/self/exe").unwrap();
        assert_eq!(
            real_exe(std::process::id(), "/dev/fd/3").as_deref(),
            Some(me.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn upperdir_comes_from_the_root_overlay_mount() {
        let docker = "\
1890 1500 0:220 / / rw,relatime master:500 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/A:/var/lib/docker/overlay2/l/B,upperdir=/var/lib/docker/overlay2/abc/diff,workdir=/var/lib/docker/overlay2/abc/work
1891 1890 0:222 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1900 1890 0:230 / /data rw - overlay overlay rw,upperdir=/elsewhere/diff,workdir=/elsewhere/work";
        assert_eq!(
            root_upperdir(docker).as_deref(),
            Some("/var/lib/docker/overlay2/abc/diff")
        );
        let host = "24 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro";
        assert_eq!(root_upperdir(host), None);
    }

    /// 真容器验证：OPENXDR_TEST_UPPER_PID 是容器里执行运行时写入的程序的进程，
    /// OPENXDR_TEST_LOWER_PID 是同一容器里执行镜像自带程序的进程
    #[test]
    #[ignore = "需要 root 与正在运行的容器进程"]
    fn upper_layer_on_real_container() {
        let pid = |k: &str| std::env::var(k).unwrap().parse::<u32>().unwrap();
        assert!(in_upper_layer(pid("OPENXDR_TEST_UPPER_PID")));
        assert!(!in_upper_layer(pid("OPENXDR_TEST_LOWER_PID")));
    }

    #[test]
    fn passwd_lookup_uses_the_given_file() {
        let text = "root:x:0:0:root:/root:/bin/bash\napp:x:999:999::/home/app:/bin/sh\n";
        assert_eq!(passwd_name(text, 999).as_deref(), Some("app"));
        assert_eq!(passwd_name(text, 1000), None);
        assert_eq!(username("/no/such/passwd", 0), None);
    }
}
