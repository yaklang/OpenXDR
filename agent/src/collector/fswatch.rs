//! 敏感文件监控（Linux inotify）。持久化与提权动作大多要碰这几个地方：
//! cron、authorized_keys、ld.so.preload、sudoers、账号库。
//!
//! inotify 不提供进程上下文（那是 fanotify/audit 的领域），事件只有路径与
//! 动作——够用：这些路径上的任何写入本身就值得一条告警。

use std::io;
use std::os::unix::io::RawFd;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::pb::AgentEvent;

use super::EventSink;

/// OCSF File System Activity
const CLASS_FILE_ACTIVITY: u32 = 1001;

/// 监控的目录。inotify 不递归，逐个列出；不存在的路径跳过。
const WATCH_DIRS: &[&str] = &[
    "/etc",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/sudoers.d",
    "/etc/ssh",
    "/root/.ssh",
];

const EVENT_MASK: u32 =
    libc::IN_CREATE | libc::IN_MODIFY | libc::IN_ATTRIB | libc::IN_DELETE | libc::IN_MOVED_TO;

pub fn spawn(agent_id: String, sink: EventSink) -> io::Result<usize> {
    let (fd, watched) = init_watches(WATCH_DIRS)?;
    let n = watched.len();
    std::thread::spawn(move || run(fd, &watched, &agent_id, &sink));
    Ok(n)
}

/// 初始化 inotify 并注册监控目录，返回 (fd, wd -> 目录路径)。
fn init_watches(dirs: &[&str]) -> io::Result<(RawFd, Vec<(i32, String)>)> {
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut watched = Vec::new();
    for dir in dirs {
        let c = std::ffi::CString::new(*dir).unwrap();
        let wd = unsafe { libc::inotify_add_watch(fd, c.as_ptr(), EVENT_MASK) };
        if wd >= 0 {
            watched.push((wd, dir.to_string()));
        }
    }
    if watched.is_empty() {
        unsafe { libc::close(fd) };
        return Err(io::Error::new(io::ErrorKind::NotFound, "没有可监控的目录"));
    }
    Ok((fd, watched))
}

fn run(fd: RawFd, watched: &[(i32, String)], agent_id: &str, sink: &EventSink) {
    // 单条 inotify_event 最大 sizeof(event) + NAME_MAX + 1，缓冲区放宽裕些
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            unsafe { libc::close(fd) };
            return;
        }
        let mut off = 0usize;
        while off + std::mem::size_of::<libc::inotify_event>() <= n as usize {
            let ev = unsafe { &*(buf.as_ptr().add(off).cast::<libc::inotify_event>()) };
            let name_off = off + std::mem::size_of::<libc::inotify_event>();
            let name = std::str::from_utf8(&buf[name_off..name_off + ev.len as usize])
                .unwrap_or("")
                .trim_end_matches('\0');
            off = name_off + ev.len as usize;

            // 只关心文件本体的变化，子目录事件跳过
            if ev.mask & libc::IN_ISDIR != 0 || name.is_empty() {
                continue;
            }
            let dir = match watched.iter().find(|(wd, _)| *wd == ev.wd) {
                Some((_, d)) => d,
                None => continue,
            };
            let path = format!("{}/{}", dir.trim_end_matches('/'), name);
            if !sink.send(file_event(agent_id, &path, activity(ev.mask))) {
                unsafe { libc::close(fd) };
                return;
            }
        }
    }
}

/// inotify mask -> OCSF File Activity：1 Create / 3 Update / 4 Delete
fn activity(mask: u32) -> u8 {
    match () {
        _ if mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0 => 1,
        _ if mask & libc::IN_DELETE != 0 => 4,
        _ => 3,
    }
}

fn file_event(agent_id: &str, path: &str, activity: u8) -> AgentEvent {
    let raw = serde_json::json!({
        "activity_id": activity,
        "file": { "path": path },
    });
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: CLASS_FILE_ACTIVITY,
        process_guid: String::new(),
        parent_process_guid: String::new(),
        username: String::new(),
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
        dropped_events: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use tokio::sync::mpsc;

    #[test]
    fn watch_reports_file_change() {
        let dir = std::env::temp_dir().join("openxdr_fswatch_test");
        let _ = std::fs::create_dir(&dir);
        let dir_s = dir.to_str().unwrap().to_string();

        let (fd, watched) = init_watches(&[dir_s.as_str()]).unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        let sink = EventSink {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        std::thread::spawn(move || run(fd, &watched, "agent-t", &sink));

        std::fs::write(dir.join("evil.txt"), b"x").unwrap();

        let ev = rx.blocking_recv().expect("应收到文件事件");
        assert_eq!(ev.class_uid, CLASS_FILE_ACTIVITY);
        let v: serde_json::Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["file"]["path"], dir.join("evil.txt").to_str().unwrap());
        assert_eq!(v["activity_id"], 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_dirs_error() {
        assert!(init_watches(&["/nonexistent/openxdr"]).is_err());
    }
}
