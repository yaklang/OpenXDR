//! 敏感文件监控。持久化与提权动作大多要碰这几个地方：
//! cron（/etc/cron.*、/var/spool/cron）、systemd unit（/etc/systemd/system）、
//! authorized_keys（/root/.ssh、/home/*/.ssh）、sudoers、账号库。
//!
//! 两条采集路径，产出同构的 OCSF File System Activity（1001）事件：
//!
//! - fanotify（优先）：FAN_REPORT_FID 模式（内核 >= 5.9）覆盖建/删/改/移动，
//!   事件元数据自带肇事者 pid——回填 /proc 解析出 exe/comm/属主，
//!   让文件事件能回答"谁改的"。fanotify_init 需要 CAP_SYS_ADMIN，
//!   句柄解析路径另需 CAP_DAC_READ_SEARCH（root 通常两者兼有）。
//! - inotify（兜底）：无进程上下文（那是 fanotify/audit 的领域），事件只有
//!   路径与动作——够用：这些路径上的任何写入本身就值得一条告警。
//!   启动时递归挂 watch（限深 MAX_DEPTH，防 /etc 这类大目录 watch 爆炸），
//!   运行中为新建/移入的子目录动态补挂。
//!
//! fanotify 初始化或打标失败都干净回落 inotify，绝不上报残缺数据。

use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::pb::AgentEvent;

use super::{EventSink, username_of};

/// OCSF File System Activity
const CLASS_FILE_ACTIVITY: u32 = 1001;

/// 递归挂载的最大深度（相对监控根），防 watch/mark 数量爆炸
const MAX_DEPTH: usize = 4;

/// 监控的目录清单（递归，限深 MAX_DEPTH）；不存在的路径跳过。
/// 覆盖的持久化面：cron、systemd 服务、SSH 免密、sudoers、/etc 账号库。
const WATCH_DIRS: &[&str] = &[
    "/etc",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/sudoers.d",
    "/etc/ssh",
    "/etc/systemd/system",
    "/var/spool/cron",
    "/root/.ssh",
];

/// inotify 事件掩码：建/改/属性/删/移入
const EVENT_MASK: u32 =
    libc::IN_CREATE | libc::IN_MODIFY | libc::IN_ATTRIB | libc::IN_DELETE | libc::IN_MOVED_TO;

/// fanotify_init 标志：FID + 目录 FID + 名字报告，事件才能还原完整路径
const FA_INIT_FLAGS: u32 = libc::FAN_CLASS_NOTIF
    | libc::FAN_CLOEXEC
    | libc::FAN_NONBLOCK
    | libc::FAN_REPORT_FID
    | libc::FAN_REPORT_DIR_FID
    | libc::FAN_REPORT_NAME;

/// fanotify mark 掩码：建/删/属性/改/移出/移入，含目录本体与子项事件
const FA_MARK_MASK: u64 = libc::FAN_CREATE
    | libc::FAN_DELETE
    | libc::FAN_ATTRIB
    | libc::FAN_MODIFY
    | libc::FAN_MOVED_FROM
    | libc::FAN_MOVED_TO
    | libc::FAN_ONDIR
    | libc::FAN_EVENT_ON_CHILD;

/// dirs 为空时用内置的敏感目录清单（含 /home 各用户 .ssh）；非空表示按下发配置覆盖。
/// 优先 fanotify（带进程上下文），不可用时干净回落 inotify 递归监控。
pub fn spawn(agent_id: String, sink: EventSink, dirs: &[String]) -> io::Result<usize> {
    let targets: Vec<String> = if dirs.is_empty() {
        default_targets()
    } else {
        dirs.to_vec()
    };
    match fa_setup(&targets) {
        Ok((st, n)) => {
            eprintln!("文件监控: fanotify 递归盯 {n} 个目录（含进程上下文）");
            std::thread::spawn(move || fa_run(st, &agent_id, &sink));
            Ok(n)
        }
        Err(e) => {
            eprintln!("fanotify 不可用（{e}），回落 inotify 递归监控");
            let (fd, watched) = ino_init(&targets)?;
            let n = watched.len();
            std::thread::spawn(move || ino_run(fd, watched, targets, &agent_id, &sink));
            Ok(n)
        }
    }
}

/// 内置清单 + /home 下各用户的 .ssh（启动时枚举 /home 一层，只收真实存在的目录）。
fn default_targets() -> Vec<String> {
    let mut dirs: Vec<String> = WATCH_DIRS.iter().map(|s| s.to_string()).collect();
    let users: Vec<String> = std::fs::read_dir("/home")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    for p in home_ssh_dirs(&users) {
        if std::path::Path::new(&p).is_dir() {
            dirs.push(p);
        }
    }
    dirs
}

/// /home 下的用户名 -> 各自的 .ssh 路径
fn home_ssh_dirs(users: &[String]) -> Vec<String> {
    users.iter().map(|u| format!("/home/{u}/.ssh")).collect()
}

/// 收集 root 及其子目录（含 root，root 深度为 0），最深 max_depth 层。
/// root 不存在时返回 [root]，由后续挂 watch/mark 失败来跳过。
fn collect_subdirs(root: &str, max_depth: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![(root.trim_end_matches('/').to_string(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        out.push(dir.clone());
        if depth >= max_depth {
            continue;
        }
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push((p.to_string_lossy().into_owned(), depth + 1));
                }
            }
        }
    }
    out
}

/// path 相对各监控根的深度（取最浅），不在任何根下返回 None。
/// 用于运行中给动态出现的子目录核算剩余递归预算。
fn rel_depth(roots: &[String], path: &str) -> Option<usize> {
    roots
        .iter()
        .filter_map(|root| {
            let root = root.trim_end_matches('/');
            if root.is_empty() {
                return None;
            }
            path.strip_prefix(root)
                .and_then(|rest| rest.strip_prefix('/'))
                .map(|rest| rest.matches('/').count() + 1)
        })
        .min()
}

// ---------------- inotify 路径（兜底，无进程上下文） ----------------

/// 初始化 inotify 并递归注册监控目录，返回 (fd, wd -> 目录路径)。
fn ino_init(targets: &[String]) -> io::Result<(RawFd, HashMap<i32, String>)> {
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut watched = HashMap::new();
    for root in targets {
        ino_add_tree(fd, root, MAX_DEPTH, &mut watched);
    }
    if watched.is_empty() {
        unsafe { libc::close(fd) };
        return Err(io::Error::new(io::ErrorKind::NotFound, "没有可监控的目录"));
    }
    Ok((fd, watched))
}

/// 给 root 及其限深内的子目录全部挂上 watch。
fn ino_add_tree(fd: RawFd, root: &str, max_depth: usize, watched: &mut HashMap<i32, String>) {
    for dir in collect_subdirs(root, max_depth) {
        let Ok(c) = std::ffi::CString::new(dir.as_str()) else {
            continue;
        };
        let wd = unsafe { libc::inotify_add_watch(fd, c.as_ptr(), EVENT_MASK) };
        if wd >= 0 {
            watched.insert(wd, dir);
        }
    }
}

fn ino_run(
    fd: RawFd,
    mut watched: HashMap<i32, String>,
    roots: Vec<String>,
    agent_id: &str,
    sink: &EventSink,
) {
    // 单条 inotify_event 最大 sizeof(event) + NAME_MAX + 1，缓冲区放宽裕些
    let mut buf = [0u8; 16384];
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

            // watch 被内核摘除（目录已删），清理映射防泄漏
            if ev.mask & libc::IN_IGNORED != 0 {
                watched.remove(&ev.wd);
                continue;
            }
            let Some(dir) = watched.get(&ev.wd).cloned() else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let path = format!("{}/{}", dir.trim_end_matches('/'), name);
            if ev.mask & libc::IN_ISDIR != 0 {
                // 新建/移入的子目录动态补挂 watch；目录本体的事件不上报
                if ev.mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0
                    && let Some(d) = rel_depth(&roots, &path)
                    && d <= MAX_DEPTH
                {
                    ino_add_tree(fd, &path, MAX_DEPTH - d, &mut watched);
                }
                continue;
            }
            if !sink.send(file_event(agent_id, &path, ino_activity(ev.mask))) {
                unsafe { libc::close(fd) };
                return;
            }
        }
    }
}

/// inotify mask -> OCSF File Activity：1 Create / 3 Update / 4 Delete
fn ino_activity(mask: u32) -> u8 {
    match () {
        _ if mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0 => 1,
        _ if mask & libc::IN_DELETE != 0 => 4,
        _ => 3,
    }
}

// ---------------- fanotify 路径（优先，带进程上下文） ----------------

/// fanotify 运行状态：事件 fd、监控根（算深度用）、fsid -> 挂载点 fd 缓存。
struct FaState {
    fd: RawFd,
    roots: Vec<String>,
    mounts: HashMap<(i32, i32), RawFd>,
    warned_overflow: bool,
    warned_resolve: bool,
}

/// 初始化 fanotify 并递归打标。需要 CAP_SYS_ADMIN；内核 < 5.9 不支持
/// FAN_REPORT_NAME 会在 fanotify_init 直接 EINVAL。任何失败都由调用方回落 inotify。
fn fa_setup(targets: &[String]) -> io::Result<(FaState, usize)> {
    let fd =
        unsafe { libc::fanotify_init(FA_INIT_FLAGS, (libc::O_RDONLY | libc::O_CLOEXEC) as u32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut n = 0;
    for root in targets {
        n += fa_mark_tree(fd, root, MAX_DEPTH);
    }
    if n == 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::new(io::ErrorKind::NotFound, "没有可监控的目录"));
    }
    let st = FaState {
        fd,
        roots: targets.to_vec(),
        mounts: HashMap::new(),
        warned_overflow: false,
        warned_resolve: false,
    };
    Ok((st, n))
}

/// 给 root 及其限深内的子目录全部打上 mark，返回成功数。
fn fa_mark_tree(fd: RawFd, root: &str, max_depth: usize) -> usize {
    let mut n = 0;
    for dir in collect_subdirs(root, max_depth) {
        let Ok(c) = std::ffi::CString::new(dir.as_str()) else {
            continue;
        };
        let rc = unsafe {
            libc::fanotify_mark(
                fd,
                libc::FAN_MARK_ADD | libc::FAN_MARK_ONLYDIR,
                FA_MARK_MASK,
                libc::AT_FDCWD,
                c.as_ptr(),
            )
        };
        if rc == 0 {
            n += 1;
        }
    }
    n
}

/// 一条解析后的 fanotify 事件。FID 模式下 fd 恒为 FAN_NOFD，路径靠 fid 还原。
struct FaEvent<'a> {
    mask: u64,
    pid: i32,
    fid: Option<Fid<'a>>,
}

/// FID 信息记录：fsid 定位挂载点，fh 是从 handle_bytes 字段起的
/// struct file_handle 内存（直接交给 open_by_handle_at），name 是
/// FAN_REPORT_NAME 附带的目录项名（仅建/删/移动这类涉名事件才有）。
struct Fid<'a> {
    fsid: (i32, i32),
    fh: &'a [u8],
    name: &'a str,
}

/// 解析一段 fanotify 读缓冲。fanotify_event_metadata 布局固定
/// （u32 event_len / u8 vers / u8 reserved / u16 metadata_len / u64 mask /
/// s32 fd / s32 pid，共 24 字节），其后是 info 记录链。逐字段按字节解析，
/// 不做指针强转，天然免疫对齐问题，也便于单测构造语料。
fn fa_parse(buf: &[u8]) -> Vec<FaEvent<'_>> {
    const MD_LEN: usize = 24;
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + MD_LEN <= buf.len() {
        let event_len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        let vers = buf[off + 4];
        let metadata_len = u16::from_ne_bytes(buf[off + 6..off + 8].try_into().unwrap()) as usize;
        let mask = u64::from_ne_bytes(buf[off + 8..off + 16].try_into().unwrap());
        let pid = i32::from_ne_bytes(buf[off + 20..off + 24].try_into().unwrap());
        // 版本不符或长度越界说明缓冲解析失步，剩下的不可信，直接丢弃
        if vers != libc::FANOTIFY_METADATA_VERSION
            || event_len < MD_LEN
            || off + event_len > buf.len()
        {
            break;
        }
        let end = off + event_len;
        let mut fid = None;
        let mut ioff = off + metadata_len.max(MD_LEN);
        while ioff + 4 <= end {
            // fanotify_event_info_header：u8 info_type / u8 pad / u16 len
            let info_type = buf[ioff];
            let len = u16::from_ne_bytes(buf[ioff + 2..ioff + 4].try_into().unwrap()) as usize;
            if len < 4 || ioff + len > end {
                break;
            }
            // fanotify_event_info_fid：hdr(4) + fsid(8) + handle_bytes(4)
            // + handle_type(4) + f_handle[handle_bytes] + name（可选，\0 结尾）
            if info_type == libc::FAN_EVENT_INFO_TYPE_FID && len >= 20 {
                let rec = &buf[ioff..ioff + len];
                let fsid = (
                    i32::from_ne_bytes(rec[4..8].try_into().unwrap()),
                    i32::from_ne_bytes(rec[8..12].try_into().unwrap()),
                );
                let handle_bytes = u32::from_ne_bytes(rec[12..16].try_into().unwrap()) as usize;
                if 20 + handle_bytes <= len {
                    let raw_name = &rec[20 + handle_bytes..];
                    let z = raw_name
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(raw_name.len());
                    fid = Some(Fid {
                        fsid,
                        fh: &rec[12..20 + handle_bytes],
                        name: std::str::from_utf8(&raw_name[..z]).unwrap_or(""),
                    });
                }
            }
            ioff += len;
        }
        out.push(FaEvent { mask, pid, fid });
        off += event_len;
    }
    out
}

/// fanotify mask -> OCSF File Activity：1 Create / 3 Update / 4 Delete
/// （与 inotify 路径对齐：移入视同新建，移出视同删除）
fn fa_activity(mask: u64) -> u8 {
    match () {
        _ if mask & (libc::FAN_CREATE | libc::FAN_MOVED_TO) != 0 => 1,
        _ if mask & (libc::FAN_DELETE | libc::FAN_MOVED_FROM) != 0 => 4,
        _ => 3,
    }
}

/// 按 fsid 找挂载点 fd：遍历 /proc/self/mountinfo，用 statfs 的 f_fsid 与
/// 事件 fsid 对拍（man fanotify 示例的做法），命中后 O_PATH 打开并缓存。
fn mount_fd_for(mounts: &mut HashMap<(i32, i32), RawFd>, fsid: (i32, i32)) -> Option<RawFd> {
    if let Some(&fd) = mounts.get(&fsid) {
        return Some(fd);
    }
    let table = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    for line in table.lines() {
        // "-" 之前第 5 个字段是挂载点（含空格的路径会被转义成 \040，忽略此边角）
        let Some(mp) = line
            .split(" - ")
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(4)
        else {
            continue;
        };
        let Ok(c) = std::ffi::CString::new(mp) else {
            continue;
        };
        let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(c.as_ptr(), &mut sf) } != 0 {
            continue;
        }
        // f_fsid 就是两个 c_int（glibc __fsid_t），按字节取，
        // 不依赖 libc 内部类型 fsid_t 的字段定义
        let val: [i32; 2] = unsafe { std::ptr::read(&raw const sf.f_fsid as *const [i32; 2]) };
        if (val[0], val[1]) != fsid {
            continue;
        }
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd >= 0 {
            mounts.insert(fsid, fd);
            return Some(fd);
        }
    }
    None
}

/// 把 FID 记录还原成完整路径：open_by_handle_at 打开句柄，读
/// /proc/self/fd 符号链接得对象路径；涉名事件（建/删/移动）fid 指向父目录，
/// 再拼上 name。句柄失效（对象已删）或权限不足（缺 CAP_DAC_READ_SEARCH）返回 None。
fn fa_resolve(mounts: &mut HashMap<(i32, i32), RawFd>, fid: &Fid) -> Option<String> {
    let mfd = mount_fd_for(mounts, fid.fsid)?;
    let fd = unsafe {
        libc::open_by_handle_at(
            mfd,
            fid.fh.as_ptr() as *mut libc::file_handle,
            libc::O_PATH | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    let base = std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    unsafe { libc::close(fd) };
    let base = base?;
    Some(if fid.name.is_empty() {
        base
    } else {
        format!("{}/{}", base.trim_end_matches('/'), fid.name)
    })
}

fn fa_run(mut st: FaState, agent_id: &str, sink: &EventSink) {
    let mut buf = [0u8; 65536];
    loop {
        // fd 是 FAN_NONBLOCK：先 poll 等事件再读，避免空转
        let mut pfd = libc::pollfd {
            fd: st.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let prc = unsafe { libc::poll(&mut pfd, 1, -1) };
        if prc <= 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        let n = unsafe { libc::read(st.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
                _ => break,
            }
        }
        for ev in fa_parse(&buf[..n as usize]) {
            if ev.mask & libc::FAN_Q_OVERFLOW != 0 {
                if !st.warned_overflow {
                    st.warned_overflow = true;
                    eprintln!("文件监控: fanotify 队列溢出，部分文件事件丢失");
                }
                continue;
            }
            let Some(fid) = ev.fid else {
                continue;
            };
            let Some(path) = fa_resolve(&mut st.mounts, &fid) else {
                if !st.warned_resolve {
                    st.warned_resolve = true;
                    eprintln!("文件监控: fanotify 句柄解析失败，部分事件缺路径被跳过");
                }
                continue;
            };
            // 新建/移入的子目录动态补打 mark（受深度限制）
            if ev.mask & libc::FAN_ONDIR != 0
                && ev.mask & (libc::FAN_CREATE | libc::FAN_MOVED_TO) != 0
                && let Some(d) = rel_depth(&st.roots, &path)
                && d <= MAX_DEPTH
            {
                fa_mark_tree(st.fd, &path, MAX_DEPTH - d);
            }
            let activity = fa_activity(ev.mask);
            // pid <= 0 是内核侧事件，没有可回填的肇事者
            let event = if ev.pid > 0 {
                file_event_proc(agent_id, &path, activity, ev.pid as u32)
            } else {
                file_event(agent_id, &path, activity)
            };
            if !sink.send(event) {
                fa_close(st);
                return;
            }
        }
    }
    fa_close(st);
}

fn fa_close(st: FaState) {
    unsafe { libc::close(st.fd) };
    for (_, fd) in st.mounts {
        unsafe { libc::close(fd) };
    }
}

// ---------------- 事件组装 ----------------

/// inotify 路径的事件：只有路径与动作，没有进程上下文。
fn file_event(agent_id: &str, path: &str, activity: u8) -> AgentEvent {
    let raw = serde_json::json!({
        "activity_id": activity,
        "file": { "path": path },
    });
    base_event(agent_id, raw, String::new())
}

/// fanotify 路径的事件：按元数据里的肇事者 pid 回填进程上下文。
/// 进程可能已退场（写后即退），/proc 读不到就给空字段，路径事件仍要上报。
fn file_event_proc(agent_id: &str, path: &str, activity: u8, pid: u32) -> AgentEvent {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let username = username_of(pid);
    let raw = serde_json::json!({
        "activity_id": activity,
        "file": { "path": path },
        "process": {
            "pid": pid,
            "name": name,
            "file": { "path": exe },
        },
    });
    base_event(agent_id, raw, username)
}

fn base_event(agent_id: &str, raw: serde_json::Value, username: String) -> AgentEvent {
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: CLASS_FILE_ACTIVITY,
        process_guid: String::new(),
        parent_process_guid: String::new(),
        username,
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

    fn test_sink() -> (EventSink, mpsc::Receiver<AgentEvent>) {
        let (tx, rx) = mpsc::channel(16);
        (
            EventSink {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    fn temp_root(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("openxdr_fswatch_{tag}_{}", std::process::id()))
    }

    #[test]
    fn watch_reports_file_change() {
        let dir = temp_root("basic");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let dir_s = dir.to_str().unwrap().to_string();

        let (fd, watched) = ino_init(std::slice::from_ref(&dir_s)).unwrap();
        let (sink, mut rx) = test_sink();
        std::thread::spawn(move || ino_run(fd, watched, vec![dir_s], "agent-t", &sink));

        std::fs::write(dir.join("evil.txt"), b"x").unwrap();

        let ev = rx.blocking_recv().expect("应收到文件事件");
        assert_eq!(ev.class_uid, CLASS_FILE_ACTIVITY);
        assert!(ev.username.is_empty(), "inotify 路径没有进程上下文");
        let v: serde_json::Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["file"]["path"], dir.join("evil.txt").to_str().unwrap());
        assert_eq!(v["activity_id"], 1);
        assert!(v.get("process").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn watch_picks_up_new_subdir() {
        let dir = temp_root("dyn");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let dir_s = dir.to_str().unwrap().to_string();

        let (fd, watched) = ino_init(std::slice::from_ref(&dir_s)).unwrap();
        let (sink, mut rx) = test_sink();
        std::thread::spawn(move || ino_run(fd, watched, vec![dir_s], "agent-t", &sink));

        // 运行中新建的子目录应被动态补挂；稍等事件循环处理完再写文件
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        std::fs::write(dir.join("sub").join("evil.sh"), b"x").unwrap();

        let ev = rx.blocking_recv().expect("新建子目录里的文件事件也应上报");
        let v: serde_json::Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(
            v["file"]["path"],
            dir.join("sub").join("evil.sh").to_str().unwrap()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_dirs_error() {
        assert!(ino_init(&["/nonexistent/openxdr".to_string()]).is_err());
    }

    #[test]
    fn collect_subdirs_respects_depth() {
        let dir = temp_root("depth");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a/b/c/d/e")).unwrap();

        let root = dir.to_str().unwrap();
        let shallow = collect_subdirs(root, 2);
        assert_eq!(shallow.len(), 3, "限深 2 层只应收 root、a、a/b");
        let full = collect_subdirs(root, 99);
        assert_eq!(full.len(), 6, "全深度应收齐 6 层目录");
        assert_eq!(collect_subdirs("/nonexistent/openxdr", 4).len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rel_depth_matches_longest_root() {
        let roots = vec!["/etc".to_string(), "/etc/ssh".to_string()];
        assert_eq!(rel_depth(&roots, "/etc/ssh/sshd_config.d/x"), Some(2));
        assert_eq!(rel_depth(&roots, "/etc/cron.d"), Some(1));
        assert_eq!(rel_depth(&roots, "/var/log/x"), None);
        // /etcfoo 只是字符串前缀，不是目录前缀
        assert_eq!(rel_depth(&roots, "/etcfoo/x"), None);
    }

    #[test]
    fn home_ssh_dirs_maps_users() {
        let users = vec!["alice".to_string(), "bob".to_string()];
        assert_eq!(
            home_ssh_dirs(&users),
            vec!["/home/alice/.ssh".to_string(), "/home/bob/.ssh".to_string()]
        );
    }

    #[test]
    fn ino_activity_mapping() {
        assert_eq!(ino_activity(libc::IN_CREATE), 1);
        assert_eq!(ino_activity(libc::IN_MOVED_TO), 1);
        assert_eq!(ino_activity(libc::IN_DELETE), 4);
        assert_eq!(ino_activity(libc::IN_MODIFY), 3);
        assert_eq!(ino_activity(libc::IN_ATTRIB), 3);
    }

    #[test]
    fn fa_activity_mapping() {
        assert_eq!(fa_activity(libc::FAN_CREATE), 1);
        assert_eq!(fa_activity(libc::FAN_MOVED_TO), 1);
        assert_eq!(fa_activity(libc::FAN_CREATE | libc::FAN_ONDIR), 1);
        assert_eq!(fa_activity(libc::FAN_DELETE), 4);
        assert_eq!(fa_activity(libc::FAN_MOVED_FROM), 4);
        assert_eq!(fa_activity(libc::FAN_MODIFY), 3);
        assert_eq!(fa_activity(libc::FAN_ATTRIB), 3);
    }

    /// 按 fanotify_event_metadata + FID 信息记录的真实布局构造一条语料。
    fn build_fid_event(
        mask: u64,
        pid: i32,
        fsid: (i32, i32),
        handle: &[u8],
        name: &str,
    ) -> Vec<u8> {
        let name_z = format!("{name}\0");
        let info_len = 4 + 8 + 4 + 4 + handle.len() + name_z.len();
        let event_len = 24 + info_len;
        let mut b = Vec::new();
        b.extend_from_slice(&(event_len as u32).to_ne_bytes());
        b.push(libc::FANOTIFY_METADATA_VERSION);
        b.push(0); // reserved
        b.extend_from_slice(&24u16.to_ne_bytes()); // metadata_len
        b.extend_from_slice(&mask.to_ne_bytes());
        b.extend_from_slice(&(-1i32).to_ne_bytes()); // fd = FAN_NOFD
        b.extend_from_slice(&pid.to_ne_bytes());
        b.push(libc::FAN_EVENT_INFO_TYPE_FID);
        b.push(0); // pad
        b.extend_from_slice(&(info_len as u16).to_ne_bytes());
        b.extend_from_slice(&fsid.0.to_ne_bytes());
        b.extend_from_slice(&fsid.1.to_ne_bytes());
        b.extend_from_slice(&(handle.len() as u32).to_ne_bytes());
        b.extend_from_slice(&1i32.to_ne_bytes()); // handle_type
        b.extend_from_slice(handle);
        b.extend_from_slice(name_z.as_bytes());
        b
    }

    #[test]
    fn fa_parse_extracts_fid_and_name() {
        let buf = build_fid_event(
            libc::FAN_CREATE,
            4242,
            (8, 1),
            &[0xde, 0xad, 0xbe, 0xef],
            "evil.sh",
        );
        let events = fa_parse(&buf);
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.mask, libc::FAN_CREATE);
        assert_eq!(ev.pid, 4242);
        let fid = ev.fid.as_ref().expect("应解析出 FID 记录");
        assert_eq!(fid.fsid, (8, 1));
        assert_eq!(fid.name, "evil.sh");
        // fh 从 handle_bytes 字段起：句柄长度(4) + handle_type(4) + 句柄本体，
        // 整体即 struct file_handle，直接交给 open_by_handle_at
        assert_eq!(u32::from_ne_bytes(fid.fh[..4].try_into().unwrap()), 4);
        assert_eq!(i32::from_ne_bytes(fid.fh[4..8].try_into().unwrap()), 1);
        assert_eq!(&fid.fh[8..], &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn fa_parse_handles_no_name_and_truncation() {
        // 无名事件（如 FAN_MODIFY 落在文件本体上）：name 为空
        let buf = build_fid_event(libc::FAN_MODIFY, 1, (0, 0), &[1, 2], "");
        let events = fa_parse(&buf);
        assert_eq!(events[0].fid.as_ref().unwrap().name, "");

        // 缓冲在事件中间截断：整条丢弃，不能产出半个事件
        let buf = build_fid_event(libc::FAN_DELETE, 1, (0, 0), &[1, 2], "x");
        assert!(fa_parse(&buf[..buf.len() - 3]).is_empty());

        // 版本号不符：解析失步，丢弃
        let mut bad = build_fid_event(libc::FAN_DELETE, 1, (0, 0), &[1, 2], "x");
        bad[4] = 99;
        assert!(fa_parse(&bad).is_empty());
    }

    #[test]
    fn file_event_proc_fills_process_context() {
        // 用当前测试进程自己的 pid：/proc 一定可读，属主一定能解析
        let pid = std::process::id();
        let ev = file_event_proc("agent-t", "/etc/ssh/sshd_config", 3, pid);
        assert_eq!(ev.class_uid, CLASS_FILE_ACTIVITY);
        assert!(!ev.username.is_empty(), "当前进程属主应可解析");
        let v: serde_json::Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["activity_id"], 3);
        assert_eq!(v["file"]["path"], "/etc/ssh/sshd_config");
        assert_eq!(v["process"]["pid"], pid);
        assert!(!v["process"]["name"].as_str().unwrap().is_empty());
        assert!(!v["process"]["file"]["path"].as_str().unwrap().is_empty());
    }
}
