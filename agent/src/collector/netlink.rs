//! Linux 用户态进程事件采集：netlink proc connector。
//!
//! 内核把每一次 fork/exec/exit 主动推给用户态，不漏短命进程——
//! 这是轮询采集永远做不到的。整段代码跑在三环，不需要 eBPF、
//! 不需要 nightly 工具链，只要 CAP_NET_ADMIN。
//!
//! 内核只给 pid，命令行和可执行路径仍要现场从 /proc 补；进程退得太快
//! 时补不到，但事件本身不会丢——这点比轮询强。

use std::io;
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};

use super::liveness::{Stop, Worker};
use super::{
    ACTIVITY_LAUNCH, ACTIVITY_TERMINATE, EventSink, ProcessInfo, ProcessRegistry, emit_process,
    username_of,
};

const NETLINK_CONNECTOR: libc::c_int = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;

const PROC_EVENT_FORK: u32 = 0x0000_0001;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;

/// nlmsghdr(16) + cn_msg(20)，之后才是 proc_event
const NLMSG_HDR_LEN: usize = 16;
const CN_MSG_LEN: usize = 20;
const PROC_EVENT_OFFSET: usize = NLMSG_HDR_LEN + CN_MSG_LEN;
/// proc_event 里 what(4) + cpu(4) + timestamp(8)，联合体从第 16 字节开始
const EVENT_DATA_OFFSET: usize = PROC_EVENT_OFFSET + 16;

/// 初始 pid 命名空间的固定 inode。内核把它写死成这个值，
/// systemd 等一票工具都靠它判断自己是不是在容器里。
const INIT_PID_NS_INO: u64 = 4026531836;

/// 判断当前是否处在初始 pid 命名空间。
///
/// proc connector 报的 pid 属于初始命名空间。在容器（以及 WSL2 这类
/// 嵌套环境）里，这些 pid 与我们能看到的 /proc 对不上号，采出来的事件
/// 全是错 pid、空进程名的垃圾——比轮询还糟，必须主动退让。
fn in_init_pid_namespace() -> bool {
    let Ok(link) = std::fs::read_link("/proc/self/ns/pid") else {
        return false;
    };
    let text = link.to_string_lossy();
    text.trim_start_matches("pid:[")
        .trim_end_matches(']')
        .parse::<u64>()
        .map(|ino| ino == INIT_PID_NS_INO)
        .unwrap_or(false)
}

/// 尝试开启 netlink 采集。成功后事件循环跑在独立 OS 线程上——
/// recv 是阻塞调用，放进 async 会占死 tokio 的工作线程。
pub fn spawn(agent_id: String, tx: EventSink) -> io::Result<()> {
    if !in_init_pid_namespace() {
        return Err(io::Error::other(
            "当前不在初始 pid 命名空间（容器或 WSL2），proc connector 的 pid 无法对应到本地进程",
        ));
    }
    // 内核只报 pid，血缘靠本地注册表维护，先用 /proc 快照打底；自检进程要持锁登记，注册表共享。
    // 注册表在订阅之外持有：静默重建只换套接字，已登记的进程 GUID 不丢，退出事件照样配得上启动
    let registry = Arc::new(Mutex::new(super::seeded_registry()));
    let worker = start(&agent_id, &tx, &registry)?;
    let probe = registry.clone();
    super::liveness::spawn(
        tx.clone(),
        &super::liveness::PROCESS,
        move || super::liveness::probe_process(&probe),
        worker,
        move || start(&agent_id, &tx, &registry).map_err(|e| e.to_string()),
    );
    Ok(())
}

/// 开一个新套接字重新订阅，收事件的线程跑到叫停或这一轮采集结束
fn start(
    agent_id: &str,
    tx: &EventSink,
    registry: &Arc<Mutex<ProcessRegistry>>,
) -> io::Result<Worker> {
    let sock = Socket::open()?;
    sock.subscribe()?;
    tx.capability("process", "netlink", "active");
    let (agent_id, tx, registry) = (agent_id.to_string(), tx.clone(), registry.clone());
    Ok(Worker::spawn(move |stop| {
        pump(sock, agent_id, tx, registry, stop)
    }))
}

fn pump(
    sock: Socket,
    agent_id: String,
    tx: EventSink,
    registry: Arc<Mutex<ProcessRegistry>>,
    stop: &Stop,
) {
    let mut buf = vec![0u8; 8192];

    while !tx.is_closed() && !stop.requested() {
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => {
                tx.capability("process", "netlink", "unavailable");
                return;
            }
        };
        for event in parse_events(&buf[..n]) {
            let Some(d) = describe(&event) else { continue };
            let mut registry = registry.lock().unwrap_or_else(|e| e.into_inner());
            let events = emit_process(
                &agent_id,
                &mut registry,
                d.activity,
                ProcessInfo {
                    pid: d.pid,
                    name: &d.name,
                    exe: d.exe.as_deref(),
                    cmd_line: d.cmd_line.as_deref(),
                    ppid: d.ppid,
                    username: username_of(d.pid),
                    exit_code: d.exit_code,
                },
            );
            drop(registry);
            for event in events {
                if !tx.send(event) {
                    return; // 上报端已断开
                }
            }
        }
    }
}

struct ProcEvent {
    what: u32,
    pid: u32,
    ppid: Option<u32>,
    exit_code: Option<u32>,
}

/// 一个 netlink 数据报可能带多条消息，按 nlmsghdr 的长度逐条走。
fn parse_events(buf: &[u8]) -> Vec<ProcEvent> {
    let mut events = Vec::new();
    let mut offset = 0;

    while offset + PROC_EVENT_OFFSET <= buf.len() {
        let msg = &buf[offset..];
        let len = u32::from_ne_bytes(msg[0..4].try_into().unwrap()) as usize;
        if len < PROC_EVENT_OFFSET || offset + len > buf.len() {
            break;
        }

        let what = u32::from_ne_bytes(
            msg[PROC_EVENT_OFFSET..PROC_EVENT_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        let data = &msg[EVENT_DATA_OFFSET..];
        match what {
            // exec: process_pid, process_tgid
            PROC_EVENT_EXEC if data.len() >= 8 => events.push(ProcEvent {
                what,
                pid: u32::from_ne_bytes(data[0..4].try_into().unwrap()),
                ppid: None,
                exit_code: None,
            }),
            // fork: parent_pid, parent_tgid, child_pid, child_tgid
            PROC_EVENT_FORK if data.len() >= 16 => events.push(ProcEvent {
                what,
                pid: u32::from_ne_bytes(data[8..12].try_into().unwrap()),
                ppid: Some(u32::from_ne_bytes(data[0..4].try_into().unwrap())),
                exit_code: None,
            }),
            // exit: process_pid, process_tgid, exit_code, exit_signal。
            // 每个线程退出都会来一条，只有主线程（pid == tgid）退出才是进程退出
            PROC_EVENT_EXIT if data.len() >= 16 && data[0..4] == data[4..8] => {
                events.push(ProcEvent {
                    what,
                    pid: u32::from_ne_bytes(data[0..4].try_into().unwrap()),
                    ppid: None,
                    exit_code: Some(u32::from_ne_bytes(data[8..12].try_into().unwrap())),
                })
            }
            _ => {}
        }

        // netlink 消息按 4 字节对齐
        offset += (len + 3) & !3;
    }
    events
}

/// 一次进程活动的现场信息。字段持有所有权，避免为了凑生命周期而泄漏内存。
struct Described {
    pid: u32,
    activity: u32,
    name: String,
    exe: Option<String>,
    cmd_line: Option<String>,
    ppid: Option<u32>,
    exit_code: Option<u32>,
}

/// 从 /proc 补齐命令行、可执行路径和父进程。短命进程可能已经退场，
/// 拿不到就只报 pid——事件本身不丢。退出事件到达时进程尚在退出途中，
/// /proc 往往还读得到，同样尽力补。
fn describe(event: &ProcEvent) -> Option<Described> {
    let pid = event.pid;
    // fork 事件只用于维护血缘，真正产生事件的是 exec/exit
    let activity = match event.what {
        PROC_EVENT_EXEC => ACTIVITY_LAUNCH,
        PROC_EVENT_EXIT => ACTIVITY_TERMINATE,
        _ => return None,
    };

    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let cmd_line = super::container::cmd_line(pid);
    let (name, ppid) = read_status(pid);

    Some(Described {
        pid,
        activity,
        name: name.unwrap_or_default(),
        exe,
        cmd_line,
        ppid: ppid.or(event.ppid),
        exit_code: event.exit_code,
    })
}

fn read_status(pid: u32) -> (Option<String>, Option<u32>) {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return (None, None);
    };
    let mut name = None;
    let mut ppid = None;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("Name:") {
            name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("PPid:") {
            ppid = v.trim().parse().ok();
        }
    }
    (name, ppid)
}

struct Socket(RawFd);

impl Socket {
    fn open() -> io::Result<Self> {
        // SAFETY: 纯 FFI 调用，参数都是整数常量，不涉及指针；返回值在下面检查 < 0。
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                NETLINK_CONNECTOR,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let sock = Self(fd);

        // SAFETY: sockaddr_nl 只含整数字段，全零是合法值，也是内核要求的初值（nl_pid 为 0 交给内核分配）。
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_groups = CN_IDX_PROC;
        // SAFETY: fd 是上面刚创建、由 sock 持有的有效套接字；addr 是栈上已初始化的 sockaddr_nl，
        // 传入的长度正是它的大小，bind 只在调用期间读取。
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            // 绑定组播组需要 CAP_NET_ADMIN，权限不足时由调用方回落轮询
            return Err(io::Error::last_os_error());
        }
        Ok(sock)
    }

    /// 告诉内核开始推送进程事件。不发这条订阅消息，socket 上什么都收不到。
    fn subscribe(&self) -> io::Result<()> {
        let mut msg = [0u8; PROC_EVENT_OFFSET + 4];
        let total = msg.len() as u32;

        msg[0..4].copy_from_slice(&total.to_ne_bytes()); // nlmsg_len
        msg[4..6].copy_from_slice(&(libc::NLMSG_DONE as u16).to_ne_bytes());
        // nlmsg_pid 留 0，交给内核按发送方填

        let cn = NLMSG_HDR_LEN;
        msg[cn..cn + 4].copy_from_slice(&CN_IDX_PROC.to_ne_bytes());
        msg[cn + 4..cn + 8].copy_from_slice(&CN_VAL_PROC.to_ne_bytes());
        msg[cn + 16..cn + 18].copy_from_slice(&4u16.to_ne_bytes()); // cn_msg.len
        msg[PROC_EVENT_OFFSET..].copy_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());

        // SAFETY: msg 是栈上数组，指针与 msg.len() 对应同一段内存，send 只读；
        // self.0 在 Socket 存活期间一直有效（只在 Drop 里关闭）。
        let n = unsafe { libc::send(self.0, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut fd = libc::pollfd {
                fd: self.0,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: &mut fd 指向栈上单个 pollfd，nfds 传 1 与之相符，poll 只在调用期间读写它。
            let ready = unsafe { libc::poll(&mut fd, 1, 1000) };
            if ready == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            if ready < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            // SAFETY: buf 是调用方独占借用的可写切片，长度如实传 buf.len()，内核最多写这么多字节；
            // self.0 在 Socket 存活期间有效。
            let n =
                unsafe { libc::recv(self.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            return Ok(n as usize);
        }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        // SAFETY: self.0 由 Socket 独占持有（open 成功才构造），Drop 只执行一次，不会重复关闭或关到别人的 fd。
        unsafe { libc::close(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 拼一条 proc connector 报文：nlmsghdr + cn_msg + proc_event 头 + 数据。
    fn build_msg(what: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; EVENT_DATA_OFFSET + data.len()];
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes()); // nlmsg_len
        buf[PROC_EVENT_OFFSET..PROC_EVENT_OFFSET + 4].copy_from_slice(&what.to_ne_bytes());
        buf[EVENT_DATA_OFFSET..].copy_from_slice(data);
        buf
    }

    /// exit: process_pid, process_tgid, exit_code, exit_signal 共 16 字节。
    #[test]
    fn parse_exit_event() {
        let mut data = Vec::new();
        data.extend_from_slice(&1234u32.to_ne_bytes()); // process_pid
        data.extend_from_slice(&1234u32.to_ne_bytes()); // process_tgid
        data.extend_from_slice(&9u32.to_ne_bytes()); // exit_code
        data.extend_from_slice(&0u32.to_ne_bytes()); // exit_signal

        let events = parse_events(&build_msg(PROC_EVENT_EXIT, &data));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].what, PROC_EVENT_EXIT);
        assert_eq!(events[0].pid, 1234);
        assert_eq!(events[0].exit_code, Some(9));

        // 非主线程退出（pid != tgid）不是进程退出
        data[0..4].copy_from_slice(&1240u32.to_ne_bytes());
        assert!(parse_events(&build_msg(PROC_EVENT_EXIT, &data)).is_empty());
    }

    /// exec 报文不带退出码，pid 取自 process_pid。
    #[test]
    fn parse_exec_event() {
        let mut data = Vec::new();
        data.extend_from_slice(&777u32.to_ne_bytes()); // process_pid
        data.extend_from_slice(&777u32.to_ne_bytes()); // process_tgid

        let events = parse_events(&build_msg(PROC_EVENT_EXEC, &data));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].what, PROC_EVENT_EXEC);
        assert_eq!(events[0].pid, 777);
        assert_eq!(events[0].exit_code, None);
    }

    /// 截断的 exit 数据（不足 16 字节）直接丢弃，不产生错解析。
    #[test]
    fn parse_truncated_exit_dropped() {
        let data = 1234u32.to_ne_bytes(); // 只有 process_pid
        let events = parse_events(&build_msg(PROC_EVENT_EXIT, &data));
        assert!(events.is_empty());
    }

    /// describe 把 exit 事件标成 Terminate，/proc 读不到时字段留空但事件不丢。
    #[test]
    fn describe_exit_is_terminate() {
        let d = describe(&ProcEvent {
            what: PROC_EVENT_EXIT,
            pid: u32::MAX, // 不存在的 pid，/proc 必然读不到
            ppid: None,
            exit_code: Some(3),
        })
        .expect("exit 事件必须产生事件");
        assert_eq!(d.activity, ACTIVITY_TERMINATE);
        assert_eq!(d.exit_code, Some(3));
        assert!(d.name.is_empty());
    }
}
