//! Linux eBPF 采集：tracepoint sched_process_exec 抓进程启动，
//! sched_process_exit 抓进程退出（sys_enter_exit_group 补退出码），
//! tracepoint sock:inet_sock_set_state 抓 TCP 出站与入站，kprobe udp_sendmsg 抓 UDP 出站。
//! 捕获所有 execve（含短命进程），需要 root/CAP_BPF；
//! 失败按 netlink proc connector → 轮询逐级回落，不跳档。网络与退出码各自独立降级。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::dnswatch::{self, Origin};
use super::inventory::{Owner, Proto};
use super::inventory_linux::Scanner;
use super::netwatch::{self, ConnInfo, ConnSampler};
use super::{
    ACTIVITY_LAUNCH, ACTIVITY_TERMINATE, EventSink, ProcessInfo, ProcessRegistry, container,
    emit_process, netlink, poll, seeded_registry, stdio_socket_event, stdiosock,
};
use crate::pb::AgentEvent;

/// 与 ebpf/src/main.rs 的 ARGV_BUF 一致
const ARGV_BUF: usize = 2048;

// 与 ebpf/src/main.rs 中的定义保持一致
#[repr(C)]
#[derive(Clone, Copy)]
struct ExecEvent {
    pid: u32,
    /// fork 时记下的父进程，0 表示没记到
    ppid: u32,
    uid: u32,
    /// argv 用掉的字节（参数以 0 分隔），0 表示内核没抓到命令行
    argv_len: u32,
    argv_truncated: u32,
    comm: [u8; 16],
    filename: [u8; 256],
    argv: [u8; ARGV_BUF],
}

impl ExecEvent {
    /// 内核抓到的命令行，参数之间用空格连起来（与读 /proc/<pid>/cmdline 同一写法，空参数略去）；
    /// 截断的末尾标「…」。没抓到返回 None
    fn cmd_line(&self) -> Option<String> {
        let used = &self.argv[..(self.argv_len as usize).min(ARGV_BUF)];
        let line = used
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(String::from_utf8_lossy)
            .collect::<Vec<_>>()
            .join(" ");
        if line.is_empty() {
            return None;
        }
        Some(if self.argv_truncated != 0 {
            line + " …"
        } else {
            line
        })
    }
}

// 与 ebpf/src/main.rs 中的定义保持一致
#[repr(C)]
#[derive(Clone, Copy)]
struct ExitEvent {
    pid: u32,
    code: i32,
    has_code: u32,
}

// 与 ebpf/src/main.rs 中的定义保持一致
#[repr(C)]
#[derive(Clone, Copy)]
struct DupEvent {
    pid: u32,
    fd: u32,
}

// 与 ebpf/src/main.rs 中的定义保持一致
#[repr(C)]
#[derive(Clone, Copy)]
struct ConnEvent {
    pid: u32,
    family: u16,
    sport: u16,
    dport: u16,
    kind: u16,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

/// 内核侧按 `#[repr(C)]` 原样写进 perf 缓冲的事件结构。
///
/// # Safety
/// 实现者必须是 `#[repr(C)]`、只由整数与整数数组组成的类型：任意字节序列都是它的合法值。
unsafe trait Pod: Copy {}

// SAFETY: 事件结构都是 #[repr(C)]，字段只有 u32 / i32 / u16 与 [u8; N]，任意位模式都合法
unsafe impl Pod for ExecEvent {}
// SAFETY: 同上，字段为 u32 / i32 / u32
unsafe impl Pod for ExitEvent {}
// SAFETY: 同上，字段为两个 u32
unsafe impl Pod for DupEvent {}
// SAFETY: 同上，字段为 u32 / u16 与两个 [u8; 16]
unsafe impl Pod for ConnEvent {}

/// 从 perf 缓冲的一条记录里取出事件。不足一个结构体长的残包返回 None；
/// perf 记录按 8 字节补齐，尾部多出的字节忽略。
fn decode<T: Pod>(b: &[u8]) -> Option<T> {
    if b.len() < size_of::<T>() {
        return None;
    }
    // SAFETY: 上面已校验 b 至少有 size_of::<T>() 个已初始化字节，读不越界；
    // read_unaligned 不要求源地址对齐（BytesMut 只保证字节对齐）；T: Pod 保证任意字节都是合法值
    Some(unsafe { std::ptr::read_unaligned(b.as_ptr().cast::<T>()) })
}

const AF_INET: u16 = 2;
const CONN_TCP_OUT: u16 = 0;
const CONN_TCP_IN: u16 = 1;
const CONN_UDP_OUT: u16 = 2;
const DNS_PORT: u16 = 53;

type Shared<T> = Arc<Mutex<T>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub async fn run(agent_id: String, tx: EventSink, collect_network: bool) {
    // 跨重建要留的状态都在这里建一次：进程注册表（已登记的 GUID 映射，退出事件靠它复用启动 GUID）、
    // 连接采样表与监听表（重建后同一目标不在采样窗口内重报）、DNS 源端口归属
    let registry: Shared<ProcessRegistry> = Arc::new(Mutex::new(seeded_registry()));
    let rt = tokio::runtime::Handle::current();
    let process = {
        let (agent_id, tx, registry, rt) =
            (agent_id.clone(), tx.clone(), registry.clone(), rt.clone());
        move || start_process(&agent_id, &tx, &registry, &rt)
    };
    let pipeline = match process() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("eBPF 采集不可用（{e}），尝试 netlink proc connector");
            if collect_network {
                tx.capability("network", "ebpf", "unavailable");
                dnswatch::spawn(agent_id.clone(), tx.clone(), None);
            }
            // 与默认构建同一降级链：netlink 拿不到再退轮询，不直接从最强掉到最弱
            match netlink::spawn(agent_id.clone(), tx.clone()) {
                Ok(()) => eprintln!("采集方式: netlink proc connector（用户态，捕获全部 exec）"),
                Err(e) => {
                    eprintln!("netlink 采集不可用（{e}），回落到轮询采集（会漏短命进程）");
                    poll::run(agent_id, tx).await;
                }
            }
            return;
        }
    };
    // 进程活性检测放在挂载成功之后：失败会回落 netlink，那条路径自己盯，
    // 自检进程得登记在真正处理事件的那张注册表里。静默重建只重载进程这一组程序
    let probe = registry.clone();
    super::liveness::spawn(
        tx.clone(),
        &super::liveness::PROCESS,
        move || super::liveness::probe_process(&probe),
        pipeline,
        move || process().map_err(|e| e.to_string()),
    );

    // 网络采集独立降级：老内核没有 inet_sock_set_state 时进程采集照常
    if !collect_network {
        return;
    }
    let owners: Shared<HashMap<u16, (u32, Instant)>> = Default::default();
    let state = Arc::new(ConnState {
        registry: registry.clone(),
        tcp_out: Default::default(),
        tcp_in: Default::default(),
        udp_out: Default::default(),
        listeners: Default::default(),
        dns_owners: owners.clone(),
    });
    let network = {
        let (agent_id, tx, rt) = (agent_id.clone(), tx.clone(), rt.clone());
        move || start_network(&agent_id, &tx, &state, &rt)
    };
    match network() {
        Ok(pipeline) => {
            let udp = if pipeline.udp { "、UDP 出站" } else { "" };
            eprintln!("网络采集: eBPF（TCP 出站与入站{udp}，60s 采样）");
            super::liveness::spawn(
                tx.clone(),
                &super::liveness::NETWORK,
                super::liveness::probe_network,
                pipeline,
                move || network().map_err(|e| e.to_string()),
            );
            dnswatch::spawn(
                agent_id.clone(),
                tx.clone(),
                Some(dns_resolver(registry, owners)),
            );
        }
        Err(e) => {
            tx.capability("network", "ebpf", "unavailable");
            eprintln!("网络采集不可用（{e}）");
            dnswatch::spawn(agent_id, tx, None);
        }
    }
}

/// 一组挂好的 eBPF 程序与它们的读取任务，作为活性检测的采集实例。
/// drop 时先停读取任务（JoinSet 析构即 abort），再随 Ebpf 卸下程序：字段按声明顺序析构
struct Pipeline {
    _readers: tokio::task::JoinSet<()>,
    _bpf: aya::Ebpf,
    /// 网络组：UDP 出站探针挂上了没有
    udp: bool,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Linux 5.11 之前的内核把 eBPF map 计入 RLIMIT_MEMLOCK（默认 64 KiB 不足）。
/// 存量主机通过二进制热升级时不会重写 systemd 单元文件，首次加载前由进程主动抬到 128 MiB。
fn ensure_memlock_rlimit() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        const TARGET: libc::rlim_t = 128 * 1024 * 1024;
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: current 是栈上有效的 rlimit 结构体
        if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut current) } == 0
            && current.rlim_cur >= TARGET
        {
            return;
        }
        let raised = libc::rlimit {
            rlim_cur: TARGET,
            rlim_max: current.rlim_max.max(TARGET),
        };
        // SAFETY: raised 是栈上有效的 rlimit 结构体；失败不阻断，后续 aya::Ebpf::load 会按真实错误降级
        if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raised) } != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("提升 RLIMIT_MEMLOCK 到 128 MiB 失败（{err}），旧内核 eBPF 可能受限");
        }
    });
}

/// 进程与网络各自载入一份对象：两组程序不共用 map，各自重建互不打扰
fn load() -> Result<aya::Ebpf, BoxError> {
    ensure_memlock_rlimit();
    Ok(aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/openxdr-ebpf"
    )))?)
}

/// 挂上进程启动与退出探针，按 CPU 派发读取任务
fn start_process(
    agent_id: &str,
    tx: &EventSink,
    registry: &Shared<ProcessRegistry>,
    rt: &tokio::runtime::Handle,
) -> Result<Pipeline, BoxError> {
    use aya::maps::perf::AsyncPerfEventArray;
    use aya::util::online_cpus;

    // 重建在活性检测的线程上做，读取任务要派到 tokio 运行时上
    let _rt = rt.enter();
    let mut readers = tokio::task::JoinSet::new();
    let mut bpf = load()?;
    attach_tracepoint(&mut bpf, "sched_process_exec", "sched")?;
    attach_tracepoint(&mut bpf, "sched_process_exit", "sched")?;
    attach_exec_context(&mut bpf);

    let mut events: AsyncPerfEventArray<_> = bpf
        .take_map("EVENTS")
        .ok_or("EVENTS map 缺失")?
        .try_into()?;

    let mut exits: AsyncPerfEventArray<_> =
        bpf.take_map("EXITS").ok_or("EXITS map 缺失")?.try_into()?;

    // 退出码独立降级：没有 syscalls tracepoint（内核没开 FTRACE_SYSCALLS）时退出事件照报，只是不带退出码
    if let Err(e) = attach_tracepoint(&mut bpf, "sys_enter_exit_group", "syscalls") {
        eprintln!("退出码采集不可用（{e}）");
    }

    // exec 事件按 CPU 分发到多个任务，进程血缘是全局的，注册表要共享。
    // exec 频率远低于包速率，这把锁的争用可以忽略。
    for cpu in online_cpus().map_err(|(_, e)| e)? {
        // 事件带着命令行有 2 KiB 多，默认两页的缓冲经不起登录、构建这类成串的 exec，给 128 KiB
        let mut buf = events.open(cpu, Some(EXEC_BUFFER_PAGES))?;
        let tx = tx.clone();
        let agent_id = agent_id.to_string();
        let registry = registry.clone();
        readers.spawn(async move {
            let mut bufs = (0..8)
                .map(|_| bytes::BytesMut::with_capacity(2048))
                .collect::<Vec<_>>();
            loop {
                let Ok(batch) = buf.read_events(&mut bufs).await else {
                    return;
                };
                for b in bufs.iter().take(batch.read) {
                    let Some(ev) = decode::<ExecEvent>(b) else {
                        continue;
                    };
                    let events = {
                        let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
                        to_agent_event(&agent_id, &mut reg, &ev)
                    };
                    for event in events {
                        if !tx.send(event) {
                            return;
                        }
                    }
                }
            }
        });
    }

    for cpu in online_cpus().map_err(|(_, e)| e)? {
        let mut buf = exits.open(cpu, None)?;
        let tx = tx.clone();
        let agent_id = agent_id.to_string();
        let registry = registry.clone();
        readers.spawn(async move {
            let mut bufs = (0..8)
                .map(|_| bytes::BytesMut::with_capacity(256))
                .collect::<Vec<_>>();
            loop {
                let Ok(batch) = buf.read_events(&mut bufs).await else {
                    return;
                };
                for b in bufs.iter().take(batch.read) {
                    let Some(ev) = decode::<ExitEvent>(b) else {
                        continue;
                    };
                    let events = {
                        let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
                        to_exit_event(&agent_id, &mut reg, &ev)
                    };
                    for event in events {
                        if !tx.send(event) {
                            return;
                        }
                    }
                }
            }
        });
    }

    start_stdio(&mut bpf, &mut readers, agent_id, tx, registry)?;

    tx.capability("process", "ebpf", "active");
    Ok(Pipeline {
        _readers: readers,
        _bpf: bpf,
        udp: false,
    })
}

/// 标准输入输出被 dup 覆盖的事件（见 stdiosock）。没有 syscalls tracepoint（内核没开 FTRACE_SYSCALLS）
/// 或某个系统调用不存在（arm64 没有 dup2）就跳过那一个，三个都挂不上时只是少这一类检测，进程采集照常
fn start_stdio(
    bpf: &mut aya::Ebpf,
    readers: &mut tokio::task::JoinSet<()>,
    agent_id: &str,
    tx: &EventSink,
    registry: &Shared<ProcessRegistry>,
) -> Result<(), BoxError> {
    use aya::maps::perf::AsyncPerfEventArray;
    use aya::util::online_cpus;

    let attached = ["sys_exit_dup", "sys_exit_dup2", "sys_exit_dup3"]
        .into_iter()
        .filter(|name| match attach_tracepoint(bpf, name, "syscalls") {
            Ok(()) => true,
            Err(e) => {
                eprintln!("{name} 不可用（{e}）");
                false
            }
        })
        .count();
    if attached == 0 {
        eprintln!("标准输入输出重定向检测不可用");
        return Ok(());
    }
    let mut dups: AsyncPerfEventArray<_> =
        bpf.take_map("DUPS").ok_or("DUPS map 缺失")?.try_into()?;
    let seen: Shared<stdiosock::Seen> = Default::default();
    for cpu in online_cpus().map_err(|(_, e)| e)? {
        let mut buf = dups.open(cpu, None)?;
        let (tx, agent_id) = (tx.clone(), agent_id.to_string());
        let (registry, seen) = (registry.clone(), seen.clone());
        readers.spawn(async move {
            let mut bufs = (0..16)
                .map(|_| bytes::BytesMut::with_capacity(64))
                .collect::<Vec<_>>();
            loop {
                let Ok(batch) = buf.read_events(&mut bufs).await else {
                    return;
                };
                for b in bufs.iter().take(batch.read) {
                    let Some(ev) = decode::<DupEvent>(b) else {
                        continue;
                    };
                    // 绝大多数是 shell 的管道与重定向，读一次 /proc 就排除，不碰注册表
                    let Some(sock) = stdiosock::connected_tcp(ev.pid, ev.fd) else {
                        continue;
                    };
                    if !lock(&seen).first(ev.pid, sock.inode) {
                        continue;
                    }
                    let events =
                        stdio_socket_event(&agent_id, &mut lock(&registry), ev.pid, ev.fd, &sock);
                    for event in events {
                        if !tx.send(event) {
                            return;
                        }
                    }
                }
            }
        });
    }
    Ok(())
}

/// exec 事件的 perf 缓冲页数（每 CPU），须是 2 的幂
const EXEC_BUFFER_PAGES: usize = 32;

/// exec 时就在内核里抓命令行与父进程：用户态收到事件再去 /proc 读，短命进程早已退场，
/// 生产上 1%~28% 的启动事件因此丢了命令行与父进程。各自独立降级，挂不上只是回到读 /proc
fn attach_exec_context(bpf: &mut aya::Ebpf) {
    for name in ["sys_enter_execve", "sys_enter_execveat"] {
        if let Err(e) = attach_tracepoint(bpf, name, "syscalls") {
            eprintln!("{name} 不可用，命令行退回读 /proc（{e}）");
        }
    }
    // sched_process_fork 的布局随内核版本变，child_pid 的偏移从本机 format 读
    let Some(offset) = tracepoint_field_offset("sched", "sched_process_fork", "child_pid") else {
        eprintln!("读不到 sched_process_fork 的布局，父进程退回读 /proc");
        return;
    };
    let set = (|| -> Result<(), BoxError> {
        let mut layout: aya::maps::Array<_, u32> = bpf
            .map_mut("FORK_LAYOUT")
            .ok_or("FORK_LAYOUT map 缺失")?
            .try_into()?;
        layout.set(0, offset, 0)?;
        attach_tracepoint(bpf, "sched_process_fork", "sched")
    })();
    if let Err(e) = set {
        eprintln!("sched_process_fork 不可用，父进程退回读 /proc（{e}）");
    }
}

/// tracepoint format 里某个字段的偏移（tracefs 新旧两个挂载点都试）
fn tracepoint_field_offset(category: &str, name: &str, field: &str) -> Option<u32> {
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .iter()
        .find_map(|root| {
            std::fs::read_to_string(format!("{root}/events/{category}/{name}/format")).ok()
        })
        .and_then(|format| field_offset(&format, field))
}

/// format 每行形如 `field:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;`
fn field_offset(format: &str, field: &str) -> Option<u32> {
    format.lines().find_map(|line| {
        let decl = line.trim().strip_prefix("field:")?.split(';').next()?;
        let name = decl.rsplit([' ', '*']).next()?.split('[').next()?;
        if name != field {
            return None;
        }
        line.split(';')
            .find_map(|part| part.trim().strip_prefix("offset:"))?
            .parse()
            .ok()
    })
}

fn attach_tracepoint(bpf: &mut aya::Ebpf, name: &str, category: &str) -> Result<(), BoxError> {
    let program: &mut aya::programs::TracePoint =
        bpf.program_mut(name).ok_or("eBPF 程序缺失")?.try_into()?;
    program.load()?;
    program.attach(category, name)?;
    Ok(())
}

fn attach_kprobe(bpf: &mut aya::Ebpf, name: &str, function: &str) -> Result<(), BoxError> {
    let program: &mut aya::programs::KProbe =
        bpf.program_mut(name).ok_or("eBPF 程序缺失")?.try_into()?;
    program.load()?;
    program.attach(function, 0)?;
    Ok(())
}

/// 连接事件的用户态共享状态：各 CPU 的读取任务共用，同一目标不因内核把事件派到不同 CPU 而重复上报；
/// 也跨重建保留，重建后不在采样窗口内重报
struct ConnState {
    registry: Shared<ProcessRegistry>,
    tcp_out: Mutex<ConnSampler>,
    tcp_in: Mutex<ConnSampler>,
    udp_out: Mutex<ConnSampler>,
    listeners: Mutex<Listeners>,
    /// DNS 查询的源端口 → 发起进程，dnswatch 归属进程用
    dns_owners: Shared<HashMap<u16, (u32, Instant)>>,
}

/// 挂载连接探针并按 CPU 派发读取任务。UDP 探针挂不上只降级，记在 Pipeline::udp 上
fn start_network(
    agent_id: &str,
    tx: &EventSink,
    state: &Arc<ConnState>,
    rt: &tokio::runtime::Handle,
) -> Result<Pipeline, BoxError> {
    use aya::maps::perf::AsyncPerfEventArray;
    use aya::util::online_cpus;

    let _rt = rt.enter();
    let mut readers = tokio::task::JoinSet::new();
    let mut bpf = load()?;
    attach_tracepoint(&mut bpf, "inet_sock_set_state", "sock")?;
    let udp = attach_kprobe(&mut bpf, "kp_udp_sendmsg", "udp_sendmsg")
        .and_then(|()| attach_kprobe(&mut bpf, "kp_udpv6_sendmsg", "udpv6_sendmsg"));
    if let Err(e) = &udp {
        eprintln!("UDP 出站采集不可用（{e}）");
    }

    let mut conns: AsyncPerfEventArray<_> =
        bpf.take_map("CONNS").ok_or("CONNS map 缺失")?.try_into()?;

    for cpu in online_cpus().map_err(|(_, e)| e)? {
        let mut buf = conns.open(cpu, None)?;
        let tx = tx.clone();
        let agent_id = agent_id.to_string();
        let state = state.clone();
        readers.spawn(async move {
            let mut bufs = (0..8)
                .map(|_| bytes::BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop {
                let Ok(batch) = buf.read_events(&mut bufs).await else {
                    return;
                };
                for b in bufs.iter().take(batch.read) {
                    let Some(ev) = decode::<ConnEvent>(b) else {
                        continue;
                    };
                    let Some(event) = to_conn_event(&agent_id, &state, &ev) else {
                        continue;
                    };
                    let revealed = lock(&state.registry).take_outbox();
                    for event in revealed.into_iter().chain([event]) {
                        if !tx.send(event) {
                            return;
                        }
                    }
                }
            }
        });
    }
    let udp = udp.is_ok();
    tx.capability("network", "ebpf", if udp { "active" } else { "degraded" });
    Ok(Pipeline {
        _readers: readers,
        _bpf: bpf,
        udp,
    })
}

fn to_conn_event(agent_id: &str, state: &ConnState, ev: &ConnEvent) -> Option<AgentEvent> {
    // 活性按原始事件记：回环自检连接与被采样、过滤掉的连接都算
    super::liveness::pulse(super::liveness::Channel::Network);
    let local = ip_of(ev.family, &ev.saddr);
    let remote = ip_of(ev.family, &ev.daddr);
    // DNS 查询不单独成网络事件（dnswatch 会报完整的问答），只记下源端口归哪个进程；
    // 解析器常在本机回环上（systemd-resolved、docker 内置 DNS），所以放在回环过滤之前
    if ev.kind == CONN_UDP_OUT && ev.dport == DNS_PORT {
        let mut owners = lock(&state.dns_owners);
        if owners.len() >= 4096 {
            owners.retain(|_, (_, t)| t.elapsed() < OWNER_TTL);
        }
        owners.insert(ev.sport, (ev.pid, Instant::now()));
        return None;
    }
    // 本机自娱自乐的连接没有检测价值；UDP 的组播、广播（mDNS、SSDP 之类）也只是噪声
    if remote.is_loopback() || remote.is_multicast() || remote == IpAddr::from([255, 255, 255, 255])
    {
        return None;
    }
    match ev.kind {
        CONN_TCP_IN => {
            // 握手在软中断里完成，内核给不出进程：按本机端口找监听它的服务进程
            if !lock(&state.tcp_in).should_report(remote, ev.sport) {
                return None;
            }
            // tracepoint 不分网络命名空间：目的是宿主机自己的地址才查宿主机的监听表。
            // 连到容器里服务的（LXC 有自己的地址）按端口查会错归到宿主机上同端口的进程，只认出是哪个容器
            let pid = if is_host_addr(local) {
                lock(&state.listeners).owner(ev.sport).map(|o| o.pid)
            } else {
                None
            };
            let mut info = conn_info(
                state,
                pid.unwrap_or(0),
                "tcp",
                remote,
                ev.dport,
                local,
                ev.sport,
            );
            info.inbound = true;
            // 域名回填只对出站有意义：入站的目的是本机，那个「域名」只是有人解析过本机地址
            info.hostname = None;
            if pid.is_none() {
                info.container = container::lxc_by_ip(local);
            }
            Some(netwatch::conn_event(agent_id, &info))
        }
        CONN_UDP_OUT => {
            // 从本机 UDP 服务端口发出的是服务给客户端的回包（NTP、syslog、corosync 之类），不算出站
            if lock(&state.listeners).serves_udp(ev.sport)
                || !lock(&state.udp_out).should_report(remote, ev.dport)
            {
                return None;
            }
            // 未 connect 的套接字（sendto）在内核里源地址还是未指定，发包时才按路由选；
            // 能照同样的路由查到出口地址就用，查不到保持未指定，组装时省略、不当真实地址报
            let local = local
                .is_unspecified()
                .then(|| egress_source(ev.pid, remote))
                .flatten()
                .unwrap_or(local);
            let info = conn_info(state, ev.pid, "udp", local, ev.sport, remote, ev.dport);
            Some(netwatch::conn_event(agent_id, &info))
        }
        CONN_TCP_OUT => {
            if !lock(&state.tcp_out).should_report(remote, ev.dport) {
                return None;
            }
            let info = conn_info(state, ev.pid, "tcp", local, ev.sport, remote, ev.dport);
            Some(netwatch::conn_event(agent_id, &info))
        }
        _ => None,
    }
}

/// 发起方在前：出站是本机 → 对端，入站是对端 → 本机服务。进程按 pid 查注册表，
/// 没登记的（极少数）连接发生时进程还在，现读 comm 与 cgroup
fn conn_info(
    state: &ConnState,
    pid: u32,
    proto: &'static str,
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
) -> ConnInfo {
    // 连接归到被折叠的进程上：它（和被折叠的祖先）压着的启动事件转入待发，由发送循环带出去
    let known = (pid != 0)
        .then(|| {
            let mut reg = lock(&state.registry);
            reg.reveal(pid);
            reg.known(pid)
        })
        .flatten();
    let name = known
        .as_ref()
        .map(|k| k.name.clone())
        .filter(|n| !n.is_empty())
        .or_else(|| {
            (pid != 0)
                .then(|| std::fs::read_to_string(format!("/proc/{pid}/comm")).ok())
                .flatten()
                .map(|s| s.trim_end().to_string())
        });
    let container = match &known {
        Some(k) => k.container.clone(),
        None if pid != 0 => container::of(pid),
        None => None,
    };
    ConnInfo {
        proto,
        inbound: false,
        pid,
        guid: known.as_ref().map(|k| k.guid),
        exe: known.as_ref().and_then(|k| k.exe.clone()),
        name,
        src,
        sport,
        dst,
        dport,
        container,
        hostname: super::dnsnames::hostname_of(dst),
        command: known.as_ref().and_then(|k| k.command.clone()),
    }
}

/// 发往 remote 的包会用的源地址：在 agent 自己的网络命名空间里对 remote 做一次 UDP connect
/// （只查路由、不发包），取内核选出的本端地址。发起进程不在同一网络命名空间（容器自己的网络）时
/// 查出来的是宿主机的地址，不如不填；进程已退出也一样。不看发起套接字的 SO_MARK / 绑定网卡，
/// 策略路由下可能选到本机另一个地址——总归是本机自己的地址，不会把连接安到别的主机头上
fn egress_source(pid: u32, remote: IpAddr) -> Option<IpAddr> {
    let netns = |who: &str| std::fs::read_link(format!("/proc/{who}/ns/net")).ok();
    if pid == 0 || netns(&pid.to_string())? != netns("self")? {
        return None;
    }
    let any: IpAddr = if remote.is_ipv4() {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv6Addr::UNSPECIFIED.into()
    };
    let sock = std::net::UdpSocket::bind((any, 0)).ok()?;
    sock.connect((remote, 9)).ok()?;
    let ip = sock.local_addr().ok()?.ip().to_canonical();
    (!ip.is_unspecified()).then_some(ip)
}

/// 地址是不是宿主机自己网络命名空间里的地址（含回环）。地址会变（DHCP、新网卡），每分钟刷新
fn is_host_addr(ip: IpAddr) -> bool {
    static ADDRS: std::sync::OnceLock<Mutex<(Vec<IpAddr>, Option<Instant>)>> =
        std::sync::OnceLock::new();
    let mut addrs = lock(ADDRS.get_or_init(Default::default));
    if addrs
        .1
        .is_none_or(|t| t.elapsed() >= Duration::from_secs(60))
    {
        addrs.0 = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .map(|i| i.addr.ip())
            .collect();
        addrs.1 = Some(Instant::now());
    }
    ip.is_loopback() || addrs.0.contains(&ip)
}

/// DNS 查询源端口的归属保留多久：抓包与 eBPF 事件走两条路，先后差不了几秒
const OWNER_TTL: Duration = Duration::from_secs(10);

/// dnswatch 用：源端口 → 最近从这个端口发 DNS 查询的进程
fn dns_resolver(
    registry: Shared<ProcessRegistry>,
    owners: Shared<HashMap<u16, (u32, Instant)>>,
) -> dnswatch::Resolver {
    Arc::new(move |port| {
        let (pid, at) = *lock(&owners).get(&port)?;
        if at.elapsed() >= OWNER_TTL {
            return None;
        }
        // 查询归到被折叠的进程上：压着的启动事件转入待发，下一次进程或网络事件发送时带出去
        let known = {
            let mut reg = lock(&registry);
            reg.reveal(pid);
            reg.known(pid)
        };
        Some(match known {
            Some(k) => Origin {
                pid,
                guid: Some(k.guid),
                name: Some(k.name).filter(|n| !n.is_empty()),
                exe: k.exe,
                container: k.container,
                command: k.command,
            },
            None => Origin {
                pid,
                guid: None,
                name: std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .ok()
                    .map(|s| s.trim_end().to_string()),
                exe: None,
                container: container::of(pid),
                command: None,
            },
        })
    })
}

/// 本机监听端口：TCP 端口 → 服务进程，UDP 服务端口集合。监听表很少变：TCP 查不到才重扫（每秒最多一次，
/// 刚起的服务马上就有入站），UDP 每 30 秒刷新。容器自己网络命名空间里的监听在这里看不到，那类入站不归属进程
#[derive(Default)]
struct Listeners {
    scanner: Scanner,
    tcp: HashMap<u16, Owner>,
    udp: std::collections::HashSet<u16>,
    scanned: Option<Instant>,
}

impl Listeners {
    fn refresh(&mut self, hit: bool, every: Duration) {
        let fresh = self.scanned.is_some_and(|t| t.elapsed() < every);
        if hit || fresh {
            return;
        }
        let listeners = self.scanner.scan();
        self.udp = listeners
            .iter()
            .filter(|l| l.proto == Proto::Udp)
            .map(|l| l.port)
            .collect();
        self.tcp = listeners
            .into_iter()
            .filter(|l| l.proto == Proto::Tcp)
            .filter_map(|l| Some((l.port, l.owner?)))
            .collect();
        self.scanned = Some(Instant::now());
    }

    fn owner(&mut self, port: u16) -> Option<&Owner> {
        self.refresh(self.tcp.contains_key(&port), Duration::from_secs(1));
        self.tcp.get(&port)
    }

    /// 端口是不是本机的 UDP 服务端口。临时端口不在监听表里（inventory_linux 已剔除）；按 30 秒周期刷新
    fn serves_udp(&mut self, port: u16) -> bool {
        self.refresh(false, Duration::from_secs(30));
        self.udp.contains(&port)
    }
}

fn ip_of(family: u16, bytes: &[u8; 16]) -> IpAddr {
    let ip = if family == AF_INET {
        IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        IpAddr::from(*bytes)
    };
    // 双栈套接字上的 IPv4 连接是 ::ffff:a.b.c.d，还原成 IPv4，与 sensor、DNS 应答对得上
    ip.to_canonical()
}

fn to_agent_event(
    agent_id: &str,
    registry: &mut ProcessRegistry,
    ev: &ExecEvent,
) -> Vec<AgentEvent> {
    let name = cstr(&ev.comm);
    let exe = cstr(&ev.filename);
    // 命令行、父进程、属主优先用内核在 exec 时抓的；没抓到（老内核、钩子没挂上）才去 /proc 读，
    // 短命进程那时可能已退场，就只能缺省
    let cmd_line = ev.cmd_line().or_else(|| super::container::cmd_line(ev.pid));
    let ppid = (ev.ppid != 0)
        .then_some(ev.ppid)
        .or_else(|| super::container::ppid(ev.pid));
    // 属主取 exec 那一刻内核给的 uid，同样不怕进程已退场
    let username =
        super::execfacts::username("/etc/passwd", ev.uid).unwrap_or_else(|| ev.uid.to_string());

    emit_process(
        agent_id,
        registry,
        ACTIVITY_LAUNCH,
        ProcessInfo {
            pid: ev.pid,
            name: &name,
            exe: Some(exe.as_ref()),
            cmd_line: cmd_line.as_deref(),
            ppid,
            username,
            ..Default::default()
        },
    )
}

/// 退出事件只有 pid 与退出码（tracepoint 触发时进程已在退出途中），
/// 名字、路径、GUID 与容器走注册表复用启动时的登记。
fn to_exit_event(
    agent_id: &str,
    registry: &mut ProcessRegistry,
    ev: &ExitEvent,
) -> Vec<AgentEvent> {
    emit_process(
        agent_id,
        registry,
        ACTIVITY_TERMINATE,
        ProcessInfo {
            pid: ev.pid,
            exit_code: (ev.has_code != 0).then_some(ev.code as u32),
            ..Default::default()
        },
    )
}

fn cstr(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::mem::offset_of;

    /// 布局必须与 ebpf/src/main.rs 逐字节一致：内核侧原样写、这边原样读
    #[test]
    fn event_layout_matches_kernel_side() {
        assert_eq!(size_of::<ExecEvent>(), 20 + 16 + 256 + ARGV_BUF);
        assert_eq!(offset_of!(ExecEvent, ppid), 4);
        assert_eq!(offset_of!(ExecEvent, uid), 8);
        assert_eq!(offset_of!(ExecEvent, argv_len), 12);
        assert_eq!(offset_of!(ExecEvent, argv_truncated), 16);
        assert_eq!(offset_of!(ExecEvent, comm), 20);
        assert_eq!(offset_of!(ExecEvent, filename), 36);
        assert_eq!(offset_of!(ExecEvent, argv), 292);

        assert_eq!(size_of::<ExitEvent>(), 12);
        assert_eq!(offset_of!(ExitEvent, code), 4);
        assert_eq!(offset_of!(ExitEvent, has_code), 8);

        assert_eq!(size_of::<DupEvent>(), 8);
        assert_eq!(offset_of!(DupEvent, fd), 4);

        assert_eq!(size_of::<ConnEvent>(), 44);
        assert_eq!(offset_of!(ConnEvent, family), 4);
        assert_eq!(offset_of!(ConnEvent, sport), 6);
        assert_eq!(offset_of!(ConnEvent, dport), 8);
        assert_eq!(offset_of!(ConnEvent, kind), 10);
        assert_eq!(offset_of!(ConnEvent, saddr), 12);
        assert_eq!(offset_of!(ConnEvent, daddr), 28);
    }

    /// 真内核验证：加载 eBPF、挂上 dup 退出 tracepoint，bash 子进程把一条 TCP 连接接到 0~2 号描述符，
    /// 要收到它的 DupEvent，且 stdiosock 认出对端。CI 只编译不加载，这条要 root 在目标内核上跑：
    /// `cargo test --features ebpf --no-run` 编出测试程序，`sudo <测试程序> --ignored kernel_reports_stdio_dup`
    #[test]
    #[ignore = "需要 root 与可加载 eBPF 的内核"]
    fn kernel_reports_stdio_dup_to_socket() {
        use aya::maps::perf::AsyncPerfEventArray;
        use aya::util::online_cpus;

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            ensure_memlock_rlimit();
            let mut bpf = load().unwrap();
            for name in ["sys_exit_dup", "sys_exit_dup2", "sys_exit_dup3"] {
                if let Err(e) = attach_tracepoint(&mut bpf, name, "syscalls") {
                    eprintln!("{name}: {e}");
                }
            }
            let mut dups: AsyncPerfEventArray<_> =
                bpf.take_map("DUPS").unwrap().try_into().unwrap();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            for cpu in online_cpus().unwrap() {
                let mut buf = dups.open(cpu, None).unwrap();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut bufs = vec![bytes::BytesMut::with_capacity(64); 16];
                    while let Ok(batch) = buf.read_events(&mut bufs).await {
                        for b in bufs.iter().take(batch.read) {
                            if let Some(ev) = decode::<DupEvent>(b) {
                                let _ = tx.send((ev.pid, ev.fd));
                            }
                        }
                    }
                });
            }
            // 回环连接不报，连本机的非回环地址：路由选出的本端地址
            let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            probe.connect("192.0.2.1:9").unwrap();
            let ip = probe.local_addr().unwrap().ip();
            let listener = std::net::TcpListener::bind((ip, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let mut child = std::process::Command::new("bash")
                .arg("-c")
                .arg(format!(
                    "exec 3<>/dev/tcp/{ip}/{port}; exec 0<&3 1>&3 2>&3; sleep 3"
                ))
                .spawn()
                .unwrap();
            let _conn = listener.accept().unwrap();
            let pid = child.id();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            let (mut fds, mut others) = (Vec::new(), Vec::new());
            while let Ok(Some((p, fd))) = tokio::time::timeout_at(deadline, rx.recv()).await {
                if p != pid {
                    others.push(p);
                    continue;
                }
                fds.push(fd);
                if let Some(s) = stdiosock::connected_tcp(pid, fd) {
                    assert_eq!(s.remote.port(), port);
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            panic!("没认出子进程 {pid} 接到套接字上的标准输入输出：它的描述符 {fds:?}，期间别的进程的 dup 事件：{others:?}");
        });
    }

    #[test]
    fn fork_layout_comes_from_the_format_file() {
        // Debian 6.1
        let old = "name: sched_process_fork
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:char parent_comm[16];\toffset:8;\tsize:16;\tsigned:1;
\tfield:pid_t parent_pid;\toffset:24;\tsize:4;\tsigned:1;
\tfield:char child_comm[16];\toffset:28;\tsize:16;\tsigned:1;
\tfield:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;";
        assert_eq!(field_offset(old, "child_pid"), Some(44));
        // PVE 7.0：comm 改成 __data_loc，布局整体前移
        let new = "\tfield:__data_loc char[] parent_comm;\toffset:8;\tsize:4;\tsigned:0;
\tfield:pid_t parent_pid;\toffset:12;\tsize:4;\tsigned:1;
\tfield:__data_loc char[] child_comm;\toffset:16;\tsize:4;\tsigned:0;
\tfield:pid_t child_pid;\toffset:20;\tsize:4;\tsigned:1;";
        assert_eq!(field_offset(new, "child_pid"), Some(20));
        assert_eq!(field_offset(new, "child_comm"), Some(16));
        assert_eq!(field_offset(new, "nope"), None);
    }

    #[test]
    fn kernel_argv_joins_like_proc_cmdline() {
        let mut ev: ExecEvent = decode(&vec![0u8; size_of::<ExecEvent>()]).unwrap();
        assert_eq!(ev.cmd_line(), None, "没抓到就是 None");
        let args = b"sh\0-c\0\0curl x | sh\0";
        ev.argv[..args.len()].copy_from_slice(args);
        ev.argv_len = args.len() as u32;
        assert_eq!(ev.cmd_line().as_deref(), Some("sh -c curl x | sh"));
        ev.argv_truncated = 1;
        assert_eq!(ev.cmd_line().as_deref(), Some("sh -c curl x | sh …"));
    }

    /// 真内核验证：起一个转瞬即逝的 sh 子进程，exec 事件里要有它的命令行，父进程指向本测试进程。
    /// 需要 root：`cargo test --features ebpf --no-run` 后 `sudo <测试程序> --ignored kernel_captures_short_lived`
    #[test]
    #[ignore = "需要 root 与可加载 eBPF 的内核"]
    fn kernel_captures_short_lived_exec() {
        use aya::maps::perf::AsyncPerfEventArray;
        use aya::util::online_cpus;

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            ensure_memlock_rlimit();
            let mut bpf = load().unwrap();
            attach_tracepoint(&mut bpf, "sched_process_exec", "sched").unwrap();
            attach_exec_context(&mut bpf);
            let mut events: AsyncPerfEventArray<_> =
                bpf.take_map("EVENTS").unwrap().try_into().unwrap();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            for cpu in online_cpus().unwrap() {
                let mut buf = events.open(cpu, Some(EXEC_BUFFER_PAGES)).unwrap();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut bufs = vec![bytes::BytesMut::with_capacity(4096); 8];
                    while let Ok(batch) = buf.read_events(&mut bufs).await {
                        for b in bufs.iter().take(batch.read) {
                            if let Some(ev) = decode::<ExecEvent>(b) {
                                let _ = tx.send((ev.pid, ev.ppid, ev.uid, ev.cmd_line()));
                            }
                        }
                    }
                });
            }
            let marker = format!("openxdr-argv-{}", std::process::id());
            let child = std::process::Command::new("/bin/sh")
                .args(["-c", "exit 0", &marker])
                .status()
                .unwrap();
            assert!(child.success());
            let me = std::process::id();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            while let Ok(Some((pid, ppid, uid, cmd))) =
                tokio::time::timeout_at(deadline, rx.recv()).await
            {
                if cmd.as_deref().is_some_and(|c| c.contains(&marker)) {
                    eprintln!("pid {pid} ppid {ppid} uid {uid} cmd {cmd:?}");
                    assert_eq!(
                        cmd.as_deref(),
                        Some(format!("/bin/sh -c exit 0 {marker}").as_str())
                    );
                    assert_eq!(ppid, me, "父进程应是本测试进程");
                    return;
                }
            }
            panic!("没收到带命令行的 exec 事件");
        });
    }

    fn exit_bytes(pid: u32, code: i32, has_code: u32) -> Vec<u8> {
        [
            pid.to_ne_bytes(),
            code.to_ne_bytes(),
            has_code.to_ne_bytes(),
        ]
        .concat()
    }

    fn conn_bytes(pid: u32, family: u16, ports: [u16; 3], saddr: &[u8], daddr: &[u8]) -> Vec<u8> {
        let mut b = pid.to_ne_bytes().to_vec();
        b.extend(family.to_ne_bytes());
        for p in ports {
            b.extend(p.to_ne_bytes());
        }
        let mut s = [0u8; 16];
        s[..saddr.len()].copy_from_slice(saddr);
        let mut d = [0u8; 16];
        d[..daddr.len()].copy_from_slice(daddr);
        b.extend(s);
        b.extend(d);
        b
    }

    #[test]
    fn decode_rejects_short_record() {
        let b = exit_bytes(1, 0, 0);
        assert!(decode::<ExitEvent>(&b[..b.len() - 1]).is_none());
        assert!(decode::<ExitEvent>(&[]).is_none());
        assert!(
            decode::<ConnEvent>(&b).is_none(),
            "退出事件长度不够一条连接事件"
        );
    }

    #[test]
    fn decode_reads_fields_and_ignores_padding() {
        // perf 记录按 8 字节补齐，尾部的补齐字节不影响解码
        let mut b = exit_bytes(4242, 3, 1);
        b.extend([0xaa; 4]);
        let ev = decode::<ExitEvent>(&b).unwrap();
        assert_eq!((ev.pid, ev.code, ev.has_code), (4242, 3, 1));
    }

    #[test]
    fn decode_handles_unaligned_source() {
        let raw = conn_bytes(
            7,
            AF_INET,
            [40000, 443, CONN_TCP_OUT],
            &[10, 0, 0, 1],
            &[1, 1, 1, 1],
        );
        // 错开一个字节，保证源地址不满足 4 字节对齐
        let mut shifted = vec![0u8];
        shifted.extend(&raw);
        let ev = decode::<ConnEvent>(&shifted[1..]).unwrap();
        assert_eq!(ev.pid, 7);
        assert_eq!(
            (ev.family, ev.sport, ev.dport, ev.kind),
            (AF_INET, 40000, 443, CONN_TCP_OUT)
        );
        assert_eq!(&ev.saddr[..4], &[10, 0, 0, 1]);
        assert_eq!(&ev.daddr[..4], &[1, 1, 1, 1]);
    }

    #[test]
    fn decode_exec_event_strings() {
        let argv = b"bash\0-i\0";
        let mut b = Vec::new();
        for v in [99u32, 7, 1000, argv.len() as u32, 0] {
            b.extend(v.to_ne_bytes());
        }
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"bash");
        let mut filename = [0u8; 256];
        filename[..9].copy_from_slice(b"/bin/bash");
        let mut args = [0u8; ARGV_BUF];
        args[..argv.len()].copy_from_slice(argv);
        b.extend(comm);
        b.extend(filename);
        b.extend(args);
        let ev = decode::<ExecEvent>(&b).unwrap();
        assert_eq!((ev.pid, ev.ppid, ev.uid), (99, 7, 1000));
        assert_eq!(cstr(&ev.comm), "bash");
        assert_eq!(cstr(&ev.filename), "/bin/bash");
        assert_eq!(ev.cmd_line().as_deref(), Some("bash -i"));
    }

    #[test]
    fn cstr_stops_at_nul_or_end() {
        assert_eq!(cstr(b"abc\0def"), "abc");
        assert_eq!(cstr(b"\0abc"), "");
        // comm 正好 16 字节、没有结尾 NUL 时取满整个数组
        assert_eq!(cstr(b"0123456789abcdef"), "0123456789abcdef");
        assert_eq!(cstr(b"a\xffb\0"), "a\u{fffd}b");
    }

    #[test]
    fn ip_of_by_family() {
        let mut v4 = [0u8; 16];
        v4[..4].copy_from_slice(&[192, 168, 1, 5]);
        // IPv4 只看前 4 字节，后面的残留不影响
        v4[4] = 0xff;
        assert_eq!(
            ip_of(AF_INET, &v4),
            "192.168.1.5".parse::<IpAddr>().unwrap()
        );

        let v6: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(ip_of(10, &v6.octets()), IpAddr::V6(v6));

        // 双栈套接字上的 v4 映射地址还原成 IPv4
        let mapped: std::net::Ipv6Addr = "::ffff:8.8.8.8".parse().unwrap();
        assert_eq!(
            ip_of(10, &mapped.octets()),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
    }

    fn exec_event(pid: u32) -> ExecEvent {
        let mut comm = [0u8; 16];
        comm[..6].copy_from_slice(b"probe1");
        let mut filename = [0u8; 256];
        let path = b"/nonexistent/openxdr/probe1";
        filename[..path.len()].copy_from_slice(path);
        // argv_len 为 0、ppid 为 0：内核没抓到，走读 /proc 的回落路径
        ExecEvent {
            pid,
            ppid: 0,
            // SAFETY: getuid 没有前置条件、不会失败
            uid: unsafe { libc::getuid() },
            argv_len: 0,
            argv_truncated: 0,
            comm,
            filename,
            argv: [0; ARGV_BUF],
        }
    }

    fn process_json(events: &[AgentEvent]) -> Value {
        let last = events.last().expect("应产出进程事件");
        serde_json::from_str(&last.raw_json).unwrap()
    }

    #[test]
    fn exec_then_exit_carries_code_only_when_known() {
        // 用本进程的 pid：to_agent_event 会去 /proc 补命令行与父进程
        let pid = std::process::id();
        let mut reg = ProcessRegistry::default();

        let launch = to_agent_event("agent-1", &mut reg, &exec_event(pid));
        let v = process_json(&launch);
        assert_eq!(v["process"]["pid"], pid);
        assert_eq!(v["process"]["name"], "probe1");
        assert_eq!(v["process"]["file"]["path"], "/nonexistent/openxdr/probe1");
        assert_eq!(v["activity_id"], ACTIVITY_LAUNCH);

        let exit = ExitEvent {
            pid,
            code: 0,
            has_code: 0,
        };
        let v = process_json(&to_exit_event("agent-1", &mut reg, &exit));
        assert_eq!(v["activity_id"], ACTIVITY_TERMINATE);
        assert_eq!(
            v["process"]["name"], "probe1",
            "退出事件的名字来自启动时的登记"
        );
        assert!(
            v["process"]["exit_code"].is_null(),
            "has_code 为 0 时不编造退出码"
        );

        to_agent_event("agent-1", &mut reg, &exec_event(pid));
        let exit = ExitEvent {
            pid,
            code: 3,
            has_code: 1,
        };
        let v = process_json(&to_exit_event("agent-1", &mut reg, &exit));
        assert_eq!(v["process"]["exit_code"], 3);
    }

    #[test]
    fn exit_of_unknown_process_is_dropped() {
        let mut reg = ProcessRegistry::default();
        let exit = ExitEvent {
            pid: 999_999_999,
            code: 1,
            has_code: 1,
        };
        assert!(to_exit_event("agent-1", &mut reg, &exit).is_empty());
    }

    fn conn_state() -> ConnState {
        ConnState {
            registry: Default::default(),
            tcp_out: Default::default(),
            tcp_in: Default::default(),
            udp_out: Default::default(),
            listeners: Default::default(),
            dns_owners: Default::default(),
        }
    }

    fn conn(kind: u16, local: [u8; 4], sport: u16, remote: [u8; 4], dport: u16) -> ConnEvent {
        decode(&conn_bytes(
            0,
            AF_INET,
            [sport, dport, kind],
            &local,
            &remote,
        ))
        .unwrap()
    }

    #[test]
    fn dns_query_only_records_source_port_owner() {
        let state = conn_state();
        let mut ev = conn(
            CONN_UDP_OUT,
            [10, 0, 0, 5],
            53001,
            [127, 0, 0, 53],
            DNS_PORT,
        );
        ev.pid = 4321;
        // 解析器在回环上也要记：这一步在回环过滤之前
        assert!(to_conn_event("agent-1", &state, &ev).is_none());
        assert_eq!(lock(&state.dns_owners).get(&53001).map(|o| o.0), Some(4321));
    }

    #[test]
    fn loopback_multicast_broadcast_are_noise() {
        let state = conn_state();
        for remote in [[127, 0, 0, 1], [224, 0, 0, 251], [255, 255, 255, 255]] {
            let ev = conn(CONN_TCP_OUT, [10, 0, 0, 5], 40000, remote, 443);
            assert!(
                to_conn_event("agent-1", &state, &ev).is_none(),
                "{remote:?}"
            );
        }
    }

    #[test]
    fn unknown_kind_is_ignored() {
        let state = conn_state();
        let ev = conn(9, [10, 0, 0, 5], 40000, [203, 0, 113, 9], 443);
        assert!(to_conn_event("agent-1", &state, &ev).is_none());
    }

    #[test]
    fn tcp_out_reports_once_per_window() {
        let state = conn_state();
        let ev = conn(CONN_TCP_OUT, [10, 0, 0, 5], 40000, [203, 0, 113, 9], 443);
        let out = to_conn_event("agent-1", &state, &ev).expect("首次出站应上报");
        assert_eq!(out.conn_tuple, "tcp:10.0.0.5:40000>203.0.113.9:443");
        let v: Value = serde_json::from_str(&out.raw_json).unwrap();
        assert_eq!(v["connection_info"]["direction"], "outbound");
        assert!(v.get("process").is_none(), "pid 为 0 时不写进程");
        assert!(
            to_conn_event("agent-1", &state, &ev).is_none(),
            "窗口内同一目标只报一次"
        );
    }

    /// sendto 的 UDP 套接字源地址未指定：同一网络命名空间里按路由查出口地址，
    /// 查不到（进程不存在）就留空，不报 0.0.0.0
    #[test]
    fn udp_out_unspecified_source() {
        let state = conn_state();
        let mut ev = conn(CONN_UDP_OUT, [0, 0, 0, 0], 41641, [127, 0, 0, 2], 41641);
        ev.pid = std::process::id();
        assert_eq!(
            egress_source(ev.pid, IpAddr::from([127, 0, 0, 2])),
            Some(IpAddr::from([127, 0, 0, 1])),
            "同一网络命名空间按路由取出口地址"
        );
        assert_eq!(egress_source(0, IpAddr::from([127, 0, 0, 2])), None);

        // 不存在的进程查不到命名空间：保持未指定，事件里省略源地址
        ev.pid = u32::MAX;
        ev.daddr[..4].copy_from_slice(&[203, 0, 113, 9]);
        let out = to_conn_event("agent-1", &state, &ev).expect("UDP 出站应上报");
        assert_eq!(out.conn_tuple, "udp::41641>203.0.113.9:41641");
        let v: Value = serde_json::from_str(&out.raw_json).unwrap();
        assert!(v["src_endpoint"].get("ip").is_none());
    }

    #[test]
    fn tcp_in_puts_remote_first() {
        let state = conn_state();
        // 本机端是文档地址，必不是宿主机地址：不去查宿主机监听表
        let ev = conn(CONN_TCP_IN, [192, 0, 2, 10], 5432, [198, 51, 100, 7], 51515);
        let out = to_conn_event("agent-1", &state, &ev).expect("入站应上报");
        assert_eq!(out.conn_tuple, "tcp:198.51.100.7:51515>192.0.2.10:5432");
        let v: Value = serde_json::from_str(&out.raw_json).unwrap();
        assert_eq!(v["connection_info"]["direction"], "inbound");
        assert!(v["dst_endpoint"].get("hostname").is_none());
    }
}
