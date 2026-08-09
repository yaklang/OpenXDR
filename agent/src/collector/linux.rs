//! Linux eBPF 采集：tracepoint sched_process_exec 抓进程启动，
//! sched_process_exit 抓进程退出，tracepoint sock:inet_sock_set_state 抓 TCP 出站连接。
//! 捕获所有 execve（含短命进程），需要 root/CAP_BPF；
//! 失败按 netlink proc connector → 轮询逐级回落，不跳档。

use std::net::IpAddr;

use super::netwatch::{self, ConnInfo, ConnSampler};
use super::{
    ACTIVITY_LAUNCH, ACTIVITY_TERMINATE, EventSink, ProcessInfo, ProcessRegistry, netlink, poll,
    process_event, seeded_registry, username_of,
};
use crate::pb::AgentEvent;

// 与 ebpf/src/main.rs 中的定义保持一致
#[repr(C)]
#[derive(Clone, Copy)]
struct ExecEvent {
    pid: u32,
    comm: [u8; 16],
    filename: [u8; 256],
}

// 与 ebpf/src/main.rs 中的定义保持一致
#[repr(C)]
#[derive(Clone, Copy)]
struct ExitEvent {
    pid: u32,
}

// 与 ebpf/src/main.rs 中的定义保持一致
#[repr(C)]
#[derive(Clone, Copy)]
struct ConnEvent {
    pid: u32,
    family: u16,
    sport: u16,
    dport: u16,
    _pad: u16,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

const AF_INET: u16 = 2;

pub async fn run(agent_id: String, tx: EventSink, collect_network: bool) {
    if let Err(e) = run_ebpf(agent_id.clone(), tx.clone(), collect_network).await {
        eprintln!("eBPF 采集不可用（{e}），尝试 netlink proc connector");
        // 与默认构建同一降级链：netlink 拿不到再退轮询，不直接从最强掉到最弱
        match netlink::spawn(agent_id.clone(), tx.clone()) {
            Ok(()) => eprintln!("采集方式: netlink proc connector（用户态，捕获全部 exec）"),
            Err(e) => {
                eprintln!("netlink 采集不可用（{e}），回落到轮询采集（会漏短命进程）");
                poll::run(agent_id, tx).await;
            }
        }
    }
}

async fn run_ebpf(
    agent_id: String,
    tx: EventSink,
    collect_network: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use aya::maps::perf::AsyncPerfEventArray;
    use aya::programs::TracePoint;
    use aya::util::online_cpus;

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/openxdr-ebpf"
    )))?;

    let program: &mut TracePoint = bpf
        .program_mut("sched_process_exec")
        .ok_or("eBPF 程序缺失")?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    let exit_program: &mut TracePoint = bpf
        .program_mut("sched_process_exit")
        .ok_or("eBPF 程序缺失")?
        .try_into()?;
    exit_program.load()?;
    exit_program.attach("sched", "sched_process_exit")?;

    let mut events: AsyncPerfEventArray<_> = bpf
        .take_map("EVENTS")
        .ok_or("EVENTS map 缺失")?
        .try_into()?;

    let mut exits: AsyncPerfEventArray<_> =
        bpf.take_map("EXITS").ok_or("EXITS map 缺失")?.try_into()?;

    // exec 事件按 CPU 分发到多个任务，进程血缘是全局的，注册表要共享。
    // exec 频率远低于包速率，这把锁的争用可以忽略。
    let registry = std::sync::Arc::new(std::sync::Mutex::new(seeded_registry()));

    for cpu in online_cpus().map_err(|(_, e)| e)? {
        let mut buf = events.open(cpu, None)?;
        let tx = tx.clone();
        let agent_id = agent_id.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            let mut bufs = (0..8)
                .map(|_| bytes::BytesMut::with_capacity(2048))
                .collect::<Vec<_>>();
            loop {
                let Ok(batch) = buf.read_events(&mut bufs).await else {
                    return;
                };
                for b in bufs.iter().take(batch.read) {
                    if b.len() < size_of::<ExecEvent>() {
                        continue;
                    }
                    let ev = unsafe { std::ptr::read_unaligned(b.as_ptr() as *const ExecEvent) };
                    let event = {
                        let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
                        to_agent_event(&agent_id, &mut reg, &ev)
                    };
                    if !tx.send(event) {
                        return;
                    }
                }
            }
        });
    }

    for cpu in online_cpus().map_err(|(_, e)| e)? {
        let mut buf = exits.open(cpu, None)?;
        let tx = tx.clone();
        let agent_id = agent_id.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            let mut bufs = (0..8)
                .map(|_| bytes::BytesMut::with_capacity(256))
                .collect::<Vec<_>>();
            loop {
                let Ok(batch) = buf.read_events(&mut bufs).await else {
                    return;
                };
                for b in bufs.iter().take(batch.read) {
                    if b.len() < size_of::<ExitEvent>() {
                        continue;
                    }
                    let ev = unsafe { std::ptr::read_unaligned(b.as_ptr() as *const ExitEvent) };
                    let event = {
                        let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
                        to_exit_event(&agent_id, &mut reg, &ev)
                    };
                    if !tx.send(event) {
                        return;
                    }
                }
            }
        });
    }

    // 网络采集独立降级：老内核没有 inet_sock_set_state 时进程采集照常
    if collect_network {
        match spawn_conn_readers(&mut bpf, &agent_id, &tx, &registry).await {
            Ok(()) => eprintln!("网络采集: eBPF inet_sock_set_state（TCP 出站，60s 采样）"),
            Err(e) => eprintln!("网络采集不可用（{e}）"),
        }
    }

    // 常驻：bpf 句柄在本栈上保活，程序保持挂载
    std::future::pending::<()>().await;
    Ok(())
}

/// 挂载出站连接 tracepoint 并按 CPU 派发读取任务。
async fn spawn_conn_readers(
    bpf: &mut aya::Ebpf,
    agent_id: &str,
    tx: &EventSink,
    registry: &std::sync::Arc<std::sync::Mutex<ProcessRegistry>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use aya::maps::perf::AsyncPerfEventArray;
    use aya::programs::TracePoint;
    use aya::util::online_cpus;

    let program: &mut TracePoint = bpf
        .program_mut("inet_sock_set_state")
        .ok_or("eBPF 程序缺失")?
        .try_into()?;
    program.load()?;
    program.attach("sock", "inet_sock_set_state")?;

    let mut conns: AsyncPerfEventArray<_> =
        bpf.take_map("CONNS").ok_or("CONNS map 缺失")?.try_into()?;

    // 采样表跨 CPU 共享：同一目标不因内核把事件派到不同 CPU 而重复上报
    let sampler = std::sync::Arc::new(std::sync::Mutex::new(ConnSampler::default()));

    for cpu in online_cpus().map_err(|(_, e)| e)? {
        let mut buf = conns.open(cpu, None)?;
        let tx = tx.clone();
        let agent_id = agent_id.to_string();
        let registry = registry.clone();
        let sampler = sampler.clone();
        tokio::spawn(async move {
            let mut bufs = (0..8)
                .map(|_| bytes::BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop {
                let Ok(batch) = buf.read_events(&mut bufs).await else {
                    return;
                };
                for b in bufs.iter().take(batch.read) {
                    if b.len() < size_of::<ConnEvent>() {
                        continue;
                    }
                    let ev = unsafe { std::ptr::read_unaligned(b.as_ptr() as *const ConnEvent) };
                    let Some(event) = to_conn_event(&agent_id, &registry, &sampler, &ev) else {
                        continue;
                    };
                    if !tx.send(event) {
                        return;
                    }
                }
            }
        });
    }
    Ok(())
}

fn to_conn_event(
    agent_id: &str,
    registry: &std::sync::Mutex<ProcessRegistry>,
    sampler: &std::sync::Mutex<ConnSampler>,
    ev: &ConnEvent,
) -> Option<AgentEvent> {
    let dst = ip_of(ev.family, &ev.daddr);
    // 本机自娱自乐的连接没有检测价值
    if dst.is_loopback() {
        return None;
    }
    if !sampler
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .should_report(dst, ev.dport)
    {
        return None;
    }
    let guid = registry
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .guid_of(ev.pid);
    Some(netwatch::conn_event(
        agent_id,
        &ConnInfo {
            pid: ev.pid,
            guid,
            src: ip_of(ev.family, &ev.saddr),
            sport: ev.sport,
            dst,
            dport: ev.dport,
        },
    ))
}

fn ip_of(family: u16, bytes: &[u8; 16]) -> IpAddr {
    if family == AF_INET {
        IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        IpAddr::from(*bytes)
    }
}

fn to_agent_event(agent_id: &str, registry: &mut ProcessRegistry, ev: &ExecEvent) -> AgentEvent {
    let name = cstr(&ev.comm);
    let exe = cstr(&ev.filename);
    // exec 瞬间从 /proc 补充命令行和父进程；短命进程可能已退场，拿不到就算了
    let cmd_line = std::fs::read(format!("/proc/{}/cmdline", ev.pid))
        .ok()
        .map(|b| {
            b.split(|c| *c == 0)
                .filter(|s| !s.is_empty())
                .map(String::from_utf8_lossy)
                .collect::<Vec<_>>()
                .join(" ")
        });
    let ppid = std::fs::read_to_string(format!("/proc/{}/status", ev.pid))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("PPid:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        });

    process_event(
        agent_id,
        registry,
        ACTIVITY_LAUNCH,
        ProcessInfo {
            pid: ev.pid,
            name: &name,
            exe: Some(exe.as_ref()),
            cmd_line: cmd_line.as_deref(),
            ppid,
            username: username_of(ev.pid),
            ..Default::default()
        },
    )
}

/// 退出事件只有 pid 可查（tracepoint 触发时进程已在退出途中），
/// 其余字段留空；GUID 走注册表复用启动时的映射。
fn to_exit_event(agent_id: &str, registry: &mut ProcessRegistry, ev: &ExitEvent) -> AgentEvent {
    process_event(
        agent_id,
        registry,
        ACTIVITY_TERMINATE,
        ProcessInfo {
            pid: ev.pid,
            ..Default::default()
        },
    )
}

fn cstr(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
}
