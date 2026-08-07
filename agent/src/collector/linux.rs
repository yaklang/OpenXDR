//! Linux eBPF 采集：tracepoint sched_process_exec。
//! 捕获所有 execve（含短命进程），需要 root/CAP_BPF；失败回落轮询。

use tokio::sync::mpsc;

use super::{poll, process_event, ProcessRegistry};
use crate::pb::AgentEvent;

// 与 ebpf/src/main.rs 中的定义保持一致
#[repr(C)]
#[derive(Clone, Copy)]
struct ExecEvent {
    pid: u32,
    comm: [u8; 16],
    filename: [u8; 256],
}

pub async fn run(agent_id: String, tx: mpsc::Sender<AgentEvent>) {
    if let Err(e) = run_ebpf(agent_id.clone(), tx.clone()).await {
        eprintln!("eBPF 采集不可用（{e}），回落到轮询采集");
        poll::run(agent_id, tx).await;
    }
}

async fn run_ebpf(
    agent_id: String,
    tx: mpsc::Sender<AgentEvent>,
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

    let mut events: AsyncPerfEventArray<_> =
        bpf.take_map("EVENTS").ok_or("EVENTS map 缺失")?.try_into()?;

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
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
        });
    }

    // 常驻：bpf 句柄在本栈上保活，程序保持挂载
    std::future::pending::<()>().await;
    Ok(())
}

/// 用 /proc 快照预登记现有进程，之后派生的子进程才能找到父。
fn seeded_registry() -> ProcessRegistry {
    let mut registry = ProcessRegistry::default();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for pid in entries
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        {
            registry.seed(pid);
        }
    }
    registry
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
        ev.pid,
        &name,
        Some(exe.as_ref()),
        cmd_line.as_deref(),
        ppid,
        String::new(),
    )
}

fn cstr(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
}
