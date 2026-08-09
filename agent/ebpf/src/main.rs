//! eBPF 内核侧：tracepoint sched_process_exec 捕获所有 execve（含短命进程）；
//! tracepoint sched_process_exit 捕获进程退出；tracepoint sock:inet_sock_set_state
//! 捕获 TCP 出站连接发起（SYN_SENT）。

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
};

// 与 userspace collector/linux.rs 中的定义保持一致
#[repr(C)]
pub struct ExecEvent {
    pub pid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

#[map]
static EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

// /sys/kernel/tracing/events/sched/sched_process_exec/format:
//   field:__data_loc char[] filename;  offset:8;  size:4
const FILENAME_DATA_LOC_OFFSET: usize = 8;

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_exec(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let mut event = ExecEvent {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        comm: [0; 16],
        filename: [0; 256],
    };
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }

    // __data_loc 低 16 位是 filename 相对事件起始的偏移
    let data_loc: u32 = unsafe { ctx.read_at(FILENAME_DATA_LOC_OFFSET)? };
    let offset = (data_loc & 0xffff) as usize;
    unsafe {
        let src = (ctx.as_ptr() as *const u8).add(offset);
        let _ = bpf_probe_read_kernel_str_bytes(src, &mut event.filename);
    }

    EVENTS.output(ctx, &event, 0);
    Ok(())
}

// 与 userspace collector/linux.rs 中的定义保持一致
#[repr(C)]
pub struct ExitEvent {
    pub pid: u32,
}

#[map]
static EXITS: PerfEventArray<ExitEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    match try_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_exit(ctx: &TracePointContext) -> Result<(), i64> {
    // 退出事件只需 pid：血缘与进程细节由用户态注册表补全
    let event = ExitEvent {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
    };
    EXITS.output(ctx, &event, 0);
    Ok(())
}

// 与 userspace collector/linux.rs 中的定义保持一致
#[repr(C)]
pub struct ConnEvent {
    pub pid: u32,
    pub family: u16,
    pub sport: u16,
    pub dport: u16,
    pub _pad: u16,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

#[map]
static CONNS: PerfEventArray<ConnEvent> = PerfEventArray::new(0);

/// SYN_SENT 时 tracepoint 的 sport 仍是 0。先按 socket 地址记住发起进程，
/// 等 ESTABLISHED（成功）或 CLOSE（失败）拿到内核分配的真实源端口再上报。
#[map]
static CONNECTING: HashMap<u64, u32> = HashMap::with_max_entries(16384, 0);

// /sys/kernel/tracing/events/sock/inet_sock_set_state/format
const NEWSTATE_OFFSET: usize = 20;
const SKADDR_OFFSET: usize = 8;
const SPORT_OFFSET: usize = 24;
const DPORT_OFFSET: usize = 26;
const FAMILY_OFFSET: usize = 28;
const PROTOCOL_OFFSET: usize = 30;
const SADDR_OFFSET: usize = 32;
const DADDR_OFFSET: usize = 36;
const SADDR6_OFFSET: usize = 40;
const DADDR6_OFFSET: usize = 56;

const TCP_SYN_SENT: i32 = 2;
const TCP_ESTABLISHED: i32 = 1;
const TCP_CLOSE: i32 = 7;
const IPPROTO_TCP: u16 = 6;
const AF_INET: u16 = 2;

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_conn(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_conn(ctx: &TracePointContext) -> Result<(), i64> {
    // SYN_SENT 必然在发起进程上下文，但此时源端口尚未写入 tracepoint。
    // 用 skaddr 关联到后续 ESTABLISHED/CLOSE，再输出完整五元组。
    let newstate: i32 = unsafe { ctx.read_at(NEWSTATE_OFFSET)? };
    let protocol: u16 = unsafe { ctx.read_at(PROTOCOL_OFFSET)? };
    if protocol != IPPROTO_TCP {
        return Ok(());
    }
    let skaddr: u64 = unsafe { ctx.read_at(SKADDR_OFFSET)? };
    if newstate == TCP_SYN_SENT {
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        CONNECTING.insert(&skaddr, &pid, 0)?;
        return Ok(());
    }
    if newstate != TCP_ESTABLISHED && newstate != TCP_CLOSE {
        return Ok(());
    }
    let Some(pid) = (unsafe { CONNECTING.get(&skaddr).copied() }) else {
        return Ok(());
    };

    let family: u16 = unsafe { ctx.read_at(FAMILY_OFFSET)? };
    let mut event = ConnEvent {
        pid,
        family,
        sport: unsafe { ctx.read_at(SPORT_OFFSET)? },
        dport: unsafe { ctx.read_at(DPORT_OFFSET)? },
        _pad: 0,
        saddr: [0; 16],
        daddr: [0; 16],
    };
    if family == AF_INET {
        let s: [u8; 4] = unsafe { ctx.read_at(SADDR_OFFSET)? };
        let d: [u8; 4] = unsafe { ctx.read_at(DADDR_OFFSET)? };
        event.saddr[..4].copy_from_slice(&s);
        event.daddr[..4].copy_from_slice(&d);
    } else {
        event.saddr = unsafe { ctx.read_at(SADDR6_OFFSET)? };
        event.daddr = unsafe { ctx.read_at(DADDR6_OFFSET)? };
    }

    CONNS.output(ctx, &event, 0);
    let _ = CONNECTING.remove(&skaddr);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
