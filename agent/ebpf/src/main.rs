//! eBPF 内核侧：tracepoint sched_process_exec 捕获所有 execve（含短命进程）；
//! tracepoint sock:inet_sock_set_state 捕获 TCP 出站连接发起（SYN_SENT）。

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel_str_bytes},
    macros::{map, tracepoint},
    maps::PerfEventArray,
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

// /sys/kernel/tracing/events/sock/inet_sock_set_state/format
const NEWSTATE_OFFSET: usize = 20;
const SPORT_OFFSET: usize = 24;
const DPORT_OFFSET: usize = 26;
const FAMILY_OFFSET: usize = 28;
const PROTOCOL_OFFSET: usize = 30;
const SADDR_OFFSET: usize = 32;
const DADDR_OFFSET: usize = 36;
const SADDR6_OFFSET: usize = 40;
const DADDR6_OFFSET: usize = 56;

const TCP_SYN_SENT: i32 = 2;
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
    // 只看 TCP 进入 SYN_SENT：本机主动发起的出站连接，且必然在发起进程的上下文里
    let newstate: i32 = unsafe { ctx.read_at(NEWSTATE_OFFSET)? };
    if newstate != TCP_SYN_SENT {
        return Ok(());
    }
    let protocol: u16 = unsafe { ctx.read_at(PROTOCOL_OFFSET)? };
    if protocol != IPPROTO_TCP {
        return Ok(());
    }

    let family: u16 = unsafe { ctx.read_at(FAMILY_OFFSET)? };
    let mut event = ConnEvent {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
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
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
