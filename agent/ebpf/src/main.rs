//! eBPF 内核侧：tracepoint sched_process_exec，捕获所有 execve，含短命进程。

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel_str_bytes},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    EbpfContext,
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
