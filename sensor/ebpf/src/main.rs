//! XDP 侧：把网卡收到的每个包重定向到对应队列的 AF_XDP socket。
//! 没有注册 socket 的队列直接放行，不影响主机正常收包。

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};

/// 每个网卡队列一个 XSK socket，索引就是队列号
#[map]
static XSKS: XskMap = XskMap::with_max_entries(64, 0);

#[xdp]
pub fn openxdr_redirect(ctx: XdpContext) -> u32 {
    let queue = unsafe { (*ctx.ctx).rx_queue_index };
    // 该队列没有挂 socket 时 redirect 失败，此时放行给内核协议栈
    XSKS.redirect(queue, xdp_action::XDP_PASS as u64)
        .unwrap_or(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
