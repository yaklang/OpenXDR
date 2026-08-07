//! XDP 重定向程序的加载与 socket 注册。
//!
//! AF_XDP socket 本身收不到包——必须有 XDP 程序把包 redirect 到 XSKMAP。
//! 程序挂在网卡上，进程退出时自动卸载（句柄随 Ebpf 一起释放）。

use std::os::fd::AsRawFd;

use aya::maps::XskMap;
use aya::programs::{Xdp, XdpMode};

pub struct XdpProgram {
    // 持有 Ebpf 句柄即保持程序挂载，drop 时自动卸载
    _bpf: aya::Ebpf,
    xsks: XskMap<aya::maps::MapData>,
}

impl XdpProgram {
    pub fn attach(iface: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/openxdr-xdp"
        )))?;

        let program: &mut Xdp = bpf
            .program_mut("openxdr_redirect")
            .ok_or("XDP 程序缺失")?
            .try_into()?;
        program.load()?;
        // 优先原生驱动模式，不支持则退回 SKB 模式（性能低但能用）
        if program.attach(iface, XdpMode::Driver).is_err() {
            program.attach(iface, XdpMode::Skb)?;
        }

        let xsks = XskMap::try_from(bpf.take_map("XSKS").ok_or("XSKS map 缺失")?)?;
        Ok(Self { _bpf: bpf, xsks })
    }

    /// 把 AF_XDP socket 登记到对应队列，XDP 程序才知道往哪儿 redirect。
    pub fn register(
        &mut self,
        queue_id: u32,
        socket: &impl AsRawFd,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.xsks.set(queue_id, socket.as_raw_fd(), 0)?;
        Ok(())
    }
}
