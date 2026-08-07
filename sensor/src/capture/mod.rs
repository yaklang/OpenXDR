//! 抓包层。后端抽象成 trait，上层的解码与流表对后端无感。
//!
//! afpacket：任何 Linux 都能跑，不挑网卡驱动，默认后端。
//! afxdp：绕过协议栈，吞吐更高，但需要驱动支持并加载 XDP 程序。

pub mod afpacket;
pub mod afxdp;
pub mod xdp_loader;

/// 抓包后端：向 worker 交付原始帧。
pub trait Capture {
    /// 阻塞取下一批帧，对每帧调用 `f`。帧数据是环形缓冲的借用，零拷贝。
    fn poll_batch(&mut self, f: &mut dyn FnMut(&[u8], u64)) -> std::io::Result<usize>;

    /// 内核丢包统计（累计）。
    fn dropped(&self) -> u64;
}
