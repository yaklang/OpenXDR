//! 抓包层。后端抽象成 trait，当前实现 AF_PACKET v3；
//! 二期可加 AF_XDP 后端（40G 线速）而不动上层解码/流表。

pub mod afpacket;

/// 抓包后端：向 worker 交付原始帧。
pub trait Capture {
    /// 阻塞取下一批帧，对每帧调用 `f`。帧数据是 mmap 环形缓冲的借用，零拷贝。
    fn poll_batch(&mut self, f: &mut dyn FnMut(&[u8], u64)) -> std::io::Result<usize>;

    /// 内核丢包统计（累计）。
    fn dropped(&self) -> u64;
}
