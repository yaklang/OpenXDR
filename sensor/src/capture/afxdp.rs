//! AF_XDP 抓包后端：绕过内核协议栈，直接从网卡队列取包。
//!
//! 结构：一块 UMEM（帧内存池）+ 四个环。
//!   FILL  用户态 → 内核：交出空闲帧供网卡填充
//!   RX    内核 → 用户态：收到的包
//!   TX / COMPLETION 本探针只收不发，建了但不用
//!
//! 收包前提是有 XDP 程序把包 redirect 到本 socket，见 ebpf/src/main.rs。
//! 一个 socket 对应一个网卡队列，多队列网卡需要每队列一个 worker。
#![cfg_attr(not(feature = "xdp"), allow(dead_code))]

use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use super::Capture;

const SOL_XDP: libc::c_int = 283;
const AF_XDP: libc::c_int = 44;
const XDP_MMAP_OFFSETS: libc::c_int = 1;
const XDP_RX_RING: libc::c_int = 2;
const XDP_UMEM_REG: libc::c_int = 4;
const XDP_UMEM_FILL_RING: libc::c_int = 5;
const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;

const XDP_PGOFF_RX_RING: libc::off_t = 0;
const XDP_UMEM_PGOFF_FILL_RING: libc::off_t = 0x1_0000_0000;
const XDP_UMEM_PGOFF_COMPLETION_RING: libc::off_t = 0x1_8000_0000;

const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;
const XDP_RING_NEED_WAKEUP: u32 = 1 << 0;
/// NEED_WAKEUP 置位时的 poll 超时（毫秒），同时唤醒内核并让出 CPU
const WAKEUP_POLL_TIMEOUT_MS: libc::c_int = 1000;
/// 无包且内核未置 NEED_WAKEUP 时的短超时 poll（毫秒），消除空闲 100% CPU 忙等
const IDLE_POLL_TIMEOUT_MS: libc::c_int = 20;

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
}

#[repr(C)]
#[derive(Default)]
struct RingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct MmapOffsets {
    rx: RingOffset,
    tx: RingOffset,
    fill: RingOffset,
    completion: RingOffset,
}

#[repr(C)]
struct XdpDesc {
    addr: u64,
    len: u32,
    options: u32,
}

#[repr(C)]
struct SockaddrXdp {
    sxdp_family: u16,
    sxdp_flags: u16,
    sxdp_ifindex: u32,
    sxdp_queue_id: u32,
    sxdp_shared_umem_fd: u32,
}

pub struct Config {
    /// UMEM 帧数，必须是 2 的幂
    pub frame_count: u32,
    pub frame_size: u32,
    pub queue_id: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            frame_count: 4096,
            frame_size: 2048,
            queue_id: 0,
        }
    }
}

/// 无锁单生产者/单消费者环的用户态视图。
struct Ring {
    producer: *mut u32,
    consumer: *mut u32,
    flags: *mut u32,
    desc: *mut u8,
    mask: u32,
    cached_consumer: u32,
}

impl Ring {
    /// # Safety
    /// `base` 指向 XDP 环的 mmap 区域，`off` 是内核经 XDP_MMAP_OFFSETS 给出的偏移，区域至少
    /// 覆盖 `off.desc` 起 `size` 个描述符；`size` 是 2 的幂且等于建环时的大小。
    /// 返回的视图只能在映射存活期间使用。
    unsafe fn new(base: *mut u8, off: &RingOffset, size: u32) -> Self {
        // SAFETY: 按本函数 # Safety，各偏移都由内核给出、落在同一映射内，这里只做指针运算。
        unsafe {
            Self {
                producer: base.add(off.producer as usize) as *mut u32,
                consumer: base.add(off.consumer as usize) as *mut u32,
                flags: base.add(off.flags as usize) as *mut u32,
                desc: base.add(off.desc as usize),
                mask: size - 1,
                cached_consumer: 0,
            }
        }
    }

    /// 与内核共享的计数器。内核按 smp_load_acquire / smp_store_release 读写，用户态对应
    /// Acquire 读、Release 写：读到对方推进的计数后才能看到描述符，写完描述符才发布计数。
    fn counter(&self, ptr: *mut u32) -> &AtomicU32 {
        // SAFETY: ptr 是本环的 producer / consumer / flags 之一，指向映射内内核给的 4 字节对齐计数器，
        // AtomicU32 与 u32 大小、对齐相同；映射在 Ring 使用期间存活，引用的生命周期绑在 &self 上。
        unsafe { AtomicU32::from_ptr(ptr) }
    }

    fn producer_value(&self) -> u32 {
        self.counter(self.producer).load(Ordering::Acquire)
    }

    fn needs_wakeup(&self) -> bool {
        self.counter(self.flags).load(Ordering::Relaxed) & XDP_RING_NEED_WAKEUP != 0
    }

    /// 生产者侧（FILL 环）：从当前 producer 起依次写入帧地址，再发布新的 producer。
    /// 调用方保证 addrs 不超过环上的空闲槽数。
    fn publish(&mut self, addrs: &[u64]) {
        let producer = self.producer_value();
        for (i, addr) in addrs.iter().enumerate() {
            let slot = (producer.wrapping_add(i as u32) & self.mask) as usize;
            // SAFETY: slot 经掩码后 < size，desc 起至少有 size 个 u64 槽（FILL 环；RX 环的描述符更大，同样不越界），
            // 都在映射内且 8 字节对齐；[producer, producer + addrs.len()) 这些槽内核在 producer 推进前不会读。
            unsafe { std::ptr::write((self.desc as *mut u64).add(slot), *addr) };
        }
        self.counter(self.producer)
            .store(producer.wrapping_add(addrs.len() as u32), Ordering::Release);
    }

    /// 消费者侧（RX 环）：取走 [cached_consumer, producer) 的描述符，对每帧调用 `f`，
    /// 发布新的 consumer，返回取走的帧地址（之后还给 FILL 环）。
    ///
    /// # Safety
    /// `self` 必须是 RX 环（desc 为 XdpDesc 数组）；`umem` 指向本 socket 注册的 UMEM，
    /// 且内核填进描述符的每个 addr + len 都落在 UMEM 内。
    unsafe fn consume(
        &mut self,
        umem: *const u8,
        producer: u32,
        f: &mut dyn FnMut(&[u8]),
    ) -> Vec<u64> {
        let mut consumer = self.cached_consumer;
        let mut used = Vec::with_capacity((producer.wrapping_sub(consumer)) as usize);
        while consumer != producer {
            let slot = (consumer & self.mask) as usize;
            // SAFETY: slot 经掩码后 < size，RX 环 desc 起有 size 个 XdpDesc，映射内 8 字节对齐；
            // [cached_consumer, producer) 范围的描述符内核已写好，consumer 推进前不会再改。
            let desc = unsafe { &*(self.desc as *const XdpDesc).add(slot) };
            // SAFETY: 按本函数 # Safety，addr + len 落在 UMEM 内；对应帧在归还 FILL 环之前内核不会再写，
            // 切片只借给本次回调。
            let frame = unsafe {
                std::slice::from_raw_parts(umem.add(desc.addr as usize), desc.len as usize)
            };
            f(frame);
            used.push(desc.addr);
            consumer = consumer.wrapping_add(1);
        }

        // 所有帧都已交付回调，发布后内核才可复用这些描述符槽
        self.counter(self.consumer)
            .store(consumer, Ordering::Release);
        self.cached_consumer = consumer;
        used
    }
}

/// 独占的一段 mmap 映射，Drop 时 munmap。
struct Mapping {
    ptr: *mut u8,
    len: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: ptr / len 正是 mmap 成功返回的地址与长度，Mapping 独占它且只 Drop 一次；
        // 帧切片只在 poll_batch 回调期间借用，此时不可能还有存活的借用。
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

/// 独占的 fd，Drop 时 close。
struct Fd(RawFd);

impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: 只包裹 socket 刚返回的有效 fd，由本结构独占，只关一次。
        unsafe { libc::close(self.0) };
    }
}

/// 资源按字段声明顺序释放：先拆三段环与 UMEM 的映射，最后关 fd。
/// open 中途失败时，已申请的部分同样随局部变量自动释放。
pub struct AfXdp {
    // RX / FILL / COMPLETION 三段环的映射，只经 rx、fill 两个视图访问，持有它们是为了释放
    _rings: [Mapping; 3],
    umem: Mapping,
    fd: Fd,
    rx: Ring,
    fill: Ring,
    frame_size: u32,
    frame_count: u32,
    dropped: u64,
}

// SAFETY: AfXdp 独占 fd、UMEM 与三段环映射（不可 Clone，没有别的别名），裸指针不绑定创建线程，
// 移到 worker 线程使用、在别的线程 Drop 都没问题；只实现 Send 不实现 Sync。
unsafe impl Send for AfXdp {}

impl AfXdp {
    pub fn open(iface: &str, cfg: &Config) -> io::Result<Self> {
        assert!(
            cfg.frame_count.is_power_of_two(),
            "frame_count 必须是 2 的幂"
        );

        // SAFETY: 纯 FFI 调用，参数都是整数常量，不涉及指针；返回值在下面检查 < 0。
        let raw = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = Fd(raw);

        // UMEM：页对齐的连续内存，网卡直接往里 DMA
        let umem_len = (cfg.frame_count * cfg.frame_size) as usize;
        // SAFETY: 匿名私有映射，不指定地址，长度为 frame_count × frame_size；MAP_FAILED 在下面检查。
        let umem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                umem_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if umem == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let umem = Mapping {
            ptr: umem as *mut u8,
            len: umem_len,
        };
        let fd_raw = fd.0;

        let reg = XdpUmemReg {
            addr: umem.ptr as u64,
            len: umem_len as u64,
            chunk_size: cfg.frame_size,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        setsockopt(fd_raw, XDP_UMEM_REG, &reg)?;
        setsockopt(fd_raw, XDP_UMEM_FILL_RING, &cfg.frame_count)?;
        setsockopt(fd_raw, XDP_UMEM_COMPLETION_RING, &cfg.frame_count)?;
        setsockopt(fd_raw, XDP_RX_RING, &cfg.frame_count)?;

        let offsets = mmap_offsets(fd_raw)?;
        let rx_map = map_ring(
            fd_raw,
            XDP_PGOFF_RX_RING,
            offsets.rx.desc as usize + cfg.frame_count as usize * size_of::<XdpDesc>(),
        )?;
        let fill_map = map_ring(
            fd_raw,
            XDP_UMEM_PGOFF_FILL_RING,
            offsets.fill.desc as usize + cfg.frame_count as usize * size_of::<u64>(),
        )?;
        let comp_map = map_ring(
            fd_raw,
            XDP_UMEM_PGOFF_COMPLETION_RING,
            offsets.completion.desc as usize + cfg.frame_count as usize * size_of::<u64>(),
        )?;

        // SAFETY: rx_map 是按 offsets.rx.desc + frame_count 个 XdpDesc 映射的 RX 环，偏移来自内核，
        // frame_count 已断言为 2 的幂且等于 XDP_RX_RING 申请的大小；映射由 AfXdp 持有到 Drop。
        let rx = unsafe { Ring::new(rx_map.ptr, &offsets.rx, cfg.frame_count) };
        // SAFETY: fill_map 同理：按 offsets.fill.desc + frame_count 个 u64 映射的 FILL 环，大小与申请一致。
        let fill = unsafe { Ring::new(fill_map.ptr, &offsets.fill, cfg.frame_count) };

        let index = if_index(iface)?;
        let addr = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: XDP_USE_NEED_WAKEUP,
            sxdp_ifindex: index,
            sxdp_queue_id: cfg.queue_id,
            sxdp_shared_umem_fd: 0,
        };
        // SAFETY: fd 是有效 AF_XDP 套接字；addr 是栈上与内核 struct sockaddr_xdp 布局一致的 #[repr(C)]
        // 结构，传入的长度正是它的大小，内核只读它。
        let rc = unsafe {
            libc::bind(
                fd_raw,
                &addr as *const _ as *const libc::sockaddr,
                size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut this = Self {
            _rings: [rx_map, fill_map, comp_map],
            umem,
            fd,
            rx,
            fill,
            frame_size: cfg.frame_size,
            frame_count: cfg.frame_count,
            dropped: 0,
        };
        this.fill_all();
        Ok(this)
    }

    /// 把所有帧交给内核，网卡才有地方放包。
    fn fill_all(&mut self) {
        let addrs: Vec<u64> = (0..self.frame_count)
            .map(|i| (i * self.frame_size) as u64)
            .collect();
        self.fill.publish(&addrs);
    }

    /// 把消费完的帧还给 FILL 环，否则网卡很快无帧可用。
    fn recycle(&mut self, addrs: &[u64]) {
        if addrs.is_empty() {
            return;
        }
        self.fill.publish(addrs);
    }

    /// 等待可读或超时：NEED_WAKEUP 置位时唤醒内核，未置位时用短超时让出 CPU 避免忙等。
    fn wait(&self, timeout_ms: libc::c_int) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.fd.0,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: &mut pfd 指向栈上单个 pollfd，nfds 传 1 与之相符；self.fd 有效。
        let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(err);
        }
        if pfd.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0 {
            return Err(io::Error::other(format!(
                "AF_XDP 套接字异常: revents={:#x}",
                pfd.revents
            )));
        }
        Ok(n > 0)
    }
}

impl Capture for AfXdp {
    fn poll_batch(&mut self, f: &mut dyn FnMut(&[u8], u64)) -> io::Result<usize> {
        let mut producer = self.rx.producer_value();
        let consumer = self.rx.cached_consumer;
        if consumer == producer {
            let timeout = if self.fill.needs_wakeup() {
                WAKEUP_POLL_TIMEOUT_MS
            } else {
                IDLE_POLL_TIMEOUT_MS
            };
            let _ = self.wait(timeout)?;
            producer = self.rx.producer_value();
            if consumer == producer {
                return Ok(0);
            }
        }

        // AF_XDP 不提供硬件时间戳，用接收时刻代替
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // SAFETY: self.rx 是 open 时按内核偏移建好的 RX 环，self.umem 是本 socket 注册的 UMEM；
        // 对齐模式下内核只会把从 FILL 环拿到的帧地址（都 < umem_len）连同不超过帧大小的长度
        // 写回 RX 描述符，满足 consume 的前提。
        let used = unsafe {
            self.rx
                .consume(self.umem.ptr, producer, &mut |frame| f(frame, now_ns))
        };
        let count = used.len();
        self.recycle(&used);
        Ok(count)
    }

    fn dropped(&self) -> u64 {
        // 内核不通过 socket 选项暴露 XDP 丢包，这里只统计本进程可见的部分
        self.dropped
    }
}

impl std::os::fd::AsRawFd for AfXdp {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.0
    }
}

fn validate_mmap_offsets_len(len: libc::socklen_t) -> io::Result<()> {
    if len as usize != size_of::<MmapOffsets>() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "内核返回的 XDP_MMAP_OFFSETS 长度为 {len} 字节，期望 {} 字节（AF_XDP 后端需要 Linux 5.4+）",
                size_of::<MmapOffsets>()
            ),
        ));
    }
    Ok(())
}

fn mmap_offsets(fd: RawFd) -> io::Result<MmapOffsets> {
    let mut offsets = MmapOffsets::default();
    let mut len = size_of::<MmapOffsets>() as libc::socklen_t;
    // SAFETY: offsets 是栈上已初始化的 #[repr(C)] 结构，len 如实给出它的大小，内核最多写这么多；
    // 返回后严格校验 len == size_of::<MmapOffsets>()，拒绝 < 5.4 老内核的 96 字节 v1 结构，防止字段错位 UB。
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            &mut offsets as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    validate_mmap_offsets_len(len)?;
    Ok(offsets)
}

fn map_ring(fd: RawFd, offset: libc::off_t, len: usize) -> io::Result<Mapping> {
    // SAFETY: fd 是有效 AF_XDP 套接字，offset 是该环约定的页偏移，len 由调用方按内核偏移算出；
    // MAP_FAILED 在下面检查。
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            offset,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(Mapping {
        ptr: ptr as *mut u8,
        len,
    })
}

fn setsockopt<T>(fd: RawFd, opt: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: value 是调用方给的 &T，在调用期间有效、可读 size_of::<T>() 字节，长度如实传入；
    // 各调用点的 T（XdpUmemReg、u32）与该选项的内核结构一致，内核只读它。
    let rc = unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
            opt,
            value as *const T as *const libc::c_void,
            size_of::<T>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn if_index(iface: &str) -> io::Result<u32> {
    let name = std::ffi::CString::new(iface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "网卡名含 NUL"))?;
    // SAFETY: name 是以 NUL 结尾的 CString，调用期间存活，函数只读它。
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{ManuallyDrop, offset_of};

    const N: u32 = 4;
    const FRAME: u32 = 2048;
    /// 仿内核的环布局：producer / consumer / flags 各占一条缓存行，描述符数组在后
    const OFF: RingOffset = RingOffset {
        producer: 0,
        consumer: 64,
        flags: 128,
        desc: 192,
    };

    /// 8 字节对齐的堆内存充当 mmap 出来的环
    struct Mem(Vec<u64>);

    impl Mem {
        fn new(bytes: usize) -> Self {
            Self(vec![0; bytes.div_ceil(8)])
        }

        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr().cast()
        }

        fn ring(&mut self) -> Ring {
            // SAFETY: 内存足够容纳 OFF 布局下 N 个描述符，偏移均按 4/8 字节对齐，测试期间不释放
            unsafe { Ring::new(self.ptr(), &OFF, N) }
        }

        fn u32_at(&mut self, off: u64) -> u32 {
            // SAFETY: off 是 OFF 中的 4 字节对齐偏移，落在 Mem 内
            unsafe { std::ptr::read(self.ptr().add(off as usize).cast::<u32>()) }
        }

        fn set_u32(&mut self, off: u64, v: u32) {
            // SAFETY: 同上
            unsafe { std::ptr::write(self.ptr().add(off as usize).cast::<u32>(), v) }
        }

        fn fill_slots(&mut self) -> Vec<u64> {
            (0..N as usize)
                .map(|i| self.0[OFF.desc as usize / 8 + i])
                .collect()
        }

        fn put(&mut self, at: usize, bytes: &[u8]) {
            assert!(at + bytes.len() <= self.0.len() * 8);
            // SAFETY: 上面已校验 [at, at + len) 落在 Mem 内；u8 无对齐要求
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr().add(at), bytes.len())
            }
        }

        fn set_rx_desc(&mut self, slot: u32, addr: u64, len: u32) {
            let at = OFF.desc as usize + slot as usize * size_of::<XdpDesc>();
            let desc = XdpDesc {
                addr,
                len,
                options: 0,
            };
            // SAFETY: slot < N，描述符落在 RX 环内；OFF.desc 为 8 的倍数，满足 XdpDesc 对齐
            unsafe { std::ptr::write(self.ptr().add(at).cast::<XdpDesc>(), desc) }
        }
    }

    fn rx_mem() -> Mem {
        Mem::new(OFF.desc as usize + N as usize * size_of::<XdpDesc>())
    }

    fn fill_mem() -> Mem {
        Mem::new(OFF.desc as usize + N as usize * size_of::<u64>())
    }

    #[test]
    fn uapi_struct_layout() {
        // 与 linux/if_xdp.h 一致
        assert_eq!(size_of::<XdpDesc>(), 16);
        assert_eq!(offset_of!(XdpDesc, len), 8);
        assert_eq!(size_of::<SockaddrXdp>(), 16);
        assert_eq!(size_of::<XdpUmemReg>(), 32);
        assert_eq!(size_of::<MmapOffsets>(), 4 * 32);
        assert_eq!(offset_of!(MmapOffsets, fill), 64);
    }

    #[test]
    fn ring_view_points_into_mapping() {
        let mut mem = fill_mem();
        let base = mem.ptr();
        let ring = mem.ring();
        assert_eq!(ring.mask, N - 1);
        assert_eq!(ring.producer as usize - base as usize, 0);
        assert_eq!(ring.consumer as usize - base as usize, 64);
        assert_eq!(ring.flags as usize - base as usize, 128);
        assert_eq!(ring.desc as usize - base as usize, 192);
        assert_eq!(ring.cached_consumer, 0);
    }

    #[test]
    fn needs_wakeup_reads_flag_bit() {
        let mut mem = fill_mem();
        let ring = mem.ring();
        assert!(!ring.needs_wakeup());
        mem.set_u32(OFF.flags, XDP_RING_NEED_WAKEUP);
        assert!(ring.needs_wakeup());
        mem.set_u32(OFF.flags, !XDP_RING_NEED_WAKEUP);
        assert!(!ring.needs_wakeup());
    }

    #[test]
    fn publish_wraps_slots_and_producer() {
        let mut mem = fill_mem();
        let mut ring = mem.ring();
        // producer 停在 u32 上限前两格：槽号按掩码回绕，producer 本身也按 u32 回绕
        mem.set_u32(OFF.producer, u32::MAX - 1);
        ring.publish(&[10, 20, 30]);
        assert_eq!(mem.u32_at(OFF.producer), 1);
        // (MAX-1)&3 = 2，MAX&3 = 3，0&3 = 0
        assert_eq!(mem.fill_slots(), [30, 0, 10, 20]);

        ring.publish(&[]);
        assert_eq!(mem.u32_at(OFF.producer), 1, "空批次不动 producer");
    }

    #[test]
    fn consume_reads_frames_and_publishes_consumer() {
        let mut umem = Mem::new((N * FRAME) as usize);
        for i in 0..N as usize {
            umem.put(i * FRAME as usize, format!("frame-{i}").as_bytes());
        }
        let mut mem = rx_mem();
        let mut ring = mem.ring();
        // 从回绕边界前一格开始消费两帧：槽 3 与槽 0
        ring.cached_consumer = u32::MAX;
        mem.set_rx_desc(3, 2 * FRAME as u64, 7);
        mem.set_rx_desc(0, 0, 5);
        let mut seen = Vec::new();
        // SAFETY: 描述符的 addr + len 都在 umem 内
        let used = unsafe { ring.consume(umem.ptr(), 1, &mut |f: &[u8]| seen.push(f.to_vec())) };
        assert_eq!(seen, [b"frame-2".to_vec(), b"frame".to_vec()]);
        assert_eq!(used, [2 * FRAME as u64, 0]);
        assert_eq!(ring.cached_consumer, 1);
        assert_eq!(mem.u32_at(OFF.consumer), 1);
    }

    #[test]
    fn consume_with_nothing_pending_is_empty() {
        let umem = Mem::new(FRAME as usize);
        let mut mem = rx_mem();
        let mut ring = mem.ring();
        ring.cached_consumer = 7;
        let mut calls = 0;
        // SAFETY: 没有待取描述符，不会访问 umem
        let used = unsafe { ring.consume(umem.0.as_ptr().cast(), 7, &mut |_| calls += 1) };
        assert!(used.is_empty());
        assert_eq!(calls, 0);
        assert_eq!(mem.u32_at(OFF.consumer), 7);
    }

    /// 不经 open 拼出一个指向假环的 AfXdp。ManuallyDrop 防止 Drop 去 munmap 堆内存、close(-1)
    fn fake_socket(umem: &mut Mem, rx: &mut Mem, fill: &mut Mem) -> ManuallyDrop<AfXdp> {
        ManuallyDrop::new(AfXdp {
            _rings: [rx.ptr(), fill.ptr(), std::ptr::null_mut()].map(|ptr| Mapping { ptr, len: 0 }),
            umem: Mapping {
                ptr: umem.ptr(),
                len: (N * FRAME) as usize,
            },
            fd: Fd(-1),
            rx: rx.ring(),
            fill: fill.ring(),
            frame_size: FRAME,
            frame_count: N,
            dropped: 0,
        })
    }

    #[test]
    fn fill_all_hands_every_frame_to_kernel() {
        let (mut umem, mut rx, mut fill) = (Mem::new((N * FRAME) as usize), rx_mem(), fill_mem());
        let mut sock = fake_socket(&mut umem, &mut rx, &mut fill);
        sock.fill_all();
        assert_eq!(fill.fill_slots(), [0, 2048, 4096, 6144]);
        assert_eq!(fill.u32_at(OFF.producer), N);
    }

    #[test]
    fn poll_batch_recycles_consumed_frames() {
        let (mut umem, mut rx, mut fill) = (Mem::new((N * FRAME) as usize), rx_mem(), fill_mem());
        let mut sock = fake_socket(&mut umem, &mut rx, &mut fill);
        sock.fill_all();
        // 内核收了两帧：放在第 1、3 帧，producer 前进 2
        rx.set_rx_desc(0, FRAME as u64, 60);
        rx.set_rx_desc(1, 3 * FRAME as u64, 1514);
        rx.set_u32(OFF.producer, 2);

        let mut lens = Vec::new();
        let n = sock
            .poll_batch(&mut |f, ts| lens.push((f.len(), ts > 0)))
            .unwrap();
        assert_eq!(n, 2);
        assert_eq!(lens, [(60, true), (1514, true)]);
        assert_eq!(rx.u32_at(OFF.consumer), 2);
        // 用过的帧按消费顺序回到 FILL 环，接在 fill_all 的 4 帧之后（槽号回绕到 0、1）
        assert_eq!(fill.u32_at(OFF.producer), N + 2);
        assert_eq!(fill.fill_slots(), [2048, 6144, 4096, 6144]);
    }

    #[test]
    fn poll_batch_without_new_frames_waits_and_returns_zero() {
        let (mut umem, mut rx, mut fill) = (Mem::new((N * FRAME) as usize), rx_mem(), fill_mem());
        let mut sock = fake_socket(&mut umem, &mut rx, &mut fill);
        // 内核未置 NEED_WAKEUP 时也应走短超时 poll 让出 CPU，而非 0ms 忙等
        let start = std::time::Instant::now();
        assert_eq!(sock.poll_batch(&mut |_, _| unreachable!()).unwrap(), 0);
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(10),
            "无包空闲时应走短超时 poll 等待，避免 100% CPU 忙等"
        );
        assert_eq!(fill.u32_at(OFF.producer), 0);
    }

    #[test]
    fn mmap_offsets_rejects_pre_5_4_v1_layout() {
        // Linux < 5.4 返回 96 字节的 xdp_mmap_offsets_v1，必须拒绝而不能按 128 字节强解释
        let err = validate_mmap_offsets_len(96).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(validate_mmap_offsets_len(0).is_err());
        assert!(validate_mmap_offsets_len(size_of::<MmapOffsets>() as libc::socklen_t).is_ok());
    }
}
