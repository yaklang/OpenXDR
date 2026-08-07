//! AF_XDP 抓包后端：绕过内核协议栈，直接从网卡队列取包。
//!
//! 结构：一块 UMEM（帧内存池）+ 四个环。
//!   FILL  用户态 → 内核：交出空闲帧供网卡填充
//!   RX    内核 → 用户态：收到的包
//!   TX / COMPLETION 本探针只收不发，建了但不用
//!
//! 收包前提是有 XDP 程序把包 redirect 到本 socket，见 ebpf/src/main.rs。
//! 一个 socket 对应一个网卡队列，多队列网卡需要每队列一个 worker。

use std::io;
use std::os::fd::RawFd;

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
    unsafe fn new(base: *mut u8, off: &RingOffset, size: u32) -> Self {
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

    fn producer_value(&self) -> u32 {
        unsafe { std::ptr::read_volatile(self.producer) }
    }

    fn consumer_value(&self) -> u32 {
        unsafe { std::ptr::read_volatile(self.consumer) }
    }

    fn needs_wakeup(&self) -> bool {
        unsafe { std::ptr::read_volatile(self.flags) & XDP_RING_NEED_WAKEUP != 0 }
    }
}

pub struct AfXdp {
    fd: RawFd,
    umem: *mut u8,
    umem_len: usize,
    rx_map: *mut u8,
    rx_map_len: usize,
    fill_map: *mut u8,
    fill_map_len: usize,
    comp_map: *mut u8,
    comp_map_len: usize,
    rx: Ring,
    fill: Ring,
    frame_size: u32,
    frame_count: u32,
    dropped: u64,
}

unsafe impl Send for AfXdp {}

impl AfXdp {
    pub fn open(iface: &str, cfg: &Config) -> io::Result<Self> {
        assert!(cfg.frame_count.is_power_of_two(), "frame_count 必须是 2 的幂");

        let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // UMEM：页对齐的连续内存，网卡直接往里 DMA
        let umem_len = (cfg.frame_count * cfg.frame_size) as usize;
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
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }
        let umem = umem as *mut u8;

        let reg = XdpUmemReg {
            addr: umem as u64,
            len: umem_len as u64,
            chunk_size: cfg.frame_size,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        setsockopt(fd, XDP_UMEM_REG, &reg)?;
        setsockopt(fd, XDP_UMEM_FILL_RING, &cfg.frame_count)?;
        setsockopt(fd, XDP_UMEM_COMPLETION_RING, &cfg.frame_count)?;
        setsockopt(fd, XDP_RX_RING, &cfg.frame_count)?;

        let offsets = mmap_offsets(fd)?;
        let (rx_map, rx_map_len) = map_ring(
            fd,
            XDP_PGOFF_RX_RING,
            offsets.rx.desc as usize + cfg.frame_count as usize * size_of::<XdpDesc>(),
        )?;
        let (fill_map, fill_map_len) = map_ring(
            fd,
            XDP_UMEM_PGOFF_FILL_RING,
            offsets.fill.desc as usize + cfg.frame_count as usize * size_of::<u64>(),
        )?;
        let (comp_map, comp_map_len) = map_ring(
            fd,
            XDP_UMEM_PGOFF_COMPLETION_RING,
            offsets.completion.desc as usize + cfg.frame_count as usize * size_of::<u64>(),
        )?;

        let rx = unsafe { Ring::new(rx_map, &offsets.rx, cfg.frame_count) };
        let fill = unsafe { Ring::new(fill_map, &offsets.fill, cfg.frame_count) };

        let index = if_index(iface)?;
        let addr = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: XDP_USE_NEED_WAKEUP,
            sxdp_ifindex: index,
            sxdp_queue_id: cfg.queue_id,
            sxdp_shared_umem_fd: 0,
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut this = Self {
            fd,
            umem,
            umem_len,
            rx_map,
            rx_map_len,
            fill_map,
            fill_map_len,
            comp_map,
            comp_map_len,
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
        let producer = self.fill.producer_value();
        for i in 0..self.frame_count {
            let slot = (producer.wrapping_add(i) & self.fill.mask) as usize;
            unsafe {
                let addr = self.fill.desc as *mut u64;
                std::ptr::write(addr.add(slot), (i * self.frame_size) as u64);
            }
        }
        unsafe {
            std::ptr::write_volatile(
                self.fill.producer,
                producer.wrapping_add(self.frame_count),
            )
        };
    }

    /// 把消费完的帧还给 FILL 环，否则网卡很快无帧可用。
    fn recycle(&mut self, addrs: &[u64]) {
        if addrs.is_empty() {
            return;
        }
        let producer = self.fill.producer_value();
        for (i, addr) in addrs.iter().enumerate() {
            let slot = (producer.wrapping_add(i as u32) & self.fill.mask) as usize;
            unsafe { std::ptr::write((self.fill.desc as *mut u64).add(slot), *addr) };
        }
        unsafe {
            std::ptr::write_volatile(
                self.fill.producer,
                producer.wrapping_add(addrs.len() as u32),
            )
        };
    }

    /// NEED_WAKEUP 模式下内核可能在休眠，要用 poll 叫醒它继续填包。
    fn wait(&self) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, 1000) };
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
        let producer = self.rx.producer_value();
        let mut consumer = self.rx.cached_consumer;
        if consumer == producer {
            if self.fill.needs_wakeup() && !self.wait()? {
                return Ok(0);
            }
            let producer = self.rx.producer_value();
            if consumer == producer {
                return Ok(0);
            }
        }

        let producer = self.rx.producer_value();
        let mut used = Vec::with_capacity((producer.wrapping_sub(consumer)) as usize);
        // AF_XDP 不提供硬件时间戳，用接收时刻代替
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        while consumer != producer {
            let slot = (consumer & self.rx.mask) as usize;
            let desc = unsafe { &*(self.rx.desc as *const XdpDesc).add(slot) };
            let frame =
                unsafe { std::slice::from_raw_parts(self.umem.add(desc.addr as usize), desc.len as usize) };
            f(frame, now_ns);
            used.push(desc.addr);
            consumer = consumer.wrapping_add(1);
        }

        unsafe { std::ptr::write_volatile(self.rx.consumer, consumer) };
        self.rx.cached_consumer = consumer;
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
        self.fd
    }
}

impl Drop for AfXdp {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.rx_map as *mut libc::c_void, self.rx_map_len);
            libc::munmap(self.fill_map as *mut libc::c_void, self.fill_map_len);
            libc::munmap(self.comp_map as *mut libc::c_void, self.comp_map_len);
            libc::munmap(self.umem as *mut libc::c_void, self.umem_len);
            libc::close(self.fd);
        }
    }
}

fn mmap_offsets(fd: RawFd) -> io::Result<MmapOffsets> {
    let mut offsets = MmapOffsets::default();
    let mut len = size_of::<MmapOffsets>() as libc::socklen_t;
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
    Ok(offsets)
}

fn map_ring(fd: RawFd, offset: libc::off_t, len: usize) -> io::Result<(*mut u8, usize)> {
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
    Ok((ptr as *mut u8, len))
}

fn setsockopt<T>(fd: RawFd, opt: libc::c_int, value: &T) -> io::Result<()> {
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
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}
