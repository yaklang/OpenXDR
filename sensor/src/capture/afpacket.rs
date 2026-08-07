//! AF_PACKET v3 (TPACKET_V3) 抓包环。
//!
//! 内核把帧写进 mmap 共享的块（block）环形缓冲，用户态按块批量消费——
//! 每块一次同步，而不是每包一次，这是 v3 相对 v2 的核心优势。
//! PACKET_FANOUT_HASH 保证同一条流恒定落到同一 worker，流表因此无需加锁。

use std::io;
use std::os::fd::{AsRawFd, RawFd};

use super::Capture;

const TPACKET_V3: libc::c_int = 2;
const PACKET_RX_RING: libc::c_int = 5;
const PACKET_VERSION: libc::c_int = 10;
const PACKET_FANOUT: libc::c_int = 18;
const PACKET_FANOUT_HASH: libc::c_uint = 0;
const TP_STATUS_USER: u32 = 1 << 0;

#[repr(C)]
struct TpacketReq3 {
    tp_block_size: libc::c_uint,
    tp_block_nr: libc::c_uint,
    tp_frame_size: libc::c_uint,
    tp_frame_nr: libc::c_uint,
    tp_retire_blk_tov: libc::c_uint,
    tp_sizeof_priv: libc::c_uint,
    tp_feature_req_word: libc::c_uint,
}

/// 对应内核 struct tpacket_block_desc：前两个字段是 version 和 offset_to_priv，
/// 之后才是 tpacket_hdr_v1。少了这 8 字节会把 version 当成 block_status 读。
#[repr(C)]
struct BlockDescV1 {
    version: u32,
    offset_to_priv: u32,
    block_status: u32,
    num_pkts: u32,
    offset_to_first_pkt: u32,
    blk_len: u32,
    seq_num: u64,
    ts_first_pkt: TpacketBdTs,
    ts_last_pkt: TpacketBdTs,
}

#[repr(C)]
struct TpacketBdTs {
    ts_sec: u32,
    ts_nsec: u32,
}

#[repr(C)]
struct Tpacket3Hdr {
    tp_next_offset: u32,
    tp_sec: u32,
    tp_nsec: u32,
    tp_snaplen: u32,
    tp_len: u32,
    tp_status: u32,
    tp_mac: u16,
    tp_net: u16,
    // 后续还有 hv1 union，我们用不到
}

#[repr(C)]
struct TpacketStatsV3 {
    tp_packets: libc::c_uint,
    tp_drops: libc::c_uint,
    tp_freeze_q_cnt: libc::c_uint,
}

pub struct RingConfig {
    pub block_size: u32,
    pub block_count: u32,
    /// 块超时（毫秒）：块未满也会在此时限后交给用户态，控制延迟
    pub block_timeout_ms: u32,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            block_size: 1 << 21, // 2 MiB
            block_count: 64,     // 共 128 MiB
            block_timeout_ms: 100,
        }
    }
}

pub struct AfPacket {
    fd: RawFd,
    ring: *mut u8,
    ring_len: usize,
    block_size: usize,
    block_count: usize,
    next_block: usize,
}

// ring 指针指向本 fd 私有的 mmap 区域，随结构体一起移动到 worker 线程
unsafe impl Send for AfPacket {}

impl AfPacket {
    /// 在 `iface` 上开一个抓包环。`fanout_group` 非 0 时加入 FANOUT 组，
    /// 同组的多个 socket 按流哈希分担流量。
    pub fn open(iface: &str, cfg: &RingConfig, fanout_group: u16) -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (libc::ETH_P_ALL as u16).to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let guard = FdGuard(fd);

        setsockopt(fd, PACKET_VERSION, &TPACKET_V3)?;

        // frame_size 设成 block_size：v3 下帧在块内自由排布，此值仅用于合法性校验
        let req = TpacketReq3 {
            tp_block_size: cfg.block_size,
            tp_block_nr: cfg.block_count,
            tp_frame_size: cfg.block_size,
            tp_frame_nr: cfg.block_count,
            tp_retire_blk_tov: cfg.block_timeout_ms,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };
        setsockopt(fd, PACKET_RX_RING, &req)?;

        let ring_len = cfg.block_size as usize * cfg.block_count as usize;
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_LOCKED,
                fd,
                0,
            )
        };
        if ring == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        bind_iface(fd, iface)?;

        if fanout_group != 0 {
            let arg = (fanout_group as libc::c_uint) | (PACKET_FANOUT_HASH << 16);
            setsockopt(fd, PACKET_FANOUT, &arg)?;
        }

        std::mem::forget(guard);
        Ok(Self {
            fd,
            ring: ring as *mut u8,
            ring_len,
            block_size: cfg.block_size as usize,
            block_count: cfg.block_count as usize,
            next_block: 0,
        })
    }

    fn block_ptr(&self, index: usize) -> *mut BlockDescV1 {
        unsafe { self.ring.add(index * self.block_size) as *mut BlockDescV1 }
    }

    /// 等待当前块就绪。返回 false 表示超时（无数据）。
    fn wait_block(&self) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let n = unsafe { libc::poll(&mut pfd, 1, 1000) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if pfd.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0 {
                return Err(io::Error::other(format!(
                    "抓包套接字异常: revents={:#x}",
                    pfd.revents
                )));
            }
            return Ok(n > 0);
        }
    }
}

impl Capture for AfPacket {
    fn poll_batch(&mut self, f: &mut dyn FnMut(&[u8], u64)) -> io::Result<usize> {
        let desc = self.block_ptr(self.next_block);

        // 内核写完整块才置 TP_STATUS_USER；未就绪就 poll 等。
        // poll 可能报可读但当前块尚未retire，限次让出，避免空转饿死上层的老化与统计。
        let mut attempts = 0;
        while unsafe { std::ptr::read_volatile(&(*desc).block_status) } & TP_STATUS_USER == 0 {
            if !self.wait_block()? {
                return Ok(0);
            }
            attempts += 1;
            if attempts >= 8 {
                return Ok(0);
            }
        }

        let (num_pkts, first_offset) = unsafe { ((*desc).num_pkts, (*desc).offset_to_first_pkt) };
        let block_base = desc as *mut u8;
        let mut offset = first_offset as usize;

        for _ in 0..num_pkts {
            let hdr = unsafe { block_base.add(offset) as *const Tpacket3Hdr };
            let (next, mac, snaplen, sec, nsec) = unsafe {
                (
                    (*hdr).tp_next_offset as usize,
                    (*hdr).tp_mac as usize,
                    (*hdr).tp_snaplen as usize,
                    (*hdr).tp_sec as u64,
                    (*hdr).tp_nsec as u64,
                )
            };
            // 零拷贝：帧数据直接借用 mmap 区域
            let frame = unsafe { std::slice::from_raw_parts(block_base.add(offset + mac), snaplen) };
            f(frame, sec * 1_000_000_000 + nsec);

            if next == 0 {
                break;
            }
            offset += next;
        }

        // 归还块给内核
        unsafe { std::ptr::write_volatile(&mut (*desc).block_status, 0) };
        self.next_block = (self.next_block + 1) % self.block_count;
        Ok(num_pkts as usize)
    }

    fn dropped(&self) -> u64 {
        let mut stats = TpacketStatsV3 {
            tp_packets: 0,
            tp_drops: 0,
            tp_freeze_q_cnt: 0,
        };
        let mut len = size_of::<TpacketStatsV3>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                &mut stats as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc < 0 { 0 } else { stats.tp_drops as u64 }
    }
}

impl AsRawFd for AfPacket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for AfPacket {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ring as *mut libc::c_void, self.ring_len);
            libc::close(self.fd);
        }
    }
}

struct FdGuard(RawFd);

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn setsockopt<T>(fd: RawFd, opt: libc::c_int, value: &T) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
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

fn bind_iface(fd: RawFd, iface: &str) -> io::Result<()> {
    let name = std::ffi::CString::new(iface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "网卡名含 NUL"))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = index as i32;

    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
