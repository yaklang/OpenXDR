//! Windows 抓包：系统自带的 Packet Monitor（PktMon）实时包流 API（Pktmonapi.dll），
//! Windows 11 与 Windows Server 2022（2022-06 更新）起才有。用的是系统已签名的驱动，不需要自研驱动或证书；
//! 支持多会话，不影响管理员同时用 pktmon.exe 排障。更老的系统明确报不支持，不退回未公开接口。
//!
//! 只加网卡类数据源；同一个包经过协议栈多个组件时 PktGroupId 相同，只收第一次。
//! 回调跑在 PktMon 自己的线程上：把帧复制进有界队列，poll_batch 从队列取；队列满就丢弃计数，绝不阻塞回调。
//! IP 类型的帧（没有以太网头，VPN、回环这类接口）补一个以太网头，解码器原样复用。
//!
//! 只有加载 DLL 的两个调用依赖 Windows，其余在别的平台的测试构建里也编译，布局与去重的测试 CI 上就能跑。
#![cfg_attr(not(windows), allow(dead_code))]

use super::Capture;
use std::collections::{HashSet, VecDeque};
use std::ffi::c_void;
use std::io;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Proc = unsafe extern "system" fn() -> isize;

#[cfg(windows)]
fn load_library(name: &str) -> *mut c_void {
    let name = wide(name);
    // SAFETY: 以 0 结尾的 UTF-16 模块名；系统目录里的 DLL，句柄随进程存在，不释放
    unsafe { windows_sys::Win32::System::LibraryLoader::LoadLibraryW(name.as_ptr()) }
}

#[cfg(windows)]
fn proc_address(module: *mut c_void, name: &str) -> Option<Proc> {
    let name: Vec<u8> = name.bytes().chain([0]).collect();
    // SAFETY: module 是 load_library 成功返回的句柄，名字以 0 结尾
    unsafe { windows_sys::Win32::System::LibraryLoader::GetProcAddress(module, name.as_ptr()) }
}

#[cfg(not(windows))]
fn load_library(_name: &str) -> *mut c_void {
    null_mut()
}

#[cfg(not(windows))]
fn proc_address(_module: *mut c_void, _name: &str) -> Option<Proc> {
    None
}

const API_VERSION_1_0: u32 = 0x0001_0000;
const KIND_NETWORK_INTERFACE: u32 = 1;
/// 截断长度取 API 上限：网卡层看到的是还没分段的大包（LSO），截断后字节数只计前 9000
const TRUNCATION: u16 = 9000;
const BUFFER_MULTIPLIER: u16 = 10;
/// 回调与抓包线程之间的队列深度
const QUEUE: usize = 65536;
/// 去重记住最近多少个 PktGroupId
const DEDUP: usize = 4096;
const PACKET_ETHERNET: u16 = 1;
const PACKET_IP: u16 = 3;
const EVENT_STOPPED: u32 = 1;
const EVENT_FATAL: u32 = 2;

type Handle = *mut c_void;
type DataCallback = unsafe extern "system" fn(*mut c_void, *const DataDescriptor);
type EventCallback = unsafe extern "system" fn(*mut c_void, *const c_void, u32);

/// PACKETMONITOR_DATA_SOURCE_SPECIFICATION
#[repr(C)]
#[derive(Clone, Copy)]
struct Spec {
    kind: u32,
    name: [u16; 64],
    description: [u16; 128],
    id: u32,
    secondary_id: u32,
    parent_id: u32,
    is_present: u32,
    /// 联合体（GUID / IP / MAC），按 8 字节对齐
    detail: [u64; 2],
}

/// PACKETMONITOR_REALTIME_STREAM_CONFIGURATION
#[repr(C)]
struct StreamConfig {
    user_context: *mut c_void,
    event_callback: Option<EventCallback>,
    data_callback: Option<DataCallback>,
    buffer_size_multiplier: u16,
    truncation_size: u16,
}

/// PACKETMONITOR_STREAM_DATA_DESCRIPTOR：每次回调一个包，元数据与包内容都在 data 指向的缓冲里
#[repr(C)]
struct DataDescriptor {
    data: *const u8,
    data_size: u32,
    metadata_offset: u32,
    packet_offset: u32,
    packet_length: u32,
    missed_write: u32,
    missed_read: u32,
}

/// PACKETMONITOR_STREAM_METADATA
#[repr(C)]
#[derive(Clone, Copy)]
struct Metadata {
    group_id: u64,
    pkt_count: u16,
    appearance_count: u16,
    direction: u16,
    packet_type: u16,
    component_id: u16,
    edge_id: u16,
    reserved: u16,
    drop_reason: u32,
    drop_location: u32,
    processor: u16,
    timestamp: i64,
}

type Initialize = unsafe extern "system" fn(u32, *mut c_void, *mut Handle) -> i32;
type Close = unsafe extern "system" fn(Handle);
type CreateLiveSession = unsafe extern "system" fn(Handle, *const u16, *mut Handle) -> i32;
type EnumDataSources =
    unsafe extern "system" fn(Handle, u32, u8, usize, *mut usize, *mut c_void) -> i32;
type AddDataSource = unsafe extern "system" fn(Handle, *const Spec) -> i32;
type CreateStream = unsafe extern "system" fn(Handle, *const StreamConfig, *mut Handle) -> i32;
type AttachOutput = unsafe extern "system" fn(Handle, Handle) -> i32;
type SetActive = unsafe extern "system" fn(Handle, u8) -> i32;

/// Pktmonapi.dll 的导出：SDK 里没有头文件与导入库，按文档用 LoadLibrary + GetProcAddress
struct Api {
    initialize: Initialize,
    uninitialize: Close,
    create_live_session: CreateLiveSession,
    close_session: Close,
    enum_data_sources: EnumDataSources,
    add_data_source: AddDataSource,
    create_stream: CreateStream,
    close_stream: Close,
    attach_output: AttachOutput,
    set_active: SetActive,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

impl Api {
    fn load() -> io::Result<Self> {
        let module = load_library("pktmonapi.dll");
        if module.is_null() {
            return Err(unsupported());
        }
        macro_rules! sym {
            ($name:literal, $ty:ty) => {{
                let f = proc_address(module, $name).ok_or_else(unsupported)?;
                // SAFETY: 导出函数的签名照 Microsoft Learn 的 Packet Monitor 参考，按 system 调用约定
                unsafe { std::mem::transmute::<Proc, $ty>(f) }
            }};
        }
        Ok(Self {
            initialize: sym!("PacketMonitorInitialize", Initialize),
            uninitialize: sym!("PacketMonitorUninitialize", Close),
            create_live_session: sym!("PacketMonitorCreateLiveSession", CreateLiveSession),
            close_session: sym!("PacketMonitorCloseSessionHandle", Close),
            enum_data_sources: sym!("PacketMonitorEnumDataSources", EnumDataSources),
            add_data_source: sym!("PacketMonitorAddSingleDataSourceToSession", AddDataSource),
            create_stream: sym!("PacketMonitorCreateRealtimeStream", CreateStream),
            close_stream: sym!("PacketMonitorCloseRealtimeStream", Close),
            attach_output: sym!("PacketMonitorAttachOutputToSession", AttachOutput),
            set_active: sym!("PacketMonitorSetSessionActive", SetActive),
        })
    }
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "本系统没有 Packet Monitor 实时 API（需要 Windows 11 或 Windows Server 2022 2022-06 更新以上）",
    )
}

fn check(what: &str, hr: i32) -> io::Result<()> {
    if hr >= 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{what} 失败：0x{:08x}",
            hr as u32
        )))
    }
}

fn text(chars: &[u16]) -> String {
    let end = chars.iter().position(|c| *c == 0).unwrap_or(chars.len());
    String::from_utf16_lossy(&chars[..end])
}

/// 回调与抓包线程共享的状态，生命期从建流到关流
struct Shared {
    tx: SyncSender<Vec<u8>>,
    /// 队列满丢掉的
    dropped: AtomicU64,
    /// PktMon 自己报的写入、读取丢失
    missed: AtomicU64,
    stopped: AtomicBool,
    recent: Mutex<Recent>,
}

/// 最近见过的 PktGroupId：同一个包在多个组件上出现只收一次
#[derive(Default)]
struct Recent {
    order: VecDeque<u64>,
    seen: HashSet<u64>,
}

impl Recent {
    fn first(&mut self, group: u64) -> bool {
        if group == 0 {
            return true;
        }
        if !self.seen.insert(group) {
            return false;
        }
        self.order.push_back(group);
        if self.order.len() > DEDUP
            && let Some(old) = self.order.pop_front()
        {
            self.seen.remove(&old);
        }
        true
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 统一成以太网帧：以太网原样；裸 IP 按版本补 14 字节头（地址全 0，解码器只看类型）；别的类型不收
fn to_ethernet(packet_type: u16, packet: &[u8]) -> Option<Vec<u8>> {
    match packet_type {
        PACKET_ETHERNET => Some(packet.to_vec()),
        PACKET_IP => {
            let ethertype: u16 = match packet.first()? >> 4 {
                4 => 0x0800,
                6 => 0x86dd,
                _ => return None,
            };
            let mut frame = Vec::with_capacity(14 + packet.len());
            frame.extend_from_slice(&[0; 12]);
            frame.extend_from_slice(&ethertype.to_be_bytes());
            frame.extend_from_slice(packet);
            Some(frame)
        }
        _ => None,
    }
}

unsafe extern "system" fn on_data(context: *mut c_void, descriptor: *const DataDescriptor) {
    // SAFETY: context 是建流时传入的 Shared 指针，关流之后才释放；descriptor 在回调期间有效
    let (Some(shared), Some(d)) = (unsafe { context.cast::<Shared>().as_ref() }, unsafe {
        descriptor.as_ref()
    }) else {
        return;
    };
    shared.missed.fetch_add(
        u64::from(d.missed_write) + u64::from(d.missed_read),
        Ordering::Relaxed,
    );
    let size = d.data_size as usize;
    let (meta_at, packet_at, len) = (
        d.metadata_offset as usize,
        d.packet_offset as usize,
        d.packet_length as usize,
    );
    if d.data.is_null() || meta_at + size_of::<Metadata>() > size || packet_at + len > size {
        return;
    }
    // SAFETY: 上面已核对元数据与包内容都落在 data 缓冲之内；元数据不保证对齐，按不对齐读
    let meta = unsafe { std::ptr::read_unaligned(d.data.add(meta_at).cast::<Metadata>()) };
    if !lock(&shared.recent).first(meta.group_id) {
        return;
    }
    // SAFETY: 同上，[packet_at, packet_at + len) 在缓冲之内
    let packet = unsafe { std::slice::from_raw_parts(d.data.add(packet_at), len) };
    let Some(frame) = to_ethernet(meta.packet_type, packet) else {
        return;
    };
    if let Err(TrySendError::Full(_)) = shared.tx.try_send(frame) {
        shared.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe extern "system" fn on_event(context: *mut c_void, _info: *const c_void, kind: u32) {
    // SAFETY: 同 on_data
    let Some(shared) = (unsafe { context.cast::<Shared>().as_ref() }) else {
        return;
    };
    if kind == EVENT_STOPPED || kind == EVENT_FATAL {
        eprintln!("PktMon 包流已停止（事件 {kind}）");
        shared.stopped.store(true, Ordering::Relaxed);
    }
}

pub struct PktMon {
    api: Api,
    handle: Handle,
    session: Handle,
    stream: Handle,
    shared: *mut Shared,
    rx: Receiver<Vec<u8>>,
    /// 实际在抓的网卡（名字 / 描述），启动时打出来
    pub interfaces: Vec<String>,
}

// SAFETY: 句柄只在持有它的抓包线程上使用；Shared 里的成员本身线程安全，回调线程只读它
unsafe impl Send for PktMon {}

impl PktMon {
    /// iface 为空或 all 时抓所有网卡，否则抓名字或描述里含它（不分大小写）的网卡
    pub fn open(iface: &str) -> io::Result<Self> {
        let api = Api::load()?;
        let mut handle = null_mut();
        // SAFETY: 出参是栈上变量；保留参数按文档传空
        check("PacketMonitorInitialize", unsafe {
            (api.initialize)(API_VERSION_1_0, null_mut(), &mut handle)
        })?;
        let (tx, rx) = sync_channel(QUEUE);
        let mut me = Self {
            api,
            handle,
            session: null_mut(),
            stream: null_mut(),
            shared: Box::into_raw(Box::new(Shared {
                tx,
                dropped: AtomicU64::new(0),
                missed: AtomicU64::new(0),
                stopped: AtomicBool::new(false),
                recent: Mutex::new(Recent::default()),
            })),
            rx,
            interfaces: Vec::new(),
        };
        // 之后任何一步失败，me 的 Drop 按已建好的部分收尾
        let name = wide("OpenXDR sensor");
        // SAFETY: handle 有效，名字以 0 结尾，出参是 me 的字段
        check("PacketMonitorCreateLiveSession", unsafe {
            (me.api.create_live_session)(me.handle, name.as_ptr(), &mut me.session)
        })?;
        let wanted = iface.trim().to_lowercase();
        let all = wanted.is_empty() || wanted == "all";
        let nics = me.network_interfaces()?;
        for nic in &nics {
            let label = format!("{} / {}", text(&nic.name), text(&nic.description));
            if !all && !label.to_lowercase().contains(&wanted) {
                continue;
            }
            // SAFETY: session 有效，nic 是本函数持有的完整结构
            check("PacketMonitorAddSingleDataSourceToSession", unsafe {
                (me.api.add_data_source)(me.session, nic)
            })?;
            me.interfaces.push(label);
        }
        if me.interfaces.is_empty() {
            let names: Vec<String> = nics.iter().map(|n| text(&n.description)).collect();
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("没有匹配「{iface}」的网卡，可选：{}", names.join("；")),
            ));
        }
        let config = StreamConfig {
            user_context: me.shared.cast(),
            event_callback: Some(on_event),
            data_callback: Some(on_data),
            buffer_size_multiplier: BUFFER_MULTIPLIER,
            truncation_size: TRUNCATION,
        };
        // SAFETY: config 在调用期间有效，user_context 指向的 Shared 活到 Drop 关流之后
        check("PacketMonitorCreateRealtimeStream", unsafe {
            (me.api.create_stream)(me.handle, &config, &mut me.stream)
        })?;
        // SAFETY: session 与 stream 都是上面成功建出的句柄
        check("PacketMonitorAttachOutputToSession", unsafe {
            (me.api.attach_output)(me.session, me.stream)
        })?;
        // SAFETY: 同上
        check("PacketMonitorSetSessionActive", unsafe {
            (me.api.set_active)(me.session, 1)
        })?;
        Ok(me)
    }

    /// 列出能抓的网卡（描述 / 名字）。系统不支持实时 API 时返回 Unsupported，安装脚本据此拦下
    pub fn list() -> io::Result<Vec<String>> {
        let api = Api::load()?;
        let mut handle = null_mut();
        // SAFETY: 同 open
        check("PacketMonitorInitialize", unsafe {
            (api.initialize)(API_VERSION_1_0, null_mut(), &mut handle)
        })?;
        let nics = enum_nics(&api, handle);
        // SAFETY: handle 是上面成功初始化的
        unsafe { (api.uninitialize)(handle) };
        Ok(nics?
            .iter()
            .map(|n| format!("{} / {}", text(&n.description), text(&n.name)))
            .collect())
    }

    fn network_interfaces(&self) -> io::Result<Vec<Spec>> {
        enum_nics(&self.api, self.handle)
    }

    fn shared(&self) -> &Shared {
        // SAFETY: shared 从 open 起有效，到 Drop 关流后才释放
        unsafe { &*self.shared }
    }
}

/// 枚举网卡类数据源，拷出来再释放缓冲（列表里的指针指向缓冲内部）
fn enum_nics(api: &Api, handle: Handle) -> io::Result<Vec<Spec>> {
    let mut needed = 0usize;
    // SAFETY: 先只问需要多大，缓冲传空、容量 0
    unsafe {
        (api.enum_data_sources)(
            handle,
            KIND_NETWORK_INTERFACE,
            0,
            0,
            &mut needed,
            null_mut(),
        );
    }
    if needed == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u64; needed.div_ceil(8)];
    // SAFETY: buf 至少 needed 字节，按 8 字节对齐，满足列表里指针数组的对齐
    check("PacketMonitorEnumDataSources", unsafe {
        (api.enum_data_sources)(
            handle,
            KIND_NETWORK_INTERFACE,
            0,
            buf.len() * 8,
            &mut needed,
            buf.as_mut_ptr().cast(),
        )
    })?;
    // PACKETMONITOR_DATA_SOURCE_LIST：u32 个数，补齐到 8 字节后是指针数组
    let count = (buf[0] & 0xffff_ffff) as usize;
    let pointers = buf.get(1..1 + count).unwrap_or(&[]);
    Ok(pointers
        .iter()
        .filter(|p| **p != 0)
        // SAFETY: 指针由 API 写入，指向本缓冲里的 Spec，按不对齐读拷出
        .map(|p| unsafe { std::ptr::read_unaligned(*p as usize as *const Spec) })
        .filter(|s| s.kind == KIND_NETWORK_INTERFACE)
        .collect())
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

impl Capture for PktMon {
    fn poll_batch(&mut self, f: &mut dyn FnMut(&[u8], u64)) -> io::Result<usize> {
        if self.shared().stopped.load(Ordering::Relaxed) {
            return Err(io::Error::other("PktMon 包流已停止"));
        }
        // 最多等 100 毫秒，让上层能按时检查退出与流表过期
        let first = match self.rx.recv_timeout(Duration::from_millis(100)) {
            Ok(frame) => frame,
            Err(_) => return Ok(0),
        };
        let ts = now_ns();
        f(&first, ts);
        let mut n = 1;
        while n < 1024 {
            match self.rx.try_recv() {
                Ok(frame) => f(&frame, ts),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
            n += 1;
        }
        Ok(n)
    }

    fn dropped(&self) -> u64 {
        let s = self.shared();
        s.dropped.load(Ordering::Relaxed) + s.missed.load(Ordering::Relaxed)
    }
}

impl Drop for PktMon {
    fn drop(&mut self) {
        // SAFETY: 各句柄要么为空（那一步没走到），要么是 open 里成功建出、只在这里关一次。
        // 先停会话、关流，回调不再来了才释放 Shared
        unsafe {
            if !self.session.is_null() {
                (self.api.set_active)(self.session, 0);
            }
            if !self.stream.is_null() {
                (self.api.close_stream)(self.stream);
            }
            if !self.session.is_null() {
                (self.api.close_session)(self.session);
            }
            (self.api.uninitialize)(self.handle);
            drop(Box::from_raw(self.shared));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::offset_of;

    /// 布局照 Packet Monitor 参考里的 C 结构（x64）
    #[test]
    fn layouts_match_the_c_structures() {
        assert_eq!(offset_of!(Spec, id), 388);
        assert_eq!(offset_of!(Spec, detail), 408);
        assert_eq!(size_of::<Spec>(), 424);
        assert_eq!(size_of::<StreamConfig>(), 32);
        assert_eq!(offset_of!(StreamConfig, truncation_size), 26);
        assert_eq!(size_of::<DataDescriptor>(), 32);
        assert_eq!(offset_of!(Metadata, drop_reason), 24);
        assert_eq!(offset_of!(Metadata, timestamp), 40);
        assert_eq!(size_of::<Metadata>(), 48);
    }

    #[test]
    fn raw_ip_frames_get_an_ethernet_header() {
        let ipv4 = [0x45u8, 0, 0, 20];
        let frame = to_ethernet(PACKET_IP, &ipv4).unwrap();
        assert_eq!(&frame[12..14], &[0x08, 0x00]);
        assert_eq!(&frame[14..], &ipv4);
        let ipv6 = [0x60u8, 0, 0, 0];
        assert_eq!(
            &to_ethernet(PACKET_IP, &ipv6).unwrap()[12..14],
            &[0x86, 0xdd]
        );
        assert_eq!(to_ethernet(PACKET_ETHERNET, &ipv4).unwrap(), ipv4);
        assert!(to_ethernet(2, &ipv4).is_none(), "Wi-Fi 原始帧不收");
    }

    /// 真机验证（管理员、Windows 11 / Server 2022 6B+）：抓所有网卡，自己连一次网关的 TCP 端口，
    /// 要收到帧且其中有这条连接的包。`cargo test --target x86_64-pc-windows-gnu --no-run` 编出测试程序后在目标机上
    /// `<测试程序> --ignored pktmon_sees_live_traffic --nocapture`；OPENXDR_TEST_TARGET 指定连谁（默认 10.1.1.1:80）
    #[cfg(windows)]
    #[test]
    #[ignore = "需要管理员与带 Packet Monitor 实时 API 的 Windows"]
    fn pktmon_sees_live_traffic() {
        let target: std::net::SocketAddr = std::env::var("OPENXDR_TEST_TARGET")
            .unwrap_or_else(|_| "10.1.1.1:80".into())
            .parse()
            .unwrap();
        let mut cap = PktMon::open("all").unwrap();
        eprintln!("网卡：{:?}", cap.interfaces);
        let conn = std::net::TcpStream::connect_timeout(&target, Duration::from_secs(3));
        let local = conn.as_ref().ok().and_then(|c| c.local_addr().ok());
        let (mut frames, mut decoded, mut ours) = (0, 0, 0);
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            cap.poll_batch(&mut |frame, _| {
                frames += 1;
                if let Some(p) = crate::decode::decode(frame) {
                    decoded += 1;
                    let ends = [(p.src, p.sport), (p.dst, p.dport)];
                    if local.is_some_and(|l| ends.contains(&(l.ip(), l.port()))) {
                        ours += 1;
                    }
                }
            })
            .unwrap();
        }
        eprintln!(
            "帧 {frames}，可解码 {decoded}，本次连接 {ours}，丢 {}；连接结果 {conn:?}",
            cap.dropped()
        );
        assert!(frames > 0, "一个帧都没收到");
        assert!(ours > 0, "没看到自己发起的那条连接");
    }

    #[test]
    fn same_packet_group_is_taken_once() {
        let mut r = Recent::default();
        assert!(r.first(7));
        assert!(!r.first(7));
        assert!(r.first(0) && r.first(0), "没有组号的不去重");
        for g in 100..100 + DEDUP as u64 {
            r.first(g);
        }
        assert!(r.first(7), "太久以前的组号会被忘掉");
    }
}
