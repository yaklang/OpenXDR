//! DNS 采集：AF_PACKET 抓本机经过的 UDP 53 报文，配对查询与应答，组装成 DNS 活动事件（OCSF 4003）。
//!
//! 没有 sensor 的部署也拿得到域名：情报的域名部分有东西可撞，出站连接能带上域名。
//! 只收本机自己（客户端地址是本机地址）与本机容器（报文经 veth 接口）的查询；
//! 宿主机网桥上转发的虚拟机流量、别的主机来问本机 DNS 服务的查询都不收——那不是这台主机做的事。
//! 但容器是解析器（AdGuard、dnsmasq）时，它发出的上游查询其实是替局域网客户端问的：别的主机送进容器的查询
//! 只记不报，容器随后转发同一域名时在事件上标出真正的查询方（requester），告警才不会全算在解析器头上。
//!
//! 内核侧用经典 BPF 过滤器只放行 UDP 53，用户态不碰别的包。发起进程由 eBPF 的 UDP 发送事件按源端口归属，
//! 默认构建没有 eBPF 时只有地址、没有进程。同一客户端对同一域名、同一类型的查询 60 秒内只报一次。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use super::{Container, EventSink, container, dnsnames};
use crate::pb::AgentEvent;

/// OCSF DNS Activity
const CLASS_DNS: u32 = 4003;
const DNS_PORT: u16 = 53;

/// 查询等应答的时限，过了按无应答上报
const ANSWER_WAIT: Duration = Duration::from_secs(5);
/// 应答到了再等一会儿才上报：抓包与 eBPF 的 UDP 发送事件走两条路，后者可能晚到
const ATTRIBUTION_WAIT: Duration = Duration::from_secs(1);
/// 同一 (客户端, 域名, 类型) 的上报间隔
const REPORT_WINDOW: Duration = Duration::from_secs(60);
/// 同一报文在多个接口（veth、网桥、物理口、lo 收发两份）各抓到一次，这段时间内只算一次
const DUP_WINDOW: Duration = Duration::from_secs(10);
/// 各表上限，超过即清理过期项，防止查询风暴撑爆内存
const MAX_TRACKED: usize = 8192;
/// 应答地址最多记几个：够做情报碰撞与域名回填
const MAX_ANSWERS: usize = 8;
/// 客户端查询送进容器后，容器多久内转发同一域名算作替它问的
const REQUESTER_WINDOW: Duration = Duration::from_secs(5);
/// sockaddr_ll.sll_pkttype：本机发出的包
const PACKET_OUTGOING: u8 = 4;

/// DNS 查询的发起进程，由 eBPF 采集按源端口提供
#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
pub struct Origin {
    pub pid: u32,
    pub guid: Option<Uuid>,
    pub name: Option<String>,
    pub exe: Option<String>,
    pub container: Option<Arc<Container>>,
    pub command: Option<Arc<str>>,
}

pub type Resolver = Arc<dyn Fn(u16) -> Option<Origin> + Send + Sync>;

pub fn spawn(agent_id: String, sink: EventSink, resolver: Option<Resolver>) {
    match open() {
        Ok(fd) => {
            sink.capability(
                "dns",
                "af_packet",
                if resolver.is_some() {
                    "active"
                } else {
                    "degraded"
                },
            );
            let how = if resolver.is_some() {
                "，按 eBPF UDP 事件归属进程"
            } else {
                "，没有 eBPF，不归属进程"
            };
            eprintln!("DNS 采集: AF_PACKET（UDP 53{how}）");
            std::thread::spawn(move || {
                let status = sink.clone();
                run(fd, agent_id, sink, resolver);
                status.capability("dns", "af_packet", "unavailable");
            });
        }
        Err(e) => {
            sink.capability("dns", "af_packet", "unavailable");
            eprintln!("DNS 采集不可用（{e}）");
        }
    }
}

/// 应答里的地址按 TTL 记住（最短 1 分钟，连接常在 TTL 过期后才建；最长 1 小时），出站连接回填域名用
fn remember(message: &Message) {
    for answer in &message.answers {
        if let Rdata::Ip(ip) = answer.data {
            let ttl = Duration::from_secs(answer.ttl.clamp(60, 3600) as u64);
            dnsnames::remember(&message.qname, ip, ttl);
        }
    }
}

fn open() -> std::io::Result<i32> {
    // SAFETY: 标准 socket 调用，返回值检查后才使用
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut filter = udp53_filter();
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // 每秒醒一次：上报侧关闭（断线重连）时及时退出
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    // SAFETY: 传入的结构体在调用期间有效，长度与类型匹配
    let ok = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const _ as *const libc::c_void,
            size_of::<libc::sock_fprog>() as u32,
        ) == 0
            && libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                size_of::<libc::timeval>() as u32,
            ) == 0
    };
    if !ok {
        let err = std::io::Error::last_os_error();
        // SAFETY: fd 是上面刚打开的
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok(fd)
}

/// 经典 BPF：SOCK_DGRAM 包从网络层开始。放行源或目的端口为 53 的 UDP（IPv4 不收分片，IPv6 不看扩展头）
fn udp53_filter() -> Vec<libc::sock_filter> {
    let op = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    const LD_H_ABS: u16 = 0x28;
    const LD_B_ABS: u16 = 0x30;
    const LDX_B_MSH: u16 = 0xb1;
    const LD_H_IND: u16 = 0x48;
    const JEQ: u16 = 0x15;
    const JSET: u16 = 0x45;
    const RET: u16 = 0x06;
    const SKF_AD_PROTOCOL: u32 = 0xfffff000; // SKF_AD_OFF + SKF_AD_PROTOCOL：帧的以太类型
    let port = DNS_PORT as u32;
    vec![
        op(LD_H_ABS, 0, 0, SKF_AD_PROTOCOL), // 0
        op(JEQ, 0, 9, 0x0800),               // 1  IPv4 → 2，否则 → 11
        op(LD_B_ABS, 0, 0, 9),               // 2  协议号
        op(JEQ, 0, 15, 17),                  // 3  非 UDP → 丢
        op(LD_H_ABS, 0, 0, 6),               // 4  分片偏移
        op(JSET, 13, 0, 0x1fff),             // 5  分片 → 丢
        op(LDX_B_MSH, 0, 0, 0),              // 6  X = 首部长度
        op(LD_H_IND, 0, 0, 0),               // 7  源端口
        op(JEQ, 9, 0, port),                 // 8
        op(LD_H_IND, 0, 0, 2),               // 9  目的端口
        op(JEQ, 7, 8, port),                 // 10
        op(JEQ, 0, 7, 0x86dd),               // 11 IPv6，否则 → 丢
        op(LD_B_ABS, 0, 0, 6),               // 12 下一个首部
        op(JEQ, 0, 5, 17),                   // 13
        op(LD_H_ABS, 0, 0, 40),              // 14 源端口
        op(JEQ, 2, 0, port),                 // 15
        op(LD_H_ABS, 0, 0, 42),              // 16 目的端口
        op(JEQ, 0, 1, port),                 // 17
        op(RET, 0, 0, 4096),                 // 18 收
        op(RET, 0, 0, 0),                    // 19 丢
    ]
}

/// 一次查询：客户端是发起查询的一方
#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    client: IpAddr,
    port: u16,
    id: u16,
}

struct Pending {
    server: IpAddr,
    message: Message,
    answer: Option<(Message, Instant)>,
    container: Option<Arc<Container>>,
    /// 容器发出的查询经过的 veth，用来找送进同一容器的客户端查询
    iface: Option<String>,
    seen: Instant,
}

/// 送进容器的一次客户端查询：(veth, 小写域名, 类型)
type Inbound = (String, String, u16);

struct State {
    agent_id: String,
    sink: EventSink,
    resolver: Option<Resolver>,
    pending: HashMap<Key, Pending>,
    done: HashMap<Key, Instant>,
    reported: HashMap<(IpAddr, String, u16), Instant>,
    inbound: HashMap<Inbound, (IpAddr, Instant)>,
    local: Vec<IpAddr>,
    local_at: Option<Instant>,
    ifnames: HashMap<i32, String>,
}

fn run(fd: i32, agent_id: String, sink: EventSink, resolver: Option<Resolver>) {
    let mut st = State {
        agent_id,
        sink,
        resolver,
        pending: HashMap::new(),
        done: HashMap::new(),
        reported: HashMap::new(),
        inbound: HashMap::new(),
        local: Vec::new(),
        local_at: None,
        ifnames: HashMap::new(),
    };
    let mut buf = vec![0u8; 4096];
    while !st.sink.is_closed() {
        // SAFETY: sockaddr_ll 全零是合法初值；buf 与 addr 的长度如实传入
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut len = size_of::<libc::sockaddr_ll>() as u32;
        // SAFETY: fd 是本线程持有的 AF_PACKET 套接字；buf 为独占的可写 Vec，长度如实传 buf.len()；
        // addr / len 指向栈上的 sockaddr_ll 与其大小，内核最多写 len 字节并回填实际长度。
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut addr as *mut _ as *mut libc::sockaddr,
                &mut len,
            )
        };
        if n > 0 {
            st.packet(&buf[..n as usize], addr.sll_ifindex, addr.sll_pkttype);
        }
        st.expire();
    }
    // SAFETY: fd 归本线程所有
    unsafe { libc::close(fd) };
}

impl State {
    fn packet(&mut self, pkt: &[u8], ifindex: i32, pkttype: u8) {
        let Some((src, sport, dst, dport, payload)) = udp(pkt) else {
            return;
        };
        let Some(message) = parse(payload) else {
            return;
        };
        let (client, port, server) = if message.response {
            (dst, dport, src)
        } else {
            (src, sport, dst)
        };
        if !message.response && dport != DNS_PORT || message.response && sport != DNS_PORT {
            return;
        }
        let iface = self.ifname(ifindex);
        // veth 是容器与宿主机之间的线：容器发出的包在宿主机这端是收到，送进容器的包是发出。
        // 只认容器当客户端的方向（容器发出的查询、送回容器的应答）；别的主机来问容器里 DNS 服务的流量
        // 也经过 veth，但那是别人的查询，不收
        let from_container =
            iface.starts_with("veth") && (pkttype == PACKET_OUTGOING) == message.response;
        if iface.starts_with("veth")
            && !message.response
            && pkttype == PACKET_OUTGOING
            && !self.is_local(client)
        {
            let key = (iface, message.qname.to_ascii_lowercase(), message.qtype);
            self.inbound.insert(key, (client, Instant::now()));
            return;
        }
        if !from_container && !self.is_local(client) {
            return;
        }
        // Proxmox 的 LXC 容器接口名是 veth<VMID>i<序号>；docker 的 veth 名是随机的，靠进程归属认容器
        let container = from_container
            .then(|| lxc_of(&iface).map(container::lxc))
            .flatten();
        let key = Key {
            client,
            port,
            id: message.id,
        };
        if message.response {
            remember(&message);
        }
        if self.done.contains_key(&key) {
            return;
        }
        let now = Instant::now();
        let entry = self.pending.entry(key).or_insert_with(|| Pending {
            server,
            message: message.clone(),
            answer: None,
            container: None,
            iface: None,
            seen: now,
        });
        entry.container = entry.container.take().or(container);
        if from_container && entry.iface.is_none() {
            entry.iface = Some(iface);
        }
        // 应答先存着，由 expire 稍后上报：应答往往几毫秒就到，eBPF 那边的 UDP 事件可能还没处理完
        if message.response && entry.answer.is_none() {
            entry.answer = Some((message, now));
        }
    }

    /// 应答到了 1 秒的上报（等进程归属就位）；超时没等到应答的按无应答上报；过期的去重记录清掉
    fn expire(&mut self) {
        let now = Instant::now();
        let ready: Vec<Key> = self
            .pending
            .iter()
            .filter(|(_, p)| match &p.answer {
                Some((_, at)) => now.duration_since(*at) >= ATTRIBUTION_WAIT,
                None => now.duration_since(p.seen) >= ANSWER_WAIT,
            })
            .map(|(k, _)| k.clone())
            .collect();
        for key in ready {
            if let Some(p) = self.pending.remove(&key) {
                self.done.insert(key.clone(), now);
                let answer = p.answer.as_ref().map(|(m, _)| m);
                let requester = self.requester(&p);
                self.report(&key, p.server, &p.message, answer, p.container, requester);
            }
        }
        if self.done.len() >= MAX_TRACKED {
            self.done.retain(|_, t| now.duration_since(*t) < DUP_WINDOW);
        }
        if self.reported.len() >= MAX_TRACKED {
            self.reported
                .retain(|_, t| now.duration_since(*t) < REPORT_WINDOW);
        }
        if self.pending.len() >= MAX_TRACKED {
            self.pending.clear();
        }
        if self.inbound.len() >= MAX_TRACKED {
            self.inbound
                .retain(|_, (_, t)| now.duration_since(*t) < REQUESTER_WINDOW);
        }
    }

    /// 容器转发的这条查询是替谁问的：同一容器前后几秒内收到的同名同类型客户端查询
    fn requester(&self, p: &Pending) -> Option<IpAddr> {
        let iface = p.iface.clone()?;
        let key = (iface, p.message.qname.to_ascii_lowercase(), p.message.qtype);
        let (client, at) = self.inbound.get(&key)?;
        let near = p.seen.saturating_duration_since(*at) <= REQUESTER_WINDOW
            && at.saturating_duration_since(p.seen) <= REQUESTER_WINDOW;
        near.then_some(*client)
    }

    fn report(
        &mut self,
        key: &Key,
        server: IpAddr,
        query: &Message,
        answer: Option<&Message>,
        container: Option<Arc<Container>>,
        requester: Option<IpAddr>,
    ) {
        let now = Instant::now();
        let dedup = (key.client, query.qname.clone(), query.qtype);
        if let Some(t) = self.reported.get(&dedup)
            && now.duration_since(*t) < REPORT_WINDOW
        {
            return;
        }
        self.reported.insert(dedup, now);
        // 发起进程只在本机网络命名空间里按源端口找得到；容器里的查询由容器自己的进程发出，端口照样能对上
        let origin = self.resolver.as_ref().and_then(|r| r(key.port));
        let container = origin
            .as_ref()
            .and_then(|o| o.container.clone())
            .or(container);
        let _ = self.sink.send(dns_event(
            &self.agent_id,
            key,
            server,
            query,
            answer,
            Who {
                origin: origin.as_ref(),
                container: container.as_deref(),
                requester,
            },
        ));
    }

    fn is_local(&mut self, ip: IpAddr) -> bool {
        let stale = self
            .local_at
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(60));
        if stale {
            self.local = if_addrs::get_if_addrs()
                .unwrap_or_default()
                .into_iter()
                .map(|i| i.addr.ip())
                .collect();
            self.local_at = Some(Instant::now());
        }
        ip.is_loopback() || self.local.contains(&ip)
    }

    fn ifname(&mut self, ifindex: i32) -> String {
        if let Some(name) = self.ifnames.get(&ifindex) {
            return name.clone();
        }
        let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
        // SAFETY: buf 长度为 IF_NAMESIZE，满足 if_indextoname 的要求
        let name = unsafe {
            let p = libc::if_indextoname(ifindex as u32, buf.as_mut_ptr());
            if p.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };
        // 接口会增删（容器起停），索引可能复用：表大了就整体重建
        if self.ifnames.len() >= 1024 {
            self.ifnames.clear();
        }
        self.ifnames.insert(ifindex, name.clone());
        name
    }
}

/// veth203i0 → 203
fn lxc_of(iface: &str) -> Option<&str> {
    let rest = iface.strip_prefix("veth")?;
    let (vmid, nic) = rest.split_once('i')?;
    (!vmid.is_empty()
        && vmid.bytes().all(|b| b.is_ascii_digit())
        && !nic.is_empty()
        && nic.bytes().all(|b| b.is_ascii_digit()))
    .then_some(vmid)
}

/// 网络层包 → (源, 源端口, 目的, 目的端口, UDP 载荷)
fn udp(pkt: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16, &[u8])> {
    let version = pkt.first()? >> 4;
    let (src, dst, l4): (IpAddr, IpAddr, &[u8]) = match version {
        4 => {
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < 20 || pkt.len() < ihl + 8 || pkt[9] != 17 {
                return None;
            }
            let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
            let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            (src.into(), dst.into(), &pkt[ihl..])
        }
        6 => {
            if pkt.len() < 48 || pkt[6] != 17 {
                return None;
            }
            let src: [u8; 16] = pkt[8..24].try_into().ok()?;
            let dst: [u8; 16] = pkt[24..40].try_into().ok()?;
            (
                Ipv6Addr::from(src).into(),
                Ipv6Addr::from(dst).into(),
                &pkt[40..],
            )
        }
        _ => return None,
    };
    let sport = u16::from_be_bytes([l4[0], l4[1]]);
    let dport = u16::from_be_bytes([l4[2], l4[3]]);
    let len = (u16::from_be_bytes([l4[4], l4[5]]) as usize).clamp(8, l4.len());
    Some((src, sport, dst, dport, &l4[8..len]))
}

#[derive(Clone, Debug, PartialEq)]
struct Message {
    id: u16,
    response: bool,
    rcode: u8,
    qname: String,
    qtype: u16,
    answers: Vec<Answer>,
}

#[derive(Clone, Debug, PartialEq)]
struct Answer {
    rtype: u16,
    ttl: u32,
    data: Rdata,
}

#[derive(Clone, Debug, PartialEq)]
enum Rdata {
    Ip(IpAddr),
    Name(String),
}

/// 标准查询（opcode 0）的首个问题与应答段里的 A / AAAA / CNAME。格式不对就整个丢弃
fn parse(msg: &[u8]) -> Option<Message> {
    if msg.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if (flags >> 11) & 0xf != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    if qdcount == 0 {
        return None;
    }
    let (qname, mut pos) = read_name(msg, 12)?;
    let qtype = u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]);
    pos += 4;
    let mut answers = Vec::new();
    for _ in 0..ancount {
        let (_, next) = read_name(msg, pos)?;
        let head = msg.get(next..next + 10)?;
        let rtype = u16::from_be_bytes([head[0], head[1]]);
        let ttl = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
        let rdlen = u16::from_be_bytes([head[8], head[9]]) as usize;
        let rdata = msg.get(next + 10..next + 10 + rdlen)?;
        let data = match (rtype, rdlen) {
            (1, 4) => Some(Rdata::Ip(IpAddr::from(<[u8; 4]>::try_from(rdata).ok()?))),
            (28, 16) => Some(Rdata::Ip(IpAddr::from(<[u8; 16]>::try_from(rdata).ok()?))),
            (5, _) => read_name(msg, next + 10).map(|(n, _)| Rdata::Name(n)),
            _ => None,
        };
        if let Some(data) = data
            && answers.len() < MAX_ANSWERS
        {
            answers.push(Answer { rtype, ttl, data });
        }
        pos = next + 10 + rdlen;
    }
    Some(Message {
        id: u16::from_be_bytes([msg[0], msg[1]]),
        response: flags & 0x8000 != 0,
        rcode: (flags & 0xf) as u8,
        qname,
        qtype,
        answers,
    })
}

/// 读域名（支持压缩指针），返回小写、不带末尾点的名字与紧跟其后的位置。
/// 指针最多跳 16 次，防恶意报文绕圈；不可打印字符换成 ?，隧道检测仍看得出异常
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut end = None;
    for _ in 0..128 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some((name, end.unwrap_or(pos + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let target = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            if target >= pos {
                return None;
            }
            pos = target;
            continue;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.iter().map(|&b| {
            let c = b.to_ascii_lowercase() as char;
            if c.is_ascii_graphic() { c } else { '?' }
        }));
        if name.len() > 253 {
            return None;
        }
        pos += 1 + len;
    }
    None
}

/// 字段与 sensor 的 DNS 事件同一约定（query.hostname、answers[].ip），规则与情报对两路一视同仁
/// 这条查询是谁发的：本机进程、所在容器、替哪个客户端转发
#[derive(Default)]
struct Who<'a> {
    origin: Option<&'a Origin>,
    container: Option<&'a Container>,
    requester: Option<IpAddr>,
}

fn dns_event(
    agent_id: &str,
    key: &Key,
    server: IpAddr,
    query: &Message,
    answer: Option<&Message>,
    who: Who,
) -> AgentEvent {
    let Who {
        origin,
        container,
        requester,
    } = who;
    let mut raw = serde_json::json!({
        // OCSF：1 Query（没等到应答）/ 6 Traffic（一问一答）
        "activity_id": if answer.is_some() { 6 } else { 1 },
        "query": { "hostname": query.qname, "type": dnsnames::qtype_name(query.qtype) },
        "src_endpoint": { "ip": key.client.to_string(), "port": key.port },
        "dst_endpoint": { "ip": server.to_string(), "port": DNS_PORT },
    });
    if let Some(answer) = answer {
        raw["query"]["rcode_id"] = answer.rcode.into();
        raw["answers"] = answer
            .answers
            .iter()
            .map(|a| {
                let mut v =
                    serde_json::json!({ "type": dnsnames::qtype_name(a.rtype), "ttl": a.ttl });
                match &a.data {
                    Rdata::Ip(ip) => v["ip"] = ip.to_string().into(),
                    Rdata::Name(n) => v["rdata"] = n.as_str().into(),
                }
                v
            })
            .collect();
    }
    if let Some(o) = origin {
        raw["process"] = serde_json::json!({ "pid": o.pid, "uid": o.guid.map(|g| g.to_string()) });
        if let Some(name) = &o.name {
            raw["process"]["name"] = name.as_str().into();
        }
        if let Some(exe) = &o.exe {
            raw["process"]["file"] = serde_json::json!({ "path": exe });
        }
        if let Some(id) = &o.command {
            raw["platform_command"] = serde_json::json!({ "uid": id.as_ref() });
        }
    }
    if let Some(c) = container {
        raw["container"] = c.to_json();
    }
    if let Some(ip) = requester {
        raw["requester"] = serde_json::json!({ "ip": ip.to_string() });
    }
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: CLASS_DNS,
        process_guid: origin
            .and_then(|o| o.guid)
            .map(|g| g.to_string())
            .unwrap_or_default(),
        parent_process_guid: String::new(),
        username: String::new(),
        conn_tuple: format!("udp:{}:{}>{}:{}", key.client, key.port, server, DNS_PORT),
        raw_json: raw.to_string(),
        dropped_events: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// example.com A 查询，id 0x1234
    fn query() -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(b"\x07Example\x03com\x00\x00\x01\x00\x01");
        m
    }

    /// 应答：CNAME www → example.com（压缩指针指回问题），再给一个 A
    fn response() -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6]);
        m.extend_from_slice(b"\x03www\xc0\x0c");
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 93, 184, 216, 34]);
        m
    }

    #[test]
    fn parses_query_and_response() {
        let q = parse(&query()).unwrap();
        assert!(!q.response);
        assert_eq!(
            (q.id, q.qname.as_str(), q.qtype),
            (0x1234, "example.com", 1)
        );
        let r = parse(&response()).unwrap();
        assert!(r.response);
        assert_eq!(r.rcode, 0);
        assert_eq!(
            r.answers,
            vec![
                Answer {
                    rtype: 5,
                    ttl: 60,
                    data: Rdata::Name("www.example.com".into())
                },
                Answer {
                    rtype: 1,
                    ttl: 300,
                    data: Rdata::Ip("93.184.216.34".parse().unwrap())
                },
            ]
        );
    }

    #[test]
    fn rejects_bad_messages() {
        assert!(parse(&[0; 11]).is_none());
        // opcode 非 0（如 NOTIFY / UPDATE）不收
        let mut notify = query();
        notify[2] = 0x20;
        assert!(parse(&notify).is_none());
        // 指针指向自己或之后：绕圈报文
        let mut looped = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        looped.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        assert!(parse(&looped).is_none());
        // 截断
        let r = response();
        assert!(parse(&r[..r.len() - 2]).is_none());
    }

    #[test]
    fn udp_headers() {
        let payload = query();
        let mut v4 = vec![
            0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 5, 10, 0, 0, 1,
        ];
        let udp_len = (8 + payload.len()) as u16;
        v4.extend_from_slice(&[0xd4, 0x31, 0, 53]);
        v4.extend_from_slice(&udp_len.to_be_bytes());
        v4.extend_from_slice(&[0, 0]);
        v4.extend_from_slice(&payload);
        let (src, sport, dst, dport, body) = udp(&v4).unwrap();
        assert_eq!(
            (src.to_string(), sport, dst.to_string(), dport),
            ("10.0.0.5".into(), 54321, "10.0.0.1".into(), 53)
        );
        assert_eq!(body, payload.as_slice());
        v4[9] = 6;
        assert!(udp(&v4).is_none(), "非 UDP 不收");
    }

    #[test]
    fn lxc_interface() {
        assert_eq!(lxc_of("veth203i0"), Some("203"));
        assert_eq!(lxc_of("veth1001i12"), Some("1001"));
        assert_eq!(lxc_of("veth5f3a2b1"), None);
        assert_eq!(lxc_of("vethi0"), None);
        assert_eq!(lxc_of("tap108i0"), None);
    }

    #[test]
    fn event_shape() {
        let key = Key {
            client: "10.0.0.5".parse().unwrap(),
            port: 54321,
            id: 0x1234,
        };
        let q = parse(&query()).unwrap();
        let r = parse(&response()).unwrap();
        let origin = Origin {
            pid: 7,
            guid: None,
            name: Some("curl".into()),
            exe: None,
            container: None,
            command: None,
        };
        let c = Container {
            runtime: "lxc",
            uid: "203".into(),
            name: None,
            healthcheck: false,
        };
        let evt = dns_event(
            "a",
            &key,
            "10.0.0.1".parse().unwrap(),
            &q,
            Some(&r),
            Who {
                origin: Some(&origin),
                container: Some(&c),
                requester: Some("192.168.1.20".parse().unwrap()),
            },
        );
        assert_eq!(evt.class_uid, CLASS_DNS);
        assert_eq!(evt.conn_tuple, "udp:10.0.0.5:54321>10.0.0.1:53");
        let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
        assert_eq!(v["activity_id"], 6);
        assert_eq!(v["query"]["hostname"], "example.com");
        assert_eq!(v["query"]["type"], "A");
        assert_eq!(v["query"]["rcode_id"], 0);
        assert_eq!(v["answers"][1]["ip"], "93.184.216.34");
        assert_eq!(v["answers"][0]["rdata"], "www.example.com");
        assert_eq!(v["process"]["name"], "curl");
        assert_eq!(v["container"]["uid"], "203");
        assert_eq!(v["requester"]["ip"], "192.168.1.20");

        let unanswered = dns_event(
            "a",
            &key,
            "10.0.0.1".parse().unwrap(),
            &q,
            None,
            Who::default(),
        );
        let v: Value = serde_json::from_str(&unanswered.raw_json).unwrap();
        assert_eq!(v["activity_id"], 1);
        assert!(v.get("answers").is_none() && v["query"].get("rcode_id").is_none());
        assert!(v.get("requester").is_none());
    }

    #[test]
    fn requester_is_the_client_that_asked_the_container() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let now = Instant::now();
        let client: IpAddr = "192.168.1.20".parse().unwrap();
        let st = State {
            agent_id: "a".into(),
            sink: EventSink {
                tx,
                dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                health: crate::health::Health::new(),
                generation: 0,
            },
            resolver: None,
            pending: HashMap::new(),
            done: HashMap::new(),
            reported: HashMap::new(),
            inbound: HashMap::from([(
                ("veth201i0".into(), "example.com".into(), 1),
                (client, now),
            )]),
            local: Vec::new(),
            local_at: None,
            ifnames: HashMap::new(),
        };
        let pending = |iface: Option<&str>, seen: Instant| Pending {
            server: "1.1.1.1".parse().unwrap(),
            message: parse(&query()).unwrap(),
            answer: None,
            container: None,
            iface: iface.map(str::to_string),
            seen,
        };
        assert_eq!(st.requester(&pending(Some("veth201i0"), now)), Some(client));
        // 别的容器、本机自己的查询、隔太久的都不算
        assert_eq!(st.requester(&pending(Some("veth202i0"), now)), None);
        assert_eq!(st.requester(&pending(None, now)), None);
        let late = now + REQUESTER_WINDOW + Duration::from_secs(1);
        assert_eq!(st.requester(&pending(Some("veth201i0"), late)), None);
    }

    #[test]
    fn remembers_answer_names() {
        remember(&parse(&response()).unwrap());
        assert_eq!(
            dnsnames::hostname_of("93.184.216.34".parse().unwrap()).as_deref(),
            Some("example.com")
        );
        assert_eq!(dnsnames::hostname_of("1.1.1.1".parse().unwrap()), None);
    }

    /// 过滤器跳转偏移手算，越界会被内核拒绝：每条跳转都必须落在程序内
    #[test]
    fn filter_jumps_in_range() {
        let f = udp53_filter();
        for (i, ins) in f.iter().enumerate() {
            if ins.code & 0x07 == 0x05 {
                assert!(
                    i + 1 + (ins.jt as usize) < f.len() && i + 1 + (ins.jf as usize) < f.len(),
                    "第 {i} 条"
                );
            }
        }
        assert_eq!(f[18].k, 4096);
        assert_eq!(f[19].k, 0);
    }
}
