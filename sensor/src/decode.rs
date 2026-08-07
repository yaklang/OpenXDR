//! 零拷贝协议解码：Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP。
//! 只解到传输层，payload 原样借出给协议识别层。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;

pub const TCP_FIN: u8 = 1 << 0;
pub const TCP_SYN: u8 = 1 << 1;
pub const TCP_RST: u8 = 1 << 2;

pub struct Packet<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub tcp_flags: u8,
    pub payload: &'a [u8],
    /// 链路层总长度，用于流量统计
    pub frame_len: usize,
}

pub fn decode(frame: &[u8]) -> Option<Packet<'_>> {
    let mut offset = 14;
    let mut ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);

    // VLAN / QinQ：最多剥两层，再多的当异常丢弃
    for _ in 0..2 {
        if ethertype != ETHERTYPE_VLAN && ethertype != ETHERTYPE_QINQ {
            break;
        }
        ethertype = u16::from_be_bytes([*frame.get(offset + 2)?, *frame.get(offset + 3)?]);
        offset += 4;
    }

    match ethertype {
        ETHERTYPE_IPV4 => decode_ipv4(frame, offset),
        ETHERTYPE_IPV6 => decode_ipv6(frame, offset),
        _ => None,
    }
}

fn decode_ipv4(frame: &[u8], offset: usize) -> Option<Packet<'_>> {
    let ip = frame.get(offset..)?;
    let ihl = (ip.first()? & 0x0f) as usize * 4;
    if ihl < 20 {
        return None;
    }
    let total_len = u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]) as usize;
    let proto = *ip.get(9)?;
    let src = Ipv4Addr::new(*ip.get(12)?, *ip.get(13)?, *ip.get(14)?, *ip.get(15)?);
    let dst = Ipv4Addr::new(*ip.get(16)?, *ip.get(17)?, *ip.get(18)?, *ip.get(19)?);

    // 分片包：只有首片带传输层头，非首片直接丢（重组是二期）
    let frag_off = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]) & 0x1fff;
    if frag_off != 0 {
        return None;
    }

    let l4_len = total_len.checked_sub(ihl)?.min(ip.len() - ihl);
    decode_l4(
        IpAddr::V4(src),
        IpAddr::V4(dst),
        proto,
        ip.get(ihl..ihl + l4_len)?,
        frame.len(),
    )
}

fn decode_ipv6(frame: &[u8], offset: usize) -> Option<Packet<'_>> {
    let ip = frame.get(offset..)?;
    let payload_len = u16::from_be_bytes([*ip.get(4)?, *ip.get(5)?]) as usize;
    let next_header = *ip.get(6)?;
    let src: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
    let dst: [u8; 16] = ip.get(24..40)?.try_into().ok()?;

    // 扩展头不解析：带扩展头的包跳过，不影响主流量识别
    if next_header != IPPROTO_TCP && next_header != IPPROTO_UDP {
        return None;
    }
    let l4_len = payload_len.min(ip.len() - 40);
    decode_l4(
        IpAddr::V6(Ipv6Addr::from(src)),
        IpAddr::V6(Ipv6Addr::from(dst)),
        next_header,
        ip.get(40..40 + l4_len)?,
        frame.len(),
    )
}

fn decode_l4(
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    l4: &[u8],
    frame_len: usize,
) -> Option<Packet<'_>> {
    let sport = u16::from_be_bytes([*l4.first()?, *l4.get(1)?]);
    let dport = u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]);

    let (tcp_flags, payload) = match proto {
        IPPROTO_TCP => {
            let data_offset = (*l4.get(12)? >> 4) as usize * 4;
            if data_offset < 20 {
                return None;
            }
            (*l4.get(13)?, l4.get(data_offset..).unwrap_or(&[]))
        }
        IPPROTO_UDP => (0, l4.get(8..).unwrap_or(&[])),
        _ => return None,
    };

    Some(Packet {
        src,
        dst,
        proto,
        sport,
        dport,
        tcp_flags,
        payload,
        frame_len,
    })
}
