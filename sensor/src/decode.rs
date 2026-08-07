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
pub const TCP_ACK: u8 = 1 << 4;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12]; // dst+src mac
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// 构造 IPv4 + TCP 帧。flags 完整 16 位（高 3 位为 DF/MF/取值见上，低 13 位是分片偏移）。
    fn ipv4_tcp(sport: u16, dport: u16, tcp_flags: u8, frag_field: u16, payload: &[u8]) -> Vec<u8> {
        let ihl = 20;
        let total = (ihl + 20 + payload.len()) as u16;
        let mut ip = Vec::new();
        ip.push(0x45); // IPv4, IHL=5
        ip.push(0); // DSCP/ECN
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 0]); // ident
        ip.extend_from_slice(&frag_field.to_be_bytes());
        ip.push(64); // TTL
        ip.push(IPPROTO_TCP);
        ip.extend_from_slice(&[0, 0]); // checksum 占位
        ip.extend_from_slice(&[1, 2, 3, 4]); // src
        ip.extend_from_slice(&[5, 6, 7, 8]); // dst
        ip.extend_from_slice(&sport.to_be_bytes());
        ip.extend_from_slice(&dport.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0]); // seq
        ip.extend_from_slice(&[0, 0, 0, 0]); // ack
        ip.push(5 << 4); // data offset 5
        ip.push(tcp_flags);
        ip.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // window+checksum+urg
        ip.extend_from_slice(payload);
        eth(0x0800, &ip)
    }

    fn ipv4_udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = (20 + 8 + payload.len()) as u16;
        let mut ip = Vec::new();
        ip.push(0x45);
        ip.push(0);
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0]);
        ip.push(64);
        ip.push(IPPROTO_UDP);
        ip.extend_from_slice(&[0, 0]);
        ip.extend_from_slice(&[1, 2, 3, 4]);
        ip.extend_from_slice(&[5, 6, 7, 8]);
        ip.extend_from_slice(&sport.to_be_bytes());
        ip.extend_from_slice(&dport.to_be_bytes());
        ip.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0]); // checksum
        ip.extend_from_slice(payload);
        eth(0x0800, &ip)
    }

    fn ipv6_tcp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut ip = Vec::new();
        ip.extend_from_slice(&[0x60, 0, 0, 0]); // v6 + flow
        ip.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        ip.push(IPPROTO_TCP);
        ip.push(64); // hop limit
        ip.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);
        ip.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]);
        ip.extend_from_slice(&sport.to_be_bytes());
        ip.extend_from_slice(&dport.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0]);
        ip.extend_from_slice(&[0, 0, 0, 0]);
        ip.push(5 << 4);
        ip.push(0);
        ip.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // window+checksum+urg
        ip.extend_from_slice(payload);
        eth(0x86dd, &ip)
    }

    #[test]
    fn decode_ipv4_tcp() {
        let frame = ipv4_tcp(12345, 443, TCP_SYN, 0, b"hello");
        let pkt = decode(&frame).unwrap();
        assert_eq!(pkt.src, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(pkt.dst, IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
        assert_eq!(pkt.proto, IPPROTO_TCP);
        assert_eq!(pkt.sport, 12345);
        assert_eq!(pkt.dport, 443);
        assert_eq!(pkt.tcp_flags, TCP_SYN);
        assert_eq!(pkt.payload, b"hello");
        assert_eq!(pkt.frame_len, frame.len());
    }

    #[test]
    fn decode_ipv4_udp() {
        let frame = ipv4_udp(53, 5353, &[1, 2, 3]);
        let pkt = decode(&frame).unwrap();
        assert_eq!(pkt.proto, IPPROTO_UDP);
        assert_eq!(pkt.sport, 53);
        assert_eq!(pkt.dport, 5353);
        assert_eq!(pkt.payload, &[1, 2, 3]);
    }

    #[test]
    fn decode_ipv6_tcp() {
        let frame = ipv6_tcp(40000, 80, b"GET /");
        let pkt = decode(&frame).unwrap();
        assert_eq!(pkt.proto, IPPROTO_TCP);
        assert_eq!(pkt.sport, 40000);
        assert_eq!(pkt.dport, 80);
        assert_eq!(pkt.payload, b"GET /");
        assert_eq!(
            pkt.src,
            IpAddr::V6("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn decode_vlan_and_qinq() {
        // 单层 VLAN：0x8100 + 4 字节 tag
        let inner = {
            let mut frame = ipv4_tcp(1000, 443, 0, 0, b"x");
            frame.drain(0..14); // 剥掉已有以太头，只留 IP
            frame
        };
        let mut vlan = vec![0u8; 12];
        vlan.extend_from_slice(&0x8100u16.to_be_bytes()); // TPID
        vlan.extend_from_slice(&[0, 1]); // TCI
        vlan.extend_from_slice(&0x0800u16.to_be_bytes()); // inner ethertype
        vlan.extend_from_slice(&inner);
        let pkt = decode(&vlan).expect("单层 VLAN 应能解出");
        assert_eq!(pkt.sport, 1000);

        // QinQ：0x88a8 外层 + 0x8100 内层
        let mut qinq = vec![0u8; 12];
        qinq.extend_from_slice(&0x88a8u16.to_be_bytes());
        qinq.extend_from_slice(&[0, 1]);
        qinq.extend_from_slice(&0x8100u16.to_be_bytes());
        qinq.extend_from_slice(&[0, 2]);
        qinq.extend_from_slice(&0x0800u16.to_be_bytes());
        qinq.extend_from_slice(&inner);
        let pkt = decode(&qinq).expect("QinQ 应能解出");
        assert_eq!(pkt.sport, 1000);
    }

    #[test]
    fn decode_fragment_discarded() {
        // 分片偏移非 0：非首片丢
        let frame = ipv4_tcp(1000, 443, 0, 0x0040, b"x"); // offset 8 字
        assert!(decode(&frame).is_none());
    }

    #[test]
    fn decode_non_ip_discarded() {
        // ARP (0x0806)
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        assert!(decode(&frame).is_none());
    }

    #[test]
    fn decode_truncated_gives_none() {
        assert!(decode(b"").is_none());
        assert!(decode(&[0u8; 13]).is_none()); // 不足 14 字节以太头
        assert!(decode(&[0u8; 20]).is_none()); // 以太头够但 IP/TCP 不够
    }
}
