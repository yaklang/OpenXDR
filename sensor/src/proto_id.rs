//! 协议识别与元数据提取：DNS 查询域名、TLS SNI。
//! 每条流只探测一次，命中或明确不是就置 probed，避免对大流反复解析。

use crate::decode::Packet;
use crate::flow::Flow;

const DNS_PORT: u16 = 53;
const MAX_NAME_LEN: usize = 253;

pub fn probe(flow: &mut Flow, pkt: &Packet) {
    if flow.probed {
        return;
    }
    if pkt.sport == DNS_PORT || pkt.dport == DNS_PORT {
        flow.meta.dns_query = parse_dns_question(pkt.payload);
        flow.probed = true;
        return;
    }
    if let Some(sni) = parse_tls_sni(pkt.payload) {
        flow.meta.tls_sni = Some(sni);
        flow.probed = true;
    }
}

/// DNS 报文首个 question 的域名。只看查询，响应报文的 question 也一样能取。
fn parse_dns_question(payload: &[u8]) -> Option<String> {
    let qdcount = u16::from_be_bytes([*payload.get(4)?, *payload.get(5)?]);
    if qdcount == 0 {
        return None;
    }

    let mut name = String::new();
    let mut pos = 12; // 跳过固定头
    loop {
        let len = *payload.get(pos)? as usize;
        match len {
            0 => break,
            // 指针压缩：question 段不应出现，出现即畸形
            l if l & 0xc0 != 0 => return None,
            _ => {
                if name.len() + len > MAX_NAME_LEN {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                let label = payload.get(pos + 1..pos + 1 + len)?;
                name.push_str(&String::from_utf8_lossy(label));
                pos += 1 + len;
            }
        }
    }
    (!name.is_empty()).then_some(name)
}

/// TLS ClientHello 的 server_name 扩展。
fn parse_tls_sni(payload: &[u8]) -> Option<String> {
    // TLS record: type(1) version(2) length(2)；0x16 = handshake
    if *payload.first()? != 0x16 {
        return None;
    }
    let handshake = payload.get(5..)?;
    // handshake: type(1) length(3) version(2) random(32)；0x01 = ClientHello
    if *handshake.first()? != 0x01 {
        return None;
    }

    let mut pos = 38;
    // session_id
    pos += 1 + *handshake.get(pos)? as usize;
    // cipher_suites
    let cipher_len = u16::from_be_bytes([*handshake.get(pos)?, *handshake.get(pos + 1)?]) as usize;
    pos += 2 + cipher_len;
    // compression_methods
    pos += 1 + *handshake.get(pos)? as usize;
    // extensions 总长
    let ext_total = u16::from_be_bytes([*handshake.get(pos)?, *handshake.get(pos + 1)?]) as usize;
    pos += 2;

    let end = (pos + ext_total).min(handshake.len());
    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([*handshake.get(pos)?, *handshake.get(pos + 1)?]);
        let ext_len = u16::from_be_bytes([*handshake.get(pos + 2)?, *handshake.get(pos + 3)?]) as usize;
        pos += 4;
        if ext_type == 0x0000 {
            // server_name_list: list_len(2) type(1) name_len(2) name
            let name_len =
                u16::from_be_bytes([*handshake.get(pos + 3)?, *handshake.get(pos + 4)?]) as usize;
            if name_len > MAX_NAME_LEN {
                return None;
            }
            let name = handshake.get(pos + 5..pos + 5 + name_len)?;
            return Some(String::from_utf8_lossy(name).into_owned());
        }
        pos += ext_len;
    }
    None
}
