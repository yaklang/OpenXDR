//! 协议识别与元数据提取：DNS 查询、TLS SNI/JA3、HTTP 请求头。
//! 每条流只探测一次，命中或明确不是就置 probed，避免对大流反复解析。

use md5::{Digest, Md5};

use crate::decode::Packet;
use crate::flow::Flow;

const DNS_PORT: u16 = 53;
const MAX_NAME_LEN: usize = 253;
/// HTTP 头部字段长度上限，防止畸形请求撑爆内存
const MAX_HEADER_LEN: usize = 512;

pub fn probe(flow: &mut Flow, pkt: &Packet) {
    if flow.probed || pkt.payload.is_empty() {
        return;
    }
    if pkt.sport == DNS_PORT || pkt.dport == DNS_PORT {
        flow.meta.dns_query = parse_dns_question(pkt.payload);
        flow.probed = true;
        return;
    }
    if let Some(hello) = parse_client_hello(pkt.payload) {
        flow.meta.tls_sni = hello.sni;
        flow.meta.ja3 = Some(hello.ja3);
        flow.probed = true;
        return;
    }
    if let Some(http) = parse_http_request(pkt.payload) {
        flow.meta.http_host = http.host;
        flow.meta.http_uri = Some(http.uri);
        flow.meta.http_user_agent = http.user_agent;
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

pub struct ClientHello {
    pub sni: Option<String>,
    pub ja3: String,
}

/// TLS ClientHello：一次遍历同时取出 SNI 和 JA3 指纹。
/// JA3 = md5(版本,密码套件,扩展,椭圆曲线,曲线点格式)，GREASE 值按规范剔除。
fn parse_client_hello(payload: &[u8]) -> Option<ClientHello> {
    // TLS record: type(1) version(2) length(2)；0x16 = handshake
    if *payload.first()? != 0x16 {
        return None;
    }
    let hs = payload.get(5..)?;
    // handshake: type(1) length(3) version(2) random(32)；0x01 = ClientHello
    if *hs.first()? != 0x01 {
        return None;
    }
    let version = u16::from_be_bytes([*hs.get(4)?, *hs.get(5)?]);

    let mut pos = 38;
    pos += 1 + *hs.get(pos)? as usize; // session_id

    let cipher_len = be16(hs, pos)? as usize;
    pos += 2;
    let ciphers = u16_list(hs.get(pos..pos + cipher_len)?);
    pos += cipher_len;

    pos += 1 + *hs.get(pos)? as usize; // compression_methods

    let ext_total = be16(hs, pos)? as usize;
    pos += 2;
    let end = (pos + ext_total).min(hs.len());

    let mut sni = None;
    let mut extensions = Vec::new();
    let mut curves = Vec::new();
    let mut point_formats = Vec::new();

    while pos + 4 <= end {
        let ext_type = be16(hs, pos)?;
        let ext_len = be16(hs, pos + 2)? as usize;
        pos += 4;
        let body = hs.get(pos..(pos + ext_len).min(hs.len()))?;

        if !is_grease(ext_type) {
            extensions.push(ext_type);
        }
        match ext_type {
            0x0000 => sni = parse_sni(body),
            0x000a => {
                // supported_groups: list_len(2) + u16 列表
                if body.len() >= 2 {
                    curves = u16_list(&body[2..]);
                }
            }
            0x000b => {
                // ec_point_formats: len(1) + u8 列表
                if body.len() >= 1 {
                    point_formats = body[1..].to_vec();
                }
            }
            _ => {}
        }
        pos += ext_len;
    }

    let ja3_str = format!(
        "{},{},{},{},{}",
        version,
        join_u16(&ciphers),
        join_u16(&extensions),
        join_u16(&curves),
        point_formats
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-"),
    );
    let digest = Md5::digest(ja3_str.as_bytes());
    let ja3 = digest.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });
    Some(ClientHello { sni, ja3 })
}

fn parse_sni(body: &[u8]) -> Option<String> {
    // server_name_list: list_len(2) type(1) name_len(2) name
    let name_len = be16(body, 3)? as usize;
    if name_len > MAX_NAME_LEN {
        return None;
    }
    let name = body.get(5..5 + name_len)?;
    Some(String::from_utf8_lossy(name).into_owned())
}

pub struct HttpRequest {
    pub uri: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
}

/// HTTP/1.x 明文请求首部。只看第一个包，跨包的请求头不做重组。
fn parse_http_request(payload: &[u8]) -> Option<HttpRequest> {
    let head_end = payload.len().min(4096);
    let text = std::str::from_utf8(payload.get(..head_end)?).ok()?;
    let mut lines = text.split("\r\n");

    // 请求行: METHOD SP URI SP HTTP/1.x
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?;
    let uri = parts.next()?;
    let proto = parts.next()?;
    if !proto.starts_with("HTTP/1.") || !is_http_method(method) {
        return None;
    }

    let mut host = None;
    let mut user_agent = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        let value = value.trim();
        if value.len() > MAX_HEADER_LEN {
            continue;
        }
        if name.eq_ignore_ascii_case("host") {
            host = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("user-agent") {
            user_agent = Some(value.to_string());
        }
    }

    Some(HttpRequest {
        uri: uri.chars().take(MAX_HEADER_LEN).collect(),
        host,
        user_agent,
    })
}

fn is_http_method(m: &str) -> bool {
    matches!(
        m,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "TRACE" | "CONNECT"
    )
}

/// GREASE 值（RFC 8701）在 JA3 里必须剔除，否则同一客户端每次握手指纹都不同。
fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

fn be16(buf: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]))
}

fn u16_list(buf: &[u8]) -> Vec<u16> {
    buf.chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|v| !is_grease(*v))
        .collect()
}

fn join_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{FlowKey, Metadata};
    use std::net::{IpAddr, Ipv4Addr};

    fn default_flow() -> Flow {
        Flow {
            key: FlowKey {
                a_ip: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
                b_ip: IpAddr::V4(Ipv4Addr::new(2, 0, 0, 2)),
                a_port: 0,
                b_port: 0,
                proto: 6,
            },
            start_ns: 0,
            last_ns: 0,
            a_to_b_packets: 0,
            a_to_b_bytes: 0,
            b_to_a_packets: 0,
            b_to_a_bytes: 0,
            tcp_flags: 0,
            meta: Metadata::default(),
            probed: false,
            client_is_a: true,
        }
    }

    fn pkt<'a>(sport: u16, dport: u16, payload: &'a [u8]) -> Packet<'a> {
        Packet {
            src: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(2, 0, 0, 2)),
            proto: 6,
            sport,
            dport,
            tcp_flags: 0,
            payload,
            frame_len: 100,
        }
    }

    fn dns_query(name: &str) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0); // root
        p.extend_from_slice(&[0, 1, 0, 1]); // type A, class IN
        p
    }

    #[test]
    fn dns_question_parsing() {
        let payload = dns_query("www.example.com");
        assert_eq!(parse_dns_question(&payload).as_deref(), Some("www.example.com"));
    }
    #[test]
    fn dns_single_label() {
        assert_eq!(parse_dns_question(&dns_query("localhost")).as_deref(), Some("localhost"));
    }

    #[test]
    fn dns_zero_qdcount_none() {
        let mut p = dns_query("example.com");
        p[5] = 0; // qdcount 高字节已是 0，改低字节
        assert_eq!(parse_dns_question(&p), None);
    }

    #[test]
    fn dns_compression_pointer_none() {
        // 构造 label 长度字节为 0xc0（指针标记）→ 应视为畸形
        let mut p = Vec::new();
        p.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        p.push(0xc0);
        p.push(0x0c);
        p.push(0);
        assert_eq!(parse_dns_question(&p), None);
    }

    #[test]
    fn probe_sets_dns_and_probed() {
        let mut flow = default_flow();
        let payload = dns_query("pwn.example");
        let mut pkt = pkt(54321, DNS_PORT, &payload);
        probe(&mut flow, &pkt);
        assert_eq!(flow.meta.dns_query.as_deref(), Some("pwn.example"));
        assert!(flow.probed, "命中后应置 probed 防止重复解析");
        assert!(flow.meta.tls_sni.is_none());

        // probed 后不再重复解析
        pkt.dport = 9999; // 即使换端口也不再探测
        probe(&mut flow, &pkt);
        assert_eq!(flow.meta.dns_query.as_deref(), Some("pwn.example"));
    }

    /// 构造带 SNI 的 ClientHello（含一个 GREASE 密码套件和一个 GREASE 扩展）。
    /// 返回 (payload, 期望 SNI)。
    fn client_hello(sni: &str, grease: bool) -> Vec<u8> {
        let mut hs = Vec::new();
        hs.push(0x01); // handshake type ClientHello
        hs.extend_from_slice(&[0, 0, 0]); // length 占位
        hs.extend_from_slice(&[0x03, 0x03]); // version TLS1.2
        hs.extend_from_slice(&[0xAA; 32]); // random
        hs.push(0); // session_id len == 0

        let mut ciphers = vec![0x13, 0x01];
        if grease {
            ciphers.push(0x0a); ciphers.push(0x0a);
        }
        hs.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ciphers);

        hs.push(0); // compression len

        // extensions: SNI + 可选 GREASE
        let mut exts = Vec::new();
        // SNI：server_name_list = [list_len(2)][type(1)][name_len(2)][name]
        let name = sni.as_bytes();
        let mut ext_body = Vec::new();
        ext_body.extend_from_slice(&((3 + name.len()) as u16).to_be_bytes()); // list_len
        ext_body.push(0x00); // name_type = host_name
        ext_body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext_body.extend_from_slice(name);
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_body);
        // GREASE 扩展
        if grease {
            exts.extend_from_slice(&0x0a0au16.to_be_bytes());
            exts.extend_from_slice(&0u16.to_be_bytes());
        }

        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);

        // record header
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn tls_sni_and_ja3() {
        let payload = client_hello("evil.example.com", false);
        let hello = parse_client_hello(&payload).expect("应解析出 ClientHello");
        assert_eq!(hello.sni.as_deref(), Some("evil.example.com"));
        // MD5 16 字节 → 32 位 hex
        assert_eq!(hello.ja3.len(), 32);
        assert!(hello.ja3.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn tls_grease_removed_stable_ja3() {
        let a = parse_client_hello(&client_hello("x.example", false)).unwrap();
        let b = parse_client_hello(&client_hello("x.example", true)).unwrap();
        // GREASE 被剔除 → 指纹一致
        assert_eq!(a.ja3, b.ja3, "GREASE 值应被剔除，JA3 不受其影响");
    }

    #[test]
    fn tls_parse_rejects_non_clienthello() {
        assert!(parse_client_hello(b"").is_none());
        assert!(parse_client_hello(&[0x17, 0x03, 0x01, 0x00]).is_none()); // 0x17 应用数据
    }

    #[test]
    fn probe_detects_tls() {
        let payload = client_hello("c2.example", false);
        let mut flow = default_flow();
        probe(&mut flow, &pkt(52000, 443, &payload));
        assert_eq!(flow.meta.tls_sni.as_deref(), Some("c2.example"));
        assert!(!flow.meta.ja3.as_deref().unwrap_or("").is_empty());
        assert!(flow.probed);
    }

    #[test]
    fn http_request_parsing() {
        let req = b"GET /admin/login HTTP/1.1\r\nHost: target.example\r\nUser-Agent: curl/8.0\r\n\r\n";
        let h = parse_http_request(req).expect("应解析出 HTTP 请求");
        assert_eq!(h.uri, "/admin/login");
        assert_eq!(h.host.as_deref(), Some("target.example"));
        assert_eq!(h.user_agent.as_deref(), Some("curl/8.0"));
    }

    #[test]
    fn http_rejects_non_http() {
        assert!(parse_http_request(b"\x16GARBAGE").is_none());
        assert!(parse_http_request(b"GET / HTTP/2.0\r\n").is_none()); // HTTP/2 不在此范围
        assert!(parse_http_request(b"BOGUS / HTTP/1.1\r\n").is_none()); // 非法方法
    }

    #[test]
    fn http_case_insensitive_headers() {
        let req = b"POST /api HTTP/1.1\r\nhOsT: a.example\r\n";
        let h = parse_http_request(req).unwrap();
        assert_eq!(h.host.as_deref(), Some("a.example"));
    }

    #[test]
    fn grease_constant() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(!is_grease(0x0a0b));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0a00));
    }
}
