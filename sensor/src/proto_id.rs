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
