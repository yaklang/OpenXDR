//! 协议识别与元数据提取：DNS 查询/应答、TLS SNI/JA3/JA3S、HTTP 请求头。
//! 每条流每个方向探到命中、或前几个包都没命中就置 probed，避免对大流反复解析。

use std::net::{Ipv4Addr, Ipv6Addr};

use md5::{Digest, Md5};

use crate::decode::{IPPROTO_TCP, IPPROTO_UDP, Packet};
use crate::flow::{Flow, Metadata, TlsBufBudget, TlsClient};
use crate::x509;

const DNS_PORT: u16 = 53;
const MAX_NAME_LEN: usize = 253;
/// 压缩指针跳转上限：防恶意循环指针把解析拖进死循环
const MAX_PTR_JUMPS: usize = 16;
/// DNS 应答 IP 收集上限，够做情报碰撞即可，不囤全量
const MAX_DNS_ANSWERS: usize = 4;
/// HTTP 头部字段长度上限，防止畸形请求撑爆内存
const MAX_HEADER_LEN: usize = 512;
/// TLS 服务端 handshake 重组缓冲上限：证书链再大也不会超过这个量级，
/// 超限视为异常流，直接放弃等待而不是无限攒内存
const MAX_TLS_HS_BUF: usize = 16 * 1024;
/// TLS record 长度上限（明文 16KB，加密后最多再多 2KB），超过即不是 TLS record
const MAX_TLS_RECORD: usize = 16 * 1024 + 2048;
/// 每个方向最多看前这么多个包找 ClientHello / ServerHello：STARTTLS（SMTP/IMAP/LDAP/PG）、RDP、
/// CONNECT 代理都先走几轮明文才进 TLS，只看首个载荷包会把它们全漏掉；再往后就是长流的数据，不再扫
const MAX_PROBE_PACKETS: u64 = 24;
/// 应用数据 record 至少要这么长才算带了载荷：TLS 1.3 加密的 alert（close_notify）是
/// 2 字节明文 + 1 字节类型 + 16 字节认证标签 = 19，装不下任何请求
const MIN_DATA_RECORD: usize = 20;

pub fn probe(flow: &mut Flow, pkt: &Packet, from_client: bool, tls_budget: &mut TlsBufBudget) {
    if pkt.payload.is_empty() {
        return;
    }
    // DNS 查询与应答各探一次：UDP 53 直接解析，TCP 53 跳过 2 字节大端长度前缀（绝不错位解析）
    if pkt.sport == DNS_PORT || pkt.dport == DNS_PORT {
        match pkt.proto {
            IPPROTO_UDP => {
                probe_dns_payload(flow, pkt.payload);
                return;
            }
            IPPROTO_TCP => {
                if let Some(dns) = tcp_dns_payload(pkt.payload)
                    && probe_dns_payload(flow, dns)
                {
                    return;
                }
                // TCP 53 非 DNS 载荷（如复用 53 端口的 TLS/HTTP 隧道）继续往下探测
            }
            _ => {}
        }
    }
    if from_client {
        if !flow.probed {
            if let Some(hello) = parse_client_hello(pkt.payload) {
                flow.meta.tls_sni = hello.sni;
                flow.meta.ja3 = Some(hello.ja3);
                if flow.meta.tls_alpn.is_none() {
                    flow.meta.tls_alpn = hello.alpn;
                }
                flow.probed = true;
            } else if let Some(http) = parse_http_request(pkt.payload) {
                flow.meta.http_host = http.host;
                flow.meta.http_uri = Some(http.uri);
                flow.meta.http_user_agent = http.user_agent;
                flow.probed = true;
            } else if direction_packets(flow, true) >= MAX_PROBE_PACKETS {
                // 前几个包都没命中就不是要找的协议，避免 SSH/DB/gRPC 长流每包重复扫描
                flow.probed = true;
            }
        }
        return;
    }
    // 仅服务端方向进入 TLS handshake 重组，杜绝客户端包污染服务端 tls_hs_buf
    if !flow.probed_server {
        probe_tls_server(flow, pkt.payload, tls_budget);
    }
}

/// 流在客户端或服务端方向上已经过了多少个包（含本包）
fn direction_packets(flow: &Flow, client: bool) -> u64 {
    if client == flow.client_is_a {
        flow.a_to_b_packets
    } else {
        flow.b_to_a_packets
    }
}

/// TCP DNS 报文带 2 字节大端长度前缀（RFC 1035 4.2.2），长度不足 12 或未收齐不解析。
fn tcp_dns_payload(payload: &[u8]) -> Option<&[u8]> {
    let len = be16(payload, 0)? as usize;
    if len < 12 {
        return None;
    }
    payload.get(2..2 + len)
}

/// 解析 DNS 报文（按 QR 位区分查询/应答），返回 true 表示解析到了合法 DNS 字段。
fn probe_dns_payload(flow: &mut Flow, payload: &[u8]) -> bool {
    let is_response = payload.get(2).is_some_and(|f| f & 0x80 != 0);
    if is_response {
        if !flow.probed_server {
            if let Some(resp) = parse_dns_response(payload) {
                if flow.meta.dns_query.is_none() {
                    flow.meta.dns_query = resp.query;
                }
                flow.meta.dns_rcode = Some(resp.rcode);
                flow.meta.dns_answers = resp.answers;
                flow.probed_server = true;
                return true;
            }
            flow.probed_server = true;
        }
        false
    } else if !flow.probed {
        flow.meta.dns_query = parse_dns_question(payload);
        flow.probed = true;
        flow.meta.dns_query.is_some()
    } else {
        false
    }
}

/// TLS 服务端方向探测：把 handshake record 攒进 tls_hs_buf 做有界重组，
/// 增量解析 ServerHello（JA3S、TLS1.3 判定）与 Certificate（证书元数据）。
/// 完成条件：拿到 JA3S 且证书已见（或判定 TLS1.3 等不到证书）；
/// 或看到应用数据 record（0x17）；或前 MAX_PROBE_PACKETS 个包都不是握手；或单流/全局缓冲超限。完成后置 probed_server。
fn probe_tls_server(flow: &mut Flow, payload: &[u8], budget: &mut TlsBufBudget) {
    if flow.tls_hs_buf.is_empty() {
        // 缓冲为空时，0x17 应用数据说明握手窗口已过（TLS1.3、会话复用等），不等了
        if payload.first() == Some(&0x17) {
            flow.probed_server = true;
            return;
        }
        // 只有以 handshake record 开头、且首个 handshake 消息是
        // ServerHello(2)/Certificate(11) 的 payload 才启动重组；
        // 非 TLS 服务端首包（如 HTTP 响应、SSH banner、DB 协议）或已过证书阶段直接收尾
        let starts_hs =
            payload.first() == Some(&0x16) && matches!(payload.get(5), Some(&2) | Some(&11));
        if !starts_hs {
            // 明文阶段（STARTTLS 的 220、代理的 200 Connection established）之后才是 ServerHello
            if direction_packets(flow, false) >= MAX_PROBE_PACKETS {
                flow.probed_server = true;
            }
            return;
        }

        // 先就地扫描：单包完整 TLS 1.3 或 ServerHello+Certificate 零堆分配，且不受重组缓冲预算打满影响
        let (consumed, done) = scan_server_records(payload, &mut flow.meta);
        if done {
            flow.probed_server = true;
            return;
        }
        let tail = &payload[consumed..];
        if tail.is_empty() {
            return;
        }
        if tail.len() > MAX_TLS_HS_BUF || !budget.can_add(tail.len()) {
            flow.probed_server = true;
            return;
        }
        flow.tls_hs_buf = tail.to_vec();
        budget.add(tail.len());
        return;
    }

    // 续传分段：先检查单流上限与 worker 级总预算再追加，超限时彻底释放堆容量
    let new_total = flow.tls_hs_buf.len().saturating_add(payload.len());
    if new_total > MAX_TLS_HS_BUF || !budget.can_add(payload.len()) {
        budget.release(&mut flow.tls_hs_buf);
        flow.probed_server = true;
        return;
    }

    // 拿出缓冲再扫描，避免与 meta 的可变借用冲突；扫完只留未消费的不完整尾巴
    let old_len = flow.tls_hs_buf.len();
    let mut buf = std::mem::take(&mut flow.tls_hs_buf);
    buf.extend_from_slice(payload);
    let (consumed, done) = scan_server_records(&buf, &mut flow.meta);
    if done {
        budget.sub(old_len);
        flow.probed_server = true; // buf 随作用域结束释放，tls_hs_buf 已是空 Vec::new()
    } else {
        let tail = &buf[consumed..];
        if tail.is_empty() {
            budget.sub(old_len);
        } else {
            flow.tls_hs_buf = tail.to_vec();
            budget.update(old_len, tail.len());
        }
    }
}

/// 在重组缓冲上增量扫描完整 record。返回（已消费前缀长度, 是否完成探测）。
/// record 不完整就停，等下一个包再续。
fn scan_server_records(buf: &[u8], meta: &mut Metadata) -> (usize, bool) {
    let mut pos = 0;
    loop {
        let rec = &buf[pos..];
        if rec.len() < 5 {
            break;
        }
        let rlen = be16(rec, 3).map_or(0, |l| l as usize);
        if rec.len() < 5 + rlen {
            break; // record 没攒齐，等下一段
        }
        let rtype = rec[0];
        let body = &rec[5..5 + rlen];
        pos += 5 + rlen;
        match rtype {
            // handshake record：扫其中完整的 handshake 消息
            0x16 if scan_handshakes(body, meta) => return (pos, true),
            // 应用数据出现 → 握手窗口已过
            0x17 => return (pos, true),
            // CCS/alert 等不关注，跳过
            _ => {}
        }
    }
    (pos, false)
}

/// 扫一个 handshake record 里完整的 handshake 消息（跨 record 的残缺尾巴丢弃）。
/// 返回 true 表示探测完成。
fn scan_handshakes(body: &[u8], meta: &mut Metadata) -> bool {
    let mut pos = 0;
    while pos + 4 <= body.len() {
        let htype = body[pos];
        let hlen = be24(body, pos + 1).map_or(0, |l| l as usize);
        let Some(hs) = body.get(pos..pos + 4 + hlen) else {
            break;
        };
        match htype {
            // ServerHello：JA3S 只填一次；supported_versions 选 0x0304 → TLS1.3，
            // 证书加密传输等不到，JA3S 在手即完成；证书先见过的也同样完成
            0x02 if meta.ja3s.is_none() => {
                if let Some(sh) = parse_server_hello_hs(hs) {
                    meta.ja3s = Some(sh.ja3s);
                    meta.tls13 = sh.tls13;
                    if sh.version.is_some() {
                        meta.tls_version = sh.version;
                    }
                    if sh.alpn.is_some() {
                        meta.tls_alpn = sh.alpn;
                    }
                    if sh.tls13 || meta.cert_not_after != 0 || meta.cert_subject.is_some() {
                        return true;
                    }
                }
            }
            // Certificate：取第一张叶证书解析；见过证书且 JA3S 在手即完成
            0x0b if meta.cert_not_after == 0 && meta.cert_subject.is_none() => {
                if let Some(der) = first_certificate(&hs[4..])
                    && let Some(info) = x509::parse_certificate(der)
                {
                    meta.cert_subject = info.subject_cn;
                    meta.cert_issuer = info.issuer_cn;
                    meta.cert_self_signed = info.self_signed;
                    meta.cert_not_before = info.not_before;
                    meta.cert_not_after = info.not_after;
                }
                if meta.ja3s.is_some() {
                    return true;
                }
            }
            _ => {}
        }
        pos += 4 + hlen;
    }
    false
}

/// 客户端方向跟 TLS record，判断握手之后有没有发请求（见 `TlsClient`）。
/// 第一段客户端载荷必须是 ClientHello 才开始跟；已经数到两条应用数据就不必再看。
pub fn track_tls_client(flow: &mut Flow, pkt: &Packet, from_client: bool) {
    let t = &mut flow.tls_client;
    if !from_client
        || pkt.proto != IPPROTO_TCP
        || pkt.payload.is_empty()
        || t.lost
        || t.data_records >= 2
    {
        return;
    }
    if !t.tracking {
        // record 类型 22（handshake）且第一条握手消息是 ClientHello(1)
        if pkt.payload.first() != Some(&0x16) || pkt.payload.get(5) != Some(&1) {
            t.lost = true;
            return;
        }
        t.tracking = true;
    }
    advance_records(t, pkt.payload);
}

/// 逐 record 前进：先过完上一段没走完的 record，再读新的 record 头。
/// 头对不上或跨了段（少见）就判跟丢——跟丢只会让结论变成「不知道」，不会编出「只握手」。
fn advance_records(t: &mut TlsClient, mut p: &[u8]) {
    while !p.is_empty() {
        if t.pending > 0 {
            let n = t.pending.min(p.len());
            t.pending -= n;
            p = &p[n..];
            continue;
        }
        let Some(&[rtype, major, _, hi, lo]) = p.get(..5) else {
            t.lost = true;
            return;
        };
        let len = u16::from_be_bytes([hi, lo]) as usize;
        if !(20..=24).contains(&rtype) || major != 3 || len > MAX_TLS_RECORD {
            t.lost = true;
            return;
        }
        if rtype == 23 && len >= MIN_DATA_RECORD {
            t.data_records = t.data_records.saturating_add(1);
        }
        t.pending = len;
        p = &p[5..];
    }
}

/// Certificate 消息体：certificate_list = 3字节总长 + 重复(3字节证书长度 + DER)，
/// 只取第一张（叶证书）。
fn first_certificate(body: &[u8]) -> Option<&[u8]> {
    let _list_len = be24(body, 0)?;
    let cert_len = be24(body, 3)? as usize;
    body.get(6..6 + cert_len)
}

fn be24(buf: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        0,
        *buf.get(pos)?,
        *buf.get(pos + 1)?,
        *buf.get(pos + 2)?,
    ]))
}

/// 解析域名（RFC 1035 压缩指针）。返回域名与线性流上下一个位置
/// （跳过名字本体；跳过第一个指针的两字节）。
/// 跳转次数与总长度双上限，越界即畸形。
fn read_name(payload: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut next = None; // 第一次跳指针后线性流的下一个位置
    let mut jumps = 0;
    loop {
        let len = *payload.get(pos)? as usize;
        match len & 0xc0 {
            0xc0 => {
                // 压缩指针：14 位偏移
                let lo = *payload.get(pos + 1)? as usize;
                if next.is_none() {
                    next = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_PTR_JUMPS {
                    return None;
                }
                pos = ((len & 0x3f) << 8) | lo;
            }
            0 => {
                if len == 0 {
                    return Some((name, next.unwrap_or(pos + 1)));
                }
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
            // 0x40/0x80 是保留标记，非法
            _ => return None,
        }
    }
}

/// DNS 报文首个 question 的域名。只看查询，响应报文的 question 也一样能取。
fn parse_dns_question(payload: &[u8]) -> Option<String> {
    let qdcount = be16(payload, 4)?;
    if qdcount == 0 {
        return None;
    }
    let (name, _) = read_name(payload, 12)?;
    (!name.is_empty()).then_some(name)
}

pub struct DnsResponse {
    pub query: Option<String>,
    pub rcode: u32,
    pub answers: Vec<String>,
}

/// DNS 应答：rcode + answer 段的 A/AAAA 地址（至多 4 个），question 域名顺带取出。
/// 畸形/截断静默返回 None，绝不 panic。
fn parse_dns_response(payload: &[u8]) -> Option<DnsResponse> {
    let rcode = (*payload.get(3)? & 0x0f) as u32;
    let qdcount = be16(payload, 4)? as usize;
    let ancount = be16(payload, 6)? as usize;

    // question 段：逐个跳过，首个名字留作域名
    let mut pos = 12;
    let mut query = None;
    for i in 0..qdcount {
        let (name, next) = read_name(payload, pos)?;
        if i == 0 && !name.is_empty() {
            query = Some(name);
        }
        pos = next.checked_add(4)?; // qtype + qclass
        if pos > payload.len() {
            return None;
        }
    }

    // answer 段：只收 A/AAAA 的地址，其余类型跳过
    let mut answers = Vec::new();
    for _ in 0..ancount {
        let (_, after_name) = read_name(payload, pos)?;
        let rtype = be16(payload, after_name)?;
        // type(2) class(2) ttl(4) 之后是 rdlength(2) + rdata
        let rdlen = be16(payload, after_name + 8)? as usize;
        let rdata = payload.get(after_name + 10..after_name + 10 + rdlen)?;
        if answers.len() < MAX_DNS_ANSWERS {
            match (rtype, rdlen) {
                (1, 4) => {
                    answers.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string())
                }
                (28, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(rdata);
                    answers.push(Ipv6Addr::from(octets).to_string());
                }
                _ => {}
            }
        }
        pos = after_name + 10 + rdlen;
    }

    Some(DnsResponse {
        query,
        rcode,
        answers,
    })
}

pub struct ClientHello {
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub ja3: String,
}

/// TLS ClientHello：一次遍历同时取出 SNI、ALPN 首选协议和 JA3 指纹。
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
    let mut alpn = None;
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
            // supported_groups: list_len(2) + u16 列表
            0x000a if body.len() >= 2 => curves = u16_list(&body[2..]),
            // ec_point_formats: len(1) + u8 列表
            0x000b if !body.is_empty() => point_formats = body[1..].to_vec(),
            0x0010 => alpn = parse_alpn(body),
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
    Some(ClientHello {
        sni,
        alpn,
        ja3: md5_hex(&ja3_str),
    })
}

/// TLS ServerHello（单 record payload 形式）：提取 JA3S 服务端指纹。
/// 重组路径走 parse_server_hello_hs；这个包装只留给出参更简单的单测。
/// JA3S = md5(版本,密码套件,扩展)，GREASE 扩展按规范剔除。
#[cfg(test)]
fn parse_server_hello(payload: &[u8]) -> Option<String> {
    // TLS record: type(1) version(2) length(2)；0x16 = handshake
    if *payload.first()? != 0x16 {
        return None;
    }
    parse_server_hello_hs(payload.get(5..)?).map(|sh| sh.ja3s)
}

struct ServerHelloInfo {
    ja3s: String,
    /// supported_versions(0x002b) 选了 0x0304 → TLS1.3，证书加密传输
    tls13: bool,
    version: Option<String>,
    alpn: Option<String>,
}

/// 作用于 handshake 消息切片（type 字节 + 3字节长度开头）的 ServerHello 解析，
/// 重组缓冲里的 ServerHello 与单 record 场景共用。
fn parse_server_hello_hs(hs: &[u8]) -> Option<ServerHelloInfo> {
    // handshake: type(1) length(3) version(2) random(32)；0x02 = ServerHello
    if *hs.first()? != 0x02 {
        return None;
    }
    let version = be16(hs, 4)?;

    let mut pos = 38;
    pos += 1 + *hs.get(pos)? as usize; // session_id

    let cipher = be16(hs, pos)?;
    pos += 2;
    pos += 1; // compression_method

    // 扩展块可选：老服务端的 ServerHello 可能没有
    let mut extensions = Vec::new();
    let mut selected_version = version;
    let mut alpn = None;
    if hs.get(pos).is_some() {
        let ext_total = be16(hs, pos)? as usize;
        pos += 2;
        let end = (pos + ext_total).min(hs.len());
        while pos + 4 <= end {
            let ext_type = be16(hs, pos)?;
            let ext_len = be16(hs, pos + 2)? as usize;
            pos += 4;
            let body = hs.get(pos..(pos + ext_len).min(hs.len()))?;
            if !is_grease(ext_type) {
                extensions.push(ext_type);
            }
            match ext_type {
                0x0010 => alpn = parse_alpn(body),
                // ServerHello 的 supported_versions 扩展体即选中的版本号
                0x002b => {
                    if let Some(v) = be16(body, 0) {
                        selected_version = v;
                    }
                }
                _ => {}
            }
            pos += ext_len;
        }
    }
    let tls13 = selected_version == 0x0304;

    Some(ServerHelloInfo {
        ja3s: md5_hex(&format!("{},{},{}", version, cipher, join_u16(&extensions))),
        tls13,
        version: tls_version_name(selected_version).map(str::to_string),
        alpn,
    })
}

fn tls_version_name(v: u16) -> Option<&'static str> {
    match v {
        0x0304 => Some("TLS 1.3"),
        0x0303 => Some("TLS 1.2"),
        0x0302 => Some("TLS 1.1"),
        0x0301 => Some("TLS 1.0"),
        _ => None,
    }
}

/// ALPN（RFC 7301，扩展 0x0010）：ProtocolNameList = list_len(2) + 重复(name_len(1) + name)。
/// ServerHello 里只有服务端选定的唯一协议；ClientHello 里按优先级排列，取首个非空可见 ASCII 协议名。
fn parse_alpn(body: &[u8]) -> Option<String> {
    let list_len = be16(body, 0)? as usize;
    if list_len == 0 || 2 + list_len > body.len() {
        return None;
    }
    let name_len = *body.get(2)? as usize;
    if name_len == 0 || name_len > 64 || 3 + name_len > 2 + list_len {
        return None;
    }
    let name = body.get(3..3 + name_len)?;
    let s = std::str::from_utf8(name).ok()?;
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic())).then(|| s.to_string())
}

/// md5 摘要转小写十六进制，JA3/JA3S 共用。
fn md5_hex(s: &str) -> String {
    let digest = Md5::digest(s.as_bytes());
    digest.iter().fold(String::with_capacity(32), |mut out, b| {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
        out
    })
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
/// 先在字节切片里按 \r\n\r\n 切出头部区域，避免二进制 POST body 导致整体 UTF-8 失败；
/// 头部末尾被 TCP 分段截断的行容错忽略，保留已解析的 Host/URI/UA。
fn parse_http_request(payload: &[u8]) -> Option<HttpRequest> {
    let window = payload.get(..payload.len().min(4096))?;
    let header_bytes = match window.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(pos) => &window[..pos],
        None => window,
    };

    // 请求行必须完整（以 \r\n 结尾）且是合法 UTF-8：METHOD SP URI SP HTTP/1.x
    let first_eol = header_bytes.windows(2).position(|w| w == b"\r\n")?;
    let request_line = std::str::from_utf8(&header_bytes[..first_eol]).ok()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?;
    let uri = parts.next()?;
    let proto = parts.next()?;
    if !proto.starts_with("HTTP/1.") || !is_http_method(method) {
        return None;
    }

    let mut host = None;
    let mut user_agent = None;
    let mut cursor = &header_bytes[first_eol + 2..];
    while !cursor.is_empty() {
        let (line, next) = match cursor.windows(2).position(|w| w == b"\r\n") {
            Some(pos) => (&cursor[..pos], &cursor[pos + 2..]),
            None => (cursor, &[][..]),
        };
        cursor = next;
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            // 尾部被 TCP 分段截断或非标准头行：停止继续扫描，保留已解析字段
            break;
        };
        let Ok(name) = std::str::from_utf8(&line[..colon]) else {
            continue;
        };
        let Ok(value) = std::str::from_utf8(&line[colon + 1..]) else {
            continue;
        };
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
    buf.as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_be_bytes(c))
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
            probed_server: false,
            client_is_a: true,
            tls_hs_buf: Vec::new(),
            tls_client: TlsClient::default(),
        }
    }

    fn pkt<'a>(sport: u16, dport: u16, payload: &'a [u8]) -> Packet<'a> {
        Packet {
            src: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(2, 0, 0, 2)),
            proto: IPPROTO_TCP,
            sport,
            dport,
            tcp_flags: 0,
            payload,
            frame_len: 100,
        }
    }

    fn udp_pkt<'a>(sport: u16, dport: u16, payload: &'a [u8]) -> Packet<'a> {
        Packet {
            proto: IPPROTO_UDP,
            ..pkt(sport, dport, payload)
        }
    }

    // 同 FlowTable::update：先给本方向记一个包再探测
    fn probe_client(flow: &mut Flow, pkt: &Packet) {
        flow.a_to_b_packets += 1;
        probe(flow, pkt, true, &mut TlsBufBudget::default());
    }

    fn probe_server(flow: &mut Flow, pkt: &Packet) {
        flow.b_to_a_packets += 1;
        probe(flow, pkt, false, &mut TlsBufBudget::default());
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
        assert_eq!(
            parse_dns_question(&payload).as_deref(),
            Some("www.example.com")
        );
    }
    #[test]
    fn dns_single_label() {
        assert_eq!(
            parse_dns_question(&dns_query("localhost")).as_deref(),
            Some("localhost")
        );
    }

    #[test]
    fn dns_zero_qdcount_none() {
        let mut p = dns_query("example.com");
        p[5] = 0; // qdcount 高字节已是 0，改低字节
        assert_eq!(parse_dns_question(&p), None);
    }

    #[test]
    fn dns_name_follows_compression_pointer() {
        // 合法指针：偏移 12 起是 "www.a"（标签 "a" 在偏移 16），
        // 偏移 19 的名字是 "b" + 指针 0xC010 → 应解析出 "b.a"
        let mut p = Vec::new();
        p.extend_from_slice(&[0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&[3, b'w', b'w', b'w', 1, b'a', 0]); // 偏移 12 起："www.a"
        p.extend_from_slice(&[1, b'b', 0xc0, 0x10]); // "b" + 指针→偏移 16（"a"）
        p.extend_from_slice(&[0, 1, 0, 1]);
        let (name, _) = read_name(&p, 19).expect("指针应被跟随");
        assert_eq!(name, "b.a");
    }

    #[test]
    fn dns_name_rejects_pointer_loop() {
        // 恶意自指指针：0x0c 指向自己，跳转上限兜住 → 畸形
        let mut p = Vec::new();
        p.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        p.push(0xc0);
        p.push(0x0c);
        p.push(0);
        assert_eq!(parse_dns_question(&p), None, "自指循环指针应判畸形");

        // 双指针互指同样不允许
        let mut q = Vec::new();
        q.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        q.extend_from_slice(&[0xc0, 0x0e, 0xc0, 0x0c]); // 12→14→12…
        assert_eq!(parse_dns_question(&q), None, "互指循环指针应判畸形");
    }

    #[test]
    fn dns_name_rejects_out_of_bounds_pointer() {
        let mut p = dns_query("example.com");
        // 把 question 名字换成指向报文外的指针
        p.truncate(12);
        p.extend_from_slice(&[0xc0, 0xff]);
        assert_eq!(parse_dns_question(&p), None);
    }

    /// 构造 DNS 应答：rcode + question + answers（(类型, rdata) 列表）。
    /// answer 名字统一用指针 0xC00C 指向 question。
    fn dns_response(name: &str, rcode: u8, answers: &[(u16, &[u8])]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0x12, 0x34]); // id
        p.extend_from_slice(&[0x81, 0x80 | rcode]); // QR=1，标准查询应答
        p.extend_from_slice(&[0, 1]); // qdcount
        p.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ancount
        p.extend_from_slice(&[0, 0, 0, 0]); // nscount arcount
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&[0, 1, 0, 1]); // qtype A qclass IN
        for (rtype, rdata) in answers {
            p.extend_from_slice(&[0xc0, 0x0c]); // name → 指针指向 question
            p.extend_from_slice(&rtype.to_be_bytes());
            p.extend_from_slice(&[0, 1]); // class IN
            p.extend_from_slice(&[0, 0, 0, 60]); // ttl
            p.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            p.extend_from_slice(rdata);
        }
        p
    }

    #[test]
    fn dns_response_parses_rcode_and_answers() {
        let a: &[u8] = &[93, 184, 216, 34];
        let aaaa: &[u8] = &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        // CNAME 应被跳过，只留 A/AAAA
        let p = dns_response(
            "cdn.example.com",
            0,
            &[(5, b"\x03www\x00"), (1, a), (28, aaaa)],
        );
        let resp = parse_dns_response(&p).expect("应解析出应答");
        assert_eq!(resp.query.as_deref(), Some("cdn.example.com"));
        assert_eq!(resp.rcode, 0);
        assert_eq!(resp.answers, vec!["93.184.216.34", "2001:db8::1"]);
    }

    #[test]
    fn dns_response_nxdomain_no_answers() {
        let p = dns_response("nope.example", 3, &[]);
        let resp = parse_dns_response(&p).expect("NXDOMAIN 也是合法应答");
        assert_eq!(resp.rcode, 3);
        assert!(resp.answers.is_empty());
    }

    #[test]
    fn dns_response_answers_capped() {
        let ips: Vec<[u8; 4]> = (0..6u8).map(|i| [10, 0, 0, i]).collect();
        let answers: Vec<(u16, &[u8])> = ips.iter().map(|a| (1u16, a as &[u8])).collect();
        let p = dns_response("many.example", 0, &answers);
        let resp = parse_dns_response(&p).unwrap();
        assert_eq!(resp.answers.len(), MAX_DNS_ANSWERS, "应答 IP 应有上限");
        assert_eq!(resp.answers[0], "10.0.0.0");
        assert_eq!(resp.answers[3], "10.0.0.3");
    }

    #[test]
    fn dns_response_truncated_none() {
        let p = dns_response("cdn.example.com", 0, &[(1, &[1, 2, 3, 4])]);
        for cut in [13, 20, p.len() - 3] {
            assert!(
                parse_dns_response(&p[..cut]).is_none(),
                "截断到 {cut} 字节应静默返回 None"
            );
        }
    }

    #[test]
    fn dns_response_malformed_answer_name_none() {
        let mut p = dns_response("x.example", 0, &[(1, &[1, 2, 3, 4])]);
        // answer 共 16 字节（指针2 + 固定10 + rdata4），起始处的名字指针改成指到报文外
        let idx = p.len() - 16;
        assert_eq!(p[idx], 0xc0);
        p[idx + 1] = 0xfe;
        assert!(parse_dns_response(&p).is_none());
    }

    #[test]
    fn probe_dns_query_then_response() {
        let mut flow = default_flow();
        let q = dns_query("pwn.example");
        probe_client(&mut flow, &udp_pkt(54321, DNS_PORT, &q));
        assert_eq!(flow.meta.dns_query.as_deref(), Some("pwn.example"));
        assert!(flow.probed);
        assert!(!flow.probed_server, "查询不应占用服务端探测位");

        let r = dns_response("pwn.example", 0, &[(1, &[6, 6, 6, 6])]);
        probe_server(&mut flow, &udp_pkt(DNS_PORT, 54321, &r));
        assert!(flow.probed_server);
        assert_eq!(flow.meta.dns_rcode, Some(0));
        assert_eq!(flow.meta.dns_answers, vec!["6.6.6.6"]);
        // 应答里的 question 不覆盖已有域名
        assert_eq!(flow.meta.dns_query.as_deref(), Some("pwn.example"));
    }

    #[test]
    fn probe_dns_response_only_fills_query() {
        // 只抓到应答（漏了查询包）：域名也能从应答的 question 段补上
        let mut flow = default_flow();
        let r = dns_response("lone.example", 0, &[]);
        probe_server(&mut flow, &udp_pkt(DNS_PORT, 1234, &r));
        assert_eq!(flow.meta.dns_query.as_deref(), Some("lone.example"));
        assert!(flow.probed_server);
        assert!(!flow.probed);
    }

    #[test]
    fn probe_sets_dns_and_probed() {
        let mut flow = default_flow();
        let payload = dns_query("pwn.example");
        let mut p = udp_pkt(54321, DNS_PORT, &payload);
        probe_client(&mut flow, &p);
        assert_eq!(flow.meta.dns_query.as_deref(), Some("pwn.example"));
        assert!(flow.probed, "命中后应置 probed 防止重复解析");
        assert!(flow.meta.tls_sni.is_none());

        // probed 后不再重复解析
        p.dport = 9999; // 即使换端口也不再探测
        probe_client(&mut flow, &p);
        assert_eq!(flow.meta.dns_query.as_deref(), Some("pwn.example"));
    }

    #[test]
    fn probe_tcp_dns_skips_length_prefix_and_avoids_misalignment() {
        // TCP 53 带 2 字节大端长度前缀：正常解析查询与应答
        let mut flow = default_flow();
        let q = dns_query("tcp.example");
        let mut tcp_q = Vec::with_capacity(2 + q.len());
        tcp_q.extend_from_slice(&(q.len() as u16).to_be_bytes());
        tcp_q.extend_from_slice(&q);
        probe_client(&mut flow, &pkt(54321, DNS_PORT, &tcp_q));
        assert_eq!(flow.meta.dns_query.as_deref(), Some("tcp.example"));
        assert!(flow.probed);

        let r = dns_response("tcp.example", 0, &[(1, &[9, 9, 9, 9])]);
        let mut tcp_r = Vec::with_capacity(2 + r.len());
        tcp_r.extend_from_slice(&(r.len() as u16).to_be_bytes());
        tcp_r.extend_from_slice(&r);
        probe_server(&mut flow, &pkt(DNS_PORT, 54321, &tcp_r));
        assert_eq!(flow.meta.dns_answers, vec!["9.9.9.9"]);
        assert!(flow.probed_server);

        // TCP 53 上不带长度前缀的裸报文：绝不错位解析出垃圾域名
        let mut raw_flow = default_flow();
        probe_client(&mut raw_flow, &pkt(54321, DNS_PORT, &q));
        assert!(raw_flow.meta.dns_query.is_none());

        // TCP 53 复用跑 TLS 隧道：不被误当 DNS，能正常识别 SNI
        let mut tls_flow = default_flow();
        let ch = client_hello("tunnel.example", false);
        probe_client(&mut tls_flow, &pkt(54321, DNS_PORT, &ch));
        assert!(tls_flow.meta.dns_query.is_none());
        assert_eq!(tls_flow.meta.tls_sni.as_deref(), Some("tunnel.example"));
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
            ciphers.push(0x0a);
            ciphers.push(0x0a);
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
        probe_client(&mut flow, &pkt(52000, 443, &payload));
        assert_eq!(flow.meta.tls_sni.as_deref(), Some("c2.example"));
        assert!(!flow.meta.ja3.as_deref().unwrap_or("").is_empty());
        assert!(flow.probed);
        assert!(!flow.probed_server, "ClientHello 不应占用服务端探测位");
    }

    /// 构造 ServerHello：version TLS1.2 + 指定密码套件 + 扩展列表（可含 GREASE，空扩展体）。
    fn server_hello(cipher: u16, extensions: &[u16]) -> Vec<u8> {
        server_hello_exts(
            cipher,
            &extensions.iter().map(|e| (*e, &[][..])).collect::<Vec<_>>(),
        )
    }

    /// 构造带扩展体的 ServerHello（TLS1.3 的 supported_versions 需要非空扩展体）。
    fn server_hello_exts(cipher: u16, extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut hs = Vec::new();
        hs.push(0x02); // handshake type ServerHello
        hs.extend_from_slice(&[0, 0, 0]); // length 占位
        hs.extend_from_slice(&[0x03, 0x03]); // version TLS1.2
        hs.extend_from_slice(&[0xBB; 32]); // random
        hs.push(0); // session_id len == 0
        hs.extend_from_slice(&cipher.to_be_bytes());
        hs.push(0); // compression = null

        let mut exts = Vec::new();
        for (ext, body) in extensions {
            exts.extend_from_slice(&ext.to_be_bytes());
            exts.extend_from_slice(&(body.len() as u16).to_be_bytes());
            exts.extend_from_slice(body);
        }
        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);

        // 回填 handshake 3 字节长度（type 之后）
        let hs_len = (hs.len() - 4) as u32;
        hs[1..4].copy_from_slice(&hs_len.to_be_bytes()[1..]);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn tls_server_hello_ja3s() {
        let payload = server_hello(0x1301, &[0x0000, 0x0010]);
        let ja3s = parse_server_hello(&payload).expect("应解析出 ServerHello");
        // 771,4865,0-16 的 md5
        assert_eq!(ja3s, md5_hex("771,4865,0-16"));
    }

    #[test]
    fn tls_server_hello_no_extensions() {
        // 没有扩展块的老服务端：JA3S 第三段为空
        let mut payload = server_hello(0x002f, &[]);
        // 砍掉扩展长度两字节，模拟真·无扩展块
        payload.truncate(payload.len() - 2);
        let ja3s = parse_server_hello(&payload).expect("无扩展块也应出指纹");
        assert_eq!(ja3s, md5_hex("771,47,"));
    }

    #[test]
    fn tls_server_hello_grease_removed() {
        let a = parse_server_hello(&server_hello(0x1301, &[0x0000])).unwrap();
        let b = parse_server_hello(&server_hello(0x1301, &[0x0a0a, 0x0000])).unwrap();
        assert_eq!(a, b, "GREASE 扩展应被剔除，JA3S 不受其影响");
    }

    #[test]
    fn tls_parse_rejects_non_serverhello() {
        assert!(parse_server_hello(b"").is_none());
        assert!(parse_server_hello(&client_hello("x.example", false)).is_none());
        assert!(parse_server_hello(&[0x17, 0x03, 0x03, 0x00]).is_none()); // 应用数据
    }

    #[test]
    fn probe_tls_both_directions() {
        // 同一条流：ClientHello 与 ServerHello 各探一次
        let mut flow = default_flow();
        probe_client(
            &mut flow,
            &pkt(52000, 443, &client_hello("c2.example", false)),
        );
        assert!(flow.probed);
        assert!(!flow.probed_server);

        // TLS1.2 的 ServerHello 之后还要等 Certificate，先不置 probed_server
        probe_server(&mut flow, &pkt(443, 52000, &server_hello(0x1301, &[])));
        assert!(!flow.probed_server);
        assert_eq!(
            flow.meta.ja3s.as_deref(),
            Some(md5_hex("771,4865,").as_str())
        );

        // 应用数据出现 → 握手窗口已过，探测完成
        let app = [0x17, 0x03, 0x03, 0x00, 0x01, 0x00];
        probe_server(&mut flow, &pkt(443, 52000, &app));
        assert!(flow.probed_server);
    }

    /// 构造 Certificate handshake record：certificate_list 只放一张 DER。
    fn certificate_record(der: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&((3 + der.len()) as u32).to_be_bytes()[1..]); // list 总长
        body.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]); // 证书长度
        body.extend_from_slice(der);

        let mut hs = vec![0x0b]; // handshake type Certificate
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    use crate::x509::tests::{LEAF_DER, SELF_DER};

    #[test]
    fn probe_tls_cert_cross_packet_reassembly() {
        // ServerHello 与 Certificate 各自完整，但 Certificate record 跨 3 个 TCP 段
        let mut flow = default_flow();
        let mut budget = TlsBufBudget::default();
        probe(
            &mut flow,
            &pkt(443, 52000, &server_hello(0x1301, &[])),
            false,
            &mut budget,
        );
        assert!(flow.meta.ja3s.is_some());
        assert!(!flow.probed_server);

        let cert = certificate_record(SELF_DER);
        let third = cert.len() / 3;
        for chunk in [&cert[..third], &cert[third..2 * third], &cert[2 * third..]] {
            probe(&mut flow, &pkt(443, 52000, chunk), false, &mut budget);
        }
        assert!(flow.probed_server, "证书解析完成应置 probed_server");
        assert_eq!(flow.tls_hs_buf.capacity(), 0, "完成后应释放堆容量");
        assert_eq!(budget.used(), 0, "完成后预算应归零");
        assert_eq!(flow.meta.cert_subject.as_deref(), Some("evil.selfsigned"));
        assert_eq!(flow.meta.cert_issuer.as_deref(), Some("evil.selfsigned"));
        assert!(flow.meta.cert_self_signed);
        assert_eq!(flow.meta.cert_not_before, 1_786_286_565);
        assert_eq!(flow.meta.cert_not_after, 1_817_822_565);
    }

    #[test]
    fn probe_client_packet_does_not_corrupt_tls_hs_buf() {
        // 服务端 Certificate 跨段传输期间穿插客户端包，不能把客户端载荷拼进服务端 tls_hs_buf
        let mut flow = default_flow();
        let mut budget = TlsBufBudget::default();
        probe(
            &mut flow,
            &pkt(52000, 443, &client_hello("c2.example", false)),
            true,
            &mut budget,
        );
        probe(
            &mut flow,
            &pkt(443, 52000, &server_hello(0x1301, &[])),
            false,
            &mut budget,
        );
        let cert = certificate_record(SELF_DER);
        let mid = cert.len() / 2;
        probe(
            &mut flow,
            &pkt(443, 52000, &cert[..mid]),
            false,
            &mut budget,
        );
        // 穿插一个客户端方向的数据包（如重传或乱序客户端包）
        probe(
            &mut flow,
            &pkt(52000, 443, b"CLIENT_NOISE_MUST_NOT_POLLUTE"),
            true,
            &mut budget,
        );
        probe(
            &mut flow,
            &pkt(443, 52000, &cert[mid..]),
            false,
            &mut budget,
        );
        assert!(flow.probed_server);
        assert_eq!(
            flow.meta.cert_subject.as_deref(),
            Some("evil.selfsigned"),
            "穿插客户端包后证书仍应完整解析"
        );
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn probe_non_http_tls_gives_up_after_first_packets() {
        // SSH/DB/gRPC 等非 HTTP/TLS 流量：前 MAX_PROBE_PACKETS 个包都没命中就置 probed，避免长流反复扫描
        let mut flow = default_flow();
        for _ in 0..MAX_PROBE_PACKETS {
            assert!(!flow.probed && !flow.probed_server);
            probe_client(&mut flow, &pkt(52000, 22, b"SSH-2.0-OpenSSH_9.6\r\n"));
            probe_server(&mut flow, &pkt(22, 52000, b"SSH-2.0-OpenSSH_9.6\r\n"));
        }
        assert!(flow.probed && flow.probed_server);
        assert!(flow.meta.http_uri.is_none());
        assert!(flow.meta.tls_sni.is_none());
    }

    #[test]
    fn probe_starttls_after_plaintext() {
        // SMTP STARTTLS：两边先走几轮明文，之后的 ClientHello / ServerHello 照样要提取
        let mut flow = default_flow();
        probe_server(&mut flow, &pkt(25, 52000, b"220 mx.example ESMTP\r\n"));
        probe_client(&mut flow, &pkt(52000, 25, b"EHLO c.example\r\n"));
        probe_server(
            &mut flow,
            &pkt(25, 52000, b"250-mx.example\r\n250 STARTTLS\r\n"),
        );
        probe_client(&mut flow, &pkt(52000, 25, b"STARTTLS\r\n"));
        probe_server(
            &mut flow,
            &pkt(25, 52000, b"220 2.0.0 Ready to start TLS\r\n"),
        );
        assert!(!flow.probed && !flow.probed_server);
        probe_client(
            &mut flow,
            &pkt(52000, 25, &client_hello("mx.example", false)),
        );
        assert_eq!(flow.meta.tls_sni.as_deref(), Some("mx.example"));
        assert!(flow.probed);
        let mut payload = server_hello(0x1301, &[]);
        payload.extend_from_slice(&certificate_record(LEAF_DER));
        probe_server(&mut flow, &pkt(25, 52000, &payload));
        assert!(flow.meta.ja3s.is_some());
        assert_eq!(flow.meta.cert_subject.as_deref(), Some("leaf.example"));
    }

    #[test]
    fn probe_tls_serverhello_and_cert_same_packet() {
        // ServerHello + Certificate 两个 record 塞同一个包，批量解析
        let mut flow = default_flow();
        let mut payload = server_hello(0x1301, &[]);
        payload.extend_from_slice(&certificate_record(LEAF_DER));
        probe_server(&mut flow, &pkt(443, 52000, &payload));
        assert!(flow.probed_server);
        assert!(flow.meta.ja3s.is_some());
        assert_eq!(flow.meta.cert_subject.as_deref(), Some("leaf.example"));
        assert_eq!(flow.meta.cert_issuer.as_deref(), Some("Test CA"));
        assert!(!flow.meta.cert_self_signed);
    }

    #[test]
    fn probe_tls13_stops_without_cert() {
        // TLS1.3：supported_versions 选 0x0304，证书永远等不到 → JA3S 到手即完成，同时记下版本与 ALPN
        let mut flow = default_flow();
        // ALPN 扩展体：list_len=3, name_len=2, "h2"
        let sh = server_hello_exts(
            0x1301,
            &[
                (0x002b, &[0x03, 0x04]),
                (0x0010, &[0x00, 0x03, 0x02, b'h', b'2']),
            ],
        );
        probe_server(&mut flow, &pkt(443, 52000, &sh));
        assert!(flow.probed_server, "TLS1.3 不应等证书");
        assert!(flow.meta.ja3s.is_some());
        assert_eq!(flow.meta.tls_version.as_deref(), Some("TLS 1.3"));
        assert_eq!(flow.meta.tls_alpn.as_deref(), Some("h2"));
        assert!(flow.tls_hs_buf.is_empty());
        assert_eq!(flow.tls_hs_buf.capacity(), 0);
        assert!(flow.meta.cert_subject.is_none());
    }

    #[test]
    fn tls_alpn_parsing_and_negotiation() {
        // 合法 ALPN 列表：取首个协议；服务端选定值覆盖客户端候选
        assert_eq!(
            parse_alpn(&[
                0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'
            ])
            .as_deref(),
            Some("h2")
        );
        // 截断或空名应静默返回 None
        assert_eq!(parse_alpn(&[]), None);
        assert_eq!(parse_alpn(&[0x00, 0x05, 0x02, b'h']), None);
        assert_eq!(parse_alpn(&[0x00, 0x01, 0x00]), None);

        // TLS 1.2 ServerHello 无 supported_versions 扩展时，version 回退取握手头 0x0303 -> "TLS 1.2"
        let mut flow = default_flow();
        let sh12 = server_hello_exts(
            0xc02f,
            &[(
                0x0010,
                &[
                    0x00, 0x09, 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
                ],
            )],
        );
        probe_server(&mut flow, &pkt(443, 52000, &sh12));
        assert_eq!(flow.meta.tls_version.as_deref(), Some("TLS 1.2"));
        assert_eq!(flow.meta.tls_alpn.as_deref(), Some("http/1.1"));
    }

    #[test]
    fn probe_tls_buffer_cap_stops() {
        // 声明一个永远攒不齐的大 record，缓冲超过 16KB 上限 → 先判超限不追加并彻底释放堆容量
        let mut flow = default_flow();
        let mut budget = TlsBufBudget::default();
        let mut junk = vec![0x16, 0x03, 0x03, 0x3f, 0xff, 0x0b]; // len=16383，type Certificate
        junk.extend_from_slice(&[0xAA; 8192]);
        probe(&mut flow, &pkt(443, 52000, &junk), false, &mut budget);
        assert!(!flow.probed_server);
        assert_eq!(budget.used(), junk.len());
        // 第二段把缓冲推过上限
        let more = vec![0xBB; 9000];
        probe(&mut flow, &pkt(443, 52000, &more), false, &mut budget);
        assert!(flow.probed_server, "缓冲超限应停止");
        assert!(flow.tls_hs_buf.is_empty(), "超限后缓冲应清空");
        assert_eq!(flow.tls_hs_buf.capacity(), 0, "超限后应真正释放底层堆容量");
        assert_eq!(budget.used(), 0, "超限后应归还预算");
    }

    #[test]
    fn probe_tls_buffer_budget_caps_half_handshake_oom() {
        // worker 级重组预算上限：半截 ServerHello 洪泛不能无限囤积内存
        let mut budget = TlsBufBudget::new(10_000);
        let mut half = vec![0x16, 0x03, 0x03, 0x3f, 0xff, 0x0b];
        half.extend_from_slice(&[0xAA; 6000]);

        let mut f1 = default_flow();
        probe(&mut f1, &pkt(443, 50001, &half), false, &mut budget);
        assert!(!f1.probed_server);
        assert_eq!(budget.used(), half.len());

        // 第二条半截流会超 10_000 预算 → 拒绝囤积缓冲并置 probed_server
        let mut f2 = default_flow();
        probe(&mut f2, &pkt(443, 50002, &half), false, &mut budget);
        assert!(f2.probed_server);
        assert_eq!(f2.tls_hs_buf.capacity(), 0);
        assert_eq!(budget.used(), half.len());

        // 预算紧张时单包完整 TLS 1.3 ServerHello 走零分配路径依然能正常解析
        let mut f3 = default_flow();
        let sh13 = server_hello_exts(0x1301, &[(0x002b, &[0x03, 0x04])]);
        probe(&mut f3, &pkt(443, 50003, &sh13), false, &mut budget);
        assert!(f3.probed_server);
        assert!(f3.meta.ja3s.is_some());
        assert_eq!(f3.meta.tls_version.as_deref(), Some("TLS 1.3"));
    }

    #[test]
    fn probe_tls_appdata_stops_immediately() {
        // 服务端第一个包就是应用数据（会话复用等）→ 直接完成，不进缓冲
        let mut flow = default_flow();
        let app = [0x17, 0x03, 0x03, 0x00, 0x10, 0x00];
        probe_server(&mut flow, &pkt(443, 52000, &app));
        assert!(flow.probed_server);
        assert!(flow.tls_hs_buf.is_empty());
        assert!(flow.meta.ja3s.is_none());
    }

    #[test]
    fn http_request_parsing() {
        let req =
            b"GET /admin/login HTTP/1.1\r\nHost: target.example\r\nUser-Agent: curl/8.0\r\n\r\n";
        let h = parse_http_request(req).expect("应解析出 HTTP 请求");
        assert_eq!(h.uri, "/admin/login");
        assert_eq!(h.host.as_deref(), Some("target.example"));
        assert_eq!(h.user_agent.as_deref(), Some("curl/8.0"));
    }

    #[test]
    fn http_request_with_binary_post_body() {
        // POST 请求头后紧跟非法 UTF-8 二进制 body（gzip / protobuf 等）：不能因 body 导致头部解析失败
        let mut req = Vec::new();
        req.extend_from_slice(
            b"POST /upload HTTP/1.1\r\nHost: api.example\r\nUser-Agent: agent/1.0\r\nContent-Type: application/octet-stream\r\n\r\n",
        );
        req.extend_from_slice(&[0x1f, 0x8b, 0x08, 0xff, 0xfe, 0x80, 0x00, 0xc0]);
        let h = parse_http_request(&req).expect("含二进制 body 的 HTTP 请求应能解析出头部");
        assert_eq!(h.uri, "/upload");
        assert_eq!(h.host.as_deref(), Some("api.example"));
        assert_eq!(h.user_agent.as_deref(), Some("agent/1.0"));
    }

    #[test]
    fn http_request_with_truncated_tail_header() {
        // 头部末尾被 TCP 分段截断（残缺头名无冒号），应容错保留已解析的 URI / Host / User-Agent
        let req = b"GET /download?id=1 HTTP/1.1\r\nHost: cdn.example\r\nUser-Agent: Mozilla/5.0\r\nX-Truncated-Header-No-Colon";
        let h = parse_http_request(req).expect("截断尾部头行时应保留已解析字段");
        assert_eq!(h.uri, "/download?id=1");
        assert_eq!(h.host.as_deref(), Some("cdn.example"));
        assert_eq!(h.user_agent.as_deref(), Some("Mozilla/5.0"));
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

    /// 客户端方向的 TLS record：类型 + 指定长度的占位载荷
    fn record(rtype: u8, len: usize) -> Vec<u8> {
        let mut r = vec![rtype, 0x03, 0x03];
        r.extend_from_slice(&(len as u16).to_be_bytes());
        r.extend(std::iter::repeat_n(0xCC, len));
        r
    }

    fn handshake_only(segments: &[&[u8]], tls13: bool) -> bool {
        let mut flow = default_flow();
        flow.meta.tls13 = tls13;
        for seg in segments {
            track_tls_client(&mut flow, &pkt(52000, 443, seg), true);
        }
        flow.tls_client.handshake_only(flow.meta.tls13)
    }

    #[test]
    fn tls_handshake_only_tracking() {
        let hello = client_hello("gw.example", false);
        // TLS 1.2 扫描器：ClientHello，再发 ClientKeyExchange / CCS / Finished、alert 后关连接
        let tail12 = [record(22, 70), record(20, 1), record(22, 40), record(21, 2)].concat();
        assert!(handshake_only(&[&hello, &tail12], false));
        // 1.2 正常客户端：握手后发了请求
        assert!(!handshake_only(&[&hello, &tail12, &record(23, 120)], false));
        // 只发 ClientHello 就断开（证书 / JA3S 探测）
        assert!(handshake_only(&[&hello], false));
        // TLS 1.3：CCS + 加密的 Finished + 加密的 close_notify，仍是只握手
        let tail13 = [record(20, 1), record(23, 53), record(23, 19)].concat();
        assert!(handshake_only(&[&hello, &tail13], true));
        // 1.3 发了请求
        assert!(!handshake_only(&[&hello, &tail13, &record(23, 90)], true));
        // 没见过 ServerHello、不知道是 1.3：Finished 当请求算，宁可漏报
        assert!(!handshake_only(&[&hello, &tail13], false));
    }

    #[test]
    fn tls_tracking_spans_segments_and_fails_closed() {
        let hello = client_hello("gw.example", false);
        // ClientHello 跨两段：第二段整段都是 hello 的剩余部分，不能当新 record 头读
        let (a, b) = hello.split_at(20);
        assert!(handshake_only(&[a, b], false));
        let data = record(23, 300);
        let (c, d) = data.split_at(100);
        assert!(!handshake_only(&[&hello, c, d], false));
        // 第一段客户端载荷不是 ClientHello：不是 TLS 或没看到开头，不下结论
        assert!(!handshake_only(&[b"GET / HTTP/1.1\r\n\r\n"], false));
        // record 头对不上（抓包丢段后错位）：判跟丢
        assert!(!handshake_only(&[&hello, b"\x99garbage"], false));
        // 服务端方向的载荷不参与
        let mut flow = default_flow();
        track_tls_client(&mut flow, &pkt(443, 52000, &record(23, 500)), false);
        track_tls_client(&mut flow, &pkt(52000, 443, &hello), true);
        assert!(flow.tls_client.handshake_only(false));
    }
}
