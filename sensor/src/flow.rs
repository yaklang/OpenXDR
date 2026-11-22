//! 流表：五元组 → 会话状态。
//!
//! 每 worker 一张独立流表，无锁——FANOUT_HASH 保证同一条流恒定落到同一 worker。
//! 老化策略：TCP 见 FIN/RST 立即结束；否则空闲超时；长流按最大生存期强制切分。

use std::collections::HashMap;
use std::net::IpAddr;

use crate::decode::{IPPROTO_TCP, Packet, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

/// 规范化五元组：小端在前，双向流量归并到同一条流。
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct FlowKey {
    pub a_ip: IpAddr,
    pub b_ip: IpAddr,
    pub a_port: u16,
    pub b_port: u16,
    pub proto: u8,
}

impl FlowKey {
    fn from_packet(pkt: &Packet) -> (Self, bool) {
        let forward = (pkt.src, pkt.sport) <= (pkt.dst, pkt.dport);
        let key = if forward {
            Self {
                a_ip: pkt.src,
                b_ip: pkt.dst,
                a_port: pkt.sport,
                b_port: pkt.dport,
                proto: pkt.proto,
            }
        } else {
            Self {
                a_ip: pkt.dst,
                b_ip: pkt.src,
                a_port: pkt.dport,
                b_port: pkt.sport,
                proto: pkt.proto,
            }
        };
        (key, forward)
    }
}

#[derive(Default, Clone)]
pub struct Metadata {
    pub dns_query: Option<String>,
    pub dns_rcode: Option<u32>,
    /// A/AAAA 应答 IP（至多 4 个）
    pub dns_answers: Vec<String>,
    pub tls_sni: Option<String>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub http_host: Option<String>,
    pub http_uri: Option<String>,
    pub http_user_agent: Option<String>,
    /// 叶证书 subject CN（仅 TLS ≤1.2 可见，1.3 证书加密传输）
    pub cert_subject: Option<String>,
    /// 叶证书 issuer CN
    pub cert_issuer: Option<String>,
    /// subject 与 issuer 原始 DER 相等（自签启发式，不做签名验证）
    pub cert_self_signed: bool,
    /// 证书有效期起（unix 秒），无则 0
    pub cert_not_before: i64,
    /// 证书有效期止（unix 秒），无则 0
    pub cert_not_after: i64,
    /// ServerHello 选了 TLS 1.3（supported_versions = 0x0304）
    pub tls13: bool,
    /// ServerHello 选定的 TLS 版本（如 "TLS 1.3"、"TLS 1.2"）
    pub tls_version: Option<String>,
    /// ALPN 应用层协议（如 "h2"、"http/1.1"），服务端选定值优先，回退取客户端首个协议
    pub tls_alpn: Option<String>,
}

/// 客户端方向 TLS record 跟踪：从 ClientHello 起逐个 record 往前走，数带载荷的应用数据，
/// 用来判断握手之后客户端有没有发过请求。只看 record 头，不重组、不解密。
#[derive(Default, Clone)]
pub struct TlsClient {
    /// 见过 ClientHello 才开始跟
    pub tracking: bool,
    /// 跟丢了（第一段载荷不是 ClientHello、record 头对不上或跨段）：不再下结论
    pub lost: bool,
    /// 当前 record 还差多少字节没过完
    pub pending: usize,
    /// 带载荷的应用数据 record 数（TLS 1.3 加密后的 Finished 也算一条）
    pub data_records: u32,
}

impl TlsClient {
    /// 只握手不发请求：跟得上、且应用数据 record 不超过 TLS 1.3 的 Finished 那一条。
    /// 没见过 ServerHello 时按 1.2 算，1.3 的 Finished 会被当成请求——宁可漏报不误报。
    pub fn handshake_only(&self, tls13: bool) -> bool {
        self.tracking && !self.lost && self.data_records <= u32::from(tls13)
    }
}

pub struct Flow {
    pub key: FlowKey,
    pub start_ns: u64,
    pub last_ns: u64,
    pub a_to_b_packets: u64,
    pub a_to_b_bytes: u64,
    pub b_to_a_packets: u64,
    pub b_to_a_bytes: u64,
    pub tcp_flags: u8,
    pub meta: Metadata,
    /// 已尝试过协议识别（DNS 查询 / ClientHello / HTTP），不再重复解析
    pub probed: bool,
    /// 服务端方向已探测（DNS 应答 rcode/answers、ServerHello JA3S）。
    /// 与 probed 分开：同一条流两个方向各探一次。
    pub probed_server: bool,
    /// a 侧是否为客户端。五元组按大小归一化会丢掉方向，
    /// 而"谁是服务端"是网络检测的基本前提，必须单独记住。
    pub client_is_a: bool,
    /// TLS 服务端 handshake 重组缓冲：证书常跨 TCP 分段，攒到有界上限再解析。
    /// 默认空 Vec 无堆分配，只有 TLS 流才会 push。
    pub tls_hs_buf: Vec<u8>,
    pub tls_client: TlsClient,
}

/// 默认每 worker 未完成 TLS 服务端握手重组缓冲总上限（32 MiB），防止半截 ServerHello 洪泛 OOM
pub const DEFAULT_MAX_TLS_HS_BYTES: usize = 32 * 1024 * 1024;

/// 满表触发时间清理时暂存待导出流的数量上限，避免洪泛场景在内存里无限囤积
const MAX_PENDING_EXPIRED: usize = 65536;

/// 满表回收的最短间隔（1s），不论上次腾没腾出空间：百万条流的全表扫描要几十毫秒，
/// SYN 洪泛下每腾一批就再扫一次，worker 会被扫描吃满，连已有流都统计不过来
const FULL_RECLAIM_COOLDOWN_NS: u64 = 1_000_000_000;

/// worker 级 TLS 服务端握手重组缓冲预算。每张流表独享一份，无锁。
#[derive(Debug)]
pub struct TlsBufBudget {
    used: usize,
    limit: usize,
}

impl Default for TlsBufBudget {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_TLS_HS_BYTES)
    }
}

impl TlsBufBudget {
    pub fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }

    #[cfg(test)]
    pub fn used(&self) -> usize {
        self.used
    }

    pub fn can_add(&self, delta: usize) -> bool {
        self.used.saturating_add(delta) <= self.limit
    }

    pub fn add(&mut self, bytes: usize) {
        self.used = self.used.saturating_add(bytes);
    }

    pub fn sub(&mut self, bytes: usize) {
        self.used = self.used.saturating_sub(bytes);
    }

    pub fn update(&mut self, old_len: usize, new_len: usize) {
        self.used = self.used.saturating_sub(old_len).saturating_add(new_len);
    }

    /// 释放单条流的重组缓冲并归还预算（替换为 Vec::new() 真正释放底层堆容量）
    pub fn release(&mut self, buf: &mut Vec<u8>) {
        let taken = std::mem::take(buf);
        self.used = self.used.saturating_sub(taken.len());
    }
}

impl Flow {
    fn finished(&self) -> bool {
        self.key.proto == IPPROTO_TCP && self.tcp_flags & (TCP_FIN | TCP_RST) != 0
    }

    /// 空/短连接流判定：TCP 纯 SYN 半开连接，或双向合计不超过 1 个包。
    /// 满表时优先驱逐这类流，防止 SYN 洪泛或扫描包长期占满流表。
    fn is_evictable_short(&self) -> bool {
        let syn_only =
            self.key.proto == IPPROTO_TCP && (self.tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN;
        syn_only || self.a_to_b_packets.saturating_add(self.b_to_a_packets) <= 1
    }
}

pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    idle_timeout_ns: u64,
    max_lifetime_ns: u64,
    max_flows: usize,
    last_sweep_ns: u64,
    sweep_interval_ns: u64,
    tls_budget: TlsBufBudget,
    pending_expired: Vec<Flow>,
    last_full_reclaim_ns: Option<u64>,
}

pub struct Config {
    pub idle_timeout_secs: u64,
    pub max_lifetime_secs: u64,
    pub max_flows: usize,
    pub sweep_interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            idle_timeout_secs: 30,
            max_lifetime_secs: 300,
            max_flows: 1 << 20, // 每 worker 上限 100 万条流
            sweep_interval_secs: 5,
        }
    }
}

impl FlowTable {
    pub fn new(cfg: &Config) -> Self {
        Self {
            flows: HashMap::with_capacity((1 << 16).min(cfg.max_flows)),
            idle_timeout_ns: cfg.idle_timeout_secs * 1_000_000_000,
            max_lifetime_ns: cfg.max_lifetime_secs * 1_000_000_000,
            max_flows: cfg.max_flows,
            last_sweep_ns: 0,
            sweep_interval_ns: cfg.sweep_interval_secs * 1_000_000_000,
            tls_budget: TlsBufBudget::default(),
            pending_expired: Vec::new(),
            last_full_reclaim_ns: None,
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// 满表时回收空间：先做一次按时间清理（到期流暂存待导出，暂存满了就留在表里等下次清理，不丢），
    /// 若仍满再批量驱逐最新的一批空/短连接流，防止 SYN 洪泛阻断新流长达 30 秒。
    /// 驱逐最新的而不是最老的：洪泛的伪造 SYN 都是新的，较早的单包流（DNS 外传、UDP beacon）是证据，要留到正常超时导出
    fn reclaim_on_full(&mut self, now_ns: u64) {
        let idle = self.idle_timeout_ns;
        let lifetime = self.max_lifetime_ns;
        self.last_sweep_ns = now_ns;
        let mut room = MAX_PENDING_EXPIRED.saturating_sub(self.pending_expired.len());
        for (_, mut flow) in self.flows.extract_if(|_, flow| {
            let due = flow.finished()
                || now_ns.saturating_sub(flow.last_ns) >= idle
                || now_ns.saturating_sub(flow.start_ns) >= lifetime;
            if due && room > 0 {
                room -= 1;
                return true;
            }
            false
        }) {
            self.tls_budget.release(&mut flow.tls_hs_buf);
            self.pending_expired.push(flow);
        }
        if self.flows.len() < self.max_flows {
            return;
        }

        // 仍满：挑最新的一批空/短连接流驱逐，一次腾出表的 1/16，配合冷却间隔把全表扫描压到每秒至多一次
        let target = (self.max_flows / 16).max(1);
        let mut shorts: Vec<(FlowKey, u64)> = self
            .flows
            .iter()
            .filter(|(_, f)| f.is_evictable_short())
            .map(|(k, f)| (*k, f.last_ns))
            .collect();
        if shorts.len() > target {
            shorts.select_nth_unstable_by_key(target, |&(_, last_ns)| std::cmp::Reverse(last_ns));
            shorts.truncate(target);
        }
        for (k, _) in shorts {
            if let Some(mut flow) = self.flows.remove(&k) {
                self.tls_budget.release(&mut flow.tls_hs_buf);
            }
        }
    }

    /// 收一个包。返回本包所属流的可变引用、方向（true = a→b）与本 worker 的 TLS 重组预算，
    /// 供上层做协议识别；流表满且无法回收时返回 None（丢弃计数由调用方统计）。
    pub fn update<'a>(
        &'a mut self,
        pkt: &Packet,
        ts_ns: u64,
    ) -> Option<(&'a mut Flow, bool, &'a mut TlsBufBudget)> {
        let (key, forward) = FlowKey::from_packet(pkt);
        if !self.flows.contains_key(&key) && self.flows.len() >= self.max_flows {
            if self.max_flows == 0 {
                return None;
            }
            if self
                .last_full_reclaim_ns
                .is_some_and(|t| ts_ns.saturating_sub(t) < FULL_RECLAIM_COOLDOWN_NS)
            {
                return None;
            }
            self.reclaim_on_full(ts_ns);
            self.last_full_reclaim_ns = Some(ts_ns);
            if self.flows.len() >= self.max_flows {
                return None;
            }
        }

        // 方向判定：SYN 且无 ACK 的发送方是客户端；SYN+ACK 的发送方是服务端；
        // 都不是（UDP、或从中途开始观察的 TCP）则以首包发送方为客户端。
        let client_is_a = match pkt.tcp_flags & (TCP_SYN | TCP_ACK) {
            TCP_SYN => forward,
            f if f == TCP_SYN | TCP_ACK => !forward,
            _ => forward,
        };

        let flow = self.flows.entry(key).or_insert_with(|| Flow {
            key,
            start_ns: ts_ns,
            last_ns: ts_ns,
            a_to_b_packets: 0,
            a_to_b_bytes: 0,
            b_to_a_packets: 0,
            b_to_a_bytes: 0,
            tcp_flags: 0,
            meta: Metadata::default(),
            probed: false,
            probed_server: false,
            client_is_a,
            tls_hs_buf: Vec::new(),
            tls_client: TlsClient::default(),
        });

        flow.last_ns = ts_ns;
        flow.tcp_flags |= pkt.tcp_flags;
        if forward {
            flow.a_to_b_packets += 1;
            flow.a_to_b_bytes += pkt.frame_len as u64;
        } else {
            flow.b_to_a_packets += 1;
            flow.b_to_a_bytes += pkt.frame_len as u64;
        }
        Some((flow, forward, &mut self.tls_budget))
    }

    /// 导出已结束/超时的流。TCP 的 FIN/RST 流在扫描周期内导出，其余按超时。
    /// 未到扫描间隔时不做全表遍历，但会交付满表清理时暂存的到期流。
    pub fn expire(&mut self, now_ns: u64, out: &mut Vec<Flow>) {
        if !self.pending_expired.is_empty() {
            out.append(&mut self.pending_expired);
        }
        let full_sweep = now_ns.saturating_sub(self.last_sweep_ns) >= self.sweep_interval_ns;
        if !full_sweep {
            return;
        }
        self.last_sweep_ns = now_ns;

        let idle = self.idle_timeout_ns;
        let lifetime = self.max_lifetime_ns;
        let before = self.flows.len();
        for (_, mut flow) in self.flows.extract_if(|_, flow| {
            flow.finished()
                || now_ns.saturating_sub(flow.last_ns) >= idle
                || now_ns.saturating_sub(flow.start_ns) >= lifetime
        }) {
            self.tls_budget.release(&mut flow.tls_hs_buf);
            out.push(flow);
        }
        if self.flows.len() < before {
            self.last_full_reclaim_ns = None;
        }
    }

    /// 进程退出前导出全部在途流。
    pub fn drain_all(&mut self, out: &mut Vec<Flow>) {
        if !self.pending_expired.is_empty() {
            out.append(&mut self.pending_expired);
        }
        for (_, mut flow) in self.flows.drain() {
            self.tls_budget.release(&mut flow.tls_hs_buf);
            out.push(flow);
        }
        self.last_full_reclaim_ns = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::IPPROTO_UDP;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn pkt(
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        flags: u8,
        frame_len: usize,
    ) -> Packet<'static> {
        Packet {
            src,
            dst,
            proto: IPPROTO_TCP,
            sport,
            dport,
            tcp_flags: flags,
            payload: b"",
            frame_len,
        }
    }

    #[test]
    fn flow_key_bidirectional_normalization() {
        let a = pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1234, 80, 0, 100);
        let b = pkt(v4(2, 0, 0, 2), v4(1, 0, 0, 1), 80, 1234, 0, 100);

        let (ka, fa) = FlowKey::from_packet(&a);
        let (kb, fb) = FlowKey::from_packet(&b);

        assert!(ka == kb, "正反方向应归并到同一条流");
        assert_ne!(fa, fb, "方向标志应相反");
        // 规范化后源侧应是较小端点
        assert_eq!(ka.a_ip, v4(1, 0, 0, 1));
        assert_eq!(ka.a_port, 1234);
    }

    #[test]
    fn update_counts_per_direction() {
        let mut ft = FlowTable::new(&Config::default());
        let now = 1000;

        let a = pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1111, 80, TCP_SYN, 100);
        let (_, forward, _) = ft.update(&a, now).unwrap();
        assert!(forward, "小端→大端的包应为 forward");
        let reverse = pkt(v4(2, 0, 0, 2), v4(1, 0, 0, 1), 80, 1111, TCP_ACK, 64);
        ft.update(&reverse, now + 1);

        assert_eq!(ft.flows.values().next().unwrap().a_to_b_packets, 1);
        assert_eq!(ft.flows.values().next().unwrap().b_to_a_packets, 1);
        assert_eq!(ft.flows.values().next().unwrap().a_to_b_bytes, 100);
        assert_eq!(ft.flows.values().next().unwrap().b_to_a_bytes, 64);
    }

    #[test]
    fn client_direction_detection() {
        // 纯 SYN 发送方为客户端
        let f = pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1000, 443, TCP_SYN, 60);
        let mut ft = FlowTable::new(&Config::default());
        let _ = ft.update(&f, 0);
        assert!(ft.flows.values().next().unwrap().client_is_a);

        // SYN+ACK 发送方为服务端：服务端地址更小（是规范化后的 a 侧）→ a 是服务端
        let mut ft2 = FlowTable::new(&Config::default());
        let sa = pkt(
            v4(1, 0, 0, 1),
            v4(2, 0, 0, 2),
            443,
            1000,
            TCP_SYN | TCP_ACK,
            60,
        );
        let _ = ft2.update(&sa, 0);
        assert!(!ft2.flows.values().next().unwrap().client_is_a);

        // UDP：首包发送方即客户端
        let mut ft3 = FlowTable::new(&Config::default());
        let udp = Packet {
            proto: IPPROTO_UDP,
            ..pkt(v4(3, 0, 0, 3), v4(4, 0, 0, 4), 5000, 53, 0, 60)
        };
        let _ = ft3.update(&udp, 0);
        assert!(ft3.flows.values().next().unwrap().client_is_a);
    }

    #[test]
    fn flow_table_full_drops_when_all_active() {
        let cfg = Config {
            max_flows: 2,
            ..Config::default()
        };
        let mut ft = FlowTable::new(&cfg);
        let now = 0;
        // 两条均为已完成握手的双向活跃流，不应被当短连接驱逐
        assert!(
            ft.update(
                &pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1, 80, TCP_SYN, 60),
                now
            )
            .is_some()
        );
        assert!(
            ft.update(
                &pkt(v4(2, 0, 0, 2), v4(1, 0, 0, 1), 80, 1, TCP_SYN | TCP_ACK, 60),
                now
            )
            .is_some()
        );
        assert!(
            ft.update(
                &pkt(v4(3, 0, 0, 3), v4(4, 0, 0, 4), 1, 80, TCP_SYN, 60),
                now
            )
            .is_some()
        );
        assert!(
            ft.update(
                &pkt(v4(4, 0, 0, 4), v4(3, 0, 0, 3), 80, 1, TCP_SYN | TCP_ACK, 60),
                now
            )
            .is_some()
        );
        // 表内全是活跃流且未到期，第三条被拒
        assert!(
            ft.update(
                &pkt(v4(5, 0, 0, 5), v4(6, 0, 0, 6), 1, 80, TCP_ACK, 60),
                now
            )
            .is_none()
        );
        // 已有 key 仍能更新（不新增）
        assert!(
            ft.update(&pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1, 80, TCP_ACK, 0), now)
                .is_some()
        );
        assert_eq!(ft.len(), 2);
    }

    #[test]
    fn flow_table_full_reclaims_expired_first() {
        let cfg = Config {
            idle_timeout_secs: 10,
            max_lifetime_secs: 300,
            max_flows: 2,
            sweep_interval_secs: 30,
        };
        let mut ft = FlowTable::new(&cfg);
        // 插入两条已建连接，其中第一条在 t=1s，第二条在 t=5s
        let p1_a = pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1, 80, TCP_SYN, 60);
        let p1_b = pkt(v4(2, 0, 0, 2), v4(1, 0, 0, 1), 80, 1, TCP_SYN | TCP_ACK, 60);
        let p2_a = pkt(v4(3, 0, 0, 3), v4(4, 0, 0, 4), 1, 80, TCP_SYN, 60);
        let p2_b = pkt(v4(4, 0, 0, 4), v4(3, 0, 0, 3), 80, 1, TCP_SYN | TCP_ACK, 60);
        let _ = ft.update(&p1_a, 1_000_000_000);
        let _ = ft.update(&p1_b, 1_000_000_000);
        let _ = ft.update(&p2_a, 5_000_000_000);
        let _ = ft.update(&p2_b, 5_000_000_000);

        // t=12s 时第一条已空闲超过 10s（即使未到 30s 常规扫描周期），新流到达应触发清理并成功插入
        let p3 = pkt(v4(5, 0, 0, 5), v4(6, 0, 0, 6), 1, 443, TCP_SYN, 60);
        assert!(ft.update(&p3, 12_000_000_000).is_some());
        assert_eq!(ft.len(), 2);

        // 被清理的到期流在下次 expire 时应能交出，不丢失
        let mut out = Vec::new();
        ft.expire(12_000_000_000, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].key.a_ip, v4(1, 0, 0, 1));
    }

    #[test]
    fn flow_table_full_evicts_newest_syn_flood() {
        let cfg = Config {
            idle_timeout_secs: 30,
            max_lifetime_secs: 300,
            max_flows: 4,
            sweep_interval_secs: 5,
        };
        let mut ft = FlowTable::new(&cfg);
        // 1 条正常双向活跃流（t=1）
        let _ = ft.update(
            &pkt(v4(10, 0, 0, 1), v4(10, 0, 0, 2), 1000, 443, TCP_SYN, 60),
            1,
        );
        let _ = ft.update(
            &pkt(
                v4(10, 0, 0, 2),
                v4(10, 0, 0, 1),
                443,
                1000,
                TCP_SYN | TCP_ACK,
                60,
            ),
            1,
        );
        // 3 条 SYN 洪泛半开流占满剩余槽位（t=2, 3, 4）
        for i in 1u8..=3 {
            let _ = ft.update(
                &pkt(
                    v4(192, 0, 2, i),
                    v4(10, 0, 0, 2),
                    2000 + i as u16,
                    443,
                    TCP_SYN,
                    60,
                ),
                1 + i as u64,
            );
        }
        assert_eq!(ft.len(), 4);

        // t=5（远未到 30s 超时）新合法流到达：应驱逐最新的 SYN 流（t=4，192.0.2.3）并放行新流，较早的单包流留作证据
        let legit = pkt(v4(10, 0, 0, 9), v4(10, 0, 0, 2), 3000, 443, TCP_SYN, 60);
        assert!(
            ft.update(&legit, 5).is_some(),
            "SYN 洪泛占满流表时应驱逐短流放行新流"
        );
        assert_eq!(ft.len(), 4);
        assert!(
            ft.flows
                .keys()
                .any(|k| k.a_ip == v4(10, 0, 0, 1) || k.b_ip == v4(10, 0, 0, 1)),
            "已有双向活跃流不应被误驱逐"
        );
        assert!(
            !ft.flows
                .keys()
                .any(|k| k.a_ip == v4(192, 0, 2, 3) || k.b_ip == v4(192, 0, 2, 3)),
            "最新的 SYN 半开流应被优先驱逐"
        );
        assert!(
            ft.flows
                .keys()
                .any(|k| k.a_ip == v4(192, 0, 2, 1) || k.b_ip == v4(192, 0, 2, 1)),
            "较早的短流应留到正常超时导出"
        );

        // 冷却期内再满：直接丢新流，不再全表扫描；过了冷却期才再回收
        let next = pkt(v4(10, 0, 0, 10), v4(10, 0, 0, 2), 3001, 443, TCP_SYN, 60);
        assert!(ft.update(&next, 6).is_none());
        assert!(ft.update(&next, 5 + FULL_RECLAIM_COOLDOWN_NS).is_some());
    }

    #[test]
    fn tls_budget_released_on_expire_and_drain() {
        let cfg = Config {
            idle_timeout_secs: 1,
            max_lifetime_secs: 300,
            max_flows: 4,
            sweep_interval_secs: 0,
        };
        let mut ft = FlowTable::new(&cfg);
        let (flow, _, budget) = ft
            .update(
                &pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1000, 443, TCP_ACK, 60),
                0,
            )
            .unwrap();
        flow.tls_hs_buf = vec![0xAA; 1024];
        budget.add(1024);
        assert_eq!(ft.tls_budget.used(), 1024);

        let mut out = Vec::new();
        ft.expire(2_000_000_000, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(ft.tls_budget.used(), 0, "流过期后应归还 TLS 缓冲预算");
        assert_eq!(out[0].tls_hs_buf.capacity(), 0, "导出流应释放重组缓冲容量");
    }

    /// 空闲超时导出。sweep_interval=0 保证每次 expire 都做全量扫描。
    #[test]
    fn expire_idle_timeout() {
        let cfg = Config {
            idle_timeout_secs: 1,
            max_lifetime_secs: 3600,
            max_flows: 100,
            sweep_interval_secs: 0,
        };
        let mut ft = FlowTable::new(&cfg);
        let _ = ft.update(&pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1, 80, 0, 60), 0);
        let mut out = Vec::new();
        // 1 秒后仍未超时（>= 判定）
        ft.expire(999_999_999, &mut out);
        assert_eq!(out.len(), 0, "未到超时不应导出");
        ft.expire(1_000_000_000, &mut out); // 恰好 1s
        assert_eq!(out.len(), 1, "空闲超时应导出");
    }

    /// FIN/RST 立即结束，跨小间隔也能被收走。
    #[test]
    fn expire_fin_immediate() {
        let cfg = Config {
            sweep_interval_secs: 0,
            ..Config::default()
        };
        let mut ft = FlowTable::new(&cfg);
        let _ = ft.update(&pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1, 80, TCP_FIN, 60), 0);
        let mut out = Vec::new();
        ft.expire(1, &mut out);
        assert_eq!(out.len(), 1, "收到 FIN 的流应立即导出");
    }

    /// 重组流量按最大生存期强制切分。
    #[test]
    fn expire_max_lifetime() {
        let cfg = Config {
            idle_timeout_secs: 3600,
            max_lifetime_secs: 1,
            max_flows: 100,
            sweep_interval_secs: 0,
        };
        let mut ft = FlowTable::new(&cfg);
        let _ = ft.update(&pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1, 80, 0, 60), 0);
        let mut out = Vec::new();
        ft.expire(1_999_999_999, &mut out);
        assert_eq!(out.len(), 1, "超过最大生存期应被切分导出");
    }

    /// 未到扫描间隔时，即使有已结束的流也不做全量扫描（当前实现）。
    #[test]
    fn expire_skips_when_not_sweep_interval() {
        let cfg = Config {
            sweep_interval_secs: 10,
            idle_timeout_secs: 1,
            ..Config::default()
        };
        let mut ft = FlowTable::new(&cfg);
        let _ = ft.update(&pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1, 80, TCP_FIN, 60), 0);
        let mut out = Vec::new();
        ft.expire(1, &mut out); // 未到 10s 扫描间隔
        assert_eq!(out.len(), 0, "未到扫描间隔不导出（含已结束流）");
        assert_eq!(ft.len(), 1);
    }

    #[test]
    fn drain_all_empties_table() {
        let mut ft = FlowTable::new(&Config::default());
        let _ = ft.update(&pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1, 80, 0, 60), 0);
        let _ = ft.update(&pkt(v4(3, 0, 0, 3), v4(4, 0, 0, 4), 1, 80, 0, 60), 0);
        let mut out = Vec::new();
        ft.drain_all(&mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(ft.len(), 0);
    }
}
