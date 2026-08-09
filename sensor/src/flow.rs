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
}

impl Flow {
    fn finished(&self) -> bool {
        self.key.proto == IPPROTO_TCP && self.tcp_flags & (TCP_FIN | TCP_RST) != 0
    }
}

pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    idle_timeout_ns: u64,
    max_lifetime_ns: u64,
    max_flows: usize,
    last_sweep_ns: u64,
    sweep_interval_ns: u64,
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
            flows: HashMap::with_capacity(1 << 16),
            idle_timeout_ns: cfg.idle_timeout_secs * 1_000_000_000,
            max_lifetime_ns: cfg.max_lifetime_secs * 1_000_000_000,
            max_flows: cfg.max_flows,
            last_sweep_ns: 0,
            sweep_interval_ns: cfg.sweep_interval_secs * 1_000_000_000,
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// 收一个包。返回本包所属流的可变引用和方向（true = a→b），
    /// 供上层做协议识别；流表满时返回 None（丢弃计数由调用方统计）。
    pub fn update<'a>(&'a mut self, pkt: &Packet, ts_ns: u64) -> Option<(&'a mut Flow, bool)> {
        let (key, forward) = FlowKey::from_packet(pkt);
        if !self.flows.contains_key(&key) && self.flows.len() >= self.max_flows {
            return None;
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
        Some((flow, forward))
    }

    /// 导出已结束/超时的流。TCP 的 FIN/RST 流立即导出，其余按超时。
    /// 未到扫描间隔时只处理已结束的流，避免每包遍历全表。
    pub fn expire(&mut self, now_ns: u64, out: &mut Vec<Flow>) {
        let full_sweep = now_ns.saturating_sub(self.last_sweep_ns) >= self.sweep_interval_ns;
        if !full_sweep {
            return;
        }
        self.last_sweep_ns = now_ns;

        let idle = self.idle_timeout_ns;
        let lifetime = self.max_lifetime_ns;
        out.extend(
            self.flows
                .extract_if(|_, flow| {
                    flow.finished()
                        || now_ns.saturating_sub(flow.last_ns) >= idle
                        || now_ns.saturating_sub(flow.start_ns) >= lifetime
                })
                .map(|(_, flow)| flow),
        );
    }

    /// 进程退出前导出全部在途流。
    pub fn drain_all(&mut self, out: &mut Vec<Flow>) {
        out.extend(self.flows.drain().map(|(_, f)| f));
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
        let (_, forward) = ft.update(&a, now).unwrap();
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
    fn flow_table_full_drops() {
        let cfg = Config {
            max_flows: 2,
            ..Config::default()
        };
        let mut ft = FlowTable::new(&cfg);
        let now = 0;
        assert!(
            ft.update(&pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1, 80, 0, 60), now)
                .is_some()
        );
        assert!(
            ft.update(&pkt(v4(3, 0, 0, 3), v4(4, 0, 0, 4), 1, 80, 0, 60), now)
                .is_some()
        );
        // 已满，第三条被丢
        assert!(
            ft.update(&pkt(v4(5, 0, 0, 5), v4(6, 0, 0, 6), 1, 80, 0, 60), now)
                .is_none()
        );
        // 已有 key 仍能更新（不新增）
        assert!(
            ft.update(&pkt(v4(1, 0, 0, 1), v4(2, 0, 0, 2), 1, 80, 0, 0), now)
                .is_some()
        );
        assert_eq!(ft.len(), 2);
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
