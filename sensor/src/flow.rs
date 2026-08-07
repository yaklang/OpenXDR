//! 流表：五元组 → 会话状态。
//!
//! 每 worker 一张独立流表，无锁——FANOUT_HASH 保证同一条流恒定落到同一 worker。
//! 老化策略：TCP 见 FIN/RST 立即结束；否则空闲超时；长流按最大生存期强制切分。

use std::collections::HashMap;
use std::net::IpAddr;

use crate::decode::{Packet, IPPROTO_TCP, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

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
    pub tls_sni: Option<String>,
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
    /// 已尝试过协议识别，不再重复解析
    pub probed: bool,
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
