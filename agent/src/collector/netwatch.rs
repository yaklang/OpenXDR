//! TCP 出站连接采集的用户态侧：eBPF inet_sock_set_state 事件的采样与组装。
//!
//! 补的是无 sensor 小部署的网络盲区。同一目标的高频连接在窗口内只报一次——
//! 网络事件的价值在"连了谁"，不在"连了多少次"，次数是流量探针的活。

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::pb::AgentEvent;

/// OCSF Network Activity
const CLASS_NETWORK: u32 = 4001;

/// 同一 (目标地址, 端口) 的上报间隔
const SAMPLE_WINDOW: Duration = Duration::from_secs(60);

/// 采样表条目上限，超过即清理过期项，防止扫描行为撑爆内存
const MAX_TRACKED: usize = 4096;

#[derive(Default)]
pub struct ConnSampler {
    seen: HashMap<(IpAddr, u16), Instant>,
}

impl ConnSampler {
    /// 该目标是否值得上报。窗口内重复目标返回 false。
    pub fn should_report(&mut self, dst: IpAddr, dport: u16) -> bool {
        let now = Instant::now();
        if self.seen.len() >= MAX_TRACKED {
            self.seen.retain(|_, t| now.duration_since(*t) < SAMPLE_WINDOW);
        }
        match self.seen.get(&(dst, dport)) {
            Some(t) if now.duration_since(*t) < SAMPLE_WINDOW => false,
            _ => {
                self.seen.insert((dst, dport), now);
                true
            }
        }
    }
}

pub struct ConnInfo {
    pub pid: u32,
    pub guid: Option<Uuid>,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
}

/// 组装一条出站连接事件。conn_tuple 与 sensor 同一格式，
/// 横向移动关联（ConnTupleContains）对两路数据一视同仁。
pub fn conn_event(agent_id: &str, info: &ConnInfo) -> AgentEvent {
    let raw = serde_json::json!({
        "activity_id": 1, // OCSF: Open
        "connection_info": { "direction": "outbound", "protocol_name": "tcp" },
        "src_endpoint": { "ip": info.src.to_string(), "port": info.sport },
        "dst_endpoint": { "ip": info.dst.to_string(), "port": info.dport },
        "process": { "pid": info.pid, "uid": info.guid.map(|g| g.to_string()) },
    });
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: CLASS_NETWORK,
        process_guid: info.guid.map(|g| g.to_string()).unwrap_or_default(),
        parent_process_guid: String::new(),
        username: String::new(),
        conn_tuple: format!(
            "tcp:{}:{}>{}:{}",
            info.src, info.sport, info.dst, info.dport
        ),
        raw_json: raw.to_string(),
        dropped_events: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn sampler_dedups_within_window() {
        let mut s = ConnSampler::default();
        let dst: IpAddr = "10.0.0.9".parse().unwrap();
        assert!(s.should_report(dst, 443), "首次出现应上报");
        assert!(!s.should_report(dst, 443), "窗口内重复目标应压掉");
        assert!(s.should_report(dst, 8080), "不同端口是不同目标");
        assert!(s.should_report("10.0.0.10".parse().unwrap(), 443));
    }

    #[test]
    fn conn_event_fields() {
        let guid = Uuid::new_v4();
        let evt = conn_event(
            "agent-1",
            &ConnInfo {
                pid: 42,
                guid: Some(guid),
                src: "192.168.1.5".parse().unwrap(),
                sport: 51000,
                dst: "1.2.3.4".parse().unwrap(),
                dport: 443,
            },
        );
        assert_eq!(evt.class_uid, CLASS_NETWORK);
        assert_eq!(evt.conn_tuple, "tcp:192.168.1.5:51000>1.2.3.4:443");
        assert_eq!(evt.process_guid, guid.to_string());
        let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
        assert_eq!(v["dst_endpoint"]["ip"], "1.2.3.4");
        assert_eq!(v["dst_endpoint"]["port"], 443);
        assert_eq!(v["connection_info"]["direction"], "outbound");
        assert_eq!(v["process"]["uid"], guid.to_string());
    }

    #[test]
    fn conn_event_without_guid() {
        let evt = conn_event(
            "agent-1",
            &ConnInfo {
                pid: 7,
                guid: None,
                src: "::1".parse().unwrap(),
                sport: 1,
                dst: "2001:db8::1".parse().unwrap(),
                dport: 80,
            },
        );
        assert!(evt.process_guid.is_empty());
        let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
        assert!(v["process"]["uid"].is_null());
    }
}
