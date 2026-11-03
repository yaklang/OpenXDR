//! 网络连接采集的用户态侧：eBPF（TCP 出站 / 入站、UDP 出站）与 Windows ETW 事件的采样与组装。
//!
//! 补的是无 sensor 小部署的网络盲区。同一目标的高频连接在窗口内只报一次——
//! 网络事件的价值在"连了谁"，不在"连了多少次"，次数是流量探针的活。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use super::Container;
use crate::pb::AgentEvent;

/// OCSF Network Activity
const CLASS_NETWORK: u32 = 4001;

/// 同一 (对端地址, 端口) 的上报间隔
const SAMPLE_WINDOW: Duration = Duration::from_secs(60);

/// 采样表条目上限，超过即清理过期项，防止扫描行为撑爆内存
const MAX_TRACKED: usize = 4096;

#[derive(Default)]
pub struct ConnSampler {
    /// (对端地址, 端口, 进程)：按目标采样时进程位填 0
    seen: HashMap<(IpAddr, u16, u32), Instant>,
}

impl ConnSampler {
    /// 该目标是否值得上报。窗口内重复目标返回 false。
    pub fn should_report(&mut self, dst: IpAddr, dport: u16) -> bool {
        self.first((dst, dport, 0))
    }

    /// 同上，但每个进程各算各的：别的进程连过同一目标不压掉这一个
    #[cfg(target_os = "windows")]
    pub fn should_report_for(&mut self, dst: IpAddr, dport: u16, pid: u32) -> bool {
        self.first((dst, dport, pid))
    }

    fn first(&mut self, key: (IpAddr, u16, u32)) -> bool {
        let now = Instant::now();
        if self.seen.len() >= MAX_TRACKED {
            self.seen
                .retain(|_, t| now.duration_since(*t) < SAMPLE_WINDOW);
        }
        match self.seen.get(&key) {
            Some(t) if now.duration_since(*t) < SAMPLE_WINDOW => false,
            _ => {
                self.seen.insert(key, now);
                true
            }
        }
    }
}

pub struct ConnInfo {
    /// tcp / udp
    pub proto: &'static str,
    /// 入站：src 是对端，dst 是本机服务，进程是监听它的服务进程
    pub inbound: bool,
    pub pid: u32,
    pub guid: Option<Uuid>,
    /// 进程名与路径：长驻进程早于 agent 启动，server 回查不到它的启动事件，只能随连接带上
    pub name: Option<String>,
    pub exe: Option<String>,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
    pub container: Option<Arc<Container>>,
    /// 目的地址最近一次被解析时的域名（agent 自己看到的 DNS 应答），没见过就不写
    pub hostname: Option<String>,
    /// 发起连接的进程属于哪条平台指令
    pub command: Option<Arc<str>>,
}

/// 组装一条连接事件。conn_tuple 与 sensor 同一格式（发起方在前），
/// 横向移动关联（ConnTupleContains）对两路数据一视同仁。
///
/// 源地址未指定（0.0.0.0 / ::，未 connect 的 UDP 套接字且查不到出口地址）表示「不知道」，
/// 不是一台主机：不写 src_endpoint.ip，conn_tuple 的源地址留空（`udp::41641>1.2.3.4:41641`）
pub fn conn_event(agent_id: &str, info: &ConnInfo) -> AgentEvent {
    let direction = if info.inbound { "inbound" } else { "outbound" };
    let src = if info.src.is_unspecified() {
        String::new()
    } else {
        info.src.to_string()
    };
    let mut raw = serde_json::json!({
        "activity_id": 1, // OCSF: Open
        "connection_info": { "direction": direction, "protocol_name": info.proto },
        "src_endpoint": { "port": info.sport },
        "dst_endpoint": { "ip": info.dst.to_string(), "port": info.dport },
    });
    if !src.is_empty() {
        raw["src_endpoint"]["ip"] = src.as_str().into();
    }
    // 入站找不到服务进程时 pid 为 0：不写进程，不编一个出来
    if info.pid != 0 {
        raw["process"] =
            serde_json::json!({ "pid": info.pid, "uid": info.guid.map(|g| g.to_string()) });
    }
    if let Some(hostname) = &info.hostname {
        raw["dst_endpoint"]["hostname"] = hostname.as_str().into();
    }
    if let Some(c) = &info.container {
        raw["container"] = c.to_json();
    }
    if let Some(id) = &info.command {
        raw["platform_command"] = serde_json::json!({ "uid": id.as_ref() });
    }
    // 拿不到就不写，不编造
    if let Some(name) = info.name.as_deref().filter(|n| !n.is_empty()) {
        raw["process"]["name"] = name.into();
    }
    if let Some(exe) = &info.exe {
        raw["process"]["file"] = serde_json::json!({ "path": exe });
    }
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
            "{}:{}:{}>{}:{}",
            info.proto, src, info.sport, info.dst, info.dport
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
                proto: "tcp",
                inbound: false,
                pid: 42,
                guid: Some(guid),
                name: Some("curl".into()),
                exe: Some("/usr/bin/curl".into()),
                src: "192.168.1.5".parse().unwrap(),
                sport: 51000,
                dst: "1.2.3.4".parse().unwrap(),
                dport: 443,
                container: None,
                hostname: Some("github.com".into()),
                command: Some("01a1-cmd".into()),
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
        assert_eq!(v["process"]["name"], "curl");
        assert_eq!(v["process"]["file"]["path"], "/usr/bin/curl");
        assert_eq!(v["dst_endpoint"]["hostname"], "github.com");
        assert_eq!(v["platform_command"]["uid"], "01a1-cmd");
        assert!(v.get("container").is_none());
    }

    /// 入站与 UDP：方向、协议写进事件与 conn_tuple，容器原样带上
    #[test]
    fn conn_event_inbound_udp() {
        let evt = conn_event(
            "agent-1",
            &ConnInfo {
                proto: "udp",
                inbound: true,
                pid: 9,
                guid: None,
                name: Some("named".into()),
                exe: None,
                src: "10.0.0.7".parse().unwrap(),
                sport: 40000,
                dst: "10.0.0.2".parse().unwrap(),
                dport: 53,
                container: Some(Arc::new(Container {
                    runtime: "lxc",
                    uid: "203".into(),
                    name: Some("dns".into()),
                    healthcheck: false,
                })),
                hostname: None,
                command: None,
            },
        );
        assert_eq!(evt.conn_tuple, "udp:10.0.0.7:40000>10.0.0.2:53");
        let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
        assert_eq!(v["connection_info"]["direction"], "inbound");
        assert_eq!(v["connection_info"]["protocol_name"], "udp");
        assert_eq!(v["container"]["runtime"], "lxc");
        assert_eq!(v["container"]["uid"], "203");
        assert_eq!(v["container"]["name"], "dns");
        assert!(v["dst_endpoint"].get("hostname").is_none());

        let orphan = ConnInfo {
            pid: 0,
            name: None,
            container: None,
            ..info_inbound()
        };
        let v: Value = serde_json::from_str(&conn_event("agent-1", &orphan).raw_json).unwrap();
        assert!(v.get("process").is_none(), "找不到服务进程时不写 process");
    }

    /// 未指定的源地址不当真实地址报：省略 src_endpoint.ip，conn_tuple 源地址留空
    #[test]
    fn conn_event_unspecified_source() {
        for (src, dst, tuple) in [
            ("0.0.0.0", "110.42.47.158", "udp::41641>110.42.47.158:41641"),
            ("::", "2001:db8::9", "udp::41641>2001:db8::9:41641"),
        ] {
            let info = ConnInfo {
                proto: "udp",
                inbound: false,
                sport: 41641,
                dport: 41641,
                src: src.parse().unwrap(),
                dst: dst.parse().unwrap(),
                ..info_inbound()
            };
            let evt = conn_event("agent-1", &info);
            assert_eq!(evt.conn_tuple, tuple);
            let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
            assert!(v["src_endpoint"].get("ip").is_none(), "{src}");
            assert_eq!(v["src_endpoint"]["port"], 41641);
            assert_eq!(v["dst_endpoint"]["ip"], dst);
        }
    }

    fn info_inbound() -> ConnInfo {
        ConnInfo {
            proto: "tcp",
            inbound: true,
            pid: 1,
            guid: None,
            name: None,
            exe: None,
            src: "10.0.0.7".parse().unwrap(),
            sport: 40000,
            dst: "10.0.0.2".parse().unwrap(),
            dport: 5432,
            container: None,
            hostname: None,
            command: None,
        }
    }

    #[test]
    fn conn_event_without_guid() {
        let evt = conn_event(
            "agent-1",
            &ConnInfo {
                proto: "tcp",
                inbound: false,
                pid: 7,
                guid: None,
                name: None,
                exe: None,
                src: "::1".parse().unwrap(),
                sport: 1,
                dst: "2001:db8::1".parse().unwrap(),
                dport: 80,
                container: None,
                hostname: None,
                command: None,
            },
        );
        assert!(evt.process_guid.is_empty());
        let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
        assert!(v["process"]["uid"].is_null());
        assert!(v["process"].get("name").is_none() && v["process"].get("file").is_none());
    }
}
