//! 资产清单：本机监听端口（附属主进程）、云环境与操作系统显示名，供 server
//! 画资产地图与攻击面。
//!
//! 平台相关的只有"拿到监听套接字表"这一步（Linux /proc/net/*，Windows
//! IP Helper），其余——条目模型、去重排序截断、变化判定、事件组装——都在
//! 本模块，Linux CI 上就能测到。
//!
//! 产出 OCSF Device Inventory Info（class_uid=5001），activity_id=2。
//! 启动时探测一次云环境与系统显示名（进程内缓存）并报一次全量；之后每 60s
//! 轮询，监听集合（协议、地址、端口、进程名）有变化才报，另外最长 6 小时
//! 无条件补报一次，server 侧视图漏了也能自愈。

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use crate::pb::AgentEvent;

use super::EventSink;
use super::cloud::{self, Cloud};
use super::osinfo;

/// OCSF Device Inventory Info
const CLASS_DEVICE_INVENTORY: u32 = 5001;

/// OCSF 活动类型：Collect
const ACTIVITY_COLLECT: u32 = 2;

/// 监听表轮询间隔
const POLL_INTERVAL: Duration = Duration::from_secs(60);

/// 无变化时的最长补报间隔
const HEARTBEAT: Duration = Duration::from_secs(6 * 3600);

/// 单条事件最多带多少个监听条目，防异常主机（端口扫描器、海量 UDP）撑爆事件
const MAX_LISTENERS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// 监听套接字的属主进程。name 拿不到就不构造 Owner——宁缺毋滥
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub proto: Proto,
    pub addr: IpAddr,
    pub port: u16,
    pub owner: Option<Owner>,
}

/// 变化判定的指纹：协议、地址、端口、进程名
type Fingerprint = Vec<(Proto, IpAddr, u16, Option<String>)>;

/// 启动清单线程。云探测与 /proc、IP Helper 读取都是阻塞 I/O，放独立线程。
/// scan 由平台模块提供，返回当前监听表（无需排序去重）。
pub fn spawn<F>(agent_id: String, sink: EventSink, scan: F)
where
    F: FnMut() -> std::io::Result<Vec<Listener>> + Send + 'static,
{
    std::thread::spawn(move || run(&agent_id, &sink, scan));
}

fn run(agent_id: &str, sink: &EventSink, mut scan: impl FnMut() -> std::io::Result<Vec<Listener>>) {
    // 断线重连会重新拉起采集，云环境探测与系统识别都按进程只做一次
    static CLOUD: OnceLock<Option<Cloud>> = OnceLock::new();
    let cloud = CLOUD.get_or_init(cloud::detect).as_ref();
    static OS: OnceLock<Option<String>> = OnceLock::new();
    let os = OS.get_or_init(osinfo::display);

    let mut last: Option<(Fingerprint, Instant)> = None;
    #[cfg(target_os = "linux")]
    let mut last_accounts = None;
    #[cfg(target_os = "linux")]
    let mut last_hosted = None;
    while !sink.is_closed() {
        let listeners = match scan() {
            Ok(listeners) => {
                sink.capability(
                    "inventory",
                    if cfg!(windows) {
                        "ip-helper"
                    } else {
                        "proc-net"
                    },
                    "active",
                );
                normalize(listeners)
            }
            Err(_) => {
                sink.capability(
                    "inventory",
                    if cfg!(windows) {
                        "ip-helper"
                    } else {
                        "proc-net"
                    },
                    "unavailable",
                );
                std::thread::sleep(POLL_INTERVAL);
                continue;
            }
        };
        let fp = fingerprint(&listeners);
        let due = match &last {
            Some((prev, at)) => *prev != fp || at.elapsed() >= HEARTBEAT,
            None => true,
        };
        #[cfg(target_os = "linux")]
        let (accounts, due) = {
            let value = super::local_accounts::snapshot().ok();
            sink.capability(
                "local-accounts",
                "etc-passwd",
                if value.is_some() {
                    "active"
                } else {
                    "unavailable"
                },
            );
            let changed = due || value != last_accounts;
            (value, changed)
        };
        // 本机容器的地址：容器起停、换网络时随清单重报
        #[cfg(target_os = "linux")]
        let (hosted, due) = {
            let hosted = super::hosted::snapshot();
            let changed = due || last_hosted.as_ref() != Some(&hosted);
            (hosted, changed)
        };
        if due {
            let event = inventory_event(agent_id, &listeners, cloud, os.as_deref(), package_of);
            #[cfg(target_os = "linux")]
            let event = with_local_accounts(event, accounts.as_deref());
            #[cfg(target_os = "linux")]
            let event = with_hosted(event, &hosted);
            if !sink.send(event) {
                return;
            }
            #[cfg(target_os = "linux")]
            {
                last_accounts = accounts;
                last_hosted = Some(hosted);
            }
            last = Some((fp, Instant::now()));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn with_local_accounts(
    mut event: AgentEvent,
    accounts: Option<&[super::local_accounts::Account]>,
) -> AgentEvent {
    // 输入是本模块刚生成的 JSON，不包含外部文本；失败时保留原始清单事件。
    if let Ok(mut raw) = serde_json::from_str::<Value>(&event.raw_json) {
        raw["device"]["local_accounts"] = match accounts {
            Some(items) => {
                json!({"version": 1, "source": "etc-passwd", "state": "observed", "items": items})
            }
            None => json!({"version": 1, "source": "etc-passwd", "state": "unavailable"}),
        };
        event.raw_json = raw.to_string();
    }
    event
}

#[cfg(target_os = "linux")]
fn with_hosted(mut event: AgentEvent, hosted: &[super::hosted::Hosted]) -> AgentEvent {
    if let Ok(mut raw) = serde_json::from_str::<Value>(&event.raw_json) {
        raw["device"]["containers"] = super::hosted::to_json(hosted);
        event.raw_json = raw.to_string();
    }
    event
}

/// 去重（按协议+地址+端口，优先保留认出属主的那条）、排序（协议、端口、地址）、截断。
/// 端口 0 不是监听，丢掉。
pub fn normalize(list: Vec<Listener>) -> Vec<Listener> {
    let mut map: BTreeMap<(Proto, u16, IpAddr), Listener> = BTreeMap::new();
    for l in list.into_iter().filter(|l| l.port != 0) {
        let slot = map.entry((l.proto, l.port, l.addr)).or_insert(l.clone());
        if slot.owner.is_none() {
            slot.owner = l.owner;
        }
    }
    map.into_values().take(MAX_LISTENERS).collect()
}

fn fingerprint(list: &[Listener]) -> Fingerprint {
    list.iter()
        .map(|l| {
            (
                l.proto,
                l.addr,
                l.port,
                l.owner.as_ref().map(|o| o.name.clone()),
            )
        })
        .collect()
}

/// 服务进程所属的包：Linux 查 dpkg，其余平台没有
#[cfg(target_os = "linux")]
fn package_of(path: &str) -> Option<String> {
    super::software::package_of(path)
}
#[cfg(not(target_os = "linux"))]
fn package_of(_: &str) -> Option<String> {
    None
}

fn listener_json(l: &Listener, package: fn(&str) -> Option<String>) -> Value {
    let mut v = json!({
        "proto": l.proto.as_str(),
        "addr": l.addr.to_string(),
        "port": l.port,
    });
    if let Some(o) = &l.owner {
        let mut p = json!({ "pid": o.pid, "name": o.name });
        if let Some(path) = &o.path {
            p["file"] = json!({ "path": path });
            // 服务进程属于哪个包：攻击面据此回答「暴露的服务有没有已知漏洞」
            if let Some(pkg) = package(path) {
                p["file"]["package"] = pkg.into();
            }
        }
        v["process"] = p;
    }
    v
}

fn cloud_json(c: &Cloud) -> Value {
    let mut m = Map::new();
    m.insert("provider".into(), c.provider.into());
    m.insert("instance_id".into(), c.instance_id.clone().into());
    if let Some(r) = &c.region {
        m.insert("region".into(), r.clone().into());
    }
    if let Some(ip) = c.public_ip {
        m.insert("public_ip".into(), ip.to_string().into());
    }
    Value::Object(m)
}

fn inventory_event(
    agent_id: &str,
    listeners: &[Listener],
    cloud: Option<&Cloud>,
    os: Option<&str>,
    package: fn(&str) -> Option<String>,
) -> AgentEvent {
    let mut device = json!({ "listening": listeners.iter().map(|l| listener_json(l, package)).collect::<Vec<_>>() });
    if let Some(c) = cloud {
        device["cloud"] = cloud_json(c);
    }
    // 系统显示名（发行版+版本）：注册只报 family，这里才是带版本的实测值。
    // 拿不到就不带这个键，server 侧保留导入时声明的值
    if let Some(os) = os {
        device["os"] = json!(os);
    }
    let raw = json!({ "activity_id": ACTIVITY_COLLECT, "device": device });
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: CLASS_DEVICE_INVENTORY,
        process_guid: String::new(),
        parent_process_guid: String::new(),
        username: String::new(),
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
        dropped_events: 0, // 由 EventSink 在发送时填当前累计值
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn account_inventory_distinguishes_empty_from_unavailable() {
        let empty = with_local_accounts(inventory_event("a", &[], None, None, |_| None), Some(&[]));
        let value: Value = serde_json::from_str(&empty.raw_json).unwrap();
        assert_eq!(value["device"]["local_accounts"]["items"], json!([]));
        assert_eq!(value["device"]["local_accounts"]["state"], "observed");
        assert_eq!(value["device"]["listening"], json!([]));
        let missing = with_local_accounts(inventory_event("a", &[], None, None, |_| None), None);
        let value: Value = serde_json::from_str(&missing.raw_json).unwrap();
        assert_eq!(value["device"]["local_accounts"]["state"], "unavailable");
        assert!(value["device"]["local_accounts"].get("items").is_none());
    }

    fn l(proto: Proto, addr: &str, port: u16, owner: Option<&str>) -> Listener {
        Listener {
            proto,
            addr: addr.parse().unwrap(),
            port,
            owner: owner.map(|n| Owner {
                pid: 1,
                name: n.to_string(),
                path: None,
            }),
        }
    }

    #[test]
    fn normalize_dedups_sorts_and_caps() {
        let out = normalize(vec![
            l(Proto::Udp, "::", 53, None),
            l(Proto::Tcp, "0.0.0.0", 443, None),
            l(Proto::Tcp, "0.0.0.0", 443, Some("nginx")),
            l(Proto::Tcp, "::", 22, Some("sshd")),
            l(Proto::Tcp, "0.0.0.0", 22, Some("sshd")),
            l(Proto::Tcp, "0.0.0.0", 0, None),
        ]);
        let keys: Vec<_> = out
            .iter()
            .map(|x| (x.proto, x.addr.to_string(), x.port))
            .collect();
        assert_eq!(
            keys,
            [
                (Proto::Tcp, "0.0.0.0".to_string(), 22),
                (Proto::Tcp, "::".to_string(), 22),
                (Proto::Tcp, "0.0.0.0".to_string(), 443),
                (Proto::Udp, "::".to_string(), 53),
            ]
        );
        assert_eq!(
            out[2].owner.as_ref().unwrap().name,
            "nginx",
            "重复条目优先保留认出属主的"
        );

        let many = (1..=600)
            .map(|p| l(Proto::Tcp, "0.0.0.0", p, None))
            .collect();
        assert_eq!(normalize(many).len(), MAX_LISTENERS);
    }

    #[test]
    fn fingerprint_tracks_process_name() {
        let a = normalize(vec![l(Proto::Tcp, "0.0.0.0", 80, Some("nginx"))]);
        let b = normalize(vec![l(Proto::Tcp, "0.0.0.0", 80, Some("httpd"))]);
        assert_ne!(fingerprint(&a), fingerprint(&b));
        assert_eq!(fingerprint(&a), fingerprint(&a.clone()));
    }

    #[test]
    fn event_shape_matches_contract() {
        let listeners = vec![
            Listener {
                proto: Proto::Tcp,
                addr: "0.0.0.0".parse().unwrap(),
                port: 22,
                owner: Some(Owner {
                    pid: 812,
                    name: "sshd".into(),
                    path: Some("/usr/sbin/sshd".into()),
                }),
            },
            Listener {
                proto: Proto::Tcp,
                addr: "::1".parse().unwrap(),
                port: 25,
                owner: Some(Owner {
                    pid: 9,
                    name: "master".into(),
                    path: None,
                }),
            },
            l(Proto::Udp, "::", 53, None),
        ];
        let cloud = Cloud {
            provider: "aliyun",
            instance_id: "i-xxx".into(),
            region: Some("cn-hangzhou".into()),
            public_ip: Some("47.1.2.3".parse().unwrap()),
        };
        let evt = inventory_event("agent-1", &listeners, Some(&cloud), None, |_| None);
        assert_eq!(evt.class_uid, 5001);
        assert!(evt.process_guid.is_empty() && evt.conn_tuple.is_empty());
        let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
        assert_eq!(
            v,
            json!({
                "activity_id": 2,
                "device": {
                    "listening": [
                        {"proto": "tcp", "addr": "0.0.0.0", "port": 22,
                         "process": {"pid": 812, "name": "sshd", "file": {"path": "/usr/sbin/sshd"}}},
                        {"proto": "tcp", "addr": "::1", "port": 25,
                         "process": {"pid": 9, "name": "master"}},
                        {"proto": "udp", "addr": "::", "port": 53},
                    ],
                    "cloud": {"provider": "aliyun", "instance_id": "i-xxx",
                              "region": "cn-hangzhou", "public_ip": "47.1.2.3"},
                }
            })
        );

        let bare = Cloud {
            provider: "aws",
            instance_id: "i-0123456789abcdef0".into(),
            region: None,
            public_ip: None,
        };
        let v: Value =
            serde_json::from_str(&inventory_event("a", &[], Some(&bare), None, |_| None).raw_json)
                .unwrap();
        assert_eq!(
            v["device"]["cloud"],
            json!({"provider": "aws", "instance_id": "i-0123456789abcdef0"})
        );
        let v: Value =
            serde_json::from_str(&inventory_event("a", &[], None, None, |_| None).raw_json)
                .unwrap();
        assert!(v["device"].get("cloud").is_none(), "非云主机不带 cloud 键");
        assert!(v["device"].get("os").is_none(), "识别不到系统时不带 os 键");
        assert_eq!(v["device"]["listening"], json!([]));
    }

    #[test]
    fn event_carries_os_display() {
        let v: Value = serde_json::from_str(
            &inventory_event("a", &[], None, Some("Ubuntu 24.04.1 LTS"), |_| None).raw_json,
        )
        .unwrap();
        assert_eq!(v["device"]["os"], json!("Ubuntu 24.04.1 LTS"));
        assert!(v["device"].get("cloud").is_none());
    }

    #[test]
    fn listener_carries_owner_package() {
        let listeners = vec![l(Proto::Tcp, "0.0.0.0", 22, Some("sshd"))];
        let mut with_path = listeners.clone();
        with_path[0].owner.as_mut().unwrap().path = Some("/usr/sbin/sshd".into());
        let evt = inventory_event("a", &with_path, None, None, |p| {
            (p == "/usr/sbin/sshd").then(|| "openssh-server".into())
        });
        let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
        assert_eq!(
            v["device"]["listening"][0]["process"]["file"]["package"],
            "openssh-server"
        );
        let none = inventory_event("a", &listeners, None, None, |_| Some("x".into()));
        let v: Value = serde_json::from_str(&none.raw_json).unwrap();
        assert!(
            v["device"]["listening"][0]["process"].get("file").is_none(),
            "没有路径就不查包"
        );
    }
}
