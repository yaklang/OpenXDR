//! Windows DNS 采集：订阅 Microsoft-Windows-DNS-Client provider，取事件 3008（查询完成），
//! 组装成与 Linux AF_PACKET 路径同构的 DNS 活动事件（OCSF 4003）。
//!
//! 实机勘定（Win10 22H2，logman 打全事件对拍 Resolve-DnsName / ping / .NET 解析）：
//! - 3008 由发起解析的进程自己的 dnsapi 记录，事件头的 PID 就是发起进程——不用像 Linux 那样按源端口猜；
//!   3006（发起）同在调用方进程但没有结果；3020（网络应答）在 Dnscache 服务进程里，归属不到调用方。
//! - 字段：QueryName / QueryType / QueryOptions / QueryStatus / QueryResults。结果是
//!   `type:  5 www.a.shifen.com;183.2.172.177;` 这样的分号串：CNAME 带 `type:  5` 前缀，地址直接写，
//!   getaddrinfo 的双栈查询会把 IPv4 结果写成 `::ffff:a.b.c.d`。没有 TTL，也没有 DNS 服务器地址与源端口。
//! - getaddrinfo 会并行发 A 与 AAAA，其中一路以状态 87 / 1223 收场，那是 API 内部的取消，不是查询结果；
//!   QueryOptions 带 DNS_QUERY_NO_WIRE_QUERY（0x10）的是只查缓存的试探，也不是一次解析。两类都不报；
//!   localhost 由系统内置解析、不出本机（实机上 WMI 查询每次都解析一遍），也不报。
//!
//! 与 Linux 的差别：看到的是 API 层的解析（含缓存命中），不是线上报文——绕过系统解析器、自己发 UDP 53 的
//! 程序（nslookup、隧道工具）这里看不到，由网络采集的 UDP 出站事件兜住。拿不到的服务器地址与端口不编，
//! 事件里不写 src_endpoint / dst_endpoint，conn_tuple 留空。
//!
//! 独立 trace session，失败只降级警告，不影响进程与网络采集。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use uuid::Uuid;

use super::{EventSink, ProcessRegistry, dnsnames};
use crate::pb::AgentEvent;

// ETW 会话用固定名字：agent 被强杀或升级退出时会话不随进程消失，启动时先停掉同名旧会话；
// 用随机名每次重启都漏一个，系统总共 64 个会话名额迟早占满，之后采集就起不来
const SESSION: &str = "OpenXDR-DNS";

const DNS_CLIENT_GUID: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
const EVENT_QUERY_COMPLETED: u16 = 3008;

/// OCSF DNS Activity
const CLASS_DNS: u32 = 4003;

/// 同一进程对同一域名、同一类型的查询 60 秒内只报一次（与 Linux 的 REPORT_WINDOW 一致）
const REPORT_WINDOW: Duration = Duration::from_secs(60);
const MAX_TRACKED: usize = 8192;
/// 结果里没有 TTL：应答地址按 5 分钟记住，供出站连接回填域名
const ANSWER_TTL: Duration = Duration::from_secs(300);
/// 应答地址最多记几个，与 Linux 一致
const MAX_ANSWERS: usize = 8;

/// DNS_QUERY_NO_WIRE_QUERY：只查本机缓存
const NO_WIRE_QUERY: u64 = 0x10;
/// ERROR_INVALID_PARAMETER / ERROR_CANCELLED：getaddrinfo 并行查询里被取消的那一路
const STATUS_ARTIFACTS: [u32; 2] = [87, 1223];

pub fn spawn(agent_id: String, sink: EventSink, registry: Arc<Mutex<ProcessRegistry>>) {
    std::thread::spawn(move || run(agent_id, sink, registry));
}

fn run(agent_id: String, sink: EventSink, registry: Arc<Mutex<ProcessRegistry>>) {
    let health_sink = sink.clone();
    let reported: Mutex<HashMap<(u32, String, u32), Instant>> = Mutex::default();
    let provider = Provider::by_guid(DNS_CLIENT_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if record.event_id() != EVENT_QUERY_COMPLETED {
                return;
            }
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let (Ok(name), Ok(qtype), Ok(options), Ok(status)) = (
                parser.try_parse::<String>("QueryName"),
                parser.try_parse::<u32>("QueryType"),
                parser.try_parse::<u64>("QueryOptions"),
                parser.try_parse::<u32>("QueryStatus"),
            ) else {
                return;
            };
            let results: String = parser.try_parse("QueryResults").unwrap_or_default();
            let Some(query) = Query::new(&name, qtype, options, status, &results) else {
                return;
            };
            let pid = record.process_id();
            if !first_in_window(&reported, pid, &query) {
                return;
            }
            for answer in &query.answers {
                if let Answer::Ip(ip) = answer {
                    dnsnames::remember(&query.name, *ip, ANSWER_TTL);
                }
            }
            // 查询归到被折叠的进程上：压着的启动事件（连同被折叠的祖先）先补发
            let (origin, revealed) = {
                let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
                reg.reveal(pid);
                let origin = match reg.known(pid) {
                    Some(k) => Origin {
                        pid,
                        guid: Some(k.guid),
                        name: Some(k.name).filter(|n| !n.is_empty()),
                        exe: k.exe,
                        command: k.command,
                    },
                    None => Origin {
                        pid,
                        guid: Some(reg.placeholder(pid)),
                        name: None,
                        exe: None,
                        command: None,
                    },
                };
                (origin, reg.take_outbox())
            };
            for event in revealed {
                sink.send(event);
            }
            sink.send(dns_event(&agent_id, &query, &origin));
        })
        .build();

    match super::etw_session::user_trace(SESSION, provider) {
        Ok(_trace) => {
            health_sink.capability("dns", "etw-dns-client", "active");
            eprintln!("DNS 采集: ETW DNS-Client（查询完成事件，按发起进程归属）");
            // trace 句柄保活；agent 退出即进程结束，无需额外清理
            while !health_sink.is_closed() {
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        Err(e) => {
            health_sink.capability("dns", "etw-dns-client", "unavailable");
            eprintln!("DNS 采集不可用（{e:?}），进程与网络采集不受影响");
        }
    }
}

fn first_in_window(
    reported: &Mutex<HashMap<(u32, String, u32), Instant>>,
    pid: u32,
    query: &Query,
) -> bool {
    let now = Instant::now();
    let mut reported = reported.lock().unwrap_or_else(|e| e.into_inner());
    let key = (pid, query.name.clone(), query.qtype);
    if reported
        .get(&key)
        .is_some_and(|t| now.duration_since(*t) < REPORT_WINDOW)
    {
        return false;
    }
    if reported.len() >= MAX_TRACKED {
        reported.retain(|_, t| now.duration_since(*t) < REPORT_WINDOW);
        if reported.len() >= MAX_TRACKED {
            reported.clear();
        }
    }
    reported.insert(key, now);
    true
}

#[derive(Debug, PartialEq)]
enum Answer {
    Ip(IpAddr),
    /// 非地址记录：类型号与内容（CNAME 的目标名、NXDOMAIN 带回的 SOA 主服务器名）
    Record(u16, String),
}

#[derive(Debug)]
struct Query {
    name: String,
    qtype: u32,
    /// None 表示没等到应答（超时、网络不通之类）
    rcode: Option<u8>,
    answers: Vec<Answer>,
}

impl Query {
    /// 不是一次真实解析的（缓存试探、并行查询里被取消的一路、IP 字面量、系统内置解析的 localhost）返回 None
    fn new(name: &str, qtype: u32, options: u64, status: u32, results: &str) -> Option<Self> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty()
            || options & NO_WIRE_QUERY != 0
            || STATUS_ARTIFACTS.contains(&status)
            || name.parse::<IpAddr>().is_ok()
            || name == "localhost"
            || name.ends_with(".localhost")
        {
            return None;
        }
        // DNS_ERROR_RCODE_*：9001 起依次是 FORMERR / SERVFAIL / NXDOMAIN / NOTIMP / REFUSED；
        // 9501 DNS_INFO_NO_RECORDS 与 9701 DNS_ERROR_RECORD_DOES_NOT_EXIST 是有应答、无此类记录
        let rcode = match status {
            0 | 9501 | 9701 => Some(0),
            9001..=9005 => Some((status - 9000) as u8),
            _ => None,
        };
        let answers = if rcode.is_some() {
            parse_results(results)
        } else {
            Vec::new()
        };
        Some(Query {
            name,
            qtype,
            rcode,
            answers,
        })
    }
}

/// `type:  5 www.a.shifen.com;183.2.172.177;::ffff:1.2.3.4;` → 应答列表。认不出的段跳过
fn parse_results(results: &str) -> Vec<Answer> {
    results
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|item| match item.strip_prefix("type:") {
            Some(rest) => {
                let (rtype, data) = rest.trim_start().split_once(' ')?;
                let data = data.trim().trim_end_matches('.').to_ascii_lowercase();
                (!data.is_empty()).then_some(Answer::Record(rtype.parse().ok()?, data))
            }
            None => item
                .parse::<IpAddr>()
                .ok()
                .map(|ip| Answer::Ip(ip.to_canonical())),
        })
        .take(MAX_ANSWERS)
        .collect()
}

struct Origin {
    pid: u32,
    guid: Option<Uuid>,
    name: Option<String>,
    exe: Option<String>,
    command: Option<Arc<str>>,
}

/// 字段与 Linux dnswatch 同一约定（query.hostname / query.type / query.rcode_id、answers[].ip / rdata），
/// 规则与情报对两路一视同仁
fn dns_event(agent_id: &str, query: &Query, origin: &Origin) -> AgentEvent {
    let qtype = u16::try_from(query.qtype).unwrap_or(0);
    let mut raw = serde_json::json!({
        // OCSF：1 Query（没等到应答）/ 6 Traffic（一问一答）
        "activity_id": if query.rcode.is_some() { 6 } else { 1 },
        "query": { "hostname": query.name, "type": dnsnames::qtype_name(qtype) },
        "process": { "pid": origin.pid, "uid": origin.guid.map(|g| g.to_string()) },
    });
    if let Some(rcode) = query.rcode {
        raw["query"]["rcode_id"] = rcode.into();
        raw["answers"] = query
            .answers
            .iter()
            .map(|a| match a {
                Answer::Ip(ip) => serde_json::json!({
                    "type": if ip.is_ipv4() { "A" } else { "AAAA" },
                    "ip": ip.to_string(),
                }),
                Answer::Record(t, data) => {
                    serde_json::json!({ "type": dnsnames::qtype_name(*t), "rdata": data })
                }
            })
            .collect();
    }
    if let Some(name) = &origin.name {
        raw["process"]["name"] = name.as_str().into();
    }
    if let Some(exe) = &origin.exe {
        raw["process"]["file"] = serde_json::json!({ "path": exe });
    }
    if let Some(id) = &origin.command {
        raw["platform_command"] = serde_json::json!({ "uid": id.as_ref() });
    }
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: CLASS_DNS,
        process_guid: origin.guid.map(|g| g.to_string()).unwrap_or_default(),
        parent_process_guid: String::new(),
        username: String::new(),
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
        dropped_events: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// 实机抓到的结果串：CNAME 前缀、IPv4 映射地址还原、NXDOMAIN 带回的 SOA
    #[test]
    fn parses_results() {
        let answers = parse_results(
            "type:  5 www.taobao.com.danuoyi.tbcache.com;::ffff:222.211.12.106;240e:97c:2f:201d::12d;",
        );
        assert_eq!(
            answers,
            vec![
                Answer::Record(5, "www.taobao.com.danuoyi.tbcache.com".into()),
                Answer::Ip("222.211.12.106".parse().unwrap()),
                Answer::Ip("240e:97c:2f:201d::12d".parse().unwrap()),
            ]
        );
        assert_eq!(
            parse_results("type:  6 dns.baidu.com;"),
            vec![Answer::Record(6, "dns.baidu.com".into())]
        );
        assert!(parse_results("").is_empty());
        assert!(parse_results("garbage;type: x y;").is_empty());
    }

    /// 缓存试探、被取消的并行查询、IP 字面量不算一次解析；状态码映射成 rcode，没应答的不带 answers
    #[test]
    fn filters_and_maps_status() {
        assert!(
            Query::new("example.com", 1, 0x8010, 9701, "").is_none(),
            "只查缓存"
        );
        assert!(Query::new("www.163.com", 1, 1073766400, 87, "").is_none());
        assert!(Query::new("www.163.com", 1, 0, 1223, "").is_none());
        assert!(Query::new("10.0.0.1", 1, 0, 0, "10.0.0.1;").is_none());
        assert!(Query::new("localhost", 1, 0, 0, "127.0.0.1;").is_none());

        let ok = Query::new("WWW.Baidu.com.", 1, 196616, 0, "183.2.172.177;").unwrap();
        assert_eq!(ok.name, "www.baidu.com");
        assert_eq!(ok.rcode, Some(0));
        assert_eq!(ok.answers.len(), 1);
        let nx = Query::new("nope.baidu.com", 28, 0, 9003, "type:  6 dns.baidu.com;").unwrap();
        assert_eq!(nx.rcode, Some(3));
        let timeout = Query::new("slow.example", 1, 0, 1460, "").unwrap();
        assert_eq!(timeout.rcode, None);
    }

    /// 事件形状与 Linux 同构：query / answers / process；拿不到的服务器地址与端口不写
    #[test]
    fn event_shape() {
        let guid = Uuid::new_v4();
        let query = Query::new(
            "www.baidu.com",
            1,
            0,
            0,
            "type:  5 www.a.shifen.com;183.2.172.177;",
        )
        .unwrap();
        let origin = Origin {
            pid: 3868,
            guid: Some(guid),
            name: Some("powershell.exe".into()),
            exe: Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into()),
            command: None,
        };
        let evt = dns_event("a", &query, &origin);
        assert_eq!(evt.class_uid, CLASS_DNS);
        assert_eq!(evt.process_guid, guid.to_string());
        assert!(evt.conn_tuple.is_empty());
        let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
        assert_eq!(v["activity_id"], 6);
        assert_eq!(v["query"]["hostname"], "www.baidu.com");
        assert_eq!(v["query"]["type"], "A");
        assert_eq!(v["query"]["rcode_id"], 0);
        assert_eq!(v["answers"][0]["type"], "CNAME");
        assert_eq!(v["answers"][0]["rdata"], "www.a.shifen.com");
        assert_eq!(v["answers"][1]["type"], "A");
        assert_eq!(v["answers"][1]["ip"], "183.2.172.177");
        assert_eq!(v["process"]["pid"], 3868);
        assert_eq!(v["process"]["name"], "powershell.exe");
        assert!(v.get("src_endpoint").is_none() && v.get("dst_endpoint").is_none());

        let timeout = Query::new("slow.example", 1, 0, 1460, "").unwrap();
        let v: Value = serde_json::from_str(&dns_event("a", &timeout, &origin).raw_json).unwrap();
        assert_eq!(v["activity_id"], 1);
        assert!(v.get("answers").is_none() && v["query"].get("rcode_id").is_none());
    }

    #[test]
    fn dedups_per_process_name_and_type() {
        let reported = Mutex::default();
        let q = Query::new("example.com", 1, 0, 0, "").unwrap();
        assert!(first_in_window(&reported, 1, &q));
        assert!(!first_in_window(&reported, 1, &q), "窗口内重复压掉");
        assert!(first_in_window(&reported, 2, &q), "不同进程各报一次");
        let aaaa = Query::new("example.com", 28, 0, 0, "").unwrap();
        assert!(first_in_window(&reported, 1, &aaaa), "不同类型各报一次");
    }

    #[test]
    fn reported_table_stays_bounded_under_dns_storm() {
        let reported = Mutex::default();
        let q = Query::new("storm.example", 1, 0, 0, "").unwrap();
        for pid in 1..=(MAX_TRACKED * 2 + 100) as u32 {
            assert!(first_in_window(&reported, pid, &q));
            assert!(reported.lock().unwrap().len() <= MAX_TRACKED);
        }
    }
}
