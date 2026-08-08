//! 登录事件采集（Linux）：增量读 wtmp（成功登录）与 btmp（失败登录）。
//!
//! 账号是第二攻击面。syslog 转发只有部分环境配了，agent 直接读登录记录
//! 让认证可见性不依赖外部配置。从文件末尾开始增量读——存量历史不是事件。

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::pb::AgentEvent;

use super::EventSink;

/// OCSF Authentication
const CLASS_AUTH: u32 = 3002;

const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// glibc x86_64 的 utmp 记录布局
const RECORD_SIZE: usize = 384;
const USER_PROCESS: i16 = 7;

pub fn spawn(agent_id: String, sink: EventSink) {
    std::thread::spawn(move || run(&agent_id, &sink));
}

struct Tail {
    path: &'static str,
    /// true = 该文件记录的是失败登录（btmp）
    failure: bool,
    offset: u64,
}

fn run(agent_id: &str, sink: &EventSink) {
    let mut tails = [
        Tail {
            path: "/var/log/wtmp",
            failure: false,
            offset: 0,
        },
        Tail {
            path: "/var/log/btmp",
            failure: true,
            offset: 0,
        },
    ];
    // 从当前末尾开始：agent 启动前的历史不重放
    for t in &mut tails {
        t.offset = std::fs::metadata(t.path).map(|m| m.len()).unwrap_or(0);
    }

    loop {
        std::thread::sleep(POLL_INTERVAL);
        for t in &mut tails {
            for rec in read_new(t) {
                if !sink.send(auth_event(agent_id, &rec, t.failure)) {
                    return;
                }
            }
        }
    }
}

struct LoginRecord {
    user: String,
    host: String,
    line: String,
}

/// 读出自上次 offset 以来的新记录。文件轮转（变小）时从头开始。
fn read_new(t: &mut Tail) -> Vec<LoginRecord> {
    let Ok(mut f) = File::open(t.path) else {
        return Vec::new();
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len < t.offset {
        t.offset = 0; // logrotate 截断
    }
    if len == t.offset {
        return Vec::new();
    }
    if f.seek(SeekFrom::Start(t.offset)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity((len - t.offset) as usize);
    if f.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    // 只消费完整记录，残缺的尾部留给下一轮
    let whole = buf.len() - buf.len() % RECORD_SIZE;
    t.offset += whole as u64;

    buf[..whole]
        .chunks_exact(RECORD_SIZE)
        .filter_map(parse_record)
        .collect()
}

/// 解析一条 utmp 记录，非登录类型或空用户名返回 None。
fn parse_record(rec: &[u8]) -> Option<LoginRecord> {
    let ut_type = i16::from_le_bytes([rec[0], rec[1]]);
    if ut_type != USER_PROCESS {
        return None;
    }
    let user = cstr(&rec[44..76]);
    if user.is_empty() {
        return None;
    }
    Some(LoginRecord {
        user,
        host: cstr(&rec[76..332]),
        line: cstr(&rec[8..40]),
    })
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn auth_event(agent_id: &str, rec: &LoginRecord, failure: bool) -> AgentEvent {
    let raw = serde_json::json!({
        "activity_id": 1, // OCSF: Logon
        "status_id": if failure { 2 } else { 1 },
        "user": { "name": rec.user },
        "src_endpoint": { "ip": rec.host },
        "service": { "name": rec.line },
    });
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: CLASS_AUTH,
        process_guid: String::new(),
        parent_process_guid: String::new(),
        username: rec.user.clone(),
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
        dropped_events: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(ut_type: i16, user: &str, host: &str) -> Vec<u8> {
        let mut rec = vec![0u8; RECORD_SIZE];
        rec[..2].copy_from_slice(&ut_type.to_le_bytes());
        rec[8..8 + 5].copy_from_slice(b"pts/0");
        rec[44..44 + user.len()].copy_from_slice(user.as_bytes());
        rec[76..76 + host.len()].copy_from_slice(host.as_bytes());
        rec
    }

    #[test]
    fn parses_login_record() {
        let rec = record(USER_PROCESS, "root", "10.0.0.99");
        let parsed = parse_record(&rec).expect("应解析出登录记录");
        assert_eq!(parsed.user, "root");
        assert_eq!(parsed.host, "10.0.0.99");
        assert_eq!(parsed.line, "pts/0");
    }

    #[test]
    fn skips_non_login_records() {
        assert!(
            parse_record(&record(8, "root", "")).is_none(),
            "登出记录应跳过"
        );
        assert!(
            parse_record(&record(USER_PROCESS, "", "")).is_none(),
            "空用户应跳过"
        );
    }

    #[test]
    fn tail_reads_incrementally_and_handles_rotation() {
        let path = std::env::temp_dir().join("openxdr_wtmp_test");
        let path_s: &'static str = Box::leak(path.to_str().unwrap().to_string().into_boxed_str());

        std::fs::write(&path, record(USER_PROCESS, "alice", "h1")).unwrap();
        let mut t = Tail {
            path: path_s,
            failure: false,
            offset: 0,
        };

        let first = read_new(&mut t);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].user, "alice");
        assert!(read_new(&mut t).is_empty(), "无新数据不应重复读");

        // 追加一条
        let mut data = std::fs::read(&path).unwrap();
        data.extend(record(USER_PROCESS, "bob", "h2"));
        std::fs::write(&path, &data).unwrap();
        let second = read_new(&mut t);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].user, "bob");

        // 轮转：文件变小，从头读
        std::fs::write(&path, record(USER_PROCESS, "carol", "h3")).unwrap();
        let third = read_new(&mut t);
        assert_eq!(third.len(), 1);
        assert_eq!(third[0].user, "carol");

        let _ = std::fs::remove_file(&path);
    }
}
