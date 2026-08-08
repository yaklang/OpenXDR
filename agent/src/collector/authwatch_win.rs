//! 登录事件采集（Windows）：订阅 Security 日志的 4624（成功）/ 4625（失败）。
//!
//! Security-Auditing 的 ETW provider 是受保护通道，用户态订阅不到，
//! Event Log API 拉取是唯一正路。只订阅未来事件——存量历史不是事件。
//! 需要管理员或 Event Log Readers 权限，权限不够只降级警告，不影响其他采集。

use std::time::{SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, GetLastError};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtRender, EvtRenderEventXml, EvtSubscribe, EvtSubscribeToFutureEvents,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, ResetEvent, WaitForSingleObject,
};

use super::EventSink;
use crate::pb::AgentEvent;

/// OCSF Authentication
const CLASS_AUTH: u32 = 3002;

pub fn spawn(agent_id: String, sink: EventSink) {
    std::thread::spawn(move || run(&agent_id, &sink));
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn run(agent_id: &str, sink: &EventSink) {
    // 手动复位的信号：EvtNext 读空后复位，日志服务有新事件时置位
    let signal = unsafe { CreateEventW(std::ptr::null(), 1, 1, std::ptr::null()) };
    if signal.is_null() {
        return;
    }
    let channel = wide("Security");
    let query = wide("*[System[(EventID=4624) or (EventID=4625)]]");
    let sub = unsafe {
        EvtSubscribe(
            0,
            signal,
            channel.as_ptr(),
            query.as_ptr(),
            0,
            std::ptr::null(),
            None,
            EvtSubscribeToFutureEvents,
        )
    };
    if sub == 0 {
        eprintln!(
            "登录监控不可用（EvtSubscribe 错误码 {}），需要管理员权限",
            unsafe { GetLastError() }
        );
        return;
    }
    eprintln!("登录监控: Security 日志 4624/4625");

    loop {
        unsafe { WaitForSingleObject(signal, INFINITE) };
        loop {
            let mut handles = [0isize; 16];
            let mut got = 0u32;
            if unsafe { EvtNext(sub, 16, handles.as_mut_ptr(), INFINITE, 0, &mut got) } == 0 {
                if unsafe { GetLastError() } == ERROR_NO_MORE_ITEMS {
                    unsafe { ResetEvent(signal) };
                }
                break;
            }
            for &h in &handles[..got as usize] {
                let rec = render_xml(h).as_deref().and_then(parse_security_xml);
                unsafe { EvtClose(h) };
                if let Some(rec) = rec
                    && !sink.send(auth_event(agent_id, &rec))
                {
                    unsafe { EvtClose(sub) };
                    return;
                }
            }
        }
    }
}

/// 把事件句柄渲染成 XML 文本。第一次调用探大小，第二次真渲染。
fn render_xml(event: isize) -> Option<String> {
    let mut used = 0u32;
    let mut props = 0u32;
    unsafe {
        EvtRender(
            0,
            event,
            EvtRenderEventXml,
            0,
            std::ptr::null_mut(),
            &mut used,
            &mut props,
        )
    };
    if used == 0 {
        return None;
    }
    // used 是字节数，缓冲区按 u16 分配
    let mut buf = vec![0u16; used.div_ceil(2) as usize];
    if unsafe {
        EvtRender(
            0,
            event,
            EvtRenderEventXml,
            used,
            buf.as_mut_ptr().cast(),
            &mut used,
            &mut props,
        )
    } == 0
    {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..end]))
}

struct LoginRecord {
    user: String,
    ip: String,
    logon_type: String,
    failure: bool,
}

/// 取 <Data Name='X'>value</Data> 的值。wevtapi 渲染用单引号属性。
fn xml_data<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let tag = format!("Name='{name}'>");
    let rest = &xml[xml.find(&tag)? + tag.len()..];
    Some(&rest[..rest.find("</Data>")?])
}

/// 解析 4624/4625，滤掉机器账号与服务会话——人的登录才是信号。
fn parse_security_xml(xml: &str) -> Option<LoginRecord> {
    let failure = if xml.contains("<EventID>4625</EventID>") {
        true
    } else if xml.contains("<EventID>4624</EventID>") {
        false
    } else {
        return None;
    };
    let user = xml_data(xml, "TargetUserName").unwrap_or_default();
    if user.is_empty() || user == "-" || user.ends_with('$') || user.eq_ignore_ascii_case("SYSTEM")
    {
        return None;
    }
    let logon_type = xml_data(xml, "LogonType").unwrap_or_default();
    // Type 0/5 是系统与服务自身的会话，成功了也不是认证行为
    if !failure && matches!(logon_type, "0" | "5") {
        return None;
    }
    Some(LoginRecord {
        user: user.to_string(),
        ip: xml_data(xml, "IpAddress").unwrap_or_default().to_string(),
        logon_type: logon_type.to_string(),
        failure,
    })
}

fn auth_event(agent_id: &str, rec: &LoginRecord) -> AgentEvent {
    let raw = serde_json::json!({
        "activity_id": 1, // OCSF: Logon
        "status_id": if rec.failure { 2 } else { 1 },
        "user": { "name": rec.user },
        "src_endpoint": { "ip": rec.ip },
        "service": { "name": format!("logon-type-{}", rec.logon_type) },
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

    fn xml(event_id: u16, user: &str, logon_type: &str, ip: &str) -> String {
        format!(
            "<Event><System><EventID>{event_id}</EventID></System><EventData>\
             <Data Name='TargetUserName'>{user}</Data>\
             <Data Name='LogonType'>{logon_type}</Data>\
             <Data Name='IpAddress'>{ip}</Data>\
             </EventData></Event>"
        )
    }

    #[test]
    fn parses_failure() {
        let rec = parse_security_xml(&xml(4625, "admin", "3", "10.0.0.9")).expect("应解析");
        assert!(rec.failure);
        assert_eq!(rec.user, "admin");
        assert_eq!(rec.ip, "10.0.0.9");
    }

    #[test]
    fn parses_success() {
        let rec = parse_security_xml(&xml(4624, "alice", "10", "10.0.0.7")).expect("应解析");
        assert!(!rec.failure);
        assert_eq!(rec.logon_type, "10");
    }

    #[test]
    fn skips_noise() {
        assert!(
            parse_security_xml(&xml(4624, "WIN-DC01$", "3", "-")).is_none(),
            "机器账号应跳过"
        );
        assert!(
            parse_security_xml(&xml(4624, "svc-user", "5", "-")).is_none(),
            "服务登录应跳过"
        );
        assert!(
            parse_security_xml(&xml(4625, "svc-user", "5", "-")).is_some(),
            "服务账号的失败仍是信号"
        );
        assert!(
            parse_security_xml(&xml(4688, "x", "2", "-")).is_none(),
            "无关事件应跳过"
        );
    }
}
