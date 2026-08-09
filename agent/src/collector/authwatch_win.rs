//! 认证与安全日志采集（Windows）：Event Log 订阅两条通道。
//!
//! Security 通道：4624/4625（登录成功/失败）、4720/4726（创建/删除用户）、
//! 4732（成员加入本地组）、1102（Security 日志被清空）、4648（显式凭据登录）、
//! 4719（审计策略变更），统一归一化成 OCSF 3002（Authentication）。
//! PowerShell Operational 通道：4104（Script Block Logging），脚本块内容
//! 归一化成 OCSF 1007（Process Activity），cmd_line 放脚本体，让进程类
//! Sigma 规则的 CommandLine 匹配直接作用于脚本内容。
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
/// OCSF Process Activity（4104 脚本块视同一次脚本执行）
const CLASS_PROCESS: u32 = 1007;

/// OCSF 3002 标准活动：登录（4624/4625）
const ACTIVITY_LOGON: u32 = 1;
// 以下活动取值 OCSF 3002 未定义，是平台自定义（从 10 起，与标准值互不混淆），
// Sigma 规则按 activity_id 直接匹配：
/// 创建用户（4720）
const ACTIVITY_USER_CREATED: u32 = 10;
/// 删除用户（4726）
const ACTIVITY_USER_DELETED: u32 = 11;
/// 成员加入本地组（4732），是否管理员组由规则按 group_name 判定
const ACTIVITY_GROUP_MEMBER_ADDED: u32 = 12;
/// Security 日志被清空（1102）——高危信号：擦除审计痕迹是攻击者的标准动作，
/// 正常运维几乎不会触发，独立取值让规则可以直接给 critical 级别
const ACTIVITY_LOG_CLEARED: u32 = 13;
/// 显式凭据登录（4648，runas / net use 带口令）
const ACTIVITY_EXPLICIT_CREDENTIAL: u32 = 14;
/// 审计策略变更（4719）
const ACTIVITY_AUDIT_POLICY_CHANGE: u32 = 15;

/// Security 通道订阅：登录 + 账户管理 + 日志安全 + 审计策略
const SECURITY_QUERY: &str = "*[System[(EventID=4624) or (EventID=4625) or (EventID=4648) \
     or (EventID=4719) or (EventID=4720) or (EventID=4726) or (EventID=4732) or (EventID=1102)]]";
/// PowerShell 脚本块日志（需组策略开启 Script Block Logging）
const POWERSHELL_CHANNEL: &str = "Microsoft-Windows-PowerShell/Operational";
const POWERSHELL_QUERY: &str = "*[System[(EventID=4104)]]";

pub fn spawn(agent_id: String, sink: EventSink) {
    let (sec_id, sec_sink) = (agent_id.clone(), sink.clone());
    std::thread::spawn(move || {
        if let Err(e) = subscribe(
            &sec_id,
            &sec_sink,
            "Security",
            SECURITY_QUERY,
            "登录/安全日志监控: Security 日志 4624/4625/4648/4719/4720/4726/4732/1102",
            parse_security_event,
        ) {
            eprintln!("登录/安全日志监控不可用（EvtSubscribe 错误码 {e}），需要管理员权限");
        }
    });
    // 4104 依赖组策略开启 Script Block Logging，默认可能未启用——
    // 订阅失败只打日志，不影响 Security 主路
    std::thread::spawn(move || {
        if let Err(e) = subscribe(
            &agent_id,
            &sink,
            POWERSHELL_CHANNEL,
            POWERSHELL_QUERY,
            "PowerShell 脚本块监控: 4104 Script Block Logging",
            parse_script_block,
        ) {
            eprintln!(
                "PowerShell 脚本块监控不可用（EvtSubscribe 错误码 {e}），\
                 可能未启用 Script Block Logging，不影响登录监控"
            );
        }
    });
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 订阅一个通道并循环取事件，每条 XML 交给 parse 归一化后发出。
/// 仅在订阅建立失败时返回 Err（错误码）；正常情况循环到上报侧关闭为止。
fn subscribe(
    agent_id: &str,
    sink: &EventSink,
    channel: &str,
    query: &str,
    desc: &str,
    parse: fn(&str, &str) -> Option<AgentEvent>,
) -> Result<(), u32> {
    // 手动复位的信号：EvtNext 读空后复位，日志服务有新事件时置位
    let signal = unsafe { CreateEventW(std::ptr::null(), 1, 1, std::ptr::null()) };
    if signal.is_null() {
        return Err(unsafe { GetLastError() });
    }
    let channel_w = wide(channel);
    let query_w = wide(query);
    let sub = unsafe {
        EvtSubscribe(
            0,
            signal,
            channel_w.as_ptr(),
            query_w.as_ptr(),
            0,
            std::ptr::null(),
            None,
            EvtSubscribeToFutureEvents,
        )
    };
    if sub == 0 {
        return Err(unsafe { GetLastError() });
    }
    eprintln!("{desc}");

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
                let ev = render_xml(h)
                    .as_deref()
                    .and_then(|xml| parse(xml, agent_id));
                unsafe { EvtClose(h) };
                if let Some(ev) = ev
                    && !sink.send(ev)
                {
                    unsafe { EvtClose(sub) };
                    return Ok(());
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
    /// 4625 的失败原因码（NTSTATUS，如 0xC000006A）；4624 通常为空
    status: String,
    /// 更细的子状态码，区分"用户不存在"与"口令错误"等场景
    sub_status: String,
}

/// 取 <Data Name='X'>value</Data> 的值。wevtapi 渲染用单引号属性。
fn xml_data<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let tag = format!("Name='{name}'>");
    let rest = &xml[xml.find(&tag)? + tag.len()..];
    Some(&rest[..rest.find("</Data>")?])
}

/// 从 System 段提取 EventID（标签可能带 Qualifiers 属性，不能按定长标签切）。
fn event_id(xml: &str) -> Option<u32> {
    let start = xml.find("<EventID")? + "<EventID".len();
    let start = start + xml[start..].find('>')? + 1;
    let end = start + xml[start..].find("</EventID>")?;
    xml[start..end].trim().parse().ok()
}

/// System/Execution 的 ProcessID 属性：`<Execution ProcessID='1234' ThreadID='...'/>`
fn execution_pid(xml: &str) -> Option<u32> {
    let tag = "ProcessID='";
    let rest = &xml[xml.find(tag)? + tag.len()..];
    rest[..rest.find('\'')?].parse().ok()
}

/// 机器账号与服务账号过滤器：账户管理类事件里域控的机器账号增删是日常噪声。
fn is_machine_or_service(user: &str) -> bool {
    user.is_empty() || user == "-" || user.ends_with('$') || user.eq_ignore_ascii_case("SYSTEM")
}

/// Security 通道事件分发：按 EventID 归一化成 OCSF 3002。
fn parse_security_event(xml: &str, agent_id: &str) -> Option<AgentEvent> {
    match event_id(xml)? {
        4624 | 4625 => parse_security_xml(xml).map(|rec| login_event(agent_id, &rec)),
        4720 => account_mgmt_event(xml, agent_id, ACTIVITY_USER_CREATED),
        4726 => account_mgmt_event(xml, agent_id, ACTIVITY_USER_DELETED),
        4732 => group_add_event(xml, agent_id),
        1102 => Some(log_cleared_event(xml, agent_id)),
        4648 => explicit_cred_event(xml, agent_id),
        4719 => Some(audit_policy_event(xml, agent_id)),
        _ => None,
    }
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
    if is_machine_or_service(user) {
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
        status: xml_data(xml, "Status").unwrap_or_default().to_string(),
        sub_status: xml_data(xml, "SubStatus").unwrap_or_default().to_string(),
    })
}

fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

/// 组装一条 OCSF 3002 事件：raw 由调用方按事件类型构造，
/// user 同时写进事件的 username 字段，便于按人归一化检索。
fn auth_event(agent_id: &str, user: &str, raw: serde_json::Value) -> AgentEvent {
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: now_ns(),
        class_uid: CLASS_AUTH,
        process_guid: String::new(),
        parent_process_guid: String::new(),
        username: user.to_string(),
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
        dropped_events: 0,
    }
}

fn login_event(agent_id: &str, rec: &LoginRecord) -> AgentEvent {
    let mut raw = serde_json::json!({
        "activity_id": ACTIVITY_LOGON,
        "status_id": if rec.failure { 2 } else { 1 },
        "user": { "name": rec.user },
        "src_endpoint": { "ip": rec.ip },
        "service": { "name": format!("logon-type-{}", rec.logon_type) },
    });
    // 失败原因码有值才写：4624 的 Status 恒为成功码，没有研判价值
    if !rec.status.is_empty() {
        raw["status_code"] = rec.status.clone().into();
    }
    if !rec.sub_status.is_empty() {
        raw["status_detail"] = rec.sub_status.clone().into();
    }
    auth_event(agent_id, &rec.user, raw)
}

/// 4720（创建用户）/ 4726（删除用户）：字段结构相同，activity 由分发处区分。
/// actor 是操作者，user 是被增删的账号。
fn account_mgmt_event(xml: &str, agent_id: &str, activity: u32) -> Option<AgentEvent> {
    let target = xml_data(xml, "TargetUserName").unwrap_or_default();
    if is_machine_or_service(target) {
        return None;
    }
    let raw = serde_json::json!({
        "activity_id": activity,
        "status_id": 1,
        "user": { "name": target },
        "actor_user": xml_data(xml, "SubjectUserName").unwrap_or_default(),
        "target_domain": xml_data(xml, "TargetDomainName").unwrap_or_default(),
    });
    Some(auth_event(agent_id, target, raw))
}

/// 4732（成员加入本地组）：组名进 raw，是否管理员组交给规则判定，
/// 采集端不替检测策略做取舍。
fn group_add_event(xml: &str, agent_id: &str) -> Option<AgentEvent> {
    let member = xml_data(xml, "MemberName").unwrap_or_default();
    if member.ends_with('$') {
        return None;
    }
    // MemberName 常是 '-' 或未解析的 SID，留空也不挡事件——组变更本身即信号
    let member = if member == "-" { "" } else { member };
    let raw = serde_json::json!({
        "activity_id": ACTIVITY_GROUP_MEMBER_ADDED,
        "status_id": 1,
        "user": { "name": member },
        "actor_user": xml_data(xml, "SubjectUserName").unwrap_or_default(),
        "group_name": xml_data(xml, "TargetUserName").unwrap_or_default(),
    });
    Some(auth_event(agent_id, member, raw))
}

/// 1102（Security 日志被清空）：独立 activity 取值 + log_cleared 显式标记，
/// 这条事件的含义是"有人在擦除审计痕迹"。
fn log_cleared_event(xml: &str, agent_id: &str) -> AgentEvent {
    let user = xml_data(xml, "SubjectUserName").unwrap_or_default();
    let raw = serde_json::json!({
        "activity_id": ACTIVITY_LOG_CLEARED,
        "status_id": 1,
        "user": { "name": user },
        "log_cleared": true,
    });
    auth_event(agent_id, user, raw)
}

/// 4648（显式凭据登录）：runas / net use 带口令时使用目标账号的凭据。
/// 该事件有噪声（计划任务、服务也会触发），级别与研判交给规则侧。
fn explicit_cred_event(xml: &str, agent_id: &str) -> Option<AgentEvent> {
    let target = xml_data(xml, "TargetUserName").unwrap_or_default();
    if is_machine_or_service(target) {
        return None;
    }
    let raw = serde_json::json!({
        "activity_id": ACTIVITY_EXPLICIT_CREDENTIAL,
        "status_id": 1,
        "user": { "name": target },
        "actor_user": xml_data(xml, "SubjectUserName").unwrap_or_default(),
        "src_endpoint": { "ip": xml_data(xml, "IpAddress").unwrap_or_default() },
        "target_server": xml_data(xml, "TargetServerName").unwrap_or_default(),
        "process_name": xml_data(xml, "ProcessName").unwrap_or_default(),
    });
    Some(auth_event(agent_id, target, raw))
}

/// 4719（审计策略变更）：关掉审计类别是擦除痕迹的前奏。
fn audit_policy_event(xml: &str, agent_id: &str) -> AgentEvent {
    let user = xml_data(xml, "SubjectUserName").unwrap_or_default();
    let raw = serde_json::json!({
        "activity_id": ACTIVITY_AUDIT_POLICY_CHANGE,
        "status_id": 1,
        "user": { "name": user },
        // 新旧系统字段名不同（Category / CategoryId），取到哪个用哪个
        "policy_category": xml_data(xml, "Category")
            .or_else(|| xml_data(xml, "CategoryId"))
            .unwrap_or_default(),
        "policy_subcategory": xml_data(xml, "Subcategory")
            .or_else(|| xml_data(xml, "SubcategoryId"))
            .unwrap_or_default(),
        "policy_changes": xml_data(xml, "AuditPolicyChanges").unwrap_or_default(),
    });
    auth_event(agent_id, user, raw)
}

/// 4104（PowerShell 脚本块）：归一化成 1007 进程事件，脚本体放 cmd_line，
/// Sigma 进程规则的 CommandLine 匹配因此直接作用于脚本内容。
/// 分片不拼接：单片（MessageTotal=1）直接发；分片每片各发一条并标注
/// message_number/message_total——特征落在单一片内时规则仍能命中。
fn parse_script_block(xml: &str, agent_id: &str) -> Option<AgentEvent> {
    if event_id(xml)? != 4104 {
        return None;
    }
    let text = xml_data(xml, "ScriptBlockText")?;
    if text.trim().is_empty() {
        return None;
    }
    let total: u32 = xml_data(xml, "MessageTotal")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let number: u32 = xml_data(xml, "MessageNumber")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let mut raw = serde_json::json!({
        "activity_id": 1, // OCSF 1007: Launch
        "process": {
            "pid": execution_pid(xml).unwrap_or_default(),
            "name": "powershell.exe",
            "cmd_line": text,
        },
    });
    if total > 1 {
        raw["message_number"] = number.into();
        raw["message_total"] = total.into();
    }
    // Path 是脚本文件路径（交互输入时为空）
    if let Some(path) = xml_data(xml, "Path")
        && !path.is_empty()
    {
        raw["script_path"] = path.into();
    }
    Some(AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: now_ns(),
        class_uid: CLASS_PROCESS,
        process_guid: String::new(),
        parent_process_guid: String::new(),
        username: String::new(),
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
        dropped_events: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn xml(event_id: u16, user: &str, logon_type: &str, ip: &str) -> String {
        format!(
            "<Event><System><EventID>{event_id}</EventID></System><EventData>\
             <Data Name='TargetUserName'>{user}</Data>\
             <Data Name='LogonType'>{logon_type}</Data>\
             <Data Name='IpAddress'>{ip}</Data>\
             </EventData></Event>"
        )
    }

    /// 带失败原因码的完整事件（4625 的真实形态）
    fn xml_with_status(user: &str, logon_type: &str, ip: &str, status: &str, sub: &str) -> String {
        format!(
            "<Event><System><EventID>4625</EventID></System><EventData>\
             <Data Name='TargetUserName'>{user}</Data>\
             <Data Name='LogonType'>{logon_type}</Data>\
             <Data Name='IpAddress'>{ip}</Data>\
             <Data Name='Status'>{status}</Data>\
             <Data Name='SubStatus'>{sub}</Data>\
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

    #[test]
    fn parses_failure_status_codes() {
        // 口令错误：Status=0xC000006A，SubStatus 同值
        let rec = parse_security_xml(&xml_with_status(
            "admin",
            "3",
            "10.0.0.9",
            "0xC000006A",
            "0xC000006A",
        ))
        .expect("应解析");
        assert!(rec.failure);
        assert_eq!(rec.status, "0xC000006A");
        assert_eq!(rec.sub_status, "0xC000006A");

        let ev = login_event("agent-t", &rec);
        let v: Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["status_code"], "0xC000006A");
        assert_eq!(v["status_detail"], "0xC000006A");
    }

    #[test]
    fn success_event_omits_status_codes() {
        let rec = parse_security_xml(&xml(4624, "alice", "10", "10.0.0.7")).expect("应解析");
        let ev = login_event("agent-t", &rec);
        let v: Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert!(v.get("status_code").is_none(), "无值时不写 status_code");
        assert!(v.get("status_detail").is_none(), "无值时不写 status_detail");
    }

    #[test]
    fn event_id_with_qualifiers() {
        let xml = "<Event><System><EventID Qualifiers='4776'>4720</EventID></System></Event>";
        assert_eq!(event_id(xml), Some(4720));
        assert_eq!(event_id("<Event><System/></Event>"), None);
    }

    /// 账户管理事件的通用 XML（4720/4726 字段结构相同）
    fn account_xml(event_id: u16, actor: &str, target: &str, domain: &str) -> String {
        format!(
            "<Event><System><EventID>{event_id}</EventID></System><EventData>\
             <Data Name='SubjectUserName'>{actor}</Data>\
             <Data Name='TargetUserName'>{target}</Data>\
             <Data Name='TargetDomainName'>{domain}</Data>\
             </EventData></Event>"
        )
    }

    #[test]
    fn parses_user_created() {
        let ev = parse_security_event(
            &account_xml(4720, "Administrator", "backdoor01", "CORP"),
            "agent-t",
        )
        .expect("应解析");
        assert_eq!(ev.class_uid, CLASS_AUTH);
        assert_eq!(ev.username, "backdoor01");
        let v: Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["activity_id"], ACTIVITY_USER_CREATED);
        assert_eq!(v["user"]["name"], "backdoor01");
        assert_eq!(v["actor_user"], "Administrator");
        assert_eq!(v["target_domain"], "CORP");
    }

    #[test]
    fn parses_user_deleted() {
        let ev = parse_security_event(
            &account_xml(4726, "Administrator", "ex-employee", "CORP"),
            "agent-t",
        )
        .expect("应解析");
        let v: Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["activity_id"], ACTIVITY_USER_DELETED);
        assert_eq!(v["user"]["name"], "ex-employee");
    }

    #[test]
    fn skips_machine_account_mgmt() {
        assert!(
            parse_security_event(
                &account_xml(4720, "Administrator", "NEWPC$", "CORP"),
                "agent-t"
            )
            .is_none(),
            "机器账号的创建应跳过"
        );
    }

    #[test]
    fn parses_group_member_added() {
        let xml = "<Event><System><EventID>4732</EventID></System><EventData>\
                   <Data Name='SubjectUserName'>Administrator</Data>\
                   <Data Name='MemberName'>backdoor01</Data>\
                   <Data Name='TargetUserName'>Administrators</Data>\
                   </EventData></Event>";
        let ev = parse_security_event(xml, "agent-t").expect("应解析");
        let v: Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["activity_id"], ACTIVITY_GROUP_MEMBER_ADDED);
        assert_eq!(v["user"]["name"], "backdoor01");
        assert_eq!(v["group_name"], "Administrators");
        assert_eq!(v["actor_user"], "Administrator");
    }

    #[test]
    fn group_add_keeps_unresolved_member() {
        // MemberName 为 '-'（成员是未解析的 SID）时事件仍要出，user 留空
        let xml = "<Event><System><EventID>4732</EventID></System><EventData>\
                   <Data Name='SubjectUserName'>Administrator</Data>\
                   <Data Name='MemberName'>-</Data>\
                   <Data Name='TargetUserName'>Administrators</Data>\
                   </EventData></Event>";
        let ev = parse_security_event(xml, "agent-t").expect("应解析");
        let v: Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["user"]["name"], "");
        assert_eq!(v["group_name"], "Administrators");
    }

    #[test]
    fn parses_log_cleared() {
        let xml = "<Event><System><EventID>1102</EventID></System><EventData>\
                   <Data Name='SubjectUserName'>attacker</Data>\
                   </EventData></Event>";
        let ev = parse_security_event(xml, "agent-t").expect("应解析");
        assert_eq!(ev.username, "attacker");
        let v: Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["activity_id"], ACTIVITY_LOG_CLEARED);
        assert_eq!(v["log_cleared"], true, "日志清空必须有显式标记");
    }

    #[test]
    fn parses_explicit_credential() {
        let xml = "<Event><System><EventID>4648</EventID></System><EventData>\
                   <Data Name='SubjectUserName'>attacker</Data>\
                   <Data Name='TargetUserName'>admin</Data>\
                   <Data Name='TargetServerName'>WIN-DC01</Data>\
                   <Data Name='IpAddress'>10.0.0.5</Data>\
                   <Data Name='ProcessName'>C:\\Windows\\System32\\net.exe</Data>\
                   </EventData></Event>";
        let ev = parse_security_event(xml, "agent-t").expect("应解析");
        let v: Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["activity_id"], ACTIVITY_EXPLICIT_CREDENTIAL);
        assert_eq!(v["user"]["name"], "admin");
        assert_eq!(v["actor_user"], "attacker");
        assert_eq!(v["target_server"], "WIN-DC01");
        assert_eq!(v["src_endpoint"]["ip"], "10.0.0.5");
        assert_eq!(v["process_name"], "C:\\Windows\\System32\\net.exe");
    }

    #[test]
    fn skips_machine_account_explicit_cred() {
        let xml = "<Event><System><EventID>4648</EventID></System><EventData>\
                   <Data Name='SubjectUserName'>svc</Data>\
                   <Data Name='TargetUserName'>WIN-DC01$</Data>\
                   </EventData></Event>";
        assert!(
            parse_security_event(xml, "agent-t").is_none(),
            "机器账号的显式凭据应跳过"
        );
    }

    #[test]
    fn parses_audit_policy_change() {
        let xml = "<Event><System><EventID>4719</EventID></System><EventData>\
                   <Data Name='SubjectUserName'>attacker</Data>\
                   <Data Name='CategoryId'>Logon/Logoff</Data>\
                   <Data Name='SubcategoryId'>Logon</Data>\
                   <Data Name='AuditPolicyChanges'>Success Removed</Data>\
                   </EventData></Event>";
        let ev = parse_security_event(xml, "agent-t").expect("应解析");
        let v: Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["activity_id"], ACTIVITY_AUDIT_POLICY_CHANGE);
        assert_eq!(v["policy_category"], "Logon/Logoff");
        assert_eq!(v["policy_changes"], "Success Removed");
    }

    /// 4104 的通用 XML：Execution ProcessID 在 System 段，脚本体在 EventData
    fn script_block_xml(pid: u32, number: u32, total: u32, text: &str) -> String {
        format!(
            "<Event><System><EventID>4104</EventID>\
             <Execution ProcessID='{pid}' ThreadID='100'/>\
             </System><EventData>\
             <Data Name='MessageNumber'>{number}</Data>\
             <Data Name='MessageTotal'>{total}</Data>\
             <Data Name='ScriptBlockText'>{text}</Data>\
             <Data Name='ScriptBlockId'>guid-1</Data>\
             <Data Name='Path'></Data>\
             </EventData></Event>"
        )
    }

    #[test]
    fn parses_script_block_single() {
        let ev = parse_script_block(
            &script_block_xml(4212, 1, 1, "Get-ChildItem C:\\"),
            "agent-t",
        )
        .expect("应解析");
        assert_eq!(ev.class_uid, CLASS_PROCESS);
        let v: Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["process"]["name"], "powershell.exe");
        assert_eq!(v["process"]["pid"], 4212);
        assert_eq!(v["process"]["cmd_line"], "Get-ChildItem C:\\");
        assert!(
            v.get("message_total").is_none(),
            "单片不应标注 message_total"
        );
    }

    #[test]
    fn parses_script_block_fragment() {
        let ev = parse_script_block(
            &script_block_xml(4212, 2, 3, "frombase64string("),
            "agent-t",
        )
        .expect("应解析");
        let v: Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["message_number"], 2);
        assert_eq!(v["message_total"], 3);
        assert_eq!(v["process"]["cmd_line"], "frombase64string(");
    }

    #[test]
    fn skips_empty_script_block() {
        assert!(parse_script_block(&script_block_xml(1, 1, 1, "   "), "agent-t").is_none());
        let other = "<Event><System><EventID>4103</EventID></System><EventData/></Event>";
        assert!(
            parse_script_block(other, "agent-t").is_none(),
            "非 4104 应跳过"
        );
    }
}
