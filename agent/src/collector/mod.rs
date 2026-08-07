//! 事件采集层。平台差异封死在本模块内部，对外只有一个 channel。
//!
//! Linux 优先 eBPF (tracepoint sched_process_exec)，Windows 优先 ETW (Kernel-Process)，
//! 内核采集不可用时（无权限、内核不支持）自动回落到跨平台轮询。

use tokio::sync::mpsc;

use crate::pb::AgentEvent;

mod poll;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

pub fn spawn(agent_id: String) -> mpsc::Receiver<AgentEvent> {
    let (tx, rx) = mpsc::channel(1024);

    #[cfg(target_os = "linux")]
    tokio::spawn(linux::run(agent_id, tx));

    #[cfg(target_os = "windows")]
    tokio::spawn(windows::run(agent_id, tx));

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    tokio::spawn(poll::run(agent_id, tx));

    rx
}

/// 采集器共用：组装一条进程活动事件（OCSF 1007）。
fn process_event(
    agent_id: &str,
    pid: u32,
    name: &str,
    exe: Option<&str>,
    cmd_line: Option<&str>,
    ppid: Option<u32>,
    username: String,
) -> AgentEvent {
    use std::time::{SystemTime, UNIX_EPOCH};

    let raw = serde_json::json!({
        "activity_id": 1, // OCSF: Launch
        "process": {
            "pid": pid,
            "name": name,
            "file": { "path": exe },
            "cmd_line": cmd_line,
            "parent_process": { "pid": ppid },
        },
    });

    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: 1007,
        process_guid: uuid::Uuid::new_v4().to_string(),
        username,
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
    }
}
