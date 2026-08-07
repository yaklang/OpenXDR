//! 事件采集层。平台差异封死在本模块内部，对外只有一个 channel。
//!
//! Linux 优先 eBPF (tracepoint sched_process_exec)，Windows 优先 ETW (Kernel-Process)，
//! 内核采集不可用时（无权限、内核不支持）自动回落到跨平台轮询。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::pb::AgentEvent;

mod poll;
mod registry;

pub use registry::ProcessRegistry;

// eBPF 采集是可选特性；未启用时 Linux 也走轮询，构建不需要 nightly
#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

pub fn spawn(agent_id: String) -> mpsc::Receiver<AgentEvent> {
    let (tx, rx) = mpsc::channel(1024);
    let sink = EventSink {
        tx,
        dropped: Arc::new(AtomicU64::new(0)),
    };

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    tokio::spawn(linux::run(agent_id, sink));

    #[cfg(target_os = "windows")]
    tokio::spawn(windows::run(agent_id, sink));

    #[cfg(not(any(all(target_os = "linux", feature = "ebpf"), target_os = "windows")))]
    tokio::spawn(poll::run(agent_id, sink));

    rx
}

/// 事件出口。上报侧堵住时丢弃并计数，绝不反压采集——
/// 阻塞采集线程只会让内核缓冲区溢出，丢得更多且无从知晓。
#[derive(Clone)]
pub struct EventSink {
    tx: mpsc::Sender<AgentEvent>,
    dropped: Arc<AtomicU64>,
}

impl EventSink {
    /// 返回 false 表示上报侧已关闭，采集任务应当退出。
    pub fn send(&self, mut event: AgentEvent) -> bool {
        event.dropped_events = self.dropped.load(Ordering::Relaxed);
        match self.tx.try_send(event) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

/// 一个进程的采集结果。用具名字段而非位置参数：
/// exe 与 cmd_line 同为 Option<&str> 且相邻，位置传参很容易传反。
#[derive(Default)]
pub struct ProcessInfo<'a> {
    pub pid: u32,
    pub name: &'a str,
    pub exe: Option<&'a str>,
    pub cmd_line: Option<&'a str>,
    pub ppid: Option<u32>,
    pub username: String,
}

/// 采集器共用：组装一条进程活动事件（OCSF 1007），并在注册表里建立血缘。
fn process_event(
    agent_id: &str,
    registry: &mut ProcessRegistry,
    info: ProcessInfo<'_>,
) -> AgentEvent {
    use std::time::{SystemTime, UNIX_EPOCH};

    let ProcessInfo {
        pid,
        name,
        exe,
        cmd_line,
        ppid,
        username,
    } = info;

    let (guid, parent_guid) = registry.register(pid, ppid);
    let raw = serde_json::json!({
        "activity_id": 1, // OCSF: Launch
        "process": {
            "pid": pid,
            "uid": guid.to_string(),
            "name": name,
            "file": { "path": exe },
            "cmd_line": cmd_line,
            "parent_process": {
                "pid": ppid,
                "uid": parent_guid.map(|g| g.to_string()),
            },
        },
    });

    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: 1007,
        process_guid: guid.to_string(),
        parent_process_guid: parent_guid.map(|g| g.to_string()).unwrap_or_default(),
        username,
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
        dropped_events: 0, // 由 EventSink 在发送时填当前累计值
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn process_event_links_lineage() {
        let mut reg = ProcessRegistry::default();
        let parent = process_event(
            "agent-1",
            &mut reg,
            ProcessInfo {
                pid: 100,
                name: "parent.exe",
                exe: Some("/x/parent.exe"),
                cmd_line: Some("parent cmd"),
                ppid: None,
                username: "u".to_string(),
            },
        );
        let child = process_event(
            "agent-1",
            &mut reg,
            ProcessInfo {
                pid: 200,
                name: "child.exe",
                exe: None,
                cmd_line: Some("child cmd"),
                ppid: Some(100),
                username: "u".to_string(),
            },
        );
        assert_eq!(
            parent.process_guid, child.parent_process_guid,
            "子进程应连到父进程 GUID"
        );
        assert_eq!(child.class_uid, 1007);
        assert!(!parent.process_guid.is_empty());
        assert!(!child.process_guid.is_empty());
    }

    #[test]
    fn process_event_parent_unknown() {
        let mut reg = ProcessRegistry::default();
        let evt = process_event(
            "agent-1",
            &mut reg,
            ProcessInfo {
                pid: 1,
                name: "x",
                exe: None,
                cmd_line: Some("c"),
                ppid: Some(999),
                username: "u".to_string(),
            },
        );
        assert!(
            evt.parent_process_guid.is_empty(),
            "父未登记时 parent GUID 应为空"
        );
        let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
        assert_eq!(v["process"]["pid"], 1);
        assert_eq!(v["process"]["name"], "x");
        assert_eq!(v["process"]["cmd_line"], "c");
        assert!(
            v["process"]["parent_process"]["uid"].is_null(),
            "父未知时 uid 应为 null"
        );
    }

    #[test]
    fn process_event_raw_fields() {
        let mut reg = ProcessRegistry::default();
        let evt = process_event(
            "agent-x",
            &mut reg,
            ProcessInfo {
                pid: 42,
                name: "bash",
                exe: Some("/bin/bash"),
                cmd_line: Some("-c whoami"),
                ppid: None,
                username: "root".to_string(),
            },
        );
        let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
        assert_eq!(v["activity_id"], 1);
        assert_eq!(v["process"]["uid"], evt.process_guid);
        assert_eq!(v["process"]["file"]["path"], "/bin/bash");
        assert_eq!(v["process"]["pid"], 42);
        assert_eq!(evt.agent_id, "agent-x");
        assert_eq!(evt.username, "root");
        assert!(evt.ts_unix_ns > 0);
    }
}
