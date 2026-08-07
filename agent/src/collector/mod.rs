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

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

pub fn spawn(agent_id: String) -> mpsc::Receiver<AgentEvent> {
    let (tx, rx) = mpsc::channel(1024);
    let sink = EventSink {
        tx,
        dropped: Arc::new(AtomicU64::new(0)),
    };

    #[cfg(target_os = "linux")]
    tokio::spawn(linux::run(agent_id, sink));

    #[cfg(target_os = "windows")]
    tokio::spawn(windows::run(agent_id, sink));

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
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

/// 采集器共用：组装一条进程活动事件（OCSF 1007），并在注册表里建立血缘。
fn process_event(
    agent_id: &str,
    registry: &mut ProcessRegistry,
    pid: u32,
    name: &str,
    exe: Option<&str>,
    cmd_line: Option<&str>,
    ppid: Option<u32>,
    username: String,
) -> AgentEvent {
    use std::time::{SystemTime, UNIX_EPOCH};

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
