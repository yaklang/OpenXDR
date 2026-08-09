//! 事件采集层。平台差异封死在本模块内部，对外只有一个 channel。
//!
//! Linux 进程采集逐级降级：eBPF (tracepoint sched_process_exec) →
//! netlink proc connector → 跨平台轮询；Windows 优先 ETW (Kernel-Process)，
//! 不可用时（无权限、内核不支持）回落轮询。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::pb::AgentEvent;

mod config;
mod hash;
mod poll;
mod registry;

#[cfg(target_os = "linux")]
mod authwatch;

#[cfg(target_os = "linux")]
mod fswatch;

#[cfg(target_os = "linux")]
mod netlink;

pub use config::Config;
pub use registry::ProcessRegistry;

// eBPF 采集是可选特性；关掉它 Linux 走 netlink，构建不需要 nightly。
// 网络采集（TCP 出站）只在 eBPF 模式下提供
#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod linux;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod netwatch;

#[cfg(target_os = "windows")]
mod authwatch_win;

#[cfg(target_os = "windows")]
mod fswatch_win;

#[cfg(target_os = "windows")]
mod persistwatch;

#[cfg(target_os = "windows")]
mod windows;

pub fn spawn(agent_id: String, cfg: Config) -> mpsc::Receiver<AgentEvent> {
    let (tx, rx) = mpsc::channel(1024);
    let sink = EventSink {
        tx,
        dropped: Arc::new(AtomicU64::new(0)),
    };

    // 进程采集的各分支会拿走 agent_id/sink 所有权，文件监控的副本先留出来
    #[cfg(target_os = "linux")]
    let (agent_id_fs, sink_fs) = (agent_id.clone(), sink.clone());
    #[cfg(target_os = "linux")]
    let (agent_id_auth, sink_auth) = (agent_id.clone(), sink.clone());

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    tokio::spawn(linux::run(agent_id, sink, cfg.collect_network));

    // 持久化点监控与进程采集并行
    #[cfg(target_os = "windows")]
    if cfg.collect_persist {
        persistwatch::spawn(agent_id.clone(), sink.clone());
    }

    // 登录事件：Security 日志 4624/4625，认证可见性与 Linux 侧对称
    #[cfg(target_os = "windows")]
    if cfg.collect_auth {
        authwatch_win::spawn(agent_id.clone(), sink.clone());
    }

    // 敏感文件监控：ReadDirectoryChangesW 盯关键配置目录，与 Linux 侧对称
    #[cfg(target_os = "windows")]
    if cfg.collect_files {
        match fswatch_win::spawn(agent_id.clone(), sink.clone(), &cfg.file_watch_dirs) {
            Ok(n) => eprintln!("文件监控: ReadDirectoryChangesW 盯 {n} 个敏感目录"),
            Err(e) => eprintln!("文件监控不可用（{e}）"),
        }
    }

    #[cfg(target_os = "windows")]
    tokio::spawn(windows::run(agent_id, sink));

    // Linux 默认走三环的 netlink proc connector：内核主动推送 exec 事件，
    // 不漏短命进程，也不需要 eBPF 工具链。权限不足时才退到轮询。
    #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
    match netlink::spawn(agent_id.clone(), sink.clone()) {
        Ok(()) => eprintln!("采集方式: netlink proc connector（用户态，捕获全部 exec）"),
        Err(e) => {
            eprintln!("netlink 采集不可用（{e}），回落到轮询采集（会漏短命进程）");
            tokio::spawn(poll::run(agent_id, sink));
        }
    }

    // 敏感文件监控与进程采集并行，各自独立降级
    #[cfg(target_os = "linux")]
    if cfg.collect_files {
        match fswatch::spawn(agent_id_fs, sink_fs, &cfg.file_watch_dirs) {
            // 具体走 fanotify 还是 inotify 由 fswatch 内部日志说明
            Ok(_) => {}
            Err(e) => eprintln!("文件监控不可用（{e}）"),
        }
    }

    // 登录事件：wtmp/btmp 增量读，认证可见性不依赖 syslog 配置
    #[cfg(target_os = "linux")]
    if cfg.collect_auth {
        authwatch::spawn(agent_id_auth, sink_auth);
    }

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

/// OCSF 1007 活动类型：进程启动
pub const ACTIVITY_LAUNCH: u32 = 1;
/// OCSF 1007 活动类型：进程退出
pub const ACTIVITY_TERMINATE: u32 = 2;

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
    /// 退出码，仅退出事件（Terminate）可能拿到
    pub exit_code: Option<u32>,
}

/// 用 /proc 快照预登记现有进程，之后派生的子进程才能找到父。
#[cfg(target_os = "linux")]
fn seeded_registry() -> ProcessRegistry {
    let mut registry = ProcessRegistry::default();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for pid in entries
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        {
            registry.seed(pid);
        }
    }
    registry
}

/// Linux 进程采集路径共用：按 pid 解析进程属主。
/// 先读 /proc/<pid>/status 的 real uid，再查 /etc/passwd 映射成用户名；
/// passwd 里没有退化为 uid 数字串（与轮询路径一致），进程已退场则给空串。
/// uid→用户名几乎不变，解析结果带缓存，不在事件路径上反复读 passwd。
#[cfg(target_os = "linux")]
fn username_of(pid: u32) -> String {
    use std::sync::{Mutex, OnceLock};

    fn uid_of(pid: u32) -> Option<u32> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        status.lines().find_map(|l| {
            l.strip_prefix("Uid:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
    }

    fn name_of(uid: u32) -> Option<String> {
        static CACHE: OnceLock<Mutex<std::collections::HashMap<u32, Option<String>>>> =
            OnceLock::new();
        let cache = CACHE.get_or_init(Default::default);
        if let Some(hit) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&uid) {
            return hit.clone();
        }
        let name = std::fs::read_to_string("/etc/passwd")
            .ok()
            .and_then(|passwd| {
                passwd.lines().find_map(|line| {
                    let mut fields = line.split(':');
                    let name = fields.next()?;
                    fields.next()?; // 口令占位
                    (fields.next()?.parse::<u32>().ok()? == uid).then(|| name.to_string())
                })
            });
        cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(uid, name.clone());
        name
    }

    match uid_of(pid) {
        Some(uid) => name_of(uid).unwrap_or_else(|| uid.to_string()),
        None => String::new(),
    }
}

/// 采集器共用：组装一条进程活动事件（OCSF 1007），并在注册表里建立血缘。
/// activity 取 ACTIVITY_LAUNCH / ACTIVITY_TERMINATE。退出事件的 GUID 优先
/// 复用启动时登记的映射——血缘分析靠退出事件与启动事件共享 process_guid；
/// 查不到（进程早于 agent 启动）再正常登记。
fn process_event(
    agent_id: &str,
    registry: &mut ProcessRegistry,
    activity: u32,
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
        exit_code,
    } = info;

    let (guid, parent_guid) = if activity == ACTIVITY_TERMINATE {
        match registry.guid_of(pid) {
            Some(g) => (g, ppid.and_then(|p| registry.guid_of(p))),
            None => registry.register(pid, ppid),
        }
    } else {
        registry.register(pid, ppid)
    };
    let raw = serde_json::json!({
        "activity_id": activity,
        "process": {
            "pid": pid,
            "uid": guid.to_string(),
            "name": name,
            "file": { "path": exe, "sha256": exe.and_then(hash::exe_sha256) },
            "cmd_line": cmd_line,
            "exit_code": exit_code,
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
            ACTIVITY_LAUNCH,
            ProcessInfo {
                pid: 100,
                name: "parent.exe",
                exe: Some("/x/parent.exe"),
                cmd_line: Some("parent cmd"),
                ppid: None,
                username: "u".to_string(),
                ..Default::default()
            },
        );
        let child = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_LAUNCH,
            ProcessInfo {
                pid: 200,
                name: "child.exe",
                exe: None,
                cmd_line: Some("child cmd"),
                ppid: Some(100),
                username: "u".to_string(),
                ..Default::default()
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
            ACTIVITY_LAUNCH,
            ProcessInfo {
                pid: 1,
                name: "x",
                exe: None,
                cmd_line: Some("c"),
                ppid: Some(999),
                username: "u".to_string(),
                ..Default::default()
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
            ACTIVITY_LAUNCH,
            ProcessInfo {
                pid: 42,
                name: "bash",
                exe: Some("/bin/bash"),
                cmd_line: Some("-c whoami"),
                ppid: None,
                username: "root".to_string(),
                ..Default::default()
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

    /// 退出事件：activity_id=2、带退出码，且 process_guid 复用启动时登记的
    /// 映射——血缘分析靠首尾事件共享同一个 GUID。
    #[test]
    fn process_event_terminate_reuses_guid() {
        let mut reg = ProcessRegistry::default();
        let launch = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_LAUNCH,
            ProcessInfo {
                pid: 300,
                name: "worker",
                exe: Some("/bin/worker"),
                cmd_line: Some("worker -d"),
                ppid: None,
                username: "u".to_string(),
                ..Default::default()
            },
        );
        let exit = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_TERMINATE,
            ProcessInfo {
                pid: 300,
                name: "worker",
                exit_code: Some(137),
                ..Default::default()
            },
        );
        assert_eq!(exit.process_guid, launch.process_guid);
        let v: Value = serde_json::from_str(&exit.raw_json).unwrap();
        assert_eq!(v["activity_id"], 2);
        assert_eq!(v["process"]["pid"], 300);
        assert_eq!(v["process"]["exit_code"], 137);
        assert_eq!(v["process"]["uid"], launch.process_guid);
    }

    /// 进程早于 agent 启动时注册表里没有映射，退出事件退化为正常登记。
    #[test]
    fn process_event_terminate_unknown_pid() {
        let mut reg = ProcessRegistry::default();
        let exit = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_TERMINATE,
            ProcessInfo {
                pid: 555,
                ..Default::default()
            },
        );
        assert!(!exit.process_guid.is_empty());
        let v: Value = serde_json::from_str(&exit.raw_json).unwrap();
        assert_eq!(v["activity_id"], 2);
        assert!(
            v["process"]["exit_code"].is_null(),
            "拿不到退出码时应为 null"
        );
    }
}
