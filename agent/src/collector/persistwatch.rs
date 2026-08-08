//! Windows 持久化点监控：注册表自启动键 + Startup 目录。
//!
//! 统一用快照 diff 轮询——不上 ReadDirectoryChangesW 和注册表通知两套机制。
//! 持久化检测不需要毫秒级延迟，30 秒轮询换来实现的简单可靠，
//! 且注册表通知本身也不告诉你改了什么，终归要 diff。

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::pb::AgentEvent;

use super::EventSink;

/// OCSF Registry Value Activity / File System Activity
const CLASS_REGISTRY: u32 = 201002;
const CLASS_FILE: u32 = 1001;

const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// 监控的自启动键（HKLM 与 HKCU 各查一遍）。
/// 值的增改就是持久化动作本身，事件天然高信噪比。
const WATCH_KEYS: &[&str] = &[
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
];

pub fn spawn(agent_id: String, sink: EventSink) {
    std::thread::spawn(move || run(&agent_id, &sink));
}

fn run(agent_id: &str, sink: &EventSink) {
    // 首轮只建立基线不发事件：agent 重启不该把存量自启动项全报一遍
    let mut reg_seen = registry_snapshot();
    let mut file_seen = startup_snapshot();

    loop {
        std::thread::sleep(POLL_INTERVAL);

        let reg_now = registry_snapshot();
        for (path, data) in &reg_now {
            if reg_seen.get(path) != Some(data) {
                let activity = if reg_seen.contains_key(path) { 3 } else { 1 };
                if !sink.send(registry_event(agent_id, path, data, activity)) {
                    return;
                }
            }
        }
        reg_seen = reg_now;

        let file_now = startup_snapshot();
        for path in file_now.keys() {
            if !file_seen.contains_key(path) && !sink.send(file_event(agent_id, path)) {
                return;
            }
        }
        file_seen = file_now;
    }
}

/// 注册表快照：完整值路径（含 hive 前缀与值名）-> 值内容。
fn registry_snapshot() -> HashMap<String, String> {
    let mut snap = HashMap::new();
    for (hive_name, hive) in hives() {
        for key in WATCH_KEYS {
            for (name, data) in winreg::values(hive, key) {
                snap.insert(format!("{hive_name}\\{key}\\{name}"), data);
            }
        }
    }
    snap
}

/// Startup 目录快照：全局一个 + 每用户一个。
fn startup_snapshot() -> HashMap<String, ()> {
    let mut snap = HashMap::new();
    let mut dirs =
        vec![r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp".to_string()];
    if let Ok(users) = std::fs::read_dir(r"C:\Users") {
        for u in users.flatten() {
            dirs.push(format!(
                r"{}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
                u.path().display()
            ));
        }
    }
    for dir in dirs {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                if e.path().is_file() {
                    snap.insert(e.path().display().to_string(), ());
                }
            }
        }
    }
    snap
}

fn registry_event(agent_id: &str, path: &str, data: &str, activity: u8) -> AgentEvent {
    let raw = serde_json::json!({
        "activity_id": activity,
        "reg_key": { "path": path },
        "reg_value": { "data": data },
    });
    event(agent_id, CLASS_REGISTRY, raw)
}

fn file_event(agent_id: &str, path: &str) -> AgentEvent {
    let raw = serde_json::json!({
        "activity_id": 1,
        "file": { "path": path },
    });
    event(agent_id, CLASS_FILE, raw)
}

fn event(agent_id: &str, class_uid: u32, raw: serde_json::Value) -> AgentEvent {
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid,
        process_guid: String::new(),
        parent_process_guid: String::new(),
        username: String::new(),
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
        dropped_events: 0,
    }
}

fn hives() -> [(&'static str, winreg::Hive); 2] {
    [
        ("HKLM", winreg::Hive::LocalMachine),
        ("HKCU", winreg::Hive::CurrentUser),
    ]
}

/// 最小注册表读取封装：只读枚举一个键下的所有值。
mod winreg {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ, REG_SZ, RegCloseKey,
        RegEnumValueW, RegOpenKeyExW,
    };

    #[derive(Clone, Copy)]
    pub enum Hive {
        LocalMachine,
        CurrentUser,
    }

    impl Hive {
        fn raw(self) -> HKEY {
            match self {
                Hive::LocalMachine => HKEY_LOCAL_MACHINE,
                Hive::CurrentUser => HKEY_CURRENT_USER,
            }
        }
    }

    /// 枚举键下全部值，返回 (值名, 内容)。字符串类型给原文，其余给类型标注。
    pub fn values(hive: Hive, key: &str) -> Vec<(String, String)> {
        let key_w: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
        let mut handle: HKEY = std::ptr::null_mut();
        if unsafe { RegOpenKeyExW(hive.raw(), key_w.as_ptr(), 0, KEY_READ, &mut handle) } != 0 {
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name = [0u16; 512];
            let mut name_len = name.len() as u32;
            let mut kind = 0u32;
            let mut data = [0u8; 4096];
            let mut data_len = data.len() as u32;
            let rc = unsafe {
                RegEnumValueW(
                    handle,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut data_len,
                )
            };
            if rc != 0 {
                break; // ERROR_NO_MORE_ITEMS 或读取失败，都结束枚举
            }
            let value_name = String::from_utf16_lossy(&name[..name_len as usize]);
            let content = if kind == REG_SZ || kind == REG_EXPAND_SZ {
                let wide: Vec<u16> = data[..data_len as usize]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&c| c != 0)
                    .collect();
                String::from_utf16_lossy(&wide)
            } else {
                format!("<type {kind}, {data_len} bytes>")
            };
            out.push((value_name, content));
            index += 1;
        }
        unsafe { RegCloseKey(handle) };
        out
    }
}
