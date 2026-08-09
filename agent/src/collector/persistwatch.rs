//! Windows 持久化点监控：注册表自启动键、Startup 目录、Windows 服务、计划任务。
//!
//! 统一用快照 diff 轮询——不上 ReadDirectoryChangesW 和注册表通知两套机制。
//! 持久化检测不需要毫秒级延迟，30 秒轮询换来实现的简单可靠，
//! 且注册表通知本身也不告诉你改了什么，终归要 diff。
//! 增、改、删都上报：清理持久化痕迹与写入痕迹同样是攻击信号。

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

/// 服务清单所在的注册表键（仅 HKLM，服务不挂在 HKCU 下）。
const SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services";

/// 计划任务文件目录：任务是无扩展名的 XML，按子目录组织。
const TASKS_DIR: &str = r"C:\Windows\System32\Tasks";

pub fn spawn(agent_id: String, sink: EventSink) {
    std::thread::spawn(move || run(&agent_id, &sink));
}

fn run(agent_id: &str, sink: &EventSink) {
    // 首轮只建立基线不发事件：agent 重启不该把存量自启动项全报一遍。
    // 服务与计划任务基线是 Option——首轮读取失败（权限等）时留空，
    // 等首次读取成功再静默建立基线，避免把失败轮的空快照当成"全量删除"。
    let mut reg_seen = registry_snapshot();
    let mut file_seen = startup_snapshot();
    let mut svc_seen = services_snapshot();
    let mut task_seen = tasks_snapshot();

    loop {
        std::thread::sleep(POLL_INTERVAL);

        // 四类快照各自独立 diff，一类读取失败只跳过自己这一轮
        let reg_now = registry_snapshot();
        for (path, data, activity) in diff(&reg_seen, &reg_now) {
            if !sink.send(registry_event(agent_id, path, data, activity)) {
                return;
            }
        }
        reg_seen = reg_now;

        let file_now = startup_snapshot();
        for (path, _, activity) in diff(&file_seen, &file_now) {
            if !sink.send(file_event(agent_id, path, activity)) {
                return;
            }
        }
        file_seen = file_now;

        if let Some(svc_now) = services_snapshot() {
            if let Some(seen) = &svc_seen {
                for (path, data, activity) in diff(seen, &svc_now) {
                    if !sink.send(registry_event(agent_id, path, data, activity)) {
                        return;
                    }
                }
            }
            svc_seen = Some(svc_now);
        }

        if let Some(task_now) = tasks_snapshot() {
            if let Some(seen) = &task_seen {
                for (path, _, activity) in diff(seen, &task_now) {
                    if !sink.send(file_event(agent_id, path, activity)) {
                        return;
                    }
                }
            }
            task_seen = Some(task_now);
        }
    }
}

/// 快照 diff：新增→Create(1)、变化→Modify(3)、删除→Delete(4)。
/// 删除项带旧内容，便于研判被清理的持久化痕迹。
fn diff<'a, V: PartialEq>(
    seen: &'a HashMap<String, V>,
    now: &'a HashMap<String, V>,
) -> Vec<(&'a String, &'a V, u8)> {
    let mut out = Vec::new();
    for (path, data) in now {
        match seen.get(path) {
            None => out.push((path, data, 1)),
            Some(old) if old != data => out.push((path, data, 3)),
            _ => {}
        }
    }
    for (path, old_data) in seen {
        if !now.contains_key(path) {
            out.push((path, old_data, 4));
        }
    }
    out
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

/// Windows 服务快照：完整键路径 -> ImagePath + 启动类型。
/// 服务有几百个，每轮全量枚举注册表比走 SCM/WMI 简单，也不依赖服务控制权限。
/// 返回 None 表示连 Services 键都打不开（权限等），本轮整体跳过。
fn services_snapshot() -> Option<HashMap<String, String>> {
    let names = winreg::subkeys(winreg::Hive::LocalMachine, SERVICES_KEY)?;
    let mut snap = HashMap::new();
    for name in names {
        let key = format!(r"{SERVICES_KEY}\{name}");
        let image_path = winreg::values(winreg::Hive::LocalMachine, &key)
            .into_iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("ImagePath"))
            .map(|(_, data)| data)
            .unwrap_or_default();
        let start = winreg::dword(winreg::Hive::LocalMachine, &key, "Start")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "?".to_string());
        snap.insert(
            format!(r"HKLM\{SERVICES_KEY}\{name}"),
            format!("ImagePath={image_path}; Start={start}"),
        );
    }
    Some(snap)
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

/// 计划任务快照：任务文件路径 -> (mtime 秒, 大小)。
/// 返回 None 表示 Tasks 根目录都读不了（权限等），本轮整体跳过；
/// 子目录读取失败只跳过该子目录。
fn tasks_snapshot() -> Option<HashMap<String, (u64, u64)>> {
    let mut snap = HashMap::new();
    let mut stack = vec![std::fs::read_dir(TASKS_DIR).ok()?];
    while let Some(entries) = stack.pop() {
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                if let Ok(sub) = std::fs::read_dir(&path) {
                    stack.push(sub);
                }
            } else if let Ok(meta) = e.metadata() {
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                snap.insert(path.display().to_string(), (mtime, meta.len()));
            }
        }
    }
    Some(snap)
}

fn registry_event(agent_id: &str, path: &str, data: &str, activity: u8) -> AgentEvent {
    let raw = serde_json::json!({
        "activity_id": activity,
        "reg_key": { "path": path },
        "reg_value": { "data": data },
    });
    event(agent_id, CLASS_REGISTRY, raw)
}

fn file_event(agent_id: &str, path: &str, activity: u8) -> AgentEvent {
    let raw = serde_json::json!({
        "activity_id": activity,
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

/// 最小注册表读取封装：只读枚举子键、枚举值、读单个 DWORD。
mod winreg {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_SZ,
        RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW,
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

    /// 打开键，失败返回 None。子模块内部统一走这里，免得每个函数重复开键样板。
    fn open(hive: Hive, key: &str) -> Option<HKEY> {
        let key_w: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
        let mut handle: HKEY = std::ptr::null_mut();
        if unsafe { RegOpenKeyExW(hive.raw(), key_w.as_ptr(), 0, KEY_READ, &mut handle) } != 0 {
            return None;
        }
        Some(handle)
    }

    /// 枚举键下全部子键名。返回 None 表示键打不开（权限等）。
    pub fn subkeys(hive: Hive, key: &str) -> Option<Vec<String>> {
        let handle = open(hive, key)?;
        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name = [0u16; 256];
            let mut name_len = name.len() as u32;
            let rc = unsafe {
                RegEnumKeyExW(
                    handle,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if rc != 0 {
                break; // ERROR_NO_MORE_ITEMS 或读取失败，都结束枚举
            }
            out.push(String::from_utf16_lossy(&name[..name_len as usize]));
            index += 1;
        }
        unsafe { RegCloseKey(handle) };
        Some(out)
    }

    /// 读单个 DWORD 值（如服务的 Start 启动类型），读不到或类型不符返回 None。
    pub fn dword(hive: Hive, key: &str, name: &str) -> Option<u32> {
        let handle = open(hive, key)?;
        let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut kind = 0u32;
        let mut data = 0u32;
        let mut data_len = std::mem::size_of::<u32>() as u32;
        let rc = unsafe {
            RegQueryValueExW(
                handle,
                name_w.as_ptr(),
                std::ptr::null(),
                &mut kind,
                &mut data as *mut u32 as *mut u8,
                &mut data_len,
            )
        };
        unsafe { RegCloseKey(handle) };
        (rc == 0 && kind == REG_DWORD).then_some(data)
    }

    /// 枚举键下全部值，返回 (值名, 内容)。字符串类型给原文，其余给类型标注。
    pub fn values(hive: Hive, key: &str) -> Vec<(String, String)> {
        let Some(handle) = open(hive, key) else {
            return Vec::new();
        };

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

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn diff_detects_create_modify_delete() {
        let seen = snap(&[("keep", "1"), ("change", "old"), ("drop", "gone")]);
        let now = snap(&[("keep", "1"), ("change", "new"), ("add", "fresh")]);
        let d = diff(&seen, &now);
        assert_eq!(d.len(), 3, "未变化的不该上报");
        assert!(
            d.iter()
                .any(|&(p, v, a)| p == "add" && v == "fresh" && a == 1),
            "新增应报 Create(1)，内容为新值"
        );
        assert!(
            d.iter()
                .any(|&(p, v, a)| p == "change" && v == "new" && a == 3),
            "变化应报 Modify(3)，内容为新值"
        );
        assert!(
            d.iter()
                .any(|&(p, v, a)| p == "drop" && v == "gone" && a == 4),
            "删除应报 Delete(4)，内容为旧值"
        );
    }

    #[test]
    fn diff_unchanged_is_quiet() {
        let seen = snap(&[("a", "1"), ("b", "2")]);
        let now = seen.clone();
        assert!(diff(&seen, &now).is_empty());
    }

    #[test]
    fn diff_empty_baseline_reports_all_as_create() {
        let seen = HashMap::new();
        let now = snap(&[("a", "1"), ("b", "2")]);
        let d = diff(&seen, &now);
        assert_eq!(d.len(), 2);
        assert!(d.iter().all(|(_, _, a)| *a == 1));
    }

    #[test]
    fn diff_works_for_task_metadata() {
        // 计划任务快照的值是 (mtime, size)，任一字段变化都算修改
        let mut seen = HashMap::new();
        seen.insert(r"C:\Tasks\evil".to_string(), (100u64, 10u64));
        let mut now = seen.clone();
        now.insert(r"C:\Tasks\evil".to_string(), (100, 11));
        let d = diff(&seen, &now);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].2, 3);
    }
}
