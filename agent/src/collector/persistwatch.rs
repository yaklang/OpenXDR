//! Windows 持久化点监控：注册表自启动与篡改点（Run 键、Winlogon、AppInit、
//! IFEO 调试器劫持、Defender 排除项、COM 劫持）、Startup 目录、Windows 服务、
//! 计划任务、WMI 永久事件订阅。
//!
//! 统一用快照 diff 轮询——不上 ReadDirectoryChangesW 和注册表通知两套机制。
//! 持久化检测不需要毫秒级延迟，30 秒轮询换来实现的简单可靠，
//! 且注册表通知本身也不告诉你改了什么，终归要 diff。
//! 增、改、删都上报：清理持久化痕迹与写入痕迹同样是攻击信号。

use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::pb::AgentEvent;

use super::EventSink;

/// OCSF Registry Value Activity / File System Activity
const CLASS_REGISTRY: u32 = 201002;
const CLASS_FILE: u32 = 1001;

const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// 监控的注册表键（HKLM 与 HKCU 各查一遍），直接枚举键下的值。
/// 值的增改就是持久化动作本身，事件天然高信噪比。
/// CurrentVersion\Windows 盯的是 AppInit_DLLs 一系值。
const WATCH_KEYS: &[&str] = &[
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
];

/// 树形监控点（hive, 键, 子键枚举深度）：键本身是容器，威胁写在子键的值里，
/// 整棵子树按深度纳入快照，子键值与其增删都可见。
/// - Defender 排除项：Paths/Extensions/Processes 子键下的值即排除清单，落地前常见动作
/// - IFEO：每个可执行文件一个子键，Debugger 值即调试器劫持
/// - COM 劫持：HKCU 的 CLSID 子键下 InprocServer32/LocalServer32 默认值（无需管理员；
///   HKCU\Software\Classes 是合并视图，HKLM 侧的系统级注册也一并纳入）
const WATCH_TREES: &[(winreg::Hive, &str, u32)] = &[
    (
        winreg::Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows Defender\Exclusions",
        1,
    ),
    (
        winreg::Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        1,
    ),
    (winreg::Hive::CurrentUser, r"Software\Classes\CLSID", 2),
];

/// 服务清单所在的注册表键（仅 HKLM，服务不挂在 HKCU 下）。
const SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services";

/// 计划任务文件目录：任务是无扩展名的 XML，按子目录组织。
const TASKS_DIR: &str = r"C:\Windows\System32\Tasks";

/// WMI 永久事件订阅监控（T1546.003）：命名空间与要盯的类。
const WMI_NAMESPACE: &str = r"root\subscription";
const WMI_CLASSES: &[&str] = &["__EventFilter", "__EventConsumer"];

pub fn spawn(agent_id: String, sink: EventSink) {
    std::thread::spawn(move || run(&agent_id, &sink));
}

fn run(agent_id: &str, sink: &EventSink) {
    // 首轮只建立基线不发事件：agent 重启不该把存量自启动项全报一遍。
    // 服务/计划任务/WMI 基线是 Option——首轮读取失败（权限等）时留空，
    // 等首次读取成功再静默建立基线，避免把失败轮的空快照当成"全量删除"。
    let mut reg_seen = registry_snapshot();
    let mut file_seen = startup_snapshot();
    let mut svc_seen = services_snapshot();
    let mut task_seen = tasks_snapshot();
    let mut wmi_seen = wmi_snapshot();

    loop {
        std::thread::sleep(POLL_INTERVAL);

        // 五类快照各自独立 diff，一类读取失败只跳过自己这一轮
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

        if let Some(wmi_now) = wmi_snapshot() {
            if let Some(seen) = &wmi_seen {
                for (path, data, activity) in diff(seen, &wmi_now) {
                    if !sink.send(wmi_event(agent_id, path, data, activity)) {
                        return;
                    }
                }
            }
            wmi_seen = Some(wmi_now);
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
    // 树形键各自绑定 hive，不走上面的双 hive 循环
    for (hive, key, depth) in WATCH_TREES {
        snapshot_tree(&mut snap, hive.name(), *hive, key, *depth);
    }
    snap
}

/// 递归枚举键的值与子键（限深度），全部纳入快照。
/// 键打不开（不存在/权限）静默跳过——IFEO、排除项这类键默认不存在是正常的。
fn snapshot_tree(
    snap: &mut HashMap<String, String>,
    hive_name: &str,
    hive: winreg::Hive,
    key: &str,
    depth: u32,
) {
    for (name, data) in winreg::values(hive, key) {
        snap.insert(format!("{hive_name}\\{key}\\{name}"), data);
    }
    if depth == 0 {
        return;
    }
    if let Some(subkeys) = winreg::subkeys(hive, key) {
        for sub in subkeys {
            snapshot_tree(snap, hive_name, hive, &format!("{key}\\{sub}"), depth - 1);
        }
    }
}

/// Windows 服务快照：完整键路径 -> ImagePath + 启动类型 + 运行状态。
/// 服务清单走注册表（有几百个，全量枚举比逐个 OpenService 简单），
/// 运行状态走 SCM 一次性枚举——注册表拿不到 Running/Stopped，
/// 而"停掉 EventLog 瞎眼"恰恰是最关键的信号。
/// 返回 None 表示连 Services 键都打不开或 SCM 枚举失败（权限等），本轮整体跳过：
/// 拿着缺 State 字段的半份快照去 diff，会把全量服务误报成"修改"。
fn services_snapshot() -> Option<HashMap<String, String>> {
    let names = winreg::subkeys(winreg::Hive::LocalMachine, SERVICES_KEY)?;
    let states = service_states()?;
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
        // 注册表里有键但 SCM 没有对应服务（卸载残留等）时状态记 "?"
        let state = states.get(&name.to_lowercase()).copied().unwrap_or("?");
        snap.insert(
            format!(r"HKLM\{SERVICES_KEY}\{name}"),
            format!("ImagePath={image_path}; Start={start}; State={state}"),
        );
    }
    Some(snap)
}

/// 服务运行状态：服务名（小写）-> 状态串。
/// EnumServicesStatusEx 一次枚举全部服务（含驱动），比逐服务 QueryServiceStatus 便宜。
/// 失败返回 None，调用方整轮跳过服务快照。
fn service_states() -> Option<HashMap<String, &'static str>> {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
        SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_DRIVER, SERVICE_STATE_ALL,
        SERVICE_WIN32,
    };

    let scm = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_ENUMERATE_SERVICE,
        )
    };
    if scm.is_null() {
        return None;
    }
    // 先空调用拿缓冲区大小（必然失败并报 ERROR_MORE_DATA，bytes_needed 为所需大小）
    let mut bytes_needed = 0u32;
    let mut count = 0u32;
    let mut resume = 0u32;
    unsafe {
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            std::ptr::null_mut(),
            0,
            &mut bytes_needed,
            &mut count,
            &mut resume,
            std::ptr::null(),
        );
    }
    // 用 u64 缓冲保证对齐：ENUM_SERVICE_STATUS_PROCESSW 含指针字段，
    // Vec<u8> 不保证 8 字节对齐
    let mut buf = vec![0u64; (bytes_needed as usize).div_ceil(8)];
    let ok = unsafe {
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            buf.as_mut_ptr() as *mut u8,
            bytes_needed,
            &mut bytes_needed,
            &mut count,
            &mut resume,
            std::ptr::null(),
        )
    };
    unsafe { CloseServiceHandle(scm) };
    if ok == 0 {
        return None;
    }
    let entries = unsafe {
        std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            count as usize,
        )
    };
    let mut out = HashMap::new();
    for e in entries {
        let name = unsafe { wide_str(e.lpServiceName) };
        out.insert(
            name.to_lowercase(),
            service_state_name(e.ServiceStatusProcess.dwCurrentState),
        );
    }
    Some(out)
}

/// SERVICE_STATUS_PROCESS.dwCurrentState 数值 -> 状态串。
fn service_state_name(state: u32) -> &'static str {
    use windows_sys::Win32::System::Services::{
        SERVICE_CONTINUE_PENDING, SERVICE_PAUSE_PENDING, SERVICE_PAUSED, SERVICE_RUNNING,
        SERVICE_START_PENDING, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    };
    match state {
        SERVICE_STOPPED => "Stopped",
        SERVICE_START_PENDING => "StartPending",
        SERVICE_STOP_PENDING => "StopPending",
        SERVICE_RUNNING => "Running",
        SERVICE_CONTINUE_PENDING => "ContinuePending",
        SERVICE_PAUSE_PENDING => "PausePending",
        SERVICE_PAUSED => "Paused",
        _ => "Unknown",
    }
}

/// 从 Win32 API 返回的宽字符指针构造 String，空指针给空串。
unsafe fn wide_str(p: *mut u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
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

/// WMI 永久事件订阅快照：伪路径 -> 实例属性（规范化 JSON 串）。
/// 没有引 wmi crate（重依赖），30 秒一次走 powershell 子进程拿 JSON 再解析，
/// 对这个频率来说足够。查询失败（权限/WMI 服务异常）返回 None，本轮静默跳过，
/// 不影响其他快照；查询成功但没有实例是合法的空快照（输出为空，退出码 0）。
fn wmi_snapshot() -> Option<HashMap<String, String>> {
    let mut snap = HashMap::new();
    for class in WMI_CLASSES {
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &wmi_query(class),
            ])
            // agent 作为服务运行没有控制台，禁止子进程弹窗
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        for (name, props) in parse_wmi_json(&text) {
            snap.insert(format!(r"wmi:{WMI_NAMESPACE}\{class}.{name}"), props);
        }
    }
    Some(snap)
}

/// agent 作为服务运行没有控制台，powershell 子进程不应尝试创建窗口。
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 单类的 WMI 查询：ConvertTo-Json 输出整个实例（含各类专有属性），
/// -ErrorAction Stop 让命名空间/权限错误变成非零退出码而不是半截输出。
fn wmi_query(class: &str) -> String {
    format!(
        "Get-WmiObject -Namespace '{WMI_NAMESPACE}' -Class '{class}' -ErrorAction Stop | ConvertTo-Json -Compress -Depth 4"
    )
}

/// 解析 ConvertTo-Json 输出，返回 (实例名, 规范化属性串)。
/// 只有一个实例时 ConvertTo-Json 输出对象而不是数组，两种形态都要接。
/// serde_json 默认 BTreeMap 按键排序，重新序列化即得顺序稳定的 diff 载荷。
fn parse_wmi_json(json: &str) -> Vec<(String, String)> {
    let text = json.trim();
    if text.is_empty() {
        return Vec::new();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let items = match value {
        serde_json::Value::Array(items) => items,
        obj @ serde_json::Value::Object(_) => vec![obj],
        _ => return Vec::new(),
    };
    items
        .into_iter()
        .filter_map(|item| {
            let name = item.get("Name")?.as_str()?.to_string();
            Some((name, item.to_string()))
        })
        .collect()
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

/// WMI 订阅事件：class_uid 用文件事件，伪路径落在 file.path 便于规则匹配，
/// 实例属性放在 wmi.data——删除事件带的是被删实例的旧属性。
fn wmi_event(agent_id: &str, path: &str, data: &str, activity: u8) -> AgentEvent {
    let raw = serde_json::json!({
        "activity_id": activity,
        "file": { "path": path },
        "wmi": { "data": data },
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

        /// 事件路径里的 hive 前缀。
        pub fn name(self) -> &'static str {
            match self {
                Hive::LocalMachine => "HKLM",
                Hive::CurrentUser => "HKCU",
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

    #[test]
    fn service_state_flip_is_modify() {
        // EventLog 被停止：ImagePath/Start 都没变，只有 State 翻转，必须报 Modify
        let path = r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog";
        let seen = snap(&[(
            path,
            "ImagePath=C:\\Windows\\System32\\svchost.exe; Start=2; State=Running",
        )]);
        let now = snap(&[(
            path,
            "ImagePath=C:\\Windows\\System32\\svchost.exe; Start=2; State=Stopped",
        )]);
        let d = diff(&seen, &now);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].2, 3, "State 翻转应报 Modify(3)");
        assert!(d[0].1.contains("State=Stopped"), "内容应为新值");
    }

    #[test]
    fn service_state_same_is_quiet() {
        let path = r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog";
        let seen = snap(&[(
            path,
            "ImagePath=C:\\Windows\\System32\\svchost.exe; Start=2; State=Running",
        )]);
        let now = seen.clone();
        assert!(diff(&seen, &now).is_empty());
    }

    #[test]
    fn parse_wmi_json_single_object_not_array() {
        // 只有一个实例时 ConvertTo-Json 输出对象而不是数组
        let json = r#"{"Name":"EvilFilter","Query":"SELECT * FROM __InstanceCreationEvent"}"#;
        let items = parse_wmi_json(json);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, "EvilFilter");
        // 键排序稳定，同一对象永远序列化成同一串，diff 不会误报
        assert_eq!(
            items[0].1,
            r#"{"Name":"EvilFilter","Query":"SELECT * FROM __InstanceCreationEvent"}"#
        );
    }

    #[test]
    fn parse_wmi_json_array() {
        let json = r#"[{"Name":"a","Query":"q1"},{"Name":"b","CommandLineTemplate":"evil.exe"}]"#;
        let items = parse_wmi_json(json);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].0, "a");
        assert_eq!(items[1].0, "b");
    }

    #[test]
    fn parse_wmi_json_empty_and_garbage() {
        // 无实例（空输出）与查询异常输出都不该产生快照条目
        assert!(parse_wmi_json("").is_empty());
        assert!(parse_wmi_json("  \r\n ").is_empty());
        assert!(parse_wmi_json("not json").is_empty());
        // 没有 Name 属性的实例无法定位伪路径，跳过
        assert!(parse_wmi_json(r#"[{"Query":"q"}]"#).is_empty());
    }

    #[test]
    fn wmi_diff_delete_carries_old_properties() {
        let seen = snap(&[(
            r"wmi:root\subscription\__EventConsumer.EvilConsumer",
            r#"{"CommandLineTemplate":"evil.exe","Name":"EvilConsumer"}"#,
        )]);
        let now = HashMap::new();
        let d = diff(&seen, &now);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].2, 4, "删除应报 Delete(4)");
        assert!(d[0].1.contains("evil.exe"), "删除事件应带被删实例的旧属性");
    }
}
