//! Windows 持久化点监控：注册表自启动与篡改点（Run 键、Winlogon、AppInit、
//! IFEO 调试器劫持、Defender 排除项、COM 劫持）、Startup 目录、Windows 服务、
//! 计划任务、WMI 永久事件订阅。
//!
//! 统一用快照 diff 轮询——不上 ReadDirectoryChangesW 和注册表通知两套机制。
//! 持久化检测不需要毫秒级延迟，30 秒轮询换来实现的简单可靠，
//! 且注册表通知本身也不告诉你改了什么，终归要 diff。
//! 增、改、删都上报：清理持久化痕迹与写入痕迹同样是攻击信号。

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::pb::AgentEvent;

use super::EventSink;
use super::persistwatch_tasks::{reconcile_snapshot, scan_dir_snapshot};

/// OCSF Registry Value Activity / File System Activity
const CLASS_REGISTRY: u32 = 201002;
const CLASS_FILE: u32 = 1001;

const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// 监控的注册表键（HKLM 与每个已加载的用户配置单元各查一遍），直接枚举键下的值。
/// 值的增改就是持久化动作本身，事件天然高信噪比。
/// CurrentVersion\Windows 盯的是 AppInit_DLLs 一系值。
const WATCH_KEYS: &[&str] = &[
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
];

/// 树形监控点（键, 子键枚举深度）：键本身是容器，威胁写在子键的值里，
/// 整棵子树按深度纳入快照，子键值与其增删都可见。
/// - Defender 排除项：Paths/Extensions/Processes 子键下的值即排除清单，落地前常见动作
/// - IFEO：每个可执行文件一个子键，Debugger 值即调试器劫持
const MACHINE_TREES: &[(&str, u32)] = &[
    (r"SOFTWARE\Microsoft\Windows Defender\Exclusions", 1),
    (
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        1,
    ),
];

/// 用户配置单元里的树形监控点。
/// - COM 劫持：用户自己的 CLSID 注册（InprocServer32/LocalServer32 默认值，无需管理员）。
///   HKCU\Software\Classes 只有该用户自己的注册（实体是 HKU\<SID>_Classes，即 UsrClass.dat，
///   经 HKU\<SID>\Software\Classes 链接可达）；HKLM 与用户注册的合并视图是 HKCR，不在这里。
const USER_TREES: &[(&str, u32)] = &[(r"Software\Classes\CLSID", 2)];

/// 注册表快照按配置单元分组：None 是 HKLM，Some(SID) 是该用户已加载的配置单元。
/// 分组是为了让用户登录/登出（配置单元加载/卸载）不被当成键值增删，见 [`diff_hives`]。
type RegSnapshot = HashMap<Option<String>, HashMap<String, String>>;

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
    let mut task_seen = tasks_snapshot(None).map(|(snap, complete)| {
        if !complete {
            eprintln!("计划任务首轮基线未完整扫描（触发上限或读取失败），后续完整轮次将自动补齐");
        }
        snap
    });
    let mut wmi_seen = wmi_snapshot();

    while !sink.is_closed() {
        std::thread::sleep(POLL_INTERVAL);

        // 五类快照各自独立 diff，一类读取失败只跳过自己这一轮
        let reg_now = registry_snapshot();
        for (sid, path, data, activity) in diff_hives(&reg_seen, &reg_now) {
            if !sink.send(registry_event(
                agent_id,
                path,
                data,
                activity,
                sid.as_deref(),
            )) {
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
                for (path, svc, activity) in diff(seen, &svc_now) {
                    let prev = seen.get(path).filter(|_| activity == 3);
                    if !sink.send(service_event(agent_id, path, svc, prev, activity)) {
                        return;
                    }
                }
            }
            svc_seen = Some(svc_now);
        }

        if let Some((task_now, complete)) = tasks_snapshot(task_seen.as_ref()) {
            if !complete {
                eprintln!(
                    "计划任务快照未完整扫描（触发深度/条目上限或目录读取失败），本轮保留未覆盖旧基线并跳过删除判定"
                );
            }
            let (next_seen, changes) = reconcile_snapshot(task_seen.as_ref(), task_now, complete);
            for (path, task, prev, activity) in changes {
                if !sink.send(task_event(agent_id, &path, &task, prev.as_ref(), activity)) {
                    return;
                }
            }
            task_seen = Some(next_seen);
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

/// 按配置单元 diff：只比两轮都在的配置单元。
/// 新出现的（用户登录、配置单元加载）这一轮静默建基线，不把存量值报成新增；
/// 消失的（用户登出、配置单元卸载）直接从基线里丢掉，不报删除——
/// 否则每次登出都会触发「Autostart Registry Entry or Service Deleted」。
fn diff_hives<'a>(
    seen: &'a RegSnapshot,
    now: &'a RegSnapshot,
) -> Vec<(&'a Option<String>, &'a String, &'a String, u8)> {
    now.iter()
        .filter_map(|(hive, cur)| seen.get(hive).map(|old| (hive, old, cur)))
        .flat_map(|(hive, old, cur)| {
            diff(old, cur)
                .into_iter()
                .map(move |(path, data, activity)| (hive, path, data, activity))
        })
        .collect()
}

/// 注册表快照：HKLM 一份，每个已加载的用户配置单元一份。
/// 用户配置单元只覆盖已加载的（已登录、或被服务/任务以该用户身份载入）：
/// 不调用 RegLoadKey 去挂别人的 NTUSER.DAT——那会和用户登录抢文件锁，
/// 用户离线期间对其配置单元的离线篡改因此看不到，等其登录加载后才以那时为基线。
fn registry_snapshot() -> RegSnapshot {
    let mut snap = RegSnapshot::new();
    snap.insert(
        None,
        hive_snapshot(winreg::LOCAL_MACHINE, "HKLM", MACHINE_TREES),
    );
    let loaded = winreg::subkeys(winreg::USERS, "").unwrap_or_default();
    for sid in user_hives(&loaded) {
        // 先拿住配置单元根键的句柄再读：持有句柄期间配置单元不会被卸载，
        // 不会读到一半赶上登出、把读不到的值当成删除。打不开说明刚卸载，跳过。
        let Some(root) = winreg::Key::open(winreg::USERS, sid) else {
            continue;
        };
        snap.insert(
            Some(sid.to_string()),
            hive_snapshot(root.raw(), "HKCU", USER_TREES),
        );
    }
    snap
}

/// HKEY_USERS 下要看的配置单元：交互用户（本地/域账户 S-1-5-21-…、Entra ID 账户 S-1-12-1-…）
/// 与 LocalSystem（S-1-5-18，agent 自身身份，以 SYSTEM 运行的程序写的 HKCU 落在这里）。
/// `<SID>_Classes` 是用户 Software\Classes 的实体，经 `<SID>\Software\Classes` 链接读，
/// 不单独当用户；.DEFAULT 与 LocalService/NetworkService 不是登录用户，不看。
fn user_hives(names: &[String]) -> impl Iterator<Item = &str> {
    names.iter().map(String::as_str).filter(|name| {
        !name.ends_with("_Classes")
            && (*name == "S-1-5-18"
                || name.starts_with("S-1-5-21-")
                || name.starts_with("S-1-12-1-"))
    })
}

/// 单个配置单元的快照：事件路径（hive 前缀 + 键 + 值名）-> 值内容。
/// 用户配置单元统一写成 `HKCU\...`，与规则按 HKCU 前缀匹配的形态一致，属主另记 SID。
fn hive_snapshot(
    root: winreg::HKEY,
    prefix: &str,
    trees: &[(&str, u32)],
) -> HashMap<String, String> {
    let mut snap = HashMap::new();
    for key in WATCH_KEYS {
        for (name, data) in winreg::values(root, key) {
            snap.insert(format!("{prefix}\\{key}\\{name}"), data);
        }
    }
    for (key, depth) in trees {
        snapshot_tree(&mut snap, prefix, root, key, *depth);
    }
    snap
}

/// 递归枚举键的值与子键（限深度），全部纳入快照。
/// 键打不开（不存在/权限）静默跳过——IFEO、排除项这类键默认不存在是正常的。
fn snapshot_tree(
    snap: &mut HashMap<String, String>,
    prefix: &str,
    root: winreg::HKEY,
    key: &str,
    depth: u32,
) {
    for (name, data) in winreg::values(root, key) {
        snap.insert(format!("{prefix}\\{key}\\{name}"), data);
    }
    if depth == 0 {
        return;
    }
    if let Some(subkeys) = winreg::subkeys(root, key) {
        for sub in subkeys {
            snapshot_tree(snap, prefix, root, &format!("{key}\\{sub}"), depth - 1);
        }
    }
}

/// Windows 服务快照：完整键路径 -> 执行目标（ImagePath / ServiceDll / FailureCommand）+ 启动类型 + 运行状态。
/// 服务清单走注册表（有几百个，全量枚举比逐个 OpenService 简单），
/// 运行状态走 SCM 一次性枚举——注册表拿不到 Running/Stopped，
/// 而"停掉 EventLog 瞎眼"恰恰是最关键的信号。
/// 返回 None 表示连 Services 键都打不开或 SCM 枚举失败（权限等），本轮整体跳过：
/// 拿着缺 State 字段的半份快照去 diff，会把全量服务误报成"修改"。
fn services_snapshot() -> Option<HashMap<String, ServiceEntry>> {
    let names = winreg::subkeys(winreg::LOCAL_MACHINE, SERVICES_KEY)?;
    let states = service_states()?;
    let services: Vec<Service> = names.into_iter().map(read_service).collect();
    let by_name: HashMap<String, &Service> = services
        .iter()
        .map(|s| (s.name.to_lowercase(), s))
        .collect();
    let mut snap = HashMap::new();
    for svc in services
        .iter()
        .filter(|s| !is_user_service_instance(s, &by_name))
    {
        // 注册表里有键但 SCM 没有对应服务（卸载残留等）时状态记 "?"
        let state = states.get(&svc.name.to_lowercase()).copied().unwrap_or("?");
        snap.insert(
            format!(r"HKLM\{SERVICES_KEY}\{}", svc.name),
            ServiceEntry {
                image_path: svc.image_path.clone(),
                service_dll: svc.service_dll.clone(),
                failure_command: svc.failure_command.clone(),
                start: svc.start.clone(),
                state: state.to_string(),
            },
        );
    }
    Some(snap)
}

/// 服务键里快照关心的字段。
struct Service {
    name: String,
    /// Type 值，读不到记 0
    kind: u32,
    image_path: String,
    /// svchost 托管服务真正加载的 DLL（Parameters\ServiceDll，老写法直接挂在服务键下）
    service_dll: String,
    /// 服务失败时执行的命令，与 ImagePath 一样是劫持点
    failure_command: String,
    start: String,
}

fn read_service(name: String) -> Service {
    let key = format!(r"{SERVICES_KEY}\{name}");
    let values = winreg::values(winreg::LOCAL_MACHINE, &key);
    let params = winreg::values(winreg::LOCAL_MACHINE, &format!(r"{key}\Parameters"));
    let start = winreg::dword(winreg::LOCAL_MACHINE, &key, "Start")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "?".to_string());
    let kind = winreg::dword(winreg::LOCAL_MACHINE, &key, "Type").unwrap_or(0);
    Service {
        name,
        kind,
        image_path: value_of(&values, "ImagePath").unwrap_or_default(),
        service_dll: value_of(&params, "ServiceDll")
            .or_else(|| value_of(&values, "ServiceDll"))
            .unwrap_or_default(),
        failure_command: value_of(&values, "FailureCommand").unwrap_or_default(),
        start,
    }
}

fn value_of(values: &[(String, String)], name: &str) -> Option<String> {
    values
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, data)| data.clone())
}

/// 服务快照里的一项。修改事件要说清改了哪个字段：系统自己翻 State / Start 一夜几百次，
/// 换掉执行目标（ImagePath / ServiceDll / FailureCommand）才是劫持（T1543.003），规则据此分级。
#[derive(PartialEq)]
struct ServiceEntry {
    image_path: String,
    service_dll: String,
    failure_command: String,
    start: String,
    state: String,
}

impl ServiceEntry {
    fn fields(&self) -> [(&'static str, &str); 5] {
        [
            ("ImagePath", &self.image_path),
            ("ServiceDll", &self.service_dll),
            ("FailureCommand", &self.failure_command),
            ("Start", &self.start),
            ("State", &self.state),
        ]
    }

    /// 事件里的值：`ImagePath=…; ServiceDll=…; Start=2; State=Running`，空字段省略
    /// （多数服务没有 ServiceDll / FailureCommand）。
    fn data(&self) -> String {
        self.fields()
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// 与旧值相比变了的字段名，逗号分隔，如 `Start,State`。
    fn changed(&self, old: &ServiceEntry) -> String {
        self.fields()
            .iter()
            .zip(old.fields())
            .filter(|((_, now), (_, before))| now != before)
            .map(|((name, _), _)| *name)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// 每用户服务实例：用户登录时系统按模板服务（Type 带 SERVICE_USER_SERVICE）复制出
/// `<模板名>_<会话后缀>`，登出时删掉。它们随登录登出增删，不是持久化动作，不进快照——
/// 否则每次登出都报一批「服务被删除」。模板本身仍在快照里，改模板照报。
/// 只认 ImagePath 与模板一致的实例：自己造个实例位、换了 ImagePath 的照样进快照。
/// 模板的 ImagePath 常写成 `%SystemRoot%\...`，实例里是展开后的路径，比较前两边都展开、忽略大小写。
fn is_user_service_instance(svc: &Service, by_name: &HashMap<String, &Service>) -> bool {
    /// windows-sys 未导出这两个服务类型位
    const SERVICE_USER_SERVICE: u32 = 0x40;
    const SERVICE_USERSERVICE_INSTANCE: u32 = 0x80;
    if svc.kind & SERVICE_USERSERVICE_INSTANCE == 0 {
        return false;
    }
    let Some((template, _)) = svc.name.rsplit_once('_') else {
        return false;
    };
    by_name.get(&template.to_lowercase()).is_some_and(|t| {
        t.kind & SERVICE_USER_SERVICE != 0
            && expand_env(&t.image_path, env_var)
                .eq_ignore_ascii_case(&expand_env(&svc.image_path, env_var))
    })
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// 展开 `%变量%`（REG_EXPAND_SZ 的写法），查不到的变量原样保留。
fn expand_env(s: &str, var: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        let Some(len) = rest[start + 1..].find('%') else {
            break;
        };
        let end = start + len + 2;
        out.push_str(&rest[..start]);
        match var(&rest[start + 1..end - 1]) {
            Some(value) => out.push_str(&value),
            None => out.push_str(&rest[start..end]),
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
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

    // SAFETY: 两个字符串参数传空指针表示本机、默认数据库，是 API 约定的用法；空句柄表示失败，下面已检查。
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
    // SAFETY: 第一段只问大小：缓冲区传空指针、长度 0 是 API 约定的用法（必然报 ERROR_MORE_DATA），
    // 系统只写三个栈上出参；scm 是上面成功打开的句柄；组名传空表示不按组过滤。
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
    // SAFETY: buf 至少 bytes_needed 字节，以 Vec<u64> 分配保证结构体内指针字段的 8 字节对齐，
    // 传入的长度就是 bytes_needed，系统不会写出界；出参都指向栈上变量。
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
    // SAFETY: scm 是上面 OpenSCManagerW 成功返回、只由本函数持有的句柄，枚举完关一次，之后不再使用。
    unsafe { CloseServiceHandle(scm) };
    if ok == 0 {
        return None;
    }
    // SAFETY: EnumServicesStatusExW 成功后 buf 开头是 count 个连续的 ENUM_SERVICE_STATUS_PROCESSW，
    // 全部落在 bytes_needed 之内；buf 8 字节对齐，在 entries 使用期间存活且不再改动。
    let entries = unsafe {
        std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            count as usize,
        )
    };
    let mut out = HashMap::new();
    for e in entries {
        // SAFETY: lpServiceName 由系统指向同一块 buf 内以 0 结尾的 UTF-16 串（或为空），buf 仍存活。
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
///
/// # Safety
/// `p` 为空，或指向一段以 0 结尾、u16 对齐、调用期间不被改写的 UTF-16 串。
unsafe fn wide_str(p: *mut u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: 调用方保证 p 指向以 0 结尾的 u16 串：遇到第一个 0 之前的每个下标都在串内。
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: 上面数出的 len 个 u16 都在串内且已初始化，p 非空、u16 对齐由系统保证；
    // 返回的 String 是拷贝，不延长借用。
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

/// 计划任务快照里的一项。系统维护一夜改几十次自带任务的触发器与状态，动作不变；
/// 劫持已有任务（T1053.005）改的是动作，所以动作单独拿出来比。
#[derive(Clone, PartialEq)]
struct TaskEntry {
    mtime: u64,
    size: u64,
    /// 任务 XML 里的动作（见 [`task_actions`]），文件读不到且没有上一轮的值时为 None
    actions: Option<String>,
}

/// 计划任务目录递归遍历的最大深度与最大扫描条目数（目录+文件），防止符号链接/目录联接或恶意目录树耗尽资源。
const MAX_TASK_DEPTH: usize = 8;
const MAX_TASK_ENTRIES: usize = 4096;

/// 计划任务快照：任务文件路径 -> mtime 秒、大小与动作，以及本轮是否完整扫描（`complete`）。
/// 返回 None 表示 Tasks 根目录都读不了（权限等），本轮整体跳过；
/// 若触及深度/条目上限或任一子目录读取失败，`complete` 为 `false`，调用方跳过删除判定并保留旧基线缺失项。
/// 任务文件这一轮读不到（计划任务服务正在写）时沿用上一轮的动作，不把"读不到"当成动作变化。
fn tasks_snapshot(
    prev: Option<&BTreeMap<String, TaskEntry>>,
) -> Option<(BTreeMap<String, TaskEntry>, bool)> {
    tasks_snapshot_at(
        std::path::Path::new(TASKS_DIR),
        prev,
        MAX_TASK_DEPTH,
        MAX_TASK_ENTRIES,
    )
}

fn tasks_snapshot_at(
    root: &std::path::Path,
    prev: Option<&BTreeMap<String, TaskEntry>>,
    max_depth: usize,
    max_entries: usize,
) -> Option<(BTreeMap<String, TaskEntry>, bool)> {
    scan_dir_snapshot(root, max_depth, max_entries, |e, path| {
        let meta = e.metadata().ok()?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let key = path.display().to_string();
        let actions = read_task(path)
            .map(|xml| task_actions(&xml))
            .or_else(|| prev?.get(&key)?.actions.clone());
        Some((
            key,
            TaskEntry {
                mtime,
                size: meta.len(),
                actions,
            },
        ))
    })
}

/// 任务文件只读前 1 MiB：计划任务服务写出的 XML 只有几 KB，不为塞进来的大文件每 30 秒读一遍。
const TASK_READ_LIMIT: u64 = 1 << 20;

/// 读任务文件并解码。计划任务服务写的是带 BOM 的 UTF-16LE，手写的也可能是 UTF-8。
fn read_task(path: &std::path::Path) -> Option<String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(TASK_READ_LIMIT)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(decode_task(&bytes))
}

fn decode_task(bytes: &[u8]) -> String {
    let utf16 = |b: &[u8]| {
        let units: Vec<u16> = b
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        String::from_utf16_lossy(&units)
    };
    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        [_, 0, ..] => utf16(bytes),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// 任务 XML 里会执行代码的动作，按出现顺序一行一个：Exec 为「命令 参数」，ComHandler 为 `com:{CLSID}`。
/// 不引 XML 库：任务文件由计划任务服务按固定架构写出，按标签找足够；SendEmail / ShowMessage 早已废弃，不执行代码。
fn task_actions(xml: &str) -> String {
    let mut actions: Vec<(usize, String)> = elements(xml, "Exec")
        .map(|(at, body)| {
            let command = element_text(body, "Command");
            let line = match element_text(body, "Arguments") {
                args if args.is_empty() => command,
                args => format!("{command} {args}"),
            };
            (at, line)
        })
        .chain(
            elements(xml, "ComHandler")
                .map(|(at, body)| (at, format!("com:{}", element_text(body, "ClassId")))),
        )
        .collect();
    actions.sort_by_key(|(at, _)| *at);
    actions
        .into_iter()
        .map(|(_, line)| line.replace(['\r', '\n'], " "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `<tag>…</tag>`（开标签可带属性）的位置与内容。
fn elements<'a>(xml: &'a str, tag: &'a str) -> impl Iterator<Item = (usize, &'a str)> + 'a {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut from = 0;
    std::iter::from_fn(move || {
        loop {
            let at = from + xml[from..].find(&open)?;
            let after = &xml[at + open.len()..];
            from = at + open.len();
            // <Exec> 与 <Exec id="…">，不认 <ExecutionTimeLimit>
            if !after.starts_with(['>', ' ', '\t', '\r', '\n']) {
                continue;
            }
            let body_start = from + after.find('>')? + 1;
            let body_end = body_start + xml[body_start..].find(&close)?;
            from = body_end + close.len();
            return Some((at, &xml[body_start..body_end]));
        }
    })
}

/// 第一个 `<tag>` 的文本（反转义、去首尾空白），没有给空串。
fn element_text(body: &str, tag: &str) -> String {
    elements(body, tag)
        .next()
        .map(|(_, text)| unescape_xml(text.trim()))
        .unwrap_or_default()
}

fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// 单次 WMI PowerShell 查询超时，防止 WMI 服务卡死拖垮整个 persistwatch 线程
const WMI_TIMEOUT: Duration = Duration::from_secs(15);

/// WMI 永久事件订阅快照：伪路径 -> 实例属性（规范化 JSON 串）。
/// 没有引 wmi crate（重依赖），30 秒一次走 powershell 子进程拿 JSON 再解析，
/// 对这个频率来说足够。查询失败（权限/WMI 服务异常/超时）返回 None，本轮静默跳过，
/// 不影响其他快照；查询成功但没有实例是合法的空快照（输出为空，退出码 0）。
fn wmi_snapshot() -> Option<HashMap<String, String>> {
    let mut snap = HashMap::new();
    for class in WMI_CLASSES {
        let mut cmd = std::process::Command::new("powershell");
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &wmi_query(class),
        ])
        // agent 作为服务运行没有控制台，禁止子进程弹窗
        .creation_flags(CREATE_NO_WINDOW);
        let out = run_with_timeout(&mut cmd, WMI_TIMEOUT)?;
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

/// 带超时的子进程执行：独立线程排空 stdout/stderr 防管道写满死锁，超时强杀子进程并返回 None
fn run_with_timeout(
    cmd: &mut std::process::Command,
    timeout: Duration,
) -> Option<std::process::Output> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let out_pipe = child.stdout.take();
    let err_pipe = child.stderr.take();
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = out_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = err_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    status.map(|status| std::process::Output {
        status,
        stdout,
        stderr,
    })
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

/// 注册表事件。`sid` 是用户配置单元的属主（HKLM 为 None），记在 user 而不是 actor.user：
/// 快照只知道写在谁的配置单元里，不知道是谁写的——管理员也能写已加载的别人的配置单元。
fn registry_event(
    agent_id: &str,
    path: &str,
    data: &str,
    activity: u8,
    sid: Option<&str>,
) -> AgentEvent {
    let mut raw = serde_json::json!({
        "activity_id": activity,
        "reg_key": { "path": path },
        "reg_value": { "data": data },
    });
    if let Some(sid) = sid {
        raw["user"] = hive_owner(sid, winreg::account_name(sid).as_deref());
    }
    event(agent_id, CLASS_REGISTRY, raw)
}

/// 服务事件：路径与值的写法同注册表事件。修改事件另带旧值 `prev_data` 与变了的字段 `changed`，
/// 规则据此区分系统翻启动类型 / 运行状态与换执行目标。
fn service_event(
    agent_id: &str,
    path: &str,
    svc: &ServiceEntry,
    prev: Option<&ServiceEntry>,
    activity: u8,
) -> AgentEvent {
    let mut raw = serde_json::json!({
        "activity_id": activity,
        "reg_key": { "path": path },
        "reg_value": { "data": svc.data() },
    });
    if let Some(prev) = prev {
        raw["reg_value"]["prev_data"] = prev.data().into();
        raw["reg_value"]["changed"] = svc.changed(prev).into();
    }
    event(agent_id, CLASS_REGISTRY, raw)
}

/// 计划任务文件事件：带任务动作 `task.actions`（删除事件为旧动作）；
/// 修改事件里动作变了（前后都读得到）才带旧动作 `task.prev_actions`。
fn task_event(
    agent_id: &str,
    path: &str,
    task: &TaskEntry,
    prev: Option<&TaskEntry>,
    activity: u8,
) -> AgentEvent {
    let mut raw = serde_json::json!({
        "activity_id": activity,
        "file": { "path": path },
    });
    if let Some(actions) = &task.actions {
        raw["task"] = serde_json::json!({ "actions": actions });
        if let Some(Some(old)) = prev.map(|p| &p.actions)
            && old != actions
        {
            raw["task"]["prev_actions"] = old.as_str().into();
        }
    }
    event(agent_id, CLASS_FILE, raw)
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

/// 用户配置单元的属主：`uid` 是 SID，`name` 是解析出的 DOMAIN\user
/// （账户已删除等解析不到时省略）。
fn hive_owner(sid: &str, name: Option<&str>) -> serde_json::Value {
    match name {
        Some(name) => serde_json::json!({ "uid": sid, "name": name }),
        None => serde_json::json!({ "uid": sid }),
    }
}

/// 最小注册表读取封装：只读枚举子键、枚举值、读单个 DWORD，外加 SID 解析账户名。
mod winreg {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::PSID;
    pub use windows_sys::Win32::System::Registry::HKEY;
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_SZ, RegCloseKey,
        RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW,
    };

    pub const LOCAL_MACHINE: HKEY = HKEY_LOCAL_MACHINE;
    pub const USERS: HKEY = HKEY_USERS;

    /// 打开的键句柄，离开作用域自动关闭。
    pub struct Key(HKEY);

    impl Key {
        /// 打开 root 下的子键（空串即 root 本身的新句柄），失败返回 None。
        pub fn open(root: HKEY, key: &str) -> Option<Key> {
            let key_w: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
            let mut handle: HKEY = std::ptr::null_mut();
            // SAFETY: key_w 是以 0 结尾的 UTF-16 键名，调用期间存活；handle 是栈上出参，成功时系统写入新句柄；
            // root 是预定义根键或调用方持有的有效句柄。
            if unsafe { RegOpenKeyExW(root, key_w.as_ptr(), 0, KEY_READ, &mut handle) } != 0 {
                return None;
            }
            Some(Key(handle))
        }

        pub fn raw(&self) -> HKEY {
            self.0
        }
    }

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: self.0 是 RegOpenKeyExW 成功返回、只由本对象持有的句柄，只在这里关一次。
            unsafe { RegCloseKey(self.0) };
        }
    }

    /// SID 字符串 → DOMAIN\user，解析不到（账户已删除、格式不对）返回 None。
    pub fn account_name(sid: &str) -> Option<String> {
        let sid_w: Vec<u16> = sid.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psid: PSID = std::ptr::null_mut();
        // SAFETY: sid_w 以 0 结尾且调用期间存活；psid 是栈上出参，成功时系统写入 LocalAlloc 分配的 SID。
        if unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut psid) } == 0 {
            return None;
        }
        // SAFETY: psid 是上面转换成功得到的有效 SID，查询期间不释放。
        let name = unsafe { super::super::windows::inspect::account_name(psid) };
        // SAFETY: psid 由 ConvertStringSidToSidW 以 LocalAlloc 分配，按约定用 LocalFree 释放一次，之后不再使用。
        unsafe { LocalFree(psid) };
        name
    }

    /// 枚举键下全部子键名。返回 None 表示键打不开（权限等）。
    pub fn subkeys(root: HKEY, key: &str) -> Option<Vec<String>> {
        let key = Key::open(root, key)?;
        let handle = key.raw();
        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name = [0u16; 256];
            let mut name_len = name.len() as u32;
            // SAFETY: handle 是 open 成功返回的有效键句柄；name 是栈上 256 个 u16，name_len 如实给出容量
            // （字符数），系统最多写这么多并回填实际长度；其余可选出参传空指针表示不需要。
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
        Some(out)
    }

    /// 读单个 DWORD 值（如服务的 Start 启动类型），读不到或类型不符返回 None。
    pub fn dword(root: HKEY, key: &str, name: &str) -> Option<u32> {
        let key = Key::open(root, key)?;
        let handle = key.raw();
        let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut kind = 0u32;
        let mut data = 0u32;
        let mut data_len = std::mem::size_of::<u32>() as u32;
        // SAFETY: handle 是有效键句柄；name_w 以 0 结尾且调用期间存活；data 是栈上 u32，data_len 如实
        // 给出它的 4 字节大小，系统不会写出界（值更大时返回 ERROR_MORE_DATA 而不写入）。
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
        (rc == 0 && kind == REG_DWORD).then_some(data)
    }

    /// 枚举键下全部值，返回 (值名, 内容)。字符串类型给原文，其余给类型标注。
    /// 遇 ERROR_MORE_DATA 时按内核回写的 data_len 动态扩容（上限 256 KiB）；
    /// 单值超上限时跳过该项继续枚举后续项，绝不提前中断导致漏报后面的持久化项。
    pub fn values(root: HKEY, key: &str) -> Vec<(String, String)> {
        const ERROR_MORE_DATA: u32 = 234;
        const INIT_VALUE_BYTES: usize = 4096;
        const MAX_VALUE_BYTES: usize = 256 * 1024;

        let Some(key) = Key::open(root, key) else {
            return Vec::new();
        };
        let handle = key.raw();

        let mut out = Vec::new();
        let mut index = 0u32;
        let mut data = vec![0u8; INIT_VALUE_BYTES];
        loop {
            let mut name = [0u16; 512];
            let mut name_len = name.len() as u32;
            let mut kind = 0u32;
            if data.len() > INIT_VALUE_BYTES {
                data.resize(INIT_VALUE_BYTES, 0);
            }
            let mut data_len = data.len() as u32;
            // SAFETY: handle 是有效键句柄；name 是栈上数组，data 是堆上 Vec，name_len / data_len
            // 如实给出各自容量，系统最多写这么多并回填所需长度；保留参数传空指针。
            let mut rc = unsafe {
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
            if rc == ERROR_MORE_DATA {
                let needed = data_len as usize;
                if needed > data.len() && needed <= MAX_VALUE_BYTES {
                    data.resize(needed, 0);
                    name_len = name.len() as u32;
                    data_len = data.len() as u32;
                    // SAFETY: 同上；data 已扩容至 needed 字节，name_len / data_len 已重置为当前容量。
                    rc = unsafe {
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
                }
                if rc == ERROR_MORE_DATA {
                    // 单值超过上限（或键名过长 / 并发变大），跳过本项继续枚举后续项
                    index += 1;
                    continue;
                }
            }
            if rc != 0 {
                break; // ERROR_NO_MORE_ITEMS 或读取失败，都结束枚举
            }
            let name_used = (name_len as usize).min(name.len());
            let data_used = (data_len as usize).min(data.len());
            let value_name = String::from_utf16_lossy(&name[..name_used]);
            let content = if kind == REG_SZ || kind == REG_EXPAND_SZ {
                let wide: Vec<u16> = data[..data_used]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&c| u16::from_le_bytes(c))
                    .take_while(|&c| c != 0)
                    .collect();
                String::from_utf16_lossy(&wide)
            } else {
                format!("<type {kind}, {data_len} bytes>")
            };
            out.push((value_name, content));
            index += 1;
        }
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

    const KEI: &str = "S-1-5-21-2781788264-1670449695-3224139109-1000";
    const RUN: &str = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater";

    type Hive<'a> = (Option<&'a str>, &'a [(&'a str, &'a str)]);

    fn hives(entries: &[Hive]) -> RegSnapshot {
        entries
            .iter()
            .map(|(sid, pairs)| (sid.map(str::to_string), snap(pairs)))
            .collect()
    }

    #[test]
    fn user_hives_keeps_user_sids_only() {
        let names: Vec<String> = [
            ".DEFAULT",
            "S-1-5-19",
            "S-1-5-20",
            KEI,
            &format!("{KEI}_Classes"),
            "S-1-5-18",
            "S-1-12-1-111-222-333-444",
            "S-1-12-1-111-222-333-444_Classes",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let got: Vec<&str> = user_hives(&names).collect();
        // _Classes 是用户 Software\Classes 的实体，经 <SID>\Software\Classes 链接读，不单独算用户
        assert_eq!(got, vec![KEI, "S-1-5-18", "S-1-12-1-111-222-333-444"]);
    }

    #[test]
    fn hive_unload_is_not_delete() {
        // kei 登出：配置单元卸载，其 Run 值从快照里整组消失，不能报成删除
        let seen = hives(&[
            (None, &[]),
            (Some(KEI), &[(RUN, r"C:\Users\kei\updater.exe")]),
        ]);
        let now = hives(&[(None, &[])]);
        assert!(diff_hives(&seen, &now).is_empty());
    }

    #[test]
    fn hive_load_is_silent_baseline() {
        // kei 登录：配置单元加载，存量 Run 值不该报成新增
        let seen = hives(&[(None, &[])]);
        let now = hives(&[
            (None, &[]),
            (Some(KEI), &[(RUN, r"C:\Users\kei\updater.exe")]),
        ]);
        assert!(diff_hives(&seen, &now).is_empty());
    }

    #[test]
    fn loaded_hive_changes_carry_owner() {
        // 同一路径在两个用户的配置单元里各自独立，删除只报真正删了的那个用户
        let other = "S-1-5-21-1-2-3-1001";
        let seen = hives(&[
            (Some(KEI), &[(RUN, "a.exe")]),
            (Some(other), &[(RUN, "b.exe")]),
        ]);
        let now = hives(&[(Some(KEI), &[]), (Some(other), &[(RUN, "b.exe")])]);
        let d = diff_hives(&seen, &now);
        assert_eq!(d.len(), 1);
        let (sid, path, data, activity) = d[0];
        assert_eq!(sid.as_deref(), Some(KEI));
        assert_eq!((path.as_str(), data.as_str(), activity), (RUN, "a.exe", 4));
    }

    #[test]
    fn hive_owner_omits_unresolved_name() {
        assert_eq!(
            hive_owner(KEI, Some(r"DESKTOP\kei")),
            serde_json::json!({ "uid": KEI, "name": r"DESKTOP\kei" })
        );
        assert_eq!(hive_owner(KEI, None), serde_json::json!({ "uid": KEI }));
    }

    #[test]
    fn registry_snapshot_paths_are_hkcu_shaped() {
        // 读本机真实注册表：用户配置单元的路径一律写成 HKCU\...（规则按这个前缀匹配），
        // 不出现 HKU\<SID>；HKLM 侧保持 HKLM\...
        for (sid, snap) in registry_snapshot() {
            let prefix = if sid.is_some() { r"HKCU\" } else { r"HKLM\" };
            assert!(
                snap.keys().all(|p| p.starts_with(prefix)),
                "{sid:?} 下有不以 {prefix} 开头的路径"
            );
        }
    }

    fn service(name: &str, kind: u32, image_path: &str) -> Service {
        Service {
            name: name.to_string(),
            kind,
            image_path: image_path.to_string(),
            service_dll: String::new(),
            failure_command: String::new(),
            start: "3".to_string(),
        }
    }

    fn entry(image_path: &str, service_dll: &str, start: &str, state: &str) -> ServiceEntry {
        ServiceEntry {
            image_path: image_path.to_string(),
            service_dll: service_dll.to_string(),
            failure_command: String::new(),
            start: start.to_string(),
            state: state.to_string(),
        }
    }

    const NETSVCS: &str = r"%SystemRoot%\System32\svchost.exe -k netsvcs -p";

    #[test]
    fn service_data_omits_empty_fields() {
        assert_eq!(
            entry(NETSVCS, r"%SystemRoot%\System32\qmgr.dll", "3", "Stopped").data(),
            r"ImagePath=%SystemRoot%\System32\svchost.exe -k netsvcs -p; ServiceDll=%SystemRoot%\System32\qmgr.dll; Start=3; State=Stopped"
        );
        assert_eq!(
            entry(r"C:\Windows\System32\spoolsv.exe", "", "2", "Running").data(),
            r"ImagePath=C:\Windows\System32\spoolsv.exe; Start=2; State=Running"
        );
    }

    #[test]
    fn service_modify_reports_prev_and_changed_fields() {
        let dll = r"%SystemRoot%\System32\qmgr.dll";
        let path = r"HKLM\SYSTEM\CurrentControlSet\Services\BITS";
        let seen: HashMap<String, ServiceEntry> =
            [(path.to_string(), entry(NETSVCS, dll, "3", "Stopped"))].into();
        // BITS 被系统按需拉起：启动类型与运行状态一起翻，执行目标不变
        let now: HashMap<String, ServiceEntry> =
            [(path.to_string(), entry(NETSVCS, dll, "2", "Running"))].into();
        let (p, svc, activity) = diff(&seen, &now)[0];
        let raw: serde_json::Value =
            serde_json::from_str(&service_event("a", p, svc, seen.get(p), activity).raw_json)
                .unwrap();
        assert_eq!(raw["reg_value"]["changed"], "Start,State");
        assert!(
            raw["reg_value"]["prev_data"]
                .as_str()
                .unwrap()
                .ends_with("Start=3; State=Stopped")
        );
        // ServiceDll 换成用户目录下的 DLL：只有它变
        let evil = entry(NETSVCS, r"C:\Users\Public\x.dll", "3", "Stopped");
        assert_eq!(evil.changed(&seen[path]), "ServiceDll");
    }

    #[test]
    fn service_create_and_delete_carry_no_prev() {
        let svc = entry(r"C:\evil.exe", "", "3", "Stopped");
        let raw: serde_json::Value =
            serde_json::from_str(&service_event("a", "p", &svc, None, 1).raw_json).unwrap();
        assert!(raw["reg_value"].get("prev_data").is_none());
        assert!(raw["reg_value"].get("changed").is_none());
    }

    /// 计划任务服务写出的任务 XML（节选自 UpdateOrchestrator\Schedule Scan 的形态）
    const TASK_XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><ExecutionTimeLimit>PT72H</ExecutionTimeLimit></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%systemroot%\system32\usoclient.exe</Command>
      <Arguments>StartScan</Arguments>
    </Exec>
    <ComHandler>
      <ClassId>{A6BA00FE-40E8-477C-B713-C64A14F18ADB}</ClassId>
    </ComHandler>
    <Exec id="second">
      <Command>"C:\Program Files\x\a.exe"</Command>
      <Arguments>-q &quot;a &amp; b&quot;</Arguments>
    </Exec>
  </Actions>
</Task>"#;

    #[test]
    fn task_actions_in_document_order() {
        assert_eq!(
            task_actions(TASK_XML),
            "%systemroot%\\system32\\usoclient.exe StartScan\n\
             com:{A6BA00FE-40E8-477C-B713-C64A14F18ADB}\n\
             \"C:\\Program Files\\x\\a.exe\" -q \"a & b\""
        );
        // 只有命令没有参数；没有动作（空文件、不是任务 XML）给空串
        assert_eq!(
            task_actions("<Exec><Command>C:\\evil.exe</Command></Exec>"),
            r"C:\evil.exe"
        );
        assert_eq!(task_actions(""), "");
        assert_eq!(task_actions("<Exec><Command>unterminated"), "");
    }

    #[test]
    fn decode_task_handles_utf16_bom_and_utf8() {
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("<Exec/>".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(decode_task(&utf16), "<Exec/>");
        assert_eq!(decode_task(b"\xEF\xBB\xBF<Task/>"), "<Task/>");
        assert_eq!(decode_task(b"<Task/>"), "<Task/>");
        assert_eq!(decode_task(b""), "");
    }

    fn task(mtime: u64, actions: Option<&str>) -> TaskEntry {
        TaskEntry {
            mtime,
            size: 10,
            actions: actions.map(str::to_string),
        }
    }

    fn task_raw(now: &TaskEntry, prev: Option<&TaskEntry>, activity: u8) -> serde_json::Value {
        serde_json::from_str(&task_event("a", "p", now, prev, activity).raw_json).unwrap()
    }

    #[test]
    fn task_modify_carries_prev_actions_only_when_actions_change() {
        let usoclient = r"%systemroot%\system32\usoclient.exe StartScan";
        // 系统维护：只改了触发器，动作不变
        let raw = task_raw(
            &task(2, Some(usoclient)),
            Some(&task(1, Some(usoclient))),
            3,
        );
        assert_eq!(raw["task"]["actions"], usoclient);
        assert!(raw["task"].get("prev_actions").is_none());
        // 劫持：动作换成 powershell
        let raw = task_raw(
            &task(2, Some("powershell.exe -enc AAAA")),
            Some(&task(1, Some(usoclient))),
            3,
        );
        assert_eq!(raw["task"]["prev_actions"], usoclient);
        // 前一轮动作未知：说不清变没变，不带旧动作
        let raw = task_raw(&task(2, Some(usoclient)), Some(&task(1, None)), 3);
        assert!(raw["task"].get("prev_actions").is_none());
        // 动作未知时不带 task
        assert!(task_raw(&task(2, None), None, 1).get("task").is_none());
    }

    #[test]
    fn user_service_instance_is_skipped_only_when_it_matches_template() {
        // 模板写 %SystemRoot%，实例是展开后的路径（大小写也可能不同）
        let template = service(
            "CDPUserSvc",
            0x60,
            r"%SystemRoot%\system32\svchost.exe -k UnistackSvcGroup",
        );
        let root = std::env::var("SystemRoot").unwrap();
        let image = &format!(r"{root}\System32\svchost.exe -k UnistackSvcGroup");
        let plain = service("Spooler", 0x10, r"C:\Windows\System32\spoolsv.exe");
        let by_name: HashMap<String, &Service> = [&template, &plain]
            .into_iter()
            .map(|s| (s.name.to_lowercase(), s))
            .collect();
        // 登录时复制出的实例：随登出删除，不进快照
        assert!(is_user_service_instance(
            &service("CDPUserSvc_33fa3", 0xE0, image),
            &by_name
        ));
        // 模板本身、普通服务都留在快照里
        assert!(!is_user_service_instance(&template, &by_name));
        assert!(!is_user_service_instance(&plain, &by_name));
        // 冒充实例：换了 ImagePath、或没有对应的用户服务模板，都照样进快照
        assert!(!is_user_service_instance(
            &service("CDPUserSvc_evil", 0xE0, r"C:\evil.exe"),
            &by_name
        ));
        assert!(!is_user_service_instance(
            &service("Spooler_33fa3", 0xE0, r"C:\Windows\System32\spoolsv.exe"),
            &by_name
        ));
        assert!(!is_user_service_instance(
            &service("Nothing_33fa3", 0xE0, image),
            &by_name
        ));
    }

    #[test]
    fn expand_env_replaces_known_vars_only() {
        let var = |name: &str| (name == "SystemRoot").then(|| r"C:\Windows".to_string());
        assert_eq!(
            expand_env(r"%SystemRoot%\system32\svchost.exe -k x", var),
            r"C:\Windows\system32\svchost.exe -k x"
        );
        // 查不到的变量与落单的 % 原样保留
        assert_eq!(expand_env(r"%Nope%\a %b", var), r"%Nope%\a %b");
        assert_eq!(expand_env("plain", var), "plain");
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
