//! Windows ETW 采集：Microsoft-Windows-Kernel-Process provider，进程启动与退出事件。
//!
//! 内核推事件保证不漏短命进程；但该 provider 不带命令行和用户名，
//! 收到启动事件后趁进程还活着现场从句柄补——与 Linux netlink + /proc 同一哲学：
//! 进程退得太快时补不到细节，事件本身不丢。需要管理员权限；失败回落轮询。

use super::{
    ACTIVITY_LAUNCH, ACTIVITY_TERMINATE, EventSink, ProcessInfo, ProcessRegistry, poll,
    process_event,
};
use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;

const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const EVENT_PROCESS_START: u16 = 1;
const EVENT_PROCESS_STOP: u16 = 2;

pub async fn run(agent_id: String, tx: EventSink) {
    let cb_agent_id = agent_id.clone();
    let cb_tx = tx.clone();
    // ETW 回调是 Fn，注册表用 Mutex 包起来共享
    let registry = std::sync::Mutex::new(seeded_registry());

    let provider = Provider::by_guid(KERNEL_PROCESS_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let event_id = record.event_id();
            if event_id != EVENT_PROCESS_START && event_id != EVENT_PROCESS_STOP {
                return;
            }
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
            let raw_image: String = parser.try_parse("ImageName").unwrap_or_default();
            // ImageName 常是设备路径，翻成 Win32 路径后哈希与规则匹配才生效
            let image = to_win32_path(&raw_image);
            let name = image.rsplit('\\').next().unwrap_or(&image).to_string();

            let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
            if event_id == EVENT_PROCESS_START {
                let ppid: Option<u32> = parser.try_parse("ParentProcessID").ok();
                // 事件里没有命令行和用户名，现场从进程句柄补
                let (cmd_line, username) = inspect::describe(pid);
                cb_tx.send(process_event(
                    &cb_agent_id,
                    &mut reg,
                    ACTIVITY_LAUNCH,
                    ProcessInfo {
                        pid,
                        name: &name,
                        exe: Some(&image),
                        cmd_line: cmd_line.as_deref(),
                        ppid,
                        username,
                        ..Default::default()
                    },
                ));
            } else {
                // Stop：进程已退出，句柄多半开不到，命令行和用户名留空；
                // GUID 走注册表复用启动时的映射
                cb_tx.send(process_event(
                    &cb_agent_id,
                    &mut reg,
                    ACTIVITY_TERMINATE,
                    ProcessInfo {
                        pid,
                        name: &name,
                        exe: Some(&image),
                        ..Default::default()
                    },
                ));
            }
        })
        .build();

    match UserTrace::new().enable(provider).start_and_process() {
        Ok(_trace) => {
            // trace 句柄保活；channel 关闭即 agent 退出，无需额外清理
            std::future::pending::<()>().await
        }
        Err(e) => {
            eprintln!("ETW 采集不可用（{e:?}），回落到轮询采集");
            poll::run(agent_id, tx).await;
        }
    }
}

/// ETW 的 ImageName 常是设备路径（\Device\HarddiskVolumeN\...），按它读文件
/// 会失败——进程事件的 exe SHA-256 因此落空。用 QueryDosDeviceW 建一次
/// "设备名→盘符"映射，把设备路径翻成 Win32 路径；翻不动就原样返回。
fn to_win32_path(image: &str) -> String {
    use std::sync::OnceLock;
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;

    // (设备名前缀, 盘符)，按前缀长度降序：避免 HarddiskVolume1 抢先匹配
    // HarddiskVolume10（后者余串不以 \ 开头，双保险）
    static MAP: OnceLock<Vec<(String, String)>> = OnceLock::new();
    let map = MAP.get_or_init(|| {
        let mut pairs = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let name_w: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
            let mut buf = [0u16; 256];
            let n = unsafe { QueryDosDeviceW(name_w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if n == 0 {
                continue;
            }
            // 返回值可能含多个 NUL 分隔的名称，取第一个
            let target = String::from_utf16_lossy(&buf[..n as usize]);
            let target = target.split('\0').next().unwrap_or_default().to_string();
            if !target.is_empty() {
                pairs.push((target, drive));
            }
        }
        pairs.sort_by_key(|(dev, _)| std::cmp::Reverse(dev.len()));
        pairs
    });

    for (dev, drive) in map {
        if let Some(rest) = image.strip_prefix(dev.as_str())
            && (rest.is_empty() || rest.starts_with('\\'))
        {
            return format!("{drive}{rest}");
        }
    }
    image.to_string()
}

/// 用进程表快照预登记现有进程，之后派生的子进程才能找到父。
fn seeded_registry() -> ProcessRegistry {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    let mut registry = ProcessRegistry::default();
    for pid in sys.processes().keys() {
        registry.seed(pid.as_u32());
    }
    registry
}

/// 现场查询进程细节。全部 best-effort：任何一步失败就放弃该项，事件照常上报。
mod inspect {
    use windows_sys::Wdk::System::Threading::NtQueryInformationProcess;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, UNICODE_STRING};
    use windows_sys::Win32::Security::{
        GetTokenInformation, LookupAccountSidW, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    /// ProcessCommandLineInformation（Win 8.1+），windows-sys 未导出该常量
    const COMMAND_LINE_INFO: i32 = 60;

    /// ProcessBasicInformation（取值 0），所有 NT 版本都支持
    const BASIC_INFO: i32 = 0;

    /// x86_64 布局：PEB.ProcessParameters 偏移
    const PEB_PROCESS_PARAMETERS_OFF: usize = 0x20;
    /// x86_64 布局：RTL_USER_PROCESS_PARAMETERS.CommandLine 偏移
    const RUPP_COMMAND_LINE_OFF: usize = 0x70;
    /// 命令行长度上限（字符数 32K 足够覆盖 CreateProcess 限制），
    /// 防读到野指针内容时按垃圾长度分配巨缓冲
    const MAX_CMDLINE_BYTES: u16 = 0xFFF0;

    /// windows-sys 的 PROCESS_BASIC_INFORMATION 在额外特性后面，结构简单，手写一份
    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status: i32,
        peb_base_address: *mut core::ffi::c_void,
        affinity_mask: usize,
        base_priority: i32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    pub fn describe(pid: u32) -> (Option<String>, String) {
        // PROCESS_VM_READ 给 PEB 兜底路径用；拿不到 VM_READ 的进程
        // （如受保护进程）连 QUERY 也通常拿不到，一并放弃不丢人
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle.is_null() {
            return (None, String::new());
        }
        let cmd = command_line(handle);
        let user = username(handle).unwrap_or_default();
        unsafe { CloseHandle(handle) };
        (cmd, user)
    }

    /// 先走 ProcessCommandLineInformation（Win 8.1+，一步到位）；
    /// 老系统（Win7/2008R2）该信息类直接报错，回落到 PEB 路径。
    fn command_line(handle: HANDLE) -> Option<String> {
        command_line_nt(handle).or_else(|| command_line_peb(handle))
    }

    /// NtQueryInformationProcess 直接返回命令行，不必手动摸 PEB。
    /// 惯例两段式：先问长度再取值，拿回 UNICODE_STRING 头 + 字符串本体。
    fn command_line_nt(handle: HANDLE) -> Option<String> {
        let mut len = 0u32;
        unsafe {
            NtQueryInformationProcess(handle, COMMAND_LINE_INFO, std::ptr::null_mut(), 0, &mut len)
        };
        if len == 0 {
            return None;
        }
        // 用 u64 撑起对齐，UNICODE_STRING 里有指针字段
        let mut buf = vec![0u64; len.div_ceil(8) as usize];
        let status = unsafe {
            NtQueryInformationProcess(
                handle,
                COMMAND_LINE_INFO,
                buf.as_mut_ptr().cast(),
                len,
                &mut len,
            )
        };
        if status != 0 {
            return None;
        }
        let us = unsafe { &*buf.as_ptr().cast::<UNICODE_STRING>() };
        let chars = unsafe { std::slice::from_raw_parts(us.Buffer, (us.Length / 2) as usize) };
        Some(String::from_utf16_lossy(chars))
    }

    /// PEB 兜底路径：ProcessBasicInformation 拿 PEB 地址，顺着
    /// ProcessParameters -> CommandLine 一层层 ReadProcessMemory 读出来。
    /// 每一步都可能失败（进程刚退场、权限不够），任何一步失败返回 None。
    pub fn command_line_peb(handle: HANDLE) -> Option<String> {
        let mut pbi = ProcessBasicInformation {
            exit_status: 0,
            peb_base_address: std::ptr::null_mut(),
            affinity_mask: 0,
            base_priority: 0,
            unique_process_id: 0,
            inherited_from_unique_process_id: 0,
        };
        let status = unsafe {
            NtQueryInformationProcess(
                handle,
                BASIC_INFO,
                (&raw mut pbi).cast(),
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                std::ptr::null_mut(),
            )
        };
        if status != 0 || pbi.peb_base_address.is_null() {
            return None;
        }
        let params: *mut core::ffi::c_void = read_mem(handle, unsafe {
            pbi.peb_base_address.byte_add(PEB_PROCESS_PARAMETERS_OFF)
        })?;
        if params.is_null() {
            return None;
        }
        let us: UNICODE_STRING =
            read_mem(handle, unsafe { params.byte_add(RUPP_COMMAND_LINE_OFF) })?;
        if us.Buffer.is_null() || us.Length == 0 || us.Length > MAX_CMDLINE_BYTES {
            return None;
        }
        let mut buf = vec![0u16; (us.Length / 2) as usize];
        let mut got = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                us.Buffer.cast(),
                buf.as_mut_ptr().cast(),
                us.Length as usize,
                &mut got,
            )
        };
        if ok == 0 || got == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..got / 2]))
    }

    /// 从目标进程读一个 POD 值；读不满说明地址不可信，返回 None。
    fn read_mem<T: Copy>(handle: HANDLE, addr: *const core::ffi::c_void) -> Option<T> {
        let mut val = std::mem::MaybeUninit::<T>::uninit();
        let mut got = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                addr,
                val.as_mut_ptr().cast(),
                std::mem::size_of::<T>(),
                &mut got,
            )
        };
        if ok == 0 || got != std::mem::size_of::<T>() {
            return None;
        }
        Some(unsafe { val.assume_init() })
    }

    fn username(handle: HANDLE) -> Option<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        if unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) } == 0 {
            return None;
        }
        let user = token_to_username(token);
        unsafe { CloseHandle(token) };
        user
    }

    /// token → SID → DOMAIN\user。两个 API 都是先问长度再取值。
    fn token_to_username(token: HANDLE) -> Option<String> {
        let mut len = 0u32;
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u64; len.div_ceil(8) as usize];
        if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
            == 0
        {
            return None;
        }
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };

        let (mut name_len, mut domain_len, mut sid_use) = (0u32, 0u32, 0i32);
        unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                sid,
                std::ptr::null_mut(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut domain_len,
                &mut sid_use,
            )
        };
        if name_len == 0 {
            return None;
        }
        let mut name = vec![0u16; name_len as usize];
        let mut domain = vec![0u16; domain_len as usize];
        let ok = unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                sid,
                name.as_mut_ptr(),
                &mut name_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut sid_use,
            )
        };
        if ok == 0 {
            return None;
        }
        let name = String::from_utf16_lossy(&name[..name_len as usize]);
        let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
        Some(if domain.is_empty() {
            name
        } else {
            format!("{domain}\\{name}")
        })
    }
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    /// PEB 兜底路径直接读自己进程的命令行——任何 Windows 版本都成立。
    #[test]
    fn peb_fallback_reads_own_cmdline() {
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                0,
                std::process::id(),
            )
        };
        assert!(!handle.is_null(), "应能打开自己的进程句柄");
        let cmd = super::inspect::command_line_peb(handle);
        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        let cmd = cmd.expect("PEB 路径应能读出自己的命令行");
        assert!(!cmd.is_empty());
    }

    /// describe 端到端：命令行（任一路径）与用户名都要能补出来。
    #[test]
    fn describe_fills_details() {
        let (cmd, user) = super::inspect::describe(std::process::id());
        assert!(cmd.is_some_and(|c| !c.is_empty()), "命令行应可解析");
        assert!(!user.is_empty(), "用户名应可解析");
    }
}
