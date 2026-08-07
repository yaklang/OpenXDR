//! Windows ETW 采集：Microsoft-Windows-Kernel-Process provider，进程启动事件。
//!
//! 内核推事件保证不漏短命进程；但该 provider 不带命令行和用户名，
//! 收到事件后趁进程还活着现场从句柄补——与 Linux netlink + /proc 同一哲学：
//! 进程退得太快时补不到细节，事件本身不丢。需要管理员权限；失败回落轮询。

use super::{EventSink, ProcessInfo, ProcessRegistry, poll, process_event};
use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;

const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const EVENT_PROCESS_START: u16 = 1;

pub async fn run(agent_id: String, tx: EventSink) {
    let cb_agent_id = agent_id.clone();
    let cb_tx = tx.clone();
    // ETW 回调是 Fn，注册表用 Mutex 包起来共享
    let registry = std::sync::Mutex::new(seeded_registry());

    let provider = Provider::by_guid(KERNEL_PROCESS_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if record.event_id() != EVENT_PROCESS_START {
                return;
            }
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
            let ppid: Option<u32> = parser.try_parse("ParentProcessID").ok();
            let image: String = parser.try_parse("ImageName").unwrap_or_default();
            let name = image.rsplit('\\').next().unwrap_or(&image).to_string();
            // 事件里没有命令行和用户名，现场从进程句柄补
            let (cmd_line, username) = inspect::describe(pid);

            let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
            cb_tx.send(process_event(
                &cb_agent_id,
                &mut reg,
                ProcessInfo {
                    pid,
                    name: &name,
                    exe: Some(&image),
                    cmd_line: cmd_line.as_deref(),
                    ppid,
                    username,
                },
            ));
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
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// ProcessCommandLineInformation（Win 8.1+），windows-sys 未导出该常量
    const COMMAND_LINE_INFO: i32 = 60;

    pub fn describe(pid: u32) -> (Option<String>, String) {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return (None, String::new());
        }
        let cmd = command_line(handle);
        let user = username(handle).unwrap_or_default();
        unsafe { CloseHandle(handle) };
        (cmd, user)
    }

    /// NtQueryInformationProcess 直接返回命令行，不必手动摸 PEB。
    /// 惯例两段式：先问长度再取值，拿回 UNICODE_STRING 头 + 字符串本体。
    fn command_line(handle: HANDLE) -> Option<String> {
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
