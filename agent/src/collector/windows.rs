//! Windows ETW 采集：Microsoft-Windows-Kernel-Process provider，进程启动与退出事件。
//!
//! 内核推事件保证不漏短命进程；但该 provider 不带命令行和用户名，
//! 收到启动事件后趁进程还活着现场从句柄补——与 Linux netlink + /proc 同一哲学：
//! 进程退得太快时补不到细节，事件本身不丢。需要管理员权限；失败回落轮询。

use super::{
    ACTIVITY_LAUNCH, ACTIVITY_TERMINATE, EventSink, ProcessInfo, ProcessRegistry, emit_process,
    poll,
};
use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{UserTrace, stop_trace_by_name};
use std::sync::{Arc, Mutex};

const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const EVENT_PROCESS_START: u16 = 1;
const EVENT_PROCESS_STOP: u16 = 2;

// ETW 会话用固定名字：agent 被强杀或升级退出时会话不随进程消失，启动时先停掉同名旧会话；
// 用随机名每次重启都漏一个，系统总共 64 个会话名额迟早占满，之后采集就起不来
const SESSION: &str = "OpenXDR-Process";

pub async fn run(agent_id: String, tx: EventSink, registry: Arc<Mutex<ProcessRegistry>>) {
    let cb_agent_id = agent_id.clone();
    let cb_tx = tx.clone();
    // ETW 回调是 Fn，注册表（与网络采集共享）经 Arc 移进回调加锁使用

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
                let events = emit_process(
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
                );
                for event in events {
                    cb_tx.send(event);
                }
            } else {
                // Stop：进程已退出，句柄多半开不到，命令行和用户名留空；
                // GUID 走注册表复用启动时的映射
                for event in emit_process(
                    &cb_agent_id,
                    &mut reg,
                    ACTIVITY_TERMINATE,
                    ProcessInfo {
                        pid,
                        name: &name,
                        exe: Some(&image),
                        ..Default::default()
                    },
                ) {
                    cb_tx.send(event);
                }
            }
        })
        .build();

    let _ = stop_trace_by_name(SESSION);
    match UserTrace::new()
        .named(SESSION.to_string())
        .enable(provider)
        .start_and_process()
    {
        Ok(_trace) => {
            tx.capability("process", "etw", "active");
            // trace 句柄保活；channel 关闭即 agent 退出，无需额外清理
            tx.closed().await
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
            // SAFETY: name_w 是以 0 结尾的 UTF-16 盘符名，buf 是栈上 256 个 u16 的可写数组，
            // 传入的容量正是 buf.len()（按字符计），系统最多写这么多；两者在调用期间都存活。
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
/// 由 mod.rs 调起：进程采集与网络采集共享同一张注册表。
pub(crate) fn seeded_registry() -> ProcessRegistry {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    let mut registry = ProcessRegistry::default();
    for (pid, proc) in sys.processes() {
        let exe = proc.exe().map(|p| p.to_string_lossy().into_owned());
        registry.seed(pid.as_u32(), &proc.name().to_string_lossy(), exe.as_deref());
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
        // SAFETY: OpenProcess 只接收整数参数，不涉及指针；空句柄表示失败，下面已检查。
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle.is_null() {
            return (None, String::new());
        }
        let cmd = command_line(handle);
        let user = username(handle).unwrap_or_default();
        // SAFETY: handle 是上面 OpenProcess 成功返回、只由本函数持有的句柄，用完关一次，之后不再使用。
        unsafe { CloseHandle(handle) };
        (cmd, user)
    }

    /// 先走 ProcessCommandLineInformation（Win 8.1+，一步到位）；
    /// 老系统（Win7/2008R2）该信息类直接报错，回落到 PEB 路径。
    fn command_line(handle: HANDLE) -> Option<String> {
        // 两条路径拿到的 UNICODE_STRING 长度都可能计入结尾 NUL，
        // 带着 \u0000 的 JSON 会被 Postgres jsonb 拒收（22P05），剥掉
        command_line_nt(handle)
            .or_else(|| command_line_peb(handle))
            .map(|s| s.trim_end_matches('\0').to_string())
    }

    /// NtQueryInformationProcess 直接返回命令行，不必手动摸 PEB。
    /// 惯例两段式：先问长度再取值，拿回 UNICODE_STRING 头 + 字符串本体。
    fn command_line_nt(handle: HANDLE) -> Option<String> {
        let mut len = 0u32;
        // SAFETY: 第一段只问长度：缓冲区传空指针、长度 0 是该 API 约定的用法，系统只写 len；
        // handle 是 describe 持有的有效进程句柄。返回的失败状态是预期的，只看 len。
        unsafe {
            NtQueryInformationProcess(handle, COMMAND_LINE_INFO, std::ptr::null_mut(), 0, &mut len)
        };
        if len == 0 {
            return None;
        }
        // 用 u64 撑起对齐，UNICODE_STRING 里有指针字段
        let mut buf = vec![0u64; len.div_ceil(8) as usize];
        // SAFETY: buf 至少有 len 字节（按 8 字节向上取整），以 Vec<u64> 分配保证 UNICODE_STRING
        // 所需的 8 字节对齐；传入的长度就是 len，系统不会写出界。
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
        // SAFETY: status 为 0 表示系统已在 buf 开头写好 UNICODE_STRING 头（len 至少容纳它），
        // buf 8 字节对齐，满足 UNICODE_STRING 的对齐；引用只在 buf 存活的本函数内使用。
        let us = unsafe { &*buf.as_ptr().cast::<UNICODE_STRING>() };
        // SAFETY: ProcessCommandLineInformation 返回的 Buffer 指向同一块 buf 中紧跟头部的字符串本体，
        // Length 是字节数且已由系统保证落在 len 之内，按 u16 读 Length / 2 个不越界；
        // buf 在 chars 使用期间存活且未被改动。依赖系统总给出非空 Buffer（长度为 0 时也指向 buf 内）。
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
        // SAFETY: pbi 是栈上已初始化的 ProcessBasicInformation（#[repr(C)]，与系统结构 x64 布局一致），
        // 传入的长度就是它的大小，系统只在调用期间写入；返回长度出参允许为空指针。
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
        // PEB 地址属于目标进程，只做地址运算交给 ReadProcessMemory，本进程不解引用
        let params: *mut core::ffi::c_void = read_mem(
            handle,
            pbi.peb_base_address
                .wrapping_byte_add(PEB_PROCESS_PARAMETERS_OFF),
        )?;
        if params.is_null() {
            return None;
        }
        let us: UNICODE_STRING = read_mem(handle, params.wrapping_byte_add(RUPP_COMMAND_LINE_OFF))?;
        if us.Buffer.is_null() || us.Length == 0 || us.Length > MAX_CMDLINE_BYTES {
            return None;
        }
        // PEB 在目标进程手里、可被它改写成奇数 Length，读取长度按本地缓冲算，不信对方给的
        let mut buf = vec![0u16; (us.Length / 2) as usize];
        let mut got = 0usize;
        // SAFETY: us.Buffer 是目标进程内的地址，只交给 ReadProcessMemory 跨进程读；读取长度正是
        // 本地 buf 的字节数，系统最多写这么多；got 为栈上出参。
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                us.Buffer.cast(),
                buf.as_mut_ptr().cast(),
                buf.len() * 2,
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
        // SAFETY: val 是 size_of::<T>() 字节的未初始化本地存储，传入的长度正是它的大小，系统最多写这么多；
        // addr 是目标进程内的地址，读失败只返回 0，不会触碰本进程内存。
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
        // SAFETY: 上面已确认 got == size_of::<T>()，val 的每个字节都已被写入；调用方只用它读指针与
        // UNICODE_STRING（整数加指针），任意字节都是这两类的合法值。
        Some(unsafe { val.assume_init() })
    }

    fn username(handle: HANDLE) -> Option<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: handle 是 describe 持有的有效进程句柄；token 是栈上出参，成功时系统写入新句柄。
        if unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) } == 0 {
            return None;
        }
        let user = token_to_username(token);
        // SAFETY: token 是上面 OpenProcessToken 成功返回、只由本函数持有的句柄，用完关一次。
        unsafe { CloseHandle(token) };
        user
    }

    /// token → SID → DOMAIN\user。两个 API 都是先问长度再取值。
    fn token_to_username(token: HANDLE) -> Option<String> {
        let mut len = 0u32;
        // SAFETY: 第一段只问长度：缓冲区传空指针、长度 0 是该 API 约定的用法，系统只写 len；
        // token 是调用方持有的有效令牌句柄。
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u64; len.div_ceil(8) as usize];
        // SAFETY: buf 至少 len 字节，以 Vec<u64> 分配保证 TOKEN_USER（含指针字段）的 8 字节对齐，
        // 传入的长度就是 len，系统不会写出界。
        if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
            == 0
        {
            return None;
        }
        // SAFETY: GetTokenInformation 成功，buf 开头是系统写好的 TOKEN_USER，且 buf 8 字节对齐；
        // 取出的 Sid 指向 buf 内部，buf 在本函数结束前存活且不再改动，后续使用都在此之内。
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };

        let (mut name_len, mut domain_len, mut sid_use) = (0u32, 0u32, 0i32);
        // SAFETY: 第一段只问长度：名称与域缓冲传空指针是 API 约定的用法，系统只写三个长度出参；
        // sid 指向仍存活的 buf，系统名传空表示本机。
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
        // SAFETY: name / domain 按上一步返回的长度（字符数，含结尾 NUL）分配，传入的容量与之相符；
        // sid 仍指向存活的 buf；所有出参都指向栈上变量。
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
        // SAFETY: 测试里打开自己的进程：OpenProcess 只接收整数参数，空句柄下面已断言。
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                0,
                std::process::id(),
            )
        };
        assert!(!handle.is_null(), "应能打开自己的进程句柄");
        let cmd = super::inspect::command_line_peb(handle);
        // SAFETY: handle 是上面成功打开、只由本测试持有的句柄，command_line_peb 只借用不关闭，这里关一次。
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
