//! Windows 托盘：Shell_NotifyIcon，图标用系统自带的盾牌、警告、错误图标，不打包任何资源。
//! 一个隐藏窗口收托盘消息与 15 秒的定时器；资源管理器重启后广播 TaskbarCreated，收到就把图标重新加回去。

use crate::status_proto::{Level, Summary};
use crate::{POLL, current, worth_notifying};
use std::cell::RefCell;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, WPARAM,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_ERROR, NIIF_INFO, NIIF_WARNING, NIM_ADD,
    NIM_MODIFY, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, IDI_ERROR, IDI_SHIELD,
    IDI_WARNING, LoadIconW, MSG, RegisterClassW, RegisterWindowMessageW, SetTimer,
    TranslateMessage, WM_APP, WM_CONTEXTMENU, WM_LBUTTONUP, WM_RBUTTONUP, WM_TIMER, WNDCLASSW,
};

const WM_TRAY: u32 = WM_APP + 1;
const TIMER_ID: usize = 1;

thread_local! {
    /// 窗口过程与消息循环在同一个线程上，状态放线程局部即可
    static SHOWN: RefCell<Option<Summary>> = const { RefCell::new(None) };
    static TASKBAR_CREATED: RefCell<u32> = const { RefCell::new(0) };
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// 截到定长缓冲（留结尾 0），按 UTF-16 单元截
fn fill(dst: &mut [u16], s: &str) {
    let src: Vec<u16> = s.encode_utf16().take(dst.len() - 1).collect();
    dst[..src.len()].copy_from_slice(&src);
    dst[src.len()] = 0;
}

fn base(hwnd: HWND) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: 1,
        ..Default::default()
    }
}

fn show(hwnd: HWND, s: &Summary, add: bool) {
    let icon = match s.level {
        Level::Ok => IDI_SHIELD,
        Level::Warn => IDI_WARNING,
        Level::Alert => IDI_ERROR,
    };
    let mut nid = base(hwnd);
    nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    nid.uCallbackMessage = WM_TRAY;
    // SAFETY: 传空模块句柄与系统预定义图标 ID，取的是系统共享图标，不需要释放
    nid.hIcon = unsafe { LoadIconW(null_mut(), icon) };
    fill(&mut nid.szTip, &format!("OpenXDR：{}", s.title));
    // SAFETY: nid 是完整初始化的栈上结构，cbSize 与实际大小一致，调用期间有效
    unsafe {
        Shell_NotifyIconW(if add { NIM_ADD } else { NIM_MODIFY }, &nid);
    }
}

fn balloon(hwnd: HWND, s: &Summary) {
    let mut nid = base(hwnd);
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = match s.level {
        Level::Ok => NIIF_INFO,
        Level::Warn => NIIF_WARNING,
        Level::Alert => NIIF_ERROR,
    };
    fill(&mut nid.szInfoTitle, s.title);
    fill(&mut nid.szInfo, &s.detail);
    // SAFETY: 同上
    unsafe {
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
}

/// 读一次状态并刷新图标；add 为真时重新加图标（启动、资源管理器重启）
fn refresh(hwnd: HWND, add: bool) {
    let now = current();
    let before = SHOWN.with(|s| s.borrow().clone());
    if add || before.as_ref() != Some(&now) {
        show(hwnd, &now, add);
    }
    if worth_notifying(before.as_ref(), &now) {
        balloon(hwnd, &now);
    }
    SHOWN.with(|s| *s.borrow_mut() = Some(now));
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let taskbar_created = TASKBAR_CREATED.with(|t| *t.borrow());
    match msg {
        WM_TIMER => refresh(hwnd, false),
        // 点图标：把当前状态用气泡再说一遍
        WM_TRAY
            if matches!(
                lparam as u32 & 0xffff,
                WM_LBUTTONUP | WM_RBUTTONUP | WM_CONTEXTMENU
            ) =>
        {
            if let Some(s) = SHOWN.with(|s| s.borrow().clone()) {
                balloon(hwnd, &s);
            }
        }
        m if m != 0 && m == taskbar_created => refresh(hwnd, true),
        // SAFETY: 原样转交给系统的默认窗口过程
        _ => return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
    0
}

pub fn run() {
    let mutex_name = wide(r"Local\OpenXDR-tray");
    // SAFETY: 名字是以 0 结尾的 UTF-16；句柄不关，随进程退出释放，用来占住“本会话已有托盘”
    unsafe {
        CreateMutexW(null(), 0, mutex_name.as_ptr());
        if GetLastError() == ERROR_ALREADY_EXISTS {
            return;
        }
    }
    let class = wide("OpenXDRTray");
    // SAFETY: 传空取当前进程的模块句柄
    let instance = unsafe { GetModuleHandleW(null()) };
    let wc = WNDCLASSW {
        lpfnWndProc: Some(wndproc),
        hInstance: instance,
        lpszClassName: class.as_ptr(),
        ..Default::default()
    };
    // SAFETY: wc 与它引用的类名缓冲在调用期间有效；窗口不带 WS_VISIBLE，始终隐藏。
    // 用普通顶层窗口而不是仅消息窗口：仅消息窗口收不到 TaskbarCreated 广播
    let hwnd = unsafe {
        RegisterClassW(&wc);
        CreateWindowExW(
            0,
            class.as_ptr(),
            class.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            instance,
            null(),
        )
    };
    if hwnd.is_null() {
        return;
    }
    let taskbar = wide("TaskbarCreated");
    // SAFETY: 名字是以 0 结尾的 UTF-16
    let id = unsafe { RegisterWindowMessageW(taskbar.as_ptr()) };
    TASKBAR_CREATED.with(|t| *t.borrow_mut() = id);
    refresh(hwnd, true);
    // SAFETY: hwnd 是上面创建的窗口；不带回调，定时器消息走窗口过程
    unsafe {
        SetTimer(hwnd, TIMER_ID, POLL.as_millis() as u32, None);
    }
    let mut msg = MSG::default();
    // SAFETY: 标准消息循环，msg 是栈上出参
    unsafe {
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
