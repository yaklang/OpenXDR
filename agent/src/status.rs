//! 本机只读状态端点（协议与文案见 status_proto），以及托盘、登录提示的自启布置。

use crate::health::Health;
use crate::status_proto::{self, Status};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 查隔离状态要起 nft 或开 WFP 会话；每个登录会话的托盘 15 秒来问一次，结果缓存 10 秒
const ISOLATION_TTL: Duration = Duration::from_secs(10);

type IsolationCache = Arc<Mutex<Option<(Instant, bool)>>>;

fn snapshot(health: &Health, cache: &IsolationCache) -> Status {
    let isolated = {
        let mut cached = cache.lock().unwrap_or_else(|e| e.into_inner());
        match *cached {
            Some((at, value)) if at.elapsed() < ISOLATION_TTL => value,
            _ => {
                let value = crate::respond::host_isolated();
                *cached = Some((Instant::now(), value));
                value
            }
        }
    };
    Status {
        version: env!("CARGO_PKG_VERSION").into(),
        last_contact_unix_ms: health.last_contact_ms(),
        collection: health.collection(),
        isolated,
    }
}

/// 一次连接的回复：一行 JSON。查隔离会起进程或开 WFP 会话，放到阻塞线程上
async fn reply(health: Arc<Health>, cache: IsolationCache) -> Option<Vec<u8>> {
    let status = tokio::task::spawn_blocking(move || snapshot(&health, &cache))
        .await
        .ok()?;
    let mut line = serde_json::to_vec(&status).ok()?;
    line.push(b'\n');
    Some(line)
}

/// 开本机状态端点。起不来（非 root 调试、端点被占）只是没有托盘与状态命令可用，采集照常
pub async fn serve(health: Arc<Health>) {
    #[cfg(unix)]
    let result = listen(health, status_proto::SOCKET).await;
    #[cfg(not(unix))]
    let result = listen(health).await;
    if let Err(e) = result {
        eprintln!("本机状态端点不可用：{e}");
    }
}

#[cfg(unix)]
async fn listen(health: Arc<Health>, path: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::AsyncWriteExt;

    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
    // 只读、只有有限信息：托盘跑在普通用户的会话里，本机任何用户都得连得上
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    let cache = IsolationCache::default();
    loop {
        let mut stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                // 描述符耗尽之类的瞬时错误：等一下再接，不让端点就此停掉
                eprintln!("本机状态端点接受连接失败：{e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let (health, cache) = (health.clone(), cache.clone());
        tokio::spawn(async move {
            if let Some(line) = reply(health, cache).await {
                let _ = tokio::time::timeout(Duration::from_secs(2), stream.write_all(&line)).await;
            }
        });
    }
}

#[cfg(windows)]
async fn listen(health: Arc<Health>) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::windows::named_pipe::ServerOptions;

    // 只出不进：客户端只能读。默认安全描述符给 Everyone 读权限，普通用户会话里的托盘连得上。
    // 第一个实例要求管道还不存在：别的进程抢先建了同名管道冒充 agent，这里就起不来并报出来
    let options = |first: bool| {
        let mut o = ServerOptions::new();
        o.first_pipe_instance(first)
            .access_inbound(false)
            .access_outbound(true)
            .reject_remote_clients(true);
        o
    };
    let mut server = options(true).create(status_proto::PIPE)?;
    let cache = IsolationCache::default();
    loop {
        if let Err(e) = server.connect().await {
            eprintln!("本机状态端点等待连接失败：{e}");
            tokio::time::sleep(Duration::from_secs(1)).await;
            server = options(false).create(status_proto::PIPE)?;
            continue;
        }
        let mut client = std::mem::replace(&mut server, options(false).create(status_proto::PIPE)?);
        let (health, cache) = (health.clone(), cache.clone());
        tokio::spawn(async move {
            if let Some(line) = reply(health, cache).await {
                let _ = tokio::time::timeout(Duration::from_secs(2), client.write_all(&line)).await;
            }
        });
    }
}

#[cfg(not(any(unix, windows)))]
async fn listen(_health: Arc<Health>) -> std::io::Result<()> {
    Err(std::io::Error::other("本平台没有本机状态端点"))
}

/// `openxdr-agent status [--brief]`：给主机使用者看的状态。退出码 0 正常、1 需要留意、2 要紧
pub fn print(brief: bool) -> i32 {
    let s = status_proto::describe(status_proto::fetch().as_ref(), status_proto::now_ms());
    if brief {
        match s.level {
            status_proto::Level::Ok => println!("[OpenXDR] {}", s.title),
            _ => println!("[OpenXDR] {}：{}", s.title, s.detail),
        }
    } else {
        println!("{}\n{}", s.title, s.detail);
    }
    s.level as i32
}

/// 当前程序的路径。升级换掉文件后 /proc/self/exe 会带 " (deleted)"
#[cfg(unix)]
fn own_exe() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let text = exe.to_string_lossy();
    Some(text.strip_suffix(" (deleted)").unwrap_or(&text).into())
}

/// 内容不同才写，免得每次启动都改动文件时间
#[cfg(unix)]
fn write_if_changed(path: &str, content: &str) {
    if std::fs::read_to_string(path).ok().as_deref() == Some(content) {
        return;
    }
    if let Err(e) = std::fs::write(path, content) {
        eprintln!("写入 {path} 失败：{e}");
    }
}

/// 布置主机使用者看得到的入口：交互式登录打印一行防护状态；agent 旁边有托盘程序时让桌面会话自启它，
/// 托盘程序不在了就撤掉自启。每次启动都对一遍，升级上来的主机不用重装
#[cfg(unix)]
pub fn provision() {
    // SAFETY: geteuid 没有前置条件、不会失败
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let Some(exe) = own_exe() else {
        return;
    };
    if std::path::Path::new("/etc/profile.d").is_dir() {
        write_if_changed(
            "/etc/profile.d/openxdr-agent.sh",
            &format!(
                "# OpenXDR：交互式登录时显示本机安全防护状态（由 openxdr-agent 维护，改动会被覆盖）\n\
                 case $- in *i*) [ -x '{0}' ] && '{0}' status --brief 2>/dev/null ;; esac\n",
                exe.display()
            ),
        );
    }
    let autostart = "/etc/xdg/autostart/openxdr-tray.desktop";
    let tray = exe.with_file_name("openxdr-tray");
    if tray.is_file() && std::path::Path::new("/etc/xdg/autostart").is_dir() {
        write_if_changed(
            autostart,
            &format!(
                "[Desktop Entry]\nType=Application\nName=OpenXDR\nComment=本机安全防护状态\n\
                 Exec={}\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n",
                tray.display()
            ),
        );
    } else {
        let _ = std::fs::remove_file(autostart);
    }
}

/// Windows：%ProgramFiles%\OpenXDR\openxdr-tray.exe 在时，在 HKLM 的 Run 里登记，所有用户登录都起托盘；不在就删掉登记。
/// 托盘不放在 agent 旁边：agent 目录（%ProgramData%\OpenXDR）放着私钥，只留 SYSTEM 与管理员，
/// 普通用户执行不了；Program Files 普通用户能读能执行、只有管理员能写
#[cfg(windows)]
pub fn provision() {
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, REG_SZ, RegDeleteKeyValueW, RegSetKeyValueW,
    };
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Run");
    let name = wide("OpenXDR");
    let Some(programs) = std::env::var_os("ProgramFiles") else {
        return;
    };
    let tray = std::path::Path::new(&programs).join(r"OpenXDR\openxdr-tray.exe");
    if tray.is_file() {
        let value = wide(&format!("\"{}\"", tray.display()));
        // SAFETY: key、name、value 都是以 0 结尾的 UTF-16 缓冲，调用期间存活；长度按字节传，含结尾 0
        let code = unsafe {
            RegSetKeyValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                name.as_ptr(),
                REG_SZ,
                value.as_ptr().cast(),
                (value.len() * 2) as u32,
            )
        };
        if code != 0 {
            eprintln!("登记托盘自启失败：{code}");
        }
    } else {
        // SAFETY: 同上；值不存在时返回错误码，忽略即可
        unsafe {
            RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), name.as_ptr());
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub fn provision() {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reports_contact_and_collection() {
        let health = Health::new();
        let s = snapshot(&health, &IsolationCache::default());
        assert_eq!(s.last_contact_unix_ms, 0);
        assert_eq!(s.collection, status_proto::Collection::Starting);
        let generation = health.begin(&[("process", true)]);
        health.capability(generation, "process", "ebpf", "active");
        assert_eq!(health.collection(), status_proto::Collection::Ok);
        health.capability(generation, "process", "ebpf", "degraded");
        assert_eq!(health.collection(), status_proto::Collection::Degraded);
    }

    /// 端点真的写一行 JSON，客户端读得懂，socket 对所有用户可连
    #[tokio::test]
    async fn endpoint_serves_one_status_line() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("openxdr-status-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.sock").to_string_lossy().into_owned();
        let health = Health::new();
        let generation = health.begin(&[("process", true)]);
        health.capability(generation, "process", "ebpf", "active");
        let server = tokio::spawn({
            let path = path.clone();
            async move { listen(health, &path).await }
        });
        let mut text = None;
        for _ in 0..50 {
            let p = path.clone();
            text = tokio::task::spawn_blocking(move || status_proto::read_endpoint(&p))
                .await
                .unwrap();
            if text.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let status: Status = serde_json::from_str(text.expect("连不上端点").trim()).unwrap();
        assert_eq!(status.collection, status_proto::Collection::Ok);
        assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o666);
        server.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn isolation_check_is_cached() {
        let cache = IsolationCache::default();
        *cache.lock().unwrap() = Some((Instant::now(), true));
        assert!(
            snapshot(&Health::new(), &cache).isolated,
            "缓存未过期就不再查内核"
        );
    }
}
