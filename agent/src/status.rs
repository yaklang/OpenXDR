//! 本机只读状态端点（协议与文案见 status_proto），以及托盘、登录提示的自启布置。

use crate::health::Health;
use crate::status_proto::{self, Status};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 查隔离状态要起 nft 或开 WFP 会话；每个登录会话的托盘 15 秒来问一次，结果缓存 10 秒
const ISOLATION_TTL: Duration = Duration::from_secs(10);
/// 本机状态端点并发处理连接上限，超限时直接关闭新连接，防打满任务或阻塞线程池
const MAX_CONCURRENT_STATUS: usize = 16;
/// 单次状态查询（含获取单飞锁与隔离状态探针刷新）的总截止时间，防底层探针卡死占满并发槽位
const STATUS_REPLY_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Default)]
struct IsolationCache {
    inner: Arc<std::sync::Mutex<IsolationState>>,
}

#[derive(Default)]
struct IsolationState {
    cached: Option<(Instant, bool)>,
    /// 非空表示全局已有 1 个后台探针在运行；等待者在锁内直接克隆 watch::Receiver，
    /// 探针完成时写入缓存、清空 in_flight 并通过 watch 发送结果，天然无丢唤醒窗口
    in_flight: Option<tokio::sync::watch::Receiver<Option<bool>>>,
}

enum ProbeLookup {
    Hit(bool),
    Wait(tokio::sync::watch::Receiver<Option<bool>>),
}

impl IsolationCache {
    #[cfg(all(test, unix))]
    fn seed(&self, at: Instant, value: bool) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).cached = Some((at, value));
    }

    #[cfg(all(test, unix))]
    fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cached
            .is_none()
    }

    /// 命中未过期缓存时直接返回 `Hit`；否则复用在途探针或在全局唯一槽位启动新探针，
    /// 返回的 `Receiver` 在锁内克隆，无论探针在调用方 `await` 之前还是之后完成都不会丢唤醒。
    fn lookup_or_spawn<F>(&self, probe: F) -> ProbeLookup
    where
        F: FnOnce() -> bool + Send + 'static,
    {
        let (rx, tx_and_probe) = {
            let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((at, value)) = state.cached
                && at.elapsed() < ISOLATION_TTL
            {
                return ProbeLookup::Hit(value);
            }
            if let Some(existing_rx) = state.in_flight.clone() {
                (existing_rx, None)
            } else {
                let (tx, rx) = tokio::sync::watch::channel(None);
                state.in_flight = Some(rx.clone());
                (rx, Some((tx, probe)))
            }
        };

        if let Some((tx, probe_fn)) = tx_and_probe {
            let inner = self.inner.clone();
            tokio::spawn(async move {
                let result = tokio::task::spawn_blocking(probe_fn).await;
                let value = {
                    let mut state = inner.lock().unwrap_or_else(|e| e.into_inner());
                    state.in_flight = None;
                    match result {
                        Ok(v) => {
                            state.cached = Some((Instant::now(), v));
                            Some(v)
                        }
                        Err(_) => None,
                    }
                };
                // 成功则写入 Some(v) 唤醒所有等待者；若探针异常退出则直接释放 tx，等待者收到通道关闭后降级返回 false
                if let Some(v) = value {
                    let _ = tx.send(Some(v));
                }
            });
        }

        ProbeLookup::Wait(rx)
    }
}

/// 读取隔离状态：命中未过期缓存时直接返回，不进 blocking pool；
/// 过期或未命中时保证全局同一时刻至多 1 个后台 `spawn_blocking` 探针在运行。
/// 调用方超时取消只放弃本次等待，不会取消也不会再重复启动新探针；
/// 探针真正完成后由后台任务写回缓存、清除 `in_flight` 并经 watch 广播结果。
async fn isolated_with<F>(cache: &IsolationCache, probe: F) -> bool
where
    F: FnOnce() -> bool + Send + 'static,
{
    match cache.lookup_or_spawn(probe) {
        ProbeLookup::Hit(value) => value,
        ProbeLookup::Wait(mut rx) => match rx.wait_for(|v| v.is_some()).await {
            Ok(val) => val.unwrap_or(false),
            Err(_) => false,
        },
    }
}

async fn snapshot_with<F>(health: &Health, cache: &IsolationCache, probe: F) -> Status
where
    F: FnOnce() -> bool + Send + 'static,
{
    let isolated = isolated_with(cache, probe).await;
    Status {
        version: env!("CARGO_PKG_VERSION").into(),
        last_contact_unix_ms: health.last_contact_ms(),
        collection: health.collection(),
        isolated,
    }
}

#[cfg(all(test, unix))]
async fn snapshot(health: &Health, cache: &IsolationCache) -> Status {
    snapshot_with(health, cache, crate::respond::host_isolated).await
}

/// 一次连接的回复：一行 JSON。缓存命中全程纯异步；仅缓存过期时单飞进阻塞线程，
/// 整个等待（含排队等锁与探针执行）受 timeout 约束，超时返回 None 直接关闭连接释放槽位。
async fn reply_with<F>(
    health: Arc<Health>,
    cache: IsolationCache,
    timeout: Duration,
    probe: F,
) -> Option<Vec<u8>>
where
    F: FnOnce() -> bool + Send + 'static,
{
    let status = tokio::time::timeout(timeout, snapshot_with(&health, &cache, probe))
        .await
        .ok()?;
    let mut line = serde_json::to_vec(&status).ok()?;
    line.push(b'\n');
    Some(line)
}

async fn reply(health: Arc<Health>, cache: IsolationCache) -> Option<Vec<u8>> {
    reply_with(
        health,
        cache,
        STATUS_REPLY_TIMEOUT,
        crate::respond::host_isolated,
    )
    .await
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
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_STATUS));
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
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            // 超过并发上限时直接丢弃新连接，避免本机恶意并发打满任务或阻塞线程池
            drop(stream);
            continue;
        };
        let (health, cache) = (health.clone(), cache.clone());
        tokio::spawn(async move {
            let _permit = permit;
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
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_STATUS));
    loop {
        if let Err(e) = server.connect().await {
            eprintln!("本机状态端点等待连接失败：{e}");
            tokio::time::sleep(Duration::from_secs(1)).await;
            server = options(false).create(status_proto::PIPE)?;
            continue;
        }
        let mut client = std::mem::replace(&mut server, options(false).create(status_proto::PIPE)?);
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(client);
            continue;
        };
        let (health, cache) = (health.clone(), cache.clone());
        tokio::spawn(async move {
            let _permit = permit;
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

    #[tokio::test]
    async fn snapshot_reports_contact_and_collection() {
        let health = Health::new();
        let s = snapshot(&health, &IsolationCache::default()).await;
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

    #[tokio::test]
    async fn isolation_check_is_cached_and_singleflight() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cache = IsolationCache::default();
        cache.seed(Instant::now(), true);
        assert!(
            snapshot(&Health::new(), &cache).await.isolated,
            "缓存未过期就不再查内核"
        );

        // 并发缓存未命中时只允许单飞刷新一次，避免惊群占满 blocking pool
        let fresh_cache = IsolationCache::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let c = fresh_cache.clone();
            let calls = calls.clone();
            tasks.push(tokio::spawn(async move {
                isolated_with(&c, move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(30));
                    true
                })
                .await
            }));
        }
        for t in tasks {
            assert!(t.await.unwrap());
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "并发过期刷新应单飞执行一次"
        );
    }

    #[tokio::test]
    async fn reply_times_out_without_spawning_duplicate_probes_and_returns_latest_after_completion()
    {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let health = Health::new();
        let cache = IsolationCache::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<bool>();
        let release_rx = Arc::new(std::sync::Mutex::new(release_rx));

        // 探针卡住期间连续发起 5 次超时请求：每次都必须在 deadline 内返回 None，
        // 且全过程后台探针只启动 1 次，绝不因超时取消而堆积多个 spawn_blocking。
        for _ in 0..5 {
            let started = Instant::now();
            let calls = calls.clone();
            let rx = release_rx.clone();
            let timed_out = reply_with(
                health.clone(),
                cache.clone(),
                Duration::from_millis(50),
                move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    rx.lock().unwrap().recv().unwrap_or(false)
                },
            )
            .await;
            assert!(timed_out.is_none(), "探针卡住时应超时返回 None 释放槽位");
            assert!(
                started.elapsed() < Duration::from_millis(250),
                "超时返回不应等待卡住的探针结束"
            );
            assert!(cache.is_empty(), "探针未完成前不得写入错误缓存");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "探针卡住期间连续多次超时请求，全过程探针函数只能被调用 1 次"
        );

        // 放行唯一在途探针返回 true，下一次请求应立刻拿到最新结果且仍不再启动新探针
        release_tx.send(true).unwrap();
        let line = reply_with(health, cache, Duration::from_secs(2), {
            let calls = calls.clone();
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                false
            }
        })
        .await
        .expect("探针完成后应立即返回最新状态");
        let status: Status = serde_json::from_slice(&line).unwrap();
        assert!(status.isolated, "应拿到后台探针完成写入的最新结果 true");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "探针完成后应直接命中刷新结果，全程探针仅调用 1 次"
        );
    }

    #[tokio::test]
    async fn singleflight_waiter_does_not_lose_wakeup_when_probe_finishes_before_await() {
        let cache = IsolationCache::default();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<bool>();

        // 1. 发起者启动唯一在途探针（先阻塞在 channel 上）
        let ProbeLookup::Wait(mut initiator_rx) =
            cache.lookup_or_spawn(move || release_rx.recv().unwrap_or(false))
        else {
            panic!("首次查询缓存应未命中并进入在途等待");
        };

        // 2. 新等待者在锁内拿到 watch::Receiver，但故意先不进入 await
        let ProbeLookup::Wait(mut late_waiter_rx) = cache.lookup_or_spawn(|| {
            panic!("已有在途探针时不得启动第二个探针");
        }) else {
            panic!("在途期间新等待者应拿到共享 Receiver");
        };

        // 3. 放行探针并等待发起者确认后台任务已彻底写完缓存、发完结果并释放 Sender
        release_tx.send(true).unwrap();
        let init_val = tokio::time::timeout(
            Duration::from_secs(1),
            initiator_rx.wait_for(|v| v.is_some()),
        )
        .await
        .expect("发起者不应超时")
        .expect("探针成功时 watch 通道不应关闭失败");
        assert_eq!(*init_val, Some(true));
        drop(init_val);

        // 确保后台任务已清空 in_flight 且写回缓存
        assert!(!cache.is_empty(), "探针完成后应已写回缓存");

        // 4. 此时等待者才开始 await：使用 watch 后即使探针早已完成，也应立刻拿到最新值、不丢唤醒、不超时
        let started = Instant::now();
        let waiter_val = tokio::time::timeout(
            Duration::from_millis(100),
            late_waiter_rx.wait_for(|v| v.is_some()),
        )
        .await
        .expect("探针在 await 之前完成时，等待者绝不能丢唤醒或超时")
        .expect("应成功读取已发送的最新状态");
        assert_eq!(*waiter_val, Some(true));
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "应立刻拿到结果，不应等待超时"
        );
    }
}
