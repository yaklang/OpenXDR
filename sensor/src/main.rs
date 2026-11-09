//! OpenXDR 流量探针：镜像口或网关网卡上的全流量元数据采集。
//!
//! 每 worker 一个 AF_PACKET 抓包环（FANOUT 按流哈希），独立无锁流表，
//! 结束的会话经 channel 交给异步上报任务，批量 gRPC 推给 server。
//! 接入、升级与状态上报与 agent 同一套机制：一行安装签发探针证书，注册时按哈希自动升级，
//! 抓包状态与 agent 的采集状态同口径上报。

mod capture;
mod decode;
mod enroll;
mod flow;
mod health;
mod proto_id;
mod report;
mod tls;
mod upgrade;
mod x509;

// 生成代码不归我们管，新版 clippy 对 tonic 的 async_trait 展开报 double_must_use
#[allow(clippy::double_must_use)]
pub mod pb {
    tonic::include_proto!("openxdr.sensor.v1");
}

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use capture::Capture;
#[cfg(target_os = "linux")]
use capture::afpacket::{AfPacket, RingConfig};
#[cfg(feature = "xdp")]
use capture::afxdp::AfXdp;
#[cfg(feature = "xdp")]
use capture::xdp_loader::XdpProgram;
use flow::FlowTable;
use health::Stats;

/// 上报队列容量：server 断线时的缓冲，满了丢弃并计数——探针绝不因为上报慢而丢包
const REPORT_QUEUE: usize = 65536;

/// 本平台可选的抓包后端，第一个是默认
#[cfg(target_os = "linux")]
const BACKENDS: &[&str] = &["afpacket", "afxdp"];
#[cfg(windows)]
const BACKENDS: &[&str] = &["pktmon"];
#[cfg(target_os = "linux")]
const DEFAULT_IFACE: &str = "eth0";
/// Windows 默认抓所有网卡；SENSOR_IFACE 填网卡名或描述里的一段
#[cfg(windows)]
const DEFAULT_IFACE: &str = "all";

/// 运行统计打印间隔
const STATS_INTERVAL: Duration = Duration::from_secs(10);

/// 退出前推完在途会话的最长等待
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

fn main() {
    #[cfg(windows)]
    enroll::load_env_file();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["version"] => println!("{}", env!("CARGO_PKG_VERSION")),
        // 列出能抓的网卡；系统没有 Packet Monitor 实时 API 时报原因并以 1 退出，安装脚本据此拦下
        #[cfg(windows)]
        ["interfaces"] => match capture::pktmon::PktMon::list() {
            Ok(nics) => nics.iter().for_each(|n| println!("{n}")),
            Err(e) => exit(&e.to_string(), 1),
        },
        ["enroll-request", dir] => match enroll::request(dir.as_ref()) {
            Ok(json) => println!("{json}"),
            Err(e) => exit(&format!("生成接入请求失败：{e}"), 1),
        },
        ["enroll-apply", dir] => {
            if let Err(e) = enroll::apply(dir.as_ref(), std::io::stdin()) {
                exit(&format!("写入接入配置失败：{e}"), 1);
            }
        }
        [] => match sensor() {
            Ok(code) => std::process::exit(code),
            Err(e) => exit(&format!("sensor 退出：{e}"), 1),
        },
        _ => exit(
            "用法：openxdr-sensor [version | enroll-request <目录> | enroll-apply <目录>]",
            2,
        ),
    }
}

fn exit(msg: &str, code: i32) -> ! {
    eprintln!("{msg}");
    std::process::exit(code)
}

#[tokio::main]
async fn sensor() -> anyhow::Result<i32> {
    let iface = std::env::var("SENSOR_IFACE").unwrap_or_else(|_| DEFAULT_IFACE.into());
    let server = std::env::var("OPENXDR_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8081".into());
    // Windows 只有一个 PktMon 会话，多个 worker 只会重复收同一份包
    let workers: u16 = if cfg!(windows) {
        1
    } else {
        env_or("SENSOR_WORKERS", || {
            std::thread::available_parallelism().map_or(1, |n| n.get() as u16)
        })
    };

    // FANOUT 组 ID 用 pid，避免同机多实例串台；最低位置 1 保证非 0
    #[cfg(target_os = "linux")]
    let fanout_group = std::process::id() as u16 | 1;
    let running = Arc::new(AtomicBool::new(true));
    let (tx, rx) = async_channel::bounded(REPORT_QUEUE);

    let backend = std::env::var("SENSOR_BACKEND").unwrap_or_else(|_| BACKENDS[0].into());
    if !BACKENDS.contains(&backend.as_str()) {
        anyhow::bail!("SENSOR_BACKEND 只能是 {}：{backend}", BACKENDS.join(" 或 "));
    }
    eprintln!("sensor 启动: iface={iface} workers={workers} backend={backend} server={server}");
    let health = health::Health::new(&iface, &backend, workers);

    // AF_XDP 要先挂 XDP 程序，socket 才收得到包；程序句柄要活到进程退出
    #[cfg(feature = "xdp")]
    let mut xdp = if backend == "afxdp" {
        Some(XdpProgram::attach(&iface).map_err(|e| anyhow::anyhow!("加载 XDP 程序失败: {e}"))?)
    } else {
        None
    };
    #[cfg(not(feature = "xdp"))]
    if backend == "afxdp" {
        anyhow::bail!(
            "本次构建未启用 xdp 特性，请用 --features xdp 重新编译，或改用 afpacket 后端"
        );
    }

    let mut handles = Vec::with_capacity(workers as usize);
    for id in 0..workers {
        #[cfg(feature = "xdp")]
        let cap = open_capture(&iface, id, fanout_group, xdp.as_mut())?;
        #[cfg(all(target_os = "linux", not(feature = "xdp")))]
        let cap: Box<dyn Capture + Send> = Box::new(AfPacket::open(
            &iface,
            &RingConfig::default(),
            fanout_group,
        )?);
        #[cfg(windows)]
        let cap: Box<dyn Capture + Send> = {
            let pktmon = capture::pktmon::PktMon::open(&iface)?;
            eprintln!("抓包网卡：{}", pktmon.interfaces.join("；"));
            Box::new(pktmon)
        };

        let (running, tx, stats) = (running.clone(), tx.clone(), health.stats.clone());
        stats.workers_alive.fetch_add(1, Ordering::Relaxed);
        handles.push(std::thread::spawn(move || {
            if let Err(e) = worker(id, cap, running, tx, &stats) {
                eprintln!("worker {id} 退出: {e}");
            }
            stats.workers_alive.fetch_sub(1, Ordering::Relaxed);
        }));
    }
    drop(tx); // 只保留 worker 持有的发送端，全部退出时上报侧才能收到关闭

    let mut reporting = tokio::spawn(report::run(server.clone(), rx.clone(), health.clone()));
    let code = tokio::select! {
        result = &mut reporting => match result {
            Ok(true) => upgrade::EXIT_UPGRADED,
            // 抓包线程全部退出：非零退出交给 systemd 重启，而不是挂着一个什么都不抓的进程
            _ => 1,
        },
        _ = stop_signal() => {
            eprintln!("收到退出信号");
            0
        }
    };

    // 收尾：停抓包，worker 把流表里的在途会话倒进队列后退出，队列随之关闭
    running.store(false, Ordering::Relaxed);
    let joined = tokio::task::spawn_blocking(move || {
        for h in handles {
            let _ = h.join();
        }
    });
    let drain = async {
        let _ = joined.await;
        if reporting.is_finished() {
            report::flush(&server, rx, health.stats.clone()).await;
        } else {
            // 上报循环仍在：队列关闭后它推完剩下的会话就会返回
            let _ = reporting.await;
        }
    };
    if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
        eprintln!("推送在途会话超时，放弃剩余会话");
    }
    Ok(code)
}

#[cfg(windows)]
async fn stop_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(unix)]
async fn stop_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut terminate), Ok(mut interrupt)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        exit("无法监听停止信号", 1);
    };
    tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} }
}

/// 按后端开一个抓包句柄。afxdp 下 worker 号即网卡队列号，
/// socket 必须登记进 XSKMAP，XDP 程序才知道往哪儿 redirect。
#[cfg(feature = "xdp")]
fn open_capture(
    iface: &str,
    id: u16,
    fanout_group: u16,
    xdp: Option<&mut XdpProgram>,
) -> anyhow::Result<Box<dyn Capture + Send>> {
    let Some(program) = xdp else {
        return Ok(Box::new(AfPacket::open(
            iface,
            &RingConfig::default(),
            fanout_group,
        )?));
    };
    let cfg = capture::afxdp::Config {
        queue_id: id as u32,
        ..Default::default()
    };
    let socket = AfXdp::open(iface, &cfg)?;
    program
        .register(id as u32, &socket)
        .map_err(|e| anyhow::anyhow!("注册 AF_XDP socket 失败: {e}"))?;
    Ok(Box::new(socket))
}

fn worker(
    id: u16,
    mut cap: Box<dyn Capture + Send>,
    running: Arc<AtomicBool>,
    tx: async_channel::Sender<pb::FlowRecord>,
    stats: &Stats,
) -> anyhow::Result<()> {
    let mut table = FlowTable::new(&flow::Config::default());
    let mut expired = Vec::new();
    let mut last_ts_ns = 0u64;
    let mut queue_drops = 0u64;
    let mut packets = 0u64;
    let mut exported = 0u64;
    let mut kernel_drops = 0u64;
    let mut last_stats = std::time::Instant::now();

    while running.load(Ordering::Relaxed) {
        let mut batch_packets = 0u64;
        cap.poll_batch(&mut |frame, ts_ns| {
            batch_packets += 1;
            last_ts_ns = ts_ns;
            let Some(pkt) = decode::decode(frame) else {
                return;
            };
            if let Some((flow, forward)) = table.update(&pkt, ts_ns) {
                proto_id::probe(flow, &pkt);
                proto_id::track_tls_client(flow, &pkt, forward == flow.client_is_a);
            }
        })?;
        packets += batch_packets;
        stats.packets.fetch_add(batch_packets, Ordering::Relaxed);

        table.expire(last_ts_ns, &mut expired);
        for f in expired.drain(..) {
            exported += 1;
            stats.flows.fetch_add(1, Ordering::Relaxed);
            // 上报队列满时丢弃会话记录，绝不阻塞抓包线程
            if tx.try_send(report::to_record(&f)).is_err() {
                queue_drops += 1;
                stats.queue_drops.fetch_add(1, Ordering::Relaxed);
            }
        }
        // 各 worker 只往共享计数上加自己的增量
        let k = cap.dropped();
        stats
            .kernel_drops
            .fetch_add(k.saturating_sub(kernel_drops), Ordering::Relaxed);
        kernel_drops = k;

        if last_stats.elapsed() >= STATS_INTERVAL {
            eprintln!(
                "worker {id}: packets={packets} flows={} exported={exported} \
                 kernel_drops={kernel_drops} queue_drops={queue_drops}",
                table.len(),
            );
            last_stats = std::time::Instant::now();
        }
    }

    table.drain_all(&mut expired);
    for f in expired.drain(..) {
        let _ = tx.try_send(report::to_record(&f));
    }
    eprintln!(
        "worker {id} 退出: flows={} kernel_drops={kernel_drops} queue_drops={queue_drops}",
        table.len(),
    );
    Ok(())
}

fn env_or<T: std::str::FromStr>(key: &str, default: impl FnOnce() -> T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(default)
}
