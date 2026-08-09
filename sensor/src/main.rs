//! OpenXDR 流量探针：核心交换机镜像口全流量元数据采集。
//!
//! 每 worker 一个 AF_PACKET 抓包环（FANOUT 按流哈希），独立无锁流表，
//! 结束的会话经 channel 交给异步上报任务，批量 gRPC 推给 server。

mod capture;
mod decode;
mod flow;
mod proto_id;
mod report;
mod tls;
mod x509;

pub mod pb {
    tonic::include_proto!("openxdr.sensor.v1");
}

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use capture::Capture;
use capture::afpacket::{AfPacket, RingConfig};
#[cfg(feature = "xdp")]
use capture::afxdp::AfXdp;
#[cfg(feature = "xdp")]
use capture::xdp_loader::XdpProgram;
use flow::FlowTable;

/// 上报队列容量：server 断线时的缓冲，满了丢弃并计数——探针绝不因为上报慢而丢包
const REPORT_QUEUE: usize = 65536;

/// 运行统计打印间隔
const STATS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let iface = std::env::var("SENSOR_IFACE").unwrap_or_else(|_| "eth0".into());
    let server = std::env::var("OPENXDR_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8081".into());
    let workers: u16 = env_or("SENSOR_WORKERS", || {
        std::thread::available_parallelism().map_or(1, |n| n.get() as u16)
    });

    // FANOUT 组 ID 用 pid，避免同机多实例串台；最低位置 1 保证非 0
    let fanout_group = std::process::id() as u16 | 1;
    let running = Arc::new(AtomicBool::new(true));
    let dropped: report::DroppedCounter = Arc::new(AtomicU64::new(0));
    let (tx, rx) = async_channel::bounded(REPORT_QUEUE);

    let backend = std::env::var("SENSOR_BACKEND").unwrap_or_else(|_| "afpacket".into());
    eprintln!("sensor 启动: iface={iface} workers={workers} backend={backend} server={server}");

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
        #[cfg(not(feature = "xdp"))]
        let cap: Box<dyn Capture + Send> = Box::new(AfPacket::open(
            &iface,
            &RingConfig::default(),
            fanout_group,
        )?);

        let (running, tx, dropped) = (running.clone(), tx.clone(), dropped.clone());
        handles.push(std::thread::spawn(move || {
            if let Err(e) = worker(id, cap, running, tx, dropped) {
                eprintln!("worker {id} 退出: {e}");
            }
        }));
    }
    drop(tx); // 只保留 worker 持有的发送端，全部退出时上报侧才能收到关闭

    tokio::select! {
        _ = report::run(server, rx, dropped.clone()) => {}
        _ = tokio::signal::ctrl_c() => {
            eprintln!("收到退出信号");
            running.store(false, Ordering::Relaxed);
        }
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
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
    dropped: report::DroppedCounter,
) -> anyhow::Result<()> {
    let mut table = FlowTable::new(&flow::Config::default());
    let mut expired = Vec::new();
    let mut last_ts_ns = 0u64;
    let mut queue_drops = 0u64;
    let mut packets = 0u64;
    let mut exported = 0u64;
    let mut last_stats = std::time::Instant::now();

    while running.load(Ordering::Relaxed) {
        cap.poll_batch(&mut |frame, ts_ns| {
            packets += 1;
            last_ts_ns = ts_ns;
            let Some(pkt) = decode::decode(frame) else {
                return;
            };
            if let Some((flow, _forward)) = table.update(&pkt, ts_ns) {
                proto_id::probe(flow, &pkt);
            }
        })?;

        table.expire(last_ts_ns, &mut expired);
        for f in expired.drain(..) {
            exported += 1;
            // 上报队列满时丢弃会话记录，绝不阻塞抓包线程
            if tx.try_send(report::to_record(&f)).is_err() {
                queue_drops += 1;
            }
        }
        dropped.store(cap.dropped() + queue_drops, Ordering::Relaxed);

        if last_stats.elapsed() >= STATS_INTERVAL {
            eprintln!(
                "worker {id}: packets={packets} flows={} exported={exported} \
                 kernel_drops={} queue_drops={queue_drops}",
                table.len(),
                cap.dropped()
            );
            last_stats = std::time::Instant::now();
        }
    }

    table.drain_all(&mut expired);
    for f in expired.drain(..) {
        let _ = tx.try_send(report::to_record(&f));
    }
    eprintln!(
        "worker {id} 退出: flows={} kernel_drops={} queue_drops={queue_drops}",
        table.len(),
        cap.dropped()
    );
    Ok(())
}

fn env_or<T: std::str::FromStr>(key: &str, default: impl FnOnce() -> T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(default)
}
