//! 抓包状态快照：快照头与 agent 的采集状态同一口径（启动标识、序号、采样时刻、组件状态），
//! 组件只有 capture 一项。不从「连得上 server」推断抓包正常：线程退了、丢包了都如实报。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::pb;
use crate::pb::sensor_service_client::SensorServiceClient;

/// 上报间隔
const INTERVAL: Duration = Duration::from_secs(15);
/// 一个上报间隔内丢包超过千分之一就算降级，之后一小时内保持降级：丢包是一阵一阵的，
/// 来回翻状态只会刷通知
const LOSS_PER_MILLE: u64 = 1;
const LOSS_STICKY: Duration = Duration::from_secs(3600);

/// worker 线程累加的计数，全部是本次启动的累计值。
#[derive(Default)]
pub struct Stats {
    pub packets: AtomicU64,
    pub flows: AtomicU64,
    pub kernel_drops: AtomicU64,
    pub queue_drops: AtomicU64,
    pub workers_alive: AtomicU64,
    /// TLS 重组预算打满、放弃证书解析的流数
    pub tls_budget_exhausted: AtomicU64,
}

impl Stats {
    pub fn dropped(&self) -> u64 {
        self.kernel_drops.load(Ordering::Relaxed) + self.queue_drops.load(Ordering::Relaxed)
    }
}

/// 上次快照时的计数，用来算速率与本间隔丢包率
struct Window {
    at: Instant,
    packets: u64,
    flows: u64,
    dropped: u64,
    lossy_at: Option<Instant>,
}

pub struct Health {
    boot_id: String,
    sequence: AtomicU64,
    iface: String,
    backend: String,
    workers: u64,
    pub stats: Arc<Stats>,
    window: Mutex<Window>,
}

#[derive(Serialize)]
struct Capability {
    path: String,
    state: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    boot_id: String,
    sequence: u64,
    reported_unix_ms: u64,
    iface: String,
    backend: String,
    workers: u64,
    workers_alive: u64,
    packets: u64,
    flows: u64,
    kernel_drops: u64,
    queue_drops: u64,
    /// 为 0 时不发：旧版 server 严格拒绝不认识的字段
    #[serde(skip_serializing_if = "is_zero")]
    tls_budget_exhausted: u64,
    /// 每秒包数
    packet_rate: u64,
    /// 每分钟会话数
    flow_rate: u64,
    capabilities: std::collections::BTreeMap<&'static str, Capability>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Health {
    pub fn new(iface: &str, backend: &str, workers: u16) -> Arc<Self> {
        Arc::new(Self {
            boot_id: uuid::Uuid::new_v4().to_string(),
            sequence: AtomicU64::new(0),
            iface: iface.into(),
            backend: backend.into(),
            workers: workers.into(),
            stats: Arc::new(Stats::default()),
            window: Mutex::new(Window {
                at: Instant::now(),
                packets: 0,
                flows: 0,
                dropped: 0,
                lossy_at: None,
            }),
        })
    }

    fn json(&self) -> String {
        let now = Instant::now();
        let s = &self.stats;
        let (packets, flows, dropped) = (
            s.packets.load(Ordering::Relaxed),
            s.flows.load(Ordering::Relaxed),
            s.dropped(),
        );
        let alive = s.workers_alive.load(Ordering::Relaxed).min(self.workers);
        let mut w = self.window.lock().unwrap_or_else(|e| e.into_inner());
        let secs = now.duration_since(w.at).as_secs().max(1);
        let (dp, df, dd) = (
            packets.saturating_sub(w.packets),
            flows.saturating_sub(w.flows),
            dropped.saturating_sub(w.dropped),
        );
        if dd > 0 && dd * 1000 > (dp + dd) * LOSS_PER_MILLE {
            w.lossy_at = Some(now);
        }
        let lossy = w
            .lossy_at
            .is_some_and(|t| now.duration_since(t) < LOSS_STICKY);
        *w = Window {
            at: now,
            packets,
            flows,
            dropped,
            lossy_at: w.lossy_at,
        };
        drop(w);

        let state = match alive {
            0 => "unavailable",
            n if n < self.workers || lossy => "degraded",
            _ => "active",
        };
        let capture = Capability {
            path: format!("{}:{}", self.backend, self.iface),
            state,
        };
        let snapshot = Snapshot {
            boot_id: self.boot_id.clone(),
            sequence: self.sequence.fetch_add(1, Ordering::Relaxed) + 1,
            reported_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            iface: self.iface.clone(),
            backend: self.backend.clone(),
            workers: self.workers,
            workers_alive: alive,
            packets,
            flows,
            kernel_drops: s.kernel_drops.load(Ordering::Relaxed),
            queue_drops: s.queue_drops.load(Ordering::Relaxed),
            tls_budget_exhausted: s.tls_budget_exhausted.load(Ordering::Relaxed),
            packet_rate: dp / secs,
            flow_rate: df * 60 / secs,
            capabilities: [("capture", capture)].into(),
        };
        serde_json::to_string(&snapshot).expect("状态快照不含非 JSON 类型")
    }
}

/// 连接期间每 15 秒报一次；服务端太旧不认这个 RPC 就不再报。
pub async fn report(
    mut client: SensorServiceClient<tonic::transport::Channel>,
    hostname: String,
    health: Arc<Health>,
) {
    loop {
        let mut request = tonic::Request::new(pb::SensorHealthRequest {
            hostname: hostname.clone(),
            health_json: health.json(),
        });
        request.set_timeout(Duration::from_secs(5));
        if let Err(err) = client.report_health(request).await {
            if err.code() == tonic::Code::Unimplemented {
                eprintln!("服务端尚不支持抓包状态上报");
                return;
            }
            eprintln!("抓包状态上报失败：{}", err.code());
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(h: &Health) -> serde_json::Value {
        serde_json::from_str(&h.json()).unwrap()
    }

    #[test]
    fn capture_state_follows_workers_and_loss() {
        let h = Health::new("eth0", "afpacket", 2);
        let v = snapshot(&h);
        assert_eq!(v["capabilities"]["capture"]["state"], "unavailable");
        assert_eq!(v["capabilities"]["capture"]["path"], "afpacket:eth0");
        assert_eq!(v["sequence"], 1);

        h.stats.workers_alive.store(2, Ordering::Relaxed);
        h.stats.packets.store(100_000, Ordering::Relaxed);
        h.stats.kernel_drops.store(10, Ordering::Relaxed); // 0.01%，不算降级
        assert_eq!(snapshot(&h)["capabilities"]["capture"]["state"], "active");

        h.stats.workers_alive.store(1, Ordering::Relaxed);
        assert_eq!(snapshot(&h)["capabilities"]["capture"]["state"], "degraded");

        h.stats.workers_alive.store(2, Ordering::Relaxed);
        h.stats.packets.store(101_000, Ordering::Relaxed);
        h.stats.queue_drops.store(50, Ordering::Relaxed); // 本间隔 50 / 1050，超过千分之一
        let v = snapshot(&h);
        assert_eq!(v["capabilities"]["capture"]["state"], "degraded");
        assert_eq!(v["kernelDrops"], 10);
        assert_eq!(v["queueDrops"], 50);
        assert!(
            v.get("tlsBudgetExhausted").is_none(),
            "为 0 不发，兼容旧 server"
        );
        h.stats.tls_budget_exhausted.store(3, Ordering::Relaxed);
        assert_eq!(snapshot(&h)["tlsBudgetExhausted"], 3);
        // 丢包停了也要保持一小时降级
        h.stats.packets.store(200_000, Ordering::Relaxed);
        assert_eq!(snapshot(&h)["capabilities"]["capture"]["state"], "degraded");
    }
}
