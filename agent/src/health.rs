//! 独立状态快照；不从“有连接”推断采集完整，也不把未知路径标为正常。
use crate::pb;
use pb::agent_service_client::AgentServiceClient;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub path: String,
    pub state: String,
    /// 降级原因（目前只有活性检测会给）：通道开着却持续收不到事件
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// 本轮静默里已自动重建几次仍未恢复，只跟着 reason 出现
    #[serde(skip_serializing_if = "is_zero")]
    pub rebuilds: u32,
    /// 本轮采集以来静默后靠自动重建恢复的次数
    #[serde(skip_serializing_if = "is_zero")]
    pub recoveries: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// 活性检测对一个通道的结论（见 collector::liveness），每次巡检整体覆盖
#[derive(Clone, Copy, Default)]
pub struct Liveness {
    /// Some 表示通道静默（带原因），None 表示有事件
    pub reason: Option<&'static str>,
    /// 本轮静默里已自动重建的次数
    pub rebuilds: u32,
    /// 自动重建后恢复的累计次数
    pub recoveries: u32,
}

#[derive(Default)]
struct Capabilities {
    generation: u64,
    values: BTreeMap<String, Capability>,
    /// 活性检测的结论。静默叠加在采集路径自报的状态上：路径自报 active / degraded 时
    /// 一律按 degraded 上报并带原因与重建次数，恢复后撤掉，回到自报状态
    liveness: BTreeMap<String, Liveness>,
}

#[derive(Clone, Default, Serialize)]
pub struct ReceiptHealth {
    pub pending: usize,
    pub incomplete: usize,
}

pub struct Health {
    boot_id: String,
    sequence: AtomicU64,
    pub dropped: Arc<AtomicU64>,
    bytes: AtomicU64,
    batches: AtomicU64,
    limit: AtomicU64,
    pub write_blocked: AtomicBool,
    /// 最近一次健康状态上报成功的时间（Unix 毫秒），本机状态端点据此说联没联上管理平台
    last_contact_ms: AtomicU64,
    capabilities: Mutex<Capabilities>,
    receipts: Mutex<ReceiptHealth>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    boot_id: String,
    sequence: u64,
    reported_unix_ms: u64,
    queue_bytes: u64,
    queue_batches: u64,
    queue_limit_bytes: u64,
    dropped_events: u64,
    write_blocked: bool,
    capabilities: BTreeMap<String, Capability>,
    receipts: ReceiptHealth,
}

impl Health {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            boot_id: uuid::Uuid::new_v4().to_string(),
            sequence: AtomicU64::new(0),
            dropped: Arc::new(AtomicU64::new(0)),
            bytes: AtomicU64::new(0),
            batches: AtomicU64::new(0),
            limit: AtomicU64::new(0),
            write_blocked: AtomicBool::new(false),
            last_contact_ms: AtomicU64::new(0),
            capabilities: Mutex::new(Capabilities::default()),
            receipts: Mutex::new(ReceiptHealth::default()),
        })
    }
    pub fn last_contact_ms(&self) -> u64 {
        self.last_contact_ms.load(Ordering::Relaxed)
    }

    /// 给主机使用者的采集概况：还没有任何通道报状态是启动中；有通道降级（自报或活性检测）就是降级。
    /// unavailable 是本平台或本配置下本来就没有的能力，不算降级
    pub fn collection(&self) -> crate::status_proto::Collection {
        use crate::status_proto::Collection;
        let caps = self.capabilities();
        if caps.is_empty() {
            Collection::Starting
        } else if caps.values().any(|c| c.state == "degraded") {
            Collection::Degraded
        } else {
            Collection::Ok
        }
    }

    pub fn queued_batches(&self) -> u64 {
        self.batches.load(Ordering::Relaxed)
    }
    pub fn receipts(&self, stats: ReceiptHealth) {
        *self.receipts.lock().unwrap_or_else(|e| e.into_inner()) = stats;
    }
    pub fn queue(&self, bytes: u64, batches: usize, limit: u64) {
        self.bytes.store(bytes, Ordering::Relaxed);
        self.batches.store(batches as u64, Ordering::Relaxed);
        self.limit.store(limit, Ordering::Relaxed);
    }
    pub fn begin(&self, enabled: &[(&str, bool)]) -> u64 {
        let mut caps = self.capabilities.lock().unwrap_or_else(|e| e.into_inner());
        caps.generation += 1;
        caps.values = enabled
            .iter()
            .map(|(name, on)| {
                (
                    name.to_string(),
                    Capability {
                        path: String::new(),
                        state: if *on { "unknown" } else { "disabled" }.into(),
                        ..Default::default()
                    },
                )
            })
            .collect();
        caps.liveness.clear();
        caps.generation
    }
    pub fn capability(&self, generation: u64, name: &str, path: &str, state: &str) {
        let mut caps = self.capabilities.lock().unwrap_or_else(|e| e.into_inner());
        if caps.generation == generation {
            caps.values.insert(
                name.into(),
                Capability {
                    path: path.into(),
                    state: state.into(),
                    ..Default::default()
                },
            );
        }
    }
    /// 活性检测的结论，旧一轮采集的不作数
    pub fn liveness(&self, generation: u64, name: &str, liveness: Liveness) {
        let mut caps = self.capabilities.lock().unwrap_or_else(|e| e.into_inner());
        if caps.generation == generation {
            caps.liveness.insert(name.into(), liveness);
        }
    }
    fn capabilities(&self) -> BTreeMap<String, Capability> {
        let caps = self.capabilities.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = caps.values.clone();
        for (name, l) in &caps.liveness {
            let Some(c) = out.get_mut(name) else {
                continue;
            };
            c.recoveries = l.recoveries;
            if let Some(reason) = l.reason
                && (c.state == "active" || c.state == "degraded")
            {
                c.state = "degraded".into();
                c.reason = Some(reason.into());
                c.rebuilds = l.rebuilds;
            }
        }
        out
    }
    fn json(&self) -> String {
        let snapshot = Snapshot {
            receipts: self
                .receipts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            boot_id: self.boot_id.clone(),
            sequence: self.sequence.fetch_add(1, Ordering::Relaxed) + 1,
            reported_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            queue_bytes: self.bytes.load(Ordering::Relaxed),
            queue_batches: self.batches.load(Ordering::Relaxed),
            queue_limit_bytes: self.limit.load(Ordering::Relaxed),
            dropped_events: self.dropped.load(Ordering::Relaxed),
            write_blocked: self.write_blocked.load(Ordering::Relaxed),
            capabilities: self.capabilities(),
        };
        serde_json::to_string(&snapshot).expect("状态快照不含非 JSON 类型")
    }
}

pub async fn report(
    mut client: AgentServiceClient<tonic::transport::Channel>,
    agent_id: String,
    health: Arc<Health>,
) {
    loop {
        let mut request = tonic::Request::new(pb::HealthRequest {
            agent_id: agent_id.clone(),
            health_json: health.json(),
        });
        request.set_timeout(Duration::from_secs(5));
        let result = client.report_health(request).await;
        if result.is_ok() {
            health
                .last_contact_ms
                .store(crate::status_proto::now_ms(), Ordering::Relaxed);
        }
        if let Err(err) = result {
            if err.code() == tonic::Code::Unimplemented {
                eprintln!("服务端尚不支持采集状态上报");
                return;
            }
            eprintln!("采集状态上报失败：{}", err.code());
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_collector_cannot_overwrite_new_configuration() {
        let health = Health::new();
        let first = health.begin(&[("process", true)]);
        health.capability(first, "process", "poll", "degraded");
        let next = health.begin(&[("process", true), ("network", false)]);
        health.capability(first, "process", "etw", "active");
        let value: serde_json::Value = serde_json::from_str(&health.json()).unwrap();
        assert_eq!(value["capabilities"]["process"]["state"], "unknown");
        assert_eq!(value["capabilities"]["network"]["state"], "disabled");
        health.capability(next, "process", "netlink", "active");
        health.dropped.fetch_add(2, Ordering::Relaxed);
        let value: serde_json::Value = serde_json::from_str(&health.json()).unwrap();
        assert_eq!(value["droppedEvents"], 2);
        assert_eq!(value["sequence"], 2);
    }

    fn silent(rebuilds: u32, recoveries: u32) -> Liveness {
        Liveness {
            reason: Some("收不到"),
            rebuilds,
            recoveries,
        }
    }

    /// 静默叠加在自报状态上：active 变 degraded 并带原因与重建次数，撤掉后回到 active、
    /// 只留恢复次数；不可用的路径不受影响，旧一轮采集的结论不作数
    #[test]
    fn silence_overlays_reported_state() {
        let health = Health::new();
        let generation = health.begin(&[("process", true), ("files", true)]);
        health.capability(generation, "process", "etw", "active");
        health.capability(generation, "files", "rdcw", "unavailable");
        health.liveness(generation, "process", silent(2, 0));
        health.liveness(generation, "files", silent(1, 0));
        health.liveness(generation - 1, "network", silent(0, 0));
        let value: serde_json::Value = serde_json::from_str(&health.json()).unwrap();
        let process = &value["capabilities"]["process"];
        assert_eq!(process["state"], "degraded");
        assert_eq!(process["path"], "etw");
        assert_eq!(process["reason"], "收不到");
        assert_eq!(process["rebuilds"], 2);
        assert!(process.get("recoveries").is_none(), "零次不上报");
        let files = &value["capabilities"]["files"];
        assert_eq!(files["state"], "unavailable");
        assert!(files.get("reason").is_none());
        assert!(files.get("rebuilds").is_none(), "重建次数只跟着原因");
        assert!(value["capabilities"].get("network").is_none());

        let recovered = Liveness {
            recoveries: 1,
            ..Default::default()
        };
        health.liveness(generation, "process", recovered);
        let value: serde_json::Value = serde_json::from_str(&health.json()).unwrap();
        let process = &value["capabilities"]["process"];
        assert_eq!(process["state"], "active");
        assert!(process.get("reason").is_none());
        assert!(process.get("rebuilds").is_none());
        assert_eq!(process["recoveries"], 1, "已自动恢复，第 1 次");

        health.liveness(generation, "process", silent(1, 1));
        let next = health.begin(&[("process", true)]);
        health.capability(next, "process", "etw", "active");
        let value: serde_json::Value = serde_json::from_str(&health.json()).unwrap();
        assert_eq!(
            value["capabilities"]["process"]["state"], "active",
            "新一轮采集从头判断"
        );
    }
}
