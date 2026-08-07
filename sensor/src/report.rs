//! gRPC 批量上报：worker 通过 channel 交出结束的流，上报任务攒批推给 server。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::flow::Flow;
use crate::pb::{self, sensor_service_client::SensorServiceClient};

/// 攒批阈值：达到条数或到时间就发一批
const BATCH_SIZE: usize = 256;
const BATCH_INTERVAL: Duration = Duration::from_secs(2);

pub type DroppedCounter = Arc<AtomicU64>;

pub fn to_record(flow: &Flow) -> pb::FlowRecord {
    pb::FlowRecord {
        start_unix_ns: flow.start_ns as i64,
        end_unix_ns: flow.last_ns as i64,
        src_ip: flow.key.a_ip.to_string(),
        dst_ip: flow.key.b_ip.to_string(),
        src_port: flow.key.a_port as u32,
        dst_port: flow.key.b_port as u32,
        protocol: flow.key.proto as u32,
        src_packets: flow.a_to_b_packets,
        src_bytes: flow.a_to_b_bytes,
        dst_packets: flow.b_to_a_packets,
        dst_bytes: flow.b_to_a_bytes,
        tcp_flags: flow.tcp_flags as u32,
        dns_query: flow.meta.dns_query.clone().unwrap_or_default(),
        tls_sni: flow.meta.tls_sni.clone().unwrap_or_default(),
    }
}

/// 常驻上报循环：断线自动重连。重连期间 channel 起缓冲作用，满了由 worker 侧丢弃并计数。
///
/// 用 async-channel 而非 tokio mpsc：tonic 要求上行流是 'static，
/// 可克隆的接收端让每次重连都能拿到同一队列的新流，无需在任务间转交所有权。
pub async fn run(
    server: String,
    rx: async_channel::Receiver<pb::FlowRecord>,
    dropped: DroppedCounter,
) {
    let sensor_id = gethostname::gethostname().to_string_lossy().into_owned();

    loop {
        match SensorServiceClient::connect(server.clone()).await {
            Ok(mut client) => {
                // 攒批流：满 BATCH_SIZE 条或超过 BATCH_INTERVAL 就出一批
                let (rx, sensor_id, dropped) =
                    (rx.clone(), sensor_id.clone(), dropped.clone());
                let outbound = async_stream::stream! {
                    let mut buf = Vec::with_capacity(BATCH_SIZE);
                    loop {
                        let deadline = tokio::time::Instant::now() + BATCH_INTERVAL;
                        while buf.len() < BATCH_SIZE {
                            match tokio::time::timeout_at(deadline, rx.recv()).await {
                                Ok(Ok(record)) => buf.push(record),
                                Ok(Err(_)) => return, // 采集侧全部退出
                                Err(_) => break,      // 到时间了，有多少发多少
                            }
                        }
                        if buf.is_empty() {
                            continue;
                        }
                        yield pb::FlowBatch {
                            sensor_id: sensor_id.clone(),
                            flows: std::mem::take(&mut buf),
                            dropped_packets: dropped.load(Ordering::Relaxed),
                        };
                        buf.reserve(BATCH_SIZE);
                    }
                };
                if let Err(e) = client.report_flows(outbound).await {
                    eprintln!("上报中断: {e}");
                }
            }
            Err(e) => eprintln!("连接 server 失败: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
