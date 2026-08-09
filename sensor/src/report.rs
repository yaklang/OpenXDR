//! gRPC 批量上报：worker 通过 channel 交出结束的流，上报任务攒批推给 server。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::flow::Flow;
use crate::pb::{self, sensor_service_client::SensorServiceClient};
use crate::tls;

/// 攒批阈值：达到条数或到时间就发一批
const BATCH_SIZE: usize = 256;
const BATCH_INTERVAL: Duration = Duration::from_secs(2);

pub type DroppedCounter = Arc<AtomicU64>;

/// 上报时按客户端→服务端摆正方向：src 恒为发起方，dst 恒为服务端。
/// 检测规则写 dst_endpoint.port 才有意义。
pub fn to_record(flow: &Flow) -> pb::FlowRecord {
    let (src_ip, src_port, dst_ip, dst_port) = if flow.client_is_a {
        (
            flow.key.a_ip,
            flow.key.a_port,
            flow.key.b_ip,
            flow.key.b_port,
        )
    } else {
        (
            flow.key.b_ip,
            flow.key.b_port,
            flow.key.a_ip,
            flow.key.a_port,
        )
    };
    let (src_packets, src_bytes, dst_packets, dst_bytes) = if flow.client_is_a {
        (
            flow.a_to_b_packets,
            flow.a_to_b_bytes,
            flow.b_to_a_packets,
            flow.b_to_a_bytes,
        )
    } else {
        (
            flow.b_to_a_packets,
            flow.b_to_a_bytes,
            flow.a_to_b_packets,
            flow.a_to_b_bytes,
        )
    };

    pb::FlowRecord {
        start_unix_ns: flow.start_ns as i64,
        end_unix_ns: flow.last_ns as i64,
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        src_port: src_port as u32,
        dst_port: dst_port as u32,
        protocol: flow.key.proto as u32,
        src_packets,
        src_bytes,
        dst_packets,
        dst_bytes,
        tcp_flags: flow.tcp_flags as u32,
        dns_query: flow.meta.dns_query.clone().unwrap_or_default(),
        dns_rcode: flow.meta.dns_rcode.unwrap_or_default(),
        dns_answers: flow.meta.dns_answers.clone(),
        tls_sni: flow.meta.tls_sni.clone().unwrap_or_default(),
        ja3: flow.meta.ja3.clone().unwrap_or_default(),
        ja3s: flow.meta.ja3s.clone().unwrap_or_default(),
        http_host: flow.meta.http_host.clone().unwrap_or_default(),
        http_uri: flow.meta.http_uri.clone().unwrap_or_default(),
        http_user_agent: flow.meta.http_user_agent.clone().unwrap_or_default(),
        tls_cert_subject: flow.meta.cert_subject.clone().unwrap_or_default(),
        tls_cert_issuer: flow.meta.cert_issuer.clone().unwrap_or_default(),
        tls_cert_self_signed: flow.meta.cert_self_signed,
        tls_cert_not_before: flow.meta.cert_not_before,
        tls_cert_not_after: flow.meta.cert_not_after,
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
        match tls::connect(&server).await.map(SensorServiceClient::new) {
            Ok(mut client) => {
                // 攒批流：满 BATCH_SIZE 条或超过 BATCH_INTERVAL 就出一批
                let (rx, sensor_id, dropped) = (rx.clone(), sensor_id.clone(), dropped.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{FlowKey, Metadata};
    use std::net::{IpAddr, Ipv4Addr};

    fn flow(client_is_a: bool) -> Flow {
        Flow {
            key: FlowKey {
                a_ip: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
                b_ip: IpAddr::V4(Ipv4Addr::new(2, 0, 0, 2)),
                a_port: 1000,
                b_port: 80,
                proto: 6,
            },
            start_ns: 100,
            last_ns: 200,
            a_to_b_packets: 3,
            a_to_b_bytes: 300,
            b_to_a_packets: 5,
            b_to_a_bytes: 500,
            tcp_flags: 0,
            meta: Metadata {
                dns_query: Some("example.com".to_string()),
                dns_rcode: Some(0),
                dns_answers: vec!["93.184.216.34".to_string()],
                tls_sni: None,
                ja3: None,
                ja3s: Some("ja3s-hash".to_string()),
                http_host: Some("h.example".to_string()),
                http_uri: Some("/x".to_string()),
                http_user_agent: Some("ua".to_string()),
                cert_subject: Some("leaf.example".to_string()),
                cert_issuer: Some("Test CA".to_string()),
                cert_self_signed: false,
                cert_not_before: 1_700_000_000,
                cert_not_after: 1_800_000_000,
            },
            probed: true,
            probed_server: true,
            client_is_a,
            tls_hs_buf: Vec::new(),
        }
    }

    /// client 是 a 侧：src 直接取 a，流量方向照抄。
    #[test]
    fn to_record_client_is_a() {
        let r = to_record(&flow(true));
        assert_eq!(r.src_ip, "1.0.0.1");
        assert_eq!(r.dst_ip, "2.0.0.2");
        assert_eq!(r.src_port, 1000);
        assert_eq!(r.dst_port, 80);
        assert_eq!(r.src_packets, 3);
        assert_eq!(r.src_bytes, 300);
        assert_eq!(r.dst_packets, 5);
        assert_eq!(r.dst_bytes, 500);
    }

    /// client 是 b 侧：src 必须摆正为 b，否则 dst_endpoint 就写反了。
    #[test]
    fn to_record_server_is_a_reverses_direction() {
        let r = to_record(&flow(false));
        assert_eq!(r.src_ip, "2.0.0.2", "client 是 b 时 src 应为 b");
        assert_eq!(r.dst_ip, "1.0.0.1");
        assert_eq!(r.src_port, 80);
        assert_eq!(r.dst_port, 1000);
        assert_eq!(r.src_packets, 5, "src 侧应为 b→a 流量");
        assert_eq!(r.src_bytes, 500);
        assert_eq!(r.dst_packets, 3);
    }

    /// 时间戳与元数据忠实直通。
    #[test]
    fn to_record_metadata() {
        let r = to_record(&flow(true));
        assert_eq!(r.start_unix_ns, 100);
        assert_eq!(r.end_unix_ns, 200);
        assert_eq!(r.protocol, 6);
        assert_eq!(r.dns_query, "example.com");
        assert_eq!(r.dns_rcode, 0);
        assert_eq!(r.dns_answers, vec!["93.184.216.34"]);
        assert_eq!(r.http_host, "h.example");
        assert_eq!(r.http_uri, "/x");
        assert_eq!(r.http_user_agent, "ua");
        assert_eq!(r.tls_sni, "");
        assert_eq!(r.ja3, "");
        assert_eq!(r.ja3s, "ja3s-hash");
        assert_eq!(r.tls_cert_subject, "leaf.example");
        assert_eq!(r.tls_cert_issuer, "Test CA");
        assert!(!r.tls_cert_self_signed);
        assert_eq!(r.tls_cert_not_before, 1_700_000_000);
        assert_eq!(r.tls_cert_not_after, 1_800_000_000);
    }
}
