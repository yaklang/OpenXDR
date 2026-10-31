//! gRPC 上报：注册与升级、抓包状态；worker 通过 channel 交出结束的流，上报任务攒批推给 server。

use std::sync::Arc;
use std::time::Duration;

use tonic::codec::CompressionEncoding;

use crate::flow::Flow;
use crate::health::{Health, Stats};
use crate::pb::{self, sensor_service_client::SensorServiceClient};
use crate::{enroll, tls, upgrade};

/// 攒批阈值：达到条数或到时间就发一批
const BATCH_SIZE: usize = 256;
const BATCH_INTERVAL: Duration = Duration::from_secs(2);

/// 上行压缩开关：只认 `SENSOR_GRPC_COMPRESSION=gzip`，其它值或未设置都不压。
/// 默认关闭，清空该变量重启即回滚；只改线上字节，不改上报内容。
fn send_compression() -> Option<CompressionEncoding> {
    match std::env::var("SENSOR_GRPC_COMPRESSION").as_deref() {
        Ok("gzip") => Some(CompressionEncoding::Gzip),
        _ => None,
    }
}

/// 两处连接共用同一套压缩设置，避免一边压一边不压。
/// 开启时请求侧压、响应侧也登记 gzip：grpc-go 服务端默认用请求的编码压缩响应
/// （FlowAck 很小，压它没收益），不接受就会在解压 FlowAck 时直接报错。
fn new_client(
    channel: tonic::transport::Channel,
) -> SensorServiceClient<tonic::transport::Channel> {
    let client = SensorServiceClient::new(channel);
    match send_compression() {
        Some(encoding) => client.send_compressed(encoding).accept_compressed(encoding),
        None => client,
    }
}

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
        tls_handshake_only: flow.tls_client.handshake_only(flow.meta.tls13),
        tls_version: flow.meta.tls_version.clone().unwrap_or_default(),
        tls_alpn: flow.meta.tls_alpn.clone().unwrap_or_default(),
    }
}

/// 常驻上报循环：注册（取升级指令）→ 起状态上报 → 推会话流，断线 5 秒后重连。
/// 重连期间 channel 起缓冲作用，满了由 worker 侧丢弃并计数。
/// 返回 true 表示已换上新版、该退出了；返回 false 表示采集侧全部退出、队列已推空。
///
/// 用 async-channel 而非 tokio mpsc：tonic 要求上行流是 'static，
/// 可克隆的接收端让每次重连都能拿到同一队列的新流，无需在任务间转交所有权。
pub async fn run(
    server: String,
    rx: async_channel::Receiver<pb::FlowRecord>,
    health: Arc<Health>,
) -> bool {
    let hostname = enroll::hostname();
    loop {
        match tls::connect(&server).await.map(new_client) {
            Ok(mut client) => {
                match register(&mut client, &hostname).await {
                    // 收尾阶段（队列已关）不再升级，推完就走
                    Ok(resp) if !resp.upgrade_sha256.is_empty() && !rx.is_closed() => {
                        match tokio::time::timeout(
                            Duration::from_secs(120),
                            upgrade::apply(
                                &mut client,
                                &resp.upgrade_platform,
                                &resp.upgrade_sha256,
                            ),
                        )
                        .await
                        {
                            Ok(Ok(())) => return true,
                            Ok(Err(e)) => eprintln!("自动升级失败，继续运行当前版本：{e}"),
                            Err(_) => eprintln!("自动升级下载超时，继续运行当前版本"),
                        }
                    }
                    Ok(_) => {}
                    // 旧 server 只有会话上报：照推会话，不报状态
                    Err(e) if e.code() == tonic::Code::Unimplemented => {
                        eprintln!("服务端尚不支持探针注册，只上报会话")
                    }
                    Err(e) => {
                        eprintln!("注册失败：{e}");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                }
                let reporting = tokio::spawn(crate::health::report(
                    client.clone(),
                    hostname.clone(),
                    health.clone(),
                ));
                let result = client
                    .report_flows(batches(rx.clone(), hostname.clone(), health.stats.clone()))
                    .await;
                reporting.abort();
                if let Err(e) = result {
                    eprintln!("上报中断: {e}");
                } else if rx.is_closed() && rx.is_empty() {
                    return false;
                }
            }
            Err(e) => eprintln!("连接 server 失败: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// 升级后的收尾：采集侧已全部退出，把队列里剩下的会话推完。
pub async fn flush(server: &str, rx: async_channel::Receiver<pb::FlowRecord>, stats: Arc<Stats>) {
    if rx.is_empty() {
        return;
    }
    let result = match tls::connect(server).await.map(new_client) {
        Ok(mut client) => client
            .report_flows(batches(rx, enroll::hostname(), stats))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    if let Err(e) = result {
        eprintln!("退出前推送在途会话失败：{e}");
    }
}

async fn register(
    client: &mut SensorServiceClient<tonic::transport::Channel>,
    hostname: &str,
) -> Result<pb::SensorRegisterResponse, tonic::Status> {
    let ip_addrs = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .map(|i| i.ip().to_string())
        .collect();
    let mut request = tonic::Request::new(pb::SensorRegisterRequest {
        hostname: hostname.into(),
        ip_addrs,
        version: env!("CARGO_PKG_VERSION").into(),
        arch: std::env::consts::ARCH.into(),
        binary_sha256: upgrade::self_sha256().into(),
    });
    request.set_timeout(Duration::from_secs(10));
    Ok(client.register(request).await?.into_inner())
}

/// 攒批流：满 BATCH_SIZE 条或超过 BATCH_INTERVAL 就出一批；队列关闭时把手里的发完再结束。
fn batches(
    rx: async_channel::Receiver<pb::FlowRecord>,
    sensor_id: String,
    stats: Arc<Stats>,
) -> impl tokio_stream::Stream<Item = pb::FlowBatch> + Send + 'static {
    async_stream::stream! {
        let mut buf = Vec::with_capacity(BATCH_SIZE);
        loop {
            let deadline = tokio::time::Instant::now() + BATCH_INTERVAL;
            let mut closed = false;
            while buf.len() < BATCH_SIZE {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Ok(record)) => buf.push(record),
                    Ok(Err(_)) => {
                        // 采集侧全部退出
                        closed = true;
                        break;
                    }
                    Err(_) => break, // 到时间了，有多少发多少
                }
            }
            if !buf.is_empty() {
                yield pb::FlowBatch {
                    sensor_id: sensor_id.clone(),
                    flows: std::mem::take(&mut buf),
                    dropped_packets: stats.dropped(),
                };
                buf.reserve(BATCH_SIZE);
            }
            if closed {
                return;
            }
        }
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
                tls13: false,
                tls_version: Some("TLS 1.2".to_string()),
                tls_alpn: Some("h2".to_string()),
            },
            probed: true,
            probed_server: true,
            client_is_a,
            tls_hs_buf: Vec::new(),
            tls_client: Default::default(),
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
        assert_eq!(r.tls_version, "TLS 1.2");
        assert_eq!(r.tls_alpn, "h2");
    }
}
