use std::time::Duration;

use tokio_stream::wrappers::ReceiverStream;

pub mod pb {
    tonic::include_proto!("openxdr.agent.v1");
}

mod collector;
mod tls;

use pb::agent_service_client::AgentServiceClient;

#[tokio::main]
async fn main() {
    let server =
        std::env::var("OPENXDR_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8081".into());

    loop {
        if let Err(e) = run(&server).await {
            eprintln!("link down: {e}, retrying in 5s");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn run(server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = AgentServiceClient::new(tls::connect(server).await?);

    let resp = client
        .register(pb::RegisterRequest {
            hostname: gethostname::gethostname().to_string_lossy().into_owned(),
            os: std::env::consts::OS.into(),
            ip_addrs: local_ips(),
            agent_version: env!("CARGO_PKG_VERSION").into(),
        })
        .await?
        .into_inner();
    println!("registered: agent_id={}", resp.agent_id);

    let events = collector::spawn(resp.agent_id);
    client.report_events(ReceiverStream::new(events)).await?;
    Ok(())
}

/// 本机非回环 IP。server 按这些地址把探针看到的网络流量归属到本资产，
/// 端点侧和流量侧的证据才能落到同一实体上。
fn local_ips() -> Vec<String> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .map(|i| i.addr.ip().to_string())
        .collect()
}
