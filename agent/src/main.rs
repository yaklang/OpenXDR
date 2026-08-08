use std::time::Duration;

use tokio_stream::wrappers::ReceiverStream;

pub mod pb {
    tonic::include_proto!("openxdr.agent.v1");
}

mod collector;
mod respond;
mod tls;

use pb::agent_service_client::AgentServiceClient;

#[tokio::main]
async fn main() {
    let server = std::env::var("OPENXDR_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8081".into());

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
    let cfg = collector::Config::parse(&resp.config_json);
    println!("registered: agent_id={} config={cfg:?}", resp.agent_id);

    // 指令通道与事件上报并行：上报是长连接，不能让它挡住指令
    let commands = tokio::spawn(command_loop(client.clone(), resp.agent_id.clone()));

    let events = collector::spawn(resp.agent_id, cfg);
    let report = client.report_events(ReceiverStream::new(events)).await;
    commands.abort();
    report?;
    Ok(())
}

/// 常驻指令通道：先发一条带 agent_id 的空结果认领连接，
/// 之后逐条执行 server 推来的指令并回执。
async fn command_loop(mut client: AgentServiceClient<tonic::transport::Channel>, agent_id: String) {
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    // 认领消息：只带 agent_id，command_id 为空
    if tx
        .send(pb::CommandResult {
            agent_id: agent_id.clone(),
            ..Default::default()
        })
        .await
        .is_err()
    {
        return;
    }

    let mut inbound = match client.commands(ReceiverStream::new(rx)).await {
        Ok(stream) => stream.into_inner(),
        Err(e) => {
            eprintln!("指令通道建立失败: {e}");
            return;
        }
    };

    while let Ok(Some(cmd)) = inbound.message().await {
        let result = respond::execute(&agent_id, &cmd);
        println!("执行指令 {}: {}", cmd.id, result.detail);
        if tx.send(result).await.is_err() {
            return;
        }
    }
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
