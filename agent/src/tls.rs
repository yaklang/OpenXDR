//! 采集端 mTLS 接入配置。
//!
//! 三个环境变量都配齐才启用 TLS；一个都没配则明文（仅适合本机调试）；
//! 配了一半属于配置错误，直接失败而不是悄悄降级成明文。

use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Identity};

pub async fn connect(server: &str) -> Result<Channel, Box<dyn std::error::Error>> {
    let endpoint = Endpoint::from_shared(server.to_string())?;
    let ca = std::env::var("OPENXDR_CA").ok();
    let cert = std::env::var("OPENXDR_CERT").ok();
    let key = std::env::var("OPENXDR_KEY").ok();

    let endpoint = match (ca, cert, key) {
        (None, None, None) => endpoint,
        (Some(ca), Some(cert), Some(key)) => {
            let tls = ClientTlsConfig::new()
                .ca_certificate(tonic::transport::Certificate::from_pem(std::fs::read(ca)?))
                .identity(Identity::from_pem(
                    std::fs::read(cert)?,
                    std::fs::read(key)?,
                ));
            endpoint.tls_config(tls)?
        }
        _ => return Err("OPENXDR_CA / OPENXDR_CERT / OPENXDR_KEY 必须同时配置".into()),
    };

    Ok(endpoint.connect().await?)
}
