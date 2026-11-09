//! 在线接入：与 agent 同一套机制。私钥在本机生成、永不离开主机，server 只拿 CSR 签发
//! 探针绑定证书（CN 由 server 按用途写成 sensor:<主机名>，CSR 里写什么都不采信）。
//!
//! 安装脚本负责 HTTP，探针负责密码学与文件：
//!   openxdr-sensor enroll-request <目录>  生成私钥，向 stdout 输出接入请求 JSON
//!   openxdr-sensor enroll-apply <目录>    从 stdin 读 server 应答，写证书与 sensor.env
//! 与同机 agent 共用 /etc/openxdr，文件名各不相同，互不覆盖。

use std::io::Read;
use std::path::Path;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use serde::Deserialize;

pub fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

/// 生成私钥（0600）与 CSR，返回接入请求 JSON。
pub fn request(dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    let host = hostname();
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("sensor:{host}"));
    params.distinguished_name = dn;
    let csr = params.serialize_request(&key)?.pem()?;
    write_private(
        &dir.join("sensor.key.pending"),
        key.serialize_pem().as_bytes(),
    )?;
    Ok(
        serde_json::json!({ "hostname": host, "os": "linux", "csr": csr, "kind": "sensor" })
            .to_string(),
    )
}

#[derive(Deserialize)]
struct Grant {
    server: String,
    #[serde(default)]
    ca: String,
    #[serde(default)]
    cert: String,
}

/// 写入 server 签发的证书与连接配置。server 未启用 mTLS 时应答里没有证书，只写地址。
pub fn apply(dir: &Path, mut input: impl Read) -> Result<(), Box<dyn std::error::Error>> {
    let mut body = String::new();
    input.read_to_string(&mut body)?;
    let grant: Grant = serde_json::from_str(&body).map_err(|e| format!("接入应答无法解析：{e}"))?;
    if grant.server.is_empty() || grant.server.contains(['\n', '\r']) {
        return Err("接入应答缺少有效的 server 地址".into());
    }
    let mut env = format!("OPENXDR_SERVER={}\n", grant.server);
    if !grant.cert.is_empty() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
        let key_pem = std::fs::read(dir.join("sensor.key.pending"))?;
        let key = PrivateKeyDer::from_pem_slice(&key_pem)?;
        let certs =
            CertificateDer::pem_slice_iter(grant.cert.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        let provider = rustls::crypto::ring::default_provider();
        let certified = rustls::sign::CertifiedKey::from_der(certs, key, &provider)?;
        certified.keys_match()?;
        if CertificateDer::pem_slice_iter(grant.ca.as_bytes())
            .collect::<Result<Vec<_>, _>>()?
            .is_empty()
        {
            return Err("接入应答缺少 CA 证书".into());
        }
        // 每次签发独立保存，只有配置原子替换后才启用；旧身份始终可回滚。
        let identity = dir.join(format!("sensor-identity-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&identity)?;
        let (ca, cert, key) = (
            identity.join("ca.crt"),
            identity.join("sensor.crt"),
            identity.join("sensor.key"),
        );
        write_private(&key, &key_pem)?;
        std::fs::write(&ca, &grant.ca)?;
        std::fs::write(&cert, &grant.cert)?;
        env += &format!(
            "OPENXDR_CA={}\nOPENXDR_CERT={}\nOPENXDR_KEY={}\n",
            ca.display(),
            cert.display(),
            key.display()
        );
    }
    write_private(&dir.join("sensor.env.new"), env.as_bytes())?;
    std::fs::rename(dir.join("sensor.env.new"), dir.join("sensor.env"))?;
    let _ = std::fs::remove_file(dir.join("sensor.key.pending"));
    Ok(())
}

/// Windows 没有 systemd 的 EnvironmentFile：启动时自己读 %ProgramData%\OpenXDR\sensor.env。
/// 只认 OPENXDR_ 与 SENSOR_ 开头的键，进程环境里已有的变量优先；文件不存在不是错误
#[cfg(windows)]
pub fn load_env_file() {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    let Ok(text) = std::fs::read_to_string(Path::new(&base).join(r"OpenXDR\sensor.env")) else {
        return;
    };
    for (key, value) in parse_env(&text) {
        if std::env::var_os(key).is_none() {
            // SAFETY: 在 main 起任何线程之前调用
            unsafe { std::env::set_var(key, value) };
        }
    }
}

#[cfg(any(windows, test))]
fn parse_env(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim(), v.trim()))
        .filter(|(k, _)| k.starts_with("OPENXDR_") || k.starts_with("SENSOR_"))
}

/// Windows 上靠安装脚本收紧目录权限（只留 SYSTEM 与管理员），文件本身不另设
#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_file_keeps_only_sensor_keys() {
        let text =
            "# 注释\nOPENXDR_SERVER=https://x:8081\nSENSOR_IFACE = 以太网 \nPATH=/evil\n坏行\n";
        let got: Vec<_> = parse_env(text).collect();
        assert_eq!(
            got,
            [
                ("OPENXDR_SERVER", "https://x:8081"),
                ("SENSOR_IFACE", "以太网")
            ]
        );
    }

    #[test]
    fn request_then_apply_writes_config() {
        let dir =
            std::env::temp_dir().join(format!("openxdr-sensor-enroll-{}", uuid::Uuid::new_v4()));
        let req: serde_json::Value = serde_json::from_str(&request(&dir).unwrap()).unwrap();
        assert_eq!(req["hostname"], hostname());
        assert_eq!(req["kind"], "sensor");
        assert!(req["csr"].as_str().unwrap().contains("CERTIFICATE REQUEST"));
        // 同机 agent 的文件不受影响
        std::fs::write(dir.join("agent.env"), "agent-config").unwrap();
        std::fs::write(dir.join("sensor.env"), "old-config").unwrap();
        assert!(
            apply(
                &dir,
                br#"{"server":"https://host:8081","ca":"bad","cert":"bad"}"#.as_slice()
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("sensor.env")).unwrap(),
            "old-config",
            "被拒绝或坏应答不能损坏已安装身份"
        );
        let key =
            KeyPair::from_pem(&std::fs::read_to_string(dir.join("sensor.key.pending")).unwrap())
                .unwrap();
        let cert = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem();
        let grant =
            serde_json::json!({"server":"https://host:8081", "ca":cert, "cert":cert}).to_string();
        apply(&dir, grant.as_bytes()).unwrap();
        let env = std::fs::read_to_string(dir.join("sensor.env")).unwrap();
        assert!(env.contains("sensor-identity-") && env.contains("sensor.crt"));
        assert!(!dir.join("sensor.key.pending").exists());
        assert_eq!(
            std::fs::read_to_string(dir.join("agent.env")).unwrap(),
            "agent-config"
        );

        apply(&dir, r#"{"server":"http://10.0.0.1:8081"}"#.as_bytes()).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("sensor.env")).unwrap(),
            "OPENXDR_SERVER=http://10.0.0.1:8081\n"
        );
        assert!(
            apply(&dir, r#"{"server":"x\nOPENXDR_KEY=/tmp/evil"}"#.as_bytes()).is_err(),
            "地址里带换行不能注入配置"
        );
        std::fs::remove_dir_all(dir).ok();
    }
}
