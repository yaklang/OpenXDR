//! 自动升级：server 分发目录里放的是哪个版本，agent 就收敛到哪个版本。
//!
//! 流程：校验发布签名 → 经已认证的 gRPC 通道下载 → 校验哈希 → 用新二进制跑一次 `version` 自检
//! （架构、glibc 不兼容在这一步就暴露）→ 旧版改名 .prev 留作回滚 → 换上新版 → 退出，
//! 由 systemd / 计划任务拉起新版。任何一步失败都保持旧版继续运行，下次重连再试。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use tokio_stream::StreamExt;

use crate::pb;
use crate::pb::agent_service_client::AgentServiceClient;

/// 换上新版后的退出码：非零，让各种守护方式都视为需要重启
pub const EXIT_UPGRADED: i32 = 75;

/// 编译时嵌入的发布公钥（Ed25519，十六进制）：构建时设 OPENXDR_RELEASE_PUBKEY。嵌了就只装发布私钥签过的安装包——
/// 私钥不在 server 上，拿下 server 节点也推不了恶意 agent。开源默认构建不嵌，只校验哈希
const RELEASE_PUBKEY: Option<&str> = option_env!("OPENXDR_RELEASE_PUBKEY");

/// 发布签名的域前缀，与 server/cmd/signrelease 一致
const RELEASE_CONTEXT: &[u8] = b"openxdr-agent-release-v1\0";

/// 当前二进制的哈希，进程生命周期内不变，算一次即可。算不出来返回空串，server 就不会要求升级。
pub fn self_sha256() -> &'static str {
    static SHA: OnceLock<String> = OnceLock::new();
    SHA.get_or_init(|| {
        std::env::current_exe()
            .and_then(std::fs::File::open)
            .and_then(sha256_hex)
            .unwrap_or_default()
    })
}

fn sha256_hex(mut r: impl Read) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match r.read(&mut buf)? {
            0 => break,
            n => h.update(&buf[..n]),
        }
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// 下载并换上新版。成功返回后由调用方排空采集缓存再退出。签名不对连下载都不做
pub async fn apply(
    client: &mut AgentServiceClient<tonic::transport::Channel>,
    platform: &str,
    sha256: &str,
    signature: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    verify_release(RELEASE_PUBKEY, platform, sha256, signature)?;
    let data = download(client, platform, sha256).await?;
    let version = install(&std::env::current_exe()?, &data).await?;
    eprintln!("已安装 {version}，等待事件落盘后退出重新拉起");
    Ok(())
}

async fn download(
    client: &mut AgentServiceClient<tonic::transport::Channel>,
    platform: &str,
    sha256: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut stream = client
        .download_agent(pb::DownloadRequest {
            platform: platform.into(),
            sha256: sha256.into(),
        })
        .await?
        .into_inner();
    let mut data = Vec::new();
    while let Some(chunk) = stream.next().await {
        data.extend(chunk?.data);
    }
    let got = sha256_hex(data.as_slice())?;
    if got != sha256 {
        return Err(format!("下载的安装包哈希不符：{got}").into());
    }
    Ok(data)
}

/// 发布签名：对 前缀 + 平台 + "\0" + 安装包哈希 验签。没嵌公钥就不要求（开源默认构建）
fn verify_release(
    pubkey: Option<&str>,
    platform: &str,
    sha256: &str,
    signature: &[u8],
) -> Result<(), String> {
    let Some(pubkey) = pubkey else {
        return Ok(());
    };
    let key = decode_hex(pubkey)
        .filter(|k| k.len() == 32)
        .ok_or("编译时嵌入的发布公钥无效，拒绝升级")?;
    if signature.is_empty() {
        return Err("安装包没有发布签名，拒绝升级（本 agent 只装签过名的版本）".into());
    }
    let message = [
        RELEASE_CONTEXT,
        platform.as_bytes(),
        b"\0",
        sha256.as_bytes(),
    ]
    .concat();
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(&message, signature)
        .map_err(|_| "安装包发布签名无效，拒绝升级".to_string())
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    s.len()
        .is_multiple_of(2)
        .then(|| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
                .collect()
        })
        .flatten()
}

/// 新版先落到 .new 并自检，通过后旧版改名 .prev、新版就位。返回新版自报的版本号。
async fn install(exe: &Path, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let new = with_suffix(exe, ".new");
    write_executable(&new, data)?;
    let check = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(&new)
            .arg("version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap_or_else(|_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "新版自检超过 10 秒",
        ))
    });
    let check = match check {
        Ok(c) if c.status.success() => c,
        Ok(c) => {
            let _ = std::fs::remove_file(&new);
            return Err(format!("新版自检失败：{}", String::from_utf8_lossy(&c.stderr)).into());
        }
        Err(e) => {
            let _ = std::fs::remove_file(&new);
            return Err(format!("新版无法运行：{e}").into());
        }
    };
    // 运行中的二进制在 Linux 和 Windows 上都允许改名
    replace(exe, &new)?;
    Ok(String::from_utf8_lossy(&check.stdout).trim().to_string())
}

fn replace(exe: &Path, new: &Path) -> std::io::Result<()> {
    let previous = with_suffix(exe, ".prev");
    std::fs::rename(exe, &previous)?;
    if let Err(error) = std::fs::rename(new, exe) {
        std::fs::rename(&previous, exe).map_err(|rollback| {
            std::io::Error::other(format!("安装失败：{error}；恢复旧程序失败：{rollback}"))
        })?;
        return Err(error);
    }
    Ok(())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    s.into()
}

#[cfg(unix)]
fn write_executable(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(path)?;
    f.write_all(data)
}

#[cfg(not(unix))]
fn write_executable(path: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与 server/cmd/signrelease 的 TestReleaseSignatureVector 同一组：全零种子对 linux-amd64 + "abc" 的哈希签名
    #[test]
    fn release_signature_vector() {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let key = Ed25519KeyPair::from_seed_unchecked(&[0; 32]).unwrap();
        let pubkey: String = key
            .public_key()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let sha = sha256_hex(&b"abc"[..]).unwrap();
        let sig = decode_hex(
            "e3b72a71a5927467e125239596e627ac089a981cd8c3c0421ff940747348c5fe\
             34a7505a6edf487eae2dc5ca5b6d612d02bb33c92b1f504b1b6f0f68ed31810d",
        )
        .unwrap();
        assert!(verify_release(Some(&pubkey), "linux-amd64", &sha, &sig).is_ok());
        assert!(
            verify_release(Some(&pubkey), "linux-arm64", &sha, &sig).is_err(),
            "换平台不行"
        );
        assert!(
            verify_release(Some(&pubkey), "linux-amd64", &"0".repeat(64), &sig).is_err(),
            "换安装包不行"
        );
        assert!(
            verify_release(Some(&pubkey), "linux-amd64", &sha, &[]).is_err(),
            "嵌了公钥就必须有签名"
        );
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(verify_release(Some(&pubkey), "linux-amd64", &sha, &bad).is_err());
        assert!(
            verify_release(Some("zz"), "linux-amd64", &sha, &sig).is_err(),
            "嵌入的公钥坏了就拒绝"
        );
        assert!(
            verify_release(None, "linux-amd64", &sha, &[]).is_ok(),
            "没嵌公钥只校验哈希"
        );
    }

    /// 自检失败的新版不能换上去，旧版原地不动；自检通过才换，旧版留作 .prev。
    #[cfg(unix)]
    #[tokio::test]
    async fn install_swaps_only_after_self_check() {
        let dir = std::env::temp_dir().join(format!("openxdr-upgrade-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("openxdr-agent");
        std::fs::write(&exe, "old").unwrap();

        assert!(install(&exe, b"#!/bin/sh\nexit 1\n").await.is_err());
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "old");
        assert!(!with_suffix(&exe, ".new").exists(), "自检失败应清掉 .new");
        assert!(install(&exe, b"not an executable").await.is_err());
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "old");

        let good = b"#!/bin/sh\necho 9.9.9\n";
        assert_eq!(install(&exe, good).await.unwrap(), "9.9.9");
        assert_eq!(std::fs::read(&exe).unwrap(), good);
        assert_eq!(
            std::fs::read_to_string(with_suffix(&exe, ".prev")).unwrap(),
            "old"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stalled_self_check_keeps_old_executable() {
        let dir =
            std::env::temp_dir().join(format!("openxdr-upgrade-timeout-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let exe = dir.join("agent");
        std::fs::write(&exe, "old").unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            install(&exe, b"#!/bin/sh\nexec sleep 60\n"),
        )
        .await
        .unwrap();
        assert!(result.unwrap_err().to_string().contains("10 秒"));
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "old");
        assert!(!with_suffix(&exe, ".new").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_replacement_restores_old_executable() {
        let dir = std::env::temp_dir().join(format!("openxdr-rollback-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let exe = dir.join("agent");
        std::fs::write(&exe, "old").unwrap();
        assert!(replace(&exe, &dir.join("missing")).is_err());
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "old");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn hashes_and_suffixes() {
        assert_eq!(
            sha256_hex(&b"abc"[..]).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(self_sha256().len(), 64, "应能算出自身哈希");
        assert_eq!(
            with_suffix(Path::new("/usr/local/bin/openxdr-agent"), ".prev"),
            PathBuf::from("/usr/local/bin/openxdr-agent.prev")
        );
    }
}
