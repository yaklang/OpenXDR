//! 自动升级，与 agent 同一套流程：server 分发目录里放的是哪个版本，探针就收敛到哪个版本。
//!
//! 校验发布签名 → 经已认证的 gRPC 通道下载（带大小上限）→ 校验哈希 → 用新二进制跑一次 `version` 自检
//! （架构、libc 不兼容在这一步就暴露）→ 旧版改名 .prev 留作回滚 → 换上新版 → 退出，
//! 由 systemd 拉起新版。任何一步失败都保持旧版继续运行，下次重连再试。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use tokio_stream::StreamExt;

use crate::pb;
use crate::pb::sensor_service_client::SensorServiceClient;

/// 换上新版后的退出码：非零，systemd 视为需要重启
pub const EXIT_UPGRADED: i32 = 75;

/// 编译时嵌入的发布公钥（Ed25519，十六进制）：构建时设 OPENXDR_RELEASE_PUBKEY。
/// 嵌了就只装发布私钥签过的 sensor 安装包——私钥不在 server 上，拿下 server 节点也推不了恶意探针。
/// 开源默认构建不嵌，只校验哈希。
const RELEASE_PUBKEY: Option<&str> = option_env!("OPENXDR_RELEASE_PUBKEY");

/// 发布签名的域前缀，与 server/cmd/signrelease 一致，与 agent 域隔离
const RELEASE_CONTEXT: &[u8] = b"openxdr-sensor-release-v1\0";

/// 升级安装包下载大小上限（256 MiB），防止恶意或异常流耗尽探针内存
const MAX_DOWNLOAD_BYTES: usize = 256 * 1024 * 1024;

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

/// 下载并换上新版。成功返回后由调用方收尾（停抓包、推完在途会话）再退出。签名不对连下载都不做。
pub async fn apply(
    client: &mut SensorServiceClient<tonic::transport::Channel>,
    platform: &str,
    sha256: &str,
    signature: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    verify_release(RELEASE_PUBKEY, platform, sha256, signature)?;
    let stream = client
        .download_sensor(pb::SensorDownloadRequest {
            platform: platform.into(),
            sha256: sha256.into(),
        })
        .await?
        .into_inner();
    let data = collect_chunks(stream, MAX_DOWNLOAD_BYTES).await?;
    let got = sha256_hex(data.as_slice())?;
    if got != sha256 {
        return Err(format!("下载的安装包哈希不符：{got}").into());
    }
    let version = install(&std::env::current_exe()?, &data).await?;
    eprintln!("已安装 {version}，推完在途会话后退出重新拉起");
    Ok(())
}

/// 从分块流收集安装包字节，总大小超限时立即中止并报错。
async fn collect_chunks<S, E>(
    mut stream: S,
    max_bytes: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio_stream::Stream<Item = Result<pb::SensorChunk, E>> + Unpin,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut data = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(Into::into)?;
        if data.len().saturating_add(chunk.data.len()) > max_bytes {
            return Err(format!("下载的安装包超过大小上限（{} 字节），拒绝升级", max_bytes).into());
        }
        data.extend_from_slice(&chunk.data);
    }
    Ok(data)
}

/// 发布签名：对 前缀 + 平台 + "\0" + 安装包哈希 验签。没嵌公钥就不要求（开源默认构建）。
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
        return Err("安装包没有发布签名，拒绝升级（本 sensor 只装签过名的版本）".into());
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
async fn install(
    exe: &Path,
    data: &[u8],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let new = with_suffix(exe, ".new");
    remove_stale(&new)?;
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
    if let Err(e) = replace(exe, &new) {
        let _ = std::fs::remove_file(&new);
        return Err(e.into());
    }
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

/// 上次升级中途被杀会留下 .new，不清掉之后每次 create_new 都失败。
/// remove_file 只删链接本身不跟随；删完到重建之间若被人塞回文件，create_new + O_NOFOLLOW 仍会拒绝。
fn remove_stale(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    s.into()
}

#[cfg(not(unix))]
fn write_executable(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    if let Err(err) = f.write_all(data).and_then(|()| f.sync_all()) {
        let _ = std::fs::remove_file(path);
        return Err(err);
    }
    Ok(())
}

#[cfg(unix)]
fn write_executable(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if let Err(err) = f.write_all(data).and_then(|()| f.sync_all()) {
        let _ = std::fs::remove_file(path);
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与 server/cmd/signrelease 的 TestSensorReleaseSignatureVector 同一组：
    /// 全零种子对 sensor 域 + linux-amd64 + "abc" 的哈希签名
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
            "b10e0add23b86cf0bd97111a07eca82a4e4b78d1de69e63495ef040194b95fba\
             a66a6f35713561bd12663fa54adf3ae87b6f696da45b14068d3a8ff391161000",
        )
        .unwrap();
        assert!(verify_release(Some(&pubkey), "linux-amd64", &sha, &sig).is_ok());
        assert!(
            verify_release(Some(&pubkey), "linux-arm64", &sha, &sig).is_err(),
            "换平台应拒绝"
        );
        assert!(
            verify_release(Some(&pubkey), "linux-amd64", &"0".repeat(64), &sig).is_err(),
            "换安装包哈希应拒绝"
        );
        assert!(
            verify_release(Some(&pubkey), "linux-amd64", &sha, &[]).is_err(),
            "嵌了公钥时无签名应拒绝"
        );
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(verify_release(Some(&pubkey), "linux-amd64", &sha, &bad).is_err());
        // agent 域签出来的同种子同文件签名绝不能通过 sensor 验签
        let agent_sig = decode_hex(
            "e3b72a71a5927467e125239596e627ac089a981cd8c3c0421ff940747348c5fe\
             34a7505a6edf487eae2dc5ca5b6d612d02bb33c92b1f504b1b6f0f68ed31810d",
        )
        .unwrap();
        assert!(
            verify_release(Some(&pubkey), "linux-amd64", &sha, &agent_sig).is_err(),
            "agent 域签名不能跨组件用于 sensor"
        );
        assert!(
            verify_release(Some("zz"), "linux-amd64", &sha, &sig).is_err(),
            "嵌入公钥无效时应拒绝"
        );
        assert!(
            verify_release(None, "linux-amd64", &sha, &[]).is_ok(),
            "未嵌公钥时向后兼容，只校验哈希"
        );
    }

    #[tokio::test]
    async fn download_size_limit_rejects_oversized_stream() {
        let ok_stream = tokio_stream::iter(vec![
            Ok::<_, std::io::Error>(pb::SensorChunk { data: vec![1; 64] }),
            Ok(pb::SensorChunk { data: vec![2; 64] }),
        ]);
        let got = collect_chunks(ok_stream, 128).await.unwrap();
        assert_eq!(got.len(), 128);

        let too_big = tokio_stream::iter(vec![
            Ok::<_, std::io::Error>(pb::SensorChunk { data: vec![1; 64] }),
            Ok(pb::SensorChunk { data: vec![2; 65] }),
        ]);
        let err = collect_chunks(too_big, 128).await.unwrap_err();
        assert!(err.to_string().contains("超过大小上限"));
    }

    #[cfg(unix)]
    #[test]
    fn write_executable_rejects_existing_and_symlink() {
        use std::os::unix::fs::symlink;
        let dir =
            std::env::temp_dir().join(format!("openxdr-sensor-write-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        std::fs::write(&target, b"keep-me").unwrap();
        // 已存在文件应被 create_new 拒绝
        assert!(write_executable(&target, b"overwrite").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep-me");
        // 符号链接应被拒绝且不能覆盖目标文件
        let link = dir.join("openxdr-sensor.new");
        symlink(&target, &link).unwrap();
        assert!(write_executable(&link, b"evil").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep-me");
        std::fs::remove_dir_all(dir).ok();
    }

    /// install 测试并行时，一个测试 fork 自检子进程会继承另一个测试正在写的 .new 句柄，
    /// 后者再执行就是 ETXTBSY；串行跑
    #[cfg(unix)]
    static INSTALL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// 自检失败的新版不能换上去，旧版原地不动；自检通过才换，旧版留作 .prev。
    #[cfg(unix)]
    #[tokio::test]
    async fn install_swaps_only_after_self_check() {
        let _serial = INSTALL_LOCK.lock().await;
        let dir =
            std::env::temp_dir().join(format!("openxdr-sensor-upgrade-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("openxdr-sensor");
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

    /// 残留的 .new（中断的上次升级）不能挡住下一次；残留是符号链接时只删链接，不碰目标。
    #[cfg(unix)]
    #[tokio::test]
    async fn install_clears_stale_new() {
        let _serial = INSTALL_LOCK.lock().await;
        use std::os::unix::fs::symlink;
        let dir =
            std::env::temp_dir().join(format!("openxdr-sensor-stale-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("openxdr-sensor");
        std::fs::write(&exe, "old").unwrap();
        let new = with_suffix(&exe, ".new");
        let good = b"#!/bin/sh\necho 9.9.9\n";

        std::fs::write(&new, "half-written").unwrap();
        assert_eq!(install(&exe, good).await.unwrap(), "9.9.9");
        assert!(!new.exists());

        let target = dir.join("target");
        std::fs::write(&target, b"keep-me").unwrap();
        symlink(&target, &new).unwrap();
        assert_eq!(install(&exe, good).await.unwrap(), "9.9.9");
        assert_eq!(std::fs::read(&target).unwrap(), b"keep-me");
        assert!(std::fs::symlink_metadata(&new).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn failed_replacement_restores_old_executable() {
        let dir =
            std::env::temp_dir().join(format!("openxdr-sensor-rollback-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let exe = dir.join("sensor");
        std::fs::write(&exe, "old").unwrap();
        assert!(replace(&exe, &dir.join("missing")).is_err());
        assert_eq!(std::fs::read_to_string(&exe).unwrap(), "old");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn hashes_self() {
        assert_eq!(
            sha256_hex(&b"abc"[..]).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(self_sha256().len(), 64, "应能算出自身哈希");
    }
}
