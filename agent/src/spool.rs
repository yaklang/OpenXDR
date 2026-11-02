//! 已落盘的批次只有收到完整 ACK 后才能删除；容量不足时拒绝追加，不淘汰旧证据。
//!
//! 批次文件布局（v1，写入时使用）：
//! ```text
//! MAGIC "OXDRSPL1" (8) || codec (1) || sha256(plaintext) (32) || body (N)
//!   codec = 0：body 就是 plaintext
//!   codec = 1：body 是 plaintext 的 gzip
//!   plaintext = StoredBatch::encode_to_vec()，protobuf 编码不变
//! ```
//! 升级前的布局仍然可读（`sha256(plaintext) (32) || plaintext`），老批次照常补传。
//! 摘要按 plaintext 计算而不是 body：损坏检测语义与升级前一致，protobuf 编码也不被替换，
//! ACK 的条数语义因此不受压缩影响。
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use prost::Message;
use sha2::{Digest, Sha256};

use crate::pb::AgentEvent;

/// 单批上限，按 plaintext（`StoredBatch::encode_to_vec()`）计量。
/// 压缩只降低磁盘占用，不放宽单批大小与事件条数的语义。
const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_BATCH_EVENTS: usize = 500;
/// 老格式的摘要长度，也是新格式摘要的长度
const HEADER: usize = 32;

/// 新格式魔数。老格式的头 32 字节是 sha256，前 8 字节全撞上魔数的概率是 2^-64；
/// 真撞上也会在后面按 codec 解包或摘要校验时失败并进隔离区，不会被当成数据上传。
const MAGIC: &[u8; 8] = b"OXDRSPL1";
/// 不压缩：body 就是 plaintext
const CODEC_NONE: u8 = 0;
/// gzip：body 是 plaintext 的 gzip 压缩
const CODEC_GZIP: u8 = 1;
/// 新格式头长度：MAGIC(8) || codec(1) || sha256(plaintext)(32)
const HEADER_V1: usize = MAGIC.len() + 1 + HEADER;

#[derive(Clone, PartialEq, Message)]
struct StoredBatch {
    #[prost(message, repeated, tag = "1")]
    events: Vec<AgentEvent>,
}

pub struct Batch {
    pub sequence: u64,
    pub events: Vec<AgentEvent>,
}

pub struct Spool {
    dir: PathBuf,
    pub receipts: crate::receipts::Receipts,
    _lock: File,
    files: BTreeMap<u64, u64>,
    bytes: u64,
    limit: u64,
    next: u64,
}

impl Drop for Spool {
    fn drop(&mut self) {
        // 显式释放锁，避免并发启动子进程在 exec 前短暂持有同一文件描述。
        let _ = self._lock.unlock();
    }
}

impl Spool {
    pub fn open(dir: &Path, limit: u64) -> io::Result<Self> {
        if limit < MAX_BATCH_BYTES as u64 {
            return Err(invalid("缓存容量不能小于单批上限"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
            if fs::symlink_metadata(dir)?.permissions().mode() & 0o077 != 0 {
                return Err(invalid("缓存目录权限必须为 0700"));
            }
        }
        #[cfg(not(unix))]
        fs::create_dir_all(dir)?;
        if !fs::symlink_metadata(dir)?.is_dir() {
            return Err(invalid("缓存目录不能为符号链接"));
        }
        let lock_path = dir.join("lock");
        reject_symlink(&lock_path)?;
        let lock = private_file(&lock_path, false)?;
        lock.try_lock().map_err(io::Error::other)?;
        let mut spool = Self {
            receipts: crate::receipts::Receipts::open(&dir.join("receipts"))?,
            dir: dir.to_owned(),
            _lock: lock,
            files: BTreeMap::new(),
            bytes: 0,
            limit,
            next: 0,
        };
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "lock" || name == "session" || name == "receipts" || name == QUARANTINE {
                continue;
            }
            if name == "pending" || name == "session.pending" {
                reject_symlink(&entry.path())?;
                fs::remove_file(entry.path())?;
                continue;
            }
            let sequence = name
                .strip_suffix(".batch")
                .filter(|s| s.len() == 20 && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse::<u64>().ok());
            // 认不出或读不通的文件移进隔离区：证据留着，采集不能因此瘫痪
            let Some(sequence) = sequence else {
                quarantine(dir, &entry.path())?;
                continue;
            };
            let size = entry.metadata()?.len();
            if let Err(err) = read_batch(&entry.path()) {
                if err.kind() != io::ErrorKind::InvalidData {
                    return Err(err);
                }
                quarantine(dir, &entry.path())?;
                continue;
            }
            spool.files.insert(sequence, size);
            spool.bytes = spool
                .bytes
                .checked_add(size)
                .ok_or_else(|| invalid("缓存大小溢出"))?;
            spool.next = spool.next.max(
                sequence
                    .checked_add(1)
                    .ok_or_else(|| invalid("缓存序号耗尽"))?,
            );
        }
        sync_dir(dir)?;
        Ok(spool)
    }

    pub fn session(&self) -> io::Result<Option<crate::pb::RegisterResponse>> {
        let path = self.dir.join("session");
        reject_symlink(&path)?;
        let file = match File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        let session = (bytes.len() <= 1024 * 1024)
            .then(|| crate::pb::RegisterResponse::decode(bytes.as_slice()).ok())
            .flatten()
            .filter(|s| uuid::Uuid::parse_str(&s.agent_id).is_ok());
        // 注册配置读不通就隔离掉重新注册，不能卡在启动上
        if session.is_none() {
            quarantine(&self.dir, &self.dir.join("session"))?;
        }
        Ok(session)
    }

    /// server 换了注册身份（重装、库重建）：旧身份的批次和注册配置移进隔离区。
    /// 新身份补传不了旧身份的事件，留着只会让补传永远卡住
    pub fn retire_identity(&mut self) -> io::Result<()> {
        for sequence in std::mem::take(&mut self.files).into_keys() {
            quarantine(&self.dir, &self.path(sequence))?;
        }
        self.bytes = 0;
        let session = self.dir.join("session");
        if session.exists() {
            quarantine(&self.dir, &session)?;
        }
        Ok(())
    }

    pub fn save_session(&self, session: &crate::pb::RegisterResponse) -> io::Result<()> {
        if uuid::Uuid::parse_str(&session.agent_id).is_err() || session.encoded_len() > 1024 * 1024
        {
            return Err(invalid("注册配置无效或过大"));
        }
        let pending = self.dir.join("session.pending");
        let mut file = private_file(&pending, true)?;
        file.write_all(&session.encode_to_vec())?;
        file.sync_all()?;
        drop(file);
        replace_file(&pending, &self.dir.join("session"))?;
        sync_dir(&self.dir)
    }

    pub fn append(&mut self, events: Vec<AgentEvent>) -> io::Result<u64> {
        if events.is_empty() || events.len() > MAX_BATCH_EVENTS {
            return Err(invalid("批次必须包含 1 到 500 条事件"));
        }
        let batch = StoredBatch { events };
        // 单批上限继续按 plaintext 计量（连新格式头一起算，与升级前 plaintext + 32 字节头同口径）
        let reserved = batch
            .encoded_len()
            .checked_add(HEADER_V1)
            .ok_or_else(|| invalid("批次过大"))?;
        if reserved > MAX_BATCH_BYTES {
            return Err(invalid("批次超过 4 MiB"));
        }
        // 容量预检用 reserved（plaintext + 头）而不是压缩后大小：body 一定不大于 plaintext
        // （压不动就存原文，见下面 codec 的选择），所以 reserved 是落盘字节的严格上界，
        // 预检永远不会比实际写入乐观，rename 之后不可能出现“写进去才发现超限”，容量上界仍是硬的。
        // 反过来按压缩后大小预检必须先压缩才判断得出，被拒绝的批次也要先付一次压缩开销；
        // 剩余空间介于压缩后与未压缩大小之间时会多等一轮才落盘——旧证据仍保留，
        // delivery 每 5 秒重试一次，代价只是批次数多一点。
        if self.bytes.saturating_add(reserved as u64) > self.limit || self.files.len() >= 8192 {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "缓存已满，旧证据保留",
            ));
        }
        let next = self
            .next
            .checked_add(1)
            .ok_or_else(|| invalid("缓存序号耗尽"))?;
        let payload = batch.encode_to_vec();
        let digest = Sha256::digest(&payload);
        // 压不动（比如单条小事件压不过 gzip 的 18 字节容器开销）就存原文，避免负收益
        let (codec, body) = match gzip(&payload) {
            Some(body) if body.len() < payload.len() => (CODEC_GZIP, body),
            _ => (CODEC_NONE, payload),
        };
        let written = (HEADER_V1 + body.len()) as u64;
        let pending = self.dir.join("pending");
        let mut file = private_file(&pending, true)?;
        let write = (|| {
            file.write_all(MAGIC)?;
            file.write_all(&[codec])?;
            file.write_all(&digest)?;
            file.write_all(&body)?;
            file.sync_all()
        })();
        drop(file);
        if let Err(err) = write {
            let _ = fs::remove_file(&pending);
            return Err(err);
        }
        let sequence = self.next;
        replace_file(&pending, &self.path(sequence))?;
        // rename 后即计入本进程索引；目录同步失败也不能覆盖已写入的批次。
        // 容量按实际落盘的字节累计（压缩才换来更大的等效容量），索引恢复时用的也是文件长度。
        self.files.insert(sequence, written);
        self.bytes += written;
        self.next = next;
        sync_dir(&self.dir)?;
        Ok(sequence)
    }

    /// 最老的批次。运行中损坏的批次移进隔离区并跳过，否则补传会永远卡在它上面
    pub fn front(&mut self) -> io::Result<Option<Batch>> {
        while let Some((&sequence, &size)) = self.files.first_key_value() {
            match read_batch(&self.path(sequence)) {
                Ok(events) => return Ok(Some(Batch { sequence, events })),
                Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                    quarantine(&self.dir, &self.path(sequence))?;
                    self.files.remove(&sequence);
                    self.bytes -= size;
                }
                Err(err) => return Err(err),
            }
        }
        Ok(None)
    }

    /// 只能确认当前最老批次，且服务端接收条数必须与持久记录一致。
    pub fn acknowledge(&mut self, sequence: u64, received: u64) -> io::Result<()> {
        let batch = self.front()?.ok_or_else(|| invalid("缓存为空，无法确认"))?;
        if batch.sequence != sequence || batch.events.len() as u64 != received {
            return Err(invalid("ACK 与当前批次不匹配"));
        }
        fs::remove_file(self.path(sequence))?;
        self.bytes -= self.files.remove(&sequence).expect("front 已校验");
        sync_dir(&self.dir)
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn batches(&self) -> usize {
        self.files.len()
    }
    fn path(&self, sequence: u64) -> PathBuf {
        self.dir.join(format!("{sequence:020}.batch"))
    }
}

/// 隔离区子目录名。缓存与回执目录各有一个
pub(crate) const QUARANTINE: &str = "quarantine";

/// 把损坏或认不出的文件移进隔离区，保留原名加时间戳，等人核实
pub(crate) fn quarantine(dir: &Path, path: &Path) -> io::Result<()> {
    let target = dir.join(QUARANTINE);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&target)?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(&target)?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    eprintln!(
        "缓存文件 {name} 损坏或无法识别，已移入 {}",
        target.display()
    );
    fs::rename(path, target.join(format!("{stamp}-{name}")))?;
    sync_dir(dir)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn reject_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() => Err(invalid("缓存文件不是普通文件")),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

pub(crate) fn private_file(path: &Path, exclusive: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(!exclusive).create_new(exclusive);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// 用 flate2 的纯 Rust 后端（`miniz_oxide`，由 `rust_backend` 特性启用）压成 gzip。
/// 不选 zstd：CI 会把 agent 交叉编译到 `x86_64-pc-windows-gnu`，需要 C 工具链的压缩库
/// 进不了默认构建。`codec` 字节已为将来换算法预留——新增一个 codec 值即可，
/// 读路径按 codec 分派，老文件（codec 0/1）照常读，不需要改格式或迁移数据。
fn gzip(plaintext: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plaintext).ok()?;
    encoder.finish().ok()
}

/// 校验并解出新格式的 plaintext。所有异常都归为 `InvalidData`，由调用方移进隔离区：
/// 不 panic、不丢文件、也不让一个坏批次挡住后面的批次。
fn unpack(bytes: &[u8]) -> io::Result<Vec<u8>> {
    if bytes.len() < HEADER_V1 {
        return Err(invalid("持久批次损坏，保留原文件等待处理"));
    }
    let codec = bytes[MAGIC.len()];
    let digest = &bytes[MAGIC.len() + 1..HEADER_V1];
    let body = &bytes[HEADER_V1..];
    let plaintext = match codec {
        CODEC_NONE => {
            if body.len() > MAX_BATCH_BYTES {
                return Err(invalid("持久批次超过单批上限"));
            }
            body.to_vec()
        }
        CODEC_GZIP => {
            // 有界解压：压缩炸弹最多解出 MAX_BATCH_BYTES + 1 字节就停，
            // 不会因为 body 很小、展开很大而把内存打爆
            let mut plaintext = Vec::new();
            GzDecoder::new(body)
                .take(MAX_BATCH_BYTES as u64 + 1)
                .read_to_end(&mut plaintext)
                .map_err(|_| invalid("持久批次解压失败"))?;
            if plaintext.len() > MAX_BATCH_BYTES {
                return Err(invalid("持久批次解压后超过单批上限"));
            }
            plaintext
        }
        _ => return Err(invalid("持久批次使用了未知压缩编码")),
    };
    if Sha256::digest(&plaintext).as_slice() != digest {
        return Err(invalid("持久批次损坏，保留原文件等待处理"));
    }
    Ok(plaintext)
}

fn read_batch(path: &Path) -> io::Result<Vec<AgentEvent>> {
    reject_symlink(path)?;
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    // 上界：新格式头 + 单批上限（body 不会超过 plaintext，见 append），多读 1 字节用来判超限
    file.take((HEADER_V1 + MAX_BATCH_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > HEADER_V1 + MAX_BATCH_BYTES {
        return Err(invalid("持久批次损坏，保留原文件等待处理"));
    }
    let plaintext = if bytes.starts_with(MAGIC) {
        unpack(&bytes)?
    } else {
        // 升级前落盘的老格式：sha256(plaintext) || plaintext，照常校验、照常补传
        if bytes.len() <= HEADER
            || bytes.len() > MAX_BATCH_BYTES
            || Sha256::digest(&bytes[HEADER..])[..] != bytes[..HEADER]
        {
            return Err(invalid("持久批次损坏，保留原文件等待处理"));
        }
        bytes[HEADER..].to_vec()
    };
    let batch =
        StoredBatch::decode(plaintext.as_slice()).map_err(|_| invalid("持久批次解码失败"))?;
    if batch.events.is_empty() || batch.events.len() > MAX_BATCH_EVENTS {
        return Err(invalid("持久批次条数无效"));
    }
    Ok(batch.events)
}

pub(crate) fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(not(windows))]
    fs::rename(from, to)?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: from / to 是以 0 结尾的 UTF-16 缓冲，在调用期间一直存活，MoveFileExW 只读它们；标志为常量。
        if unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("openxdr-spool-test-{}", uuid::Uuid::new_v4())))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn event() -> AgentEvent {
        AgentEvent {
            agent_id: "agent".into(),
            raw_json: r#"{"process":"test"}"#.into(),
            ..Default::default()
        }
    }

    /// 一条贴近真实分布的进程事件：
    /// - 可重复的内容：JSON 骨架、可执行路径与 cmdline（同一个二进制反复启动）、
    ///   文件哈希（哈希是文件的属性，同一路径的事件共用同一个值）；
    /// - 每条独有的内容：随机进程 GUID、pid、时间戳。
    ///
    /// 压缩比取决于这两部分的比例，下面的报告按这个分布说明
    fn sample(index: usize) -> AgentEvent {
        let (path, cmdline) = match index % 4 {
            0 => (
                "/usr/bin/bash",
                "/usr/bin/bash -c cd /opt/app && ./deploy.sh",
            ),
            1 => ("/usr/sbin/sshd", "sshd: deploy [priv]"),
            2 => (
                "/usr/bin/curl",
                "/usr/bin/curl --connect-timeout 10 -o /tmp/pkg.tar.gz https://mirror.example.com/pkg.tar.gz",
            ),
            _ => (
                "/usr/bin/openssl",
                "/usr/bin/openssl enc -aes-256-cbc -salt -pbkdf2 -iter 600000",
            ),
        };
        AgentEvent {
            agent_id: "agent".into(),
            ts_unix_ns: 1_760_000_000_000_000_000 + index as i64 * 1_000_000,
            class_uid: 1007,
            process_guid: hex(32, index as u64 * 0x9e37_79b9),
            username: if index.is_multiple_of(3) {
                "root"
            } else {
                "deploy"
            }
            .into(),
            conn_tuple: if index.is_multiple_of(2) {
                "tcp:10.20.30.40:51234>198.51.100.7:443".into()
            } else {
                String::new()
            },
            raw_json: format!(
                "{{\"class_uid\":1007,\"process\":{{\"path\":\"{path}\",\"cmd_line\":\"{cmdline}\",\"pid\":{},\"file\":{{\"hashes\":[{{\"algorithm_id\":3,\"value\":\"{}\"}}]}}}},\"actor\":{{\"user\":{{\"name\":\"deploy\"}}}},\"message\":\"process activity\"}}",
                1000 + index,
                hex(64, (index % 4) as u64)
            ),
            parent_process_guid: "00000000-0000-4000-8000-0000000000ff".into(),
            dropped_events: 0,
        }
    }

    /// 确定性伪随机的十六进制串（模拟哈希 / GUID）：真实数据里这段不可压
    fn hex(len: usize, seed: u64) -> String {
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push(char::from(b"0123456789abcdef"[(state >> 33) as usize % 16]));
        }
        out
    }

    /// 确定性伪随机可打印 ASCII，模拟压不动的内容（哈希、base64、压缩包片段）
    fn random_ascii(seed: u64, len: usize) -> String {
        let mut state = seed | 1;
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push(char::from(b'!' + (state >> 33) as u8 % 94));
        }
        out
    }

    fn plaintext_of(events: &[AgentEvent]) -> Vec<u8> {
        StoredBatch {
            events: events.to_vec(),
        }
        .encode_to_vec()
    }

    fn batch_file(dir: &Path, sequence: u64) -> PathBuf {
        dir.join(format!("{sequence:020}.batch"))
    }

    /// 手工放文件前先把缓存目录建成 0700（`Spool::open` 会校验目录权限）
    fn create_private_dir(dir: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(dir).unwrap();
        }
        #[cfg(not(unix))]
        fs::create_dir_all(dir).unwrap();
    }

    /// 手工写升级前的老格式批次：sha256(plaintext) || plaintext
    fn write_legacy(dir: &Path, sequence: u64, plaintext: &[u8]) {
        create_private_dir(dir);
        let mut bytes = Sha256::digest(plaintext).to_vec();
        bytes.extend_from_slice(plaintext);
        fs::write(batch_file(dir, sequence), bytes).unwrap();
    }

    /// 手工写新格式批次，codec / digest / body 全由调用方指定，用来构造损坏样本
    fn write_v1(dir: &Path, sequence: u64, codec: u8, digest: &[u8], body: &[u8]) {
        create_private_dir(dir);
        let mut bytes = MAGIC.to_vec();
        bytes.push(codec);
        bytes.extend_from_slice(digest);
        bytes.extend_from_slice(body);
        fs::write(batch_file(dir, sequence), bytes).unwrap();
    }

    #[test]
    fn session_updates_survive_restart() {
        let dir = Temp::new();
        let spool = Spool::open(&dir.0, 8 << 20).unwrap();
        let mut session = crate::pb::RegisterResponse {
            agent_id: uuid::Uuid::new_v4().to_string(),
            config_json: "{}".into(),
            ..Default::default()
        };
        spool.save_session(&session).unwrap();
        session.config_json = r#"{"collectNetwork":false}"#.into();
        spool.save_session(&session).unwrap();
        drop(spool);
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        assert_eq!(spool.session().unwrap(), Some(session));

        // 换了注册身份：旧批次与注册配置进隔离区
        spool.append(vec![event()]).unwrap();
        spool.retire_identity().unwrap();
        assert_eq!((spool.batches(), spool.bytes()), (0, 0));
        assert_eq!(spool.session().unwrap(), None);
        assert_eq!(fs::read_dir(dir.0.join(QUARANTINE)).unwrap().count(), 2);

        // 注册配置损坏：隔离后当作未注册
        fs::write(dir.0.join("session"), b"\xff\xff").unwrap();
        assert_eq!(spool.session().unwrap(), None);
        assert!(!dir.0.join("session").exists());
    }

    #[test]
    fn restart_replays_until_exact_ack() {
        let dir = Temp::new();
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        let id = spool.append(vec![event(), event()]).unwrap();
        let second = spool.append(vec![event()]).unwrap();
        assert!(spool.bytes() > 0);
        assert_eq!(spool.batches(), 2);
        assert!(spool.acknowledge(second, 1).is_err());
        assert!(spool.acknowledge(id, 1).is_err());
        drop(spool);
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        assert_eq!(
            spool.front().unwrap().unwrap().events,
            vec![event(), event()]
        );
        spool.acknowledge(id, 2).unwrap();
        assert_eq!(spool.front().unwrap().unwrap().sequence, second);
        spool.acknowledge(second, 1).unwrap();
        assert_eq!(spool.bytes(), 0);
        assert!(spool.front().unwrap().is_none());
    }

    #[test]
    fn exclusive_owner_and_uncommitted_recovery() {
        let dir = Temp::new();
        let spool = Spool::open(&dir.0, 8 << 20).unwrap();
        assert!(Spool::open(&dir.0, 8 << 20).is_err());
        fs::write(dir.0.join("pending"), b"partial write").unwrap();
        let inherited = spool._lock.try_clone().unwrap();
        drop(spool);
        let spool = Spool::open(&dir.0, 8 << 20).unwrap();
        drop(inherited);
        assert!(Spool::open(&dir.0, 8 << 20).is_err());
        assert_eq!(spool.batches(), 0);
        assert!(!dir.0.join("pending").exists());
    }

    #[test]
    fn corruption_is_not_silently_discarded() {
        let dir = Temp::new();
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        let id = spool.append(vec![event()]).unwrap();
        let path = spool.path(id);
        let next = spool.append(vec![event()]).unwrap();
        fs::write(&path, b"corrupt").unwrap();
        // 损坏批次移进隔离区，补传接着走下一批
        assert_eq!(spool.front().unwrap().unwrap().sequence, next);
        assert!(!path.exists());
        assert_eq!(fs::read_dir(dir.0.join(QUARANTINE)).unwrap().count(), 1);
        assert!(spool.acknowledge(id, 1).is_err());
        drop(spool);

        // 启动时遇到坏批次与陌生文件同样隔离，不拒绝启动
        fs::write(dir.0.join(format!("{:020}.batch", next + 1)), b"corrupt").unwrap();
        fs::write(dir.0.join("stray"), b"?").unwrap();
        let spool = Spool::open(&dir.0, 8 << 20).unwrap();
        assert_eq!(spool.batches(), 1);
        assert_eq!(fs::read_dir(dir.0.join(QUARANTINE)).unwrap().count(), 3);
    }

    #[test]
    fn full_queue_preserves_old_batches() {
        let dir = Temp::new();
        let mut spool = Spool::open(&dir.0, 4 << 20).unwrap();
        let mut large = event();
        // 用不可压内容表达“一批就占掉大部分容量”：重复的 'x' 压缩后只剩几 KiB，
        // 队列永远撞不到字节上限，测不到这条语义。断言本身未改
        large.raw_json = random_ascii(0x5eed, 3 << 20);
        let id = spool.append(vec![large.clone()]).unwrap();
        assert_eq!(
            spool.append(vec![large.clone()]).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(spool.front().unwrap().unwrap().events, vec![large]);
        spool.acknowledge(id, 1).unwrap();
        assert!(spool.append(vec![event()]).is_ok());
        assert!(spool.append(vec![]).is_err());
    }

    #[test]
    fn new_format_round_trip() {
        let dir = Temp::new();
        let events: Vec<_> = (0..40).map(sample).collect();
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        let sequence = spool.append(events.clone()).unwrap();
        let bytes = fs::read(batch_file(&dir.0, sequence)).unwrap();
        assert!(bytes.starts_with(MAGIC));
        assert_eq!(bytes[MAGIC.len()], CODEC_GZIP);
        drop(spool);

        // 重启后照常取出，事件逐字段相等
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        let batch = spool.front().unwrap().unwrap();
        assert_eq!(batch.sequence, sequence);
        assert_eq!(batch.events, events);
        spool.acknowledge(sequence, events.len() as u64).unwrap();
        assert_eq!(spool.batches(), 0);
    }

    #[test]
    fn legacy_batch_still_uploads_after_upgrade() {
        let dir = Temp::new();
        let events: Vec<_> = (0..3).map(sample).collect();
        // 升级前落盘的文件：没有 MAGIC，就是 sha256 || payload
        write_legacy(&dir.0, 7, &plaintext_of(&events));

        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        assert_eq!(spool.batches(), 1);
        assert!(!dir.0.join(QUARANTINE).exists());
        let batch = spool.front().unwrap().unwrap();
        assert_eq!((batch.sequence, batch.events), (7, events));
        spool.acknowledge(7, 3).unwrap();
        assert_eq!(spool.batches(), 0);
        assert_eq!(spool.bytes(), 0);
        assert!(!batch_file(&dir.0, 7).exists());
    }

    #[test]
    fn corrupted_new_format_is_quarantined_without_stalling() {
        let dir = Temp::new();
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        let broken = spool.append(vec![sample(0)]).unwrap();
        let next = spool.append(vec![sample(1)]).unwrap();

        // 改坏 body 最后一个字节（gzip 的 ISIZE 字段）：解压或摘要必然对不上
        let path = batch_file(&dir.0, broken);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x5a;
        fs::write(&path, &bytes).unwrap();

        // 不 panic，坏批次进隔离区，补传接着走下一批
        let batch = spool.front().unwrap().unwrap();
        assert_eq!(batch.sequence, next);
        assert_eq!(batch.events, vec![sample(1)]);
        assert!(!path.exists());
        assert_eq!(fs::read_dir(dir.0.join(QUARANTINE)).unwrap().count(), 1);
        assert!(spool.acknowledge(broken, 1).is_err());
    }

    #[test]
    fn unknown_codec_is_quarantined() {
        // 启动阶段：认不出 codec 的文件被隔离，不拒绝启动
        let dir = Temp::new();
        let events = vec![sample(2)];
        let plaintext = plaintext_of(&events);
        write_v1(&dir.0, 1, 0x7f, &Sha256::digest(&plaintext), &plaintext);
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        assert_eq!(spool.batches(), 0);
        assert_eq!(fs::read_dir(dir.0.join(QUARANTINE)).unwrap().count(), 1);

        // 运行中取批：同样隔离，并接着取下一批
        let first = spool.append(events.clone()).unwrap();
        let second = spool.append(events).unwrap();
        let path = batch_file(&dir.0, first);
        let mut bytes = fs::read(&path).unwrap();
        bytes[MAGIC.len()] = 0x7f;
        fs::write(&path, &bytes).unwrap();
        assert_eq!(spool.front().unwrap().unwrap().sequence, second);
        assert_eq!(fs::read_dir(dir.0.join(QUARANTINE)).unwrap().count(), 2);
    }

    #[test]
    fn digest_covers_plaintext_not_compressed_body() {
        let events = vec![sample(3)];
        let plaintext = plaintext_of(&events);
        let body = gzip(&plaintext).unwrap();
        assert!(body.len() < plaintext.len());

        // 正例：摘要按 plaintext 算 → 读得回来
        let dir = Temp::new();
        write_v1(&dir.0, 1, CODEC_GZIP, &Sha256::digest(&plaintext), &body);
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        assert_eq!(spool.front().unwrap().unwrap().events, events);
        assert!(!dir.0.join(QUARANTINE).exists());

        // 反例：摘要按 body 算（复用旧语义就会这样）→ 隔离，证明摘要不是对 body 的计算
        let dir = Temp::new();
        write_v1(&dir.0, 1, CODEC_GZIP, &Sha256::digest(&body), &body);
        let spool = Spool::open(&dir.0, 8 << 20).unwrap();
        assert_eq!(spool.batches(), 0);
        assert_eq!(fs::read_dir(dir.0.join(QUARANTINE)).unwrap().count(), 1);

        // codec 位 1 → 0：body 还是 gzip 字节，按原文读时摘要对不上 → 隔离
        let dir = Temp::new();
        write_v1(&dir.0, 1, CODEC_NONE, &Sha256::digest(&plaintext), &body);
        let spool = Spool::open(&dir.0, 8 << 20).unwrap();
        assert_eq!(spool.batches(), 0);
        assert_eq!(fs::read_dir(dir.0.join(QUARANTINE)).unwrap().count(), 1);

        // codec 位 0 → 1：body 是原文却按 gzip 解 → 解压失败 → 隔离
        let dir = Temp::new();
        write_v1(
            &dir.0,
            1,
            CODEC_GZIP,
            &Sha256::digest(&plaintext),
            &plaintext,
        );
        let spool = Spool::open(&dir.0, 8 << 20).unwrap();
        assert_eq!(spool.batches(), 0);
        assert_eq!(fs::read_dir(dir.0.join(QUARANTINE)).unwrap().count(), 1);
    }

    #[test]
    fn compression_shrinks_disk_footprint() {
        let dir = Temp::new();
        let mut spool = Spool::open(&dir.0, 256 << 20).unwrap();
        let events: Vec<_> = (0..250).map(sample).collect();
        let mut plaintext_total = 0usize;
        let mut sequences = Vec::new();
        for chunk in events.chunks(128) {
            plaintext_total += plaintext_of(chunk).len();
            sequences.push(spool.append(chunk.to_vec()).unwrap());
        }
        let disk: u64 = sequences
            .iter()
            .map(|sequence| fs::metadata(batch_file(&dir.0, *sequence)).unwrap().len())
            .sum();
        assert_eq!(spool.bytes(), disk);
        assert!(
            (disk as usize) * 3 < plaintext_total,
            "落盘 {disk} 字节应不到 plaintext {plaintext_total} 字节的三分之一"
        );
        for sequence in sequences {
            let bytes = fs::read(batch_file(&dir.0, sequence)).unwrap();
            assert_eq!(bytes[MAGIC.len()], CODEC_GZIP);
        }
    }

    #[test]
    fn incompressible_batch_falls_back_to_raw_codec() {
        let dir = Temp::new();
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        // 单条高熵事件：gzip 的 18 字节容器开销压不回来，落盘应退化为 codec=0
        let events = vec![AgentEvent {
            agent_id: "agent".into(),
            raw_json: random_ascii(7, 96),
            ..Default::default()
        }];
        let plaintext = plaintext_of(&events);
        assert!(gzip(&plaintext).unwrap().len() >= plaintext.len());

        let sequence = spool.append(events.clone()).unwrap();
        let bytes = fs::read(batch_file(&dir.0, sequence)).unwrap();
        assert_eq!(bytes[MAGIC.len()], CODEC_NONE);
        assert_eq!(&bytes[HEADER_V1..], plaintext.as_slice());
        assert_eq!(spool.front().unwrap().unwrap().events, events);
    }

    #[test]
    fn capacity_counts_disk_bytes_but_prechecks_plaintext() {
        let dir = Temp::new();
        let mut spool = Spool::open(&dir.0, 4 << 20).unwrap();
        let mut sequences = Vec::new();
        for seed in 1..=2 {
            let mut big = event();
            big.raw_json = random_ascii(seed, 2 << 20);
            sequences.push(spool.append(vec![big]).unwrap());
        }
        // 容量按实际落盘字节累计：压缩后的占用决定了 256 MiB 能装多少事件
        let used = spool.bytes();
        assert!((2 << 20) < used && used < (4 << 20), "已占用 {used} 字节");

        // 高度可压的批次实际只占几 KiB（磁盘上放得下），但预检按 plaintext 计量 → 拒绝。
        // 宁可少装一批，也不让 rename 之后才发现超限
        let mut compressible = event();
        compressible.raw_json = "x".repeat(3 << 20);
        let compressed = gzip(&plaintext_of(&[compressible.clone()])).unwrap().len() as u64;
        assert!((HEADER_V1 as u64 + compressed) < (16 << 10));
        assert!(used + HEADER_V1 as u64 + compressed < 4 << 20);
        assert_eq!(
            spool.append(vec![compressible]).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );

        // 旧证据照常可读、可确认
        for sequence in sequences {
            let batch = spool.front().unwrap().unwrap();
            assert_eq!(batch.sequence, sequence);
            spool.acknowledge(sequence, 1).unwrap();
        }
        assert_eq!(spool.bytes(), 0);
        assert!(spool.append(vec![event()]).is_ok());
    }

    /// 前后对比：500 条代表性事件在 128 条/批下的落盘字节与 256 MiB 等效容量。
    /// 用 `cargo test --locked spool -- --nocapture` 查看输出
    #[test]
    fn old_reader_rejects_new_format_instead_of_uploading() {
        // 降级回旧版 agent 时，旧读路径只认 sha256(plaintext) || plaintext。
        // 按旧规则判定新格式文件：摘要必然对不上 → 旧版走 InvalidData 分支把它移进
        // quarantine，保留证据，不会把容器头当成事件上报
        let dir = Temp::new();
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        let sequence = spool.append(vec![sample(4)]).unwrap();
        let bytes = fs::read(batch_file(&dir.0, sequence)).unwrap();
        assert!(bytes.len() > HEADER);
        assert_ne!(
            Sha256::digest(&bytes[HEADER..]).as_slice(),
            &bytes[..HEADER]
        );
    }

    #[test]
    fn representative_500_events_compression_report() {
        let dir = Temp::new();
        let mut spool = Spool::open(&dir.0, 256 << 20).unwrap();
        let events: Vec<_> = (0..500).map(sample).collect();
        let (mut plaintext_total, mut legacy_total) = (0usize, 0usize);
        let mut sequences = Vec::new();
        for chunk in events.chunks(128) {
            let plaintext = plaintext_of(chunk);
            plaintext_total += plaintext.len();
            legacy_total += plaintext.len() + HEADER;
            sequences.push(spool.append(chunk.to_vec()).unwrap());
        }
        let disk_total: u64 = sequences
            .iter()
            .map(|sequence| fs::metadata(batch_file(&dir.0, *sequence)).unwrap().len())
            .sum();
        assert_eq!(spool.bytes(), disk_total);

        let ratio = legacy_total as f64 / disk_total as f64;
        let saving = 100.0 - disk_total as f64 / legacy_total as f64 * 100.0;
        let capacity = 256.0 * 1024.0 * 1024.0;
        let before = capacity / (legacy_total as f64 / 500.0);
        let after = capacity / (disk_total as f64 / 500.0);
        println!("500 条代表性事件（128 条/批，{} 批）：", sequences.len());
        println!("  plaintext 编码总字节 : {plaintext_total}");
        println!("  升级前落盘总字节     : {legacy_total}（plaintext + 每批 {HEADER} 字节头）");
        println!("  压缩后落盘总字节     : {disk_total}");
        println!("  压缩比（旧/新）      : {ratio:.2}x");
        println!("  磁盘节省             : {saving:.1}%");
        println!(
            "  单事件平均占用       : 旧 {:.0} 字节 → 新 {:.0} 字节",
            legacy_total as f64 / 500.0,
            disk_total as f64 / 500.0
        );
        println!(
            "  256 MiB 等效容量     : 旧 {before:.0} 条 → 新 {after:.0} 条（{:.2}x）",
            after / before
        );
        assert!(ratio > 1.5, "压缩比 {ratio:.2} 太低");
    }
}
