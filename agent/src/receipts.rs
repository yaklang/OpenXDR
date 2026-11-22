//! 指令执行前记录占位，执行后保存结果；只重传回执，绝不恢复执行。
use crate::{
    pb,
    spool::{QUARANTINE, private_file, quarantine, reject_symlink, replace_file, sync_dir},
};
use prost::Message;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const MAX_RECORDS: usize = 256;
const MAX_BYTES: usize = 1024 * 1024;
/// 防重放记录上限与文件名：持续保留已见过的 command_id 直到超过 expires_unix，
/// 彻底关闭回执 ACK 删除后到信封过期前的重放窗口
const MAX_SEEN: usize = 4096;
const SEEN_FILE: &str = "seen";
const SEEN_PENDING: &str = "seen.pending";
const INTERRUPTED: &str = "执行被 agent 停止或重启打断，结果未知；未重执行，请核实主机状态";

pub struct Receipts {
    dir: PathBuf,
    records: BTreeMap<String, pb::CommandResult>,
    ready: BTreeSet<String>,
    seen: BTreeMap<String, i64>,
}

fn now_unix_opt() -> Option<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

fn load_seen(path: &Path) -> Option<BTreeMap<String, i64>> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_BYTES as u64 + 33)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() <= 32
        || bytes.len() > MAX_BYTES + 32
        || Sha256::digest(&bytes[32..])[..] != bytes[..32]
    {
        return None;
    }
    let map: BTreeMap<String, i64> = serde_json::from_slice(&bytes[32..]).ok()?;
    if map.len() > MAX_SEEN || !map.iter().all(|(k, &v)| valid_id(k) && v > 0) {
        return None;
    }
    Some(map)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn valid_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|v| !v.is_nil() && v.to_string() == id)
}

/// 读出一条回执；损坏、身份或状态不合法时返回 None
fn load(path: &Path, name: &str) -> Option<pb::CommandResult> {
    if !valid_id(name) {
        return None;
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_BYTES as u64 + 33)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() <= 32
        || bytes.len() > MAX_BYTES + 32
        || Sha256::digest(&bytes[32..])[..] != bytes[..32]
    {
        return None;
    }
    let result = pb::CommandResult::decode(&bytes[32..]).ok()?;
    let ok = result.command_id == name
        && valid_id(&result.agent_id)
        && pb::command_result::Status::try_from(result.status).is_ok();
    ok.then_some(result)
}

impl Receipts {
    pub fn open(dir: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(dir).or_else(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(e)
                }
            })?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        if fs::symlink_metadata(dir)?.permissions().mode() & 0o077 != 0 {
            return Err(invalid("回执目录权限必须为 0700"));
        }
        if !fs::symlink_metadata(dir)?.is_dir() {
            return Err(invalid("回执目录不是普通目录"));
        }
        let mut store = Self {
            dir: dir.into(),
            records: BTreeMap::new(),
            ready: BTreeSet::new(),
            seen: BTreeMap::new(),
        };
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == QUARANTINE {
                continue;
            }
            reject_symlink(&entry.path())?;
            if name == "pending" || name == SEEN_PENDING {
                fs::remove_file(entry.path())?;
                continue;
            }
            if name == SEEN_FILE {
                match load_seen(&entry.path()) {
                    Some(map) => store.seen = map,
                    None => quarantine(dir, &entry.path())?,
                }
                continue;
            }
            // 读不通的回执移进隔离区等人核实，不能让整台 agent 起不来
            match load(&entry.path(), &name) {
                Some(result) if store.records.len() < MAX_RECORDS => {
                    // 上次运行没写下结果的执行：多半被停机或升级打断。照实报成结果未知，绝不重执行
                    store.ready.insert(name.clone());
                    let result = match result.status {
                        0 => pb::CommandResult {
                            detail: INTERRUPTED.into(),
                            ..result
                        },
                        _ => result,
                    };
                    store.records.insert(name, result);
                }
                _ => quarantine(dir, &entry.path())?,
            }
        }
        if let Some(now) = now_unix_opt()
            && store.prune_seen(now)
        {
            store.save_seen()?;
        }
        sync_dir(dir)?;
        Ok(store)
    }

    fn save_seen(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec(&self.seen).map_err(|_| invalid("防重放表序列化失败"))?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid("防重放表超过容量上限"));
        }
        let pending = self.dir.join(SEEN_PENDING);
        reject_symlink(&pending)?;
        if pending.exists() {
            fs::remove_file(&pending)?;
        }
        let mut file = private_file(&pending, true)?;
        file.write_all(&Sha256::digest(&bytes))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        replace_file(&pending, &self.dir.join(SEEN_FILE))?;
        sync_dir(&self.dir)
    }

    /// 清理已超过 expires_unix 的防重放条目，返回是否有条目被删除
    fn prune_seen(&mut self, now_unix: i64) -> bool {
        if now_unix <= 0 {
            return false;
        }
        let before = self.seen.len();
        self.seen.retain(|_, exp| *exp >= now_unix);
        self.seen.len() != before
    }

    fn record_seen(&mut self, command: &str, expires_unix: i64, now_unix: i64) -> io::Result<()> {
        if expires_unix <= 0 {
            return Ok(());
        }
        self.prune_seen(now_unix);
        if self.seen.len() >= MAX_SEEN
            && !self.seen.contains_key(command)
            && let Some(oldest) = self
                .seen
                .iter()
                .min_by_key(|(_, exp)| **exp)
                .map(|(k, _)| k.clone())
        {
            self.seen.remove(&oldest);
        }
        self.seen.insert(command.into(), expires_unix);
        self.save_seen()
    }

    fn save(&mut self, result: pb::CommandResult) -> io::Result<()> {
        let bytes = result.encode_to_vec();
        if bytes.len() > MAX_BYTES {
            return Err(invalid("回执超过容量上限"));
        }
        let pending = self.dir.join("pending");
        reject_symlink(&pending)?;
        if pending.exists() {
            fs::remove_file(&pending)?;
        }
        let mut file = private_file(&pending, true)?;
        file.write_all(&Sha256::digest(&bytes))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        replace_file(&pending, &self.dir.join(&result.command_id))?;
        let id = result.command_id.clone();
        let terminal = result.status != 0;
        self.records.insert(id.clone(), result);
        sync_dir(&self.dir)?;
        if terminal {
            self.ready.insert(id);
        }
        Ok(())
    }

    pub fn reserve(
        &mut self,
        agent: &str,
        command: &str,
        expires_unix: i64,
        now_unix: i64,
    ) -> io::Result<bool> {
        if !valid_id(agent) || !valid_id(command) {
            return Err(invalid("指令身份无效"));
        }
        let pruned = self.prune_seen(now_unix);
        if self.records.contains_key(command) || self.seen.contains_key(command) {
            if pruned {
                let _ = self.save_seen();
            }
            return Ok(false);
        }
        if self.records.len() >= MAX_RECORDS {
            return Err(invalid("回执缓存已满，拒绝执行新指令"));
        }
        self.save(pb::CommandResult {
            agent_id: agent.into(),
            command_id: command.into(),
            detail: "执行尚无持久结果，禁止自动重执行".into(),
            ..Default::default()
        })?;
        // 持久化防重放记录（即使回执随后被 ACK 删除，在 expires_unix 之前仍拒绝重放）
        self.record_seen(command, expires_unix, now_unix)?;
        Ok(true)
    }

    pub fn finish(&mut self, result: pb::CommandResult) -> io::Result<()> {
        let stored = self
            .records
            .get(&result.command_id)
            .ok_or_else(|| invalid("指令未预留回执"))?;
        if stored == &result && stored.status != 0 {
            sync_dir(&self.dir)?;
            self.ready.insert(result.command_id);
            return Ok(());
        }
        if stored.agent_id != result.agent_id
            || stored.status != 0
            || !matches!(
                result.status(),
                pb::command_result::Status::Succeeded
                    | pb::command_result::Status::Failed
                    | pb::command_result::Status::Unsupported
            )
        {
            return Err(invalid("回执身份或终态冲突"));
        }
        self.save(result)
    }

    pub fn stats(&self) -> crate::health::ReceiptHealth {
        crate::health::ReceiptHealth {
            pending: self.ready.len(),
            incomplete: self.records.len() - self.ready.len(),
        }
    }

    /// 待上报的回执。不属于当前注册身份的（server 重建后换了 agent_id）移进隔离区：
    /// 新身份报不了旧身份的结果，留在队里只会占满名额
    pub fn pending(&mut self, agent: &str) -> io::Result<Vec<pb::CommandResult>> {
        if let Some(now) = now_unix_opt()
            && self.prune_seen(now)
        {
            let _ = self.save_seen();
        }
        let foreign: Vec<String> = self
            .records
            .values()
            .filter(|r| r.agent_id != agent && self.ready.contains(&r.command_id))
            .map(|r| r.command_id.clone())
            .collect();
        for id in foreign {
            quarantine(&self.dir, &self.dir.join(&id))?;
            self.records.remove(&id);
            self.ready.remove(&id);
        }
        Ok(self
            .records
            .values()
            .filter(|r| self.ready.contains(&r.command_id))
            .cloned()
            .collect())
    }

    /// server 明确拒收（指令不存在或不属于本机）的回执：再传也不会成功，移进隔离区
    pub fn reject(&mut self, agent: &str, command: &str) -> io::Result<()> {
        match self.records.get(command) {
            Some(r) if r.agent_id == agent && self.ready.contains(command) => {}
            _ => return Err(invalid("回执拒收目标无效")),
        }
        quarantine(&self.dir, &self.dir.join(command))?;
        self.records.remove(command);
        self.ready.remove(command);
        if let Some(now) = now_unix_opt()
            && self.prune_seen(now)
        {
            let _ = self.save_seen();
        }
        Ok(())
    }

    pub fn acknowledge(&mut self, agent: &str, command: &str) -> io::Result<()> {
        let record = self
            .records
            .get(command)
            .ok_or_else(|| invalid("回执确认不存在"))?;
        if record.agent_id != agent || !self.ready.contains(command) {
            return Err(invalid("回执确认身份或状态无效"));
        }
        fs::remove_file(self.dir.join(command))?;
        self.records.remove(command);
        self.ready.remove(command);
        // 保留 seen 中的防重放记录直到超过 expires_unix，仅清理已过期的其他条目
        if let Some(now) = now_unix_opt()
            && self.prune_seen(now)
        {
            let _ = self.save_seen();
        }
        sync_dir(&self.dir)
    }
}

/// 逐条上报，单条失败不挡后面的；返回遇到的第一个暂时性错误
pub async fn upload_once(
    client: &mut pb::agent_service_client::AgentServiceClient<tonic::transport::Channel>,
    queue: &crate::delivery::Queue,
    agent: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let id = agent.to_owned();
    let pending = crate::delivery::access(queue, move |s| s.receipts.pending(&id)).await?;
    let mut first: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    for result in pending {
        let command = result.command_id.clone();
        let id = agent.to_owned();
        let sent = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            client.report_command_result(result),
        )
        .await;
        let outcome: Result<(), Box<dyn std::error::Error + Send + Sync>> = match sent {
            Ok(Ok(ack)) if ack.get_ref().command_id == command => {
                crate::delivery::access(queue, move |s| s.receipts.acknowledge(&id, &command))
                    .await
                    .map_err(Into::into)
            }
            Ok(Ok(_)) => Err(invalid("服务端确认的指令不匹配，保留回执").into()),
            // 旧 server 没有独立回执接口：结果已顺着指令流回过一份，本地记录不再重传
            Ok(Err(status)) if status.code() == tonic::Code::Unimplemented => {
                crate::delivery::access(queue, move |s| s.receipts.acknowledge(&id, &command))
                    .await
                    .map_err(Into::into)
            }
            Ok(Err(status)) if rejected(status.code()) => {
                eprintln!(
                    "服务端拒收回执 {command}（{}），移入隔离区",
                    status.message()
                );
                crate::delivery::access(queue, move |s| s.receipts.reject(&id, &command))
                    .await
                    .map_err(Into::into)
            }
            Ok(Err(status)) => Err(status.into()),
            Err(elapsed) => Err(elapsed.into()),
        };
        if let Err(err) = outcome {
            first.get_or_insert(err);
        }
    }
    first.map_or(Ok(()), Err)
}

/// server 确定性拒收：指令不存在、不属于本机、内容不合法。重传不会改变结果
fn rejected(code: tonic::Code) -> bool {
    matches!(
        code,
        tonic::Code::NotFound | tonic::Code::PermissionDenied | tonic::Code::InvalidArgument
    )
}

pub async fn upload(
    mut client: pb::agent_service_client::AgentServiceClient<tonic::transport::Channel>,
    queue: crate::delivery::Queue,
    agent: String,
) {
    loop {
        if let Err(error) = upload_once(&mut client, &queue, &agent).await {
            eprintln!("回执上报失败，保留结果等待重传: {error}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_or_unwritable_queue_refuses_reservation_and_corruption_is_preserved() {
        let dir = std::env::temp_dir().join(format!("receipts-fault-{}", uuid::Uuid::new_v4()));
        let mut store = Receipts::open(&dir).unwrap();
        let agent = uuid::Uuid::new_v4().to_string();
        let command = uuid::Uuid::new_v4().to_string();
        let now = now_unix_opt().unwrap();
        let exp = now + 3600;
        fs::create_dir(dir.join("pending")).unwrap();
        assert!(store.reserve(&agent, &command, exp, now).is_err());
        assert!(store.records.is_empty());
        fs::remove_dir(dir.join("pending")).unwrap();
        assert!(store.reserve(&agent, &command, exp, now).unwrap());
        for _ in 1..MAX_RECORDS {
            assert!(
                store
                    .reserve(&agent, &uuid::Uuid::new_v4().to_string(), exp, now)
                    .unwrap()
            );
        }
        assert!(
            store
                .reserve(&agent, &uuid::Uuid::new_v4().to_string(), exp, now)
                .is_err()
        );
        drop(store);
        let store = Receipts::open(&dir).unwrap();
        assert_eq!(store.records.len(), MAX_RECORDS);
        drop(store);
        // 损坏的回执与陌生文件移进隔离区，其余照常恢复
        fs::write(dir.join(&command), b"corrupt").unwrap();
        fs::write(dir.join("stray"), b"?").unwrap();
        let store = Receipts::open(&dir).unwrap();
        assert_eq!(store.records.len(), MAX_RECORDS - 1);
        assert!(!dir.join(&command).exists());
        assert_eq!(fs::read_dir(dir.join(QUARANTINE)).unwrap().count(), 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn restart_preserves_uncertainty_and_terminal_result() {
        let dir = std::env::temp_dir().join(format!("receipts-{}", uuid::Uuid::new_v4()));
        let agent = uuid::Uuid::new_v4().to_string();
        let command = uuid::Uuid::new_v4().to_string();
        let uncertain = uuid::Uuid::new_v4().to_string();
        let now = now_unix_opt().unwrap();
        let exp = now + 3600;
        let mut store = Receipts::open(&dir).unwrap();
        assert!(store.reserve(&agent, &uncertain, exp, now).unwrap());
        assert!(store.reserve(&agent, &command, exp, now).unwrap());
        store
            .finish(pb::CommandResult {
                agent_id: agent.clone(),
                command_id: command.clone(),
                status: 1,
                stdout: "evidence".into(),
                ..Default::default()
            })
            .unwrap();
        drop(store);
        let mut store = Receipts::open(&dir).unwrap();
        // 已占位的指令不重执行
        assert!(!store.reserve(&agent, &uncertain, exp, now).unwrap());
        assert!(!store.reserve(&agent, &command, exp, now).unwrap());
        // 被打断的那条照实报成结果未知，和终态结果一起待上报
        let pending = store.pending(&agent).unwrap();
        assert_eq!(pending.len(), 2);
        let interrupted = pending.iter().find(|r| r.command_id == uncertain).unwrap();
        assert_eq!(
            (interrupted.status, interrupted.detail.as_str()),
            (0, INTERRUPTED)
        );
        assert_eq!(
            pending
                .iter()
                .find(|r| r.command_id == command)
                .unwrap()
                .stdout,
            "evidence"
        );
        assert_eq!(store.stats().pending, 2);
        store.acknowledge(&agent, &command).unwrap();
        store.reject(&agent, &uncertain).unwrap();
        assert!(store.pending(&agent).unwrap().is_empty());
        drop(store);
        let mut store = Receipts::open(&dir).unwrap();
        assert!(store.records.is_empty());

        // 换了注册身份：旧身份的回执移进隔离区，不再占名额
        let other = uuid::Uuid::new_v4().to_string();
        assert!(store.reserve(&agent, &other, exp, now).unwrap());
        drop(store);
        let mut store = Receipts::open(&dir).unwrap();
        assert!(
            store
                .pending(&uuid::Uuid::new_v4().to_string())
                .unwrap()
                .is_empty()
        );
        assert!(store.records.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn acked_command_cannot_be_replayed_before_expiry_even_after_restart() {
        let dir = std::env::temp_dir().join(format!("receipts-replay-{}", uuid::Uuid::new_v4()));
        let agent = uuid::Uuid::new_v4().to_string();
        let command = uuid::Uuid::new_v4().to_string();
        let now = now_unix_opt().unwrap();
        let exp = now + 3600;

        let mut store = Receipts::open(&dir).unwrap();
        assert!(store.reserve(&agent, &command, exp, now).unwrap());
        store
            .finish(pb::CommandResult {
                agent_id: agent.clone(),
                command_id: command.clone(),
                status: 1,
                ..Default::default()
            })
            .unwrap();
        store.acknowledge(&agent, &command).unwrap();
        assert!(store.records.is_empty(), "回执文件 ACK 后应已删除");

        // 回执删了但在 expires_unix 内，仍必须挡住重放
        assert!(
            !store.reserve(&agent, &command, exp, now + 10).unwrap(),
            "ACK 后到过期前不得重放"
        );
        // 进程重启后从磁盘恢复 seen，仍挡住重放
        drop(store);
        let mut store = Receipts::open(&dir).unwrap();
        assert!(
            !store.reserve(&agent, &command, exp, now + 60).unwrap(),
            "重启后到过期前仍不得重放"
        );

        // 超过 expires_unix 后清理过期条目，不无限累积
        assert!(store.prune_seen(exp + 1));
        assert!(store.seen.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
