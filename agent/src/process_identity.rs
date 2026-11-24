//! 将采集时的 GUID 绑定到操作系统进程创建时间。处置必须同时匹配，PID 本身不是身份。
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

const MAX_IDENTITIES: usize = 65536;
/// 满表时单次在锁外做存活探测的最老候选批量，避免持有全局锁全表扫描阻塞采集与处置。
const PRUNE_BATCH: usize = 256;
/// 清理已退出进程后若仍达上限，按写入顺序淘汰最老的一小批条目，绝不全量清空存活进程。
const EVICT_BATCH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    guid: Uuid,
    birth: u64,
    seq: u64,
}

#[derive(Default)]
struct IdentityTable {
    entries: HashMap<u32, Entry>,
    next_seq: u64,
}

impl IdentityTable {
    fn insert_direct(&mut self, pid: u32, guid: Uuid, birth: u64) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.entries.insert(pid, Entry { guid, birth, seq });
    }

    /// 抽取写入序最老的最多 `batch` 条 `(pid, birth)` 候选，供调用方释放锁后在锁外做内核存活探测。
    fn sample_oldest(&self, batch: usize) -> Vec<(u32, u64)> {
        if batch == 0 || self.entries.is_empty() {
            return Vec::new();
        }
        let mut by_age: Vec<(u64, u32, u64)> = self
            .entries
            .iter()
            .map(|(&p, e)| (e.seq, p, e.birth))
            .collect();
        if by_age.len() > batch {
            by_age.select_nth_unstable_by_key(batch, |&(seq, _, _)| seq);
            by_age.truncate(batch);
        }
        by_age.into_iter().map(|(_, p, b)| (p, b)).collect()
    }

    /// 删除锁外探测确认已退出的陈旧条目（仅当 birth 仍匹配时才删，防释锁期间同 PID 新写入被误删）；
    /// 若仍达上限，按写入顺序淘汰最老的一小批，再插入新条目。
    fn apply_prune_and_insert(
        &mut self,
        pid: u32,
        guid: Uuid,
        birth: u64,
        limit: usize,
        dead: &[(u32, u64)],
    ) {
        for &(dead_pid, dead_birth) in dead {
            if self
                .entries
                .get(&dead_pid)
                .is_some_and(|e| e.birth == dead_birth)
            {
                self.entries.remove(&dead_pid);
            }
        }
        self.entries.remove(&pid);
        if self.entries.len() >= limit {
            let target = limit.saturating_sub(EVICT_BATCH.min(limit).max(1));
            let drop_count = self.entries.len().saturating_sub(target);
            let mut by_age: Vec<(u64, u32)> =
                self.entries.iter().map(|(&p, e)| (e.seq, p)).collect();
            if drop_count < by_age.len() {
                by_age.select_nth_unstable_by_key(drop_count, |&(seq, _)| seq);
                by_age.truncate(drop_count);
            }
            for (_, old_pid) in by_age {
                self.entries.remove(&old_pid);
            }
        }
        self.insert_direct(pid, guid, birth);
    }

    fn matches(&self, pid: u32, guid: Uuid, birth: u64) -> bool {
        self.entries
            .get(&pid)
            .is_some_and(|e| e.guid == guid && e.birth == birth)
    }
}

fn identities() -> &'static Mutex<IdentityTable> {
    static IDENTITIES: OnceLock<Mutex<IdentityTable>> = OnceLock::new();
    IDENTITIES.get_or_init(Default::default)
}

fn is_pid_alive(pid: u32, expected_birth: u64) -> bool {
    Target::read_birth(pid).ok() == Some(expected_birth)
}

/// 分批增量清理并记录进程身份：所有内核存活探测 I/O 均在释放全局锁后执行。
fn record_with(
    table: &Mutex<IdentityTable>,
    pid: u32,
    guid: Uuid,
    birth: Option<u64>,
    limit: usize,
    prune_batch: usize,
    mut is_alive: impl FnMut(u32, u64) -> bool,
) {
    let candidates = {
        let mut ids = table.lock().unwrap_or_else(|e| e.into_inner());
        ids.entries.remove(&pid);
        let Some(birth) = birth else {
            return;
        };
        if limit == 0 {
            return;
        }
        if ids.entries.len() < limit {
            ids.insert_direct(pid, guid, birth);
            return;
        }
        ids.sample_oldest(prune_batch)
    };

    // 锁外执行分批存活探测，不阻塞并发采集与 verified() 处置校验
    let dead: Vec<(u32, u64)> = candidates
        .into_iter()
        .filter(|&(p, b)| !is_alive(p, b))
        .collect();

    let Some(birth) = birth else {
        return;
    };
    let mut ids = table.lock().unwrap_or_else(|e| e.into_inner());
    ids.apply_prune_and_insert(pid, guid, birth, limit, &dead);
}

pub fn record(pid: u32, guid: Uuid) {
    // 读取进程创建时间（Linux 读 /proc，Windows 调 Target::open_readonly）始终在锁外执行
    let birth = Target::read_birth(pid).ok();
    record_with(
        identities(),
        pid,
        guid,
        birth,
        MAX_IDENTITIES,
        PRUNE_BATCH,
        is_pid_alive,
    );
}

pub fn verified(pid: u32, guid: &str) -> Result<Target, String> {
    let target = Target::open_terminate(pid)?;
    let expected = Uuid::parse_str(guid).map_err(|_| "缺少合法的进程 GUID".to_string())?;
    let birth = target.birth()?;
    let ids = identities().lock().unwrap_or_else(|e| e.into_inner());
    if !ids.matches(pid, expected, birth) {
        return Err("进程身份不匹配或已过期，拒绝结束进程".into());
    }
    #[cfg(target_os = "linux")]
    {
        let mut target = target;
        target.verified_birth = Some(birth);
        Ok(target)
    }
    #[cfg(not(target_os = "linux"))]
    Ok(target)
}

#[cfg(target_os = "linux")]
pub struct Target {
    pid: u32,
    fd: Option<std::os::fd::OwnedFd>,
    verified_birth: Option<u64>,
}

#[cfg(target_os = "linux")]
impl Target {
    fn open_terminate(pid: u32) -> Result<Self, String> {
        use std::os::fd::FromRawFd;
        // pidfd 固定进程实例，校验之后 PID 再被复用也不会误杀。
        // SAFETY: pidfd_open 只接收整数参数（pid 与 flags 0），不涉及指针；返回值在下面检查 < 0。
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS) {
            return Err(format!(
                "进程不存在或无法打开 pidfd: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            pid,
            // SAFETY: fd ≥ 0 是 pidfd_open 刚返回的新描述符，此处之外无人持有，交给 OwnedFd 独占并负责关闭；
            // fd 值不超过 RLIMIT_NOFILE，转 i32 不截断。
            fd: (fd >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) }),
            verified_birth: None,
        })
    }
    fn read_birth(pid: u32) -> Result<u64, String> {
        let stat =
            std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| e.to_string())?;
        stat.rsplit_once(')')
            .and_then(|(_, fields)| fields.split_whitespace().nth(19))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| "无法读取进程创建时间".into())
    }
    fn birth(&self) -> Result<u64, String> {
        Self::read_birth(self.pid)
    }
    pub fn terminate(&self) -> Result<(), String> {
        use std::os::fd::AsRawFd;
        if let Some(fd) = &self.fd {
            // SAFETY: fd 由 Target 持有；空 info 与 flags 0 是合法参数。
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if rc >= 0 {
                return Ok(());
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOSYS) {
                return Err(err.to_string());
            }
        }
        // 旧内核不支持 pidfd 时，发送信号前再次核对已验证的创建时间。
        if Some(self.birth()?) != self.verified_birth {
            return Err("进程身份已变化，拒绝结束进程".into());
        }
        // SAFETY: PID 来自已验证的目标，且刚刚重新核对了创建时间。
        if unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGKILL) } < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
}

#[cfg(windows)]
pub struct Target(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Target {
    /// 仅用于采集期读取进程创建时间：只申请最小权限 PROCESS_QUERY_LIMITED_INFORMATION，支持 PPL 等受保护进程。
    fn open_readonly(pid: u32) -> Result<Self, String> {
        Self::open_with_access(
            pid,
            windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
        )
    }
    /// 仅用于处置结束进程：同时申请 PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE。
    fn open_terminate(pid: u32) -> Result<Self, String> {
        use windows_sys::Win32::System::Threading::{
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        };
        Self::open_with_access(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE)
    }
    fn open_with_access(pid: u32, access: u32) -> Result<Self, String> {
        use windows_sys::Win32::System::Threading::OpenProcess;
        // SAFETY: OpenProcess 只接收整数参数，不涉及指针；返回空句柄表示失败，下面已检查。
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            return Err(format!(
                "进程不存在或无法打开: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self(handle))
    }
    fn read_birth(pid: u32) -> Result<u64, String> {
        Self::open_readonly(pid)?.birth()
    }
    fn birth(&self) -> Result<u64, String> {
        use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
        let (mut created, mut exited, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        // SAFETY: self.0 是 open 时以 PROCESS_QUERY_LIMITED_INFORMATION 打开的有效句柄（GetProcessTimes
        // 所需的访问权），在 Drop 前一直有效；四个出参都指向栈上已初始化的 FILETIME。
        if unsafe { GetProcessTimes(self.0, &mut created, &mut exited, &mut kernel, &mut user) }
            == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }
    pub fn terminate(&self) -> Result<(), String> {
        // SAFETY: self.0 是 open_terminate 时带 PROCESS_TERMINATE 权限打开的有效句柄，在 Drop 前一直有效。
        if unsafe { windows_sys::Win32::System::Threading::TerminateProcess(self.0, 1) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for Target {
    fn drop(&mut self) {
        // SAFETY: Target 独占这个句柄（open 成功才构造，不可 Clone），Drop 只执行一次，不会重复关闭。
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
pub struct Target;
#[cfg(not(any(target_os = "linux", windows)))]
impl Target {
    fn open_terminate(_: u32) -> Result<Self, String> {
        Err("当前平台不支持可靠进程身份校验".into())
    }
    fn read_birth(_: u32) -> Result<u64, String> {
        Err("不支持进程创建时间".into())
    }
    fn birth(&self) -> Result<u64, String> {
        Err("不支持进程创建时间".into())
    }
    pub fn terminate(&self) -> Result<(), String> {
        Err("不支持结束进程".into())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn terminate_without_pidfd_checks_birth() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut target = Target {
            pid: child.id(),
            fd: None,
            verified_birth: Some(0),
        };
        let refused = target.terminate();
        target.verified_birth = Some(target.birth().unwrap());
        let killed = target.terminate();
        // 即使断言失败也先回收子进程。
        let _ = child.kill();
        let status = child.wait().unwrap();
        assert_eq!(refused.unwrap_err(), "进程身份已变化，拒绝结束进程");
        assert!(killed.is_ok());
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn stale_guid_and_birth_are_rejected() {
        // 用自己的进程做只读校验，绝不调用 terminate。
        let pid = std::process::id();
        let guid = Uuid::new_v4();
        record(pid, guid);
        assert!(verified(pid, &guid.to_string()).is_ok());
        assert!(verified(pid, &Uuid::new_v4().to_string()).is_err());
        assert!(verified(pid, "").is_err());
        identities().lock().unwrap().entries.insert(
            pid,
            Entry {
                guid,
                birth: 0,
                seq: 0,
            },
        );
        assert!(verified(pid, &guid.to_string()).is_err());
    }

    #[test]
    fn full_table_prunes_dead_in_batches_outside_lock_and_preserves_alive_entries() {
        let table = Mutex::new(IdentityTable::default());
        let alive_guid = Uuid::new_v4();
        let new_guid = Uuid::new_v4();
        // 模拟表满（limit = 10，prune_batch = 4）：PID 100 存活，PID 101..=109 已退出
        record_with(&table, 100, alive_guid, Some(1000), 10, 4, |p, _| p == 100);
        for p in 101..=109 {
            record_with(
                &table,
                p,
                Uuid::new_v4(),
                Some(1000 + p as u64),
                10,
                4,
                |pid, _| pid == 100,
            );
        }
        assert_eq!(table.lock().unwrap().entries.len(), 10);

        // 插入第 11 条触发分批清理：只探测最老的 4 条，且回调期间全局锁已释放
        let mut probed = 0usize;
        let reused_guid = Uuid::new_v4();
        record_with(&table, 200, new_guid, Some(2000), 10, 4, |p, _| {
            probed += 1;
            // 验证存活探测在锁外执行：此处可立即拿到锁
            let mut guard = table.try_lock().expect("is_alive 必须在释放全局锁后执行");
            // 模拟释锁期间 PID 102 被新进程复用并覆盖了 birth，旧候选判死后不得误删新写入
            if p == 102 {
                guard.insert_direct(102, reused_guid, 9999);
            }
            p == 100
        });
        assert_eq!(probed, 4, "满表时只应分批探测 prune_batch 条最老候选");
        {
            let guard = table.lock().unwrap();
            assert!(guard.matches(100, alive_guid, 1000), "存活进程不得被清空");
            assert!(
                guard.matches(102, reused_guid, 9999),
                "释锁期间同 PID 新写入的条目不得被旧探测结果误删"
            );
            assert!(guard.matches(200, new_guid, 2000));
            // 抽查的 4 条为 100(活)、101(死删)、102(已换新birth保留)、103(死删) -> 10 - 2 + 1 = 9
            assert_eq!(guard.entries.len(), 9);
        }

        // 全部存活且达上限时，只驱逐最老的少量条目，保留其余存活进程
        let full = Mutex::new(IdentityTable::default());
        let mut guids = Vec::new();
        for p in 1..=100u32 {
            let g = Uuid::new_v4();
            guids.push((p, g));
            record_with(&full, p, g, Some(p as u64), 100, 16, |_, _| true);
        }
        let extra = Uuid::new_v4();
        let mut probed_full = 0usize;
        record_with(&full, 101, extra, Some(101), 100, 16, |_, _| {
            probed_full += 1;
            assert!(full.try_lock().is_ok(), "锁外探测不应持有全局锁");
            true
        });
        assert_eq!(probed_full, 16);
        let guard = full.lock().unwrap();
        assert!(guard.entries.len() < 100);
        assert!(
            guard.matches(100, guids[99].1, 100),
            "较新的存活进程不得被全量清空"
        );
        assert!(guard.matches(101, extra, 101));
        assert!(!guard.matches(1, guids[0].1, 1), "最老条目应被优先驱逐");
    }
}
