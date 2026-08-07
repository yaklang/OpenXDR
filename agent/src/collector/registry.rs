//! 进程 GUID 注册表：pid 会被系统复用，GUID 不会。
//! 进程血缘全靠这张表——父进程的 GUID 从这里查，查不到说明父进程早于 agent 启动。

use std::collections::HashMap;

use uuid::Uuid;

/// pid 上限量级，超过则清理最早的条目，防止长跑进程无限占用内存
const MAX_ENTRIES: usize = 1 << 16;

#[derive(Default)]
pub struct ProcessRegistry {
    guids: HashMap<u32, Entry>,
    seq: u64,
}

struct Entry {
    guid: Uuid,
    seq: u64,
}

impl ProcessRegistry {
    /// 登记新进程，返回它的 GUID 和父进程 GUID（父未知则 None）。
    pub fn register(&mut self, pid: u32, ppid: Option<u32>) -> (Uuid, Option<Uuid>) {
        let parent = ppid.and_then(|p| self.guids.get(&p).map(|e| e.guid));
        let guid = Uuid::new_v4();

        self.seq += 1;
        let seq = self.seq;
        // pid 复用时新条目直接覆盖旧的，这正是我们要的语义
        self.guids.insert(pid, Entry { guid, seq });

        if self.guids.len() > MAX_ENTRIES {
            let cutoff = seq.saturating_sub(MAX_ENTRIES as u64 / 2);
            self.guids.retain(|_, e| e.seq > cutoff);
        }
        (guid, parent)
    }

    /// 预登记已存在的进程（agent 启动时的进程表快照），让后续子进程能找到父。
    pub fn seed(&mut self, pid: u32) {
        self.register(pid, None);
    }
}
