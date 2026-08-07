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

#[cfg(test)]
mod tests {
    use super::*;

    /// 血缘靠 GUID 串联：父进程的 register 返回值就是子进程的 parent。
    #[test]
    fn lineage_via_guid() {
        let mut reg = ProcessRegistry::default();
        let (g1, _) = reg.register(1, None);
        let (g2, parent2) = reg.register(2, Some(1));
        let (g3, parent3) = reg.register(3, Some(2));

        assert_eq!(parent2, Some(g1), "子进程父 GUID 应等于父进程 GUID");
        assert_eq!(parent3, Some(g2), "孙进程应连到直系父进程");
        assert_ne!(g1, g2);
        assert_ne!(g2, g3);
    }

    /// 父进程未登记（早于 agent 启动）→ 父 GUID 为 None。
    #[test]
    fn unknown_parent_is_none() {
        let mut reg = ProcessRegistry::default();
        let (g, parent) = reg.register(100, Some(999));
        assert!(parent.is_none());
        assert!(!g.is_nil());
    }

    /// pid 复用：同一 pid 再次登记覆盖旧 GUID，父句柄随之指向新条目。
    #[test]
    fn pid_reuse_overwrites() {
        let mut reg = ProcessRegistry::default();
        let (old, _) = reg.register(50, None);
        let (fresh, _) = reg.register(50, None);
        assert_ne!(old, fresh, "pid 复用必须换新 GUID");

        let (_, parent_of_child) = reg.register(51, Some(50));
        assert_eq!(parent_of_child, Some(fresh), "子进程应连到复用后的新 GUID");
    }

    /// seed 等价于预登记，让后续子进程能追溯。
    #[test]
    fn seed_pregisters() {
        let mut reg = ProcessRegistry::default();
        reg.seed(7);
        let (child, parent) = reg.register(8, Some(7));
        assert!(parent.is_some());
        assert_ne!(child, parent.unwrap());
    }

    /// 每次 register 分配独立 GUID。
    #[test]
    fn guids_are_distinct() {
        let mut reg = ProcessRegistry::default();
        let mut seen = std::collections::HashSet::new();
        for pid in 1..=1000u32 {
            let (g, _) = reg.register(pid, None);
            assert!(seen.insert(g), "GUID 不应重复");
        }
    }
}
