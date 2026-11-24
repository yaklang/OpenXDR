//! Windows 计划任务目录快照扫描与按目录粒度的不完整扫描合并（跨平台纯逻辑，方便在各平台运行单元测试）。
//!
//! 当部分子树触及深度上限、条目上限或目录读取失败时，仅记录受影响的 `incomplete_dirs`：
//! - 落在 `incomplete_dirs` 前缀子树下的旧基线条目予以保留，绝不误报为 Delete；
//! - 其他已完整扫描的子树照常上报真实 Delete；
//! - 合并后的基线始终受最大条目数上限约束，防止轮换任务名导致基线无界增长。

use std::collections::{BTreeMap, BTreeSet};
use std::fs::DirEntry;
use std::path::Path;

/// 计划任务快照与合并基线的默认条目上限，防轮换任务名导致内存无界增长
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) const MAX_TASK_ENTRIES: usize = 4096;

/// 目录树扫描结果
#[derive(Debug)]
pub(super) struct ScanResult<V> {
    pub entries: BTreeMap<String, V>,
    /// 未完整覆盖的目录（或读取失败的单文件）路径列表
    pub incomplete_dirs: Vec<String>,
}

impl<V> ScanResult<V> {
    pub(super) fn is_complete(&self) -> bool {
        self.incomplete_dirs.is_empty()
    }
}

/// 递归扫描目录树构造快照，返回 `Option<ScanResult<V>>`：
/// - 根目录本身无法打开时返回 `None`，调用方本轮跳过；
/// - 触及 `max_entries` / `max_depth` 或某子目录 / 条目读取失败时，将具体受影响的路径记入 `incomplete_dirs`。
pub(super) fn scan_dir_snapshot<V, F>(
    root: &Path,
    max_depth: usize,
    max_entries: usize,
    mut read_file: F,
) -> Option<ScanResult<V>>
where
    F: FnMut(&DirEntry, &Path) -> Option<(String, V)>,
{
    let mut snap = BTreeMap::new();
    let mut stack = vec![(root.to_path_buf(), std::fs::read_dir(root).ok()?, 0usize)];
    let mut visited = 0usize;
    let mut incomplete = BTreeSet::new();

    'scan: while let Some((dir_path, entries, depth)) = stack.pop() {
        for entry_res in entries {
            let Ok(e) = entry_res else {
                incomplete.insert(dir_path.display().to_string());
                continue;
            };
            if visited >= max_entries {
                incomplete.insert(dir_path.display().to_string());
                for (pending_dir, _, _) in stack.drain(..) {
                    incomplete.insert(pending_dir.display().to_string());
                }
                break 'scan;
            }
            visited += 1;
            // DirEntry::file_type 不跟随符号链接或 Windows 目录联接（reparse point）
            let Ok(ft) = e.file_type() else {
                incomplete.insert(dir_path.display().to_string());
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let path = e.path();
            if ft.is_dir() {
                if depth < max_depth {
                    match std::fs::read_dir(&path) {
                        Ok(sub) => stack.push((path, sub, depth + 1)),
                        Err(_) => {
                            incomplete.insert(path.display().to_string());
                        }
                    }
                } else {
                    incomplete.insert(path.display().to_string());
                }
            } else if ft.is_file() {
                match read_file(&e, &path) {
                    Some((key, val)) => {
                        snap.insert(key, val);
                    }
                    None => {
                        incomplete.insert(path.display().to_string());
                    }
                }
            }
        }
    }
    Some(ScanResult {
        entries: snap,
        incomplete_dirs: incomplete.into_iter().collect(),
    })
}

/// 判断条目路径是否落在任一未完整扫描目录的前缀子树下（兼容 `/` 与 `\` 分隔符）
fn is_covered_by_incomplete(path: &str, incomplete_dirs: &[String]) -> bool {
    incomplete_dirs.iter().any(|dir| {
        let dir = dir.trim_end_matches(['/', '\\']);
        if path == dir {
            return true;
        }
        path.strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('\\'))
    })
}

/// 单条快照差异：(路径, 当前或旧值, Modify 时的旧值, OCSF activity_id: 1 Create / 3 Modify / 4 Delete)。
pub(super) type SnapshotChange<V> = (String, V, Option<V>, u8);

/// 结合未完整覆盖目录列表比对新旧基线并返回下一轮有界基线与需上报的变更：
/// - `seen` 为 `None`：首轮建基线，不上报事件；
/// - 对 `now` 中实际看到的条目上报 Create / Modify；
/// - 对仅存在于旧基线 `prev` 中的条目：若落在 `incomplete_dirs` 前缀子树下则保留（不误报 Delete），
///   否则属于已完整扫描子树，照常上报 Delete；
/// - 合并后的基线长度始终不超过 `max_baseline`，优先保留本轮新观测到的条目。
pub(super) fn reconcile_snapshot<V: Clone + PartialEq>(
    seen: Option<&BTreeMap<String, V>>,
    now: BTreeMap<String, V>,
    incomplete_dirs: &[String],
    max_baseline: usize,
) -> (BTreeMap<String, V>, Vec<SnapshotChange<V>>) {
    let Some(prev) = seen else {
        let bounded: BTreeMap<String, V> = now.into_iter().take(max_baseline).collect();
        return (bounded, Vec::new());
    };

    let mut changes = Vec::new();
    for (path, data) in &now {
        match prev.get(path) {
            None => changes.push((path.clone(), data.clone(), None, 1)),
            Some(old) if old != data => {
                changes.push((path.clone(), data.clone(), Some(old.clone()), 3));
            }
            _ => {}
        }
    }

    let mut next: BTreeMap<String, V> = now.into_iter().take(max_baseline).collect();
    for (path, old_data) in prev {
        if next.contains_key(path) {
            continue;
        }
        if is_covered_by_incomplete(path, incomplete_dirs) {
            if next.len() < max_baseline {
                next.insert(path.clone(), old_data.clone());
            }
        } else {
            changes.push((path.clone(), old_data.clone(), None, 4));
        }
    }

    (next, changes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_strings(
        root: &Path,
        max_depth: usize,
        max_entries: usize,
    ) -> Option<ScanResult<String>> {
        scan_dir_snapshot(root, max_depth, max_entries, |_, path| {
            let content = std::fs::read_to_string(path).ok()?;
            Some((path.display().to_string(), content))
        })
    }

    #[test]
    fn truncated_scan_preserves_missing_baseline_entries_and_recovers() {
        let dir = std::env::temp_dir().join(format!(
            "openxdr-persistwatch-tasks-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let f1 = dir.join("t1");
        let f2 = dir.join("t2");
        let f3 = dir.join("t3");
        std::fs::write(&f1, "v1").unwrap();
        std::fs::write(&f2, "v2").unwrap();
        std::fs::write(&f3, "v3").unwrap();

        // 第 1 轮：完整扫描建立基线
        let scan1 = scan_strings(&dir, 8, 100).unwrap();
        assert!(scan1.is_complete());
        assert_eq!(scan1.entries.len(), 3);
        let (baseline1, changes1) = reconcile_snapshot(
            None,
            scan1.entries,
            &scan1.incomplete_dirs,
            MAX_TASK_ENTRIES,
        );
        assert!(changes1.is_empty());

        // 第 2 轮：条目上限设为 1 触发截断，根未扫完记录在 incomplete_dirs
        let scan2 = scan_strings(&dir, 8, 1).unwrap();
        assert!(!scan2.is_complete(), "触及条目上限应记录 incomplete_dirs");
        assert_eq!(scan2.entries.len(), 1);
        let (baseline2, changes2) = reconcile_snapshot(
            Some(&baseline1),
            scan2.entries,
            &scan2.incomplete_dirs,
            MAX_TASK_ENTRIES,
        );
        assert!(
            !changes2.iter().any(|(_, _, _, act)| *act == 4),
            "不完整扫描绝不能把未扫到的旧任务误报为 Delete：{changes2:?}"
        );
        assert_eq!(baseline2.len(), 3, "旧基线中未扫到的条目应完整保留");

        // 第 3 轮：恢复正常上限，真实删除 t2、新增 t4、修改 t1
        std::fs::remove_file(&f2).unwrap();
        std::fs::write(&f1, "v1-mod").unwrap();
        let f4 = dir.join("t4");
        std::fs::write(&f4, "v4").unwrap();

        let scan3 = scan_strings(&dir, 8, 100).unwrap();
        assert!(scan3.is_complete());
        let (baseline3, changes3) = reconcile_snapshot(
            Some(&baseline2),
            scan3.entries,
            &scan3.incomplete_dirs,
            MAX_TASK_ENTRIES,
        );
        assert_eq!(baseline3.len(), 3);
        assert!(
            changes3
                .iter()
                .any(|(p, _, _, a)| p.ends_with("t4") && *a == 1),
            "新增 t4 应报 Create：{changes3:?}"
        );
        assert!(
            changes3.iter().any(|(p, v, prev, a)| p.ends_with("t1")
                && v == "v1-mod"
                && prev.as_deref() == Some("v1")
                && *a == 3),
            "修改 t1 应报 Modify：{changes3:?}"
        );
        assert!(
            changes3
                .iter()
                .any(|(p, _, _, a)| p.ends_with("t2") && *a == 4),
            "真实删除 t2 应报 Delete：{changes3:?}"
        );
        assert_eq!(changes3.len(), 3);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn depth_limit_marks_only_deep_subtree_incomplete() {
        let dir = std::env::temp_dir().join(format!(
            "openxdr-persistwatch-depth-{}",
            uuid::Uuid::new_v4()
        ));
        let deep = dir.join("a/b/c");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("task"), "exec").unwrap();

        let scan_limited = scan_strings(&dir, 1, 100).unwrap();
        assert!(!scan_limited.is_complete(), "触及深度上限应记录不完整目录");
        assert!(
            scan_limited
                .incomplete_dirs
                .iter()
                .any(|d| d.ends_with("b")),
            "应精准记录触及深度上限的子目录：{:?}",
            scan_limited.incomplete_dirs
        );

        let scan_full = scan_strings(&dir, 8, 100).unwrap();
        assert!(scan_full.is_complete());
        assert_eq!(scan_full.entries.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn incomplete_subtree_does_not_block_sibling_deletes_and_bounds_baseline() {
        let dir = std::env::temp_dir().join(format!(
            "openxdr-persistwatch-partial-{}",
            uuid::Uuid::new_v4()
        ));
        let good = dir.join("good");
        let deep = dir.join("deep/l1/l2");
        std::fs::create_dir_all(&good).unwrap();
        std::fs::create_dir_all(&deep).unwrap();

        let good_keep = good.join("keep");
        let good_del = good.join("gone");
        let deep_task = deep.join("nested_task");
        std::fs::write(&good_keep, "v1").unwrap();
        std::fs::write(&good_del, "v1").unwrap();
        std::fs::write(&deep_task, "deep-v1").unwrap();

        // 第 1 轮：完整基线（含 good 与 deep 两个子树）
        let full = scan_strings(&dir, 8, 100).unwrap();
        assert!(full.is_complete());
        let (baseline, _) = reconcile_snapshot(None, full.entries, &full.incomplete_dirs, 100);
        assert_eq!(baseline.len(), 3);

        // 在正常子树中删除 good_del、新增 good_add；deep 子树持续因深度上限(max_depth=1)不完整
        std::fs::remove_file(&good_del).unwrap();
        let good_add = good.join("added");
        std::fs::write(&good_add, "new").unwrap();

        let partial = scan_strings(&dir, 1, 100).unwrap();
        assert!(!partial.is_complete());
        let (baseline2, changes) = reconcile_snapshot(
            Some(&baseline),
            partial.entries,
            &partial.incomplete_dirs,
            100,
        );

        assert!(
            changes
                .iter()
                .any(|(p, _, _, a)| p.ends_with("gone") && *a == 4),
            "正常子树的真实删除必须照常上报 Delete：{changes:?}"
        );
        assert!(
            changes
                .iter()
                .any(|(p, _, _, a)| p.ends_with("added") && *a == 1),
            "正常子树的新增必须照常上报 Create：{changes:?}"
        );
        assert!(
            !changes
                .iter()
                .any(|(p, _, _, a)| p.ends_with("nested_task") && *a == 4),
            "不完整子树中的旧任务不得误报 Delete：{changes:?}"
        );
        assert!(
            baseline2.keys().any(|k| k.ends_with("nested_task")),
            "不完整子树中的旧任务应保留在基线中：{baseline2:?}"
        );
        assert!(
            !baseline2.keys().any(|k| k.ends_with("gone")),
            "已删除的正常子树任务应从基线移除：{baseline2:?}"
        );

        // 验证基线有界：在不完整子树下持续轮换新任务名，合并后的基线长度始终不超过 max_baseline
        let mut bounded = baseline2;
        let incomplete_deep = vec![deep.display().to_string()];
        for i in 0..20 {
            let mut next_now = BTreeMap::new();
            next_now.insert(
                deep.join(format!("rotating_{i}")).display().to_string(),
                "x".to_string(),
            );
            let (next_base, _) = reconcile_snapshot(Some(&bounded), next_now, &incomplete_deep, 5);
            assert!(
                next_base.len() <= 5,
                "基线条目数 {} 超过上限 5",
                next_base.len()
            );
            bounded = next_base;
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
