//! Windows 计划任务目录快照扫描与不完整扫描合并（跨平台纯逻辑，方便在各平台运行单元测试）。
//!
//! 当扫描触及深度上限、条目上限或子目录读取失败时，`complete` 为 `false`：
//! 本轮仅上报实际看到的新增与修改，保留旧基线里未扫描到的条目，绝不将未覆盖项误报为 Delete。

use std::collections::BTreeMap;
use std::fs::DirEntry;
use std::path::Path;

/// 递归扫描目录树构造快照，返回 `Option<(快照, 是否完整扫描)>`：
/// - 根目录本身无法打开时返回 `None`，调用方本轮跳过；
/// - 触及 `max_entries` / `max_depth` 或任一子目录 / 条目读取失败时 `complete = false`。
pub(super) fn scan_dir_snapshot<V, F>(
    root: &Path,
    max_depth: usize,
    max_entries: usize,
    mut read_file: F,
) -> Option<(BTreeMap<String, V>, bool)>
where
    F: FnMut(&DirEntry, &Path) -> Option<(String, V)>,
{
    let mut snap = BTreeMap::new();
    let mut stack = vec![(std::fs::read_dir(root).ok()?, 0usize)];
    let mut visited = 0usize;
    let mut complete = true;

    while let Some((entries, depth)) = stack.pop() {
        for entry_res in entries {
            let Ok(e) = entry_res else {
                complete = false;
                continue;
            };
            if visited >= max_entries {
                return Some((snap, false));
            }
            visited += 1;
            // DirEntry::file_type 不跟随符号链接或 Windows 目录联接（reparse point）
            let Ok(ft) = e.file_type() else {
                complete = false;
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let path = e.path();
            if ft.is_dir() {
                if depth < max_depth {
                    match std::fs::read_dir(&path) {
                        Ok(sub) => stack.push((sub, depth + 1)),
                        Err(_) => complete = false,
                    }
                } else {
                    complete = false;
                }
            } else if ft.is_file() {
                match read_file(&e, &path) {
                    Some((key, val)) => {
                        snap.insert(key, val);
                    }
                    None => complete = false,
                }
            }
        }
    }
    Some((snap, complete))
}

/// 单条快照差异：(路径, 当前或旧值, Modify 时的旧值, OCSF activity_id: 1 Create / 3 Modify / 4 Delete)。
pub(super) type SnapshotChange<V> = (String, V, Option<V>, u8);

/// 结合完整性标记比对新旧基线并返回下一轮基线与需上报的变更：
/// - `seen` 为 `None`：首轮建基线，不上报事件；
/// - `complete == true`：全量 diff（Create/Modify/Delete），以 `now` 作为新基线；
/// - `complete == false`：仅上报 `now` 中实际看到的新增与修改，绝不将未扫到的旧条目判为 Delete，
///   并将旧基线里未覆盖的条目保留进新基线。
pub(super) fn reconcile_snapshot<V: Clone + PartialEq>(
    seen: Option<&BTreeMap<String, V>>,
    now: BTreeMap<String, V>,
    complete: bool,
) -> (BTreeMap<String, V>, Vec<SnapshotChange<V>>) {
    let Some(prev) = seen else {
        return (now, Vec::new());
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

    if complete {
        for (path, old_data) in prev {
            if !now.contains_key(path) {
                changes.push((path.clone(), old_data.clone(), None, 4));
            }
        }
        (now, changes)
    } else {
        let mut merged = prev.clone();
        merged.extend(now);
        (merged, changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_strings(
        root: &Path,
        max_depth: usize,
        max_entries: usize,
    ) -> Option<(BTreeMap<String, String>, bool)> {
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
        let (snap1, complete1) = scan_strings(&dir, 8, 100).unwrap();
        assert!(complete1);
        assert_eq!(snap1.len(), 3);
        let (baseline1, changes1) = reconcile_snapshot(None, snap1, complete1);
        assert!(changes1.is_empty());

        // 第 2 轮：条目上限设为 1 触发截断（complete == false），同时修改所有文件之一
        let (snap2, complete2) = scan_strings(&dir, 8, 1).unwrap();
        assert!(!complete2, "触及条目上限应标记 complete=false");
        assert_eq!(snap2.len(), 1);
        let (baseline2, changes2) = reconcile_snapshot(Some(&baseline1), snap2, complete2);
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

        let (snap3, complete3) = scan_strings(&dir, 8, 100).unwrap();
        assert!(complete3);
        let (baseline3, changes3) = reconcile_snapshot(Some(&baseline2), snap3, complete3);
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
    fn depth_limit_marks_scan_incomplete() {
        let dir = std::env::temp_dir().join(format!(
            "openxdr-persistwatch-depth-{}",
            uuid::Uuid::new_v4()
        ));
        let deep = dir.join("a/b/c");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("task"), "exec").unwrap();

        let (_, complete) = scan_strings(&dir, 1, 100).unwrap();
        assert!(!complete, "触及深度上限应标记 complete=false");

        let (snap_full, complete_full) = scan_strings(&dir, 8, 100).unwrap();
        assert!(complete_full);
        assert_eq!(snap_full.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
