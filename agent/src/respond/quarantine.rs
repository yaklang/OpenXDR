//! 文件隔离：把可疑文件移进 agent 状态目录下的隔离区，原位置不再有这个文件，内容原样留作证据。
//!
//! 每个隔离文件旁边存一份记录：原路径、大小、SHA-256、权限与属主，恢复时按原路径找最近一次隔离的那份，
//! 原路径已经有文件就拒绝覆盖。只处理普通文件，不碰符号链接、目录、伪文件系统和 agent 自己。

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Outcome;
use crate::pb::Command;

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    path: String,
    size: u64,
    sha256: String,
    mode: u32,
    uid: u32,
    gid: u32,
    at: u64,
}

fn dir() -> PathBuf {
    crate::delivery::state_root().join("isolated-files")
}

pub fn quarantine(cmd: &Command) -> Outcome {
    match move_in(&dir(), Path::new(cmd.target.trim()), &cmd.id) {
        Ok(r) => Outcome::ok(format!(
            "已隔离 {}（{} 字节，SHA-256 {}）",
            r.path, r.size, r.sha256
        )),
        Err(e) => Outcome::failed(format!("隔离失败：{e}")),
    }
}

pub fn restore(cmd: &Command) -> Outcome {
    match move_out(&dir(), Path::new(cmd.target.trim())) {
        Ok(r) => Outcome::ok(format!("已恢复 {}（SHA-256 {}）", r.path, r.sha256)),
        Err(e) => Outcome::failed(format!("恢复失败：{e}")),
    }
}

fn has_parent_dir(path: &Path) -> bool {
    path.components().any(|c| matches!(c, Component::ParentDir))
}

fn refuse(path: &Path, store: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("路径必须是绝对路径".into());
    }
    if has_parent_dir(path) {
        return Err("路径不允许包含 .. 路径段".into());
    }

    // 对父目录做规范化后再拼文件名（不跟随目标自身符号链接），防御父目录符号链接绕过
    let parent = path.parent().ok_or("路径无效")?;
    let name = path.file_name().ok_or("路径无效")?;
    let resolved = fs::canonicalize(parent)
        .map(|p| p.join(name))
        .unwrap_or_else(|_| path.to_path_buf());

    #[cfg(unix)]
    for root in ["/proc", "/sys", "/dev", "/run"] {
        if path.starts_with(root) || resolved.starts_with(root) {
            return Err(format!("{root} 下的文件不能隔离"));
        }
    }

    let state_root = crate::delivery::state_root();
    let protected_dirs = [
        Some(store.to_path_buf()),
        fs::canonicalize(store).ok(),
        Some(state_root.clone()),
        fs::canonicalize(&state_root).ok(),
    ];
    for dir in protected_dirs.into_iter().flatten() {
        if path.starts_with(&dir) || resolved.starts_with(&dir) {
            return Err("agent 自己的状态文件不能隔离".into());
        }
    }

    if let Ok(exe) = std::env::current_exe()
        && let Ok(exe_canon) = fs::canonicalize(&exe)
    {
        let target_same = resolved == exe_canon
            || fs::canonicalize(path).is_ok_and(|p_canon| p_canon == exe_canon);
        if target_same {
            return Err("不能隔离 agent 自身".into());
        }
    }
    Ok(())
}

/// 打开普通文件并拒绝跟随符号链接；Unix 下通过 O_NOFOLLOW + fstat 消除路径 TOCTOU
fn open_regular_nofollow(path: &Path) -> io::Result<(File, fs::Metadata)> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::other(format!(
            "{} 不是普通文件（符号链接、目录、设备不处理）",
            path.display()
        )));
    }
    Ok((file, meta))
}

/// 原子新建目标文件（不覆盖已有文件、Unix 下不跟随符号链接）
fn create_new_nofollow(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

#[cfg(unix)]
fn same_identity(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_identity(_a: &fs::Metadata, _b: &fs::Metadata) -> bool {
    true
}

fn move_in(store: &Path, path: &Path, id: &str) -> Result<Record, String> {
    refuse(path, store)?;
    let lmeta = fs::symlink_metadata(path).map_err(|e| format!("{}：{e}", path.display()))?;
    if !lmeta.file_type().is_file() {
        return Err(format!(
            "{} 不是普通文件（符号链接、目录、设备不处理）",
            path.display()
        ));
    }
    let (mut src_file, meta) =
        open_regular_nofollow(path).map_err(|e| format!("读取文件失败：{e}"))?;
    if !same_identity(&lmeta, &meta) {
        return Err("文件在隔离过程中已被替换，拒绝继续".into());
    }
    let id = uuid::Uuid::parse_str(id).map_err(|_| "指令 ID 无效")?;
    create_private(store)?;
    let record = Record {
        path: path.display().to_string(),
        size: meta.len(),
        sha256: sha256_reader(&mut src_file).map_err(|e| format!("读取文件失败：{e}"))?,
        mode: mode(&meta),
        uid: owner(&meta).0,
        gid: owner(&meta).1,
        at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    let blob = store.join(format!("{id}.bin"));
    // 记录先落盘：文件挪走了却没记下从哪来，就恢复不回去了
    fs::write(
        store.join(format!("{id}.json")),
        serde_json::to_vec(&record).unwrap_or_default(),
    )
    .map_err(|e| format!("写隔离记录失败：{e}"))?;
    if let Err(e) = relocate_in(path, &blob, &meta, &mut src_file) {
        let _ = fs::remove_file(store.join(format!("{id}.json")));
        return Err(format!("移动文件失败：{e}"));
    }
    lock_down(&blob);
    Ok(record)
}

fn move_out(store: &Path, path: &Path) -> Result<Record, String> {
    if !path.is_absolute() {
        return Err("路径必须是绝对路径".into());
    }
    if has_parent_dir(path) {
        return Err("路径不允许包含 .. 路径段".into());
    }
    let want = path.display().to_string();
    let mut latest: Option<(String, Record)> = None;
    for entry in fs::read_dir(store)
        .map_err(|_| format!("{want} 没有被隔离过"))?
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = name.strip_suffix(".json") else {
            continue;
        };
        let Ok(r) = fs::read(entry.path())
            .map_err(|_| ())
            .and_then(|b| serde_json::from_slice::<Record>(&b).map_err(|_| ()))
        else {
            continue;
        };
        if r.path == want && latest.as_ref().is_none_or(|(_, l)| r.at >= l.at) {
            latest = Some((id.to_string(), r));
        }
    }
    let (id, record) = latest.ok_or_else(|| format!("{want} 没有被隔离过"))?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(format!("{want} 已经有文件，拒绝覆盖；先处理现有文件再恢复"));
    }
    let blob = store.join(format!("{id}.bin"));
    restore_blob(&blob, path, &record).map_err(|e| format!("移回原位置失败：{e}"))?;
    let _ = fs::remove_file(store.join(format!("{id}.json")));
    Ok(record)
}

/// 隔离移入：同 FS 核验身份后直接 rename；跨 FS 用已 O_NOFOLLOW 打开的 fd 拷贝到新建目标，
/// 删除源文件失败时清理已写出的目标，避免孤儿 .bin
fn relocate_in(from: &Path, to: &Path, expected: &fs::Metadata, src: &mut File) -> io::Result<()> {
    let cur = fs::symlink_metadata(from)?;
    if !cur.file_type().is_file() || !same_identity(expected, &cur) {
        return Err(io::Error::other("源文件在移动前已发生变化"));
    }
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    copy_fd_and_remove(from, to, expected, src)
}

/// 跨 FS 安全移动：从已核验的 fd 拷贝到新建（O_NOFOLLOW + create_new）目标并删除源文件
fn copy_fd_and_remove(
    from: &Path,
    to: &Path,
    expected: &fs::Metadata,
    src: &mut File,
) -> io::Result<()> {
    let fd_meta = src.metadata()?;
    if !fd_meta.file_type().is_file() || !same_identity(expected, &fd_meta) {
        return Err(io::Error::other("源文件句柄已不再指向原普通文件"));
    }
    src.seek(SeekFrom::Start(0))?;
    let mut dst = create_new_nofollow(to)?;
    let copied = match io::copy(src, &mut dst) {
        Ok(n) => n,
        Err(e) => {
            drop(dst);
            let _ = fs::remove_file(to);
            return Err(e);
        }
    };
    if copied != fd_meta.len() {
        drop(dst);
        let _ = fs::remove_file(to);
        return Err(io::Error::other("拷贝不完整"));
    }
    if let Err(e) = dst.sync_all() {
        drop(dst);
        let _ = fs::remove_file(to);
        return Err(e);
    }
    drop(dst);
    // 删原件前再次核对路径仍指向同一个文件；删除失败立即清理已写出的目标避免孤儿
    let cur = fs::symlink_metadata(from)?;
    if !same_identity(expected, &cur) {
        let _ = fs::remove_file(to);
        return Err(io::Error::other("源文件在删除前已被替换"));
    }
    if let Err(e) = fs::remove_file(from) {
        let _ = fs::remove_file(to);
        return Err(e);
    }
    Ok(())
}

/// 从隔离区安全恢复到原路径：create_new + O_NOFOLLOW 原子建文件，在 fd 上直接 fchown/fchmod，
/// 彻底消除恢复目标后的符号链接 TOCTOU 窗口
fn restore_blob(blob: &Path, to: &Path, record: &Record) -> io::Result<()> {
    // 隔离区文件平时权限 0o000，恢复时临时对属主可读（所在目录为 0700）
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(blob, fs::Permissions::from_mode(0o400));
    }
    let res = (|| -> io::Result<()> {
        let (mut src, src_meta) = open_regular_nofollow(blob)?;
        let mut dst = create_new_nofollow(to)?;
        let write_res = (|| -> io::Result<()> {
            let copied = io::copy(&mut src, &mut dst)?;
            if copied != src_meta.len() {
                return Err(io::Error::other("恢复拷贝不完整"));
            }
            restore_meta_fd(&dst, record);
            dst.sync_all()
        })();
        if let Err(e) = write_res {
            drop(dst);
            let _ = fs::remove_file(to);
            return Err(e);
        }
        Ok(())
    })();
    if res.is_err() {
        lock_down(blob);
        return res;
    }
    fs::remove_file(blob)
}

fn sha256_reader(f: &mut impl Read) -> io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

fn create_private(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    let made = {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    };
    #[cfg(not(unix))]
    let made = fs::create_dir_all(dir);
    made.map_err(|e| format!("创建隔离区失败：{e}"))
}

#[cfg(unix)]
fn mode(m: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode()
}
#[cfg(not(unix))]
fn mode(_: &fs::Metadata) -> u32 {
    0
}
#[cfg(unix)]
fn owner(m: &fs::Metadata) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    (m.uid(), m.gid())
}
#[cfg(not(unix))]
fn owner(_: &fs::Metadata) -> (u32, u32) {
    (0, 0)
}

/// 隔离区里的文件去掉全部权限，谁也执行不了
fn lock_down(blob: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(blob, fs::Permissions::from_mode(0o000));
    }
    #[cfg(not(unix))]
    let _ = blob;
}

/// 直接在已打开的目标文件句柄上恢复属主与权限，消除路径符号链接 TOCTOU
fn restore_meta_fd(file: &File, r: &Record) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: fd 是调用方持有的有效已打开普通文件句柄；先 fchown 再 fchmod 保留特殊权限位
        unsafe {
            let _ = libc::fchown(fd, r.uid, r.gid);
            let _ = libc::fchmod(fd, (r.mode & 0o7777) as libc::mode_t);
        }
    }
    #[cfg(not(unix))]
    let _ = (file, r);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("openxdr-quarantine-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn quarantine_and_restore_round_trip() {
        let root = temp();
        let store = root.join("store");
        let file = root.join("payload.sh");
        fs::write(&file, b"#!/bin/sh\necho pwned\n").unwrap();
        let id = uuid::Uuid::new_v4().to_string();

        let r = move_in(&store, &file, &id).unwrap();
        assert!(!file.exists(), "原位置不应再有文件");
        assert_eq!(r.size, 21);
        assert_eq!(r.sha256.len(), 64);
        assert!(store.join(format!("{id}.bin")).exists());

        // 原位置又有了文件：拒绝覆盖
        fs::write(&file, b"new").unwrap();
        assert!(move_out(&store, &file).unwrap_err().contains("拒绝覆盖"));
        fs::remove_file(&file).unwrap();

        let back = move_out(&store, &file).unwrap();
        assert_eq!(back.sha256, r.sha256);
        assert_eq!(fs::read(&file).unwrap(), b"#!/bin/sh\necho pwned\n");
        assert!(
            move_out(&store, &file)
                .unwrap_err()
                .contains("没有被隔离过")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_non_regular_relative_and_pseudo() {
        let root = temp();
        let store = root.join("store");
        let id = uuid::Uuid::new_v4().to_string();
        assert!(
            move_in(&store, Path::new("relative.txt"), &id)
                .unwrap_err()
                .contains("绝对路径")
        );
        assert!(
            move_in(&store, &root, &id)
                .unwrap_err()
                .contains("不是普通文件")
        );
        #[cfg(unix)]
        {
            assert!(move_in(&store, Path::new("/proc/self/status"), &id).is_err());
            let link = root.join("link");
            std::os::unix::fs::symlink("/etc/hostname", &link).unwrap();
            assert!(
                move_in(&store, &link, &id)
                    .unwrap_err()
                    .contains("不是普通文件")
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_parent_dir_traversal_and_symlink_parent_bypass() {
        let root = temp();
        let store = root.join("store");
        fs::create_dir_all(&store).unwrap();
        let secret = store.join("secret.bin");
        fs::write(&secret, b"keep").unwrap();
        let id = uuid::Uuid::new_v4().to_string();

        // 含 .. 路径穿越一律拒绝
        let traversal = root.join("sub").join("..").join("store").join("secret.bin");
        assert!(move_in(&store, &traversal, &id).unwrap_err().contains(".."));
        assert!(move_out(&store, &traversal).unwrap_err().contains(".."));

        #[cfg(unix)]
        {
            // 父目录是指向状态目录的符号链接：规范化后必须拒绝
            let alias = root.join("alias");
            std::os::unix::fs::symlink(&store, &alias).unwrap();
            assert!(
                move_in(&store, &alias.join("secret.bin"), &id)
                    .unwrap_err()
                    .contains("状态文件")
            );

            // 父目录指向 /proc 的符号链接：同样拒绝
            let proc_alias = root.join("proc_alias");
            std::os::unix::fs::symlink("/proc/self", &proc_alias).unwrap();
            assert!(
                move_in(&store, &proc_alias.join("status"), &id)
                    .unwrap_err()
                    .contains("/proc")
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn restore_refuses_dangling_symlink_and_preserves_mode_via_fd() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp();
        let store = root.join("store");
        let file = root.join("tool.sh");
        fs::write(&file, b"#!/bin/sh\necho ok\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o750)).unwrap();
        let id = uuid::Uuid::new_v4().to_string();

        move_in(&store, &file, &id).unwrap();

        // 在原位置放置悬空符号链接，恢复时不得跟随或覆盖
        let decoy = root.join("decoy-target");
        std::os::unix::fs::symlink(&decoy, &file).unwrap();
        assert!(move_out(&store, &file).is_err());
        assert!(!decoy.exists(), "不得经悬空符号链接创建目标文件");
        fs::remove_file(&file).unwrap();

        // 清理后正常恢复，且文件权限通过 fd 完整还原
        move_out(&store, &file).unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o7777,
            0o750
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn copy_fd_cleans_up_orphan_destination_if_remove_fails() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp();
        let ro_dir = root.join("ro");
        fs::create_dir_all(&ro_dir).unwrap();
        let src_path = ro_dir.join("payload.bin");
        fs::write(&src_path, b"payload").unwrap();
        let (mut src_file, meta) = open_regular_nofollow(&src_path).unwrap();

        // 去掉源目录写权限使非 root 的 remove_file(from) 失败；root 下跳过权限断言但仍验证逻辑
        fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o555)).unwrap();
        let dst_path = root.join("orphan.bin");
        let res = copy_fd_and_remove(&src_path, &dst_path, &meta, &mut src_file);
        fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o755)).unwrap();
        if res.is_err() {
            assert!(
                !dst_path.exists(),
                "删除源文件失败时必须清理已写出的目标文件"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}
