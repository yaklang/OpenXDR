//! Linux 按内容执行拦截。每次更新先加载完整新策略，保存成功后才释放旧策略。
use super::Outcome;
use aya::{
    Btf, Ebpf,
    maps::{Array, HashMap},
    programs::Lsm,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

type Error = Box<dyn std::error::Error + Send + Sync>;
#[repr(C)]
#[derive(Clone, Copy)]
struct Digest {
    algorithm: u32,
    bytes: [u8; 64],
}
// SAFETY: C 布局，无填充，全部字段都允许任意位模式。
unsafe impl aya::Pod for Digest {}
#[repr(C)]
#[derive(Clone, Copy)]
struct Probe {
    digest: Digest,
    error: i32,
}
// SAFETY: 与内核 probe_result 同布局，无填充与引用。
unsafe impl aya::Pod for Probe {}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    path: String,
    algorithm: u32,
    bytes: Vec<u8>,
}
impl Rule {
    fn digest(&self) -> Result<Digest, Error> {
        Ok(Digest {
            algorithm: self.algorithm,
            bytes: self
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| "执行拦截状态中的哈希长度错误")?,
        })
    }
}
struct Manager {
    rules: Vec<Rule>,
    _bpf: Option<Ebpf>,
}
static MANAGER: OnceLock<Mutex<Option<Manager>>> = OnceLock::new();
fn state_path() -> PathBuf {
    crate::enroll::default_env_file().with_file_name("exec-block.json")
}

fn load() -> Result<Ebpf, Error> {
    let active = fs::read_to_string("/sys/kernel/security/lsm")?;
    if !active.trim().split(',').any(|v| v == "bpf") {
        return Err("内核未启用 BPF LSM".into());
    }
    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/execblock.bpf.o"
    )))?;
    let btf = Btf::from_sys_fs()?;
    for (name, hook) in [
        ("probe_hash", "file_ioctl"),
        ("deny_execution", "bprm_check_security"),
    ] {
        let program: &mut Lsm = bpf.program_mut(name).ok_or("缺少 LSM 程序")?.try_into()?;
        program.load(hook, &btf)?;
        program.attach()?;
    }
    Ok(bpf)
}

fn hash(bpf: &mut Ebpf, path: &Path) -> Result<Digest, Error> {
    // file_open 阶段尚未建立完整的读取能力，IMA 在部分内核上会返回 EOPNOTSUPP。
    // 先打开普通文件，再用只读 FIONREAD 触发 sleepable file_ioctl 探测。
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("只能拦截普通文件".into());
    }
    // 同步 ioctl 与 map 操作期间不 await，始终处在同一 OS 线程。
    let tid =
        ((std::process::id() as u64) << 32) | unsafe { libc::syscall(libc::SYS_gettid) as u64 };
    let mut map = HashMap::<_, u64, Probe>::try_from(bpf.map_mut("PROBE").ok_or("缺少探测 map")?)?;
    map.insert(
        tid,
        Probe {
            digest: Digest {
                algorithm: 0,
                bytes: [0; 64],
            },
            error: -libc::ENODATA,
        },
        0,
    )?;
    let mut available: libc::c_int = 0;
    // SAFETY: fd 存活，FIONREAD 的输出指向可写 int；结果取 LSM map，文件系统可不实现此 ioctl。
    unsafe {
        libc::ioctl(file.as_raw_fd(), libc::FIONREAD, &mut available);
    }
    let result = map.get(&tid, 0);
    map.remove(&tid)?;
    let result = result?;
    if result.error != 0 {
        return Err(format!("内核 IMA 哈希计算失败：{}", result.error).into());
    }
    Ok(result.digest)
}

fn activate(rules: &[Rule]) -> Result<Option<Ebpf>, Error> {
    if rules.is_empty() {
        return Ok(None);
    }
    if rules.len() > 4096 {
        return Err("执行拦截规则超过 4096 条".into());
    }
    let mut bpf = load()?;
    // 重启后内核的哈希算法可能改变，不得把旧摘要当成有效防护。
    let current = hash(&mut bpf, &std::env::current_exe()?)?;
    {
        let mut denied =
            HashMap::<_, Digest, u32>::try_from(bpf.map_mut("DENIED").ok_or("缺少拒绝 map")?)?;
        for rule in rules {
            let digest = rule.digest()?;
            if digest.algorithm != current.algorithm {
                return Err("IMA 哈希算法已改变，无法恢复原规则".into());
            }
            if digest.bytes == current.bytes {
                return Err("拒绝拦截 agent 自身".into());
            }
            denied.insert(digest, 1, 0)?;
        }
    }
    Array::<_, u32>::try_from(bpf.map_mut("ENABLED").ok_or("缺少启用 map")?)?.set(0, 1, 0)?;
    Ok(Some(bpf))
}

fn read_state(path: &Path) -> Result<Vec<Rule>, Error> {
    match fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}
fn save(path: &Path, rules: &[Rule]) -> Result<(), Error> {
    let parent = path.parent().ok_or("状态目录无效")?;
    fs::create_dir_all(parent)?;
    let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<(), Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&serde_json::to_vec(rules)?)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(temp);
    result
}

fn restore_manager() -> Result<Manager, Error> {
    let rules = read_state(&state_path())?;
    let bpf = activate(&rules)?;
    Ok(Manager { rules, _bpf: bpf })
}
pub fn restore() {
    let mut guard = MANAGER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match restore_manager() {
        Ok(manager) => *guard = Some(manager),
        Err(e) => eprintln!("执行拦截恢复失败，当前规则未生效：{e}"),
    }
}

pub fn run(target: &str, block: bool) -> Outcome {
    match update(target, block) {
        Ok(()) => Outcome::ok(if block {
            format!("已按内容禁止执行 {target}（所有相同内容的拷贝）")
        } else {
            format!("已解除 {target} 的执行拦截")
        }),
        Err(e) => Outcome::failed(format!("执行拦截更新失败：{e}")),
    }
}
fn update(target: &str, block: bool) -> Result<(), Error> {
    let path = Path::new(target);
    if !path.is_absolute()
        || target.contains(['\0', '\n', '\r'])
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("文件路径必须是规范绝对路径".into());
    }
    let mut guard = MANAGER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| "执行拦截锁已损坏")?;
    if guard.is_none() {
        *guard = Some(if block {
            restore_manager()?
        } else {
            // 恢复失败时仍允许删除持久规则，特别是算法变化后的最后一条。
            Manager {
                rules: read_state(&state_path())?,
                _bpf: None,
            }
        });
    }
    let manager = guard.as_mut().ok_or("执行拦截未初始化")?;
    update_manager(manager, target, block, &state_path())
}

fn update_manager(
    manager: &mut Manager,
    target: &str,
    block: bool,
    state: &Path,
) -> Result<(), Error> {
    let path = Path::new(target);
    let mut rules = manager.rules.clone();
    if block {
        let canonical = fs::canonicalize(path)?;
        if [
            "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc", "/sys", "/dev", "/boot",
        ]
        .iter()
        .any(|p| canonical.starts_with(p))
        {
            return Err("拒绝拦截系统目录中的文件".into());
        }
        let mut bpf = load()?;
        let digest = hash(&mut bpf, &canonical)?;
        // 系统程序即使被复制到临时目录也不得封掉所有同内容副本。
        for protected in [
            std::env::current_exe()?,
            PathBuf::from("/bin/sh"),
            PathBuf::from("/bin/bash"),
            PathBuf::from("/usr/bin/env"),
            PathBuf::from("/usr/bin/systemctl"),
        ] {
            match fs::canonicalize(protected) {
                Ok(p) if hash(&mut bpf, &p)?.bytes == digest.bytes => {
                    return Err("拒绝拦截 agent 或关键系统程序的副本".into());
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        // 同路径再次下发不丢掉旧内容的规则，解除按原路径清掉该路径的全部历史摘要。
        if !rules
            .iter()
            .any(|r| r.path == target && r.algorithm == digest.algorithm && r.bytes == digest.bytes)
        {
            rules.push(Rule {
                path: target.into(),
                algorithm: digest.algorithm,
                bytes: digest.bytes.to_vec(),
            });
        }
    } else {
        rules.retain(|r| r.path != target);
    }
    let bpf = activate(&rules)?;
    save(state, &rules)?;
    *manager = Manager { rules, _bpf: bpf };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_roundtrip_and_corruption() {
        let dir = std::env::temp_dir().join(format!("openxdr-execblock-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("state.json");
        assert!(read_state(&path).unwrap().is_empty());
        let rules = vec![Rule {
            path: "/tmp/deleted".into(),
            algorithm: 4,
            bytes: vec![7; 64],
        }];
        save(&path, &rules).unwrap();
        let stored = read_state(&path).unwrap();
        assert_eq!(stored[0].path, rules[0].path);
        assert_eq!(stored[0].digest().unwrap().bytes, [7; 64]);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::write(&path, b"not json").unwrap();
        assert!(read_state(&path).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn malformed_digest_rejected() {
        let rule = Rule {
            path: "/tmp/a".into(),
            algorithm: 4,
            bytes: vec![0; 32],
        };
        assert!(rule.digest().is_err());
    }

    // 专用测试主机运行：给 ELF 副本追加唯一尾部数据，只拦截测试样本的内容。
    // 不使用平台状态路径，不修改系统启动参数，不挂后台服务。
    #[test]
    #[ignore = "需要专用 Linux 测试主机的 root、BPF LSM、BTF 与 IMA"]
    fn kernel_blocks_copies_and_restores() {
        let dir = std::env::temp_dir().join(format!("openxdr-lsm-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let original = dir.join("original");
        let copy = dir.join("copy");
        fs::copy("/bin/true", &original).unwrap();
        // ELF 加载忽略文件末尾的附加数据，IMA 全文件哈希仍区分这个独有样本。
        OpenOptions::new()
            .append(true)
            .open(&original)
            .unwrap()
            .write_all(uuid::Uuid::new_v4().as_bytes())
            .unwrap();
        fs::copy(&original, &copy).unwrap();
        assert!(
            std::process::Command::new(&original)
                .status()
                .unwrap()
                .success()
        );
        let state = dir.join("state.json");
        let target = original.to_str().unwrap();
        let mut manager = Manager {
            rules: Vec::new(),
            _bpf: None,
        };
        assert!(update_manager(&mut manager, "/bin/true", true, &state).is_err());
        update_manager(&mut manager, target, true, &state).unwrap();
        update_manager(&mut manager, target, true, &state).unwrap();
        assert_eq!(manager.rules.len(), 1);
        // 状态保存失败不能替换当前生效策略。
        let invalid_state = dir.join("missing-state-dir");
        fs::write(&invalid_state, b"not a directory").unwrap();
        assert!(update_manager(&mut manager, target, false, &invalid_state.join("state")).is_err());
        assert_eq!(manager.rules.len(), 1);
        assert!(
            std::process::Command::new("/bin/true")
                .status()
                .unwrap()
                .success()
        );
        let hardlink = dir.join("hardlink");
        let symlink = dir.join("symlink");
        fs::hard_link(&copy, &hardlink).unwrap();
        std::os::unix::fs::symlink(&copy, &symlink).unwrap();
        for p in [&original, &copy, &hardlink, &symlink] {
            assert_eq!(
                std::process::Command::new(p)
                    .status()
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EACCES)
            );
        }
        let late = dir.join("late-copy");
        fs::copy(&original, &late).unwrap();
        assert_eq!(
            std::process::Command::new(&late)
                .status()
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        let renamed = dir.join("renamed");
        fs::rename(&late, &renamed).unwrap();
        assert_eq!(
            std::process::Command::new(&renamed)
                .status()
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        // 内容改变后不再命中，防止 IMA 缓存旧摘要导致把新文件误判为旧样本。
        OpenOptions::new()
            .append(true)
            .open(&renamed)
            .unwrap()
            .write_all(b"changed")
            .unwrap();
        assert!(
            std::process::Command::new(&renamed)
                .status()
                .unwrap()
                .success()
        );
        // 两个路径引用同一内容；解除一条不能解除另一条。
        update_manager(&mut manager, copy.to_str().unwrap(), true, &state).unwrap();
        fs::remove_file(&original).unwrap();
        drop(manager);
        let rules = read_state(&state).unwrap();
        let bpf = activate(&rules).unwrap();
        let mut restored = Manager { rules, _bpf: bpf };
        update_manager(&mut restored, target, false, &state).unwrap();
        assert_eq!(
            std::process::Command::new(&copy)
                .status()
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        update_manager(&mut restored, copy.to_str().unwrap(), false, &state).unwrap();
        assert!(read_state(&state).unwrap().is_empty());
        assert!(restored._bpf.is_none());
        drop(restored);
        assert!(
            std::process::Command::new(&copy)
                .status()
                .unwrap()
                .success()
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
