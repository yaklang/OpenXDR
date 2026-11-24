//! 软件清单（Linux dpkg / RPM）：已装的包、版本，以及它们来自哪个源码包——发行版的漏洞公告按源码包发布，
//! server 对受支持的 dpkg 发行版做漏洞匹配；RPM 当前只记录清单。产出 OCSF Software Inventory Info（class_uid=5020）。
//!
//! 30 分钟查一次，清单变了才报，最长 24 小时补报一次。没有 dpkg / RPM 的主机（如 Alpine）暂不采集，
//! 健康快照里标为不可用，不编数据。

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::pb::AgentEvent;

use super::EventSink;

/// OCSF Software Inventory Info
const CLASS_SOFTWARE_INVENTORY: u32 = 5020;
const POLL: Duration = Duration::from_secs(30 * 60);
const HEARTBEAT: Duration = Duration::from_secs(24 * 3600);
const MAX_PACKAGES: usize = 20_000;
/// package_of 路径→所属包缓存上限，满时清空，防短命路径长期累积导致内存增长
const MAX_PACKAGE_CACHE: usize = 8192;
/// dpkg-query / rpm 外部命令超时上限，防锁库或卡死拖垮采集线程
const CMD_TIMEOUT: Duration = Duration::from_secs(30);
/// 外部包查询命令 stdout/stderr 最大保留字节数
const MAX_CMD_OUTPUT_BYTES: usize = 32 * 1024 * 1024;

/// 一个已装的二进制包：名称、版本、源码包名、源码版本
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub source: String,
    pub source_version: String,
}

pub fn spawn(agent_id: String, sink: EventSink) {
    std::thread::spawn(move || {
        let mut last: Option<(u64, Instant)> = None;
        while !sink.is_closed() {
            match snapshot() {
                Ok((os, manager, packages)) => {
                    sink.capability("software", manager, "active");
                    let fp = fingerprint(&os, manager, &packages);
                    if last.is_none_or(|(prev, at)| prev != fp || at.elapsed() >= HEARTBEAT) {
                        if !sink.send(event(&agent_id, &os, manager, &packages)) {
                            return;
                        }
                        last = Some((fp, Instant::now()));
                    }
                }
                Err(e) => {
                    sink.capability("software", "package-db", "unavailable");
                    eprintln!("软件清单不可用（{e}）");
                }
            }
            // 分段睡，断线重连后旧线程能及时退出
            let until = Instant::now() + POLL;
            while Instant::now() < until && !sink.is_closed() {
                std::thread::sleep(Duration::from_secs(30));
            }
        }
    });
}

/// 发行版 ID 与版本（/etc/os-release），漏洞库按发行版版本分生态
pub type Os = (String, String);

#[derive(Debug)]
struct CmdOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
}

/// 强杀超时子进程组后短轮询回收僵尸的上限，防不可中断 D 状态让 wait() 无限阻塞
const REAP_TIMEOUT: Duration = Duration::from_millis(500);

fn kill_process_group(child: &mut std::process::Child) {
    let pid = child.id() as libc::pid_t;
    if pid > 0 {
        // SAFETY: 子进程已通过 process_group(0) 独立成组（pgid == pid），
        // 向负 pgid 发 SIGKILL 杀整棵进程树，防后代继承管道写端导致挂死。
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    // 短轮询回收僵尸，避免子进程陷入不可中断 D 状态时 wait() 无限阻塞越过 deadline
    let deadline = Instant::now() + REAP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// 带超时执行外部命令：子进程独立进程组，后台线程经 channel 排空 stdout/stderr 并与命令共享同一截止时间，
/// 绝不无期限 join；超时或异常时杀整棵进程树并回收子进程。
fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> std::io::Result<CmdOutput> {
    run_with_limits(program, args, timeout, MAX_CMD_OUTPUT_BYTES, 64 * 1024)
}

fn run_with_limits(
    program: &str,
    args: &[&str],
    timeout: Duration,
    max_stdout: usize,
    max_stderr: usize,
) -> std::io::Result<CmdOutput> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()?;

    fn drain_pipe<R: Read + Send + 'static>(
        pipe: Option<R>,
        limit: usize,
    ) -> Option<std::sync::mpsc::Receiver<(Vec<u8>, bool)>> {
        pipe.map(|mut r| {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut kept = Vec::new();
                let mut truncated = false;
                let mut chunk = [0u8; 8192];
                while let Ok(n) = r.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    if kept.len() < limit {
                        let take = (limit - kept.len()).min(n);
                        kept.extend_from_slice(&chunk[..take]);
                        if take < n {
                            truncated = true;
                        }
                    } else {
                        truncated = true;
                    }
                }
                let _ = tx.send((kept, truncated));
            });
            rx
        })
    }

    let out_rx = drain_pipe(child.stdout.take(), max_stdout);
    let err_rx = drain_pipe(child.stderr.take(), max_stderr);

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_process_group(&mut child);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("{program} 执行超时"),
                    ));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                kill_process_group(&mut child);
                return Err(e);
            }
        }
    };

    let recv = |rx: Option<std::sync::mpsc::Receiver<(Vec<u8>, bool)>>,
                child: &mut std::process::Child|
     -> std::io::Result<(Vec<u8>, bool)> {
        let Some(rx) = rx else {
            return Ok((Vec::new(), false));
        };
        let rem = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(rem) {
            Ok(pair) => Ok(pair),
            Err(_) => {
                kill_process_group(child);
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("{program} 管道读取超时"),
                ))
            }
        }
    };

    let (stdout, stdout_truncated) = recv(out_rx, &mut child)?;
    let (stderr, _) = recv(err_rx, &mut child)?;
    Ok(CmdOutput {
        status,
        stdout,
        stderr,
        stdout_truncated,
    })
}

fn snapshot() -> Result<(Os, &'static str, Vec<Package>), String> {
    let release = std::fs::read_to_string("/etc/os-release")
        .map_err(|e| format!("读不到 /etc/os-release：{e}"))?;
    let out = run_with_timeout(
        "dpkg-query",
        &[
            "-W",
            "-f=${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\t${db:Status-Abbrev}\\n",
        ],
        CMD_TIMEOUT,
    );
    let (manager, out) = match out {
        Ok(out) => ("dpkg", out),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
            "rpm",
            run_with_timeout(
                "rpm",
                &[
                    "-qa",
                    "--qf",
                    "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\t%{ARCH}\n",
                ],
                CMD_TIMEOUT,
            )
            .map_err(|e| format!("没有可用的软件包查询器：{e}"))?,
        ),
        Err(e) => return Err(format!("查询 dpkg 失败：{e}")),
    };
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    if out.stdout_truncated {
        return Err(format!("{manager} 输出超过上限被截断，拒绝使用残缺清单"));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let packages = if manager == "rpm" {
        parse_rpm(&text)?
    } else {
        parse(&text)
    };
    if packages.is_empty() || packages.len() > MAX_PACKAGES {
        return Err(format!(
            "{manager} 返回 {} 个包，不像正常清单",
            packages.len()
        ));
    }
    Ok((os_release(&release), manager, packages))
}

pub fn os_release(text: &str) -> Os {
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_string())
            .unwrap_or_default()
    };
    (field("ID"), field("VERSION_ID"))
}

/// 只要真正装好的包（状态 ii）；源码包名缺省就是包名本身
pub fn parse(text: &str) -> Vec<Package> {
    let mut out: Vec<Package> = text
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() != 5 || !f[4].starts_with("ii") || f[0].is_empty() || f[1].is_empty() {
                return None;
            }
            let source = if f[2].is_empty() { f[0] } else { f[2] };
            let source_version = if f[3].is_empty() { f[1] } else { f[3] };
            Some(Package {
                name: f[0].into(),
                version: f[1].into(),
                source: source.into(),
                source_version: source_version.into(),
            })
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// RPM 版本保留 epoch；源码包文件名没有 epoch，不从二进制包推测补齐。
fn parse_rpm(text: &str) -> Result<Vec<Package>, String> {
    let mut out = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 4 || fields[0].is_empty() {
            return Err("RPM 清单字段不完整".into());
        }
        if fields[0] == "gpg-pubkey" && fields[3] == "(none)" {
            continue;
        }
        let (epoch, version) = fields[1].split_once(':').ok_or("RPM 版本缺少 epoch")?;
        if epoch.is_empty() || !epoch.bytes().all(|c| c.is_ascii_digit()) || version.is_empty() {
            return Err("RPM 版本格式无效".into());
        }
        let source = fields[2]
            .strip_suffix(".src.rpm")
            .or_else(|| fields[2].strip_suffix(".nosrc.rpm"));
        let (source_name, source_version) = match source {
            Some(source) => {
                let (base, release) = source.rsplit_once('-').ok_or("RPM 源码包缺少 release")?;
                let (name, version) = base.rsplit_once('-').ok_or("RPM 源码包缺少 version")?;
                if name.is_empty() || version.is_empty() || release.is_empty() {
                    return Err("RPM 源码包字段为空".into());
                }
                (name.to_string(), format!("{version}-{release}"))
            }
            None if fields[2] == "(none)" => (String::new(), String::new()),
            None => return Err("RPM 源码包格式无效".into()),
        };
        out.push(Package {
            name: fields[0].into(),
            version: fields[1].into(),
            source: source_name,
            source_version,
        });
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// 可执行文件属于哪个包（dpkg -S / rpm -qf），监听服务据此对上漏洞。每个路径只查一次，查不到记空
pub fn package_of(path: &str) -> Option<String> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(hit) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(path) {
        return hit.clone();
    }
    let found = match run_with_timeout("dpkg-query", &["-S", "--", path], CMD_TIMEOUT) {
        Ok(out) if out.status.success() => owner_package(&String::from_utf8_lossy(&out.stdout)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => run_with_timeout(
            "rpm",
            &["-qf", "--qf", "%{NAME}\n", "--", path],
            CMD_TIMEOUT,
        )
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .next()
                .filter(|name| !name.is_empty() && !name.chars().any(char::is_whitespace))
                .map(str::to_string)
        }),
        _ => None,
    };
    let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
    if map.len() >= MAX_PACKAGE_CACHE {
        map.clear();
    }
    map.insert(path.to_string(), found.clone());
    found
}

/// 「openssh-server: /usr/sbin/sshd」→ openssh-server；多个包共有（diversion）时取第一个，去掉架构后缀
fn owner_package(out: &str) -> Option<String> {
    let first = out.lines().next()?.split_once(": ")?.0;
    let name = first.split(", ").next()?.split(':').next()?.trim();
    (!name.is_empty() && !name.contains(' ')).then(|| name.to_string())
}

fn fingerprint(os: &Os, manager: &str, packages: &[Package]) -> u64 {
    let mut h = DefaultHasher::new();
    os.hash(&mut h);
    manager.hash(&mut h);
    packages.hash(&mut h);
    h.finish()
}

fn event(agent_id: &str, os: &Os, manager: &str, packages: &[Package]) -> AgentEvent {
    // 包列表用数组的数组，上千个包时比对象数组小一半
    let rows: Vec<_> = packages
        .iter()
        .map(|p| json!([p.name, p.version, p.source, p.source_version]))
        .collect();
    let raw = json!({
        "activity_id": 2,
        "os": { "id": os.0, "version_id": os.1 },
        "manager": manager,
        "packages": rows,
    });
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: CLASS_SOFTWARE_INVENTORY,
        raw_json: raw.to_string(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_installed_packages_with_source() {
        let text = "acl\t2.3.2-2+b1\tacl\t2.3.2-2\tii \n\
                    libssl3t64\t3.5.1-1\topenssl\t\tii \n\
                    removed\t1.0\t\t\trc \n\
                    bash\t5.2.37-2\t\t\tii \n";
        let p = parse(text);
        assert_eq!(p.len(), 3, "rc（已删只剩配置）的不算");
        let ssl = p.iter().find(|p| p.name == "libssl3t64").unwrap();
        assert_eq!(
            (ssl.source.as_str(), ssl.source_version.as_str()),
            ("openssl", "3.5.1-1"),
            "源码版本缺省取包版本"
        );
        let bash = p.iter().find(|p| p.name == "bash").unwrap();
        assert_eq!(bash.source, "bash");
        let acl = p.iter().find(|p| p.name == "acl").unwrap();
        assert_eq!(
            acl.source_version, "2.3.2-2",
            "binNMU 的源码版本与包版本不同"
        );
    }

    #[test]
    fn owner_package_from_dpkg_search() {
        assert_eq!(
            owner_package("openssh-server: /usr/sbin/sshd\n").as_deref(),
            Some("openssh-server")
        );
        assert_eq!(
            owner_package("libc6:amd64: /usr/lib/x86_64-linux-gnu/libc.so.6\n").as_deref(),
            Some("libc6")
        );
        assert_eq!(owner_package("diversion by dash from: /bin/sh\n"), None);
        assert_eq!(owner_package(""), None);
    }

    #[test]
    fn rpm_preserves_epoch_and_source_identity() {
        let packages = parse_rpm("openssl\t1:1.1.1k-9.uel20\topenssl-1.1.1k-9.uel20.src.rpm\tx86_64\nlib-example\t0:2.0-3\tlib-example-2.0-3.nosrc.rpm\tx86_64\ngpg-pubkey\t0:123-456\t(none)\t(none)\nlocal\t0:1-1\t(none)\tx86_64\n").unwrap();
        assert_eq!(packages.len(), 3);
        let ssl = packages.iter().find(|p| p.name == "openssl").unwrap();
        assert_eq!(ssl.version, "1:1.1.1k-9.uel20");
        assert_eq!(ssl.source_version, "1.1.1k-9.uel20");
        let local = packages.iter().find(|p| p.name == "local").unwrap();
        assert!(local.source.is_empty() && local.source_version.is_empty());
        let raw: serde_json::Value = serde_json::from_str(
            &event("test", &("uos".into(), "20".into()), "rpm", &packages).raw_json,
        )
        .unwrap();
        assert_eq!(raw["manager"], "rpm");
        assert_eq!(raw["packages"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn rpm_rejects_incomplete_or_malformed_rows() {
        for row in [
            "pkg\t1:2-3",
            "pkg\t2-3\tpkg-2-3.src.rpm\tx86_64",
            "pkg\t0:2-3\tbad\tx86_64",
            "pkg\t0:2-3\tpkg--3.src.rpm\tx86_64",
        ] {
            assert!(parse_rpm(row).is_err(), "{row}");
        }
    }

    #[test]
    fn reads_os_release() {
        let text = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nVERSION_ID=\"13\"\nID=debian\n";
        assert_eq!(os_release(text), ("debian".into(), "13".into()));
    }

    #[test]
    fn run_with_timeout_kills_stalled_command() {
        let started = Instant::now();
        let err = run_with_timeout("sleep", &["30"], Duration::from_millis(150)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn run_with_timeout_does_not_hang_when_descendant_holds_stdout() {
        // 父 shell 立刻退出，但后台后代 sleep 仍继承 stdout 写端，验证在 deadline 内返回且不挂死
        let started = Instant::now();
        let err =
            run_with_timeout("sh", &["-c", "sleep 30 &"], Duration::from_millis(200)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "后代持有 stdout 写端时应在 deadline 内返回，实际耗时 {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn run_with_limits_marks_truncated_output() {
        let out = run_with_limits(
            "sh",
            &["-c", "head -c 4096 /dev/zero | tr '\\0' 'a'"],
            Duration::from_secs(5),
            128,
            1024,
        )
        .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), 128);
        assert!(out.stdout_truncated, "超上限输出应明确标记截断");
    }
}
