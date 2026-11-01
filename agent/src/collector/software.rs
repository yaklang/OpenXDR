//! 软件清单（Linux dpkg / RPM）：已装的包、版本，以及它们来自哪个源码包——发行版的漏洞公告按源码包发布，
//! server 对受支持的 dpkg 发行版做漏洞匹配；RPM 当前只记录清单。产出 OCSF Software Inventory Info（class_uid=5020）。
//!
//! 30 分钟查一次，清单变了才报，最长 24 小时补报一次。没有 dpkg / RPM 的主机（如 Alpine）暂不采集，
//! 健康快照里标为不可用，不编数据。

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::pb::AgentEvent;

use super::EventSink;

/// OCSF Software Inventory Info
const CLASS_SOFTWARE_INVENTORY: u32 = 5020;
const POLL: Duration = Duration::from_secs(30 * 60);
const HEARTBEAT: Duration = Duration::from_secs(24 * 3600);
const MAX_PACKAGES: usize = 20_000;

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

fn snapshot() -> Result<(Os, &'static str, Vec<Package>), String> {
    let release = std::fs::read_to_string("/etc/os-release")
        .map_err(|e| format!("读不到 /etc/os-release：{e}"))?;
    let out = Command::new("dpkg-query")
        .args(["-W", "-f=${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\t${db:Status-Abbrev}\\n"])
        .output();
    let (manager, out) = match out {
        Ok(out) => ("dpkg", out),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
            "rpm",
            Command::new("rpm")
                .args([
                    "-qa",
                    "--qf",
                    "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\t%{ARCH}\n",
                ])
                .output()
                .map_err(|e| format!("没有可用的软件包查询器：{e}"))?,
        ),
        Err(e) => return Err(format!("查询 dpkg 失败：{e}")),
    };
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
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
    let found = match Command::new("dpkg-query").args(["-S", "--", path]).output() {
        Ok(out) if out.status.success() => owner_package(&String::from_utf8_lossy(&out.stdout)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Command::new("rpm")
            .args(["-qf", "--qf", "%{NAME}\n", "--", path])
            .output()
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
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(path.to_string(), found.clone());
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
}
