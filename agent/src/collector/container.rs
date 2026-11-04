//! 进程所在的容器：按 /proc/<pid>/cgroup 识别 docker / podman / containerd / cri-o 容器、
//! Proxmox 的 LXC 容器与 QEMU 虚拟机、systemd-nspawn。
//!
//! 宿主机上的 agent 看得到容器里的全部进程（同一内核），但不知道它们属于谁：
//! 不标出来，容器里的外联与命令都算在宿主机头上。名字读不到就只给 ID，不编造。

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::Container;

/// cgroup 路径缓存上限：同一容器里的进程共用路径，正常远到不了这个数
const MAX_CACHED: usize = 4096;

/// pid 所在的容器；宿主机自己的进程、进程已退场或读不到 cgroup 都返回 None
pub fn of(pid: u32) -> Option<Arc<Container>> {
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let path = cgroup_path(&cgroup)?;
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Arc<Container>>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(hit) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(path) {
        return hit.clone();
    }
    let found = identify(path).map(|(runtime, uid)| {
        let name = name_of(runtime, &uid);
        Arc::new(Container {
            runtime,
            uid,
            name,
            healthcheck: false,
        })
    });
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= MAX_CACHED {
        cache.clear();
    }
    cache.insert(path.to_string(), found.clone());
    found
}

/// Proxmox LXC 容器（按 VMID）。DNS 采集从 veth 接口名认出容器时用
pub fn lxc(vmid: &str) -> Arc<Container> {
    Arc::new(Container {
        runtime: "lxc",
        uid: vmid.to_string(),
        name: name_of("lxc", vmid),
        healthcheck: false,
    })
}

/// LXC 容器静态地址 → VMID，与读取时间
type LxcAddresses = (
    HashMap<std::net::IpAddr, String>,
    Option<std::time::Instant>,
);

/// 地址是不是本机某个 Proxmox LXC 容器的静态地址（配置里 netN 的 ip= / ip6=）。
/// 入站连接的目的地址落在容器上时用它认出容器；DHCP 的容器配置里没有地址，认不出
#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
pub fn lxc_by_ip(ip: std::net::IpAddr) -> Option<Arc<Container>> {
    static MAP: OnceLock<Mutex<LxcAddresses>> = OnceLock::new();
    let mut map = MAP
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if map.1.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
        map.0 = lxc_addresses();
        map.1 = Some(std::time::Instant::now());
    }
    map.0.get(&ip).map(|vmid| lxc(vmid))
}

fn lxc_addresses() -> HashMap<std::net::IpAddr, String> {
    let Ok(dir) = std::fs::read_dir("/etc/pve/lxc") else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(vmid) = name.strip_suffix(".conf").filter(|id| is_vmid(id)) else {
            continue;
        };
        if let Ok(text) = std::fs::read_to_string(entry.path()) {
            for ip in conf_addresses(&text) {
                out.insert(ip, vmid.to_string());
            }
        }
    }
    out
}

/// netN 行里的 ip=10.1.1.100/24、ip6=fd00::5/64；dhcp / manual / auto 不是地址
fn conf_addresses(text: &str) -> Vec<std::net::IpAddr> {
    text.lines()
        .take_while(|l| !l.starts_with('['))
        .filter(|l| l.starts_with("net"))
        .filter_map(|l| l.split_once(':'))
        .flat_map(|(_, v)| v.split(','))
        .filter_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            matches!(k, "ip" | "ip6").then(|| v.split('/').next()?.parse().ok())?
        })
        .collect()
}

/// cgroup v2 只有一行 0::<路径>；v1 有多行，取第一条带容器特征的
fn cgroup_path(cgroup: &str) -> Option<&str> {
    let paths = cgroup.lines().filter_map(|l| l.splitn(3, ':').nth(2));
    let mut first = None;
    for path in paths {
        if identify(path).is_some() {
            return Some(path);
        }
        first.get_or_insert(path);
    }
    first
}

/// 从 cgroup 路径认出容器运行时与 ID
fn identify(path: &str) -> Option<(&'static str, String)> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for (i, seg) in segments.iter().enumerate() {
        let next = segments.get(i + 1).copied();
        let scoped = |prefix: &str| {
            seg.strip_prefix(prefix)
                .and_then(|r| r.strip_suffix(".scope"))
                .filter(|id| is_hex_id(id))
        };
        for (prefix, runtime) in [
            ("docker-", "docker"),
            ("libpod-", "podman"),
            ("cri-containerd-", "containerd"),
            ("crio-", "cri-o"),
        ] {
            if let Some(id) = scoped(prefix) {
                return Some((runtime, short(id)));
            }
        }
        match (*seg, next) {
            // cgroupfs 驱动：/docker/<id>
            ("docker", Some(id)) if is_hex_id(id) => return Some(("docker", short(id))),
            // Proxmox / LXC 4+：/lxc.payload.<id>/…；老版本：/lxc/<id>/…。lxc.monitor.* 是宿主机侧的监控进程
            ("lxc", Some(id)) if is_vmid(id) => return Some(("lxc", id.to_string())),
            ("qemu.slice", Some(scope)) => {
                if let Some(id) = scope.strip_suffix(".scope").filter(|id| is_vmid(id)) {
                    return Some(("qemu", id.to_string()));
                }
            }
            _ => {}
        }
        if let Some(id) = seg.strip_prefix("lxc.payload.") {
            return Some(("lxc", id.to_string()));
        }
        if let Some(name) = seg
            .strip_prefix("systemd-nspawn@")
            .and_then(|r| r.strip_suffix(".service"))
        {
            return Some(("nspawn", name.to_string()));
        }
    }
    None
}

fn is_hex_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_vmid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 9 && s.bytes().all(|b| b.is_ascii_digit())
}

fn short(id: &str) -> String {
    id[..12].to_string()
}

/// 容器名：docker 读容器配置，Proxmox 读 /etc/pve 下的 LXC / VM 配置
fn name_of(runtime: &str, uid: &str) -> Option<String> {
    match runtime {
        "docker" => docker_name(uid),
        "lxc" => pve_conf_value(&format!("/etc/pve/lxc/{uid}.conf"), "hostname"),
        "qemu" => pve_conf_value(&format!("/etc/pve/qemu-server/{uid}.conf"), "name"),
        _ => None,
    }
}

fn docker_name(short_id: &str) -> Option<String> {
    let v = docker_config(short_id)?;
    let name = v["Name"].as_str()?.trim_start_matches('/');
    (!name.is_empty()).then(|| name.to_string())
}

/// docker 容器配置（默认数据目录下的 config.v2.json）。dockerd 换了数据目录、agent 自己跑在容器里就读不到
fn docker_config(short_id: &str) -> Option<serde_json::Value> {
    let dir = std::fs::read_dir("/var/lib/docker/containers").ok()?;
    let full = dir
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.starts_with(short_id))?;
    let text = std::fs::read_to_string(format!("/var/lib/docker/containers/{full}/config.v2.json"))
        .ok()?;
    serde_json::from_str(&text).ok()
}

/// 健康检查结果的缓存时长：容器的健康检查创建后就不变，但同一个短 ID 读不到（刚创建、dockerd 还没写盘）
/// 要能再试，到期一律重读，一分钟一个容器一次目录扫描
const HEALTHCHECK_TTL: Duration = Duration::from_secs(60);

/// docker 容器配置的健康检查命令，写成事件里命令行的样子（参数以空格相连）。
/// 没配、配成 NONE、配置读不到都返回 None——认不出就不标，告警照常
pub fn healthcheck(short_id: &str) -> Option<Arc<str>> {
    let cache = healthchecks();
    if let Some((hit, at)) = cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(short_id)
        && at.elapsed() < HEALTHCHECK_TTL
    {
        return hit.clone();
    }
    let found = docker_config(short_id)
        .and_then(|v| healthcheck_cmd(&v))
        .map(Arc::from);
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= MAX_CACHED {
        cache.clear();
    }
    cache.insert(
        short_id.to_string(),
        (found.clone(), std::time::Instant::now()),
    );
    found
}

type HealthcheckCache = HashMap<String, (Option<Arc<str>>, std::time::Instant)>;

fn healthchecks() -> &'static Mutex<HealthcheckCache> {
    static CACHE: OnceLock<Mutex<HealthcheckCache>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// 测试用：不读 docker 数据目录，直接给容器配上健康检查
#[cfg(test)]
pub fn set_healthcheck(short_id: &str, cmd: &str) {
    healthchecks().lock().unwrap().insert(
        short_id.to_string(),
        (Some(Arc::from(cmd)), std::time::Instant::now()),
    );
}

/// 按 dockerd 的执行方式还原健康检查的命令行：Test 是 ["CMD", 参数...] 时直接执行这些参数，
/// ["CMD-SHELL", 命令] 时在容器的 Shell（没配是 /bin/sh -c）里执行；["NONE"] 是关掉了。
/// 空参数在事件命令行里不占位，这里同样跳过
fn healthcheck_cmd(config: &serde_json::Value) -> Option<String> {
    let config = &config["Config"];
    let test = config["Healthcheck"]["Test"].as_array()?;
    let test: Vec<&str> = test.iter().map(|v| v.as_str()).collect::<Option<_>>()?;
    let argv: Vec<&str> = match test.split_first()? {
        (&"CMD", args) => args.to_vec(),
        (&"CMD-SHELL", args) => {
            let shell: Vec<&str> = match config["Shell"].as_array() {
                Some(s) if !s.is_empty() => s.iter().map(|v| v.as_str()).collect::<Option<_>>()?,
                _ => vec!["/bin/sh", "-c"],
            };
            shell.into_iter().chain(args.iter().copied()).collect()
        }
        _ => return None,
    };
    let line = argv
        .into_iter()
        .filter(|a| !a.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!line.is_empty()).then_some(line)
}

/// Proxmox 配置是 `键: 值` 行；快照段（[snapshot]）之后的同名键属于快照，不算
fn pve_conf_value(path: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    conf_value(&text, key)
}

fn conf_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .take_while(|l| !l.starts_with('['))
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim() == key).then(|| v.trim().to_string())
        })
        .filter(|v| !v.is_empty())
}

/// /proc 里的命令行，参数之间的 NUL 换成空格；读不到或为空（内核线程）返回 None
pub fn cmd_line(pid: u32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let line = raw
        .split(|c| *c == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        .join(" ");
    (!line.is_empty()).then_some(line)
}

/// 从 /proc/<pid>/status 读取当前父进程 PID（PPid > 0）。
/// 刚被 runc 拉起的容器进程在中间 fork 退出后会被内核收养到 containerd-shim，重读即可拿到真父进程
pub fn ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|&p| p > 0)
}

/// 短命容器进程在读 /proc/<pid>/cgroup 前已退场，但父进程是宿主机上的 containerd-shim 或 runc exec 时，
/// 从其命令行参数中的 64 位容器 ID 还原所属容器
pub fn from_runtime_cmd_line(cmd_line: &str) -> Option<Arc<Container>> {
    let mut args = cmd_line.split_whitespace();
    let bin = args.next()?.rsplit('/').next()?;
    let (runtime, id) = if bin.starts_with("containerd-shim") {
        let mut namespace = None;
        let mut id = None;
        while let Some(arg) = args.next() {
            match arg {
                "-namespace" => namespace = args.next(),
                "-id" => id = args.next(),
                _ => {}
            }
        }
        let runtime = match namespace {
            Some("k8s.io") => "containerd",
            _ => "docker",
        };
        (runtime, id.filter(|s| is_hex_id(s))?)
    } else if bin == "runc" {
        let rest: Vec<&str> = args.collect();
        if !rest.contains(&"exec") {
            return None;
        }
        let id = rest.last().copied().filter(|s| is_hex_id(s))?;
        let runtime = if cmd_line.contains("docker") || cmd_line.contains("moby") {
            "docker"
        } else {
            "containerd"
        };
        (runtime, id)
    } else {
        return None;
    };
    let uid = short(id);
    let name = name_of(runtime, &uid);
    Some(Arc::new(Container {
        runtime,
        uid,
        name,
        healthcheck: false,
    }))
}

/// 进程启动时间：/proc/<pid>/stat 第 22 列（开机后的时钟滴答）加开机时间。
/// 快照里早于 agent 启动的进程靠它算运行时长
pub fn started(pid: u32) -> Option<SystemTime> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // 进程名在括号里，可能含空格：从最后一个右括号之后开始数列
    let rest = &stat[stat.rfind(')')? + 2..];
    let ticks: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;
    let boot = boot_time()?;
    // SAFETY: sysconf 只读系统配置
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let hz = if hz > 0 { hz as u64 } else { 100 };
    Some(boot + Duration::from_millis(ticks * 1000 / hz))
}

fn boot_time() -> Option<SystemTime> {
    static BOOT: OnceLock<Option<SystemTime>> = OnceLock::new();
    *BOOT.get_or_init(|| {
        let stat = std::fs::read_to_string("/proc/stat").ok()?;
        let secs: u64 = stat
            .lines()
            .find_map(|l| l.strip_prefix("btime "))?
            .trim()
            .parse()
            .ok()?;
        Some(UNIX_EPOCH + Duration::from_secs(secs))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "4f1c2a3b5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7a8";

    #[test]
    fn identifies_runtimes() {
        let cases = [
            (
                format!("/system.slice/docker-{ID}.scope"),
                Some(("docker", "4f1c2a3b5d6e")),
            ),
            (format!("/docker/{ID}"), Some(("docker", "4f1c2a3b5d6e"))),
            (
                format!("/machine.slice/libpod-{ID}.scope/container"),
                Some(("podman", "4f1c2a3b5d6e")),
            ),
            (
                format!("/kubepods.slice/kubepods-burstable.slice/cri-containerd-{ID}.scope"),
                Some(("containerd", "4f1c2a3b5d6e")),
            ),
            (
                "/lxc/203/ns/system.slice/nginx.service".to_string(),
                Some(("lxc", "203")),
            ),
            (
                "/lxc.payload.201/init.scope".to_string(),
                Some(("lxc", "201")),
            ),
            ("/qemu.slice/108.scope".to_string(), Some(("qemu", "108"))),
            (
                "/machine.slice/systemd-nspawn@web.service/payload".to_string(),
                Some(("nspawn", "web")),
            ),
            // 宿主机自己的进程、LXC 监控进程都不是容器
            ("/system.slice/sshd.service".to_string(), None),
            ("/lxc.monitor.203".to_string(), None),
            ("/user.slice/user-0.slice/session-3.scope".to_string(), None),
            ("/system.slice/docker-short.scope".to_string(), None),
        ];
        for (path, want) in cases {
            let got = identify(&path);
            assert_eq!(
                got.as_ref().map(|(r, id)| (*r, id.as_str())),
                want,
                "{path}"
            );
        }
    }

    #[test]
    fn v1_picks_container_line() {
        let v1 = format!("12:pids:/user.slice\n11:memory:/docker/{ID}\n0::/\n");
        assert_eq!(cgroup_path(&v1), Some(format!("/docker/{ID}").as_str()));
        assert_eq!(cgroup_path("0::/init.scope\n"), Some("/init.scope"));
    }

    #[test]
    fn lxc_conf_addresses() {
        let conf = "hostname: gw\nnet0: name=eth0,bridge=vmbr0,gw=10.1.1.1,hwaddr=BC:24:11:00:00:01,ip=10.1.1.100/24,type=veth\nnet1: name=eth1,bridge=vmbr1,ip=dhcp,ip6=fd00::5/64\n[snap]\nnet0: name=eth0,ip=10.9.9.9/24\n";
        let got: Vec<String> = conf_addresses(conf)
            .iter()
            .map(|ip| ip.to_string())
            .collect();
        assert_eq!(got, ["10.1.1.100", "fd00::5"]);
    }

    #[test]
    fn healthcheck_forms() {
        let cmd = |v: serde_json::Value| healthcheck_cmd(&v);
        let hc = |test: serde_json::Value| serde_json::json!({ "Config": { "Healthcheck": { "Test": test } } });
        assert_eq!(
            cmd(hc(serde_json::json!([
                "CMD-SHELL",
                "nc -z 127.0.0.1 4822 || exit 1"
            ])))
            .as_deref(),
            Some("/bin/sh -c nc -z 127.0.0.1 4822 || exit 1")
        );
        assert_eq!(
            cmd(hc(serde_json::json!([
                "CMD",
                "pg_isready",
                "-U",
                "yuesheng"
            ])))
            .as_deref(),
            Some("pg_isready -U yuesheng")
        );
        // 镜像用 SHELL 指令换了 shell，dockerd 用它执行 CMD-SHELL
        let mut bash = hc(serde_json::json!(["CMD-SHELL", "curl -f localhost"]));
        bash["Config"]["Shell"] = serde_json::json!(["/bin/bash", "-o", "pipefail", "-c"]);
        assert_eq!(
            cmd(bash).as_deref(),
            Some("/bin/bash -o pipefail -c curl -f localhost")
        );
        assert_eq!(cmd(hc(serde_json::json!(["NONE"]))), None);
        assert_eq!(cmd(hc(serde_json::json!([]))), None);
        assert_eq!(cmd(hc(serde_json::json!(["CMD"]))), None);
        assert_eq!(cmd(hc(serde_json::json!(["CMD", 1]))), None);
        assert_eq!(cmd(serde_json::json!({ "Config": {} })), None);
        // 读不到配置（数据目录不在默认位置、容器已删）就认不出
        assert_eq!(healthcheck("0123456789ab"), None);
    }

    #[test]
    fn pve_conf() {
        let conf = "arch: amd64\nhostname: termix\nnet0: name=eth0,bridge=vmbr0\n\n[pre-upgrade]\nhostname: old\n";
        assert_eq!(conf_value(conf, "hostname").as_deref(), Some("termix"));
        assert_eq!(
            conf_value("name: win11\n", "name").as_deref(),
            Some("win11")
        );
        assert_eq!(conf_value("[snap]\nhostname: x\n", "hostname"), None);
        assert_eq!(conf_value("hostname:\n", "hostname"), None);
    }

    #[test]
    fn runtime_cmd_line_parsing() {
        let docker_shim = format!(
            "/usr/bin/containerd-shim-runc-v2 -namespace moby -id {ID} -address /run/containerd/containerd.sock"
        );
        let c = from_runtime_cmd_line(&docker_shim).unwrap();
        assert_eq!(c.runtime, "docker");
        assert_eq!(c.uid, "4f1c2a3b5d6e");

        let k8s_shim = format!(
            "containerd-shim-runc-v2 -namespace k8s.io -id {ID} -address /run/containerd/containerd.sock"
        );
        let c = from_runtime_cmd_line(&k8s_shim).unwrap();
        assert_eq!(c.runtime, "containerd");
        assert_eq!(c.uid, "4f1c2a3b5d6e");

        let runc_exec = format!(
            "runc --root /var/run/docker/runtime-runc/moby --systemd-cgroup exec --process /tmp/runc-process123 --detach {ID}"
        );
        let c = from_runtime_cmd_line(&runc_exec).unwrap();
        assert_eq!(c.runtime, "docker");
        assert_eq!(c.uid, "4f1c2a3b5d6e");

        assert!(from_runtime_cmd_line("/usr/bin/sshd -D").is_none());
        assert!(from_runtime_cmd_line("containerd-shim-runc-v2 -id short").is_none());
    }
}
