//! Linux 主机隔离：用 nftables 建一张独立的表，只放行回环、已建立连接和
//! server 通道，其余进出流量全部丢弃。
//!
//! 独立表意味着解除隔离只需删掉这张表，不会碰到主机原有的防火墙规则。

use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::os::unix::process::CommandExt;
use std::process::{Command as Proc, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::Outcome;
use super::netblock::Net;
use crate::pb::Command;

/// 隔离规则单独一张表，与主机原有规则互不干扰
const TABLE: &str = "openxdr_isolation";
/// 单条隔离指令允许的放行地址输入项上限
const MAX_ALLOW_ENDPOINTS: usize = 128;
/// 整条隔离指令所有主机名解析共享的总截止时间，防止串行超时累计卡死指令流
const TOTAL_RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// 单个主机名最多允许解析出的去重 IP 数量，超限直接拒绝执行而非静默截断丢弃控制端地址
const MAX_RESOLVED: usize = 32;
/// 所有放行项展开后的总地址上限，超限直接拒绝执行而非静默丢弃
const MAX_TOTAL_ENDPOINTS: usize = 256;
/// 全局在途 DNS 解析并发上限，防止重复超时堆积无限多阻塞解析线程
const MAX_INFLIGHT_DNS: usize = 8;
/// `nft` 查询/删表子进程超时上限，防止内核或 nft 卡死拖垮状态探针与隔离解除
const NFT_TIMEOUT: Duration = Duration::from_secs(3);
/// `run_nft` 输出缓冲区保留上限
const MAX_NFT_OUTPUT_BYTES: usize = 1024 * 1024;

static INFLIGHT_DNS: AtomicUsize = AtomicUsize::new(0);

/// 在途 DNS 解析并发槽位，解析线程结束时自动归还。
struct DnsSlot;

impl DnsSlot {
    fn try_acquire() -> Option<Self> {
        let mut cur = INFLIGHT_DNS.load(Ordering::Relaxed);
        loop {
            if cur >= MAX_INFLIGHT_DNS {
                return None;
            }
            match INFLIGHT_DNS.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Self),
                Err(actual) => cur = actual,
            }
        }
    }
}

impl Drop for DnsSlot {
    fn drop(&mut self) {
        INFLIGHT_DNS.fetch_sub(1, Ordering::Release);
    }
}

pub fn isolate(cmd: &Command) -> Outcome {
    if cmd.allow_endpoints.is_empty() {
        // 没有放行地址就隔离，等于把自己也关在门外，之后再也收不到解除指令
        return Outcome::failed("拒绝执行：未指定放行地址，隔离后将无法接收解除指令");
    }

    let script = match build_ruleset(&cmd.allow_endpoints) {
        Ok(s) => s,
        Err(e) => return Outcome::failed(format!("拒绝执行：{e}")),
    };
    match apply(&script) {
        Ok(()) => Outcome::ok(format!(
            "已隔离本机，放行 {}",
            cmd.allow_endpoints.join(", ")
        )),
        Err(e) => Outcome::failed(e),
    }
}

pub fn unisolate(_cmd: &Command) -> Outcome {
    match run_nft(&["delete", "table", "inet", TABLE]) {
        Ok(_) => Outcome::ok("已解除隔离"),
        // 表不存在说明本来就没隔离，视为已达成目标
        Err(e) if e.contains("No such file") || e.contains("does not exist") => {
            Outcome::ok("本机当前未处于隔离状态")
        }
        Err(e) => Outcome::failed(format!("解除隔离失败: {e}")),
    }
}

/// 本机当前是否处于隔离：隔离表还在
pub fn active() -> bool {
    run_nft(&["list", "table", "inet", TABLE]).is_ok()
}

/// 生成完整规则集。在同一 nft 事务里先建再删再建，避免旧表已删但新规则失败导致失陷主机解封。
fn build_ruleset(allow: &[String]) -> Result<String, String> {
    build_ruleset_with(allow, TOTAL_RESOLVE_TIMEOUT, system_resolve)
}

fn build_ruleset_with<F>(
    allow: &[String],
    total_timeout: Duration,
    resolver: F,
) -> Result<String, String>
where
    F: Fn(&str, u16) -> Result<Vec<IpAddr>, String> + Send + Sync + Clone + 'static,
{
    if allow.is_empty() || allow.len() > MAX_ALLOW_ENDPOINTS {
        return Err(format!(
            "放行地址须为 1–{MAX_ALLOW_ENDPOINTS} 项（IP、IP:端口、网段或主机名[:端口]）"
        ));
    }
    let deadline = Instant::now() + total_timeout;
    let mut parsed = Vec::with_capacity(allow.len());
    for ep in allow {
        parsed.extend(parse_endpoint_with(ep, deadline, resolver.clone())?);
        if parsed.len() > MAX_TOTAL_ENDPOINTS {
            return Err(format!(
                "放行地址展开后共 {} 条，超过上限 {MAX_TOTAL_ENDPOINTS}，拒绝截断以免丢失控制端地址",
                parsed.len()
            ));
        }
    }

    let mut s = String::new();
    s.push_str(&format!("add table inet {TABLE}\n"));
    s.push_str(&format!("delete table inet {TABLE}\n"));
    s.push_str(&format!("add table inet {TABLE}\n"));
    s.push_str(&format!(
        "add chain inet {TABLE} input {{ type filter hook input priority -100 ; policy drop ; }}\n"
    ));
    s.push_str(&format!(
        "add chain inet {TABLE} output {{ type filter hook output priority -100 ; policy drop ; }}\n"
    ));
    s.push_str(&format!(
        "add chain inet {TABLE} forward {{ type filter hook forward priority -100 ; policy drop ; }}\n"
    ));
    s.push_str(&format!("add rule inet {TABLE} input iif lo accept\n"));
    s.push_str(&format!("add rule inet {TABLE} output oif lo accept\n"));
    for chain in ["input", "output", "forward"] {
        s.push_str(&format!(
            "add rule inet {TABLE} {chain} ct state established,related accept\n"
        ));
    }
    // IPv6 放行必要 NDP 报文，防止邻居缓存过期后连控制面一起自锁
    for chain in ["input", "output"] {
        s.push_str(&format!(
            "add rule inet {TABLE} {chain} icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert }} accept\n"
        ));
    }
    for (net, port) in parsed {
        let family = if net.addr.is_ipv6() { "ip6" } else { "ip" };
        let host = render(&net);
        let port_clause = port.map_or(String::new(), |p| format!(" tcp dport {p}"));
        s.push_str(&format!(
            "add rule inet {TABLE} output {family} daddr {host}{port_clause} accept\n"
        ));
        let sport_clause = port.map_or(String::new(), |p| format!(" tcp sport {p}"));
        s.push_str(&format!(
            "add rule inet {TABLE} input {family} saddr {host}{sport_clause} accept\n"
        ));
    }
    Ok(s)
}

fn system_resolve(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    (host, port)
        .to_socket_addrs()
        .map(|iter| iter.map(|a| a.ip()).collect())
        .map_err(|e| e.to_string())
}

/// 严格解析放行地址，返回要放行的网段与端口：
/// - 合法 `IpAddr`，或带非零端口的 `SocketAddr`（IPv6 带端口须写成 `[addr]:port`）
/// - 网段 `ip/prefix`（不带端口，主机位清零）
/// - 主机名或 `主机名:端口`：字符集严格限定为字母、数字、`-`、`.`，在本机解析成地址后再写进规则，
///   规则里只出现解析出的数字地址，主机名本身不进 nft 脚本；解析失败、超时或超限均拒绝
#[cfg(test)]
fn parse_endpoint(ep: &str) -> Result<Vec<(Net, Option<u16>)>, String> {
    parse_endpoint_with(ep, Instant::now() + TOTAL_RESOLVE_TIMEOUT, system_resolve)
}

fn parse_endpoint_with<F>(
    ep: &str,
    deadline: Instant,
    resolver: F,
) -> Result<Vec<(Net, Option<u16>)>, String>
where
    F: Fn(&str, u16) -> Result<Vec<IpAddr>, String> + Send + 'static,
{
    let trimmed = ep.trim();
    if trimmed.is_empty() {
        return Err("放行地址为空".into());
    }
    if let Ok(sa) = trimmed.parse::<SocketAddr>() {
        if sa.port() == 0 {
            return Err(format!("放行地址端口不能为 0：{ep}"));
        }
        return Ok(vec![(host_net(sa.ip()), Some(sa.port()))]);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(vec![(host_net(ip), None)]);
    }
    if let Some((addr, prefix)) = trimmed.split_once('/') {
        let invalid = || format!("放行网段无效（须为 地址/前缀长度）：{ep}");
        let addr: IpAddr = addr.parse().map_err(|_| invalid())?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
        if prefix > if addr.is_ipv4() { 32 } else { 128 } {
            return Err(invalid());
        }
        return Ok(vec![(Net::canonical(addr, prefix), None)]);
    }
    let (host, port) = match trimmed.rsplit_once(':') {
        Some((h, p)) => (h, Some(port_of(p, ep)?)),
        None => (trimmed, None),
    };
    if !hostname(host) {
        return Err(format!(
            "放行地址无效（须为 IP、IP:端口、网段或主机名[:端口]）：{ep}"
        ));
    }
    let nets = resolve_hostname_with(host, port, deadline, resolver)?;
    Ok(nets.into_iter().map(|n| (n, port)).collect())
}

/// 在独立线程中按共享截止时间解析主机名，受全局在途并发上限约束；
/// 去重后超过 MAX_RESOLVED 直接拒绝，绝不静默截断丢弃可能唯一的控制端地址。
fn resolve_hostname_with<F>(
    host: &str,
    port: Option<u16>,
    deadline: Instant,
    resolver: F,
) -> Result<Vec<Net>, String>
where
    F: Fn(&str, u16) -> Result<Vec<IpAddr>, String> + Send + 'static,
{
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Err(format!(
            "放行地址 {host} 解析超时（已超过整条隔离指令截止时间）"
        ));
    };
    if remaining.is_zero() {
        return Err(format!(
            "放行地址 {host} 解析超时（已超过整条隔离指令截止时间）"
        ));
    }
    let Some(slot) = DnsSlot::try_acquire() else {
        return Err(format!(
            "在途 DNS 解析已达并发上限（{MAX_INFLIGHT_DNS}），拒绝解析 {host}"
        ));
    };
    let owned_host = host.to_string();
    let resolve_port = port.unwrap_or(0);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _slot = slot;
        let res = resolver(&owned_host, resolve_port);
        let _ = tx.send(res);
    });
    let ips = match rx.recv_timeout(remaining) {
        Ok(Ok(ips)) => ips,
        Ok(Err(e)) => return Err(format!("放行地址 {host} 解析失败：{e}")),
        Err(_) => return Err(format!("放行地址 {host} 解析超时")),
    };
    validate_resolved_nets(host, ips)
}

fn validate_resolved_nets(
    host: &str,
    ips: impl IntoIterator<Item = IpAddr>,
) -> Result<Vec<Net>, String> {
    let mut nets: Vec<Net> = ips.into_iter().map(host_net).collect();
    nets.sort();
    nets.dedup();
    if nets.is_empty() {
        return Err(format!("放行地址 {host} 没有解析出地址"));
    }
    if nets.len() > MAX_RESOLVED {
        return Err(format!(
            "放行地址 {host} 解析出 {} 个地址，超过上限 {MAX_RESOLVED}，拒绝截断以免丢失控制端地址",
            nets.len()
        ));
    }
    Ok(nets)
}

fn port_of(p: &str, ep: &str) -> Result<u16, String> {
    match p.parse::<u16>() {
        Ok(0) => Err(format!("放行地址端口不能为 0：{ep}")),
        Ok(port) => Ok(port),
        Err(_) => Err(format!("放行地址端口无效：{ep}")),
    }
}

/// 主机名：每段 1–63 个字母、数字或 `-`，不以 `-` 开头结尾，总长不超过 253
fn hostname(s: &str) -> bool {
    s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn host_net(ip: IpAddr) -> Net {
    Net::canonical(ip, if ip.is_ipv4() { 32 } else { 128 })
}

/// 单个地址只写地址本身，网段写成 地址/前缀
fn render(net: &Net) -> String {
    if net == &host_net(net.addr) {
        net.addr.to_string()
    } else {
        net.render()
    }
}

fn apply(script: &str) -> Result<(), String> {
    nft_script(script)
}

/// 整段规则交给 nft -f - 原子执行。容器隔离在容器的网络命名空间里也用它
pub(super) fn nft_script(script: &str) -> Result<(), String> {
    let mut child = Proc::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("无法执行 nft（隔离需要 nftables 与 root 权限）: {e}"))?;

    use std::io::Write;
    child
        .stdin
        .take()
        .ok_or("无法写入 nft 标准输入")?
        .write_all(script.as_bytes())
        .map_err(|e| e.to_string())?;

    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}

fn kill_process_group(child: &mut std::process::Child) {
    let pid = child.id() as libc::pid_t;
    if pid > 0 {
        // SAFETY: 子进程已通过 process_group(0) 独立成组（pgid == pid），
        // 发送 SIGKILL 到负 pgid 终止整棵进程树，防后代继续占用管道或卡死。
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn spawn_pipe_reader<R: Read + Send + 'static>(
    pipe: Option<R>,
    limit: usize,
) -> Option<std::sync::mpsc::Receiver<Vec<u8>>> {
    pipe.map(|mut r| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(n) = r.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if kept.len() < limit {
                    let take = (limit - kept.len()).min(n);
                    kept.extend_from_slice(&chunk[..take]);
                }
            }
            let _ = tx.send(kept);
        });
        rx
    })
}

fn run_nft(args: &[&str]) -> Result<String, String> {
    run_nft_with_timeout("nft", args, NFT_TIMEOUT)
}

fn run_nft_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    let mut child = Proc::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("无法执行 {program}: {e}"))?;

    let out_rx = spawn_pipe_reader(child.stdout.take(), MAX_NFT_OUTPUT_BYTES);
    let err_rx = spawn_pipe_reader(child.stderr.take(), 64 * 1024);

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_process_group(&mut child);
                    return Err(format!("执行 {program} 超时"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                kill_process_group(&mut child);
                return Err(format!("等待 {program} 失败: {e}"));
            }
        }
    };

    let recv = |rx: Option<std::sync::mpsc::Receiver<Vec<u8>>>,
                child: &mut std::process::Child|
     -> Result<Vec<u8>, String> {
        let Some(rx) = rx else {
            return Ok(Vec::new());
        };
        let rem = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(rem) {
            Ok(buf) => Ok(buf),
            Err(_) => {
                kill_process_group(child);
                Err(format!("读取 {program} 输出超时"))
            }
        }
    };

    let stdout = recv(out_rx, &mut child)?;
    let stderr = recv(err_rx, &mut child)?;
    if !status.success() {
        return Err(String::from_utf8_lossy(&stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(allow: &[&str]) -> String {
        let v: Vec<String> = allow.iter().map(|s| s.to_string()).collect();
        build_ruleset(&v).unwrap()
    }

    #[test]
    fn ruleset_has_atomic_rebuild_forward_ndp_and_drop_by_default() {
        let s = rules(&["1.2.3.4:443"]);
        // 原子重建：同一事务内 add -> delete -> add，避免先删表后加载失败导致失陷主机解封
        let add = format!("add table inet {TABLE}\n");
        let del = format!("delete table inet {TABLE}\n");
        assert!(
            s.starts_with(&format!("{add}{del}{add}")),
            "应以原子重建序列开头：{s}"
        );
        assert_eq!(
            s.matches("policy drop").count(),
            3,
            "input/output/forward 三链均默认丢弃"
        );
        assert!(s.contains(
            "add chain inet openxdr_isolation forward { type filter hook forward priority -100 ; policy drop ; }"
        ));
        assert!(s.contains(
            "add rule inet openxdr_isolation forward ct state established,related accept"
        ));
        // 回环与已建立连接必须放行，否则会把自己锁死在门外
        assert!(s.contains("iif lo accept"));
        assert!(s.contains("oif lo accept"));
        assert!(s.contains("ct state established,related accept"));
        // IPv6 NDP 放行，防邻居缓存过期自锁
        assert!(s.contains(
            "add rule inet openxdr_isolation input icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept"
        ));
        assert!(s.contains(
            "add rule inet openxdr_isolation output icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept"
        ));
    }

    #[test]
    fn ruleset_ipv4_with_port() {
        let s = rules(&["1.2.3.4:443"]);
        assert!(s.contains("output ip daddr 1.2.3.4 tcp dport 443 accept"));
        assert!(s.contains("input ip saddr 1.2.3.4 tcp sport 443 accept"));
    }

    #[test]
    fn ruleset_ipv6_and_portless() {
        let s = rules(&["[2001:0db8::5]:8443", "10.0.0.9"]);
        assert!(s.contains("output ip6 daddr 2001:db8::5 tcp dport 8443 accept"));
        assert!(s.contains("input ip6 saddr 2001:db8::5 tcp sport 8443 accept"));
        // 无端口：不带端口子句，整段地址放行
        assert!(s.contains("output ip daddr 10.0.0.9 accept"));
        assert!(!s.contains("10.0.0.9 tcp"));
    }

    #[test]
    fn rejects_invalid_or_injected_endpoints() {
        for bad in [
            "",
            "   ",
            "1.2.3.4:0",
            "1.2.3.4:99999",
            "1.2.3.4:abc",
            "1.2.3.4; flush ruleset",
            "1.2.3.4\nflush ruleset",
            "evil.com;flush ruleset",
            "evil.com:443 accept",
            "-bad.example.com",
            "10.0.0.0/33",
            "10.0.0.0/x",
            "10.0.0.0/24:443",
            "[1.2.3.4",
            "1.2.3.4]",
            "[2001:db8::1]",
            "[2001:db8::1]:0",
        ] {
            let v = vec!["10.0.0.1:443".to_string(), bad.to_string()];
            assert!(build_ruleset(&v).is_err(), "{bad:?} 应拒绝");
        }
        // isolate 整条指令应直接失败
        let cmd = Command {
            allow_endpoints: vec!["1.2.3.4; flush ruleset".into()],
            ..Default::default()
        };
        let r = isolate(&cmd);
        assert_eq!(r.status, crate::pb::command_result::Status::Failed);
        assert!(r.detail.contains("拒绝执行"), "{}", r.detail);
    }

    #[test]
    fn endpoint_parse_valid() {
        let one = |ep: &str| {
            let v = parse_endpoint(ep).unwrap();
            assert_eq!(v.len(), 1, "{ep}");
            (render(&v[0].0), v[0].1)
        };
        assert_eq!(one("1.2.3.4:443"), ("1.2.3.4".into(), Some(443)));
        assert_eq!(one("10.0.0.9"), ("10.0.0.9".into(), None));
        assert_eq!(
            one("[2001:db8::1]:8443"),
            ("2001:db8::1".into(), Some(8443))
        );
        assert_eq!(one("2001:db8::1"), ("2001:db8::1".into(), None));
        // 网段：主机位清零
        assert_eq!(one("10.1.1.7/24"), ("10.1.1.0/24".into(), None));
        assert_eq!(one("2001:db8::5/64"), ("2001:db8::/64".into(), None));
    }

    #[test]
    fn ruleset_cidr_and_hostname() {
        let s = rules(&["10.1.1.0/24"]);
        assert!(s.contains("output ip daddr 10.1.1.0/24 accept"));
        assert!(s.contains("input ip saddr 10.1.1.0/24 accept"));

        // 主机名在本机解析，规则里只出现数字地址
        let s = rules(&["localhost:8081"]);
        assert!(s.contains("daddr 127.0.0.1 tcp dport 8081 accept"), "{s}");
        assert!(s.contains("saddr 127.0.0.1 tcp sport 8081 accept"), "{s}");
        assert!(!s.contains("localhost"), "主机名不得写进 nft 脚本：{s}");
        let hosts = parse_endpoint("localhost").unwrap();
        assert!(hosts.iter().all(|(_, port)| port.is_none()));
    }

    #[test]
    fn resolved_hostname_exceeding_max_resolved_is_rejected() {
        let ips = (0..64u8).map(|i| IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, i)));
        let err = validate_resolved_nets("many.example.com", ips).unwrap_err();
        assert!(err.contains("超过上限"), "超限应直接拒绝：{err}");

        // 恰好 MAX_RESOLVED 个去重地址应放行
        let exact =
            (0..MAX_RESOLVED as u8).map(|i| IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 1, i)));
        let ok = validate_resolved_nets("ok.example.com", exact).unwrap();
        assert_eq!(ok.len(), MAX_RESOLVED);
    }

    #[test]
    fn allow_endpoints_count_and_total_resolved_limits_are_enforced() {
        // 超过 128 个输入项直接拒绝
        let too_many: Vec<String> = (0..=MAX_ALLOW_ENDPOINTS)
            .map(|i| format!("10.0.{}.{}:443", i / 256, i % 256))
            .collect();
        let err = build_ruleset(&too_many).unwrap_err();
        assert!(err.contains("1–128"), "{err}");

        // 9 个域名各返回 30 个 IP = 270 > MAX_TOTAL_ENDPOINTS(256)，拒绝而非静默截断
        let domains: Vec<String> = (0..9).map(|i| format!("h{i}.example.com:443")).collect();
        let err = build_ruleset_with(&domains, Duration::from_secs(2), |host, _| {
            let idx: u8 = host
                .strip_prefix('h')
                .and_then(|s| s.split('.').next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            Ok((1..=30u8)
                .map(|j| IpAddr::V4(std::net::Ipv4Addr::new(10, idx, 0, j)))
                .collect())
        })
        .unwrap_err();
        assert!(err.contains("超过上限"), "{err}");
    }

    #[test]
    fn multiple_hostnames_share_single_overall_deadline() {
        // 4 个慢域名每个睡 120ms，但整条隔离指令共享 200ms 总截止时间，不会累计到 480ms
        let domains: Vec<String> = (0..4).map(|i| format!("slow{i}.example.com:443")).collect();
        let started = Instant::now();
        let err = build_ruleset_with(&domains, Duration::from_millis(200), |_host, _| {
            std::thread::sleep(Duration::from_millis(120));
            Ok(vec![IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 1, 1))])
        })
        .unwrap_err();
        let elapsed = started.elapsed();
        assert!(err.contains("超时"), "应因共享截止时间超时拒绝：{err}");
        assert!(
            elapsed < Duration::from_millis(450),
            "多域名应共享同一截止时间，实际耗时 {elapsed:?}"
        );
    }

    #[test]
    fn run_nft_with_timeout_kills_stalled_command_and_descendant() {
        let started = Instant::now();
        let err = run_nft_with_timeout("sh", &["-c", "sleep 30 &"], Duration::from_millis(150))
            .unwrap_err();
        assert!(err.contains("超时"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "后代持有 stdout 时也应在超时内返回"
        );
    }
}
