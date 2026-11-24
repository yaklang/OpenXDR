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
/// `nft -f -` 原子规则脚本执行超时上限，防内核或 nft 卡死无限阻塞响应流
const NFT_SCRIPT_TIMEOUT: Duration = Duration::from_secs(10);
/// 强杀超时子进程组后短轮询回收僵尸的上限，防不可中断 D 状态让 wait() 无限阻塞
const REAP_TIMEOUT: Duration = Duration::from_millis(500);
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
        Ok(ApplyOutcome::Applied) => Outcome::ok(format!(
            "已隔离本机，放行 {}",
            cmd.allow_endpoints.join(", ")
        )),
        Ok(ApplyOutcome::AppliedAfterTimeout) => Outcome::ok(format!(
            "已隔离本机（提交确认超时，复核已生效），放行 {}",
            cmd.allow_endpoints.join(", ")
        )),
        Ok(ApplyOutcome::UncertainPreserved) => Outcome::ok(format!(
            "本机隔离提交超时且复核与清理均未确认清除，保守按已生效保留自动解封租约，放行 {}",
            cmd.allow_endpoints.join(", ")
        )),
        Err(e) => Outcome::failed(e),
    }
}

pub fn unisolate(_cmd: &Command) -> Outcome {
    match unisolate_table(TABLE) {
        Ok(UnisolateOutcome::Removed) => Outcome::ok("已解除隔离"),
        Ok(UnisolateOutcome::AlreadyAbsent) => Outcome::ok("本机当前未处于隔离状态"),
        Err(e) => Outcome::failed(format!("解除隔离失败: {e}")),
    }
}

/// 隔离表当前存在状态：通过完整无截断的 `nft list tables` 枚举确认，
/// 彻底摆脱对 stderr 子串与 locale 的依赖。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TableState {
    Present,
    Absent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnisolateOutcome {
    Removed,
    AlreadyAbsent,
}

/// 区分 nft 启动/等待/超时等执行层故障与子进程实际运行后的命令级非零退出。
#[derive(Debug, PartialEq, Eq)]
enum NftExecError {
    SpawnOrIo(String),
    Timeout(String),
    Exit(String),
}

impl NftExecError {
    fn into_message(self) -> String {
        match self {
            Self::SpawnOrIo(m) | Self::Timeout(m) | Self::Exit(m) => m,
        }
    }
}

/// 精确核对 `nft list tables` 输出中是否包含 `table inet <table>`。
fn list_tables_contains(output: &str, family: &str, table: &str) -> bool {
    output.lines().any(|line| {
        let mut parts = line.split_whitespace();
        parts.next() == Some("table")
            && parts.next() == Some(family)
            && parts.next() == Some(table)
            && parts.next().is_none()
    })
}

fn table_state_with(
    program: &str,
    list_args: &[&str],
    table: &str,
    timeout: Duration,
) -> TableState {
    match run_nft_with_timeout_raw(program, list_args, timeout) {
        Ok((stdout, false)) => {
            if list_tables_contains(&stdout, "inet", table) {
                TableState::Present
            } else {
                TableState::Absent
            }
        }
        // 枚举失败、超时、启动/加载器错误或输出被截断：一律判 Unknown
        Ok((_, true)) | Err(_) => TableState::Unknown,
    }
}

pub(super) fn table_state(table: &str) -> TableState {
    table_state_with("nft", &["list", "tables"], table, NFT_TIMEOUT)
}

fn delete_table_confirmed_with(
    program: &str,
    delete_args: &[&str],
    list_args: &[&str],
    table: &str,
    timeout: Duration,
) -> Result<(), String> {
    match run_nft_with_timeout_raw(program, delete_args, timeout) {
        Ok(_) => Ok(()),
        Err(e) => {
            if table_state_with(program, list_args, table, timeout) == TableState::Absent {
                Ok(())
            } else {
                Err(e.into_message())
            }
        }
    }
}

pub(super) fn delete_table_confirmed(table: &str) -> Result<(), String> {
    delete_table_confirmed_with(
        "nft",
        &["delete", "table", "inet", table],
        &["list", "tables"],
        table,
        NFT_TIMEOUT,
    )
}

pub(super) fn unisolate_table(table: &str) -> Result<UnisolateOutcome, String> {
    unisolate_table_with(
        "nft",
        &["delete", "table", "inet", table],
        &["list", "tables"],
        table,
        NFT_TIMEOUT,
    )
}

fn unisolate_table_with(
    program: &str,
    delete_args: &[&str],
    list_args: &[&str],
    table: &str,
    timeout: Duration,
) -> Result<UnisolateOutcome, String> {
    match run_nft_with_timeout_raw(program, delete_args, timeout) {
        Ok(_) => Ok(UnisolateOutcome::Removed),
        Err(e) => {
            if table_state_with(program, list_args, table, timeout) == TableState::Absent {
                Ok(UnisolateOutcome::AlreadyAbsent)
            } else {
                Err(e.into_message())
            }
        }
    }
}

/// 本机当前是否处于隔离：隔离表还在
pub fn active() -> bool {
    table_state(TABLE) == TableState::Present
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

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ApplyOutcome {
    /// 规则正常提交成功
    Applied,
    /// 提交确认超时，但复核确认隔离表已生效（按成功上报以保留服务端自动解封租约）
    AppliedAfterTimeout,
    /// 提交、复核与清理均无法确认规则未生效（保守按已生效上报以保留服务端自动解封租约）
    UncertainPreserved,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ScriptError {
    /// 明确失败（未能启动、返回非零退出码、写入失败等）
    Failed(String),
    /// 执行或读写超时，内核规则是否已提交未知，需显式复核
    Unknown(String),
}

#[cfg(test)]
impl ScriptError {
    fn into_message(self) -> String {
        match self {
            Self::Failed(m) | Self::Unknown(m) => m,
        }
    }
}

fn apply(script: &str) -> Result<ApplyOutcome, String> {
    apply_table_script(TABLE, script)
}

/// 在当前网络命名空间中应用指定隔离表规则：超时后显式复核表状态，
/// 仅在确认不存在或确认清除成功后才回报确定失败；否则保守保留租约。
pub(super) fn apply_table_script(table: &str, script: &str) -> Result<ApplyOutcome, String> {
    apply_with(
        script,
        |s| nft_script_with_timeout_raw("nft", &["-f", "-"], s, NFT_SCRIPT_TIMEOUT),
        || table_state(table),
        || delete_table_confirmed(table),
    )
}

pub(super) fn apply_with<FRun, FCheck, FCleanup>(
    script: &str,
    run: FRun,
    check_state: FCheck,
    cleanup: FCleanup,
) -> Result<ApplyOutcome, String>
where
    FRun: FnOnce(&str) -> Result<(), ScriptError>,
    FCheck: FnOnce() -> TableState,
    FCleanup: FnOnce() -> Result<(), String>,
{
    match run(script) {
        Ok(()) => Ok(ApplyOutcome::Applied),
        Err(ScriptError::Failed(e)) => Err(e),
        Err(ScriptError::Unknown(e)) => match check_state() {
            TableState::Present => Ok(ApplyOutcome::AppliedAfterTimeout),
            TableState::Absent => Err(format!("{e}（复核隔离表确认不存在）")),
            TableState::Unknown => match cleanup() {
                Ok(()) => Err(format!("{e}（复核未知，已确认清除隔离表）")),
                Err(_) => Ok(ApplyOutcome::UncertainPreserved),
            },
        },
    }
}

#[cfg(test)]
fn nft_script_with_timeout(
    program: &str,
    args: &[&str],
    script: &str,
    timeout: Duration,
) -> Result<(), String> {
    nft_script_with_timeout_raw(program, args, script, timeout).map_err(ScriptError::into_message)
}

fn nft_script_with_timeout_raw(
    program: &str,
    args: &[&str],
    script: &str,
    timeout: Duration,
) -> Result<(), ScriptError> {
    let mut child = Proc::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| {
            let msg = if program == "nft" {
                format!("无法执行 nft（隔离需要 nftables 与 root 权限）: {e}")
            } else {
                format!("无法执行 {program}: {e}")
            };
            ScriptError::Failed(msg)
        })?;

    // 后台线程并发读 stderr，避免大量错误输出撑满管道缓冲导致死锁
    let err_rx = spawn_pipe_reader(child.stderr.take(), 64 * 1024);

    // 后台线程写 stdin 并在写完后关闭写端，防子进程卡死不读 stdin 时主线程阻塞在 write_all
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ScriptError::Failed("无法写入 nft 标准输入".into()))?;
    let payload = script.as_bytes().to_vec();
    let (write_tx, write_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Write;
        let res = stdin.write_all(&payload);
        drop(stdin);
        let _ = write_tx.send(res);
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_process_group(&mut child);
                    return Err(ScriptError::Unknown(format!(
                        "执行 {program} 超时，防火墙规则状态未知"
                    )));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                kill_process_group(&mut child);
                return Err(ScriptError::Unknown(format!(
                    "等待 {program} 失败: {e}，防火墙规则状态未知"
                )));
            }
        }
    };

    let stderr = if let Some(rx) = err_rx {
        let rem = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(rem) {
            Ok((buf, _)) => buf,
            Err(_) => {
                kill_process_group(&mut child);
                return Err(ScriptError::Unknown(format!(
                    "读取 {program} 错误输出超时，防火墙规则状态未知"
                )));
            }
        }
    } else {
        Vec::new()
    };

    let write_rem = deadline.saturating_duration_since(Instant::now());
    let write_res = write_rx.recv_timeout(write_rem);

    if !status.success() {
        let msg = String::from_utf8_lossy(&stderr).trim().to_string();
        if !msg.is_empty() {
            return Err(ScriptError::Failed(msg));
        }
        return Err(ScriptError::Failed(format!(
            "{program} 执行失败（退出状态 {status}）"
        )));
    }

    match write_res {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(ScriptError::Failed(format!(
            "写入 {program} 标准输入失败: {e}"
        ))),
        Err(_) => {
            kill_process_group(&mut child);
            Err(ScriptError::Unknown(format!(
                "写入 {program} 标准输入超时，防火墙规则状态未知"
            )))
        }
    }
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
    // 短轮询回收僵尸，避免子进程卡在不可中断 D 状态时 wait() 无限阻塞越过 deadline
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

fn spawn_pipe_reader<R: Read + Send + 'static>(
    pipe: Option<R>,
    limit: usize,
) -> Option<std::sync::mpsc::Receiver<(Vec<u8>, bool)>> {
    pipe.map(|mut r| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut truncated = false;
            let mut chunk = [0u8; 4096];
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

#[cfg(test)]
fn run_nft_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    run_nft_with_timeout_raw(program, args, timeout)
        .map(|(stdout, _)| stdout)
        .map_err(NftExecError::into_message)
}

fn run_nft_with_timeout_raw(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<(String, bool), NftExecError> {
    let mut child = Proc::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| NftExecError::SpawnOrIo(format!("无法执行 {program}: {e}")))?;

    let out_rx = spawn_pipe_reader(child.stdout.take(), MAX_NFT_OUTPUT_BYTES);
    let err_rx = spawn_pipe_reader(child.stderr.take(), 64 * 1024);

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_process_group(&mut child);
                    return Err(NftExecError::Timeout(format!("执行 {program} 超时")));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                kill_process_group(&mut child);
                return Err(NftExecError::SpawnOrIo(format!("等待 {program} 失败: {e}")));
            }
        }
    };

    let recv = |rx: Option<std::sync::mpsc::Receiver<(Vec<u8>, bool)>>,
                child: &mut std::process::Child|
     -> Result<(Vec<u8>, bool), NftExecError> {
        let Some(rx) = rx else {
            return Ok((Vec::new(), false));
        };
        let rem = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(rem) {
            Ok(pair) => Ok(pair),
            Err(_) => {
                kill_process_group(child);
                Err(NftExecError::Timeout(format!("读取 {program} 输出超时")))
            }
        }
    };

    let (stdout, stdout_truncated) = recv(out_rx, &mut child)?;
    let (stderr, _) = recv(err_rx, &mut child)?;
    if !status.success() {
        return Err(NftExecError::Exit(
            String::from_utf8_lossy(&stderr).trim().to_string(),
        ));
    }
    Ok((
        String::from_utf8_lossy(&stdout).into_owned(),
        stdout_truncated,
    ))
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

    #[test]
    fn nft_script_with_timeout_handles_large_stderr_and_kills_stalled_process_group() {
        // 正常消费 stdin 并退出
        nft_script_with_timeout(
            "sh",
            &["-c", "cat >/dev/null"],
            "add table inet test\n",
            Duration::from_secs(2),
        )
        .unwrap();

        // 写超过 64 KiB stderr 后失败退出：并发读 stderr 防死锁，并返回错误文本
        let err = nft_script_with_timeout(
            "sh",
            &["-c", "head -c 131072 /dev/zero | tr '\\0' 'e' >&2; exit 1"],
            "bad ruleset\n",
            Duration::from_secs(3),
        )
        .unwrap_err();
        assert!(err.starts_with("eeee"), "应返回截断保留的 stderr：{err:?}");

        // 子进程卡住：超时强杀进程组并返回规则状态未知提示
        let started = Instant::now();
        let err = nft_script_with_timeout(
            "sh",
            &["-c", "sleep 30"],
            "add table inet test\n",
            Duration::from_millis(150),
        )
        .unwrap_err();
        assert!(
            err.contains("超时") && err.contains("规则状态未知"),
            "超时应提示规则状态未知：{err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "卡死子进程应在 deadline 内返回"
        );

        // 父进程立刻退出但后代持有 stderr 写端：共享 deadline 强杀进程组，绝不挂死
        let started = Instant::now();
        let err = nft_script_with_timeout(
            "sh",
            &["-c", "sleep 30 &"],
            "add table inet test\n",
            Duration::from_millis(150),
        )
        .unwrap_err();
        assert!(
            err.contains("超时") && err.contains("规则状态未知"),
            "后代持 stderr 超时应提示规则状态未知：{err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "后代持有 stderr 写端时也应在 deadline 内返回"
        );
    }

    #[test]
    fn apply_timeout_rechecks_isolation_state_to_preserve_lease_or_cleanup() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // 1. 规则已提交但确认/stderr 超时 -> 复核确认隔离表已生效 -> 返回 Ok(AppliedAfterTimeout)，
        //    绝不报 Failed 丢租约，也不调用清理
        let cleaned = AtomicBool::new(false);
        let res = apply_with(
            "add table inet openxdr_isolation\n",
            |s| {
                nft_script_with_timeout_raw(
                    "sh",
                    &["-c", "sleep 30 &"],
                    s,
                    Duration::from_millis(120),
                )
            },
            || TableState::Present,
            || {
                cleaned.store(true, Ordering::SeqCst);
                Ok(())
            },
        );
        assert_eq!(res, Ok(ApplyOutcome::AppliedAfterTimeout));
        assert!(
            !cleaned.load(Ordering::SeqCst),
            "复核已生效时不得误删隔离表"
        );

        // 2. 应用超时且复核确认表不存在 -> 直接返回 Err（不误报生效）
        let cleaned = AtomicBool::new(false);
        let err = apply_with(
            "add table inet openxdr_isolation\n",
            |s| {
                nft_script_with_timeout_raw(
                    "sh",
                    &["-c", "sleep 30"],
                    s,
                    Duration::from_millis(120),
                )
            },
            || TableState::Absent,
            || {
                cleaned.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(!cleaned.load(Ordering::SeqCst));
        assert!(
            err.contains("超时") && err.contains("不存在"),
            "错误信息应说明超时且确认不存在：{err}"
        );

        // 3. 应用超时 + 复核超时(Unknown) + 清理失败 -> 无法确认规则未生效，
        //    必须保守返回 Ok(UncertainPreserved) 保住自动解封租约
        let cleaned = AtomicBool::new(false);
        let res = apply_with(
            "add table inet openxdr_isolation\n",
            |s| {
                nft_script_with_timeout_raw(
                    "sh",
                    &["-c", "sleep 30"],
                    s,
                    Duration::from_millis(120),
                )
            },
            || TableState::Unknown,
            || {
                cleaned.store(true, Ordering::SeqCst);
                Err("delete timeout".into())
            },
        );
        assert!(cleaned.load(Ordering::SeqCst));
        assert_eq!(res, Ok(ApplyOutcome::UncertainPreserved));

        // 4. 应用超时 + 复核超时(Unknown) + 清理确认成功 -> 确认表已清除，返回 Err
        let cleaned = AtomicBool::new(false);
        let err = apply_with(
            "add table inet openxdr_isolation\n",
            |s| {
                nft_script_with_timeout_raw(
                    "sh",
                    &["-c", "sleep 30"],
                    s,
                    Duration::from_millis(120),
                )
            },
            || TableState::Unknown,
            || {
                cleaned.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(cleaned.load(Ordering::SeqCst));
        assert!(err.contains("已确认清除"), "{err}");

        // 5. 明确失败（非零退出）-> 不复核不清理，直接返回 Err
        let checked = AtomicBool::new(false);
        let cleaned = AtomicBool::new(false);
        let err = apply_with(
            "bad ruleset\n",
            |s| {
                nft_script_with_timeout_raw(
                    "sh",
                    &["-c", "echo syntax error >&2; exit 1"],
                    s,
                    Duration::from_secs(2),
                )
            },
            || {
                checked.store(true, Ordering::SeqCst);
                TableState::Present
            },
            || {
                cleaned.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(err, "syntax error");
        assert!(!checked.load(Ordering::SeqCst));
        assert!(!cleaned.load(Ordering::SeqCst));
    }

    #[test]
    fn table_state_uses_full_enumeration_and_rejects_enoent_loader_and_truncation() {
        let missing_bin = "/nonexistent-openxdr-nft-binary-enoent";
        let list_args = &["list", "tables"];
        let del_args = &["delete", "table", "inet", TABLE];

        // 1. 真实 ENOENT -> Unknown，清理与解封均返错，提交超时仍保租约
        assert_eq!(
            table_state_with(missing_bin, list_args, TABLE, Duration::from_secs(1)),
            TableState::Unknown
        );
        assert!(
            delete_table_confirmed_with(
                missing_bin,
                del_args,
                list_args,
                TABLE,
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert_eq!(
            apply_with(
                "add table inet openxdr_isolation\n",
                |_| Err(ScriptError::Unknown("执行 nft 超时".into())),
                || table_state_with(missing_bin, list_args, TABLE, Duration::from_secs(1)),
                || delete_table_confirmed_with(
                    missing_bin,
                    del_args,
                    list_args,
                    TABLE,
                    Duration::from_secs(1)
                ),
            ),
            Ok(ApplyOutcome::UncertainPreserved)
        );
        assert!(
            unisolate_table_with(
                missing_bin,
                del_args,
                list_args,
                TABLE,
                Duration::from_secs(1)
            )
            .is_err()
        );

        // 2. 动态加载器缺共享库（exit 127 + 含 "No such file or directory"）：
        //    必须判 Unknown，绝不能误判为表不存在或解封成功
        let loader_err = &[
            "-c",
            "echo 'nft: error while loading shared libraries: libnftables.so.1: cannot open shared object file: No such file or directory' >&2; exit 127",
        ];
        assert_eq!(
            table_state_with("sh", loader_err, TABLE, Duration::from_secs(1)),
            TableState::Unknown
        );
        assert!(
            delete_table_confirmed_with(
                "sh",
                loader_err,
                loader_err,
                TABLE,
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            unisolate_table_with("sh", loader_err, loader_err, TABLE, Duration::from_secs(1))
                .is_err()
        );
        assert_eq!(
            apply_with(
                "add table inet openxdr_isolation\n",
                |_| Err(ScriptError::Unknown("执行 nft 超时".into())),
                || table_state_with("sh", loader_err, TABLE, Duration::from_secs(1)),
                || delete_table_confirmed_with(
                    "sh",
                    loader_err,
                    loader_err,
                    TABLE,
                    Duration::from_secs(1)
                ),
            ),
            Ok(ApplyOutcome::UncertainPreserved)
        );

        // 3. 完整表枚举成功且不含目标表（含相似前缀/不同 family 干扰项）-> 确认为 Absent，
        //    删除失败后经表枚举确认返回 AlreadyAbsent
        let list_without = &[
            "-c",
            "printf 'table ip openxdr_isolation\\ntable inet openxdr_isolation_other\\ntable inet filter\\n'",
        ];
        assert_eq!(
            table_state_with("sh", list_without, TABLE, Duration::from_secs(1)),
            TableState::Absent
        );
        assert_eq!(
            unisolate_table_with(
                "sh",
                &["-c", "exit 1"],
                list_without,
                TABLE,
                Duration::from_secs(1)
            ),
            Ok(UnisolateOutcome::AlreadyAbsent)
        );

        // 4. 完整表枚举成功且精确包含目标表 -> Present
        let list_with = &[
            "-c",
            "printf 'table inet filter\\ntable inet openxdr_isolation\\n'",
        ];
        assert_eq!(
            table_state_with("sh", list_with, TABLE, Duration::from_secs(1)),
            TableState::Present
        );

        // 5. 表枚举输出超限（> 1 MiB）被截断 -> 保守判 Unknown，绝不把截断后的缺失当 Absent
        let truncated_list = &["-c", "head -c 1100000 /dev/zero | tr '\\0' 'a'"];
        assert_eq!(
            table_state_with("sh", truncated_list, TABLE, Duration::from_secs(2)),
            TableState::Unknown
        );
    }
}
