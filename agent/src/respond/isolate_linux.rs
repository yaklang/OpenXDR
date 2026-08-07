//! Linux 主机隔离：用 nftables 建一张独立的表，只放行回环、已建立连接和
//! server 通道，其余进出流量全部丢弃。
//!
//! 独立表意味着解除隔离只需删掉这张表，不会碰到主机原有的防火墙规则。

use std::process::Command as Proc;

use super::Outcome;
use crate::pb::Command;

/// 隔离规则单独一张表，与主机原有规则互不干扰
const TABLE: &str = "openxdr_isolation";

pub fn isolate(cmd: &Command) -> Outcome {
    if cmd.allow_endpoints.is_empty() {
        // 没有放行地址就隔离，等于把自己也关在门外，之后再也收不到解除指令
        return Outcome::failed("拒绝执行：未指定放行地址，隔离后将无法接收解除指令");
    }

    let script = build_ruleset(&cmd.allow_endpoints);
    if cmd.dry_run {
        return Outcome::ok(format!(
            "dry-run：将隔离本机，仅放行 {}。规则如下：\n{script}",
            cmd.allow_endpoints.join(", ")
        ));
    }

    match apply(&script) {
        Ok(()) => Outcome::ok(format!(
            "已隔离本机，放行 {}",
            cmd.allow_endpoints.join(", ")
        )),
        Err(e) => Outcome::failed(e),
    }
}

pub fn unisolate(cmd: &Command) -> Outcome {
    if cmd.dry_run {
        return Outcome::ok(format!("dry-run：将删除隔离表 {TABLE}，恢复正常通信"));
    }
    match run_nft(&["delete", "table", "inet", TABLE]) {
        Ok(_) => Outcome::ok("已解除隔离"),
        // 表不存在说明本来就没隔离，视为已达成目标
        Err(e) if e.contains("No such file") || e.contains("does not exist") => {
            Outcome::ok("本机当前未处于隔离状态")
        }
        Err(e) => Outcome::failed(format!("解除隔离失败: {e}")),
    }
}

/// 生成完整规则集。每次隔离都先删后建，保证规则是确定的而不是叠加的。
fn build_ruleset(allow: &[String]) -> String {
    let mut s = String::new();
    s.push_str(&format!("add table inet {TABLE}\n"));
    s.push_str(&format!(
        "add chain inet {TABLE} input {{ type filter hook input priority -100 ; policy drop ; }}\n"
    ));
    s.push_str(&format!(
        "add chain inet {TABLE} output {{ type filter hook output priority -100 ; policy drop ; }}\n"
    ));
    for chain in ["input", "output"] {
        s.push_str(&format!("add rule inet {TABLE} {chain} iif lo accept\n"));
        s.push_str(&format!("add rule inet {TABLE} {chain} oif lo accept\n"));
        s.push_str(&format!(
            "add rule inet {TABLE} {chain} ct state established,related accept\n"
        ));
    }
    for ep in allow {
        let (host, port) = split_endpoint(ep);
        let family = if host.contains(':') { "ip6" } else { "ip" };
        let port_clause = port.map_or(String::new(), |p| format!(" tcp dport {p}"));
        s.push_str(&format!(
            "add rule inet {TABLE} output {family} daddr {host}{port_clause} accept\n"
        ));
        let sport_clause = port.map_or(String::new(), |p| format!(" tcp sport {p}"));
        s.push_str(&format!(
            "add rule inet {TABLE} input {family} saddr {host}{sport_clause} accept\n"
        ));
    }
    s
}

/// 拆 "host:port"。IPv6 要求写成 [addr]:port，否则无法与地址里的冒号区分。
fn split_endpoint(ep: &str) -> (&str, Option<&str>) {
    if let Some(rest) = ep.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        return (host, tail.strip_prefix(':'));
    }
    match ep.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port)),
        _ => (ep, None),
    }
}

fn apply(script: &str) -> Result<(), String> {
    // 先删旧表：隔离必须是幂等的，重复下发不应叠加出半套规则
    let _ = run_nft(&["delete", "table", "inet", TABLE]);

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

fn run_nft(args: &[&str]) -> Result<String, String> {
    let out = Proc::new("nft")
        .args(args)
        .output()
        .map_err(|e| format!("无法执行 nft: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
