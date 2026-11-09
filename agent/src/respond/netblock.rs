//! 网络封锁：断开本机与指定地址的进出通信。目标可以是 IP、网段（CIDR）或域名，域名在执行时解析成地址。
//!
//! 自保：不封 server 自己（封了就再也收不到解除指令）、回环、未指定地址，也不封过宽的网段。
//! Linux 用 nftables 独立表 `openxdr_block`，Windows 用防火墙规则组「OpenXDR Block」；
//! 每条规则带着原始目标，解除时按目标整组删除，封锁和解除都可以重复下发。

use std::net::{IpAddr, ToSocketAddrs};

use super::Outcome;
use crate::pb::Command;

/// 网段下限：比这更宽的封锁更像误操作，挡掉的正常流量远多于攻击者
const MIN_PREFIX_V4: u8 = 16;
const MIN_PREFIX_V6: u8 = 48;
/// 域名解析出的地址上限，防止通配解析把整片地址都封了
const MAX_RESOLVED: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub struct Net {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Net {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }

    pub fn render(&self) -> String {
        format!("{}/{}", self.addr, self.prefix)
    }
}

/// 解析封锁目标：IP、CIDR，或者域名（交给系统解析器）。返回规范化的目标与地址
pub fn parse_target(target: &str) -> Result<(String, Vec<Net>), String> {
    let target = target.trim().trim_end_matches('.').to_ascii_lowercase();
    if target.is_empty() || target.len() > 253 {
        return Err("未指定封锁目标".into());
    }
    if let Some((addr, prefix)) = target.split_once('/') {
        let addr: IpAddr = addr.parse().map_err(|_| "网段格式应为 地址/前缀长度")?;
        let prefix: u8 = prefix.parse().map_err(|_| "网段格式应为 地址/前缀长度")?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err("前缀长度超出范围".into());
        }
        return Ok((target, vec![Net { addr, prefix }]));
    }
    if let Ok(addr) = target.parse::<IpAddr>() {
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        return Ok((target, vec![Net { addr, prefix }]));
    }
    if !hostname(&target) {
        return Err("目标必须是 IP、网段或域名".into());
    }
    let mut nets: Vec<Net> = (target.as_str(), 0)
        .to_socket_addrs()
        .map_err(|e| format!("域名 {target} 解析失败：{e}"))?
        .map(|a| {
            let addr = a.ip();
            let prefix = if addr.is_ipv4() { 32 } else { 128 };
            Net { addr, prefix }
        })
        .collect();
    nets.sort_by_key(|n| n.render());
    nets.dedup();
    if nets.is_empty() || nets.len() > MAX_RESOLVED {
        return Err(format!(
            "域名 {target} 解析出 {} 个地址，拒绝封锁",
            nets.len()
        ));
    }
    Ok((target, nets))
}

fn hostname(s: &str) -> bool {
    s.contains('.')
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// 自保检查：过宽、回环、未指定，或者覆盖了 server 地址、本机地址的，一律拒绝。
/// protected 是地址与它的称呼（「server 地址」「本机地址」）
pub fn check(nets: &[Net], protected: &[(IpAddr, &str)]) -> Result<(), String> {
    for n in nets {
        let min = if n.addr.is_ipv4() {
            MIN_PREFIX_V4
        } else {
            MIN_PREFIX_V6
        };
        if n.prefix < min {
            return Err(format!(
                "{} 范围过宽（IPv4 至少 /{MIN_PREFIX_V4}、IPv6 至少 /{MIN_PREFIX_V6}）",
                n.render()
            ));
        }
        if n.addr.is_loopback() || n.addr.is_unspecified() || n.addr.is_multicast() {
            return Err(format!("{} 不能封锁", n.render()));
        }
        if let Some((ip, what)) = protected.iter().find(|(ip, _)| n.contains(*ip)) {
            return Err(format!(
                "{} 包含{what} {ip}，封锁后本机会断网、收不到解除指令",
                n.render()
            ));
        }
    }
    Ok(())
}

/// 不能封的地址：本机网卡上的地址（反弹 shell 连回本机这类信号的对端就是自己），
/// 加上 OPENXDR_SERVER 里的主机名解析出来的全部地址
fn protected() -> Vec<(IpAddr, &'static str)> {
    let own = if_addrs::get_if_addrs().unwrap_or_default();
    let server = server_addrs();
    own.into_iter()
        .map(|i| (i.ip(), "本机地址"))
        .chain(server.into_iter().map(|ip| (ip, "server 地址")))
        .collect()
}

fn server_addrs() -> Vec<IpAddr> {
    let Ok(url) = std::env::var("OPENXDR_SERVER") else {
        return Vec::new();
    };
    let rest = url.split("://").last().unwrap_or_default();
    let authority = rest.split('/').next().unwrap_or_default();
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default().to_string(),
        None => authority
            .rsplit_once(':')
            .map_or(authority, |(h, _)| h)
            .to_string(),
    };
    (host.as_str(), 0)
        .to_socket_addrs()
        .map(|it| it.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

pub fn block(cmd: &Command) -> Outcome {
    let (target, nets) = match parse_target(&cmd.target) {
        Ok(v) => v,
        Err(e) => return Outcome::failed(e),
    };
    if let Err(e) = check(&nets, &protected()) {
        return Outcome::failed(format!("拒绝执行：{e}"));
    }
    let list = nets.iter().map(Net::render).collect::<Vec<_>>().join(", ");
    match platform::add(&target, &nets) {
        Ok(()) => Outcome::ok(format!("已封锁 {target}（{list}）的进出通信{}", platform::save())),
        Err(e) => Outcome::failed(format!("封锁失败：{e}")),
    }
}

pub fn unblock(cmd: &Command) -> Outcome {
    let target = cmd.target.trim().trim_end_matches('.').to_ascii_lowercase();
    // 解除不解析域名，但目标会拼进 nft / PowerShell 脚本，字符集与封锁时一致
    if target.is_empty()
        || target.len() > 253
        || !target
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".:/-".contains(&b))
    {
        return Outcome::failed("解除目标必须是当初封锁时的 IP、网段或域名");
    }
    match platform::remove(&target) {
        Ok(0) => Outcome::ok(format!("{target} 当前未被封锁")),
        Ok(n) => Outcome::ok(format!("已解除 {target} 的封锁（{n} 条规则）{}", platform::save())),
        Err(e) => Outcome::failed(format!("解除封锁失败：{e}")),
    }
}

/// 开机后恢复封锁：内核规则重启即丢，平台却还当它在生效。agent 启动时调用一次
pub fn restore() {
    if let Some(msg) = platform::restore() {
        eprintln!("{msg}");
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::io::Write;
    use std::process::{Command as Proc, Stdio};

    use super::Net;

    const TABLE: &str = "openxdr_block";

    /// 封锁表的落盘副本：nft 的文本格式能原样恢复，元素注释（原始目标）也在里面
    fn saved() -> std::path::PathBuf {
        crate::enroll::default_env_file().with_file_name("netblock.nft")
    }

    /// 每次封锁、解除后把整张表存下来。存不下不影响这次处置，但要在结果里说明重启后不会保留
    pub fn save() -> String {
        let write = || -> Result<(), String> {
            let table = nft(&["list", "table", "inet", TABLE], None)?;
            let path = saved();
            let tmp = path.with_extension("nft.tmp");
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp)
                    .map_err(|e| e.to_string())?;
                f.write_all(table.as_bytes()).map_err(|e| e.to_string())?;
                f.sync_all().map_err(|e| e.to_string())?;
            }
            std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
        };
        match write() {
            Ok(()) => String::new(),
            Err(e) => format!("；规则未能落盘（{e}），主机重启后不会保留"),
        }
    }

    /// 内核里没有封锁表、落盘副本在：原样载入。表已存在（agent 重启而主机没重启）不动它
    pub fn restore() -> Option<String> {
        let path = saved();
        if !path.exists() || nft(&["list", "table", "inet", TABLE], None).is_ok() {
            return None;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => return Some(format!("读不到封锁副本 {}：{e}", path.display())),
        };
        Some(match nft(&["-f", "-"], Some(&text)) {
            Ok(_) => format!("已从 {} 恢复开机前的网络封锁", path.display()),
            Err(e) => format!("恢复网络封锁失败：{e}"),
        })
    }

    /// 表、集合与规则只在表不存在时建一次：nft 的 add rule 会叠加，不能每次都跑
    fn ensure() -> Result<(), String> {
        if nft(&["list", "table", "inet", TABLE], None).is_ok() {
            return Ok(());
        }
        let mut s = format!("add table inet {TABLE}\n");
        for (set, ty) in [("b4", "ipv4_addr"), ("b6", "ipv6_addr")] {
            s += &format!("add set inet {TABLE} {set} {{ type {ty} ; flags interval ; }}\n");
        }
        for (chain, hook, dir) in [("input", "input", "saddr"), ("output", "output", "daddr")] {
            s += &format!(
                "add chain inet {TABLE} {chain} {{ type filter hook {hook} priority -90 ; policy accept ; }}\n"
            );
            s += &format!("add rule inet {TABLE} {chain} ip {dir} @b4 drop\n");
            s += &format!("add rule inet {TABLE} {chain} ip6 {dir} @b6 drop\n");
        }
        nft(&["-f", "-"], Some(&s)).map(|_| ())
    }

    pub fn add(target: &str, nets: &[Net]) -> Result<(), String> {
        ensure()?;
        nft(&["-f", "-"], Some(&elements("add", target, nets))).map(|_| ())
    }

    /// 元素带注释记原始目标：域名解除时按注释找回当初解析出的地址，不重新解析
    pub fn elements(verb: &str, target: &str, nets: &[Net]) -> String {
        nets.iter()
            .map(|n| {
                let set = if n.addr.is_ipv4() { "b4" } else { "b6" };
                format!(
                    "{verb} element inet {TABLE} {set} {{ {} comment \"{target}\" }}\n",
                    n.render()
                )
            })
            .collect()
    }

    pub fn remove(target: &str) -> Result<usize, String> {
        let mut found = Vec::new();
        for set in ["b4", "b6"] {
            let Ok(json) = nft(&["-j", "list", "set", "inet", TABLE, set], None) else {
                continue; // 表或集合不存在：本来就没封锁
            };
            found.extend(matching(&json, target));
        }
        if found.is_empty() {
            return Ok(0);
        }
        let script: String = found
            .iter()
            .map(|n| elements("delete", target, std::slice::from_ref(n)))
            .collect();
        // delete 不认注释，去掉注释子句
        let script = script.replace(&format!(" comment \"{target}\""), "");
        nft(&["-f", "-"], Some(&script))?;
        Ok(found.len())
    }

    /// 从 nft -j 的集合列表里挑出注释等于目标的元素
    pub fn matching(json: &str, target: &str) -> Vec<Net> {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for item in v["nftables"].as_array().into_iter().flatten() {
            for e in item["set"]["elem"].as_array().into_iter().flatten() {
                let elem = &e["elem"];
                if elem["comment"].as_str() != Some(target) {
                    continue;
                }
                let val = &elem["val"];
                let net = match (val.as_str(), val["prefix"]["addr"].as_str()) {
                    (Some(a), _) => a.parse().ok().map(|addr: std::net::IpAddr| Net {
                        prefix: if addr.is_ipv4() { 32 } else { 128 },
                        addr,
                    }),
                    (None, Some(a)) => {
                        a.parse()
                            .ok()
                            .zip(val["prefix"]["len"].as_u64())
                            .map(|(addr, len)| Net {
                                addr,
                                prefix: len as u8,
                            })
                    }
                    _ => None,
                };
                out.extend(net);
            }
        }
        out
    }

    fn nft(args: &[&str], stdin: Option<&str>) -> Result<String, String> {
        let mut child = Proc::new("nft")
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("无法执行 nft（封锁需要 nftables 与 root 权限）: {e}"))?;
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .ok_or("无法写入 nft 标准输入")?
                .write_all(input.as_bytes())
                .map_err(|e| e.to_string())?;
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::Net;

    /// Windows 防火墙规则本身就持久，重启后仍在
    pub fn save() -> String {
        String::new()
    }

    pub fn restore() -> Option<String> {
        None
    }
    use crate::respond::powershell;

    const GROUP: &str = "OpenXDR Block";

    pub fn add(target: &str, nets: &[Net]) -> Result<(), String> {
        // 防火墙没开时规则写进去也不生效，不能报成功
        let off = powershell("(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count")?;
        if off.trim() != "0" {
            return Err("Windows 防火墙有配置文件未启用，封锁规则不会生效".into());
        }
        let list = nets
            .iter()
            .map(|n| format!("'{}'", n.render()))
            .collect::<Vec<_>>()
            .join(",");
        let name = format!("{GROUP} {target}");
        powershell(&format!(
            "Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue; \
             foreach ($d in 'Inbound','Outbound') {{ New-NetFirewallRule -DisplayName '{name}' -Group '{GROUP}' \
             -Direction $d -Action Block -RemoteAddress {list} | Out-Null }}"
        ))
        .map(|_| ())
    }

    pub fn remove(target: &str) -> Result<usize, String> {
        let name = format!("{GROUP} {target}");
        let n = powershell(&format!(
            "$r = @(Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue); \
             $r | Remove-NetFirewallRule; $r.Count"
        ))?;
        Ok(n.trim().parse().unwrap_or(0))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod platform {
    use super::Net;
    pub fn save() -> String {
        String::new()
    }
    pub fn restore() -> Option<String> {
        None
    }
    pub fn add(_: &str, _: &[Net]) -> Result<(), String> {
        Err("本平台不支持网络封锁".into())
    }
    pub fn remove(_: &str) -> Result<usize, String> {
        Err("本平台不支持网络封锁".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_cidr_and_rejects_garbage() {
        assert_eq!(
            parse_target(" 1.2.3.4 ").unwrap().1,
            vec![Net {
                addr: "1.2.3.4".parse().unwrap(),
                prefix: 32
            }]
        );
        assert_eq!(parse_target("10.9.0.0/16").unwrap().1[0].prefix, 16);
        assert_eq!(parse_target("2001:db8::/48").unwrap().1[0].prefix, 48);
        for bad in [
            "",
            "1.2.3.4/33",
            "a b",
            "-x.com",
            "x",
            "1.2.3.4/x",
            "evil\";flush ruleset",
        ] {
            assert!(parse_target(bad).is_err(), "{bad} 应拒绝");
        }
    }

    #[test]
    fn refuses_wide_loopback_and_server() {
        let net = |s: &str| parse_target(s).unwrap().1;
        let server = [("10.1.1.199".parse().unwrap(), "server 地址")];
        assert!(check(&net("10.0.0.0/8"), &server).is_err(), "过宽");
        assert!(check(&net("127.0.0.1"), &server).is_err(), "回环");
        assert!(check(&net("0.0.0.0/16"), &server).is_err(), "未指定");
        assert!(
            check(&net("10.1.0.0/16"), &server)
                .unwrap_err()
                .contains("server")
        );
        assert!(check(&net("10.1.1.199"), &server).is_err());
        assert!(check(&net("45.9.148.0/24"), &server).is_ok());
        assert!(check(&net("2001:db8::/32"), &[]).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nft_elements_and_listing() {
        let nets = parse_target("45.9.148.0/24").unwrap().1;
        assert_eq!(
            platform::elements("add", "45.9.148.0/24", &nets),
            "add element inet openxdr_block b4 { 45.9.148.0/24 comment \"45.9.148.0/24\" }\n"
        );
        let json = r#"{"nftables":[{"metainfo":{}},{"set":{"name":"b4","elem":[
            {"elem":{"val":"1.2.3.4","comment":"c2.example.com"}},
            {"elem":{"val":{"prefix":{"addr":"45.9.148.0","len":24}},"comment":"45.9.148.0/24"}},
            {"elem":{"val":"5.6.7.8","comment":"c2.example.com"}}]}}]}"#;
        assert_eq!(platform::matching(json, "c2.example.com").len(), 2);
        assert_eq!(platform::matching(json, "45.9.148.0/24")[0].prefix, 24);
        assert!(platform::matching(json, "other").is_empty());
    }
}
