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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Net {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Net {
    /// 规范化网段：按前缀长度清零主机位，保证同一网段只有唯一表示
    pub fn canonical(addr: IpAddr, prefix: u8) -> Self {
        let addr = match addr {
            IpAddr::V4(v4) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0)
                };
                IpAddr::V4(std::net::Ipv4Addr::from(u32::from(v4) & mask))
            }
            IpAddr::V6(v6) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0)
                };
                IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & mask))
            }
        };
        Self { addr, prefix }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0)
                };
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0)
                };
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }

    #[cfg(target_os = "linux")]
    fn contains_net(&self, other: &Net) -> bool {
        self.addr.is_ipv4() == other.addr.is_ipv4()
            && self.prefix <= other.prefix
            && self.contains(other.addr)
    }

    pub fn render(&self) -> String {
        format!("{}/{}", self.addr, self.prefix)
    }
}

/// 规范化目标字符串（IP / CIDR / 域名）：IPv6 压缩为 RFC 5952 标准形式，CIDR 清零主机位
fn normalize_target_str(raw: &str) -> Result<String, String> {
    let target = raw.trim().trim_end_matches('.').to_ascii_lowercase();
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
        return Ok(Net::canonical(addr, prefix).render());
    }
    if let Ok(addr) = target.parse::<IpAddr>() {
        return Ok(addr.to_string());
    }
    if !target
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".:/-".contains(&b))
    {
        return Err("目标必须是 IP、网段或域名".into());
    }
    Ok(target)
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
        let net = Net::canonical(addr, prefix);
        return Ok((net.render(), vec![net]));
    }
    if let Ok(addr) = target.parse::<IpAddr>() {
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        return Ok((addr.to_string(), vec![Net::canonical(addr, prefix)]));
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
            Net::canonical(addr, prefix)
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
        Ok(()) => Outcome::ok(format!(
            "已封锁 {target}（{list}）的进出通信{}",
            platform::save()
        )),
        Err(e) => Outcome::failed(format!("封锁失败：{e}")),
    }
}

pub fn unblock(cmd: &Command) -> Outcome {
    // 解除不解析域名，但做与封锁一致的 IP/IPv6/CIDR 规范化与字符集校验
    let target = match normalize_target_str(&cmd.target) {
        Ok(t) => t,
        Err(_) => return Outcome::failed("解除目标必须是当初封锁时的 IP、网段或域名"),
    };
    match platform::remove(&target) {
        Ok(0) => Outcome::ok(format!("{target} 当前未被封锁")),
        Ok(n) => Outcome::ok(format!(
            "已解除 {target} 的封锁（{n} 条规则）{}",
            platform::save()
        )),
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
    /// nftables 内核集合元素 comment 最大长度（字节）
    const MAX_NFT_COMMENT: usize = 128;

    /// 集合中的一条规范化元素：网段 + 关联到它的所有 `(规范目标, 原始网段)` 归属
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Entry {
        pub net: Net,
        pub owners: Vec<(String, Net)>,
    }

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
            Ok(_) => {
                // 老副本可能缺少 forward 链，顺手补齐
                let _ = ensure();
                format!("已从 {} 恢复开机前的网络封锁", path.display())
            }
            Err(e) => format!("恢复网络封锁失败：{e}"),
        })
    }

    /// 仅用于初始化新表（含 input / output / forward 三条链）
    pub fn init_table_script() -> String {
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
        s += &forward_chain_script();
        s
    }

    /// 转发链：同时拦截宿主机网桥转发的容器/VM 进出被封地址流量
    pub fn forward_chain_script() -> String {
        let mut s = format!(
            "add chain inet {TABLE} forward {{ type filter hook forward priority -90 ; policy accept ; }}\n"
        );
        s += &format!("add rule inet {TABLE} forward ip saddr @b4 drop\n");
        s += &format!("add rule inet {TABLE} forward ip daddr @b4 drop\n");
        s += &format!("add rule inet {TABLE} forward ip6 saddr @b6 drop\n");
        s += &format!("add rule inet {TABLE} forward ip6 daddr @b6 drop\n");
        s
    }

    /// 表、集合与规则只在表不存在时建一次：nft 的 add rule 会叠加，不能每次都跑；
    /// 已存在的老表若缺少 forward 链，则平滑补建一次
    fn ensure() -> Result<(), String> {
        if let Ok(existing) = nft(&["list", "table", "inet", TABLE], None) {
            if !existing.contains("chain forward") {
                nft(&["-f", "-"], Some(&forward_chain_script()))?;
            }
            return Ok(());
        }
        nft(&["-f", "-"], Some(&init_table_script())).map(|_| ())
    }

    pub fn add(target: &str, nets: &[Net]) -> Result<(), String> {
        ensure()?;
        let mut script = String::new();
        for (set, is_v4) in [("b4", true), ("b6", false)] {
            let subset: Vec<Net> = nets
                .iter()
                .filter(|n| n.addr.is_ipv4() == is_v4)
                .cloned()
                .collect();
            if subset.is_empty() {
                continue;
            }
            let existing = nft(&["-j", "list", "set", "inet", TABLE, set], None)
                .map(|j| parse_entries(&j))
                .unwrap_or_default();
            script.push_str(&plan_add(set, &existing, target, &subset)?);
        }
        if script.is_empty() {
            return Ok(());
        }
        nft(&["-f", "-"], Some(&script)).map(|_| ())
    }

    /// 把一组 `(target, net)` 归并为互不重叠的最小覆盖集合元素（宽网段优先吸收窄网段与同 IP 多目标）
    pub fn reconcile(mut owners: Vec<(String, Net)>) -> Vec<Entry> {
        owners.sort_by(|a, b| {
            a.1.prefix
                .cmp(&b.1.prefix)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.0.cmp(&b.0))
        });
        owners.dedup();
        let mut entries: Vec<Entry> = Vec::new();
        for (target, net) in owners {
            if let Some(existing) = entries.iter_mut().find(|e| e.net.contains_net(&net)) {
                existing.owners.push((target, net));
            } else {
                entries.push(Entry {
                    net: net.clone(),
                    owners: vec![(target, net)],
                });
            }
        }
        for e in &mut entries {
            e.owners.sort();
            e.owners.dedup();
        }
        entries
    }

    /// 编码集合元素注释：与元素网段一致的直接写目标名，被超网吸收的窄网段写 `目标=原始网段`
    pub fn encode_comment(elem_net: &Net, owners: &[(String, Net)]) -> Result<String, String> {
        let mut items: Vec<String> = owners
            .iter()
            .map(|(t, n)| {
                if n == elem_net {
                    t.clone()
                } else {
                    format!("{t}={}", n.render())
                }
            })
            .collect();
        items.sort();
        items.dedup();
        let comment = items.join(",");
        if comment.len() > MAX_NFT_COMMENT {
            return Err(format!(
                "同一网段 {} 关联的目标过多，注释超出 nftables {MAX_NFT_COMMENT} 字节上限",
                elem_net.render()
            ));
        }
        Ok(comment)
    }

    /// 解析集合元素注释（兼容单目标旧格式、逗号分隔多目标与 `目标=网段` 重叠格式，同时规范化目标名）
    pub fn decode_comment(elem_net: &Net, comment: &str) -> Vec<(String, Net)> {
        let mut out = Vec::new();
        for part in comment.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (raw_target, net) = match part.split_once('=') {
                Some((t, n_str)) => {
                    let parsed = n_str
                        .split_once('/')
                        .and_then(|(a, p)| {
                            let addr: std::net::IpAddr = a.parse().ok()?;
                            let prefix: u8 = p.parse().ok()?;
                            let max = if addr.is_ipv4() { 32 } else { 128 };
                            (prefix <= max).then(|| Net::canonical(addr, prefix))
                        })
                        .unwrap_or_else(|| elem_net.clone());
                    (t, parsed)
                }
                None => (part, elem_net.clone()),
            };
            let target = super::normalize_target_str(raw_target)
                .unwrap_or_else(|_| raw_target.to_ascii_lowercase());
            out.push((target, net));
        }
        out
    }

    /// 按前后元素集差异生成单事务 nft 增量脚本（先 delete 变动旧项，再 add 变动新项）
    fn diff_script(set: &str, old: &[Entry], new: &[Entry]) -> Result<String, String> {
        let encode_all = |list: &[Entry]| -> Result<Vec<(Net, String)>, String> {
            list.iter()
                .map(|e| Ok((e.net.clone(), encode_comment(&e.net, &e.owners)?)))
                .collect()
        };
        let old_enc = encode_all(old)?;
        let new_enc = encode_all(new)?;

        let mut script = String::new();
        for (net, comment) in &old_enc {
            if !new_enc.iter().any(|(n, c)| n == net && c == comment) {
                script.push_str(&format!(
                    "delete element inet {TABLE} {set} {{ {} }}\n",
                    net.render()
                ));
            }
        }
        for (net, comment) in &new_enc {
            if !old_enc.iter().any(|(n, c)| n == net && c == comment) {
                script.push_str(&format!(
                    "add element inet {TABLE} {set} {{ {} comment \"{comment}\" }}\n",
                    net.render()
                ));
            }
        }
        Ok(script)
    }

    /// 计算新增封锁目标后的单事务 nft 脚本，自动合并同 IP 多目标与重叠 CIDR，避免 interval 冲突或注释覆盖
    pub fn plan_add(
        set: &str,
        existing: &[Entry],
        target: &str,
        nets: &[Net],
    ) -> Result<String, String> {
        let mut owners: Vec<(String, Net)> = existing
            .iter()
            .flat_map(|e| e.owners.iter().cloned())
            .collect();
        for n in nets {
            owners.push((target.to_string(), n.clone()));
        }
        let next = reconcile(owners);
        diff_script(set, existing, &next)
    }

    /// 计算解除封锁目标后的单事务 nft 脚本及受影响的引用条数；仍有其他目标引用时不误解封
    pub fn plan_remove(
        set: &str,
        existing: &[Entry],
        target: &str,
    ) -> Result<(String, usize), String> {
        let mut removed = 0usize;
        let mut kept: Vec<(String, Net)> = Vec::new();
        for e in existing {
            for (t, n) in &e.owners {
                if t == target {
                    removed += 1;
                } else {
                    kept.push((t.clone(), n.clone()));
                }
            }
        }
        if removed == 0 {
            return Ok((String::new(), 0));
        }
        let next = reconcile(kept);
        let script = diff_script(set, existing, &next)?;
        Ok((script, removed))
    }

    pub fn remove(target: &str) -> Result<usize, String> {
        let mut script = String::new();
        let mut total_removed = 0usize;
        for set in ["b4", "b6"] {
            let Ok(json) = nft(&["-j", "list", "set", "inet", TABLE, set], None) else {
                continue; // 表或集合不存在：本来就没封锁
            };
            let existing = parse_entries(&json);
            let (part, n) = plan_remove(set, &existing, target)?;
            script.push_str(&part);
            total_removed += n;
        }
        if total_removed == 0 {
            return Ok(0);
        }
        if !script.is_empty() {
            nft(&["-f", "-"], Some(&script))?;
        }
        Ok(total_removed)
    }

    /// 从 nft -j 的集合列表解析全部元素及其归属目标
    pub fn parse_entries(json: &str) -> Vec<Entry> {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for item in v["nftables"].as_array().into_iter().flatten() {
            for e in item["set"]["elem"].as_array().into_iter().flatten() {
                let elem = &e["elem"];
                let val = &elem["val"];
                let net = match (val.as_str(), val["prefix"]["addr"].as_str()) {
                    (Some(a), _) => a.parse().ok().map(|addr: std::net::IpAddr| {
                        let prefix = if addr.is_ipv4() { 32 } else { 128 };
                        Net::canonical(addr, prefix)
                    }),
                    (None, Some(a)) => a.parse().ok().zip(val["prefix"]["len"].as_u64()).and_then(
                        |(addr, len): (std::net::IpAddr, u64)| {
                            let max = if addr.is_ipv4() { 32 } else { 128 };
                            (len <= max as u64).then(|| Net::canonical(addr, len as u8))
                        },
                    ),
                    _ => None,
                };
                let Some(net) = net else {
                    continue;
                };
                let owners = elem["comment"]
                    .as_str()
                    .map(|c| decode_comment(&net, c))
                    .unwrap_or_default();
                out.push(Entry { net, owners });
            }
        }
        out
    }

    /// 元素带注释记原始目标：保留给单测及格式化展示
    #[cfg(test)]
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

    /// 从 nft -j 的集合列表里挑出注释包含目标的元素
    #[cfg(test)]
    pub fn matching(json: &str, target: &str) -> Vec<Net> {
        let norm = super::normalize_target_str(target).unwrap_or_else(|_| target.to_string());
        parse_entries(json)
            .into_iter()
            .filter(|e| e.owners.iter().any(|(t, _)| t == &norm))
            .map(|e| e.net)
            .collect()
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

    #[test]
    fn canonicalizes_ipv6_and_cidr_for_block_and_unblock() {
        let (target, nets) = parse_target("2001:0DB8:0000::0001").unwrap();
        assert_eq!(target, "2001:db8::1");
        assert_eq!(nets[0].render(), "2001:db8::1/128");
        assert_eq!(normalize_target_str("2001:0db8::1").unwrap(), "2001:db8::1");
        assert_eq!(normalize_target_str("2001:db8::1").unwrap(), "2001:db8::1");

        // 非零主机位的 CIDR 会清零主机位，封锁与解封口径一致
        let (cidr_t, cidr_n) = parse_target("2001:0db8::abcd/48").unwrap();
        assert_eq!(cidr_t, "2001:db8::/48");
        assert_eq!(cidr_n[0].render(), "2001:db8::/48");
        assert_eq!(
            normalize_target_str("2001:0DB8::1/48").unwrap(),
            "2001:db8::/48"
        );
        let (v4_t, v4_n) = parse_target("45.9.148.99/24").unwrap();
        assert_eq!(v4_t, "45.9.148.0/24");
        assert_eq!(v4_n[0].render(), "45.9.148.0/24");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn init_table_includes_forward_chain_for_containers_and_vms() {
        let s = platform::init_table_script();
        assert!(s.contains(
            "add chain inet openxdr_block forward { type filter hook forward priority -90 ; policy accept ; }"
        ));
        assert!(s.contains("add rule inet openxdr_block forward ip saddr @b4 drop"));
        assert!(s.contains("add rule inet openxdr_block forward ip daddr @b4 drop"));
        assert!(s.contains("add rule inet openxdr_block forward ip6 saddr @b6 drop"));
        assert!(s.contains("add rule inet openxdr_block forward ip6 daddr @b6 drop"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shared_ip_and_overlapping_cidr_comments_do_not_clobber_or_misunblock() {
        let ip_net = parse_target("1.2.3.4").unwrap().1[0].clone();
        let cidr_net = parse_target("1.2.3.0/24").unwrap().1[0].clone();

        // 1) a.example.com 与 b.example.com 指向同一 IP
        let s1 =
            platform::plan_add("b4", &[], "a.example.com", std::slice::from_ref(&ip_net)).unwrap();
        assert_eq!(
            s1,
            "add element inet openxdr_block b4 { 1.2.3.4/32 comment \"a.example.com\" }\n"
        );
        let after_a = platform::reconcile(vec![("a.example.com".into(), ip_net.clone())]);

        let s2 = platform::plan_add(
            "b4",
            &after_a,
            "b.example.com",
            std::slice::from_ref(&ip_net),
        )
        .unwrap();
        assert!(s2.contains("delete element inet openxdr_block b4 { 1.2.3.4/32 }\n"));
        assert!(s2.contains(
            "add element inet openxdr_block b4 { 1.2.3.4/32 comment \"a.example.com,b.example.com\" }\n"
        ));
        let after_ab = platform::reconcile(vec![
            ("a.example.com".into(), ip_net.clone()),
            ("b.example.com".into(), ip_net.clone()),
        ]);

        // 解封 a.example.com：b.example.com 仍引用该 IP，保留封锁并更新注释
        let (rem_a, n_a) = platform::plan_remove("b4", &after_ab, "a.example.com").unwrap();
        assert_eq!(n_a, 1);
        assert!(rem_a.contains("delete element inet openxdr_block b4 { 1.2.3.4/32 }\n"));
        assert!(rem_a.contains(
            "add element inet openxdr_block b4 { 1.2.3.4/32 comment \"b.example.com\" }\n"
        ));

        // 2) 重叠 CIDR：已有 1.2.3.4/32，再封 1.2.3.0/24，合并为超网并保留原目标记录
        let s_overlap = platform::plan_add(
            "b4",
            &after_a,
            "1.2.3.0/24",
            std::slice::from_ref(&cidr_net),
        )
        .unwrap();
        assert!(s_overlap.contains("delete element inet openxdr_block b4 { 1.2.3.4/32 }\n"));
        assert!(s_overlap.contains(
            "add element inet openxdr_block b4 { 1.2.3.0/24 comment \"1.2.3.0/24,a.example.com=1.2.3.4/32\" }\n"
        ));

        // 从 nft -j 解析合并后的元素，再解封 1.2.3.0/24：应精准恢复 a.example.com 的 1.2.3.4/32
        let json = r#"{"nftables":[{"set":{"name":"b4","elem":[
            {"elem":{"val":{"prefix":{"addr":"1.2.3.0","len":24}},"comment":"1.2.3.0/24,a.example.com=1.2.3.4/32"}}
        ]}}]}"#;
        let parsed = platform::parse_entries(json);
        let (rem_cidr, n_cidr) = platform::plan_remove("b4", &parsed, "1.2.3.0/24").unwrap();
        assert_eq!(n_cidr, 1);
        assert!(rem_cidr.contains("delete element inet openxdr_block b4 { 1.2.3.0/24 }\n"));
        assert!(rem_cidr.contains(
            "add element inet openxdr_block b4 { 1.2.3.4/32 comment \"a.example.com\" }\n"
        ));

        // 兼容旧的非规范 IPv6 comment 也能被规范目标匹配解封
        let v6_json = r#"{"nftables":[{"set":{"name":"b6","elem":[
            {"elem":{"val":"2001:db8::1","comment":"2001:0db8::1"}}
        ]}}]}"#;
        let v6_entries = platform::parse_entries(v6_json);
        let (rem_v6, n_v6) = platform::plan_remove("b6", &v6_entries, "2001:db8::1").unwrap();
        assert_eq!(n_v6, 1);
        assert_eq!(
            rem_v6,
            "delete element inet openxdr_block b6 { 2001:db8::1/128 }\n"
        );
    }
}
