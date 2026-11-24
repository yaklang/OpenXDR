//! Linux 监听表：解析 /proc/net/{tcp,tcp6,udp,udp6}，按套接字 inode 扫
//! /proc/[pid]/fd 归属进程。
//!
//! 注意 /proc/net/* 反映的是 agent 自身所在的网络命名空间：agent 跑在
//! 容器里（非 host 网络）时只看得到容器内的监听，宿主机与其他容器的看不到。
//!
//! fd 扫描在繁忙主机上很贵（每个进程每个 fd 一次 readlink），所以只在
//! (协议, 地址, 端口, inode) 集合与上一轮不同时才扫，否则沿用上一轮的归属。

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::EventSink;
use super::inventory::{self, Listener, Owner, Proto};

/// TCP_LISTEN
const TCP_LISTEN: &str = "0A";
/// TCP_CLOSE：未 connect 的 UDP 套接字
const UDP_UNCONNECTED: &str = "07";

/// 读不到 ip_local_port_range 时的临时端口下界（内核默认）
const DEFAULT_EPHEMERAL_LOW: u16 = 32768;

/// /proc/net/* 中的一条套接字
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Socket {
    proto: Proto,
    addr: IpAddr,
    port: u16,
    inode: u64,
}

pub fn spawn(agent_id: String, sink: EventSink) {
    let mut scanner = Scanner::default();
    inventory::spawn(agent_id, sink, move || scanner.scan_checked());
}

/// 监听表扫描：资产清单定时用，入站连接按本机端口找服务进程也用（linux.rs）
#[derive(Default)]
pub(super) struct Scanner {
    prev: BTreeSet<Socket>,
    owners: HashMap<u64, Owner>,
}

impl Scanner {
    #[cfg(feature = "ebpf")]
    pub(super) fn scan(&mut self) -> Vec<Listener> {
        self.scan_checked().unwrap_or_default()
    }

    fn scan_checked(&mut self) -> std::io::Result<Vec<Listener>> {
        self.scan_with(|path| std::fs::read_to_string(path))
    }

    fn scan_with(
        &mut self,
        mut read: impl FnMut(&str) -> std::io::Result<String>,
    ) -> std::io::Result<Vec<Listener>> {
        let low = ephemeral_low();
        let mut cur = BTreeSet::new();
        for (file, proto, optional) in [
            ("/proc/net/tcp", Proto::Tcp, false),
            ("/proc/net/tcp6", Proto::Tcp, true),
            ("/proc/net/udp", Proto::Udp, false),
            ("/proc/net/udp6", Proto::Udp, true),
        ] {
            let text = match read(file) {
                Ok(text) => text,
                Err(e) if optional && e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            cur.extend(parse_proc_net(&text, proto, low));
        }
        if cur != self.prev {
            let inodes = cur.iter().map(|s| s.inode).filter(|&i| i != 0).collect();
            self.owners = attribute(&inodes);
            self.prev = cur;
        }
        Ok(self
            .prev
            .iter()
            .map(|s| Listener {
                proto: s.proto,
                addr: s.addr,
                port: s.port,
                owner: self.owners.get(&s.inode).cloned(),
            })
            .collect())
    }
}

/// 临时端口下界：/proc/sys/net/ipv4/ip_local_port_range 首列
fn ephemeral_low() -> u16 {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(DEFAULT_EPHEMERAL_LOW)
}

/// 解析一份 /proc/net/{tcp,udp}[6]。TCP 只要 LISTEN；UDP 只要未 connect
/// （状态 07 且对端全零）、本地端口低于临时端口区间的——客户端随手开的 UDP
/// 套接字落在临时端口区间，不算对外服务。
fn parse_proc_net(text: &str, proto: Proto, ephemeral_low: u16) -> Vec<Socket> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            // sl local rem st tx:rx tr:tm retrnsmt uid timeout inode ...
            let f: Vec<&str> = line.split_whitespace().collect();
            let (local, remote, state, inode) = (f.get(1)?, f.get(2)?, f.get(3)?, f.get(9)?);
            let wanted = match proto {
                Proto::Tcp => *state == TCP_LISTEN,
                Proto::Udp => {
                    *state == UDP_UNCONNECTED && remote.bytes().all(|b| matches!(b, b'0' | b':'))
                }
            };
            if !wanted {
                return None;
            }
            let (addr, port) = parse_endpoint(local)?;
            if proto == Proto::Udp && port >= ephemeral_low {
                return None;
            }
            Some(Socket {
                proto,
                addr,
                port,
                inode: inode.parse().ok()?,
            })
        })
        .collect()
}

/// "ADDR:PORT"，ADDR 是 8 位（v4）或 32 位（v6）十六进制。
/// 内核按 32 位字逐个以主机字节序 %08X 打印网络序地址，所以每个字解析成
/// u32 后取 to_ne_bytes 就是原始网络序字节；端口则是主机序数值直接打印。
fn parse_endpoint(s: &str) -> Option<(IpAddr, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        let w = addr_hex.get(i * 8..i * 8 + 8)?;
        Some(u32::from_str_radix(w, 16).ok()?.to_ne_bytes())
    };
    let addr = match addr_hex.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some((addr, port))
}

/// 扫 /proc/[pid]/fd 找持有这些 inode 的进程。同一套接字被多个进程持有
/// （fork 出的 worker 继承监听 fd）时取最小 pid，通常就是主进程。
/// 进程名读不到就不归属——不编造。
fn attribute(inodes: &BTreeSet<u64>) -> HashMap<u64, Owner> {
    let mut pids: HashMap<u64, u32> = HashMap::new();
    if inodes.is_empty() {
        return HashMap::new();
    }
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return HashMap::new();
    };
    for pid in procs
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
    {
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Some(inode) = std::fs::read_link(fd.path())
                .ok()
                .and_then(|t| socket_inode(t.to_str()?))
            else {
                continue;
            };
            if inodes.contains(&inode) {
                let slot = pids.entry(inode).or_insert(pid);
                *slot = (*slot).min(pid);
            }
        }
    }
    pids.into_iter()
        .filter_map(|(inode, pid)| Some((inode, owner_of(pid)?)))
        .collect()
}

/// fd 链接目标 "socket:[12345]" → 12345
fn socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn owner_of(pid: u32) -> Option<Owner> {
    let name = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = name.trim_end().to_string();
    if name.is_empty() {
        return None;
    }
    let path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    Some(Owner { pid, name, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> (String, u16) {
        let (a, p) = parse_endpoint(s).unwrap();
        (a.to_string(), p)
    }

    #[test]
    fn endpoint_byte_order() {
        assert_eq!(ep("0100007F:0035"), ("127.0.0.1".into(), 53));
        assert_eq!(ep("00000000:0016"), ("0.0.0.0".into(), 22));
        assert_eq!(ep("FEFFFF0A:0035"), ("10.255.255.254".into(), 53));
        assert_eq!(
            ep("00000000000000000000000001000000:0277"),
            ("::1".into(), 631)
        );
        assert_eq!(
            ep("00000000000000000000000000000000:0050"),
            ("::".into(), 80)
        );
        assert_eq!(
            ep("000080FE00000000FF005450B6AD1DFE:0016"),
            ("fe80::5054:ff:fe1d:adb6".into(), 22)
        );
        // v4 映射的 v6 地址保持 v6 文本
        assert_eq!(
            ep("0000000000000000FFFF00000100007F:1F90"),
            ("::ffff:127.0.0.1".into(), 8080)
        );
        assert!(parse_endpoint("0100007F").is_none());
        assert!(parse_endpoint("0100:0035").is_none());
        assert!(parse_endpoint("ZZZZZZZZ:0035").is_none());
    }

    #[test]
    fn failed_table_read_preserves_previous_inventory() {
        let mut scanner = Scanner::default();
        let first = scanner.scan_with(|_| Ok(TCP.into())).unwrap();
        assert!(!first.is_empty());
        let previous = scanner.prev.clone();
        assert!(
            scanner
                .scan_with(|path| if path.ends_with("udp") {
                    Err(std::io::ErrorKind::PermissionDenied.into())
                } else {
                    Ok("header\n".into())
                })
                .is_err()
        );
        assert_eq!(scanner.prev, previous);
        assert!(
            scanner
                .scan_with(|_| Ok("header\n".into()))
                .unwrap()
                .is_empty()
        );
    }

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2597 1 0000000000000000 100 0 0 10 0
   1: 0100007F:B4E7 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 14223 1 0000000000000000 100 0 0 10 0
   2: 7E784F64:0016 0A01A8C0:D431 01 00000000:00000000 02:000A7E1C 00000000     0        0 88123 4 0000000000000000 20 4 30 10 -1
";

    const UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 10034: FEFFFF0A:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12297 2 0000000000000000 0
  232: 7E784F64:D9EB 64646464:0035 01 00000000:00000000 00:00000000 00000000   108        0 18844 2 0000000000000000 0
 51622: 00000000:A2A9 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 7484959 2 0000000000000000 0
 10304: 0100007F:0143 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 9222 2 0000000000000000 0
";

    const UDP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
10304: 00000000000000000000000001000000:0143 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 9223 2 0000000000000000 0
";

    #[test]
    fn tcp_only_listen() {
        let s = parse_proc_net(TCP, Proto::Tcp, 32768);
        let got: Vec<_> = s
            .iter()
            .map(|x| (x.addr.to_string(), x.port, x.inode))
            .collect();
        assert_eq!(
            got,
            [
                ("0.0.0.0".to_string(), 22, 2597),
                ("127.0.0.1".to_string(), 46311, 14223),
            ],
            "ESTABLISHED 不算监听；TCP 不按临时端口过滤"
        );
    }

    #[test]
    fn udp_unconnected_below_ephemeral() {
        let s = parse_proc_net(UDP, Proto::Udp, 32768);
        let got: Vec<_> = s.iter().map(|x| (x.addr.to_string(), x.port)).collect();
        assert_eq!(
            got,
            [
                ("10.255.255.254".to_string(), 53),
                ("127.0.0.1".to_string(), 323)
            ],
            "已 connect 的与临时端口区间的都不要"
        );
        // 临时端口下界调低后 323 也落进区间
        assert_eq!(parse_proc_net(UDP, Proto::Udp, 300).len(), 1);

        let s = parse_proc_net(UDP6, Proto::Udp, 32768);
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].addr.to_string(), s[0].port), ("::1".to_string(), 323));
    }

    #[test]
    fn socket_link_target() {
        assert_eq!(socket_inode("socket:[2597]"), Some(2597));
        assert_eq!(socket_inode("pipe:[2597]"), None);
        assert_eq!(socket_inode("/dev/null"), None);
        assert_eq!(socket_inode("socket:[x]"), None);
    }

    #[test]
    fn ipv6_not_found_is_optional_while_ipv4_and_other_errors_fail() {
        let mut scanner = Scanner::default();
        // 禁用 IPv6 的内核没有 /proc/net/tcp6 与 /proc/net/udp6：仍应返回 IPv4 监听
        let got = scanner
            .scan_with(|path| match path {
                "/proc/net/tcp" => Ok(TCP.into()),
                "/proc/net/udp" => Ok(UDP.into()),
                "/proc/net/tcp6" | "/proc/net/udp6" => Err(std::io::ErrorKind::NotFound.into()),
                other => panic!("unexpected path: {other}"),
            })
            .unwrap();
        assert_eq!(got.len(), 4);
        assert!(
            got.iter()
                .any(|l| l.proto == Proto::Tcp && l.port == 22 && l.addr.is_ipv4())
        );
        assert!(
            got.iter()
                .any(|l| l.proto == Proto::Udp && l.port == 53 && l.addr.is_ipv4())
        );

        // IPv6 表的非 NotFound 错误仍应向上传播
        assert!(
            scanner
                .scan_with(|path| match path {
                    "/proc/net/tcp6" => Err(std::io::ErrorKind::PermissionDenied.into()),
                    _ => Ok("header\n".into()),
                })
                .is_err()
        );

        // IPv4 表缺失仍应报错
        assert!(
            scanner
                .scan_with(|path| match path {
                    "/proc/net/tcp" => Err(std::io::ErrorKind::NotFound.into()),
                    _ => Ok("header\n".into()),
                })
                .is_err()
        );
    }
}
