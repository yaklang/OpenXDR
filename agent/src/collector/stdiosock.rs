//! 标准输入输出被接到网络连接上：dup / dup2 / dup3 把一个 TCP 套接字复制到 0、1、2 号描述符，
//! 是反弹 shell 的本质动作——`bash -i >& /dev/tcp/…`、python 的 os.dup2、`nc -e` 都绕不开它。
//! 内核侧只报「哪个进程的 0~2 号描述符刚被 dup 覆盖」，这里核对它现在是不是 TCP 套接字、连着谁。
//! 套接字表读进程自己的 /proc/<pid>/net：容器有自己的网络命名空间，读宿主机的表找不到它的连接。

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub struct Socket {
    pub inode: u64,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// pid 的 fd 号描述符现在是不是一条已连接的 TCP 套接字。监听套接字（inetd 的 wait 型服务把它放在 0 号）、
/// unix 套接字（systemd 把服务的输出接到 journald）、回环连接都不算
pub fn connected_tcp(pid: u32, fd: u32) -> Option<Socket> {
    let link = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    let inode = socket_inode(link.to_str()?)?;
    ["tcp", "tcp6"].into_iter().find_map(|table| {
        let text = std::fs::read_to_string(format!("/proc/{pid}/net/{table}")).ok()?;
        find(&text, inode).filter(|s| !s.remote.ip().is_loopback())
    })
}

fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// /proc/net/tcp(6) 每行：序号 本端 对端 状态 … inode（第 10 列）。0A 是 LISTEN
fn find(table: &str, inode: u64) -> Option<Socket> {
    table.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 || f[9].parse::<u64>().ok()? != inode || f[3] == "0A" {
            return None;
        }
        Some(Socket {
            inode,
            local: addr(f[1])?,
            remote: addr(f[2])?,
        })
    })
}

/// 地址按内核原样打印：每 32 位一组、以本机字节序写成十六进制；端口是普通十六进制
fn addr(s: &str) -> Option<SocketAddr> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        Some(
            u32::from_str_radix(ip.get(i * 8..i * 8 + 8)?, 16)
                .ok()?
                .to_ne_bytes(),
        )
    };
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            Ipv6Addr::from(b).to_canonical()
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// 一个进程把同一条套接字依次 dup 到 0、1、2，只报第一次
#[derive(Default)]
pub struct Seen(HashSet<(u32, u64)>);

impl Seen {
    pub fn first(&mut self, pid: u32, inode: u64) -> bool {
        if self.0.len() >= 4096 {
            self.0.clear();
        }
        self.0.insert((pid, inode))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_tcp() {
        let v4 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0000000000000000 100 0 0 10 0
   1: 0F02000A:C350 2A00000A:115C 01 00000000:00000000 00:00000000 00000000     0        0 2222 1 0000000000000000 20 4 30 10 -1";
        let s = find(v4, 2222).unwrap();
        assert_eq!(s.inode, 2222);
        assert_eq!(s.local, "10.0.2.15:50000".parse().unwrap());
        assert_eq!(s.remote, "10.0.0.42:4444".parse().unwrap());
        assert!(find(v4, 1111).is_none(), "监听套接字不算");
        assert!(find(v4, 3333).is_none());
    }

    #[test]
    fn ipv4_mapped_ipv6_turns_back_into_ipv4() {
        let v6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000F02000A:C350 0000000000000000FFFF00002A00000A:115C 01 00000000:00000000 00:00000000 00000000     0        0 4444 1";
        let s = find(v6, 4444).unwrap();
        assert_eq!(s.remote, "10.0.0.42:4444".parse().unwrap());
    }

    #[test]
    fn only_socket_links_have_inodes() {
        assert_eq!(socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(socket_inode("pipe:[12345]"), None);
        assert_eq!(socket_inode("/dev/pts/0"), None);
    }

    #[test]
    fn real_socket_on_stdio_is_found() {
        use std::os::fd::AsRawFd;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        // 回环连接本来就不报：直接查表验证解析，再验证 connected_tcp 把它过滤掉
        let fd = client.as_raw_fd() as u32;
        let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
        let inode = socket_inode(link.to_str().unwrap()).unwrap();
        let table = std::fs::read_to_string("/proc/self/net/tcp").unwrap();
        let s = find(&table, inode).unwrap();
        assert_eq!(s.remote, listener.local_addr().unwrap());
        assert!(
            connected_tcp(std::process::id(), fd).is_none(),
            "回环连接不报"
        );
    }

    #[test]
    fn same_socket_reported_once_per_process() {
        let mut seen = Seen::default();
        assert!(seen.first(10, 7));
        assert!(!seen.first(10, 7));
        assert!(seen.first(11, 7));
    }
}
