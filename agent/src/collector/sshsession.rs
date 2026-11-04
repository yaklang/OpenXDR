//! SSH 登录会话归属（Linux）：把 sshd 认证成功时的登录事实（用户、来源地址、公钥指纹）
//! 挂到这次登录之后拉起的每个进程上，server 据此认「可信自动化来源」。
//!
//! 关联靠内核的审计会话号（/proc/<pid>/sessionid）：sshd 打开 PAM 会话时 pam_loginuid
//! 写 loginuid，内核随之分配一个本次开机内单调递增、不复用的会话号，之后整个会话的进程
//! （包括 setsid、nohup、sudo 拉起的）都继承它。非 root 改不了；root 重写 loginuid 也只会
//! 拿到一个新号，挤不进已有会话。会话号与登录事实之间的桥是 sshd 特权监控进程的 pid：
//! 认证日志由它写出（journald 记下的 _PID/_UID/_COMM 是内核凭据，客户端伪造不了），
//! 会话打开后它的会话号就是整个会话的会话号。
//!
//! 认不出就不标：没有 pam_loginuid（会话号一直未设置）、容器里的 sshd（宿主机读不到
//! 容器的 journal，非特权容器也没有审计会话号）、日志晚于会话首个进程到达，都只是不打标，
//! 告警照常——失败方向是多告警，不是漏告警。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 内核表示「未设置」的会话号
const UNSET: u32 = u32::MAX;
/// 认证成功后等 PAM 会话打开的时限；过了还没对上，多半是这台机器没有 pam_loginuid
const PENDING_TTL: Duration = Duration::from_secs(60);
/// netlink/eBPF 捕获 sshd 子进程往往比 journalctl -f 收到 Accepted 日志早 150~500ms（实测冷启动/落盘合并可达 484ms）；
/// 对确认有 sshd 祖先的新会话号最多等 1s（50 × 20ms），每个会话号只等一次
const JOURNAL_WAIT_STEP: Duration = Duration::from_millis(20);
const JOURNAL_WAIT_STEPS: usize = 50;
/// 记住的会话上限。会话号单调递增，超限时丢最早的
const MAX_SESSIONS: usize = 4096;
const MAX_PENDING: usize = 1024;

/// 一次 SSH 登录的事实，全部取自 sshd 自己写的认证日志
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    pub user: String,
    pub src_ip: String,
    pub src_port: Option<u16>,
    /// publickey / password / keyboard-interactive/pam ……
    pub method: String,
    /// 只有 publickey 认证才有：ED25519、RSA、ED25519-CERT ……
    pub key_type: Option<String>,
    /// SHA256:<base64>，与 ssh-keygen -lf 的输出同一写法
    pub key_fp: Option<String>,
}

impl Login {
    /// 事件体里的 login_session 对象。session 为空时（认证事件本身）不写 uid
    pub fn to_json(&self, session: Option<u32>) -> serde_json::Value {
        let mut v = serde_json::json!({
            "user": self.user,
            "src_ip": self.src_ip,
            "auth_method": self.method,
        });
        if let Some(s) = session {
            v["uid"] = s.to_string().into();
        }
        if let Some(p) = self.src_port {
            v["src_port"] = p.into();
        }
        if let Some(t) = &self.key_type {
            v["key_type"] = t.as_str().into();
        }
        if let Some(fp) = &self.key_fp {
            v["key_fp"] = fp.as_str().into();
        }
        v
    }
}

/// 已对上会话号的登录：进程事件里原样带出去的 login_session 对象，绑定时算好
pub type Bound = Arc<serde_json::Value>;

/// 进程在 /proc 里的两个事实：审计会话号与启动时刻（stat 第 22 列，开机后的时钟滴答数）。
/// 启动时刻用来认出 pid 复用——监控进程退出后 pid 被别的进程占了，不能把那个进程的会话认成这次登录
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proc {
    pub session: u32,
    pub start: u64,
}

struct Pending {
    login: Login,
    start: u64,
    at: Instant,
}

#[derive(Default)]
struct State {
    /// 认证成功、会话号还没对上的 sshd 监控进程
    pending: HashMap<u32, Pending>,
    sessions: BTreeMap<u32, Bound>,
    /// 已检查过祖先或已等待过 journal 的会话号，避免非 SSH 会话或超时会话重复读 /proc 祖先链与等待
    checked: BTreeSet<u32>,
}

impl State {
    fn accepted(&mut self, pid: u32, start: u64, login: Login, now: Instant) {
        self.pending
            .retain(|_, p| now.duration_since(p.at) < PENDING_TTL);
        if self.pending.len() >= MAX_PENDING {
            return;
        }
        self.pending.insert(
            pid,
            Pending {
                login,
                start,
                at: now,
            },
        );
    }

    /// 会话号 session 对应的登录。没见过的会话号顺手把等待中的监控进程都对一遍
    fn of(
        &mut self,
        session: u32,
        read: &dyn Fn(u32) -> Option<Proc>,
        now: Instant,
    ) -> Option<Bound> {
        if session == UNSET {
            return None;
        }
        if let Some(b) = self.sessions.get(&session) {
            return Some(b.clone());
        }
        let mut done = Vec::new();
        for (&pid, p) in &self.pending {
            let fresh = now.duration_since(p.at) < PENDING_TTL;
            match read(pid) {
                // 同一个进程（启动时刻没变）且 PAM 会话已打开：登录与会话号对上了
                Some(proc) if proc.start == p.start && proc.session != UNSET => {
                    self.sessions
                        .insert(proc.session, Arc::new(p.login.to_json(Some(proc.session))));
                    done.push(pid);
                }
                // 还在等 PAM 会话打开
                Some(proc) if proc.start == p.start && fresh => {}
                // 进程没了、pid 被复用、等太久：放弃这次登录
                _ => done.push(pid),
            }
        }
        for pid in done {
            self.pending.remove(&pid);
        }
        while self.sessions.len() > MAX_SESSIONS {
            self.sessions.pop_first();
        }
        self.sessions.get(&session).cloned()
    }

    fn mark_checked(&mut self, session: u32) -> bool {
        if !self.checked.insert(session) {
            return false;
        }
        while self.checked.len() > MAX_SESSIONS {
            self.checked.pop_first();
        }
        true
    }
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(Default::default)
}

/// 认证采集调用：sshd 监控进程 pid 写下了一条认证成功日志。
/// 调用方须已核对日志确实出自 root 身份的 sshd（journald 的 _UID/_COMM）
pub fn accepted(pid: u32, login: Login) {
    let Some(proc) = read_proc(pid) else { return };
    state().lock().unwrap_or_else(|e| e.into_inner()).accepted(
        pid,
        proc.start,
        login,
        Instant::now(),
    );
}

/// 进程采集调用：新进程属于哪次 SSH 登录。外层 None 表示读不到这个进程（已退场），
/// 调用方可以退回父进程的归属；Some(None) 表示读到了、但不属于任何认得的登录
pub fn of(pid: u32, ppid: Option<u32>) -> Option<Option<Bound>> {
    let session = read_session(pid)?;
    if session == UNSET {
        return Some(None);
    }
    let should_wait = {
        let mut st = state().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(b) = st.of(session, &read_proc, Instant::now()) {
            return Some(Some(b));
        }
        st.mark_checked(session) && has_sshd_ancestor(pid, ppid)
    };
    if !should_wait {
        return Some(None);
    }
    for _ in 0..JOURNAL_WAIT_STEPS {
        std::thread::sleep(JOURNAL_WAIT_STEP);
        let mut st = state().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(b) = st.of(session, &read_proc, Instant::now()) {
            return Some(Some(b));
        }
    }
    Some(None)
}

fn read_session(pid: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/sessionid"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn read_proc(pid: u32) -> Option<Proc> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    Some(Proc {
        session: read_session(pid)?,
        start: start_time(&stat)?,
    })
}

/// /proc/<pid>/stat 的进程名（括号内）与父进程号（右括号后第 2 列）
fn comm_and_ppid(stat: &str) -> Option<(&str, u32)> {
    let (_, rest) = stat.split_once('(')?;
    let (comm, after) = rest.rsplit_once(')')?;
    let ppid = after.split_whitespace().nth(1)?.parse().ok()?;
    Some((comm, ppid))
}

/// 向上追最多 6 层父进程，判断新会话是否由 sshd / sshd-session 拉起
fn has_sshd_ancestor(pid: u32, fallback_ppid: Option<u32>) -> bool {
    let mut cur = Some(pid);
    let mut used_fallback = false;
    for _ in 0..6 {
        let Some(p) = cur.filter(|&p| p > 1) else {
            return false;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{p}/stat")) else {
            if !used_fallback {
                used_fallback = true;
                cur = fallback_ppid;
                continue;
            }
            return false;
        };
        let Some((comm, next_ppid)) = comm_and_ppid(&stat) else {
            return false;
        };
        if comm == "sshd" || comm == "sshd-session" {
            return true;
        }
        cur = (next_ppid != p).then_some(next_ppid);
    }
    false
}

/// /proc/<pid>/stat 的第 22 列。第 2 列是带括号的进程名，可能含空格与括号，从最后一个 ')' 之后数
fn start_time(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// 解析 sshd 的认证成功日志：`Accepted <method> for <user> from <ip> port <n> ssh2[: <type> <fp>…]`。
/// 用户名由对端控制，从右边切 " from "；指纹只认 publickey 认证（hostbased 的是客户端主机密钥，不是操作者的）
pub fn parse_accepted(msg: &str) -> Option<Login> {
    let rest = msg.strip_prefix("Accepted ")?;
    let (method, rest) = rest.split_once(" for ")?;
    let (user, rest) = rest.rsplit_once(" from ")?;
    let (ip, rest) = rest.split_once(" port ")?;
    let mut words = rest.split_whitespace();
    let src_port = words.next().and_then(|p| p.parse().ok());
    let (mut key_type, mut key_fp) = (None, None);
    if method == "publickey" && words.next() == Some("ssh2:") {
        let t = words.next();
        let fp = words.next().filter(|fp| valid_fp(fp));
        if let (Some(t), Some(fp)) = (t, fp) {
            key_type = Some(t.to_string());
            key_fp = Some(fp.to_string());
        }
    }
    if method.is_empty() || method.contains(' ') || ip.is_empty() || ip.contains(' ') {
        return None;
    }
    Some(Login {
        user: user.to_string(),
        src_ip: ip.to_string(),
        src_port,
        method: method.to_string(),
        key_type,
        key_fp,
    })
}

/// SHA256 指纹：前缀加 43 个无填充 base64 字符
fn valid_fp(fp: &str) -> bool {
    fp.strip_prefix("SHA256:").is_some_and(|b| {
        b.len() == 43
            && b.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

    fn login() -> Login {
        parse_accepted(&format!(
            "Accepted publickey for root from 10.1.1.35 port 51234 ssh2: ED25519 {FP}"
        ))
        .unwrap()
    }

    #[test]
    fn parses_publickey_fingerprint() {
        let l = login();
        assert_eq!(l.user, "root");
        assert_eq!(l.src_ip, "10.1.1.35");
        assert_eq!(l.src_port, Some(51234));
        assert_eq!(l.method, "publickey");
        assert_eq!(l.key_type.as_deref(), Some("ED25519"));
        assert_eq!(l.key_fp.as_deref(), Some(FP));

        // 证书登录：指纹之后还跟着 ID / serial / CA，只取第一个
        let l = parse_accepted(&format!(
            "Accepted publickey for ops from 10.0.0.9 port 2222 ssh2: ED25519-CERT {FP} ID ops (serial 7) CA ED25519 SHA256:other"
        ))
        .unwrap();
        assert_eq!(l.key_type.as_deref(), Some("ED25519-CERT"));
        assert_eq!(l.key_fp.as_deref(), Some(FP));
    }

    #[test]
    fn non_publickey_has_no_fingerprint() {
        let l = parse_accepted("Accepted password for alice from 1.2.3.4 port 22 ssh2").unwrap();
        assert_eq!(l.method, "password");
        assert!(l.key_fp.is_none() && l.key_type.is_none());
        // hostbased 带的是客户端主机密钥，不是操作者的密钥
        let l = parse_accepted(&format!(
            "Accepted hostbased for bob from 1.2.3.4 port 22 ssh2: ED25519 {FP}"
        ))
        .unwrap();
        assert!(l.key_fp.is_none());
        // 指纹格式不对（截断、MD5）不认
        let l = parse_accepted(
            "Accepted publickey for root from 1.2.3.4 port 22 ssh2: RSA MD5:aa:bb:cc",
        )
        .unwrap();
        assert!(l.key_fp.is_none());
        assert!(parse_accepted("Failed password for root from 1.2.3.4 port 22 ssh2").is_none());
    }

    /// 用户名是对端给的：塞进去的假来源与假指纹都不能生效
    #[test]
    fn user_cannot_spoof_source_or_key() {
        let l = parse_accepted(&format!(
            "Accepted publickey for x from 6.6.6.6 port 1 ssh2: ED25519 {FP} from 1.2.3.4 port 5 ssh2: RSA SHA256:{}",
            "A".repeat(43)
        ))
        .unwrap();
        assert_eq!(l.src_ip, "1.2.3.4");
        assert_eq!(l.key_type.as_deref(), Some("RSA"));
        assert_ne!(l.key_fp.as_deref(), Some(FP));
    }

    #[test]
    fn stat_start_time_survives_odd_names() {
        let stat =
            "4242 (a) b (c) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10";
        assert_eq!(start_time(stat), Some(987654));
        assert_eq!(comm_and_ppid(stat), Some(("a) b (c", 1)));
        assert_eq!(
            comm_and_ppid("999 (sshd-session) S 888 999 999 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 123"),
            Some(("sshd-session", 888))
        );
        assert_eq!(start_time("garbage"), None);
        assert_eq!(comm_and_ppid("garbage"), None);
    }

    #[test]
    fn checked_sessions_are_bounded_and_deduplicated() {
        let mut st = State::default();
        assert!(st.mark_checked(42));
        assert!(!st.mark_checked(42), "同一个会话号只应等待/检查一次");
        for s in 0..(MAX_SESSIONS as u32 + 5) {
            st.mark_checked(s);
        }
        assert_eq!(st.checked.len(), MAX_SESSIONS);
        assert!(!st.checked.contains(&0));
    }

    /// 会话号在 PAM 会话打开后才设置：认证日志先到，进程事件到达时再对上
    #[test]
    fn binds_session_after_pam_opens() {
        let mut st = State::default();
        let t0 = Instant::now();
        st.accepted(100, 555, login(), t0);
        // PAM 还没打开：监控进程的会话号未设置
        let unset = |_| {
            Some(Proc {
                session: UNSET,
                start: 555,
            })
        };
        assert!(st.of(7, &unset, t0).is_none());
        assert_eq!(st.pending.len(), 1, "还在等，不能丢");
        let opened = |pid| {
            (pid == 100).then_some(Proc {
                session: 7,
                start: 555,
            })
        };
        let b = st.of(7, &opened, t0).expect("应对上会话 7");
        assert_eq!(b["uid"], "7");
        assert_eq!(b["key_fp"], FP);
        assert!(st.pending.is_empty());
        // 之后不再读 /proc
        let never = |_| -> Option<Proc> { panic!("已绑定的会话不应再读 /proc") };
        assert!(st.of(7, &never, t0).is_some());
        // 别的会话（没登记的登录）认不出
        assert!(st.of(8, &|_| None, t0).is_none());
        // 未设置的会话号永远不认
        assert!(st.of(UNSET, &never, t0).is_none());
    }

    /// 监控进程退出、pid 被复用：新进程的会话号不能被认成这次登录
    #[test]
    fn pid_reuse_is_not_trusted() {
        let mut st = State::default();
        let t0 = Instant::now();
        st.accepted(100, 555, login(), t0);
        let reused = |_| {
            Some(Proc {
                session: 9,
                start: 999,
            })
        };
        assert!(st.of(9, &reused, t0).is_none());
        assert!(st.pending.is_empty(), "pid 复用后应放弃这次登录");
    }

    #[test]
    fn pending_expires() {
        let mut st = State::default();
        let t0 = Instant::now();
        st.accepted(100, 555, login(), t0);
        let unset = |_| {
            Some(Proc {
                session: UNSET,
                start: 555,
            })
        };
        assert!(st.of(3, &unset, t0 + PENDING_TTL).is_none());
        assert!(st.pending.is_empty(), "等太久的登录应放弃");
    }

    #[test]
    fn sessions_are_bounded() {
        let mut st = State::default();
        let t0 = Instant::now();
        for s in 0..(MAX_SESSIONS as u32 + 10) {
            st.accepted(1, 1, login(), t0);
            let read = move |_| {
                Some(Proc {
                    session: s,
                    start: 1,
                })
            };
            st.of(s, &read, t0);
        }
        assert_eq!(st.sessions.len(), MAX_SESSIONS);
        assert!(!st.sessions.contains_key(&0), "最早的会话先丢");
    }

    #[test]
    fn json_shape() {
        let v = login().to_json(Some(12));
        assert_eq!(v["uid"], "12");
        assert_eq!(v["key_fp"], FP);
        assert_eq!(v["src_ip"], "10.1.1.35");
        assert_eq!(v["src_port"], 51234);
        assert_eq!(v["auth_method"], "publickey");
        assert!(login().to_json(None).get("uid").is_none());
    }
}
