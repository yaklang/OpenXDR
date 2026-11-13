//! SSH 授权钥匙盘点（仅 Linux，需 root 权限）。
//!
//! 覆盖范围：
//! 1. `sshd -T` 解析出的 `AuthorizedKeysFile`（支持 `%h`、`%u`、`%U`、`%%` 展开）；
//!    `AuthorizedKeysCommand` 与 `AuthorizedKeysCommandUser` 只记录配置文本，绝不执行；
//! 2. `/etc/passwd` 中所有用户的家目录 `.ssh/authorized_keys`（及 `.ssh/authorized_keys2`）；
//! 3. `/etc/ssh/authorized_keys.d` 下的用户钥匙文件。
//!
//! 安全边界：
//! - 只上报 SHA256 指纹（`SHA256:<43位无填充base64>`，与 `login_session.key_fp` 同格式）、
//!   公钥类型、账号、文件路径、选项与尾部注释，**绝不上报或缓存公钥原文**；
//! - 打开钥匙文件使用 `O_RDONLY | O_NONBLOCK | O_NOFOLLOW` 并校验普通文件与大小上限，
//!   防符号链接越权与命名管道阻塞；
//! - 启动时盘点一次，之后复用 `fswatch` 文件变更通知防抖重扫，不另做定时轮询。

#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(any(target_os = "linux", test))]
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use tokio::sync::Notify;

#[cfg(target_os = "linux")]
use crate::pb::{ReportSshKeysRequest, SshAuthorizedKey, agent_service_client::AgentServiceClient};

const MAX_COMMENT_CHARS: usize = 256;
const MAX_OPTION_CHARS: usize = 256;
const MAX_CMD_CONFIG_CHARS: usize = 512;
#[cfg(target_os = "linux")]
const MAX_KEY_FILE_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_KEYS_TOTAL: usize = 4096;
#[cfg(target_os = "linux")]
const REPORT_RPC_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(any(target_os = "linux", test))]
const RETRY_BASE_SECS: u64 = 15;
#[cfg(any(target_os = "linux", test))]
const RETRY_MAX_SECS: u64 = 10 * 60;

/// 上报失败指数退避：首次失败退避 15 秒，之后逐次翻倍，封顶 10 分钟
#[cfg(any(target_os = "linux", test))]
pub fn retry_backoff(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(10);
    let secs = RETRY_BASE_SECS
        .saturating_mul(1u64 << shift)
        .min(RETRY_MAX_SECS);
    Duration::from_secs(secs)
}

/// 单次盘点快照（不含任何公钥原文）
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub observed_at_ms: i64,
    pub keys: Vec<KeyEntry>,
    pub authorized_keys_command: String,
    pub authorized_keys_command_user: String,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyEntry {
    pub account: String,
    pub path: String,
    pub key_type: String,
    pub fingerprint: String,
    pub comment: String,
    pub options: Vec<String>,
}

/// 跨采集协程与 gRPC 上报协程共享的最新盘点状态（含跨重连保留的失败退避状态）
#[cfg(target_os = "linux")]
pub struct State {
    inner: Mutex<StateInner>,
    notify: Notify,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct StateInner {
    latest: Option<(u64, Snapshot)>,
    failures: u32,
    retry_not_before: Option<Instant>,
}

#[cfg(target_os = "linux")]
impl State {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(StateInner::default()),
            notify: Notify::new(),
        })
    }

    pub fn update(&self, snap: Snapshot) {
        let mut guard = self.inner.lock().unwrap();
        let next_seq = guard.latest.as_ref().map_or(1, |(seq, _)| seq + 1);
        guard.latest = Some((next_seq, snap));
        drop(guard);
        self.notify.notify_waiters();
    }

    fn latest_after(&self, sent_seq: u64) -> Option<(u64, Snapshot)> {
        let guard = self.inner.lock().unwrap();
        match guard.latest.as_ref() {
            Some((seq, snap)) if *seq > sent_seq => Some((*seq, snap.clone())),
            _ => None,
        }
    }

    fn pending_retry_wait(&self) -> Option<Duration> {
        let guard = self.inner.lock().unwrap();
        guard
            .retry_not_before
            .and_then(|until| until.checked_duration_since(Instant::now()))
    }

    fn record_success(&self) {
        let mut guard = self.inner.lock().unwrap();
        guard.failures = 0;
        guard.retry_not_before = None;
    }

    fn record_failure(&self) -> (u32, Duration) {
        let mut guard = self.inner.lock().unwrap();
        guard.failures = guard.failures.saturating_add(1);
        let backoff = retry_backoff(guard.failures);
        guard.retry_not_before = Some(Instant::now() + backoff);
        (guard.failures, backoff)
    }
}

/// 进程内共享的钥匙盘点状态与文件变更唤醒信号
#[cfg(target_os = "linux")]
pub fn shared_state() -> &'static Arc<State> {
    static STATE: OnceLock<Arc<State>> = OnceLock::new();
    STATE.get_or_init(State::new)
}

#[cfg(target_os = "linux")]
fn change_signal() -> &'static Notify {
    static SIGNAL: OnceLock<Notify> = OnceLock::new();
    SIGNAL.get_or_init(Notify::new)
}

/// 供 `fswatch` 在观测到相关文件变更时唤醒钥匙重扫
#[cfg(target_os = "linux")]
pub fn notify_if_relevant(path: &str) {
    if is_relevant_path(path) {
        change_signal().notify_one();
    }
}

/// 判断变更路径是否可能影响 SSH 授权钥匙盘点结果
pub fn is_relevant_path(path: &str) -> bool {
    path == "/etc/passwd"
        || path == "/etc/ssh"
        || path.starts_with("/etc/ssh/")
        || path.ends_with("/.ssh")
        || path.contains("/.ssh/")
        || path.contains("authorized_keys")
}

/// gRPC 上报循环：连接建立后把最新盘点快照推给 server，之后仅在快照更新时上报；失败按指数退避重试
#[cfg(target_os = "linux")]
pub async fn report(
    mut client: AgentServiceClient<tonic::transport::Channel>,
    agent_id: String,
    state: Arc<State>,
) {
    let mut sent_seq = 0u64;
    loop {
        // 先注册 notified，避免在读取与等待之间漏掉刚发生的更新
        let notified = state.notify.notified();
        if let Some((seq, snap)) = state.latest_after(sent_seq) {
            if let Some(wait) = state.pending_retry_wait() {
                tokio::time::sleep(wait).await;
                continue;
            }
            let mut req = tonic::Request::new(ReportSshKeysRequest {
                agent_id: agent_id.clone(),
                observed_at_ms: snap.observed_at_ms,
                keys: snap
                    .keys
                    .into_iter()
                    .map(|k| SshAuthorizedKey {
                        account: k.account,
                        path: k.path,
                        key_type: k.key_type,
                        fingerprint: k.fingerprint,
                        comment: k.comment,
                        options: k.options,
                    })
                    .collect(),
                authorized_keys_command: snap.authorized_keys_command,
                authorized_keys_command_user: snap.authorized_keys_command_user,
            });
            req.set_timeout(REPORT_RPC_TIMEOUT);
            match tokio::time::timeout(REPORT_RPC_TIMEOUT, client.report_ssh_keys(req)).await {
                Ok(Ok(_)) => {
                    state.record_success();
                    sent_seq = seq;
                    continue;
                }
                Ok(Err(err)) if err.code() == tonic::Code::Unimplemented => {
                    eprintln!("服务端尚不支持 SSH 钥匙盘点上报");
                    return;
                }
                Ok(Err(err)) => {
                    let (failures, backoff) = state.record_failure();
                    eprintln!(
                        "SSH 钥匙盘点上报失败（第 {failures} 次，{}s 后重试）：{}",
                        backoff.as_secs(),
                        err.code()
                    );
                    tokio::time::sleep(backoff).await;
                    continue;
                }
                Err(_) => {
                    let (failures, backoff) = state.record_failure();
                    eprintln!(
                        "SSH 钥匙盘点上报超时（第 {failures} 次，{}s 后重试）",
                        backoff.as_secs()
                    );
                    tokio::time::sleep(backoff).await;
                    continue;
                }
            }
        }
        notified.await;
    }
}

#[cfg(target_os = "linux")]
pub fn spawn(sink: super::EventSink, state: Arc<State>) {
    // 必须以 root 运行才能完整读取所有用户与 sshd -T，非 root 明确报不可用，不产残缺观测
    if unsafe { libc::geteuid() } != 0 {
        sink.capability("ssh-keys", "authorized-keys", "unavailable");
        eprintln!("SSH 钥匙盘点不可用：需要 root 权限");
        return;
    }
    tokio::spawn(async move {
        let initial = tokio::task::spawn_blocking(collect_snapshot).await;
        match initial {
            Ok(snap) => {
                let count = snap.keys.len();
                state.update(snap);
                sink.capability("ssh-keys", "authorized-keys", "active");
                eprintln!("SSH 钥匙盘点：初始发现 {count} 把授权钥匙");
            }
            Err(err) => {
                sink.capability("ssh-keys", "authorized-keys", "unavailable");
                eprintln!("SSH 钥匙初始盘点失败：{err}");
                return;
            }
        }

        let signal = change_signal();
        loop {
            signal.notified().await;
            // 吸收编辑器保存文件时的连续 create/modify/rename 事件
            tokio::time::sleep(Duration::from_millis(300)).await;
            if let Ok(snap) = tokio::task::spawn_blocking(collect_snapshot).await {
                state.update(snap);
            }
        }
    });
}

/// 补充给 `fswatch` 默认目标的钥匙目录（非 `/home` 用户的 `.ssh` 及 `sshd -T` 静态目录）
#[cfg(target_os = "linux")]
pub fn extra_watch_dirs() -> Vec<String> {
    let mut dirs = vec!["/etc/ssh/authorized_keys.d".to_string()];
    if let Ok(text) = std::fs::read_to_string("/etc/passwd") {
        for acct in parse_passwd_homes(&text) {
            if is_watchable_home(&acct.home) {
                dirs.push(format!("{}/.ssh", acct.home.trim_end_matches('/')));
            }
        }
    }
    let cfg = read_sshd_config();
    for tpl in &cfg.authorized_keys_files {
        if !tpl.contains('%')
            && tpl.starts_with('/')
            && let Some(parent) = std::path::Path::new(tpl).parent()
        {
            let p = parent.to_string_lossy();
            if !p.is_empty() && p != "/" {
                dirs.push(p.into_owned());
            }
        }
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

#[cfg(target_os = "linux")]
fn is_watchable_home(home: &str) -> bool {
    home.starts_with('/')
        && home != "/"
        && home != "/nonexistent"
        && home != "/dev/null"
        && !home.starts_with("/proc")
        && !home.starts_with("/sys")
        && !home.starts_with("/dev")
        && !home.starts_with("/run")
        && std::path::Path::new(home).is_dir()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshdKeyConfig {
    pub authorized_keys_files: Vec<String>,
    pub authorized_keys_command: String,
    pub authorized_keys_command_user: String,
}

impl Default for SshdKeyConfig {
    fn default() -> Self {
        Self {
            authorized_keys_files: vec![
                ".ssh/authorized_keys".into(),
                ".ssh/authorized_keys2".into(),
            ],
            authorized_keys_command: String::new(),
            authorized_keys_command_user: String::new(),
        }
    }
}

/// 解析 `sshd -T` 输出中的钥匙相关配置；`AuthorizedKeysCommand` 只提取文本，绝不执行
pub fn parse_sshd_t(text: &str) -> SshdKeyConfig {
    let mut cfg = SshdKeyConfig::default();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, val)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let val = val.trim();
        if key.eq_ignore_ascii_case("authorizedkeysfile") {
            if val.eq_ignore_ascii_case("none") {
                cfg.authorized_keys_files.clear();
            } else {
                cfg.authorized_keys_files = val.split_whitespace().map(str::to_string).collect();
            }
        } else if key.eq_ignore_ascii_case("authorizedkeyscommand") {
            if !val.eq_ignore_ascii_case("none") {
                cfg.authorized_keys_command = clean_text(val, MAX_CMD_CONFIG_CHARS);
            }
        } else if key.eq_ignore_ascii_case("authorizedkeyscommanduser")
            && !val.eq_ignore_ascii_case("none")
        {
            cfg.authorized_keys_command_user = clean_text(val, MAX_OPTION_CHARS);
        }
    }
    cfg
}

/// 展开 OpenSSH `AuthorizedKeysFile` 路径模板（`%h`、`%u`、`%U`、`%%`）
pub fn expand_key_path(tpl: &str, user: &str, uid: u32, home: &str) -> Option<String> {
    if tpl.is_empty() || user.is_empty() {
        return None;
    }
    let home_clean = if home == "/" {
        "/"
    } else {
        home.trim_end_matches('/')
    };
    let mut out = String::with_capacity(tpl.len() + home_clean.len());
    let mut chars = tpl.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            '%' => out.push('%'),
            'h' => {
                if !home_clean.starts_with('/') {
                    return None;
                }
                out.push_str(home_clean);
            }
            'u' => out.push_str(user),
            'U' => out.push_str(&uid.to_string()),
            _ => return None,
        }
    }
    let full = if out.starts_with('/') {
        out
    } else {
        if !home_clean.starts_with('/') {
            return None;
        }
        if home_clean == "/" {
            format!("/{out}")
        } else {
            format!("{home_clean}/{out}")
        }
    };
    Some(normalize_slash(&full))
}

fn normalize_slash(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut prev_slash = false;
    for c in path.chars() {
        if c == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            prev_slash = false;
            out.push(c);
        }
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswdHome {
    pub name: String,
    pub uid: u32,
    pub home: String,
}

pub fn parse_passwd_homes(text: &str) -> Vec<PasswdHome> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 7 || fields[0].is_empty() {
            continue;
        }
        let Ok(uid) = fields[2].parse::<u32>() else {
            continue;
        };
        out.push(PasswdHome {
            name: fields[0].to_string(),
            uid,
            home: fields[5].to_string(),
        });
    }
    out
}

/// 单条解析出的公钥元数据（不含公钥原文）
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedAuthorizedKey {
    pub key_type: String,
    pub fingerprint: String,
    pub comment: String,
    pub options: Vec<String>,
}

/// 解析单个 `authorized_keys` 文件文本，跳过注释行、空行与畸形行
pub fn parse_authorized_keys(text: &str) -> Vec<ParsedAuthorizedKey> {
    let mut out = Vec::new();
    for raw_line in text.lines() {
        if let Some(parsed) = parse_authorized_key_line(raw_line) {
            out.push(parsed);
        }
    }
    out
}

pub fn parse_authorized_key_line(raw_line: &str) -> Option<ParsedAuthorizedKey> {
    let line = raw_line.trim_matches(|c: char| c.is_ascii_whitespace());
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (first, rest) = read_quoted_field(line)?;
    let (options, key_type, rest) = if is_ssh_key_type(first) {
        (
            Vec::new(),
            first,
            rest.trim_start_matches(|c: char| c.is_ascii_whitespace()),
        )
    } else {
        let opts = split_options(first)?;
        let rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
        let (kt, after_kt) = split_ws_token(rest)?;
        if !is_ssh_key_type(kt) {
            return None;
        }
        (
            opts,
            kt,
            after_kt.trim_start_matches(|c: char| c.is_ascii_whitespace()),
        )
    };

    let (b64_blob, comment_rest) = match split_ws_token(rest) {
        Some((b, r)) => (b, r),
        None => return None,
    };
    let fingerprint = fingerprint_of_blob(b64_blob)?;
    let comment = clean_text(comment_rest.trim(), MAX_COMMENT_CHARS);
    Some(ParsedAuthorizedKey {
        key_type: key_type.to_string(),
        fingerprint,
        comment,
        options,
    })
}

fn split_ws_token(s: &str) -> Option<(&str, &str)> {
    if s.is_empty() {
        return None;
    }
    match s.find(|c: char| c.is_ascii_whitespace()) {
        Some(idx) => Some((&s[..idx], &s[idx..])),
        None => Some((s, "")),
    }
}

/// 读取可能包含双引号字符串的字段（OpenSSH authorized_keys 选项字段）
fn read_quoted_field(s: &str) -> Option<(&str, &str)> {
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_quotes {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quotes = false;
            }
        } else if ch == '"' {
            in_quotes = true;
        } else if ch.is_ascii_whitespace() {
            return Some((&s[..idx], &s[idx..]));
        }
    }
    if in_quotes || escaped {
        return None;
    }
    Some((s, ""))
}

/// 按双引号感知的逗号切分 OpenSSH 选项串
fn split_options(raw: &str) -> Option<Vec<String>> {
    if raw.is_empty() {
        return None;
    }
    let mut opts = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, ch) in raw.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_quotes {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quotes = false;
            }
        } else if ch == '"' {
            in_quotes = true;
        } else if ch == ',' {
            let item = clean_text(raw[start..idx].trim(), MAX_OPTION_CHARS);
            if !item.is_empty() {
                opts.push(item);
            }
            start = idx + 1;
        }
    }
    if in_quotes || escaped {
        return None;
    }
    let tail = clean_text(raw[start..].trim(), MAX_OPTION_CHARS);
    if !tail.is_empty() {
        opts.push(tail);
    }
    if opts.is_empty() { None } else { Some(opts) }
}

fn is_ssh_key_type(tok: &str) -> bool {
    if tok.is_empty()
        || tok.len() > 128
        || tok.contains('=')
        || tok.contains(',')
        || tok.contains('"')
    {
        return false;
    }
    (tok.starts_with("ssh-")
        || tok.starts_with("ecdsa-sha2-")
        || tok.starts_with("sk-ssh-")
        || tok.starts_with("sk-ecdsa-"))
        && tok
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
}

/// 解码公钥 Base64，校验 SSH wire 头部结构，计算 `SHA256:<43位无填充base64>` 指纹；原文当场丢弃
fn fingerprint_of_blob(b64: &str) -> Option<String> {
    let raw = decode_base64(b64)?;
    if raw.len() < 8 {
        return None;
    }
    let hdr_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    if hdr_len == 0 || hdr_len > 128 || 4 + hdr_len >= raw.len() {
        return None;
    }
    if !raw[4..4 + hdr_len]
        .iter()
        .all(|b| (0x21..=0x7e).contains(b))
    {
        return None;
    }
    let digest = Sha256::digest(&raw);
    let mut out = String::with_capacity(7 + 43);
    out.push_str("SHA256:");
    encode_base64_nopad(&digest, &mut out);
    Some(out)
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let (chunks, _) = bytes.as_chunks::<4>();
    let mut out = Vec::with_capacity(chunks.len() * 3);
    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        let is_last = chunk_idx + 1 == chunks.len();
        let pad = if chunk[3] == b'=' {
            if !is_last {
                return None;
            }
            if chunk[2] == b'=' { 2 } else { 1 }
        } else {
            0
        };
        if (pad < 2 && chunk[2] == b'=') || chunk[0] == b'=' || chunk[1] == b'=' {
            return None;
        }
        let v0 = b64_val(chunk[0])?;
        let v1 = b64_val(chunk[1])?;
        out.push((v0 << 2) | (v1 >> 4));
        if pad < 2 {
            let v2 = b64_val(chunk[2])?;
            out.push((v1 << 4) | (v2 >> 2));
            if pad == 0 {
                let v3 = b64_val(chunk[3])?;
                out.push((v2 << 6) | v3);
            }
        }
    }
    Some(out)
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn encode_base64_nopad(data: &[u8], out: &mut String) {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
    }
}

fn clean_text(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for ch in s.chars().take(max_chars) {
        if ch.is_control() {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out.trim().to_string()
}

#[cfg(target_os = "linux")]
fn collect_snapshot() -> Snapshot {
    let cfg = read_sshd_config();
    let accounts = std::fs::read_to_string("/etc/passwd")
        .map(|s| parse_passwd_homes(&s))
        .unwrap_or_default();

    let mut candidate_files: Vec<(String, String)> = Vec::new();
    for acct in &accounts {
        for tpl in &cfg.authorized_keys_files {
            if let Some(p) = expand_key_path(tpl, &acct.name, acct.uid, &acct.home) {
                candidate_files.push((acct.name.clone(), p));
            }
        }
        if acct.home.starts_with('/') && acct.home != "/nonexistent" && acct.home != "/dev/null" {
            let h = if acct.home == "/" {
                ""
            } else {
                acct.home.trim_end_matches('/')
            };
            candidate_files.push((acct.name.clone(), format!("{h}/.ssh/authorized_keys")));
            candidate_files.push((acct.name.clone(), format!("{h}/.ssh/authorized_keys2")));
        }
        candidate_files.push((
            acct.name.clone(),
            format!("/etc/ssh/authorized_keys.d/{}", acct.name),
        ));
    }

    // 补充扫描 /etc/ssh/authorized_keys.d 目录下的文件或按用户名分目录的文件
    if let Ok(rd) = std::fs::read_dir("/etc/ssh/authorized_keys.d") {
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            if ft.is_file() {
                candidate_files.push((name, path.to_string_lossy().into_owned()));
            } else if ft.is_dir()
                && let Ok(sub) = std::fs::read_dir(&path)
            {
                for sub_entry in sub.flatten() {
                    if sub_entry.file_type().is_ok_and(|t| t.is_file()) {
                        candidate_files.push((
                            name.clone(),
                            sub_entry.path().to_string_lossy().into_owned(),
                        ));
                    }
                }
            }
        }
    }

    candidate_files.sort();
    candidate_files.dedup();

    let mut keys = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (account, path) in candidate_files {
        let Some(content) = read_regular_nofollow(&path, MAX_KEY_FILE_BYTES) else {
            continue;
        };
        for parsed in parse_authorized_keys(&content) {
            if seen.insert((account.clone(), path.clone(), parsed.fingerprint.clone())) {
                keys.push(KeyEntry {
                    account: account.clone(),
                    path: path.clone(),
                    key_type: parsed.key_type,
                    fingerprint: parsed.fingerprint,
                    comment: parsed.comment,
                    options: parsed.options,
                });
                if keys.len() >= MAX_KEYS_TOTAL {
                    break;
                }
            }
        }
        if keys.len() >= MAX_KEYS_TOTAL {
            break;
        }
    }
    keys.sort();

    Snapshot {
        observed_at_ms: crate::status_proto::now_ms() as i64,
        keys,
        authorized_keys_command: cfg.authorized_keys_command,
        authorized_keys_command_user: cfg.authorized_keys_command_user,
    }
}

#[cfg(target_os = "linux")]
fn read_sshd_config() -> SshdKeyConfig {
    use std::process::{Command, Stdio};

    let candidates = ["/usr/sbin/sshd", "/sbin/sshd", "sshd"];
    for bin in candidates {
        let Ok(mut child) = Command::new(bin)
            .arg("-T")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        break;
                    }
                    if let Some(mut stdout) = child.stdout.take() {
                        let mut buf = String::new();
                        if std::io::Read::read_to_string(&mut stdout, &mut buf).is_ok() {
                            return parse_sshd_t(&buf);
                        }
                    }
                    break;
                }
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    }
    SshdKeyConfig::default()
}

/// 以 `O_RDONLY | O_NONBLOCK | O_NOFOLLOW` 读取普通文件，拒绝符号链接、设备/管道及超大文件
#[cfg(target_os = "linux")]
fn read_regular_nofollow(path: &str, max_bytes: usize) -> Option<String> {
    use std::ffi::CString;
    use std::io::Read;
    use std::os::unix::io::FromRawFd;

    let c_path = CString::new(path).ok()?;
    let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::open(c_path.as_ptr(), flags) };
    if fd < 0 {
        return None;
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return None;
    }
    if st.st_size < 0 || (st.st_size as usize) > max_bytes {
        return None;
    }
    let mut buf = Vec::with_capacity((st.st_size as usize).min(max_bytes));
    file.by_ref()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() > max_bytes {
        return None;
    }
    String::from_utf8(buf).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ed25519_pub_b64(seed_byte: u8) -> (String, String) {
        let kt = b"ssh-ed25519";
        let pub_bytes = [seed_byte; 32];
        let mut blob = Vec::new();
        blob.extend_from_slice(&(kt.len() as u32).to_be_bytes());
        blob.extend_from_slice(kt);
        blob.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
        blob.extend_from_slice(&pub_bytes);

        // 标准带 '=' 填充的公钥原文 Base64（仅用于构造测试输入）
        let mut b64 = String::new();
        encode_base64_nopad(&blob, &mut b64);
        while !b64.len().is_multiple_of(4) {
            b64.push('=');
        }
        let digest = Sha256::digest(&blob);
        let mut fp = String::from("SHA256:");
        encode_base64_nopad(&digest, &mut fp);
        (b64, fp)
    }

    #[test]
    fn fingerprint_matches_openssh_wire_format_and_drops_raw_key() {
        // 与 `ssh-keygen -lf -` 对拍验证过的确定性测试向量（pub_bytes = [0x11; 32]）
        let (b64, fp) = make_ed25519_pub_b64(0x11);
        assert_eq!(fp, "SHA256:SQfC+vTbLURn9cTkVxIS8fGQ3FKNAJWeB0o139+gV4M");

        let content = format!(
            "# comment line\n\n\
             ssh-ed25519 {b64} kei@foghaven\n\
             from=\"10.1.1.1,10.1.1.2\",command=\"echo ssh-ed25519 \\\"fake\\\"\",cert-authority,no-pty ssh-ed25519 {b64} ops key\n\
             malformed line without valid key\n\
             ssh-ed25519 AAAAB3NzaC1yc2E=\n"
        );
        let parsed = parse_authorized_keys(&content);
        assert_eq!(parsed.len(), 2);

        assert_eq!(parsed[0].key_type, "ssh-ed25519");
        assert_eq!(parsed[0].fingerprint, fp);
        assert_eq!(parsed[0].comment, "kei@foghaven");
        assert!(parsed[0].options.is_empty());

        assert_eq!(parsed[1].key_type, "ssh-ed25519");
        assert_eq!(parsed[1].fingerprint, fp);
        assert_eq!(parsed[1].comment, "ops key");
        assert_eq!(
            parsed[1].options,
            vec![
                "from=\"10.1.1.1,10.1.1.2\"",
                "command=\"echo ssh-ed25519 \\\"fake\\\"\"",
                "cert-authority",
                "no-pty",
            ]
        );

        // 调试输出与全部字段中绝不包含公钥 Base64 原文
        let debug_repr = format!("{parsed:?}");
        assert!(!debug_repr.contains(&b64));
    }

    #[test]
    fn parses_sshd_t_and_expands_tokens_without_executing_command() {
        let text = "\
port 22\n\
authorizedkeysfile .ssh/authorized_keys /etc/ssh/keys/%u %h/.ssh/ak_%U_%%\n\
authorizedkeyscommand /usr/local/bin/fetch-keys %u\n\
authorizedkeyscommanduser nobody\n";
        let cfg = parse_sshd_t(text);
        assert_eq!(
            cfg.authorized_keys_files,
            vec![
                ".ssh/authorized_keys",
                "/etc/ssh/keys/%u",
                "%h/.ssh/ak_%U_%%"
            ]
        );
        assert_eq!(cfg.authorized_keys_command, "/usr/local/bin/fetch-keys %u");
        assert_eq!(cfg.authorized_keys_command_user, "nobody");

        assert_eq!(
            expand_key_path(".ssh/authorized_keys", "alice", 1000, "/home/alice"),
            Some("/home/alice/.ssh/authorized_keys".into())
        );
        assert_eq!(
            expand_key_path("/etc/ssh/keys/%u", "alice", 1000, "/home/alice"),
            Some("/etc/ssh/keys/alice".into())
        );
        assert_eq!(
            expand_key_path("%h/.ssh/ak_%U_%%", "root", 0, "/root/"),
            Some("/root/.ssh/ak_0_%".into())
        );
        assert_eq!(expand_key_path("%x/bad", "root", 0, "/root"), None);
    }

    #[test]
    fn relevant_paths_cover_ssh_and_passwd() {
        assert!(is_relevant_path("/etc/passwd"));
        assert!(is_relevant_path("/etc/ssh/sshd_config"));
        assert!(is_relevant_path("/etc/ssh/authorized_keys.d/alice"));
        assert!(is_relevant_path("/root/.ssh/authorized_keys"));
        assert!(is_relevant_path("/var/lib/postgresql/.ssh"));
        assert!(!is_relevant_path("/var/log/syslog"));

        let homes = parse_passwd_homes(
            "root:x:0:0:root:/root:/bin/bash\n#c\nbad\nalice:x:1000:1000::/home/alice:/bin/sh\n",
        );
        assert_eq!(homes.len(), 2);
        assert_eq!(
            homes[0],
            PasswdHome {
                name: "root".into(),
                uid: 0,
                home: "/root".into()
            }
        );
        assert_eq!(
            homes[1],
            PasswdHome {
                name: "alice".into(),
                uid: 1000,
                home: "/home/alice".into()
            }
        );
    }

    #[test]
    fn exponential_backoff_starts_at_15s_and_caps_at_10m() {
        assert_eq!(retry_backoff(1), Duration::from_secs(15));
        assert_eq!(retry_backoff(2), Duration::from_secs(30));
        assert_eq!(retry_backoff(3), Duration::from_secs(60));
        assert_eq!(retry_backoff(4), Duration::from_secs(120));
        assert_eq!(retry_backoff(5), Duration::from_secs(240));
        assert_eq!(retry_backoff(6), Duration::from_secs(480));
        assert_eq!(retry_backoff(7), Duration::from_secs(600));
        assert_eq!(retry_backoff(50), Duration::from_secs(600));
    }
}
