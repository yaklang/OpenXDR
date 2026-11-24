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
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(any(target_os = "linux", test))]
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

#[cfg(target_os = "linux")]
use prost::Message;
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use tokio::sync::Notify;

#[cfg(target_os = "linux")]
use crate::pb::{ReportSshKeysRequest, SshAuthorizedKey, agent_service_client::AgentServiceClient};

const MAX_COMMENT_CHARS: usize = 256;
const MAX_OPTION_CHARS: usize = 256;
const MAX_OPTIONS_PER_KEY: usize = 64;
const MAX_OPTION_BYTES: usize = 512;
const MAX_CMD_CONFIG_CHARS: usize = 512;
#[cfg(target_os = "linux")]
const MAX_SSHD_OUTPUT_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const SSHD_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const MAX_KEY_FILE_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_KEYS_TOTAL: usize = 4096;
/// 单帧 ReportSshKeysRequest 的 protobuf 编码体积上限（3 MiB，为 gRPC 默认 4 MiB 上限留足余量）
#[cfg(target_os = "linux")]
const MAX_SNAPSHOT_BYTES: usize = 3 * 1024 * 1024;
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
    /// 因条数或单帧 protobuf 体积预算（3 MiB）触顶而被截断
    pub truncated: bool,
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
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let next_seq = guard.latest.as_ref().map_or(1, |(seq, _)| seq + 1);
        guard.latest = Some((next_seq, snap));
        drop(guard);
        self.notify.notify_waiters();
    }

    fn latest_after(&self, sent_seq: u64) -> Option<(u64, Snapshot)> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match guard.latest.as_ref() {
            Some((seq, snap)) if *seq > sent_seq => Some((*seq, snap.clone())),
            _ => None,
        }
    }

    fn pending_retry_wait(&self) -> Option<Duration> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .retry_not_before
            .and_then(|until| until.checked_duration_since(Instant::now()))
    }

    fn record_success(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.failures = 0;
        guard.retry_not_before = None;
    }

    fn record_failure(&self) -> (u32, Duration) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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
            let Some(body) = build_report_request(&agent_id, snap) else {
                // 残缺快照绝不上报，避免服务端将缺失的尾部钥匙误标为 present=false；
                // 标记该 seq 已跳过，等待后续文件变更产生完整快照后再上报。
                sent_seq = seq;
                continue;
            };
            let mut req = tonic::Request::new(body);
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
        let mut last_trusted: Option<SshdKeyConfig> = None;
        let initial = tokio::task::spawn_blocking(move || {
            let snap = collect_snapshot(&mut last_trusted);
            (last_trusted, snap)
        })
        .await;
        let last_trusted = match initial {
            Ok((trusted, Some(snap))) => {
                let count = snap.keys.len();
                state.update(snap);
                sink.capability("ssh-keys", "authorized-keys", "active");
                eprintln!("SSH 钥匙盘点：初始发现 {count} 把授权钥匙");
                trusted
            }
            Ok((trusted, None)) => {
                // sshd -T 失败且尚无可信配置：暂缓上报，保持监听等待后续恢复
                sink.capability("ssh-keys", "authorized-keys", "degraded");
                trusted
            }
            Err(err) => {
                sink.capability("ssh-keys", "authorized-keys", "unavailable");
                eprintln!("SSH 钥匙初始盘点失败：{err}");
                return;
            }
        };

        let signal = change_signal();
        watch_changes(
            &sink,
            &state,
            signal,
            Duration::from_millis(300),
            last_trusted,
            |mut trusted| async move {
                tokio::task::spawn_blocking(move || {
                    let snap = collect_snapshot(&mut trusted);
                    (trusted, snap)
                })
                .await
                .unwrap_or_default()
            },
        )
        .await;
    });
}

#[cfg(target_os = "linux")]
async fn watch_changes<F, Fut>(
    sink: &super::EventSink,
    state: &State,
    signal: &tokio::sync::Notify,
    debounce: Duration,
    mut last_trusted: Option<SshdKeyConfig>,
    mut collect: F,
) where
    F: FnMut(Option<SshdKeyConfig>) -> Fut,
    Fut: std::future::Future<Output = (Option<SshdKeyConfig>, Option<Snapshot>)>,
{
    loop {
        tokio::select! {
            _ = sink.closed() => return,
            _ = signal.notified() => {}
        }
        // 吸收编辑器保存文件时的连续 create/modify/rename 事件
        tokio::time::sleep(debounce).await;
        if sink.is_closed() {
            return;
        }
        let (trusted_out, snap) = collect(last_trusted.clone()).await;
        if trusted_out.is_some() {
            last_trusted = trusted_out;
        }
        if let Some(snap) = snap {
            state.update(snap);
            sink.capability("ssh-keys", "authorized-keys", "active");
        }
    }
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
    if let SshdConfigOutcome::Parsed(cfg) = read_sshd_config() {
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

/// 按 UTF-8 字符边界截断到最多 max_bytes 字节
fn truncate_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// 按双引号感知的逗号切分 OpenSSH 选项串，限制单行选项数量与单选项长度，防止恶意长行撑爆上报帧
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
            if opts.len() < MAX_OPTIONS_PER_KEY {
                let piece = truncate_bytes(raw[start..idx].trim(), MAX_OPTION_BYTES);
                let item = clean_text(piece, MAX_OPTION_CHARS);
                if !item.is_empty() {
                    opts.push(item);
                }
            }
            start = idx + 1;
        }
    }
    if in_quotes || escaped {
        return None;
    }
    if opts.len() < MAX_OPTIONS_PER_KEY {
        let piece = truncate_bytes(raw[start..].trim(), MAX_OPTION_BYTES);
        let tail = clean_text(piece, MAX_OPTION_CHARS);
        if !tail.is_empty() {
            opts.push(tail);
        }
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
fn collect_snapshot(last_trusted: &mut Option<SshdKeyConfig>) -> Option<Snapshot> {
    let cfg = resolve_sshd_config(read_sshd_config(), last_trusted)?;
    Some(collect_snapshot_with_config(cfg))
}

#[cfg(target_os = "linux")]
fn collect_snapshot_with_config(cfg: SshdKeyConfig) -> Snapshot {
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

    let base_bytes = base_request_bytes(
        &cfg.authorized_keys_command,
        &cfg.authorized_keys_command_user,
    );
    let mut keys = Vec::new();
    let mut used_bytes = base_bytes;
    let mut truncated = false;
    let mut seen = std::collections::HashSet::new();
    'outer: for (account, path) in candidate_files {
        let Some(content) = read_regular_nofollow(&path, MAX_KEY_FILE_BYTES) else {
            continue;
        };
        for parsed in parse_authorized_keys(&content) {
            if seen.insert((account.clone(), path.clone(), parsed.fingerprint.clone())) {
                let entry = KeyEntry {
                    account: account.clone(),
                    path: path.clone(),
                    key_type: parsed.key_type,
                    fingerprint: parsed.fingerprint,
                    comment: parsed.comment,
                    options: parsed.options,
                };
                let entry_bytes = key_entry_wire_bytes(&entry);
                if keys.len() >= MAX_KEYS_TOTAL
                    || used_bytes.saturating_add(entry_bytes) > MAX_SNAPSHOT_BYTES
                {
                    truncated = true;
                    eprintln!(
                        "SSH 钥匙盘点快照触及上限（已保留 {} 条，约 {} 字节，上限 {} 字节），已截断剩余条目",
                        keys.len(),
                        used_bytes,
                        MAX_SNAPSHOT_BYTES
                    );
                    break 'outer;
                }
                used_bytes += entry_bytes;
                keys.push(entry);
            }
        }
    }
    keys.sort();

    Snapshot {
        observed_at_ms: crate::status_proto::now_ms() as i64,
        keys,
        authorized_keys_command: cfg.authorized_keys_command,
        authorized_keys_command_user: cfg.authorized_keys_command_user,
        truncated,
    }
}

/// 估算 ReportSshKeysRequest 固定头部的 protobuf 字节数（为 agent_id 预留 256 字节余量）
#[cfg(target_os = "linux")]
fn base_request_bytes(authorized_keys_command: &str, authorized_keys_command_user: &str) -> usize {
    ReportSshKeysRequest {
        agent_id: "x".repeat(256),
        observed_at_ms: i64::MAX,
        keys: Vec::new(),
        authorized_keys_command: authorized_keys_command.to_string(),
        authorized_keys_command_user: authorized_keys_command_user.to_string(),
    }
    .encoded_len()
}

/// 计算单条 KeyEntry 编码进 ReportSshKeysRequest.keys（字段 3）时的实际字节增量
#[cfg(target_os = "linux")]
fn key_entry_wire_bytes(k: &KeyEntry) -> usize {
    let msg = SshAuthorizedKey {
        account: k.account.clone(),
        path: k.path.clone(),
        key_type: k.key_type.clone(),
        fingerprint: k.fingerprint.clone(),
        comment: k.comment.clone(),
        options: k.options.clone(),
    };
    let len = msg.encoded_len();
    1 + prost::encoding::encoded_len_varint(len as u64) + len
}

/// 按单帧 protobuf 字节预算与条数上限打包钥匙条目，返回 `(保留条目, 是否截断)`。
#[cfg(all(target_os = "linux", test))]
fn pack_keys_within_budget(
    entries: Vec<KeyEntry>,
    base_bytes: usize,
    max_bytes: usize,
) -> (Vec<KeyEntry>, bool) {
    let mut kept = Vec::new();
    let mut used = base_bytes;
    let mut truncated = false;
    for entry in entries {
        let entry_bytes = key_entry_wire_bytes(&entry);
        if kept.len() >= MAX_KEYS_TOTAL || used.saturating_add(entry_bytes) > max_bytes {
            truncated = true;
            break;
        }
        used += entry_bytes;
        kept.push(entry);
    }
    kept.sort();
    (kept, truncated)
}

/// 强杀超时子进程组后短轮询回收僵尸的上限，防不可中断 D 状态让 wait() 无限阻塞
#[cfg(target_os = "linux")]
const REAP_TIMEOUT: Duration = Duration::from_millis(500);

/// 组装上报请求。若快照已触发截断或最终编码体积超出 MAX_SNAPSHOT_BYTES（3 MiB），
/// 返回 `None` 暂缓上报，绝不发送残缺快照导致服务端将缺失的尾部钥匙误标为 `present=false`。
#[cfg(target_os = "linux")]
fn build_report_request(agent_id: &str, snap: Snapshot) -> Option<ReportSshKeysRequest> {
    if snap.truncated {
        eprintln!(
            "SSH 钥匙盘点快照已超 {} 字节或 {} 条上限（当前保留 {} 条），暂缓上报以避免服务端误删尾部钥匙",
            MAX_SNAPSHOT_BYTES,
            MAX_KEYS_TOTAL,
            snap.keys.len()
        );
        return None;
    }
    let req = ReportSshKeysRequest {
        agent_id: agent_id.to_string(),
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
    };
    let encoded_len = req.encoded_len();
    if encoded_len > MAX_SNAPSHOT_BYTES {
        eprintln!(
            "SSH 钥匙上报请求编码体积（{} 字节）超出 {} 字节上限，暂缓上报以避免服务端误删尾部钥匙",
            encoded_len, MAX_SNAPSHOT_BYTES
        );
        return None;
    }
    Some(req)
}

#[cfg(target_os = "linux")]
fn kill_process_group(child: &mut std::process::Child) {
    let pid = child.id() as libc::pid_t;
    if pid > 0 {
        // SAFETY: 调用方通过 process_group(0) 为子进程建立了独立进程组（pgid == pid），
        // 向负 pgid 发送 SIGKILL 终止整棵进程树，防后代继承 stdout 写端导致挂死。
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

#[cfg(target_os = "linux")]
fn read_child_stdout_with_timeout(
    child: std::process::Child,
    timeout: Duration,
    max_bytes: usize,
) -> Option<String> {
    let (text, truncated) = read_child_stdout_checked(child, timeout, max_bytes)?;
    if truncated {
        eprintln!("sshd -T 输出超过 {max_bytes} 字节上限被截断，视为无效输出并忽略");
        return None;
    }
    Some(text)
}

/// 带超时读取子进程 stdout：读线程经 channel 返回结果，主线程按共享 deadline 等待（绝不无限 join），
/// 超时或 try_wait 异常均杀整棵进程树并回收子进程。返回 `Some((输出文本, 是否截断))`。
#[cfg(target_os = "linux")]
fn read_child_stdout_checked(
    mut child: std::process::Child,
    timeout: Duration,
    max_bytes: usize,
) -> Option<(String, bool)> {
    use std::io::Read;

    // 后台线程并发排空 stdout，避免输出超过 64 KiB 管道缓冲区时主线程等待退出发生死锁
    let rx = child.stdout.take().map(|mut stdout| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut truncated = false;
            let mut chunk = [0u8; 8192];
            while let Ok(n) = stdout.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if kept.len() < max_bytes {
                    let take = (max_bytes - kept.len()).min(n);
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
    })?;

    let deadline = Instant::now() + timeout;
    let exited_ok = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_process_group(&mut child);
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                kill_process_group(&mut child);
                return None;
            }
        }
    };

    if !exited_ok {
        return None;
    }

    let rem = deadline.saturating_duration_since(Instant::now());
    let (bytes, truncated) = match rx.recv_timeout(rem) {
        Ok(pair) => pair,
        Err(_) => {
            // 父进程已退出但后代进程仍持有 stdout 写端，杀整棵进程组并超时放弃
            kill_process_group(&mut child);
            return None;
        }
    };
    Some((String::from_utf8_lossy(&bytes).into_owned(), truncated))
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
enum SshdConfigOutcome {
    Parsed(SshdKeyConfig),
    NotInstalled,
    Failed,
}

/// 根据 `sshd -T` 探测结果决定本次盘点使用的配置：
/// - `Parsed`：更新并返回最新可信配置；
/// - `NotInstalled`（主机确实未装 sshd）：使用默认路径配置；
/// - `Failed`（sshd 存在但执行失败/超时/输出截断）：若存在上一次可信配置则保留沿用，
///   否则返回 `None` 暂缓本次上报，绝不回落默认路径覆盖自定义配置后上报残缺快照。
#[cfg(target_os = "linux")]
fn resolve_sshd_config(
    outcome: SshdConfigOutcome,
    last_trusted: &mut Option<SshdKeyConfig>,
) -> Option<SshdKeyConfig> {
    match outcome {
        SshdConfigOutcome::Parsed(cfg) => {
            *last_trusted = Some(cfg.clone());
            Some(cfg)
        }
        SshdConfigOutcome::NotInstalled => Some(SshdKeyConfig::default()),
        SshdConfigOutcome::Failed => {
            if let Some(prev) = last_trusted.clone() {
                eprintln!("sshd -T 执行失败或输出被截断，保留上一次可信配置继续盘点");
                Some(prev)
            } else {
                eprintln!(
                    "sshd -T 执行失败或输出被截断，且尚无可信配置，暂缓本次 SSH 钥匙盘点上报"
                );
                None
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn read_sshd_config() -> SshdConfigOutcome {
    read_sshd_config_from(
        &["/usr/sbin/sshd", "/sbin/sshd", "sshd"],
        SSHD_TIMEOUT,
        MAX_SSHD_OUTPUT_BYTES,
    )
}

#[cfg(target_os = "linux")]
fn read_sshd_config_from(
    candidates: &[&str],
    timeout: Duration,
    max_bytes: usize,
) -> SshdConfigOutcome {
    use std::process::{Command, Stdio};

    let mut saw_binary = false;
    for bin in candidates {
        match Command::new(bin)
            .arg("-T")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
        {
            Ok(child) => {
                saw_binary = true;
                if let Some(buf) = read_child_stdout_with_timeout(child, timeout, max_bytes) {
                    return SshdConfigOutcome::Parsed(parse_sshd_t(&buf));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                // 二进制存在或无法确认为未安装（如权限不足/资源耗尽），绝不按未安装回落默认配置
                saw_binary = true;
            }
        }
    }
    if saw_binary {
        SshdConfigOutcome::Failed
    } else {
        SshdConfigOutcome::NotInstalled
    }
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

    #[test]
    fn split_options_enforces_count_and_length_limits() {
        let many = (0..100)
            .map(|i| format!("opt{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let parsed = split_options(&many).unwrap();
        assert_eq!(parsed.len(), MAX_OPTIONS_PER_KEY);
        assert_eq!(parsed[0], "opt0");
        assert_eq!(parsed[MAX_OPTIONS_PER_KEY - 1], "opt63");

        let huge = format!("command=\"{}\"", "a".repeat(2000));
        let parsed = split_options(&huge).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].len() <= MAX_OPTION_BYTES);
        assert!(parsed[0].chars().count() <= MAX_OPTION_CHARS);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_child_stdout_handles_large_output_without_deadlock_and_times_out() {
        use std::process::{Command, Stdio};

        // 输出 128 KiB（超过默认 64 KiB 管道缓冲），验证并发读线程不死锁且按上限截断并标记 truncated
        let child = Command::new("sh")
            .args(["-c", "head -c 131072 /dev/zero | tr '\\0' 'a'"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let (out, truncated) =
            read_child_stdout_checked(child, Duration::from_secs(5), 1024).unwrap();
        assert_eq!(out.len(), 1024);
        assert!(truncated, "超上限输出应明确标记截断");

        // sshd -T 输出被截断时 read_child_stdout_with_timeout 必须返回 None，视为无效输出
        let truncated_child = Command::new("sh")
            .args(["-c", "head -c 4096 /dev/zero | tr '\\0' 'a'"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        assert!(
            read_child_stdout_with_timeout(truncated_child, Duration::from_secs(5), 1024).is_none(),
            "被截断的 sshd -T 输出应返回 None，不得拿残缺配置覆盖可信配置"
        );

        // 超时子进程应被及时终止返回 None
        let started = std::time::Instant::now();
        let slow = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        assert!(read_child_stdout_with_timeout(slow, Duration::from_millis(150), 1024).is_none());
        assert!(started.elapsed() < Duration::from_secs(3));

        // 父进程立刻退出但后代进程仍持 stdout 写端 sleep 30，验证在 deadline 内准时返回不挂死
        let started = std::time::Instant::now();
        let leaky = Command::new("sh")
            .args(["-c", "sleep 30 &"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        assert!(read_child_stdout_with_timeout(leaky, Duration::from_millis(200), 1024).is_none());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "后代持有 stdout 写端时应在 deadline 内返回不挂死，实际耗时 {:?}",
            started.elapsed()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn snapshot_protobuf_budget_caps_frame_under_3_mib() {
        // 构造 600 条合法但选项很长的条目（单条约 16 KiB，总量 ~9.6 MiB >> 4 MiB gRPC 默认上限）
        let long_opts: Vec<String> = (0..MAX_OPTIONS_PER_KEY)
            .map(|j| format!("from=\"{}\"", "1".repeat(240 - (j % 10))))
            .collect();
        let entries: Vec<KeyEntry> = (0..600)
            .map(|i| KeyEntry {
                account: format!("user{i}"),
                path: format!("/home/user{i}/.ssh/authorized_keys"),
                key_type: "ssh-ed25519".into(),
                fingerprint: format!("SHA256:{i:043}"),
                comment: "c".repeat(MAX_COMMENT_CHARS),
                options: long_opts.clone(),
            })
            .collect();

        let base = base_request_bytes("/usr/local/bin/fetch-keys", "nobody");
        let (kept, truncated) = pack_keys_within_budget(entries, base, MAX_SNAPSHOT_BYTES);
        assert!(truncated, "总量超过 3 MiB 时必须触发截断");
        assert!(!kept.is_empty(), "截断后应保留预算内的合法条目");
        assert!(kept.len() < 600);

        let snap = Snapshot {
            observed_at_ms: 1_700_000_000_000,
            keys: kept.clone(),
            authorized_keys_command: "/usr/local/bin/fetch-keys".into(),
            authorized_keys_command_user: "nobody".into(),
            truncated,
        };
        assert!(
            build_report_request("agent-host-01", snap).is_none(),
            "截断快照必须暂缓上报（返回 None），避免服务端将尾部钥匙误标为 present=false"
        );

        // 未标记 truncated 但实际编码体积超出 3 MiB 时同样不得上报
        let oversized = Snapshot {
            observed_at_ms: 1_700_000_000_000,
            keys: (0..400)
                .map(|i| KeyEntry {
                    account: format!("user{i}"),
                    path: format!("/home/user{i}/.ssh/authorized_keys"),
                    key_type: "ssh-ed25519".into(),
                    fingerprint: format!("SHA256:{i:043}"),
                    comment: "c".repeat(MAX_COMMENT_CHARS),
                    options: long_opts.clone(),
                })
                .collect(),
            authorized_keys_command: "/usr/local/bin/fetch-keys".into(),
            authorized_keys_command_user: "nobody".into(),
            truncated: false,
        };
        assert!(
            build_report_request("agent-host-01", oversized).is_none(),
            "编码体积超过 3 MiB 上限时必须暂缓上报（返回 None）"
        );

        // 完整且在预算内的快照正常组装上报请求
        let complete_snap = Snapshot {
            observed_at_ms: 1_700_000_000_000,
            keys: kept,
            authorized_keys_command: "/usr/local/bin/fetch-keys".into(),
            authorized_keys_command_user: "nobody".into(),
            truncated: false,
        };
        let req = build_report_request("agent-host-01", complete_snap)
            .expect("完整且在预算内的快照应正常组装上报请求");
        assert!(
            req.encoded_len() <= MAX_SNAPSHOT_BYTES,
            "单帧 protobuf 编码体积 {} 超过 3 MiB 预算 {}",
            req.encoded_len(),
            MAX_SNAPSHOT_BYTES
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sshd_config_distinguishes_not_installed_from_failed_and_preserves_trusted() {
        use std::os::unix::fs::PermissionsExt;

        let dir =
            std::env::temp_dir().join(format!("openxdr-sshkeys-cfg-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let make_script = |name: &str, body: &str| -> String {
            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path.to_string_lossy().into_owned()
        };

        let missing = dir.join("no-such-sshd").to_string_lossy().into_owned();
        let custom_sshd = make_script(
            "custom-sshd",
            "printf 'authorizedkeysfile /etc/ssh/custom_keys/%%u\\nauthorizedkeyscommand /usr/local/bin/ak %%u\\n'",
        );
        let truncated_sshd = make_script("truncated-sshd", "head -c 4096 /dev/zero | tr '\\0' 'a'");
        let failing_sshd = make_script("failing-sshd", "exit 1");

        // 1. 所有候选均不存在 -> NotInstalled，允许使用默认路径
        let not_installed =
            read_sshd_config_from(&[missing.as_str()], Duration::from_secs(2), 1024);
        assert_eq!(not_installed, SshdConfigOutcome::NotInstalled);
        let mut last_trusted = None;
        assert_eq!(
            resolve_sshd_config(not_installed, &mut last_trusted),
            Some(SshdKeyConfig::default())
        );

        // 2. 从未取得过可信配置且 sshd -T 失败/截断 -> 必须暂缓上报（返回 None），绝不回落默认
        let trunc_out =
            read_sshd_config_from(&[truncated_sshd.as_str()], Duration::from_secs(2), 1024);
        assert_eq!(trunc_out, SshdConfigOutcome::Failed);
        let mut fresh_trusted = None;
        assert_eq!(
            resolve_sshd_config(trunc_out, &mut fresh_trusted),
            None,
            "从未成功且 sshd -T 截断时必须暂缓上报"
        );
        let fail_out =
            read_sshd_config_from(&[failing_sshd.as_str()], Duration::from_secs(2), 1024);
        assert_eq!(fail_out, SshdConfigOutcome::Failed);
        assert_eq!(
            resolve_sshd_config(fail_out, &mut fresh_trusted),
            None,
            "从未成功且 sshd -T 报错时必须暂缓上报"
        );

        // 3. 已有可信自定义配置后，sshd -T 截断或报错 -> 保留上次可信自定义配置，绝不回落默认
        let parsed_out =
            read_sshd_config_from(&[custom_sshd.as_str()], Duration::from_secs(2), 1024);
        let expected_custom = SshdKeyConfig {
            authorized_keys_files: vec!["/etc/ssh/custom_keys/%u".into()],
            authorized_keys_command: "/usr/local/bin/ak %u".into(),
            authorized_keys_command_user: String::new(),
        };
        assert_eq!(
            parsed_out,
            SshdConfigOutcome::Parsed(expected_custom.clone())
        );

        let mut trusted = None;
        assert_eq!(
            resolve_sshd_config(parsed_out, &mut trusted),
            Some(expected_custom.clone())
        );

        let trunc_again =
            read_sshd_config_from(&[truncated_sshd.as_str()], Duration::from_secs(2), 1024);
        assert_eq!(trunc_again, SshdConfigOutcome::Failed);
        assert_eq!(
            resolve_sshd_config(trunc_again, &mut trusted),
            Some(expected_custom.clone()),
            "已有可信自定义配置时，sshd -T 截断必须保留上次配置"
        );

        let fail_again =
            read_sshd_config_from(&[failing_sshd.as_str()], Duration::from_secs(2), 1024);
        assert_eq!(fail_again, SshdConfigOutcome::Failed);
        assert_eq!(
            resolve_sshd_config(fail_again, &mut trusted),
            Some(expected_custom),
            "已有可信自定义配置时，sshd -T 报错必须保留上次配置"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn watch_changes_exits_cleanly_when_sink_closes() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let make_sink = || {
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            let sink = super::super::EventSink {
                tx,
                dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                health: crate::health::Health::new(),
                generation: 0,
            };
            (sink, rx)
        };

        // 1. 等待变更信号期间 sink 关闭：任务立即退出，不抢走后续通知
        let signal = Arc::new(tokio::sync::Notify::new());
        let state = Arc::new(State::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let (sink1, rx1) = make_sink();
        let handle = {
            let signal = signal.clone();
            let state = state.clone();
            let calls = calls.clone();
            tokio::spawn(async move {
                watch_changes(
                    &sink1,
                    &state,
                    &signal,
                    Duration::from_millis(50),
                    None,
                    |trusted| {
                        let calls = calls.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            (trusted, None)
                        }
                    },
                )
                .await;
            })
        };
        tokio::task::yield_now().await;
        drop(rx1);
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("sink 关闭后任务应及时退出")
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // 2. 防抖睡眠期间 sink 关闭：醒来后直接退出，不再触发采集
        let (sink2, rx2) = make_sink();
        let handle2 = {
            let signal = signal.clone();
            let state = state.clone();
            let calls = calls.clone();
            tokio::spawn(async move {
                watch_changes(
                    &sink2,
                    &state,
                    &signal,
                    Duration::from_millis(80),
                    None,
                    |trusted| {
                        let calls = calls.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            (trusted, None)
                        }
                    },
                )
                .await;
            })
        };
        tokio::task::yield_now().await;
        signal.notify_one();
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(rx2);
        tokio::time::timeout(Duration::from_secs(1), handle2)
            .await
            .expect("防抖期间 sink 关闭后任务应退出")
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
