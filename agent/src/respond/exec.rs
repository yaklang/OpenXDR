//! 命令执行：平台下发什么就执行什么，放行与审批全部在平台侧判定。
//!
//! 一次性执行、带超时、输出截断，不支持交互。Linux 交给 `sh -c`，Windows 交给
//! PowerShell。注意：后台子进程若继承了输出管道（`cmd &` 不重定向），读端会一直
//! 等到超时——与 ssh 的行为一致。

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command as Proc};

use super::{Outcome, Output};
use crate::pb::{Command, command_result::Status};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// 单条命令允许的最长执行时间（1 小时），防误传极大 timeout_ms 导致子进程永久挂起
const MAX_TIMEOUT: Duration = Duration::from_secs(3600);
/// stdout / stderr 各自的保留上限。超出部分照样读掉丢弃，否则刷屏的命令会写满管道卡住
const OUTPUT_LIMIT: usize = 64 * 1024;

pub async fn run(cmd: &Command) -> Outcome {
    if cmd.cmd.is_empty() {
        return Outcome::failed("未指定命令");
    }
    let timeout = timeout_of(cmd.timeout_ms);

    let mut child = match shell(&cmd.cmd)
        // 采集端按它认出指令拉起的进程树（只认 agent 直接子进程上的这个变量，别的进程自己设没用）
        .env(crate::collector::COMMAND_ENV, &cmd.id)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Outcome::failed(format!("启动失败: {e}")),
    };

    let (out, err) = (child.stdout.take(), child.stderr.take());
    let collected = tokio::time::timeout(timeout, async {
        tokio::join!(read_capped(out), read_capped(err), child.wait())
    })
    .await;

    let Ok(((stdout, out_cut), (stderr, err_cut), waited)) = collected else {
        kill_tree(&mut child).await;
        return Outcome::failed(format!("超过 {:?} 未结束，已终止", timeout));
    };
    let code = match waited {
        Ok(status) => status.code().unwrap_or(-1), // 被信号终止没有退出码
        Err(e) => return Outcome::failed(format!("等待进程失败: {e}")),
    };
    Outcome {
        status: Status::Succeeded,
        detail: format!("退出码 {code}"),
        output: Output {
            exit_code: code,
            stdout,
            stderr,
            truncated: out_cut || err_cut,
        },
    }
}

/// 平台给 0 表示没指定，用默认超时；非零值封顶 MAX_TIMEOUT（1 小时）
fn timeout_of(ms: u32) -> Duration {
    match ms {
        0 => DEFAULT_TIMEOUT,
        ms => Duration::from_millis(ms.into()).min(MAX_TIMEOUT),
    }
}

/// 读完整个流，只保留前 OUTPUT_LIMIT 字节。
async fn read_capped(stream: Option<impl AsyncRead + Unpin>) -> (String, bool) {
    let Some(mut stream) = stream else {
        return (String::new(), false);
    };
    let (mut kept, mut cut, mut buf) = (Vec::new(), false, [0u8; 8192]);
    while let Ok(n @ 1..) = stream.read(&mut buf).await {
        let room = OUTPUT_LIMIT - kept.len();
        kept.extend_from_slice(&buf[..n.min(room)]);
        cut |= n > room;
    }
    (String::from_utf8_lossy(&kept).into_owned(), cut)
}

#[cfg(unix)]
fn shell(line: &str) -> Proc {
    let mut c = Proc::new("sh");
    // 独立进程组，超时时整组杀掉，不留孤儿
    c.arg("-c").arg(line).process_group(0);
    c
}

#[cfg(windows)]
fn shell(line: &str) -> Proc {
    let mut c = Proc::new("powershell.exe");
    // 中文 Windows 控制台默认 GBK，强制 UTF-8 输出，否则回传的是乱码
    let script = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; {line}");
    c.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    c
}

/// Windows 上只杀 PowerShell 本身，它拉起的子进程不随之结束（原型阶段可接受）。
async fn kill_tree(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: kill 只读取参数；负 pid 表示整个进程组
        unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
    }
    let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    /// 按固定块大小吐数据、可选在末尾报错的读端，用来覆盖跨块截断与读错误
    struct Chunked {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
        fail_at_end: bool,
    }

    impl Chunked {
        fn new(data: Vec<u8>, chunk: usize) -> Self {
            Self {
                data,
                pos: 0,
                chunk,
                fail_at_end: false,
            }
        }
    }

    impl AsyncRead for Chunked {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.pos == self.data.len() && self.fail_at_end {
                return Poll::Ready(Err(io::Error::other("管道断了")));
            }
            let n = self
                .chunk
                .min(buf.remaining())
                .min(self.data.len() - self.pos);
            let start = self.pos;
            buf.put_slice(&self.data[start..start + n]);
            self.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn zero_timeout_falls_back_to_default_and_caps_at_max() {
        assert_eq!(timeout_of(0), DEFAULT_TIMEOUT);
        assert_eq!(timeout_of(1), Duration::from_millis(1));
        assert_eq!(timeout_of(1500), Duration::from_millis(1500));
        assert_eq!(timeout_of(3_600_000), MAX_TIMEOUT);
        // 超出 1 小时上限（含 u32::MAX 约 49.7 天）一律封顶 1 小时，防永久挂起
        assert_eq!(timeout_of(3_600_001), MAX_TIMEOUT);
        assert_eq!(timeout_of(u32::MAX), MAX_TIMEOUT);
    }

    #[tokio::test]
    async fn missing_stream_is_empty() {
        let none: Option<&[u8]> = None;
        assert_eq!(read_capped(none).await, (String::new(), false));
    }

    #[tokio::test]
    async fn empty_stream_is_not_truncated() {
        assert_eq!(read_capped(Some(&b""[..])).await, (String::new(), false));
    }

    #[tokio::test]
    async fn exactly_at_limit_is_not_truncated() {
        let data = vec![b'a'; OUTPUT_LIMIT];
        let (kept, cut) = read_capped(Some(&data[..])).await;
        assert_eq!(kept.len(), OUTPUT_LIMIT);
        assert!(!cut);
    }

    #[tokio::test]
    async fn one_byte_over_limit_is_truncated() {
        let data = vec![b'a'; OUTPUT_LIMIT + 1];
        let (kept, cut) = read_capped(Some(&data[..])).await;
        assert_eq!(kept.len(), OUTPUT_LIMIT);
        assert!(cut);
    }

    #[tokio::test]
    async fn limit_falling_inside_a_chunk_keeps_prefix() {
        // 5000 不整除 64 KiB，上限落在某次 read 的中间
        let data: Vec<u8> = (0..OUTPUT_LIMIT * 2)
            .map(|i| b'a' + (i % 26) as u8)
            .collect();
        let (kept, cut) = read_capped(Some(Chunked::new(data.clone(), 5000))).await;
        assert!(cut);
        assert_eq!(kept.as_bytes(), &data[..OUTPUT_LIMIT]);
    }

    #[tokio::test]
    async fn read_error_keeps_what_was_read() {
        let mut r = Chunked::new(b"partial".to_vec(), 3);
        r.fail_at_end = true;
        assert_eq!(read_capped(Some(r)).await, ("partial".to_string(), false));
    }

    #[tokio::test]
    async fn invalid_utf8_is_replaced() {
        let (kept, cut) = read_capped(Some(&b"ok\xff\xfe"[..])).await;
        assert_eq!(kept, "ok\u{fffd}\u{fffd}");
        assert!(!cut);
    }

    #[tokio::test]
    async fn truncation_may_split_a_multibyte_char() {
        // 截断按字节算，切在多字节字符中间时尾部变成替换字符而不是 panic
        let mut data = vec![b'a'; OUTPUT_LIMIT - 1];
        data.extend_from_slice("中".as_bytes());
        let (kept, cut) = read_capped(Some(&data[..])).await;
        assert!(cut);
        assert!(kept.ends_with('\u{fffd}'));
        assert_eq!(kept.len(), OUTPUT_LIMIT - 1 + '\u{fffd}'.len_utf8());
    }

    #[cfg(unix)]
    #[test]
    fn unix_shell_is_sh_c() {
        let c = shell("echo 'a b' | wc -c");
        let std = c.as_std();
        assert_eq!(std.get_program(), "sh");
        let args: Vec<_> = std.get_args().collect();
        // 命令行整体作为一个参数交给 sh，agent 侧不拆分
        assert_eq!(args, ["-c", "echo 'a b' | wc -c"]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_shell_forces_utf8_powershell() {
        let c = shell("Get-Date");
        let std = c.as_std();
        assert_eq!(std.get_program(), "powershell.exe");
        let args: Vec<_> = std.get_args().collect();
        assert_eq!(
            args,
            [
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-Date",
            ]
        );
    }

    #[cfg(target_os = "linux")]
    fn exec(line: &str) -> Command {
        Command {
            id: "cmd-exec-1".to_string(),
            cmd: line.to_string(),
            ..Default::default()
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn child_sees_command_marker_env() {
        let line = format!("printf %s \"${}\"", crate::collector::COMMAND_ENV);
        let r = run(&exec(&line)).await;
        assert_eq!(r.status, Status::Succeeded);
        assert_eq!(r.output.stdout, "cmd-exec-1");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stdin_is_closed() {
        // stdin 接 /dev/null，读 stdin 的命令立即见到 EOF 而不是挂到超时
        let mut c = exec("cat; echo done");
        c.timeout_ms = 5000;
        let r = run(&c).await;
        assert_eq!(r.status, Status::Succeeded);
        assert_eq!(r.output.stdout, "done\n");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn killed_by_signal_reports_minus_one() {
        let r = run(&exec("kill -KILL $$")).await;
        assert_eq!(r.status, Status::Succeeded);
        assert_eq!(r.output.exit_code, -1);
        assert_eq!(r.detail, "退出码 -1");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stderr_truncation_alone_marks_truncated() {
        let r = run(&exec("head -c 70000 /dev/zero >&2")).await;
        assert_eq!(r.output.stdout, "");
        assert_eq!(r.output.stderr.len(), OUTPUT_LIMIT);
        assert!(r.output.truncated);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timeout_kills_background_children_too() {
        let dir = std::env::temp_dir().join(format!("openxdr-exec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pid_file = dir.join("bg.pid");
        let mut c = exec(&format!(
            "sleep 30 & echo $! > {}; wait",
            pid_file.display()
        ));
        c.timeout_ms = 300;
        let r = run(&c).await;
        assert_eq!(r.status, Status::Failed);
        assert!(r.detail.contains("已终止"));

        // 后台 sleep 与 sh 同组，应一并被 SIGKILL；被 init 收尸前可能短暂停在僵尸态
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        let stat = format!("/proc/{}/stat", pid.trim());
        let running = || {
            std::fs::read_to_string(&stat)
                .map(|s| {
                    !s.rsplit(')')
                        .next()
                        .unwrap_or("")
                        .trim_start()
                        .starts_with('Z')
                })
                .unwrap_or(false)
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while running() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let alive = running();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!alive, "后台子进程没有随进程组被杀");
    }
}
