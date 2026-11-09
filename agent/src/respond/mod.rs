//! 响应执行器：接收 server 下发的指令并执行。
//!
//! 这是 agent 里唯一会改变主机状态的部分，收到的指令一律真执行（不再有演练）。
//! 铁律：隔离主机必须放行 server 通道，否则解除隔离的指令再也送不进来。
//!
//! exec 无条件执行平台下发的命令，放行控制在平台侧；但只认 server 指令签名私钥签过的指令（见 signed）。

use crate::pb::{Command, CommandKind, CommandResult, command_result::Status};

mod account;
mod container;
mod exec;
mod execblock;
mod netblock;
mod process;
mod quarantine;
pub mod signed;

#[cfg(target_os = "linux")]
#[path = "isolate_linux.rs"]
mod isolate;

#[cfg(target_os = "windows")]
#[path = "isolate_windows.rs"]
mod isolate;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
#[path = "isolate_unsupported.rs"]
mod isolate;

/// 执行结果：成功与否，加一句人能看懂的说明；exec 另带命令输出。
pub struct Outcome {
    pub status: Status,
    pub detail: String,
    pub output: Output,
}

#[derive(Default)]
pub struct Output {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

impl Outcome {
    fn ok(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Succeeded,
            detail: detail.into(),
            output: Output::default(),
        }
    }
    fn failed(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Failed,
            detail: detail.into(),
            output: Output::default(),
        }
    }
    /// 只有未实现隔离的平台会用到，Linux/Windows 上编译不到
    #[allow(dead_code)]
    fn unsupported(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Unsupported,
            detail: detail.into(),
            output: Output::default(),
        }
    }
}

/// Windows 上的处置动作（防火墙规则、本地账号）走 PowerShell cmdlet：输出不随系统语言变，比解析 netsh 可靠。
/// 调用方负责先校验拼进脚本的参数字符集
#[cfg(target_os = "windows")]
pub(crate) fn powershell(script: &str) -> Result<String, String> {
    let out = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("$ErrorActionPreference='Stop'; {script}"),
        ])
        .output()
        .map_err(|e| format!("无法执行 PowerShell: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// 本机当前是否处于主机隔离（查的是内核里的规则本身，不是内存里的记录：agent 重启后照样说得准）
pub fn host_isolated() -> bool {
    isolate::active()
}

pub async fn execute(agent_id: &str, cmd: &Command) -> CommandResult {
    let outcome = match cmd.kind() {
        CommandKind::KillProcess => process::kill(cmd),
        CommandKind::IsolateHost => isolate::isolate(cmd),
        CommandKind::UnisolateHost => isolate::unisolate(cmd),
        CommandKind::Exec => exec::run(cmd).await,
        CommandKind::BlockNetwork => netblock::block(cmd),
        CommandKind::UnblockNetwork => netblock::unblock(cmd),
        CommandKind::QuarantineFile => quarantine::quarantine(cmd),
        CommandKind::RestoreFile => quarantine::restore(cmd),
        CommandKind::DisableAccount => account::disable(cmd),
        CommandKind::EnableAccount => account::enable(cmd),
        CommandKind::IsolateContainer => container::isolate(cmd),
        CommandKind::UnisolateContainer => container::unisolate(cmd),
        CommandKind::BlockExecution => execblock::block(cmd),
        CommandKind::UnblockExecution => execblock::unblock(cmd),
        CommandKind::Unspecified => Outcome::failed("未指定动作"),
    };

    CommandResult {
        agent_id: agent_id.to_string(),
        command_id: cmd.id.clone(),
        status: outcome.status as i32,
        detail: outcome.detail,
        exit_code: outcome.output.exit_code,
        stdout: outcome.output.stdout,
        stderr: outcome.output.stderr,
        truncated: outcome.output.truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::{Command, CommandKind, command_result::Status};

    fn cmd(kind: CommandKind) -> Command {
        Command {
            id: "cmd-1".to_string(),
            kind: kind as i32,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn unspecified_action_fails() {
        let r = execute("agent-1", &cmd(CommandKind::Unspecified)).await;
        assert_eq!(r.agent_id, "agent-1");
        assert_eq!(r.command_id, "cmd-1");
        assert_eq!(r.status, Status::Failed as i32);
        assert!(r.detail.contains("未指定动作"));
    }

    #[tokio::test]
    async fn kill_without_pid_fails() {
        let r = execute("agent-1", &cmd(CommandKind::KillProcess)).await;
        assert_eq!(r.status, Status::Failed as i32);
        assert!(r.detail.contains("未指定 pid"));
    }

    #[tokio::test]
    async fn kill_missing_pid_fails() {
        let mut c = cmd(CommandKind::KillProcess);
        c.pid = 999_999_999; // 远超 pid_max，必然不存在
        let r = execute("agent-1", &c).await;
        assert_eq!(r.status, Status::Failed as i32);
        assert!(r.detail.contains("不存在"));
    }

    // 依赖 Linux 的隔离实现（macOS 上隔离为 unsupported）
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn isolate_without_allowlist_refused() {
        // 铁律：不放行 server 通道就隔离，等于自锁，之后收不到解除指令
        let r = execute("agent-1", &cmd(CommandKind::IsolateHost)).await;
        assert_eq!(r.status, Status::Failed as i32);
        assert!(r.detail.contains("拒绝"));
        assert!(r.detail.contains("放行"));
    }

    fn exec(line: &str) -> Command {
        let mut c = cmd(CommandKind::Exec);
        c.cmd = line.to_string();
        c
    }

    #[tokio::test]
    async fn exec_without_cmd_fails() {
        let r = execute("agent-1", &exec("")).await;
        assert_eq!(r.status, Status::Failed as i32);
        assert!(r.detail.contains("未指定命令"));
    }

    // 以下用例依赖 sh 语义
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn exec_captures_output_and_exit_code() {
        let r = execute("agent-1", &exec("echo out; echo err >&2; exit 3")).await;
        assert_eq!(r.status, Status::Succeeded as i32);
        assert_eq!(r.exit_code, 3);
        assert_eq!(r.stdout, "out\n");
        assert_eq!(r.stderr, "err\n");
        assert!(!r.truncated);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn exec_truncates_large_output() {
        let r = execute("agent-1", &exec("head -c 200000 /dev/zero")).await;
        assert_eq!(r.exit_code, 0);
        assert_eq!(r.stdout.len(), 64 * 1024);
        assert!(r.truncated);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn exec_timeout_kills_process_group() {
        let mut c = exec("sleep 30 & sleep 30");
        c.timeout_ms = 200;
        let started = std::time::Instant::now();
        let r = execute("agent-1", &c).await;
        assert_eq!(r.status, Status::Failed as i32);
        assert!(r.detail.contains("已终止"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
