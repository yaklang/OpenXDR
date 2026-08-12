//! 响应执行器：接收 server 下发的指令并执行。
//!
//! 这是 agent 里唯一会改变主机状态的部分，两条铁律：
//!   - dry_run 只报告"将会做什么"，绝不产生任何实际影响
//!   - 隔离主机必须放行 server 通道，否则解除隔离的指令再也送不进来

use crate::pb::{Command, CommandKind, CommandResult, command_result::Status};

mod process;

#[cfg(target_os = "linux")]
#[path = "isolate_linux.rs"]
mod isolate;

#[cfg(target_os = "windows")]
#[path = "isolate_windows.rs"]
mod isolate;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
#[path = "isolate_unsupported.rs"]
mod isolate;

/// 执行结果：成功与否，加一句人能看懂的说明。
pub struct Outcome {
    pub status: Status,
    pub detail: String,
}

impl Outcome {
    fn ok(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Succeeded,
            detail: detail.into(),
        }
    }
    fn failed(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Failed,
            detail: detail.into(),
        }
    }
    /// 只有未实现隔离的平台会用到，Linux/Windows 上编译不到
    #[allow(dead_code)]
    fn unsupported(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Unsupported,
            detail: detail.into(),
        }
    }
}

pub fn execute(agent_id: &str, cmd: &Command) -> CommandResult {
    let outcome = match cmd.kind() {
        CommandKind::KillProcess => process::kill(cmd),
        CommandKind::IsolateHost => isolate::isolate(cmd),
        CommandKind::UnisolateHost => isolate::unisolate(cmd),
        CommandKind::Unspecified => Outcome::failed("未指定动作"),
    };

    CommandResult {
        agent_id: agent_id.to_string(),
        command_id: cmd.id.clone(),
        status: outcome.status as i32,
        detail: outcome.detail,
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
            dry_run: false,
            process_guid: String::new(),
            pid: 0,
            allow_endpoints: Vec::new(),
        }
    }

    #[test]
    fn unspecified_action_fails() {
        let r = execute("agent-1", &cmd(CommandKind::Unspecified));
        assert_eq!(r.agent_id, "agent-1");
        assert_eq!(r.command_id, "cmd-1");
        assert_eq!(r.status, Status::Failed as i32);
        assert!(r.detail.contains("未指定动作"));
    }

    #[test]
    fn kill_without_pid_fails() {
        let r = execute("agent-1", &cmd(CommandKind::KillProcess));
        assert_eq!(r.status, Status::Failed as i32);
        assert!(r.detail.contains("未指定 pid"));
    }

    #[test]
    fn kill_missing_pid_fails() {
        let mut c = cmd(CommandKind::KillProcess);
        c.pid = 999_999_999; // 远超 pid_max，必然不存在
        let r = execute("agent-1", &c);
        assert_eq!(r.status, Status::Failed as i32);
        assert!(r.detail.contains("不存在"));
    }

    // 以下用例依赖 Linux 的 /proc 与 nft 语义（CI 即 Linux，macOS 上隔离为 unsupported）
    #[cfg(target_os = "linux")]
    #[test]
    fn kill_dry_run_uses_own_pid() {
        // dry-run 不会真杀进程，用测试进程自己的 pid 保证 /proc 下可读
        let mut c = cmd(CommandKind::KillProcess);
        c.dry_run = true;
        c.pid = std::process::id();
        let r = execute("agent-1", &c);
        assert_eq!(r.status, Status::Succeeded as i32);
        assert!(r.detail.contains("dry-run"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn isolate_without_allowlist_refused() {
        // 铁律：不放行 server 通道就隔离，等于自锁，之后收不到解除指令
        let r = execute("agent-1", &cmd(CommandKind::IsolateHost));
        assert_eq!(r.status, Status::Failed as i32);
        assert!(r.detail.contains("拒绝"));
        assert!(r.detail.contains("放行"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn isolate_dry_run_reports_without_effect() {
        let mut c = cmd(CommandKind::IsolateHost);
        c.dry_run = true;
        c.allow_endpoints = vec!["10.0.0.1:443".to_string()];
        let r = execute("agent-1", &c);
        assert_eq!(r.status, Status::Succeeded as i32);
        assert!(r.detail.contains("dry-run"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unisolate_dry_run_reports() {
        let mut c = cmd(CommandKind::UnisolateHost);
        c.dry_run = true;
        let r = execute("agent-1", &c);
        assert_eq!(r.status, Status::Succeeded as i32);
        assert!(r.detail.contains("dry-run"));
    }
}
