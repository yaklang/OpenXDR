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
