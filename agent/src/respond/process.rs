//! 使用 GUID 与创建时间验证身份，并通过稳定的系统句柄结束同一个进程实例。
use super::Outcome;
use crate::{pb::Command, process_identity};

pub fn kill(cmd: &Command) -> Outcome {
    if cmd.pid == 0 {
        return Outcome::failed("未指定 pid");
    }
    if cmd.pid == 1 || cmd.pid == std::process::id() {
        return Outcome::failed(format!("拒绝结束受保护进程 {}", cmd.pid));
    }
    let target = match process_identity::verified(cmd.pid, &cmd.process_guid) {
        Ok(target) => target,
        Err(e) => return Outcome::failed(e),
    };
    match target.terminate() {
        Ok(()) => Outcome::ok(format!("已结束进程 {}", cmd.pid)),
        Err(e) => Outcome::failed(format!("结束进程 {} 失败: {e}", cmd.pid)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::command_result::Status;

    #[test]
    fn refuses_init_and_self_pid() {
        for pid in [1, std::process::id()] {
            let cmd = Command {
                pid,
                process_guid: uuid::Uuid::new_v4().to_string(),
                ..Default::default()
            };
            let outcome = kill(&cmd);
            assert_eq!(outcome.status, Status::Failed);
            assert!(
                outcome.detail.contains("受保护进程"),
                "PID {pid} 应被拒绝：{}",
                outcome.detail
            );
        }
    }
}
