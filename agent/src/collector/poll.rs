//! 进程轮询采集：每秒 diff 一次进程表。内核级采集不可用时的兜底。
//! 已知短板：1 秒内启动又退出的短命进程会漏掉。

use std::collections::HashSet;
use std::time::Duration;

use super::{
    ACTIVITY_LAUNCH, ACTIVITY_TERMINATE, EventSink, ProcessInfo, ProcessRegistry, process_event,
};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const INTERVAL: Duration = Duration::from_secs(1);

pub async fn run(agent_id: String, tx: EventSink) {
    // 默认刷新不含命令行/可执行路径/用户，检测规则全靠这几项，必须显式要
    let kind = ProcessRefreshKind::nothing()
        .with_cmd(UpdateKind::Always)
        .with_exe(UpdateKind::Always)
        .with_user(UpdateKind::Always);

    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    let mut known: HashSet<sysinfo::Pid> = sys.processes().keys().copied().collect();

    // 已存在的进程先登记，之后它们派生的子进程才能找到父
    let mut registry = ProcessRegistry::default();
    for pid in &known {
        registry.seed(pid.as_u32());
    }

    loop {
        tokio::time::sleep(INTERVAL).await;
        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);

        let current: HashSet<sysinfo::Pid> = sys.processes().keys().copied().collect();
        let (appeared, gone) = diff(&known, &current);
        for pid in appeared {
            let Some(proc) = sys.processes().get(&pid) else {
                continue;
            };

            let cmd_line = proc
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            let exe = proc.exe().map(|p| p.to_string_lossy().into_owned());
            let event = process_event(
                &agent_id,
                &mut registry,
                ACTIVITY_LAUNCH,
                ProcessInfo {
                    pid: pid.as_u32(),
                    name: &proc.name().to_string_lossy(),
                    exe: exe.as_deref(),
                    cmd_line: Some(&cmd_line),
                    ppid: proc.parent().map(|p| p.as_u32()),
                    username: proc.user_id().map(|u| u.to_string()).unwrap_or_default(),
                    ..Default::default()
                },
            );

            if !tx.send(event) {
                return; // 上报端已断开，本采集任务随之退出
            }
        }

        // 消失的 pid 即进程退出。进程已退场，除 pid 外无从补全，
        // 其余字段留空；GUID 走注册表复用启动时的映射
        for pid in gone {
            let event = process_event(
                &agent_id,
                &mut registry,
                ACTIVITY_TERMINATE,
                ProcessInfo {
                    pid: pid.as_u32(),
                    ..Default::default()
                },
            );
            if !tx.send(event) {
                return;
            }
        }
        known = current;
    }
}

/// 进程表 diff：本轮新增与消失的 pid。纯函数，方便单测。
fn diff(
    known: &HashSet<sysinfo::Pid>,
    current: &HashSet<sysinfo::Pid>,
) -> (Vec<sysinfo::Pid>, Vec<sysinfo::Pid>) {
    (
        current.difference(known).copied().collect(),
        known.difference(current).copied().collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// diff 同时识别新增与消失：消失的 pid 就是退出事件的来源。
    #[test]
    fn diff_finds_appeared_and_gone() {
        let known: HashSet<sysinfo::Pid> = [100, 200, 300]
            .into_iter()
            .map(sysinfo::Pid::from_u32)
            .collect();
        let current: HashSet<sysinfo::Pid> = [200, 300, 400]
            .into_iter()
            .map(sysinfo::Pid::from_u32)
            .collect();

        let (appeared, gone) = diff(&known, &current);
        assert_eq!(appeared, vec![sysinfo::Pid::from_u32(400)]);
        assert_eq!(gone, vec![sysinfo::Pid::from_u32(100)]);
    }

    /// 两轮进程表一致时 diff 为空，不产生任何事件。
    #[test]
    fn diff_stable_table_is_empty() {
        let pids: HashSet<sysinfo::Pid> =
            [1, 2, 3].into_iter().map(sysinfo::Pid::from_u32).collect();
        let (appeared, gone) = diff(&pids, &pids);
        assert!(appeared.is_empty());
        assert!(gone.is_empty());
    }

    /// 退出事件只有 pid：GUID 复用启动时的登记，activity_id=2。
    #[test]
    fn gone_pid_yields_bare_terminate_event() {
        let mut reg = ProcessRegistry::default();
        let launch = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_LAUNCH,
            ProcessInfo {
                pid: 42,
                name: "bash",
                ..Default::default()
            },
        );
        let exit = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_TERMINATE,
            ProcessInfo {
                pid: 42,
                ..Default::default()
            },
        );
        assert_eq!(exit.process_guid, launch.process_guid);
        let v: serde_json::Value = serde_json::from_str(&exit.raw_json).unwrap();
        assert_eq!(v["activity_id"], 2);
        assert_eq!(v["process"]["pid"], 42);
        assert_eq!(v["process"]["name"], "");
        assert!(v["process"]["exit_code"].is_null());
    }
}
