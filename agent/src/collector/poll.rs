//! 进程轮询采集：每秒 diff 一次进程表。内核级采集不可用时的兜底。
//! 已知短板：1 秒内启动又退出的短命进程会漏掉。

use std::collections::HashSet;
use std::time::Duration;

use super::{EventSink, ProcessInfo, ProcessRegistry, process_event};
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
        for pid in current.difference(&known) {
            let Some(proc) = sys.processes().get(pid) else {
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
                ProcessInfo {
                    pid: pid.as_u32(),
                    name: &proc.name().to_string_lossy(),
                    exe: exe.as_deref(),
                    cmd_line: Some(&cmd_line),
                    ppid: proc.parent().map(|p| p.as_u32()),
                    username: proc.user_id().map(|u| u.to_string()).unwrap_or_default(),
                },
            );

            if !tx.send(event) {
                return; // 上报端已断开，本采集任务随之退出
            }
        }
        known = current;
    }
}
