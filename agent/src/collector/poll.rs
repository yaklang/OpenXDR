//! 进程轮询采集：每秒 diff 一次进程表。内核级采集不可用时的兜底。
//! 已知短板：1 秒内启动又退出的短命进程会漏掉。

use std::collections::HashSet;
use std::time::Duration;

use sysinfo::{ProcessesToUpdate, System};
use tokio::sync::mpsc;

use super::process_event;
use crate::pb::AgentEvent;

const INTERVAL: Duration = Duration::from_secs(1);

pub async fn run(agent_id: String, tx: mpsc::Sender<AgentEvent>) {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut known: HashSet<sysinfo::Pid> = sys.processes().keys().copied().collect();

    loop {
        tokio::time::sleep(INTERVAL).await;
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let current: HashSet<sysinfo::Pid> = sys.processes().keys().copied().collect();
        for pid in current.difference(&known) {
            let Some(proc) = sys.processes().get(pid) else { continue };

            let cmd_line = proc
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            let event = process_event(
                &agent_id,
                pid.as_u32(),
                &proc.name().to_string_lossy(),
                proc.exe().map(|p| p.to_string_lossy().into_owned()).as_deref(),
                Some(&cmd_line),
                proc.parent().map(|p| p.as_u32()),
                proc.user_id().map(|u| u.to_string()).unwrap_or_default(),
            );

            if tx.send(event).await.is_err() {
                return; // 上报端已断开，本采集任务随之退出
            }
        }
        known = current;
    }
}
