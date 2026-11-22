//! 进程轮询采集：每秒 diff 一次进程表。内核级采集不可用时的兜底。
//! 已知短板：1 秒内启动又退出的短命进程会漏掉。

use std::collections::HashSet;
use std::time::Duration;

use super::{
    ACTIVITY_LAUNCH, ACTIVITY_TERMINATE, EventSink, ProcessInfo, ProcessRegistry, emit_process,
};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const INTERVAL: Duration = Duration::from_secs(1);

pub async fn run(agent_id: String, tx: EventSink) {
    tx.capability("process", "poll", "degraded");
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
    for (pid, proc) in sys.processes() {
        let exe = proc.exe().map(|p| p.to_string_lossy().into_owned());
        registry.seed(pid.as_u32(), &proc.name().to_string_lossy(), exe.as_deref());
    }

    while !tx.is_closed() {
        tokio::time::sleep(INTERVAL).await;
        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);

        let current: HashSet<sysinfo::Pid> = sys.processes().keys().copied().collect();
        let (mut appeared, gone) = diff(&known, &current);
        // 同一轮里父子都是新进程时先处理父：子进程才找得到父 GUID，也才能参与周期折叠。
        // 按「在本轮新进程里有几层祖先」排序，不依赖 pid 大小（pid 会回绕）
        let fresh: HashSet<sysinfo::Pid> = appeared.iter().copied().collect();
        appeared.sort_by_key(|pid| depth(&sys, &fresh, *pid));
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
            let pid_u32 = pid.as_u32();
            let ppid = proc.parent().map(|p| p.as_u32());
            let name = proc.name().to_string_lossy().into_owned();
            // 避免在 Tokio worker 线程同步读大文件或 sleep 等 sshd 日志
            #[cfg(target_os = "linux")]
            let resolved_exe = super::resolve_launch_exe(pid_u32, exe.as_deref(), &name);
            #[cfg(not(target_os = "linux"))]
            let resolved_exe: Option<String> = None;
            let eff_exe = resolved_exe.as_deref().or(exe.as_deref());
            let exe_sha256 = match eff_exe {
                Some(p) => super::hash::exe_sha256_async(p).await,
                None => None,
            };
            #[cfg(target_os = "linux")]
            let login =
                super::LoginProbe::from_of(super::sshsession::of_async(pid_u32, ppid).await);
            #[cfg(not(target_os = "linux"))]
            let login = super::LoginProbe::Unprobed;

            let events = emit_process(
                &agent_id,
                &mut registry,
                ACTIVITY_LAUNCH,
                ProcessInfo {
                    pid: pid_u32,
                    name: &name,
                    exe: eff_exe,
                    cmd_line: Some(&cmd_line),
                    ppid,
                    username: proc.user_id().map(|u| u.to_string()).unwrap_or_default(),
                    exe_sha256: Some(exe_sha256),
                    login,
                    ..Default::default()
                },
            );

            for event in events {
                if !tx.send(event) {
                    return; // 上报端已断开，本采集任务随之退出
                }
            }
        }

        // 消失的 pid 即进程退出。进程已退场，名字与路径从启动时的登记补上
        for pid in gone {
            let pid_u32 = pid.as_u32();
            let exe_sha256 = match registry.known(pid_u32).and_then(|k| k.exe) {
                Some(p) => super::hash::exe_sha256_async(&p).await,
                None => None,
            };
            let events = emit_process(
                &agent_id,
                &mut registry,
                ACTIVITY_TERMINATE,
                ProcessInfo {
                    pid: pid_u32,
                    exe_sha256: Some(exe_sha256),
                    ..Default::default()
                },
            );
            for event in events {
                if !tx.send(event) {
                    return;
                }
            }
        }
        known = current;
    }
}

/// pid 往上有几层祖先也在本轮新进程里（封顶防环）
fn depth(sys: &System, fresh: &HashSet<sysinfo::Pid>, pid: sysinfo::Pid) -> usize {
    let mut n = 0;
    let mut cur = sys.processes().get(&pid).and_then(|p| p.parent());
    while let Some(p) = cur
        && fresh.contains(&p)
        && n < 64
    {
        n += 1;
        cur = sys.processes().get(&p).and_then(|q| q.parent());
    }
    n
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
    use super::super::process_event;
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

    /// 退出时只剩 pid：GUID、名字与路径都复用启动时的登记，activity_id=2。
    #[test]
    fn gone_pid_reuses_launch_identity() {
        let mut reg = ProcessRegistry::default();
        let launch = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_LAUNCH,
            ProcessInfo {
                pid: 42,
                name: "bash",
                exe: Some("/usr/bin/bash"),
                ..Default::default()
            },
        )
        .unwrap();
        let exit = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_TERMINATE,
            ProcessInfo {
                pid: 42,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(exit.process_guid, launch.process_guid);
        let v: serde_json::Value = serde_json::from_str(&exit.raw_json).unwrap();
        assert_eq!(v["activity_id"], 2);
        assert_eq!(v["process"]["pid"], 42);
        assert_eq!(v["process"]["name"], "bash");
        assert_eq!(v["process"]["file"]["path"], "/usr/bin/bash");
        assert!(v["process"]["exit_code"].is_null());
    }

    /// 没见过启动、也不在快照里的进程退出：配不上启动事件，说不出是谁，不上报。
    #[test]
    fn unknown_exit_is_dropped() {
        let mut reg = ProcessRegistry::default();
        let exit = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_TERMINATE,
            ProcessInfo {
                pid: 4242,
                ..Default::default()
            },
        );
        assert!(exit.is_none());
    }
}
