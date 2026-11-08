//! 受管主机上的托盘：只显示有限信息——防护在不在、和管理平台联不联得上、本机有没有被隔离。
//! 没有配置界面，也没有停止防护的入口。状态从 agent 的本机只读端点读（见 status_proto），
//! 跑在普通用户的登录会话里，由 agent 布置自启（Linux 桌面的 XDG autostart、Windows 的 HKLM Run）。
#![cfg_attr(windows, windows_subsystem = "windows")]

#[path = "../status_proto.rs"]
#[allow(dead_code)]
mod status_proto;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod platform;

#[cfg(windows)]
#[path = "windows.rs"]
mod platform;

/// 多久问一次 agent
const POLL: std::time::Duration = std::time::Duration::from_secs(15);

/// 当前该显示什么
fn current() -> status_proto::Summary {
    status_proto::describe(status_proto::fetch().as_ref(), status_proto::now_ms())
}

/// 状态变了且变得更要紧（或换成了另一种要紧）才弹通知；回到正常、失联时长变化这类不弹
fn worth_notifying(before: Option<&status_proto::Summary>, now: &status_proto::Summary) -> bool {
    now.level > status_proto::Level::Ok && before.is_none_or(|b| b.title != now.title)
}

#[cfg(any(target_os = "linux", windows))]
fn main() {
    platform::run();
}

#[cfg(not(any(target_os = "linux", windows)))]
fn main() {
    eprintln!("本平台没有托盘");
}

#[cfg(test)]
mod tests {
    use super::*;
    use status_proto::{Level, Summary};

    fn summary(level: Level, title: &'static str) -> Summary {
        Summary {
            level,
            title,
            detail: String::new(),
        }
    }

    #[test]
    fn notify_only_when_something_new_needs_attention() {
        let ok = summary(Level::Ok, "安全防护运行中");
        let lost = summary(Level::Warn, "与管理平台失联");
        let isolated = summary(Level::Alert, "本机已被安全团队隔离");
        assert!(!worth_notifying(None, &ok), "启动时正常不弹");
        assert!(worth_notifying(None, &lost), "启动时就有问题要弹");
        assert!(worth_notifying(Some(&ok), &lost));
        assert!(!worth_notifying(Some(&lost), &lost), "同一状态只弹一次");
        assert!(worth_notifying(Some(&lost), &isolated));
        assert!(!worth_notifying(Some(&isolated), &ok), "恢复正常不弹");
    }
}
