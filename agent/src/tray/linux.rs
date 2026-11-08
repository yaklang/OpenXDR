//! Linux 托盘：freedesktop StatusNotifierItem（D-Bus，KDE、Xfce 等原生支持，GNOME 要装 AppIndicator 扩展），
//! 不依赖 GTK。通知走 org.freedesktop.Notifications。桌面不支持就安静退出，不反复重试。

use crate::status_proto::{Level, Summary};
use crate::{POLL, current, worth_notifying};
use ksni::TrayMethods;

struct Tray(Summary);

fn icon(level: Level) -> &'static str {
    match level {
        Level::Ok => "security-high",
        Level::Warn => "security-medium",
        Level::Alert => "security-low",
    }
}

impl ksni::Tray for Tray {
    fn id(&self) -> String {
        "openxdr".into()
    }

    fn title(&self) -> String {
        "OpenXDR".into()
    }

    fn icon_name(&self) -> String {
        icon(self.0.level).into()
    }

    fn status(&self) -> ksni::Status {
        match self.0.level {
            Level::Alert => ksni::Status::NeedsAttention,
            _ => ksni::Status::Active,
        }
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: self.0.title.into(),
            description: self.0.detail.clone(),
            ..Default::default()
        }
    }

    /// 菜单只是把状态再说一遍，没有可点的操作
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        [self.0.title.to_string(), self.0.detail.clone()]
            .into_iter()
            .map(|label| {
                ksni::menu::StandardItem {
                    label,
                    enabled: false,
                    ..Default::default()
                }
                .into()
            })
            .collect()
    }
}

/// 同一个用户会话只跑一个托盘：XDG_RUNTIME_DIR 下的文件锁，进程退出自动释放
fn single_instance() -> Option<std::fs::File> {
    use std::os::fd::AsRawFd;
    let dir = std::env::var_os("XDG_RUNTIME_DIR")?;
    let file = std::fs::File::create(std::path::Path::new(&dir).join("openxdr-tray.lock")).ok()?;
    // SAFETY: fd 来自上面打开、由 file 持有的文件，调用期间有效
    (unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0).then_some(file)
}

async fn notify(s: &Summary) {
    let Ok(conn) = zbus::Connection::session().await else {
        return;
    };
    let hints: std::collections::HashMap<&str, zbus::zvariant::Value<'_>> = Default::default();
    let _ = conn
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "OpenXDR",
                0u32,
                icon(s.level),
                s.title,
                s.detail.as_str(),
                Vec::<&str>::new(),
                hints,
                -1i32,
            ),
        )
        .await;
}

async fn fetch() -> Summary {
    tokio::task::spawn_blocking(current)
        .await
        .unwrap_or_else(|_| current())
}

pub fn run() {
    let Some(_lock) = single_instance() else {
        return;
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    rt.block_on(async {
        let mut shown = fetch().await;
        let handle = match Tray(shown.clone()).spawn().await {
            Ok(handle) => handle,
            Err(e) => {
                eprintln!("无法显示托盘图标（桌面不支持 StatusNotifierItem？）：{e}");
                return;
            }
        };
        if worth_notifying(None, &shown) {
            notify(&shown).await;
        }
        loop {
            tokio::time::sleep(POLL).await;
            let now = fetch().await;
            if now == shown {
                continue;
            }
            if worth_notifying(Some(&shown), &now) {
                notify(&now).await;
            }
            let next = now.clone();
            if handle.update(move |t| t.0 = next).await.is_none() {
                return; // 托盘服务没了（会话结束）
            }
            shown = now;
        }
    });
}
