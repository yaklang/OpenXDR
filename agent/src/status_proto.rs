//! 本机状态：agent 在本机开一个只读端点（Linux unix socket、Windows 命名管道），连上就写一行 JSON 后关闭，
//! 不读任何输入。托盘程序与 `openxdr-agent status` 都从这里读，再按 [`describe`] 变成给主机使用者看的话。
//!
//! 只给有限信息：防护在不在、和管理平台联不联得上、本机有没有被隔离。不给告警、规则、配置，
//! 主机上的任何人（包括入侵者）读到的都只有这些。字段只增不改，旧托盘读新 agent 照样能用。
//! agent 与托盘两个程序共用这个文件（托盘经 `#[path]` 引入），这里不能依赖 agent 的其他模块。

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
pub const SOCKET: &str = "/run/openxdr-agent.sock";
#[cfg(windows)]
pub const PIPE: &str = r"\\.\pipe\openxdr-agent";

/// 健康状态每 15 秒上报一次，这么久没有一次成功算失联
pub const CONTACT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub version: String,
    /// 最近一次成功联系管理平台的时间，0 表示启动以来还没联系上
    pub last_contact_unix_ms: u64,
    pub collection: Collection,
    pub isolated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Collection {
    /// 采集还没报上任何状态
    Starting,
    Ok,
    /// 有采集通道降级（采集路径自报，或开着却持续没有事件）
    Degraded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warn,
    Alert,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Summary {
    pub level: Level,
    pub title: &'static str,
    pub detail: String,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// 给主机使用者看的一句话。读不到状态（agent 没在跑）与被隔离最要紧，其次失联，再次采集降级
pub fn describe(status: Option<&Status>, now_ms: u64) -> Summary {
    let Some(s) = status else {
        return Summary {
            level: Level::Alert,
            title: "安全防护未运行",
            detail: "本机的 OpenXDR 防护程序没有响应，请联系安全团队。".into(),
        };
    };
    if s.isolated {
        return Summary {
            level: Level::Alert,
            title: "本机已被安全团队隔离",
            detail: "网络已被限制，只保留与管理平台的连接。请联系安全团队。".into(),
        };
    }
    let since = now_ms.saturating_sub(s.last_contact_unix_ms);
    if s.last_contact_unix_ms == 0 || since > CONTACT_TIMEOUT.as_millis() as u64 {
        let when = match s.last_contact_unix_ms {
            0 => "启动以来还没有联系上".to_string(),
            _ => format!("已有 {} 联系不上", ago(since)),
        };
        return Summary {
            level: Level::Warn,
            title: "与管理平台失联",
            detail: format!("{when}；防护仍在本机运行，记录会在恢复后补传。"),
        };
    }
    match s.collection {
        Collection::Degraded => Summary {
            level: Level::Warn,
            title: "安全防护部分降级",
            detail: "防护运行中，部分采集能力暂时不可用，安全团队会收到提示。".into(),
        },
        Collection::Starting => Summary {
            level: Level::Ok,
            title: "安全防护启动中",
            detail: format!("OpenXDR {}", s.version),
        },
        Collection::Ok => Summary {
            level: Level::Ok,
            title: "安全防护运行中",
            detail: format!("OpenXDR {}，已连接管理平台", s.version),
        },
    }
}

fn ago(ms: u64) -> String {
    let m = ms / 60_000;
    match m {
        0 => "不到 1 分钟".into(),
        1..=59 => format!("{m} 分钟"),
        60..=2879 => format!("{} 小时", m / 60),
        _ => format!("{} 天", m / 1440),
    }
}

/// 读本机状态。agent 没在跑、端点不在、超时都返回 None
pub fn fetch() -> Option<Status> {
    #[cfg(unix)]
    let text = read_endpoint(SOCKET)?;
    #[cfg(windows)]
    let text = read_endpoint()?;
    serde_json::from_str(text.trim()).ok()
}

#[cfg(unix)]
pub fn read_endpoint(path: &str) -> Option<String> {
    use std::io::Read;
    let s = std::os::unix::net::UnixStream::connect(path).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let mut out = String::new();
    s.take(64 * 1024).read_to_string(&mut out).ok()?;
    Some(out)
}

#[cfg(windows)]
fn read_endpoint() -> Option<String> {
    use std::io::Read;
    // 所有实例正忙（ERROR_PIPE_BUSY）时稍等再试：agent 写完一行就关，忙只会很短
    for _ in 0..5 {
        match std::fs::OpenOptions::new().read(true).open(PIPE) {
            Ok(f) => {
                let mut out = String::new();
                f.take(64 * 1024).read_to_string(&mut out).ok()?;
                return Some(out);
            }
            Err(e) if e.raw_os_error() == Some(231) => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(_) => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(contact: u64, collection: Collection, isolated: bool) -> Status {
        Status {
            version: "0.1.0".into(),
            last_contact_unix_ms: contact,
            collection,
            isolated,
        }
    }

    #[test]
    fn most_urgent_state_wins() {
        let now = 10_000_000;
        assert_eq!(describe(None, now).level, Level::Alert);
        let isolated = status(0, Collection::Degraded, true);
        assert_eq!(describe(Some(&isolated), now).title, "本机已被安全团队隔离");
        let lost = status(now - 5 * 60_000, Collection::Degraded, false);
        let s = describe(Some(&lost), now);
        assert_eq!((s.level, s.title), (Level::Warn, "与管理平台失联"));
        assert!(s.detail.contains("5 分钟"), "{}", s.detail);
        let never = status(0, Collection::Ok, false);
        assert!(describe(Some(&never), now).detail.contains("还没有联系上"));
        let degraded = status(now - 1000, Collection::Degraded, false);
        assert_eq!(describe(Some(&degraded), now).title, "安全防护部分降级");
        let ok = status(now - 1000, Collection::Ok, false);
        assert_eq!(describe(Some(&ok), now).level, Level::Ok);
    }

    #[test]
    fn wire_format_is_stable() {
        let s = status(1, Collection::Degraded, true);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(
            json,
            r#"{"version":"0.1.0","lastContactUnixMs":1,"collection":"degraded","isolated":true}"#
        );
        // 新 agent 多出来的字段，旧托盘照样读得懂
        let newer = r#"{"version":"0.2.0","lastContactUnixMs":1,"collection":"ok","isolated":false,"extra":1}"#;
        assert!(serde_json::from_str::<Status>(newer).is_ok());
    }
}
