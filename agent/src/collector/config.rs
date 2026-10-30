//! 采集配置。server 在 Register 响应里下发，重连即生效——
//! 不做热更新：agent 断线重连本就会重新注册，那条路已经够了。
//!
//! 配置解析永不失败：字段缺失或整个 JSON 无法解析都退回内置默认。
//! 一份坏配置让 agent 变瞎，比配置不生效严重得多。

use serde::Deserialize;

// 字段名跟随 server 下发的 JSON（camelCase）
#[derive(Debug, Clone, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Config {
    /// 覆盖内置的敏感目录清单；为空表示用默认
    pub file_watch_dirs: Vec<String>,
    pub collect_files: bool,
    pub collect_auth: bool,
    pub collect_persist: bool,
    pub collect_network: bool,
    /// 资产清单：监听端口与属主进程、云环境
    pub collect_inventory: bool,
    /// 周期行为折叠：同一父进程反复执行同一条命令时改为按窗口汇总（见 periodic）
    pub collapse_periodic: bool,
    /// 平凡进程退出抑制：成功退出且存活不到两秒的进程不再单独上报退出（见 registry::trivial_exit）
    pub suppress_trivial_exit: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            file_watch_dirs: Vec::new(),
            collect_files: true,
            collect_auth: true,
            collect_persist: true,
            collect_network: true,
            collect_inventory: true,
            collapse_periodic: true,
            suppress_trivial_exit: true,
        }
    }
}

impl Config {
    /// 解析下发的配置 JSON。空串或非法内容一律回退默认。
    pub fn parse(json: &str) -> Self {
        if json.trim().is_empty() {
            return Self::default();
        }
        match serde_json::from_str(json) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("采集配置无法解析（{e}），使用内置默认");
                Self::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_default() {
        let c = Config::parse("");
        assert!(c.collect_files && c.collect_auth && c.collect_persist);
        assert!(c.file_watch_dirs.is_empty());
    }

    #[test]
    fn partial_config_keeps_other_defaults() {
        let c = Config::parse(r#"{"collectAuth": false}"#);
        assert!(!c.collect_auth, "显式关掉的要生效");
        assert!(c.collect_files, "没提到的保持默认开启");
    }

    #[test]
    fn inventory_switch() {
        assert!(Config::parse("").collect_inventory, "默认开启");
        let c = Config::parse(r#"{"collectInventory": false}"#);
        assert!(!c.collect_inventory, "显式关掉的要生效");
        assert!(c.collect_network, "没提到的保持默认开启");
    }

    #[test]
    fn collapse_switch() {
        assert!(Config::parse("").collapse_periodic, "默认开启");
        assert!(!Config::parse(r#"{"collapsePeriodic": false}"#).collapse_periodic);
    }

    /// 平凡退出抑制默认开启（与 collapsePeriodic 同一取向：默认就降噪），显式关掉要生效
    #[test]
    fn suppress_trivial_exit_switch() {
        assert!(Config::parse("").suppress_trivial_exit, "默认开启");
        let c = Config::parse(r#"{"suppressTrivialExit": false}"#);
        assert!(!c.suppress_trivial_exit, "显式关掉的要生效");
        assert!(c.collapse_periodic, "没提到的保持默认开启");
    }

    #[test]
    fn custom_watch_dirs() {
        let c = Config::parse(r#"{"fileWatchDirs": ["/srv/app", "/opt/secrets"]}"#);
        assert_eq!(c.file_watch_dirs, ["/srv/app", "/opt/secrets"]);
    }

    #[test]
    fn broken_json_falls_back_to_default() {
        let c = Config::parse("{not json");
        assert!(c.collect_files, "坏配置不能让 agent 变瞎");
    }
}
