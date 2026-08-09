//! 内核模块加载监控：rootkit 落地几乎都要过 insmod/modprobe 这一步，
//! 模块可见性是 Linux 反 rootkit 的刚需。
//!
//! 内核没有可靠的用户态模块事件推送（netlink kobject uevent 依赖配置且
//! 容易被绕过），最朴素可靠的办法是周期读 /proc/modules 做 diff：
//! 新出现的模块名报"加载"，消失的报"卸载"。30s 粒度对取证够用——
//! rootkit 加载后通常常驻；加载即卸的短命模块可能漏，是已知取舍。
//!
//! 产出 OCSF Module Activity（class_uid=1005），raw 里的
//! module.file.path 与 server Sigma 引擎 image_load/driver_load 类别的
//! ImageLoaded 字段映射（engine.go fieldMap）对齐。首次快照只做基线，
//! 不报历史存量——agent 启动前加载的模块是宿主既有状态，不是事件。

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::pb::AgentEvent;

use super::EventSink;

/// OCSF Module Activity
const CLASS_MODULE_ACTIVITY: u32 = 1005;

/// OCSF 活动类型：Create / Delete
const ACTIVITY_LOAD: u8 = 1;
const ACTIVITY_UNLOAD: u8 = 4;

/// /proc/modules 轮询间隔
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// 启动监控线程。签名与其他采集器一致，由 collector::spawn 接线调用。
/// 不返回 Result：/proc/modules 读不到时快照为空集，diff 照常工作，
/// 没有需要降级的失败面。
pub fn spawn(agent_id: String, sink: EventSink) {
    std::thread::spawn(move || run(&agent_id, &sink));
}

fn run(agent_id: &str, sink: &EventSink) {
    // 模块名 -> 磁盘路径的解析根：/lib/modules/$(uname -r)/
    let modules_dir = format!("/lib/modules/{}", kernel_release());
    // 首次快照做基线，不报历史存量
    let mut prev = snapshot();
    loop {
        std::thread::sleep(POLL_INTERVAL);
        let cur = snapshot();
        let (loaded, unloaded) = diff_modules(&prev, &cur);
        prev = cur;
        for name in &loaded {
            let path = resolve_module_path(Path::new(&modules_dir), name);
            if !sink.send(module_event(agent_id, ACTIVITY_LOAD, name, path)) {
                return;
            }
        }
        for name in &unloaded {
            // 模块已卸，磁盘文件可能还在，路径照常解析供取证定位
            let path = resolve_module_path(Path::new(&modules_dir), name);
            if !sink.send(module_event(agent_id, ACTIVITY_UNLOAD, name, path)) {
                return;
            }
        }
    }
}

/// 当前已加载模块名集合；/proc/modules 读不到时为空集（下一轮 diff 会
/// 把全量模块当新增——但 /proc 读失败意味着系统已病入膏肓，接受这点噪音）。
fn snapshot() -> BTreeSet<String> {
    std::fs::read_to_string("/proc/modules")
        .map(|t| parse_modules(&t))
        .unwrap_or_default()
}

/// 内核版本（uname -r 等价物），读不到给空串——模块路径解析会因此落空，
/// 事件只带名字，不影响加载/卸载本身的可见性。
fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// /proc/modules 每行一个模块：名字 大小 引用计数 依赖列表 状态 地址。
/// 只取首列名字；空行与残缺行跳过。
fn parse_modules(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// 基线与当前快照的差集：(新加载的, 已卸载的)。排序输出让事件顺序稳定。
fn diff_modules(prev: &BTreeSet<String>, cur: &BTreeSet<String>) -> (Vec<String>, Vec<String>) {
    (
        cur.difference(prev).cloned().collect(),
        prev.difference(cur).cloned().collect(),
    )
}

/// 模块名 -> .ko 磁盘路径：在 /lib/modules/<内核版本>/ 下递归找同名文件。
/// 找不到（内置模块、out-of-tree 加载后原文件已删）返回 None，事件只带名字。
fn resolve_module_path(modules_dir: &Path, name: &str) -> Option<String> {
    let mut stack = vec![modules_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if e
                .file_name()
                .to_str()
                .is_some_and(|f| matches_module_file(f, name))
            {
                return Some(p.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// 文件名是否为指定模块的 .ko（含 .ko.gz/.ko.xz/.ko.zst 等压缩形态）。
/// 内核模块名的 '-' 与 '_' 等价（加载时统一归一成 '_'），比对前归一化；
/// 剥离扩展名后必须全等，防止 "evildriver.ko" 误配 "evil"。
fn matches_module_file(file_name: &str, name: &str) -> bool {
    let norm = file_name.replace('-', "_");
    let Some(stem) = norm.split(".ko").next() else {
        return false;
    };
    norm.contains(".ko") && stem == name
}

/// 组装一条模块活动事件。路径未知时 module.file 只带名字。
fn module_event(agent_id: &str, activity: u8, name: &str, path: Option<String>) -> AgentEvent {
    let file = match &path {
        Some(p) => {
            let fname = Path::new(p)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| name.to_string());
            serde_json::json!({ "path": p, "name": fname })
        }
        None => serde_json::json!({ "name": name }),
    };
    let raw = serde_json::json!({
        "activity_id": activity,
        "module": { "file": file },
    });
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: CLASS_MODULE_ACTIVITY,
        process_guid: String::new(),
        parent_process_guid: String::new(),
        // 加载者 pid 从 /proc/modules 拿不到（那是 audit/eBPF 的领域），留空
        username: String::new(),
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
        dropped_events: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_MODULES_SAMPLE: &str = "\
snd_intel_dspcfg 28672 1 snd_intel_sdw_acpi, Live 0xffffffffc0a00000
rfkill 32768 2 - Live 0xffffffffc0900000
nf_tables 262144 0 - Live 0xffffffffc0800000
";

    #[test]
    fn parse_modules_takes_first_column() {
        let m = parse_modules(PROC_MODULES_SAMPLE);
        assert_eq!(m.len(), 3);
        assert!(m.contains("snd_intel_dspcfg"));
        assert!(m.contains("rfkill"));
        assert!(m.contains("nf_tables"));
        assert!(parse_modules("").is_empty());
    }

    #[test]
    fn diff_modules_reports_load_and_unload() {
        let prev: BTreeSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let cur: BTreeSet<String> = ["b", "c"].iter().map(|s| s.to_string()).collect();
        let (loaded, unloaded) = diff_modules(&prev, &cur);
        assert_eq!(loaded, vec!["c".to_string()]);
        assert_eq!(unloaded, vec!["a".to_string()]);
        // 无变化时两边都空：基线快照本身绝不产事件
        let (l2, u2) = diff_modules(&cur, &cur);
        assert!(l2.is_empty() && u2.is_empty());
    }

    #[test]
    fn matches_module_file_handles_compression_and_dashes() {
        assert!(matches_module_file("e1000e.ko", "e1000e"));
        assert!(matches_module_file("e1000e.ko.xz", "e1000e"));
        assert!(matches_module_file("e1000e.ko.zst", "e1000e"));
        // 磁盘文件名用 '-'、/proc 里归一成 '_'，两边等价
        assert!(matches_module_file(
            "snd-intel-dspcfg.ko.xz",
            "snd_intel_dspcfg"
        ));
        // 前缀相同不算同名；非 .ko 文件不算
        assert!(!matches_module_file("evildriver.ko", "evil"));
        assert!(!matches_module_file("modules.dep", "modules"));
        assert!(!matches_module_file("e1000e.ko", "other"));
    }

    #[test]
    fn resolve_module_path_walks_tree() {
        let dir = std::env::temp_dir().join(format!("openxdr_kmod_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("kernel/drivers/net")).unwrap();
        std::fs::write(dir.join("kernel/drivers/net/e1000e.ko.xz"), b"").unwrap();

        let root = dir.to_str().unwrap();
        assert_eq!(
            resolve_module_path(Path::new(root), "e1000e").as_deref(),
            Some(
                dir.join("kernel/drivers/net/e1000e.ko.xz")
                    .to_str()
                    .unwrap()
            )
        );
        assert_eq!(resolve_module_path(Path::new(root), "nonexistent"), None);
        assert_eq!(
            resolve_module_path(Path::new("/nonexistent/openxdr"), "x"),
            None
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn module_event_schema_with_path() {
        let ev = module_event(
            "agent-t",
            ACTIVITY_LOAD,
            "e1000e",
            Some("/lib/modules/6.8.0/kernel/drivers/net/e1000e.ko.xz".to_string()),
        );
        assert_eq!(ev.class_uid, CLASS_MODULE_ACTIVITY);
        let v: serde_json::Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["activity_id"], 1);
        assert_eq!(
            v["module"]["file"]["path"],
            "/lib/modules/6.8.0/kernel/drivers/net/e1000e.ko.xz"
        );
        assert_eq!(v["module"]["file"]["name"], "e1000e.ko.xz");
    }

    #[test]
    fn module_event_schema_name_only() {
        let ev = module_event("agent-t", ACTIVITY_UNLOAD, "evil", None);
        let v: serde_json::Value = serde_json::from_str(&ev.raw_json).unwrap();
        assert_eq!(v["activity_id"], 4);
        assert_eq!(v["module"]["file"]["name"], "evil");
        assert!(
            v["module"]["file"].get("path").is_none(),
            "路径未知时不应编造 path 字段"
        );
    }
}
