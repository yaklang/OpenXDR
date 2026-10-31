//! 周期行为折叠：同一个父进程反复执行完全相同的命令（防火墙守护进程定时导出规则、监控面板每隔几秒跑一遍 ps、
//! 状态守护进程轮询存储），逐条上报只会淹没真正的信号——生产上这类进程占了一半以上的事件。
//!
//! 规则：键是「父进程路径 + 父命令行 + 子进程路径 + 子命令行」。窗口内同一个键出现够多次就认定是周期行为，
//! 之后它的启动与退出不再逐条上报，每个窗口末尾报一条汇总（次数、首末时间）。一小时没再出现的键忘掉，
//! 再出现就重新逐条上报。命令行里每次都不同的随机串与长数字不进键。父进程说不清（注册表与 /proc 都查不到）
//! 或平台指令拉起的进程从不折叠。
//!
//! 折叠不是丢弃：被折叠进程的启动事件先压在注册表里，一旦它拉起了不是周期行为的子进程、
//! 或者发起网络连接与 DNS 查询，压着的启动事件（连同被折叠的祖先）先补发出去，异常的血缘照样完整。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::pb::AgentEvent;

/// 认定与汇总共用一个窗口
const WINDOW: Duration = Duration::from_secs(600);
/// 窗口内出现这么多次才算周期行为：十分钟二十次，即平均半分钟一次以上
const THRESHOLD: u32 = 20;
/// 这么久没再出现的键忘掉
const IDLE: Duration = Duration::from_secs(3600);
/// 键的上限：超出时先丢还没认定的，周期行为本身不会很多
const MAX_KEYS: usize = 4096;
/// 汇总事件的 activity_id（OCSF 的 Other）
pub const ACTIVITY_PERIODIC: u32 = 99;

static ENABLED: AtomicBool = AtomicBool::new(true);

/// 采集配置里的开关，启动时设置一次
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// 一类周期行为的样本：汇总事件靠它说清是谁在反复做什么
#[derive(Clone, Default)]
pub struct Sample {
    pub name: String,
    pub exe: Option<String>,
    pub cmd_line: Option<String>,
    pub username: String,
    pub parent_name: String,
    pub parent_exe: Option<String>,
    pub parent_cmd_line: Option<String>,
}

impl Sample {
    fn key(&self) -> String {
        let s = |v: &Option<String>| v.clone().unwrap_or_default();
        let c = |v: &Option<String>| v.as_deref().map(volatile_free).unwrap_or_default();
        [
            s(&self.parent_exe),
            c(&self.parent_cmd_line),
            s(&self.exe),
            c(&self.cmd_line),
        ]
        .join("\0")
    }
}

/// 折叠键里抹掉每次都不同的部分：16 位以上的十六进制串（容器、exec ID）、5 位以上的数字（临时文件名、PID）
/// 换成 #。docker 健康检查的 runc 命令行带着随机文件名与 exec ID，原样做键每次都是新键，永远攒不到阈值
fn volatile_free(cmd: &str) -> String {
    let mut out = String::with_capacity(cmd.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        let volatile =
            run.len() >= 16 || (run.len() >= 5 && run.bytes().all(|b| b.is_ascii_digit()));
        out.push_str(if volatile { "#" } else { run });
        run.clear();
    };
    for c in cmd.chars() {
        if c.is_ascii_hexdigit() {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

struct Stat {
    sample: Sample,
    window_start: Instant,
    seen: u32,
    learned: bool,
    last_seen: Instant,
    /// 上次汇总以来折叠掉的次数与首末时间
    folded: u64,
    first: Option<SystemTime>,
    last: Option<SystemTime>,
}

pub struct Periodic {
    keys: HashMap<String, Stat>,
    last_flush: Instant,
}

impl Default for Periodic {
    fn default() -> Self {
        Self {
            keys: HashMap::new(),
            last_flush: Instant::now(),
        }
    }
}

impl Periodic {
    /// 记一次启动。返回 true 表示这次折叠，不单独上报。开关由调用方看（enabled），这里只管状态
    pub fn observe(&mut self, sample: &Sample, now: Instant, wall: SystemTime) -> bool {
        if self.keys.len() >= MAX_KEYS {
            self.keys.retain(|_, s| s.learned);
            if self.keys.len() >= MAX_KEYS {
                return false;
            }
        }
        let st = self.keys.entry(sample.key()).or_insert_with(|| Stat {
            sample: sample.clone(),
            window_start: now,
            seen: 0,
            learned: false,
            last_seen: now,
            folded: 0,
            first: None,
            last: None,
        });
        st.last_seen = now;
        if st.learned {
            st.folded += 1;
            st.first.get_or_insert(wall);
            st.last = Some(wall);
            return true;
        }
        if now.duration_since(st.window_start) > WINDOW {
            st.window_start = now;
            st.seen = 0;
        }
        st.seen += 1;
        // 达到阈值的这一次照常上报，从下一次开始折叠
        st.learned = st.seen >= THRESHOLD;
        false
    }

    /// 窗口到了就为每类折叠过的行为出一条汇总，顺手忘掉久不出现的键。没到窗口返回空
    pub fn flush(&mut self, agent_id: &str, now: Instant) -> Vec<AgentEvent> {
        if now.duration_since(self.last_flush) < WINDOW {
            return Vec::new();
        }
        self.last_flush = now;
        let mut out = Vec::new();
        for st in self.keys.values_mut() {
            if st.folded > 0 {
                out.push(summary(agent_id, st));
                st.folded = 0;
                st.first = None;
                st.last = None;
            }
        }
        self.keys
            .retain(|_, s| now.duration_since(s.last_seen) < IDLE);
        out
    }
}

fn millis(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

/// 汇总事件：进程与父进程照常写在 process 下，规则按进程字段判断时一样能命中；periodic 给出折叠次数与首末时间
fn summary(agent_id: &str, st: &Stat) -> AgentEvent {
    let s = &st.sample;
    let last = st.last.unwrap_or_else(SystemTime::now);
    let mut parent = serde_json::json!({ "name": s.parent_name });
    if let Some(exe) = &s.parent_exe {
        parent["file"] = serde_json::json!({ "path": exe });
    }
    if let Some(cmd) = &s.parent_cmd_line {
        parent["cmd_line"] = cmd.as_str().into();
    }
    let raw = serde_json::json!({
        "activity_id": ACTIVITY_PERIODIC,
        "process": {
            "name": s.name,
            "file": { "path": s.exe },
            "cmd_line": s.cmd_line,
            "parent_process": parent,
        },
        "periodic": {
            "count": st.folded,
            "first_time": st.first.map(millis),
            "last_time": millis(last),
            "window_ms": WINDOW.as_millis() as u64,
        },
    });
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: last
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: 1007,
        process_guid: String::new(),
        parent_process_guid: String::new(),
        username: s.username.clone(),
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
        dropped_events: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(cmd: &str) -> Sample {
        Sample {
            name: "ebtables-save".into(),
            exe: Some("/usr/sbin/ebtables-save".into()),
            cmd_line: Some(cmd.into()),
            parent_name: "pve-firewall".into(),
            parent_exe: Some("/usr/bin/perl".into()),
            parent_cmd_line: Some("pve-firewall".into()),
            ..Default::default()
        }
    }

    #[test]
    fn learns_after_threshold_and_summarizes() {
        let mut p = Periodic::default();
        let t0 = Instant::now();
        let wall = SystemTime::now();
        let s = sample("/sbin/ebtables-save");
        for i in 0..THRESHOLD {
            assert!(
                !p.observe(&s, t0 + Duration::from_secs(i as u64), wall),
                "认定前第 {i} 次应照常上报"
            );
        }
        for i in 0..5 {
            assert!(
                p.observe(&s, t0 + Duration::from_secs(30 + i), wall),
                "认定后应折叠"
            );
        }
        // 命令行不同的不受影响
        assert!(!p.observe(&sample("/sbin/ebtables-save -t nat"), t0, wall));
        assert!(
            p.flush("a", t0 + Duration::from_secs(60)).is_empty(),
            "窗口没到不出汇总"
        );
        let out = p.flush("a", t0 + WINDOW + Duration::from_secs(1));
        assert_eq!(out.len(), 1);
        let v: serde_json::Value = serde_json::from_str(&out[0].raw_json).unwrap();
        assert_eq!(v["activity_id"], ACTIVITY_PERIODIC);
        assert_eq!(v["periodic"]["count"], 5);
        assert_eq!(v["process"]["name"], "ebtables-save");
        assert_eq!(v["process"]["parent_process"]["name"], "pve-firewall");
        assert!(out[0].process_guid.is_empty());
    }

    /// 每次都不同的随机串与长数字不进键：docker 健康检查的 runc 每次是同一个键，参数真正不同的照样分开
    #[test]
    fn volatile_parts_are_not_part_of_the_key() {
        assert_eq!(
            volatile_free(
                "runc exec --process /tmp/runc-process1514723391 --pid-file /run/moby/6639cde64eb561d4988f22850c1316679f3c128a9a01182e6ff81350387cf0d9/a085bc0dcb516f16.pid"
            ),
            "runc exec --process /tmp/runc-process# --pid-file /run/moby/#/#.pid"
        );
        assert_eq!(
            volatile_free("awk NR==3 { printf($2)} /proc/loadavg"),
            "awk NR==3 { printf($2)} /proc/loadavg"
        );
        assert_eq!(
            volatile_free("kill -9 1234 deadbeef"),
            "kill -9 1234 deadbeef",
            "短数字和短十六进制保留"
        );
        let runc = |process: &str, exec_id: &str| Sample {
            exe: Some("/usr/bin/runc".into()),
            cmd_line: Some(format!(
                "runc exec --process /tmp/runc-process{process} --pid-file /run/{exec_id}.pid"
            )),
            parent_exe: Some("/usr/bin/containerd-shim-runc-v2".into()),
            ..Default::default()
        };
        assert_eq!(
            runc(
                "1514723391",
                "a085bc0dcb516f16e59edae4a7bdfbdddca4ef6bfc614cfa7eb62f602a32f516"
            )
            .key(),
            runc(
                "987654321",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .key()
        );
        assert_ne!(
            sample("/sbin/ebtables-save").key(),
            sample("/sbin/iptables-save").key()
        );
    }

    #[test]
    fn sparse_behavior_is_never_folded() {
        let mut p = Periodic::default();
        let t0 = Instant::now();
        let s = sample("/sbin/ebtables-save");
        // 每次间隔超过一个窗口的二十分之一以上、窗口内凑不够次数
        for i in 0..100u64 {
            assert!(!p.observe(&s, t0 + Duration::from_secs(i * 60), SystemTime::now()));
        }
    }

    #[test]
    fn idle_keys_are_forgotten() {
        let mut p = Periodic::default();
        let t0 = Instant::now();
        let s = sample("x");
        for i in 0..THRESHOLD {
            p.observe(&s, t0 + Duration::from_secs(i as u64), SystemTime::now());
        }
        assert!(p.observe(&s, t0 + Duration::from_secs(25), SystemTime::now()));
        p.flush("a", t0 + IDLE + WINDOW);
        assert!(
            !p.observe(&s, t0 + IDLE + WINDOW, SystemTime::now()),
            "久不出现的键忘掉后应重新逐条上报"
        );
    }
}
