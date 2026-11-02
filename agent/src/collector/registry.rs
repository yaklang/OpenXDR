//! 进程 GUID 注册表：pid 会被系统复用，GUID 不会。
//! 进程血缘全靠这张表——父进程的 GUID 从这里查，查不到说明父进程早于 agent 启动。

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use uuid::Uuid;

use super::periodic::Periodic;
use crate::pb::AgentEvent;

/// 进程所在的容器或虚拟机（Linux 按 cgroup 识别），事件里原样写成 container 对象
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    /// docker / podman / containerd / cri-o / lxc / qemu / nspawn
    pub runtime: &'static str,
    /// 容器 ID（docker 系取前 12 位）或 Proxmox 的 VMID
    pub uid: String,
    pub name: Option<String>,
}

impl Container {
    pub fn to_json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({ "runtime": self.runtime, "uid": self.uid });
        if let Some(name) = &self.name {
            v["name"] = name.as_str().into();
        }
        v
    }
}

/// 注册表里保留的命令行长度上限：够规则判断父进程，又不让几千个存活进程占太多内存
const CMD_LINE_MAX: usize = 1024;

/// 安全上限：条目随进程退出删除，正常只有存活进程；漏掉退出事件的条目超限时清掉最早的一半
const MAX_ENTRIES: usize = 1 << 16;

#[derive(Default)]
pub struct ProcessRegistry {
    guids: HashMap<u32, Entry>,
    seq: u64,
    /// 周期行为折叠的状态（见 periodic）
    pub periodic: Periodic,
    /// 被折叠进程后来有了要上报的动静时，压着的启动事件移到这里，由下一次发事件的采集路径带出去
    outbox: Vec<AgentEvent>,
    /// agent 自己拉起的自检进程（见 liveness）及其后代：pid → 登记时刻。只证明采集通道活着，不上报
    canaries: HashMap<u32, Instant>,
}

/// 占位 GUID 的有效期：各 ETW 会话之间的先后差不过一两秒，再久就当作另一个进程（pid 复用）
const PLACEHOLDER_TTL: Duration = Duration::from_secs(10);

/// 自检进程登记的有效期：启动与退出事件早该到了，过期的登记不再认，pid 复用也不会把别人的进程藏掉
const CANARY_TTL: Duration = Duration::from_secs(30);

/// 平凡退出的存活上限：成功退出、且启动到现在不到这么久，退出事件不携带新信息（见 trivial_exit）
const TRIVIAL_EXIT_MAX_AGE: Duration = Duration::from_secs(2);

/// 平凡退出抑制的开关。默认开，采集配置显式关掉才逐条上报退出
static SUPPRESS_TRIVIAL_EXIT: AtomicBool = AtomicBool::new(true);

/// 采集配置里的开关（`suppressTrivialExit`），启动时设置一次
pub fn set_suppress_trivial_exit(on: bool) {
    SUPPRESS_TRIVIAL_EXIT.store(on, Ordering::Relaxed);
}

struct Entry {
    guid: Uuid,
    seq: u64,
    // 启动时记下名字与路径：退出探针触发时进程已在退出途中，只剩 pid 可查
    name: String,
    exe: Option<String>,
    cmd_line: Option<String>,
    started: Option<SystemTime>,
    container: Option<Arc<Container>>,
    command: Option<Arc<str>>,
    /// 所属的 SSH 登录（见 sshsession），事件里原样写出的 login_session 对象
    login: Option<Arc<serde_json::Value>>,
    /// 父进程 pid：补发被折叠的祖先时沿它往上走
    ppid: Option<u32>,
    /// 被折叠、还没上报的启动事件
    held: Option<AgentEvent>,
    /// 网络 / DNS 事件先于进程启动事件到达时现场占的位（见 placeholder）
    placeholder: Option<Instant>,
}

/// 注册表里记得的进程身份，退出事件靠它说清是谁退出了。
pub struct Known {
    pub guid: Uuid,
    pub name: String,
    pub exe: Option<String>,
    /// 命令行（截到 CMD_LINE_MAX）：子进程事件带上父进程的命令行，规则才能按父进程判断
    pub cmd_line: Option<String>,
    pub started: Option<SystemTime>,
    pub container: Option<Arc<Container>>,
    /// 拉起它的平台指令 ID（指令进程及其后代）
    pub command: Option<Arc<str>>,
    /// 所属的 SSH 登录
    pub login: Option<Arc<serde_json::Value>>,
}

impl ProcessRegistry {
    /// 登记新进程，返回它的 GUID 和父进程 GUID（父未知则 None）。
    pub fn register(&mut self, pid: u32, ppid: Option<u32>) -> (Uuid, Option<Uuid>) {
        let parent = ppid.and_then(|p| self.guids.get(&p).map(|e| e.guid));
        // 刚占过位的进程沿用占位时的 GUID：先到的网络 / DNS 事件与随后的启动事件才连得上
        let guid = self
            .guids
            .get(&pid)
            .filter(|e| {
                e.placeholder
                    .is_some_and(|at| at.elapsed() < PLACEHOLDER_TTL)
            })
            .map_or_else(Uuid::new_v4, |e| e.guid);
        crate::process_identity::record(pid, guid);

        self.seq += 1;
        let seq = self.seq;
        // pid 复用时新条目直接覆盖旧的，这正是我们要的语义
        self.guids.insert(
            pid,
            Entry {
                guid,
                seq,
                name: String::new(),
                exe: None,
                cmd_line: None,
                started: None,
                container: None,
                command: None,
                login: None,
                ppid,
                held: None,
                placeholder: None,
            },
        );

        if self.guids.len() > MAX_ENTRIES {
            let cutoff = seq.saturating_sub(MAX_ENTRIES as u64 / 2);
            self.guids.retain(|_, e| e.seq > cutoff);
        }
        (guid, parent)
    }

    /// 给还没登记的进程占位，返回 GUID。Windows 的进程、网络与 DNS 走各自的 ETW 会话，
    /// 短命进程（nslookup、curl）的连接或查询常比它的启动事件先到：占位后若启动事件在
    /// PLACEHOLDER_TTL 内到达，就沿用这个 GUID，而不是另发一个、把先到的事件挂空
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub fn placeholder(&mut self, pid: u32) -> Uuid {
        let (guid, _) = self.register(pid, None);
        if let Some(e) = self.guids.get_mut(&pid) {
            e.placeholder = Some(Instant::now());
        }
        guid
    }

    /// 预登记已存在的进程（agent 启动时的进程表快照），让后续子进程能找到父，
    /// 它们退出时也能报出名字。
    pub fn seed(&mut self, pid: u32, name: &str, exe: Option<&str>) {
        self.register(pid, None);
        self.describe(pid, name, exe);
    }

    /// 记下进程的名字与路径。
    pub fn describe(&mut self, pid: u32, name: &str, exe: Option<&str>) {
        if let Some(e) = self.guids.get_mut(&pid) {
            e.name = name.to_string();
            e.exe = exe.map(str::to_string);
        }
    }

    /// 记下命令行，过长的截断（按字符边界）
    pub fn set_cmd_line(&mut self, pid: u32, cmd_line: Option<&str>) {
        if let Some(e) = self.guids.get_mut(&pid) {
            e.cmd_line = cmd_line.map(|c| {
                let mut end = c.len().min(CMD_LINE_MAX);
                while !c.is_char_boundary(end) {
                    end -= 1;
                }
                c[..end].to_string()
            });
        }
    }

    /// 记下启动时间（退出时算运行时长）、所在容器与拉起它的平台指令。
    pub fn annotate(
        &mut self,
        pid: u32,
        started: Option<SystemTime>,
        container: Option<Arc<Container>>,
        command: Option<Arc<str>>,
    ) {
        if let Some(e) = self.guids.get_mut(&pid) {
            e.started = started;
            e.container = container;
            e.command = command;
        }
    }

    /// 记下进程所属的 SSH 登录
    pub fn set_login(&mut self, pid: u32, login: Option<Arc<serde_json::Value>>) {
        if let Some(e) = self.guids.get_mut(&pid) {
            e.login = login;
        }
    }

    /// pid 所属的 SSH 登录：子进程自己的 /proc 读不到时（已退场）沿父进程继承
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn login_of(&self, pid: u32) -> Option<Arc<serde_json::Value>> {
        self.guids.get(&pid).and_then(|e| e.login.clone())
    }

    /// pid 所属的平台指令，子进程沿血缘继承
    pub fn command_of(&self, pid: u32) -> Option<Arc<str>> {
        self.guids.get(&pid).and_then(|e| e.command.clone())
    }

    /// 进程退出后删掉登记。不删的话表满时会按登记先后清理，最先被清掉的恰恰是
    /// 早于 agent 启动的长驻服务，它们之后的网络连接就挂不回进程树了
    pub fn forget(&mut self, pid: u32) {
        self.guids.remove(&pid);
    }

    /// 压下一条被折叠的启动事件：它的退出也不再单独上报，除非之前被补发了
    pub fn hold(&mut self, pid: u32, event: AgentEvent) {
        if let Some(e) = self.guids.get_mut(&pid) {
            e.held = Some(event);
        }
    }

    /// 这个进程的启动是否被折叠且还没补发
    pub fn is_held(&self, pid: u32) -> bool {
        self.guids.get(&pid).is_some_and(|e| e.held.is_some())
    }

    /// 这次退出算不算「平凡退出」：成功退出（exit 0）且存活不到 2 秒。这样的退出事件
    /// 只多一个已知为 0 的退出码和一段毫秒级时长，没有分析价值，不单独上报。只读，不改状态。
    ///
    /// 拿不准一律不抑制（多报不漏报）：退出码非零是有信息量的结论；退出码未知
    /// （被信号杀掉、内核/ETW 拿不到）同样按「有信号」处理；启动时间读不到、pid 没登记、
    /// 或时钟回拨算不出存活时长，都照常上报。
    pub fn trivial_exit(&self, pid: u32, exit_code: Option<u32>) -> bool {
        if !SUPPRESS_TRIVIAL_EXIT.load(Ordering::Relaxed) {
            return false;
        }
        if exit_code != Some(0) {
            return false;
        }
        let Some(started) = self.guids.get(&pid).and_then(|e| e.started) else {
            return false;
        };
        SystemTime::now()
            .duration_since(started)
            .is_ok_and(|age| age < TRIVIAL_EXIT_MAX_AGE)
    }

    /// 进程有了要上报的动静（不是周期行为的子进程、网络连接、DNS 查询）：把它和被折叠的祖先
    /// 压着的启动事件移进待发，祖先在前。血缘按 GUID 串，晚到不影响，事件保留原本的启动时间
    pub fn reveal(&mut self, pid: u32) {
        let mut chain = Vec::new();
        let mut next = Some(pid);
        // 祖先链有限，深度封顶防止 pid 复用造成的环
        while let Some(p) = next.take()
            && chain.len() < 64
        {
            let Some(e) = self.guids.get_mut(&p) else {
                break;
            };
            let Some(event) = e.held.take() else { break };
            chain.push(event);
            next = e.ppid;
        }
        chain.reverse();
        self.outbox.append(&mut chain);
    }

    /// 登记一个自检进程。调用方须在拉起它的同时持有注册表锁，采集回调拿到锁时登记已经在了
    pub fn add_canary(&mut self, pid: u32) {
        let now = Instant::now();
        self.canaries
            .retain(|_, at| now.duration_since(*at) < CANARY_TTL);
        self.canaries.insert(pid, now);
    }

    /// 这条进程事件是不是自检进程的（是就不上报）。启动事件认登记过的 pid（父进程须是 agent 自己）
    /// 和它的后代；退出事件顺手撤掉登记
    pub fn is_canary(&mut self, activity_launch: bool, pid: u32, ppid: Option<u32>) -> bool {
        let fresh = |at: &Instant| at.elapsed() < CANARY_TTL;
        if !activity_launch {
            return self.canaries.remove(&pid).is_some_and(|at| fresh(&at));
        }
        if self.canaries.get(&pid).is_some_and(fresh) {
            return ppid.is_none_or(|p| p == std::process::id());
        }
        if ppid.is_some_and(|p| self.canaries.get(&p).is_some_and(fresh)) {
            self.canaries.insert(pid, Instant::now());
            return true;
        }
        false
    }

    /// 取走待发的补发事件
    pub fn take_outbox(&mut self) -> Vec<AgentEvent> {
        std::mem::take(&mut self.outbox)
    }

    /// 查 pid 当前登记的身份。查不到说明既没见过它启动、也不在启动快照里。
    pub fn known(&self, pid: u32) -> Option<Known> {
        self.guids.get(&pid).map(|e| Known {
            guid: e.guid,
            name: e.name.clone(),
            exe: e.exe.clone(),
            cmd_line: e.cmd_line.clone(),
            started: e.started,
            container: e.container.clone(),
            command: e.command.clone(),
            login: e.login.clone(),
        })
    }

    /// 查 pid 当前的 GUID，未登记返回 None。网络事件靠它挂进进程血缘，
    /// 退出事件靠它复用启动时的 GUID。
    pub fn guid_of(&self, pid: u32) -> Option<Uuid> {
        self.guids.get(&pid).map(|e| e.guid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 血缘靠 GUID 串联：父进程的 register 返回值就是子进程的 parent。
    #[test]
    fn lineage_via_guid() {
        let mut reg = ProcessRegistry::default();
        let (g1, _) = reg.register(1, None);
        let (g2, parent2) = reg.register(2, Some(1));
        let (g3, parent3) = reg.register(3, Some(2));

        assert_eq!(parent2, Some(g1), "子进程父 GUID 应等于父进程 GUID");
        assert_eq!(parent3, Some(g2), "孙进程应连到直系父进程");
        assert_ne!(g1, g2);
        assert_ne!(g2, g3);
    }

    /// 父进程未登记（早于 agent 启动）→ 父 GUID 为 None。
    #[test]
    fn unknown_parent_is_none() {
        let mut reg = ProcessRegistry::default();
        let (g, parent) = reg.register(100, Some(999));
        assert!(parent.is_none());
        assert!(!g.is_nil());
    }

    /// pid 复用：同一 pid 再次登记覆盖旧 GUID，父句柄随之指向新条目。
    #[test]
    fn pid_reuse_overwrites() {
        let mut reg = ProcessRegistry::default();
        let (old, _) = reg.register(50, None);
        let (fresh, _) = reg.register(50, None);
        assert_ne!(old, fresh, "pid 复用必须换新 GUID");

        let (_, parent_of_child) = reg.register(51, Some(50));
        assert_eq!(parent_of_child, Some(fresh), "子进程应连到复用后的新 GUID");
    }

    /// seed 等价于预登记，让后续子进程能追溯，并记住名字与路径。
    #[test]
    fn seed_pregisters() {
        let mut reg = ProcessRegistry::default();
        reg.seed(7, "sshd", Some("/usr/sbin/sshd"));
        let (child, parent) = reg.register(8, Some(7));
        assert!(parent.is_some());
        assert_ne!(child, parent.unwrap());
        let known = reg.known(7).unwrap();
        assert_eq!(
            (known.name.as_str(), known.exe.as_deref()),
            ("sshd", Some("/usr/sbin/sshd"))
        );
        assert!(reg.known(9).is_none());
    }

    /// 退出后删掉登记；长驻进程不会因为短命进程多而被挤出注册表
    #[test]
    fn forget_and_long_lived_survive() {
        let mut reg = ProcessRegistry::default();
        reg.seed(1, "systemd", None);
        for pid in 2..(MAX_ENTRIES as u32 * 3) {
            reg.register(pid, Some(1));
            reg.forget(pid);
        }
        assert!(reg.known(1).is_some(), "长驻进程应一直在表里");
        assert!(reg.known(2).is_none());
    }

    /// 每次 register 分配独立 GUID。
    #[test]
    fn guids_are_distinct() {
        let mut reg = ProcessRegistry::default();
        let mut seen = std::collections::HashSet::new();
        for pid in 1..=1000u32 {
            let (g, _) = reg.register(pid, None);
            assert!(seen.insert(g), "GUID 不应重复");
        }
    }

    /// 占位的 GUID 由随后的启动事件沿用，只沿用一次；pid 复用（再次登记）照常换新 GUID
    #[test]
    fn placeholder_guid_is_reused_once() {
        let mut reg = ProcessRegistry::default();
        reg.seed(1, "explorer.exe", None);
        let early = reg.placeholder(42);
        let (guid, parent) = reg.register(42, Some(1));
        assert_eq!(guid, early, "先到的网络事件与启动事件应同一 GUID");
        assert!(parent.is_some());
        let (next, _) = reg.register(42, Some(1));
        assert_ne!(next, early, "启动之后再登记是 pid 复用");
    }
}
