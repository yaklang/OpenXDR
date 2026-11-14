#!/usr/bin/env python3
"""凯伊会话的 SSH 运维意图自动登记（Claude Code PreToolUse 钩子）。

凯伊各会话经 SSH 动纳管主机前，自动向 OpenXDR 登记一条运维意图（POST /api/integration/v1/intents），
研判与结案审计据此知道「这次登录是哪台机器的哪个凯伊会话在做运维」。手工登记一周只用了十几次，只能做成自动的。

只做登记，从不拦命令：任何失败都只记日志，钩子照常放行（退出码 0、不输出决定）。

识别的命令形态：ssh / scp / rsync / sftp 的目标，以及 wrappers 目录下的单机包装脚本（如 ~/.kei-deploy/node1）。
目标经 `ssh -G` 按 SSH 配置解析出真实地址与这次会用的钥匙，再按资产的 IP 或主机名对上纳管资产；
只为配置里声明归本令牌所有的钥匙登记（平台也会校验：意图只能为事实库里持有人是自己的钥匙登记）。

配置 ~/.config/kei-intent/config.json：
{
  "base": "http://10.1.1.199:8080/api/integration/v1",
  "tokenFile": "~/.kei-deploy/openxdr-intent-token",
  "keys": ["SHA256:..."],            // 本令牌名下的钥匙指纹
  "sourceAddr": "10.1.1.3",          // 纳管主机看到的来源（WireGuard 出口）
  "sshConfigs": ["/mnt/d/RoyalSecurity-Network/configs/ssh/config"],
  "wrappers": "~/.kei-deploy",       // 单机包装脚本目录，可省略
  "category": "maintenance",         // 固定目录里的用途
  "minutes": 120
}
"""
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.request

HOME = os.path.expanduser("~")
STATE_DIR = os.path.join(HOME, ".cache", "kei-intent")
LOG = os.path.join(STATE_DIR, "hook.log")
SSH_TOOLS = {"ssh", "scp", "rsync", "sftp"}
# 至少还剩这么久才算已覆盖，不重复登记
MIN_LEFT = 20 * 60


def log(msg):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")


def load_config():
    with open(os.path.join(HOME, ".config", "kei-intent", "config.json"), encoding="utf-8") as f:
        cfg = json.load(f)
    cfg.setdefault("category", "maintenance")
    cfg.setdefault("minutes", 120)
    cfg.setdefault("sshConfigs", [])
    return cfg


# 命令前缀：跳过它们再看真正执行的程序
PREFIX = {"sudo", "exec", "nohup", "command", "env", "time", "nice"}


def ssh_targets(command):
    """命令里 ssh 族工具的目标与影响选钥匙的选项：[(目标, [-i/-F/-o 选项…])]"""
    out = []
    for segment in re.split(r"[;&|\n]+|\$\(|`", command):
        try:
            words = shlex.split(segment, comments=True)
        except ValueError:
            continue
        i = 0
        while i < len(words) and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[i]) or words[i] in PREFIX
                                  or (words[i] == "timeout") or (i > 0 and words[i - 1] == "timeout")):
            i += 1
        if i < len(words) and os.path.basename(words[i]) in SSH_TOOLS:
            out += targets_of(os.path.basename(words[i]), words[i + 1:])
    return out


def targets_of(tool, args):
    # 带参数值的选项，跳过它们的值；ssh/sftp 的目标是第一个非选项词，scp/rsync 的是带冒号的远端路径
    with_value = set("bcDEeFIiJLlmOoPpQRSWw")
    found, opts, i = [], [], 0
    while i < len(args):
        a = args[i]
        if a.startswith("-") and len(a) > 1:
            flag, val = a[1:2], a[2:]
            if flag in with_value and not val and i + 1 < len(args):
                val = args[i + 1]
                i += 1
            if flag in ("i", "F", "o") and val:
                opts += ["-" + flag, val]
            i += 1
            continue
        if tool in ("ssh", "sftp"):
            found.append(a)
            break
        if ":" in a and not a.startswith("/"):
            found.append(a.split(":", 1)[0])
        i += 1
    return [(t.split("@", 1)[-1], opts) for t in found if t]


def wrapper_targets(command, wrappers):
    """单机包装脚本（脚本里自己 ssh 到某个别名）"""
    if not wrappers:
        return []
    root = os.path.realpath(os.path.expanduser(wrappers))
    out = []
    for path in re.findall(r"(?:~|%s)/[^\s'\";|&]+" % re.escape(HOME), command):
        real = os.path.realpath(os.path.expanduser(path))
        if os.path.dirname(real) != root or not os.path.isfile(real):
            continue
        try:
            text = open(real, encoding="utf-8", errors="ignore").read(8192)
        except OSError:
            continue
        for line in text.splitlines():
            if re.search(r"\bssh\b", line) and not line.lstrip().startswith("#"):
                out += ssh_targets(line)
    return out


def resolve(target, opts, ssh_configs):
    """ssh -G：真实地址与这次会用的钥匙文件（命令自带 -F 时只按它解析）"""
    configs = [None] if "-F" in opts else ssh_configs + [None]
    for cfg in configs:
        cmd = ["ssh", "-G"] + (["-F", cfg] if cfg else []) + [os.path.expanduser(o) for o in opts] + [target]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.TimeoutExpired):
            continue
        host, idents = None, []
        for line in out.splitlines():
            k, _, v = line.partition(" ")
            if k == "hostname":
                host = v
            elif k == "identityfile":
                idents.append(os.path.expanduser(v))
        if host and host != target or cfg is None:
            return host, idents
    return None, []


def fingerprint(identity):
    pub = identity + ".pub"
    if not os.path.isfile(pub):
        return None
    try:
        out = subprocess.run(["ssh-keygen", "-lf", pub], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    parts = out.split()
    return parts[1] if len(parts) > 1 else None


class API:
    def __init__(self, cfg):
        self.base = cfg["base"].rstrip("/")
        self.token = open(os.path.expanduser(cfg["tokenFile"])).read().strip()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method, path, body=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"Authorization": "Bearer " + self.token,
                                              "Content-Type": "application/json"})
        with self.opener.open(req, timeout=8) as r:
            return json.loads(r.read() or b"{}")

    def assets(self):
        cache = os.path.join(STATE_DIR, "assets.json")
        try:
            if time.time() - os.path.getmtime(cache) < 600:
                return json.load(open(cache))
        except OSError:
            pass
        out, cursor = [], None
        while True:
            page = self.call("GET", "/assets?limit=500" + (f"&cursor={cursor}" if cursor else ""))
            out += [{"id": a["id"], "hostname": a["hostname"].lower(), "ips": a.get("ipAddrs") or []}
                    for a in page["items"]]
            if not page.get("hasMore"):
                break
            cursor = page["nextCursor"]
        os.makedirs(STATE_DIR, exist_ok=True)
        json.dump(out, open(cache, "w"))
        return out


def asset_of(host, assets):
    h = host.lower()
    for a in assets:
        if h in a["ips"] or h == a["hostname"]:
            return a["id"]
    return None


def session_state(session):
    path = os.path.join(STATE_DIR, "session-" + re.sub(r"[^A-Za-z0-9_.-]", "_", session) + ".json")
    try:
        return path, json.load(open(path))
    except (OSError, ValueError):
        return path, {}


def note():
    agent = os.environ.get("PASEO_AGENT_ID", "")
    return f"自动登记：{os.uname().nodename} 上的凯伊会话" + (f" Paseo {agent[:8]}" if agent else "") + \
        f"（{os.path.basename(os.getcwd())}）"


def main():
    event = json.load(sys.stdin)
    if event.get("tool_name") != "Bash":
        return
    command = (event.get("tool_input") or {}).get("command") or ""
    cfg = load_config()
    targets = ssh_targets(command) + wrapper_targets(command, cfg.get("wrappers"))
    if not targets:
        return
    api = API(cfg)
    assets = api.assets()
    by_key = {}
    for t, opts in {(t, tuple(o)) for t, o in targets}:
        host, idents = resolve(t, list(opts), cfg["sshConfigs"])
        aid = asset_of(host or t, assets)
        if not aid:
            continue
        fp = next((f for f in map(fingerprint, idents) if f in cfg["keys"]), None)
        if fp:
            by_key.setdefault(fp, set()).add(aid)
    if not by_key:
        return
    path, state = session_state(event.get("session_id") or "default")
    now = time.time()
    for fp, ids in by_key.items():
        covered = state.get(fp, {})
        need = sorted(i for i in ids if covered.get(i, 0) - now < MIN_LEFT)
        if not need:
            continue
        need = sorted(set(need) | {i for i, exp in covered.items() if exp - now >= MIN_LEFT})[:20]
        out = api.call("POST", "/intents", {"keyFingerprint": fp, "sourceAddr": cfg["sourceAddr"], "assetIds": need,
                                            "category": cfg["category"], "note": note(),
                                            "durationMinutes": cfg["minutes"]})
        expires = now + cfg["minutes"] * 60
        state[fp] = {**{i: e for i, e in covered.items() if e > now}, **{i: expires for i in need}}
        log(f"登记 {out.get('ref')} key={fp[:15]} hosts={len(need)}")
    os.makedirs(STATE_DIR, exist_ok=True)
    json.dump(state, open(path, "w"))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # 只登记不拦命令：任何失败都放行
        try:
            log(f"失败：{type(e).__name__}: {e}")
        except OSError:
            pass
    sys.exit(0)
