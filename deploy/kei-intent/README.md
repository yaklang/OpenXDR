# 凯伊会话自动登记运维意图

`kei-intent-hook.py` 是 Claude Code 的 `PreToolUse` 钩子：凯伊各会话经 SSH 动纳管主机前，自动向 OpenXDR
登记一条运维意图（`POST /api/integration/v1/intents`）。研判与结案审计据此认出「这次登录是哪台机器的凯伊会话在做运维」
（`facts.Lookup` 按登录的钥匙指纹与来源匹配进行中的意图）。手工登记一周只用了十几次，所以做成自动的。

- 只登记、不拦命令：任何失败只写 `~/.cache/kei-intent/hook.log`，钩子照常放行。
- 识别 `ssh` / `scp` / `rsync` / `sftp`（含 `sudo`、`timeout`、`$(…)` 包裹）与包装脚本目录里的单机脚本；
  经 `ssh -G` 带上命令自己的 `-F` / `-i` / `-o` 解析出真实地址和这次会用的钥匙，按资产 IP 或主机名对上纳管资产。
- 只为配置里声明归本令牌所有的钥匙登记；平台另行校验（意图只能为事实库里持有人是自己的钥匙登记），所以各机要用自己的钥匙
  （见网络仓库「每机一钥」），共享钥匙登记不了。
- 同一会话对同一批主机，意图还剩 20 分钟以上就不重复登记；新增主机时把仍有效的一并续上，一次最多 20 台、默认 2 小时。
- 用途固定为配置里的类别（默认 `maintenance`），说明只写机器名与 Paseo 会话 ID，不进研判模型。

## 安装（每台跑凯伊会话的机器）

1. 为本机钥匙签发集成 Token（scope `intents:write`），并在事实库把本机钥匙的持有人设为这个 Token（`integration:<ID>`）。
2. 写 `~/.config/kei-intent/config.json`（600 权限），字段见脚本头部注释。
3. 把脚本放到固定位置（如 `~/.local/share/kei-intent/`），在 `~/.claude/settings.json` 加：

```json
"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command",
  "command": "python3 ~/.local/share/kei-intent/kei-intent-hook.py", "timeout": 15}]}]}
```

4. 自测：`echo '{"tool_name":"Bash","session_id":"t","tool_input":{"command":"ssh <别名> true"}}' | python3 kei-intent-hook.py`，看日志里出现 `登记 I-…`。
